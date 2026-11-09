/**
 * The Reports API. Starting a run is a local write (JSON only, from the
 * toolkit's own page); the run itself makes only the reads the guard allows.
 * The PDF and the CSV files are built on request from the finished document.
 */

import { Router, type Response } from "express";
import { jsonBody } from "../middleware/json-body.js";
import { getProvider } from "../state.js";
import { getSettings } from "../store/settings.js";
import { tenantList } from "../services/views.js";
import { NOT_BUILT, REPORTS } from "../reports/catalogue.js";
import { GROUP_FIELDS, MATCH_SCHEMAS, SNAPSHOT_SCHEMAS, schemaLabel } from "../reports/queries.js";
import { checkRequest } from "../reports/runner.js";
import { ReportJobs, summaryOf } from "../reports/jobs.js";
import { ReportInputError } from "../reports/queries.js";
import { contentDisposition, exportName, findTable, tableCsv } from "../reports/csv.js";
import { renderPdf, type Paper } from "../reports/pdf/render.js";
import { sensorLabel } from "../mappers/views.js";

export const reportsRouter = Router();
export const reportJobs = new ReportJobs();

function readyProvider(res: Response) {
  const p = getProvider();
  if (!p) {
    res.status(503).json({ error: "not_configured", message: "Add a Sophos API credential, or turn on demo mode." });
    return null;
  }
  if (p.status !== "ready") {
    res.status(503).json({ error: p.status, message: p.statusMessage || "Starting up." });
    return null;
  }
  return p;
}

reportsRouter.get("/", (_req, res) => {
  const p = readyProvider(res);
  if (!p) return;
  const tenants = tenantList(p, { ...getSettings(), privacy: false });
  // The data sources the Sources screen has seen, to filter a log search by.
  const sensors = new Set<string>();
  for (const t of p.tenants) for (const s of p.get("sources", t.id)?.sources ?? []) sensors.add(s.sensorType);
  res.json({
    multi: !!p.context?.multiTenant,
    demo: p.kind === "demo",
    tenants,
    reports: REPORTS,
    notBuilt: NOT_BUILT,
    logSearch: {
      schemas: Object.fromEntries(Object.entries(MATCH_SCHEMAS).map(([k, list]) => [k, list.map((s) => ({ id: s, label: schemaLabel(s), snapshot: SNAPSHOT_SCHEMAS.has(s) }))])),
      groupBy: Object.entries(GROUP_FIELDS).map(([id, f]) => ({ id, label: f.label, schemas: f.schemas })),
      sensors: [...sensors].sort().map((s) => ({ id: s, label: sensorLabel(s) })),
    },
    runs: reportJobs.list(p).map(summaryOf),
  });
});

reportsRouter.post("/run", jsonBody, (req, res) => {
  const p = readyProvider(res);
  if (!p) return;
  try {
    const checked = checkRequest(p, req.body as Parameters<typeof checkRequest>[1]);
    const run = reportJobs.start(p, checked, getSettings());
    res.status(202).json({ run: summaryOf(run) });
  } catch (err) {
    if (err instanceof ReportInputError) {
      res.status(/running already/.test(err.message) ? 429 : 400).json({ error: "bad_request", message: err.message });
      return;
    }
    throw err;
  }
});

function findRun(id: string, res: Response) {
  const p = readyProvider(res);
  if (!p) return null;
  const run = reportJobs.get(id, p);
  if (!run) {
    res.status(404).json({ error: "not_found", message: "No such report run. Runs are kept in memory until the toolkit restarts or the credential changes." });
    return null;
  }
  return run;
}

reportsRouter.get("/runs/:id", (req, res) => {
  const run = findRun(String(req.params.id), res);
  if (!run) return;
  res.json({ run: summaryOf(run), document: run.document });
});

reportsRouter.get("/runs/:id/pdf", (req, res) => {
  const run = findRun(String(req.params.id), res);
  if (!run) return;
  if (!run.document) {
    res.status(409).json({ error: "not_ready", message: "The report has not finished." });
    return;
  }
  const doc = run.document;
  const paper: Paper = req.query.paper === "letter" ? "letter" : "a4";
  const pdf = renderPdf(doc, { paper, csvName: (id) => exportName(doc, "csv", id) });
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", contentDisposition(req.query.inline === "1" ? "inline" : "attachment", exportName(doc, "pdf")));
  res.send(pdf);
});

reportsRouter.get("/runs/:id/csv/:table", (req, res) => {
  const run = findRun(String(req.params.id), res);
  if (!run) return;
  const table = run.document ? findTable(run.document, String(req.params.table)) : null;
  if (!run.document || !table) {
    res.status(404).json({ error: "not_found", message: "No such table in this report." });
    return;
  }
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", contentDisposition("attachment", exportName(run.document, "csv", table.id)));
  res.send(tableCsv(table, run.document.timeZone));
});
