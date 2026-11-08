#!/usr/bin/env node
// Runs a report with no server and no page, and writes its PDF and CSV files:
// the path a scheduler would take. Demo data only from the command line;
// live reports run inside the server, which holds the credential and the cache.
//
//   npm run build
//   node scripts/report.mjs --report executive --context partner --tenant all --window 7d --out ./out
//   node scripts/report.mjs --report user --context tenant --param user=m.nguyen --out ./out
//   node scripts/report.mjs --list

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    report: { type: "string" },
    context: { type: "string", default: "partner" },
    tenant: { type: "string" },
    window: { type: "string" },
    param: { type: "string", multiple: true, default: [] },
    tz: { type: "string" },
    paper: { type: "string", default: "a4" },
    out: { type: "string", default: "." },
    list: { type: "boolean", default: false },
  },
});

const dist = new URL("../backend/dist/", import.meta.url);
const { DemoProvider } = await import(new URL("demo/demo-provider.js", dist));
const { REPORTS } = await import(new URL("reports/catalogue.js", dist));
const { checkRequest, runReport } = await import(new URL("reports/runner.js", dist));
const { DemoReportSource } = await import(new URL("reports/demo.js", dist));
const { renderPdf } = await import(new URL("reports/pdf/render.js", dist));
const { exportName, tableCsv, tableIds, findTable } = await import(new URL("reports/csv.js", dist));
const { DEFAULT_SETTINGS } = await import(new URL("store/settings.js", dist));

if (values.list) {
  for (const r of REPORTS) console.log(`${r.id.padEnd(12)} ${r.title}${r.windows ? ` (${r.windows.map((w) => w.key).join(", ")})` : ""}`);
  process.exit(0);
}
if (!values.report) {
  console.error("Name a report with --report (see --list).");
  process.exit(2);
}

const provider = new DemoProvider(values.context === "tenant" ? "tenant" : "partner");
const params = {};
for (const p of values.param) {
  const i = p.indexOf("=");
  if (i < 1) continue;
  const key = p.slice(0, i);
  const value = p.slice(i + 1);
  params[key] = key === "schemas" || key === "sensors" ? value.split(",").filter(Boolean) : value;
}
let tenant = values.tenant;
if (tenant && tenant !== "all" && !provider.tenant(tenant)) tenant = provider.tenants.find((t) => t.name.toLowerCase().includes(tenant.toLowerCase()))?.id ?? tenant;
try {
  const checked = checkRequest(provider, { reportId: values.report, tenant, window: values.window, timeZone: values.tz, params });
  const doc = await runReport(checked, { source: new DemoReportSource(provider), settings: DEFAULT_SETTINGS, progress: (s) => console.error(`  ${s}`) });
  mkdirSync(values.out, { recursive: true });
  const pdfPath = path.join(values.out, exportName(doc, "pdf"));
  writeFileSync(pdfPath, renderPdf(doc, { paper: values.paper === "letter" ? "letter" : "a4", csvName: (id) => exportName(doc, "csv", id) }));
  console.log(pdfPath);
  for (const id of tableIds(doc)) {
    const file = path.join(values.out, exportName(doc, "csv", id));
    writeFileSync(file, tableCsv(findTable(doc, id), doc.timeZone));
    console.log(file);
  }
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
} finally {
  provider.stop();
}
