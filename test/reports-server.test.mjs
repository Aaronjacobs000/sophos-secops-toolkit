import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = mkdtempSync(path.join(tmpdir(), "secops-reports-server-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");
delete process.env.HOST;
delete process.env.ALLOWED_IPS;

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { setRepoRoot } = await import("../backend/dist/store/paths.js");
setRepoRoot(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."));
const { createApp } = await import("../backend/dist/server.js");
const { networkSettings } = await import("../backend/dist/config/network.js");
const { initState, shutdown } = await import("../backend/dist/state.js");

await initState({ demo: true });
const app = createApp(networkSettings({}));
const server = await new Promise((resolve) => {
  const s = app.listen(0, "127.0.0.1", () => resolve(s));
});
const base = `http://127.0.0.1:${server.address().port}`;
test.after(() => {
  server.close();
  shutdown();
});

const json = (body) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

async function finished(id) {
  for (let i = 0; i < 100; i++) {
    const r = await (await fetch(`${base}/api/reports/runs/${id}`)).json();
    if (r.run.status !== "running") return r;
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error("the run did not finish");
}

test("the Reports screen is offered and its catalogue answers in demo mode", async () => {
  const status = await (await fetch(`${base}/api/status`)).json();
  assert.ok(status.context.views.includes("reports"));
  const cat = await (await fetch(`${base}/api/reports`)).json();
  assert.equal(cat.reports.length, 8);
  assert.ok(cat.notBuilt.length >= 3);
  assert.equal(cat.multi, true);
  assert.ok(cat.logSearch.schemas.user.length === 19 && cat.logSearch.schemas.ip.length === 17 && cat.logSearch.schemas.host.length === 13);
  assert.ok(cat.logSearch.sensors.length > 0, "the sources the Sources screen has seen");
});

test("a run starts, finishes, and exports a PDF and every table as CSV", async () => {
  const cat = await (await fetch(`${base}/api/reports`)).json();
  const fusion = cat.tenants.find((t) => t.generation === "fusion");
  const start = await fetch(`${base}/api/reports/run`, json({ reportId: "user", tenant: fusion.id, window: "7d", timeZone: "Australia/Sydney", params: { user: "k.walsh" } }));
  assert.equal(start.status, 202);
  const { run } = await start.json();
  const done = await finished(run.id);
  assert.equal(done.run.status, "done");
  assert.match(done.document.subject, /k\.walsh@/);
  const pdf = await fetch(`${base}/api/reports/runs/${run.id}/pdf?paper=letter`);
  assert.equal(pdf.headers.get("content-type"), "application/pdf");
  assert.match(pdf.headers.get("content-disposition"), /^attachment; filename="secops-user-investigation-[\w.@-]+\.pdf"$/);
  assert.equal(pdf.headers.get("cache-control"), "no-store", "tenant data is never cached by the browser");
  const bytes = Buffer.from(await pdf.arrayBuffer());
  assert.equal(bytes.subarray(0, 8).toString("latin1"), "%PDF-1.7");
  assert.match(bytes.toString("latin1"), /\/MediaBox \[0 0 612 792\]/, "US Letter when asked");
  for (const s of done.document.sections) {
    for (const b of s.blocks.filter((x) => x.kind === "table")) {
      const csv = await fetch(`${base}/api/reports/runs/${run.id}/csv/${b.id}`);
      assert.equal(csv.status, 200, b.id);
      assert.equal(csv.headers.get("content-type"), "text/csv; charset=utf-8");
      const text = await csv.text();
      assert.equal(text.split("\r\n").filter(Boolean).length, b.rows.length + 1, `${b.id}: a header and every row`);
    }
  }
  assert.equal((await fetch(`${base}/api/reports/runs/${run.id}/csv/nope`)).status, 404);
  const listed = await (await fetch(`${base}/api/reports`)).json();
  assert.ok(listed.runs.some((r) => r.id === run.id && r.status === "done"));
});

test("a request a report can't run is refused before anything starts", async () => {
  const bad = [
    [{ reportId: "user", tenant: "all", params: { user: "k.walsh" } }, /one tenant/],
    [{ reportId: "executive", tenant: "all", window: "30d" }, /every tenant/],
    [{ reportId: "nope" }, /No such report/],
  ];
  for (const [body, message] of bad) {
    const res = await fetch(`${base}/api/reports/run`, json(body));
    assert.equal(res.status, 400);
    assert.match((await res.json()).message, message);
  }
  const cat = await (await fetch(`${base}/api/reports`)).json();
  const fusion = cat.tenants.find((t) => t.generation === "fusion");
  const quoted = await fetch(`${base}/api/reports/run`, json({ reportId: "user", tenant: fusion.id, params: { user: "x' or '1'='1" } }));
  assert.equal(quoted.status, 400);
  assert.match((await quoted.json()).message, /Quotes and backslashes are not accepted/);
  const ip = await fetch(`${base}/api/reports/run`, json({ reportId: "logsearch", tenant: fusion.id, window: "24h", params: { match: "ip", value: "203.0.113.7' or '" } }));
  assert.equal(ip.status, 400);
});

test("starting a run is a local write: JSON only, from the toolkit's own page", async () => {
  const form = await fetch(`${base}/api/reports/run`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "reportId=cases" });
  assert.equal(form.status, 415);
  const cross = await fetch(`${base}/api/reports/run`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://evil.example.com" }, body: JSON.stringify({ reportId: "cases" }) });
  assert.equal(cross.status, 403);
  assert.equal((await fetch(`${base}/api/reports/runs/00000000-0000-4000-a000-000000000000`)).status, 404);
});
