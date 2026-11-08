import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = mkdtempSync(path.join(tmpdir(), "secops-server-"));
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

test("pages carry a strict Content-Security-Policy and no-store API answers", async () => {
  const page = await fetch(`${base}/`);
  assert.equal(page.status, 200);
  const csp = page.headers.get("content-security-policy");
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /connect-src 'self'/);
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  const api = await fetch(`${base}/api/status`);
  assert.equal(api.headers.get("cache-control"), "no-store");
  const body = await api.json();
  assert.equal(body.demo, true);
  assert.equal(body.context.kind, "partner");
});

test("a page reaching the server by another host name gets nothing (DNS rebinding)", async () => {
  const { request } = await import("node:http");
  const status = await new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: server.address().port, path: "/api/status", headers: { Host: "evil.example.com" } }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on("error", reject);
    req.end();
  });
  assert.equal(status, 403);
});

test("changes are JSON only and from the toolkit's own origin", async () => {
  const form = await fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "privacy=true" });
  assert.equal(form.status, 415);
  const cross = await fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json", Origin: "https://evil.example.com" }, body: JSON.stringify({ privacy: true }) });
  assert.equal(cross.status, 403);
  const ok = await fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json", Origin: base }, body: JSON.stringify({ privacy: false }) });
  assert.equal(ok.status, 200);
});

test("every screen answers in demo mode", async () => {
  for (const view of ["front", "now", "cases", "endpoints", "msp", "signins", "sources"]) {
    const res = await fetch(`${base}/api/view/${view}`);
    assert.equal(res.status, 200, view);
    const body = await res.json();
    assert.equal(body.view, view);
  }
  const tenants = (await (await fetch(`${base}/api/tenants`)).json()).tenants;
  const one = await (await fetch(`${base}/api/view/endpoints?tenant=${tenants[0].id}`)).json();
  assert.equal(one.mapAvailable, true);
  assert.ok(one.summary.locations.length > 0, "demo devices are placed on the map");
});

test("the Search screens answer per tenant, and explain a Classic tenant", async () => {
  const tenants = (await (await fetch(`${base}/api/tenants`)).json()).tenants;
  const fusion = tenants.find((t) => t.generation === "fusion");
  const classic = tenants.find((t) => t.generation === "classic");
  const si = await (await fetch(`${base}/api/view/signins?tenant=${fusion.id}`)).json();
  assert.equal(si.model.tenantsWithData, 1);
  assert.ok(si.model.mfa.reportsMfa && si.model.mfa.withoutMfa > 0);
  assert.ok(si.model.locations.length > 0);
  const so = await (await fetch(`${base}/api/view/sources?tenant=${fusion.id}`)).json();
  assert.ok(so.model.rows.length > 0);
  const none = await (await fetch(`${base}/api/view/signins?tenant=${classic.id}`)).json();
  assert.equal(none.model.tenantsWithData, 0);
  assert.deepEqual(none.tenants, { fusion: 0, classic: 1, unknown: 0 });
  const status = await (await fetch(`${base}/api/status`)).json();
  assert.ok(status.context.views.includes("signins") && status.context.views.includes("sources"));
});

test("the AI usage board answers for every tenant and for one, and a tenant without AI Defense says why", async () => {
  const status = await (await fetch(`${base}/api/status`)).json();
  assert.ok(status.context.views.includes("ai"), "the board is offered");
  const all = await fetch(`${base}/api/view/ai`);
  assert.equal(all.status, 200);
  const body = await all.json();
  assert.equal(body.view, "ai");
  assert.equal(body.model.state, "active");
  assert.equal(body.model.tenantRows.length, body.tenantCount);
  const active = body.model.tenantRows.find((t) => t.state === "active");
  const one = await (await fetch(`${base}/api/view/ai?tenant=${active.tenantId}`)).json();
  assert.equal(one.model.state, "active");
  assert.ok(one.model.recent.length > 0);
  const notSetUp = body.model.tenantRows.find((t) => t.state === "not-set-up");
  const none = await (await fetch(`${base}/api/view/ai?tenant=${notSetUp.tenantId}`)).json();
  assert.equal(none.model.state, "not-set-up");
  assert.match(none.model.note, /not set up|not finished/);
  const wall = await (await fetch(`${base}/api/view/msp`)).json();
  assert.ok(wall.tiles.some((t) => t.ai?.state === "active" && t.ai.blocked > 0));
  assert.ok(wall.tiles.some((t) => t.ai?.text === "AI Defense not set up"));
});

test("S/MIME expiry shows on the MSP wall and the overview", async () => {
  const msp = await (await fetch(`${base}/api/view/msp`)).json();
  const smime = msp.tiles.filter((t) => t.reasons.some((r) => r.startsWith("S/MIME")));
  assert.ok(smime.some((t) => t.state === "critical" && t.reasons.includes("S/MIME internal CA expires in 5 days")));
  assert.ok(smime.some((t) => t.reasons.includes("S/MIME certificate expires in 12 days")));
  const front = await (await fetch(`${base}/api/view/front?tenant=all`)).json();
  assert.equal(front.strip.smime.level, "critical");
  assert.equal(front.strip.smime.soonest.days, 5);
});

test("privacy mode hides tenant names on lobby screens", async () => {
  await fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ privacy: true }) });
  const msp = await (await fetch(`${base}/api/view/msp`)).json();
  assert.ok(msp.tiles.every((t) => /^Tenant [0-9A-F]{6}$/.test(t.name)));
  assert.equal(new Set(msp.tiles.map((t) => t.name)).size, msp.tiles.length, "no two tenants share a stand-in name");
  const signins = await (await fetch(`${base}/api/view/signins`)).json();
  assert.ok(signins.model.mfa.topUsers.length > 0 && signins.model.mfa.topUsers.every((u) => /^User [0-9A-F]{6}$/.test(u.user) && /^Tenant [0-9A-F]{6}$/.test(u.tenantName)), "user names are hidden too");
  const front = await (await fetch(`${base}/api/view/front?tenant=all`)).json();
  assert.match(front.strip.smime.soonest.tenantName, /^Tenant [0-9A-F]{6}$/, "and the S/MIME tile's tenant");
  await fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ privacy: false }) });
});

test("adding a credential needs a client ID and secret", async () => {
  const res = await fetch(`${base}/api/credentials`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ clientId: "x" }) });
  assert.equal(res.status, 400);
});

test("the cache wipe asks for an explicit confirmation", async () => {
  const no = await fetch(`${base}/api/cache/wipe`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: "yes" }) });
  assert.equal(no.status, 400);
  const yes = await fetch(`${base}/api/cache/wipe`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirm: "wipe" }) });
  assert.equal(yes.status, 200);
  assert.deepEqual((await yes.json()).rows, { latest: 0, snapshots: 0 });
});

test("the Atlas snapshot ships with the app", async () => {
  const meta = await (await fetch(`${base}/data/atlas-meta.json`)).json();
  assert.equal(meta.fusion.schemas, 31);
  assert.equal(meta.fusion.topLevelFields, 1710);
  assert.equal(meta.datalake.tables, 225);
});

test("a bad request gets a 4xx answer and the server keeps running", async () => {
  const put = (body) => fetch(`${base}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body });
  // A playlist that is not a list used to throw inside an async handler, which stopped the server.
  const odd = await put(JSON.stringify({ wall: { playlist: "front" } }));
  assert.equal(odd.status, 200);
  assert.ok(Array.isArray((await odd.json()).settings.wall.playlist), "the saved playlist is still a list");
  const broken = await put("{ not json");
  assert.equal(broken.status, 400, "malformed JSON is the caller's mistake, not a 500");
  assert.equal((await fetch(`${base}/api/status`)).status, 200, "and the server still answers");
});

test("activating an unknown credential changes nothing", async () => {
  const before = await (await fetch(`${base}/api/status`)).json();
  const res = await fetch(`${base}/api/credentials/no-such-id/activate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  assert.equal(res.status, 404);
  const after = await (await fetch(`${base}/api/status`)).json();
  assert.deepEqual([after.configured, after.demo, after.activeCredentialId], [before.configured, before.demo, before.activeCredentialId]);
});

test("the API refuses requests another website's page sends", async () => {
  for (const site of ["cross-site", "same-site"]) {
    const res = await fetch(`${base}/api/view/front`, { headers: { "Sec-Fetch-Site": site } });
    assert.equal(res.status, 403, site);
  }
  for (const site of ["same-origin", "none"]) {
    const res = await fetch(`${base}/api/status`, { headers: { "Sec-Fetch-Site": site } });
    assert.equal(res.status, 200, site);
  }
});
