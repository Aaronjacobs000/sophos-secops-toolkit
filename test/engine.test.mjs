import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fakeSophos, UUID } from "./helpers/fake-sophos.mjs";

const root = mkdtempSync(path.join(tmpdir(), "secops-engine-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { Engine, DATASET_SPECS } = await import("../backend/dist/services/engine.js");
const { EncryptedCache } = await import("../backend/dist/store/cache.js");
const { RateLimiter } = await import("../backend/dist/sophos/rate-limiter.js");
const { setQuiet } = await import("../backend/dist/log.js");
const { buildMsp, buildFront, scopeFor, screensFor } = await import("../backend/dist/services/views.js");
const { DEFAULT_SETTINGS } = await import("../backend/dist/store/settings.js");
const { ALLOWED_GRAPHQL_MUTATIONS } = await import("../backend/dist/sophos/guard.js");
setQuiet(true);
const SEARCH_DOCS = new Set(ALLOWED_GRAPHQL_MUTATIONS.values());

async function engineFor(kind, extra = {}) {
  const cache = new EncryptedCache(path.join(root, "data", `${kind}-${Math.random()}.db`));
  await cache.open();
  const fake = fakeSophos({ kind, ...extra });
  const engine = new Engine({ credentialId: `cred-${kind}`, label: `${kind} label`, clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: fake, autoSchedule: false, ...(extra.engine ?? {}) });
  await engine.start();
  return { engine, fake, cache };
}

async function runAll(engine) {
  for (const tenant of engine.tenants) {
    for (const spec of DATASET_SPECS) {
      if (spec.onDemand || !spec.applies(engine, tenant.id)) continue;
      await engine.run(spec, tenant.id);
    }
    for (const spec of DATASET_SPECS) if (!spec.onDemand && spec.applies(engine, tenant.id) && !engine.has(spec.name, tenant.id)) await engine.run(spec, tenant.id);
  }
}

function assertOnlyReads(requests) {
  for (const r of requests) {
    if (r.method === "GET") continue;
    if (r.method === "POST" && r.host === "id.sophos.com") continue;
    if (r.method === "POST" && r.path === "/xdr-query/v1/queries/runs") continue;
    if (r.method === "POST" && r.host === "api.taegis.sophos.com") {
      // The only mutations: the two search documents, exactly, with a QL text.
      if (SEARCH_DOCS.has(r.body?.query)) {
        assert.deepEqual(Object.keys(r.body.variables.input), ["text"]);
        continue;
      }
      assert.doesNotMatch(String(r.body?.query), /\bmutation\b/);
      continue;
    }
    assert.fail(`unexpected write: ${r.method} ${r.host}${r.path}`);
  }
}

test("a tenant credential is detected from whoami and read with X-Tenant-ID", async () => {
  const { engine, fake, cache } = await engineFor("tenant", { xdrOwnership: "securityOperations" });
  assert.equal(engine.status, "ready");
  assert.equal(engine.context.kind, "tenant");
  assert.equal(engine.tenants.length, 1);
  await runAll(engine);
  const t = engine.tenants[0].id;
  assert.equal(engine.get("generation", t).generation, "fusion");
  assert.equal(engine.get("endpoints", t).length, 2);
  assert.equal(engine.get("cases", t).api, "v2");
  assert.ok(engine.get("detections", t), "a Fusion tenant gets detections");
  assert.equal(engine.get("health", t).tamperDisabled, 1);
  const endpointCalls = fake.requests.filter((r) => r.path === "/endpoint/v1/endpoints");
  assert.ok(endpointCalls.every((r) => r.headers["x-tenant-id"] === t && r.host === "api-au01.central.sophos.com"));
  assertOnlyReads(fake.requests);
  engine.stop();
  cache.close();
});

test("a partner credential lists its tenants and reads each on its own regional host", async () => {
  const { engine, fake, cache } = await engineFor("partner");
  assert.equal(engine.context.kind, "partner");
  assert.equal(engine.context.multiTenant, true);
  assert.deepEqual(engine.tenants.map((t) => t.name), ["Tenant A", "Tenant B"]);
  assert.ok(fake.requests.some((r) => r.path === "/partner/v1/tenants" && r.headers["x-partner-id"]));
  await runAll(engine);
  const b = engine.tenants.find((t) => t.name === "Tenant B");
  assert.equal(engine.get("generation", b.id).generation, "classic");
  assert.equal(engine.get("cases", b.id).api, "v1", "a Classic tenant's cases come from cases v1");
  assert.equal(engine.get("detections", b.id), null, "no Fusion detections for a Classic tenant");
  assert.ok(fake.requests.some((r) => r.path === "/endpoint/v1/endpoints" && r.host === "api-us01.central.sophos.com" && r.headers["x-tenant-id"] === b.id));
  assertOnlyReads(fake.requests);
  const wall = buildMsp(engine, DEFAULT_SETTINGS, Date.now());
  assert.equal(wall.tiles.length, 2);
  assert.ok(wall.tiles.every((t) => t.state !== "pending"));
  const front = buildFront(engine, scopeFor(engine, "all"), DEFAULT_SETTINGS, 24);
  assert.equal(front.scope, "all");
  assert.equal(front.strip.endpoints.total, 4);
  engine.stop();
  cache.close();
});

test("the per-install tenant cap and the exclude list apply", async () => {
  const tenants = Array.from({ length: 5 }, (_, i) => ({ id: UUID(200 + i), name: `T${i}`, apiHost: "https://api-au01.central.sophos.com", dataRegion: "au01", billingType: "term", status: "active" }));
  const { engine, cache } = await engineFor("partner", { tenants, engine: { maxTenants: 3, excludeTenantIds: [UUID(200)] } });
  assert.equal(engine.tenants.length, 3);
  assert.ok(!engine.tenants.some((t) => t.id === UUID(200)), "an excluded tenant is skipped");
  assert.equal(engine.tenantsOverCap, 1);
  engine.stop();
  cache.close();
});

test("a refused credential leaves the engine in auth-failed without leaking the secret", async () => {
  const { engine, cache } = await engineFor("tenant", { badCredential: true });
  assert.equal(engine.status, "auth-failed");
  assert.doesNotMatch(engine.statusMessage, /fake-client-secret-5678/);
  engine.stop();
  cache.close();
});

test("every call goes through the shared limiter", async () => {
  const limiter = new RateLimiter({ perMinute: 80, perHour: 900 });
  const { engine, fake, cache } = await engineFor("partner", { engine: { limiter } });
  await runAll(engine);
  const apiCalls = fake.requests.filter((r) => r.host !== "id.sophos.com").length;
  assert.equal(limiter.total, apiCalls, "one limiter slot per Sophos API call");
  assert.ok(limiter.peakPerMinute() <= 80);
  engine.stop();
  cache.close();
});

test("the scheduler puts what is on screen first", async () => {
  const { engine, cache } = await engineFor("partner");
  const [a, b] = engine.tenants;
  await engine.run(DATASET_SPECS.find((s) => s.name === "generation"), a.id);
  await engine.run(DATASET_SPECS.find((s) => s.name === "generation"), b.id);
  engine.focus(["endpoints"], [b.id]);
  const due = engine.dueJobs();
  assert.equal(due[0].tenantId, b.id);
  assert.equal(due[0].spec.name, "endpoints");
  engine.stop();
  cache.close();
});

test("a Fusion tenant gets the Search views and S/MIME; every search is reused by its exact window", async () => {
  const { engine, fake, cache } = await engineFor("tenant", { xdrOwnership: "securityOperations", smimeCa: new Date(Date.now() + 10 * 86_400_000).toISOString() });
  await runAll(engine);
  const t = engine.tenants[0].id;
  const signins = engine.get("signins", t);
  assert.equal(signins.total, 100);
  assert.equal(signins.locations.length, 0, "no DB-IP file in tests, so nothing is placed");
  assert.equal(signins.placement.unplaced, 10);
  const mfa = engine.get("mfa", t);
  assert.equal(mfa.withoutMfa, 4);
  assert.deepEqual(mfa.topUsers.map((u) => u.user), ["user@example.com"]);
  assert.equal(engine.get("sources", t).sources[0].sensorType, "ENDPOINT_SOPHOS");
  assert.equal(engine.get("smime", t).ca.commonName, "Fake CA");
  const starts = fake.requests.filter((r) => r.host === "api.taegis.sophos.com" && /^mutation /.test(r.body?.query ?? ""));
  assert.equal(starts.length, 4, "sign-ins, MFA and its users search, data sources");
  assert.ok(starts.every((r) => r.body.query.startsWith("mutation GetOrCreateSearch")), "scheduled refreshes reuse a matching search");
  assert.ok(starts.every((r) => /earliest='\d{4}-\d{2}-\d{2}T\d{2}:(00|15|30|45):00Z' latest=/.test(r.body.variables.input.text)), "absolute quarter-hour bounds");
  assert.ok(fake.requests.filter((r) => r.path.startsWith("/email/v1/smime")).every((r) => r.method === "GET"));
  assertOnlyReads(fake.requests);
  engine.stop();
  cache.close();
});

test("Search jobs skip Classic tenants and refresh daily unless a screen shows the tenant", async () => {
  const { engine, cache } = await engineFor("partner");
  const [a, b] = engine.tenants;
  // Tenant A is on Fusion, tenant B is Classic.
  cache.put(`cred-partner:generation:${a.id}`, { generation: "fusion", xdrOwnership: "securityOperations" });
  cache.put(`cred-partner:generation:${b.id}`, { generation: "classic", xdrOwnership: "sophos" });
  const spec = (name) => DATASET_SPECS.find((x) => x.name === name);
  assert.equal(spec("signins").applies(engine, a.id), true);
  assert.equal(spec("signins").applies(engine, b.id), false);
  assert.equal(spec("smime").applies(engine, b.id), true, "S/MIME is a Central API and applies to every tenant");
  const DAY = 86_400_000;
  assert.equal(engine.intervalFor(spec("signins"), a.id), DAY);
  engine.setFastTenants([a.id]);
  assert.equal(engine.intervalFor(spec("signins"), a.id), DAY, "the MSP wall's worst tenants don't speed up Search");
  assert.equal(engine.intervalFor(spec("cases"), a.id), 5 * 60_000, "but they still speed up cases");
  engine.focus(["signins", "mfa"], [a.id]);
  assert.equal(engine.intervalFor(spec("signins"), a.id), 15 * 60_000, "on screen: every 15 minutes");
  assert.equal(engine.intervalFor(spec("sources"), a.id), DAY, "only the datasets on screen");
  const due = engine.dueJobs().filter((j) => j.spec.search);
  assert.ok(due.every((j) => j.tenantId === a.id), "nothing is searched on the Classic tenant");
  engine.stop();
  cache.close();
});

test("a search Sophos refuses marks the dataset no-access instead of retrying every few minutes", async () => {
  const { engine, cache } = await engineFor("tenant", { xdrOwnership: "securityOperations" });
  const t = engine.tenants[0].id;
  engine.core.search.run = async () => {
    const { SearchError } = await import("../backend/dist/vendor/sophos-core/index.js");
    throw new SearchError("Sophos refused the search: Sophos Fusion API error 403: Forbidden", "denied");
  };
  await engine.run(DATASET_SPECS.find((x) => x.name === "generation"), t);
  await engine.run(DATASET_SPECS.find((x) => x.name === "signins"), t);
  const row = engine.freshness([t], ["signins"])[0];
  assert.equal(row.noAccess, true);
  assert.match(row.lastError, /No access \(HTTP 403\)/);
  engine.stop();
  cache.close();
});

test("the Search screens drop out once every tenant is known to be Classic", async () => {
  const { engine, cache } = await engineFor("partner");
  assert.ok(screensFor(engine).includes("signins"), "kept while the API generation is unknown");
  for (const t of engine.tenants) await engine.run(DATASET_SPECS.find((x) => x.name === "generation"), t.id);
  assert.ok(engine.tenants.every((t) => engine.get("generation", t.id).generation === "classic"));
  assert.deepEqual(screensFor(engine), ["front", "msp", "now", "cases", "endpoints", "ai", "reports", "atlas"], "the AI usage board stays: AI Defense is not a Search screen");
  engine.stop();
  cache.close();
});

test("an engine stopped while it is still starting never polls Sophos", async () => {
  const cache = new EncryptedCache(path.join(root, "data", `stop-${Math.random()}.db`));
  await cache.open();
  const fake = fakeSophos({ kind: "partner" });
  let calls = 0;
  const slow = async (url, init) => {
    calls++;
    if (String(url).includes("/whoami/")) await new Promise((r) => setTimeout(r, 100));
    return fake(url, init);
  };
  const engine = new Engine({ credentialId: "cred-stop", label: "stop", clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: slow, tickMs: 10, retryBaseMs: 10 });
  const starting = engine.start();
  engine.stop(); // a credential switch while the tenant list is still loading
  await starting;
  const atStop = calls;
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(calls, atStop, "no call after the stop");
  assert.notEqual(engine.status, "ready");
  cache.close();
});

test("a start that fails on the network tries again by itself, and a refused credential does not", async () => {
  const cache = new EncryptedCache(path.join(root, "data", `retry-${Math.random()}.db`));
  await cache.open();
  const fake = fakeSophos({ kind: "tenant" });
  let whoami = 0;
  const flaky = async (url, init) => {
    if (String(url).includes("/whoami/") && ++whoami <= 2) return new Response("upstream unavailable", { status: 503 });
    return fake(url, init);
  };
  const engine = new Engine({ credentialId: "cred-retry", label: "retry", clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: flaky, tickMs: 60_000, retryBaseMs: 20 });
  await engine.start();
  assert.equal(engine.status, "error", "the first attempt fails");
  for (let i = 0; i < 50 && engine.status !== "ready"; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(engine.status, "ready", "and a later one connects");
  assert.equal(whoami, 3);
  engine.stop();

  const refused = async (url, init) => (String(url).includes("id.sophos.com") ? new Response('{"errorCode":"invalid_client"}', { status: 401 }) : fake(url, init));
  const denied = new Engine({ credentialId: "cred-denied", label: "denied", clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: refused, tickMs: 60_000, retryBaseMs: 20 });
  let tokens = 0;
  denied.on("status", () => tokens++);
  await denied.start();
  assert.equal(denied.status, "auth-failed");
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(tokens, 1, "no retry with a credential Sophos refused");
  denied.stop();
  cache.close();
});
