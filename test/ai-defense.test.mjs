import test from "node:test";
import assert from "node:assert/strict";
import { assertReadOnly, EXACT_GRAPHQL_QUERIES, ReadOnlyViolationError } from "../backend/dist/sophos/guard.js";
import { AI_DEFENSE_OVERVIEW, AI_DEFENSE_DETAIL, AI_DEFENSE_POLICIES } from "../backend/dist/vendor/sophos-core/fusion/queries/ai-defense.js";

const GQL = "https://api.taegis.sophos.com/graphql";
const post = (query, variables = { timeRange: { startTime: "2026-11-01T00:00:00Z", endTime: "2026-11-08T00:00:00Z" } }) => ({ method: "POST", body: JSON.stringify({ query, variables }) });

// ------------------------------------------------------------------ guard

test("the AI Defense reads pass the guard only as their exact documents, which match the client's copies", () => {
  const docs = { ToolkitAiDefenseOverview: AI_DEFENSE_OVERVIEW, ToolkitAiDefenseDetail: AI_DEFENSE_DETAIL, ToolkitAiDefensePolicies: AI_DEFENSE_POLICIES };
  for (const [name, doc] of Object.entries(docs)) {
    assert.equal(EXACT_GRAPHQL_QUERIES.get(name), doc, `${name}: guard and client copies must match character for character`);
    assert.match(doc, new RegExp(`^query ${name}\\b`));
    assertReadOnly(GQL, post(doc));
  }
  // No document selects the field the list nulls, or the settings mutation.
  for (const doc of Object.values(docs)) {
    assert.doesNotMatch(doc, /additionalData|updateSecureAITenantSettings|\bmutation\b/);
  }
});

test("near misses of the AI Defense documents and every AI Defense write are refused", () => {
  const nearMisses = [
    AI_DEFENSE_OVERVIEW + "\n",
    " " + AI_DEFENSE_OVERVIEW,
    AI_DEFENSE_OVERVIEW.replace("licenseState", "licenseState\n    licenseId"),
    AI_DEFENSE_DETAIL.replace("first: 50", "first: 100"),
    AI_DEFENSE_DETAIL.replace("aggregationCount", "aggregationCount\n      additionalData"),
    AI_DEFENSE_POLICIES.replace("failedCount", "failedCount policies { id name rules { action } }"),
    "query ToolkitAiDefenseOverview { secureAITenantSettings { licenseState } }",
    "query ToolkitAiDefensePolicies { policies(first: 1) { totalCount } }",
  ];
  for (const doc of nearMisses) assert.throws(() => assertReadOnly(GQL, post(doc)), ReadOnlyViolationError, JSON.stringify(doc.slice(0, 60)));
  // The MCP server's broader documents are not on the allowlist, and writes never pass.
  for (const doc of [
    "query FusionAiDefenseActivities($filter: SecureAiActivityFilter) { activities(filter: $filter) { totalCount } }",
    "query FusionAiDefenseTenantSettings { secureAITenantSettings { licenseState } }",
    "mutation FusionAiDefenseUpdateTenantSettings($input: SecureAIUpdateTenantSettingsInput!) { updateSecureAITenantSettings(input: $input) { licenseState } }",
    "mutation ToolkitAiDefenseOverview { updateSecureAITenantSettings(input: {}) { licenseState } }",
    "mutation FusionAiDefenseDeletePolicy($id: ID!) { deletePolicy(id: $id) { id } }",
    AI_DEFENSE_POLICIES + "\nmutation X { disablePolicy(id: \"x\") { id } }",
  ]) {
    assert.throws(() => assertReadOnly(GQL, post(doc)), ReadOnlyViolationError, doc.slice(0, 60));
  }
});

// ------------------------------------------------------------------ reads, states and views

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { aiDefenseAnswer, fakeSophos, UUID } from "./helpers/fake-sophos.mjs";

const root = mkdtempSync(path.join(tmpdir(), "secops-ai-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { createSophosCore, buildTimeRange } = await import("../backend/dist/vendor/sophos-core/index.js");
const { createGuardedFetch } = await import("../backend/dist/sophos/guard.js");
const { RateLimiter } = await import("../backend/dist/sophos/rate-limiter.js");
const { fetchAiDefense } = await import("../backend/dist/data/fetchers.js");
const { aiDefenseWindow, aiDefenseView, aiTile } = await import("../backend/dist/mappers/ai-defense.js");
const { tenantTile } = await import("../backend/dist/mappers/views.js");
const { Engine, DATASET_SPECS } = await import("../backend/dist/services/engine.js");
const { EncryptedCache } = await import("../backend/dist/store/cache.js");
const { buildAi, buildMsp, scopeFor } = await import("../backend/dist/services/views.js");
const { DEFAULT_SETTINGS, VIEWS } = await import("../backend/dist/store/settings.js");
const { DemoProvider } = await import("../backend/dist/demo/demo-provider.js");

const NOW = Date.parse("2026-11-08T02:17:45Z");
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** A real core behind the real guard, talking to a fake Fusion that answers AI Defense reads in `mode`. */
function aiCore(mode, onRequest = () => {}) {
  const requests = [];
  const baseFetch = async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname === "id.sophos.com") return new Response(JSON.stringify({ access_token: "fake-token", token_type: "bearer", expires_in: 3600, errorCode: "success" }), { status: 200 });
    const body = JSON.parse(init.body);
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    requests.push({ operation: /^query (\w+)/.exec(body.query)?.[1], variables: body.variables, tenant: headers["x-tenant-id"] });
    const answer = onRequest(body) ?? aiDefenseAnswer(body.query, mode, body.variables);
    if (answer instanceof Response) return answer;
    return new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const core = createSophosCore({ clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", fetch: createGuardedFetch({ limiter: new RateLimiter(), baseFetch }) });
  return { core, requests };
}

test("the AI Defense window is the last 7 days to the minute, and a relative preset can't be mixed with absolute bounds", () => {
  const w = aiDefenseWindow(NOW);
  assert.equal(w.end, Date.parse("2026-11-08T02:17:00Z"));
  assert.equal(w.end - w.start, 7 * DAY);
  assert.deepEqual(buildTimeRange({ startTime: "2026-11-01T02:17:00Z", endTime: "2026-11-08T02:17:00Z" }), { startTime: "2026-11-01T02:17:00Z", endTime: "2026-11-08T02:17:00Z" });
  assert.deepEqual(buildTimeRange({ relative: "LAST_MONTH" }), { relative: "LAST_MONTH" });
  assert.equal(buildTimeRange({}), undefined);
  assert.throws(() => buildTimeRange({ relative: "LAST_MONTH", startTime: "2026-11-01T00:00:00Z" }), /not both/);
});

test("a tenant with AI Defense: four reads through the guard, blocked and warned by risk, the rest of each total as unknown", async () => {
  const { core, requests } = aiCore("active");
  const r = await fetchAiDefense(core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.deepEqual(requests.map((q) => q.operation), ["ToolkitAiDefenseOverview", "ToolkitAiDefensePolicies", "ToolkitAiDefenseDetail", "ToolkitAiDefenseFlow"]);
  assert.ok(requests.every((q) => q.tenant === "t-1"));
  for (const q of requests.filter((x) => x.operation !== "ToolkitAiDefensePolicies" && x.operation !== "ToolkitAiDefenseFlow")) {
    assert.deepEqual(q.variables, { timeRange: { startTime: "2026-11-01T02:17:00.000Z", endTime: "2026-11-08T02:17:00.000Z" } }, "always an absolute window: with none, Sophos reads since 00:00 UTC");
  }
  assert.equal(r.state, "active");
  assert.equal(r.note, null);
  assert.equal(r.calls, 4);
  assert.deepEqual(r.activity, { total: 5000, unsanctioned: 40, blocked: 410, warned: 900, blockedByRisk: { critical: 300, high: 50, medium: 0, low: 50, info: 0, unknown: 10 }, warnedByRisk: { critical: 20, high: 0, medium: 0, low: 870, info: 0, unknown: 10 } });
  assert.deepEqual(r.apps, { total: 12, byRisk: { critical: 2, high: 1, medium: 1, low: 7, info: 0, unknown: 1 }, trainsOnData: 3, unsanctioned: 2 });
  assert.deepEqual(r.users, { total: 30, byRisk: { critical: 2, high: 3, medium: 0, low: 25, info: 0, unknown: 0 }, withViolations: 5, unsanctioned: 4 });
  assert.deepEqual(r.policies, { total: 5, enabled: 2, failed: 1 });
  assert.deepEqual(r.licence, { state: "ACTIVE", type: "TERM", expiresAt: "2030-01-31T23:59:59.999Z", graceEndsAt: "2030-03-01T23:59:59.999Z" });
  assert.deepEqual(r.topApps.map((a) => [a.name, a.risk, a.usage, a.users]), [["ChatGPT", "low", 2100, 22], ["DeepSeek", "critical", 310, 3], ["New App", "unknown", 4, 1]]);
  assert.equal(r.topUsers[0].name, "pat@corp.example");
  assert.equal(r.topUsers[0].violations, 320);
  assert.deepEqual(r.recent.map((a) => [a.action, a.risk, a.app, a.user, a.count]), [["blocked", "critical", "DeepSeek", "pat@corp.example", 3], ["warned", "low", "ChatGPT", "", 1]], "an allowed row is never listed as blocked or warned");
  assert.equal(r.recent[0].at, Date.parse("2026-11-08T01:00:00.5Z"));
  assert.equal(r.recentOf, 1310);
});

test("a tenant that never set AI Defense up is not set up, costs one call, and is not an error", async () => {
  const { core, requests } = aiCore("none");
  const r = await fetchAiDefense(core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.equal(requests.length, 1, "no detail or policy reads for a tenant with nothing to show");
  assert.equal(r.state, "not-set-up");
  assert.match(r.note, /not set up/);
  assert.equal(r.activity.total, 0);
  assert.deepEqual(r.topApps, []);
});

test("an expired licence reads as not licensed, and a tenant Fusion does not hold as not on Fusion", async () => {
  const expired = await fetchAiDefense(aiCore("expired").core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.equal(expired.state, "not-licensed");
  assert.match(expired.note, /licence expired/i);
  const notHeld = aiCore("none", () => new Response(JSON.stringify({ message: "error invoking downstream api\ntenantsv4.APIClient.GetTenant: input:1:30: tenant t-1 not found or not accessible" }), { status: 503 }));
  const r = await fetchAiDefense(notHeld.core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.equal(r.state, "unavailable");
  assert.match(r.note, /Sophos Fusion/);
  assert.equal(notHeld.requests.length, 1, "the 503 is not retried");
});

test("a refused AI Defense read is no access, not a retry loop; a refused policy count leaves the rest standing", async () => {
  await assert.rejects(fetchAiDefense(aiCore("denied").core, "t-1", aiDefenseWindow(NOW), NOW), (err) => err.noAccess === true && /permission/.test(err.message));
  const forbidden = aiCore("none", () => new Response(JSON.stringify({ message: "Forbidden" }), { status: 403 }));
  await assert.rejects(fetchAiDefense(forbidden.core, "t-1", aiDefenseWindow(NOW), NOW), (err) => err.noAccess === true);
  const r = await fetchAiDefense(aiCore("policies-denied").core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.equal(r.state, "active");
  assert.equal(r.policies, null);
  assert.ok(r.warnings.some((w) => /policies/i.test(w)));
});

async function record(mode) {
  return fetchAiDefense(aiCore(mode).core, "t-1", aiDefenseWindow(NOW), NOW);
}

test("the AI usage board for one tenant: totals, risks, top apps and users, the newest blocked and warned", async () => {
  const r = await record("active");
  const v = aiDefenseView([{ tenantId: "t-1", record: r }]);
  assert.equal(v.state, "active");
  assert.equal(v.activity.blocked, 410);
  assert.deepEqual(v.risks.map((x) => [x.risk, x.blocked, x.warned]), [["critical", 300, 20], ["high", 50, 0], ["medium", 0, 0], ["low", 50, 870], ["info", 0, 0], ["unknown", 10, 10]]);
  assert.deepEqual(v.topApps.map((a) => a.id), ["chatgpt", "deepseek", "newapp"]);
  assert.equal(v.licence.state, "ACTIVE");
  assert.deepEqual(v.policies, { total: 5, enabled: 2, failed: 1 });
  assert.equal(v.recent.length, 2);
  const masked = aiDefenseView([{ tenantId: "t-1", record: r }], true);
  assert.match(masked.topUsers[0].name, /^User [0-9A-F]{6}$/);
  assert.match(masked.recent[0].user, /^User [0-9A-F]{6}$/);
  assert.match(masked.recent[0].device, /^Device [0-9A-F]{6}$/);
  assert.equal(masked.recent[1].user, "", "an empty name stays empty");
  for (const [mode, state] of [["none", "not-set-up"], ["expired", "not-licensed"]]) {
    const one = aiDefenseView([{ tenantId: "t-1", record: await record(mode) }]);
    assert.equal(one.state, state);
    assert.ok(one.note);
  }
  assert.equal(aiDefenseView([{ tenantId: "t-1", record: null }]).state, "pending");
  assert.equal(aiDefenseView([{ tenantId: "t-1", record: null, noAccess: true }]).state, "no-access");
});

test("all tenants: figures add up across the tenants with AI Defense, apps merge by id, and every tenant has a row", async () => {
  const active = await record("active");
  const none = await record("none");
  const v = aiDefenseView([
    { tenantId: "a", tenantName: "Tenant A", record: active },
    { tenantId: "b", tenantName: "Tenant B", record: active },
    { tenantId: "c", tenantName: "Tenant C", record: none },
    { tenantId: "d", tenantName: "Tenant D", record: null },
  ]);
  assert.equal(v.state, "active");
  assert.deepEqual(v.scope, { tenants: 4, active: 2, notSetUp: 1, notLicensed: 0, unavailable: 0, pending: 1, noAccess: 0 });
  assert.equal(v.activity.total, 10_000);
  assert.equal(v.apps.total, 24, "apps are counted per tenant");
  assert.equal(v.topApps[0].usage, 4200);
  assert.equal(v.topApps[0].tenants, 2);
  assert.equal(v.topUsers[0].tenantName, "Tenant A");
  assert.deepEqual(v.tenantRows.map((t) => [t.name, t.state]), [["Tenant A", "active"], ["Tenant B", "active"], ["Tenant C", "not-set-up"], ["Tenant D", "pending"]]);
  const nobody = aiDefenseView([{ tenantId: "c", tenantName: "Tenant C", record: none }]);
  assert.equal(nobody.state, "not-set-up");
  const nobodyOfTwo = aiDefenseView([{ tenantId: "c", tenantName: "Tenant C", record: none }, { tenantId: "e", tenantName: "Tenant E", record: { ...none, state: "unavailable", note: "x" } }]);
  assert.equal(nobodyOfTwo.state, "none", "no tenant here has AI Defense");
});

test("the MSP wall line: inventory and blocked and warned counts, or a plain not set up, never an error", async () => {
  assert.deepEqual(aiTile(await record("active")), { state: "active", text: "12 AI apps · 30 users", apps: 12, users: 30, blocked: 410, warned: 900 });
  assert.deepEqual(aiTile(await record("none")), { state: "not-set-up", text: "AI Defense not set up", apps: null, users: null, blocked: null, warned: null });
  assert.equal(aiTile(await record("expired")).text, "AI Defense licence expired");
  assert.equal(aiTile(null), null, "nothing until the first read");
  assert.equal(aiTile(null, true).text, "AI Defense: no access");
  const tenant = { id: "t-1", name: "Tenant A", apiHost: "", dataRegion: "au01", billingType: null, status: null, products: [], city: null, countryCode: null };
  const base = { tenant, generation: "fusion", cases: { api: "v2", open: [], recentClosed: [], truncated: false, warnings: [] }, endpoints: [], health: null, licences: [], alerts: null, fetchedAt: NOW, errors: 0 };
  const without = tenantTile(base, NOW);
  const withAi = tenantTile({ ...base, aiDefense: await record("active") }, NOW);
  assert.equal(withAi.ai.blocked, 410);
  assert.equal(withAi.state, without.state, "AI Defense figures inform the tile; they don't change its state");
  assert.equal(withAi.score, without.score);
});

async function aiEngine(kind, aiDefense) {
  const cache = new EncryptedCache(path.join(root, "data", `${kind}-${Math.random()}.db`));
  await cache.open();
  const fake = fakeSophos({ kind, aiDefense });
  const engine = new Engine({ credentialId: `cred-${kind}`, label: `${kind} label`, clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: fake, autoSchedule: false });
  await engine.start();
  return { engine, fake, cache };
}

test("AI Defense refreshes every 15 min for one tenant, hourly for a partner's others, and daily where it is not set up", async () => {
  const spec = DATASET_SPECS.find((s) => s.name === "aidefense");
  assert.ok(spec, "an aidefense dataset");
  const single = await aiEngine("tenant", "active");
  const t = single.engine.tenants[0].id;
  assert.equal(spec.applies(single.engine, t), true);
  await single.engine.run(spec, t);
  assert.equal(single.engine.get("aidefense", t).state, "active");
  assert.equal(single.engine.intervalFor(spec, t), 15 * MIN);
  single.engine.stop();
  single.cache.close();

  const partner = await aiEngine("partner", "none");
  const [a, b] = partner.engine.tenants;
  await partner.engine.run(spec, a.id);
  await partner.engine.run(spec, b.id);
  assert.equal(partner.engine.get("aidefense", a.id).state, "not-set-up");
  assert.equal(partner.engine.intervalFor(spec, a.id), DAY, "a tenant without AI Defense is checked daily");
  partner.engine.focus(["aidefense"], [a.id]);
  assert.equal(partner.engine.intervalFor(spec, a.id), HOUR, "hourly while a screen shows it");
  partner.cache.put(`cred-partner:aidefense:${b.id}`, { ...partner.engine.get("aidefense", b.id), state: "active" });
  assert.equal(partner.engine.intervalFor(spec, b.id), HOUR);
  partner.engine.setFastTenants([b.id]);
  assert.equal(partner.engine.intervalFor(spec, b.id), 15 * MIN);
  const ai = partner.fake.requests.filter((r) => /^query ToolkitAiDefense/.test(r.body?.query ?? ""));
  assert.equal(ai.length, 2, "one call for each tenant without AI Defense");
  partner.engine.stop();
  partner.cache.close();
});

test("a refused AI Defense read marks the dataset no access, and the wall says so instead of showing an error", async () => {
  const { engine, cache } = await aiEngine("partner", "denied");
  const spec = DATASET_SPECS.find((s) => s.name === "aidefense");
  const [a] = engine.tenants;
  await engine.run(spec, a.id);
  const row = engine.freshness([a.id], ["aidefense"])[0];
  assert.equal(row.noAccess, true);
  assert.match(row.lastError, /No access/);
  const wall = buildMsp(engine, DEFAULT_SETTINGS, Date.now());
  assert.equal(wall.tiles.find((x) => x.id === a.id).ai.text, "AI Defense: no access");
  const board = buildAi(engine, scopeFor(engine, a.id), DEFAULT_SETTINGS, Date.now());
  assert.equal(board.model.state, "no-access");
  engine.stop();
  cache.close();
});

test("demo mode has an AI usage board for one tenant and a partner estate with every state", () => {
  const single = new DemoProvider("tenant", NOW);
  const t = single.tenants[0].id;
  assert.ok(single.context.views.includes("ai"));
  const one = buildAi(single, scopeFor(single, t), DEFAULT_SETTINGS, NOW);
  assert.equal(one.view, "ai");
  assert.equal(one.model.state, "active");
  assert.ok(one.model.activity.blocked > 0 && one.model.activity.warned > 0);
  assert.ok(one.model.topApps.length >= 8 && one.model.topUsers.length >= 8 && one.model.recent.length >= 20);
  single.stop();
  const partner = new DemoProvider("partner", NOW);
  const all = buildAi(partner, scopeFor(partner, "all"), DEFAULT_SETTINGS, NOW);
  const s = all.model.scope;
  assert.ok(s.active >= 5 && s.notSetUp >= 5 && s.notLicensed >= 1 && s.unavailable >= 1, JSON.stringify(s));
  assert.equal(all.model.tenantRows.length, partner.tenants.length);
  const wall = buildMsp(partner, DEFAULT_SETTINGS, NOW);
  assert.ok(wall.tiles.every((x) => x.ai && x.ai.text), "every demo tile has an AI Defense line");
  partner.stop();
  assert.ok(VIEWS.includes("ai"), "the board can go in the wall playlist");
  assert.ok(DEFAULT_SETTINGS.wall.playlist.includes("ai"));
});

// ------------------------------------------------------------------ executive summary

const { checkRequest, runReport } = await import("../backend/dist/reports/runner.js");
const { DemoReportSource } = await import("../backend/dist/reports/demo.js");
const { findTable, tableCsv } = await import("../backend/dist/reports/csv.js");
const { renderPdf } = await import("../backend/dist/reports/pdf/render.js");
const { reportDefinition } = await import("../backend/dist/reports/catalogue.js");

async function executive(context, tenantPick = () => "all") {
  const provider = new DemoProvider(context);
  try {
    const tenant = tenantPick(provider);
    const checked = checkRequest(provider, { reportId: "executive", tenant, window: "7d", timeZone: "Australia/Sydney" });
    return await runReport(checked, { source: new DemoReportSource(provider), settings: DEFAULT_SETTINGS });
  } finally {
    provider.stop();
  }
}

const aiSection = (doc) => doc.sections.find((s) => s.id === "ai");

test("the executive summary has an AI Defense section: blocked and warned by risk, top apps and users, a row per tenant", async () => {
  const doc = await executive("partner");
  const s = aiSection(doc);
  assert.ok(s, "an AI Defense section");
  assert.equal(s.title, "AI Defense");
  const series = s.blocks.find((b) => b.kind === "series");
  assert.deepEqual(series.series.map((x) => [x.key, x.tone]), [["blocked", "bad"], ["warned", "warn"]]);
  assert.deepEqual(series.buckets.slice(0, 4).map((b) => b.label), ["Critical", "High", "Medium", "Low"]);
  const kpis = s.blocks.find((b) => b.kind === "kpis").items;
  const blocked = Number(kpis.find((k) => k.label === "Blocked").value.replace(/,/g, ""));
  assert.equal(series.buckets.reduce((a, b) => a + b.values[0], 0), blocked, "the risk buckets add up to the blocked total");
  const apps = findTable(doc, "ai-apps");
  assert.ok(apps.rows.length >= 5);
  assert.ok(apps.columns.some((c) => c.key === "tenants"), "all tenants: how many tenants use each app");
  assert.match(tableCsv(apps, doc.timeZone), /^﻿App,Provider,Risk,Activity,Users,Unsanctioned,Tenants\r\n/);
  assert.ok(findTable(doc, "ai-users").rows.every((r) => r.tenant), "all tenants: each user's tenant");
  const tenants = findTable(doc, "ai-tenants");
  assert.equal(tenants.rows.length, 40);
  assert.ok(tenants.rows.some((r) => r.state === "Not set up") && tenants.rows.some((r) => r.state === "Licence expired") && tenants.rows.some((r) => r.state === "Not on Sophos Fusion"));
  assert.ok(doc.provenance.some((p) => p.label === "AI Defense"));
  assert.ok(renderPdf(doc, { paper: "a4" }).length > 1000, "the PDF renders with the section");
  assert.match(reportDefinition("executive").summary, /AI/);
});

test("the executive summary for one tenant with AI Defense lists its apps and users; without it, one plain line", async () => {
  const one = await executive("tenant", (p) => p.tenants[0].id);
  const s = aiSection(one);
  assert.ok(findTable(one, "ai-apps").rows.length >= 8);
  assert.ok(!findTable(one, "ai-apps").columns.some((c) => c.key === "tenants"));
  assert.equal(findTable(one, "ai-tenants"), null);
  assert.ok(s.blocks.some((b) => b.kind === "facts" && b.items.some((i) => i.label === "Policies")));
  const none = await executive("partner", (p) => p.tenants.find((t) => p.get("aidefense", t.id).state === "not-set-up").id);
  const ns = aiSection(none);
  assert.deepEqual(ns.blocks.map((b) => b.kind), ["note"]);
  assert.match(ns.blocks[0].text, /not set up/);
  assert.equal(findTable(none, "ai-apps"), null);
});
