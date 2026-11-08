import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { aiDefenseAnswer } from "./helpers/fake-sophos.mjs";

const root = mkdtempSync(path.join(tmpdir(), "secops-aiflow-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { assertReadOnly, EXACT_GRAPHQL_QUERIES, ReadOnlyViolationError, createGuardedFetch } = await import("../backend/dist/sophos/guard.js");
const { AI_DEFENSE_FLOW, AI_DEFENSE_FLOW_UNUSED, AI_DEFENSE_DETAIL } = await import("../backend/dist/vendor/sophos-core/fusion/queries/ai-defense.js");
const { createSophosCore } = await import("../backend/dist/vendor/sophos-core/index.js");
const { RateLimiter } = await import("../backend/dist/sophos/rate-limiter.js");
const { fetchAiDefense } = await import("../backend/dist/data/fetchers.js");
const { aiDefenseWindow, aiDefenseView, AI_FLOW_TOP } = await import("../backend/dist/mappers/ai-defense.js");
const { buildAi, scopeFor } = await import("../backend/dist/services/views.js");
const { DEFAULT_SETTINGS } = await import("../backend/dist/store/settings.js");
const { DemoProvider } = await import("../backend/dist/demo/demo-provider.js");

// ai-logos.js is plain data and string matching: no DOM. Loaded when a test needs it.
const logos = () => import("../frontend/js/ai-logos.js");

const GQL = "https://api.taegis.sophos.com/graphql";
const NOW = Date.parse("2026-11-08T02:17:45Z");
const post = (query, variables = {}) => ({ method: "POST", body: JSON.stringify({ query, variables }) });

function aiCore(mode, onRequest = () => {}) {
  const requests = [];
  const baseFetch = async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname === "id.sophos.com") return new Response(JSON.stringify({ access_token: "fake-token", token_type: "bearer", expires_in: 3600, errorCode: "success" }), { status: 200 });
    const body = JSON.parse(init.body);
    requests.push({ operation: /^query (\w+)/.exec(body.query)?.[1], variables: body.variables });
    const answer = onRequest(body) ?? aiDefenseAnswer(body.query, mode, body.variables);
    if (answer instanceof Response) return answer;
    return new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const core = createSophosCore({ clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", fetch: createGuardedFetch({ limiter: new RateLimiter(), baseFetch }) });
  return { core, requests };
}

const record = (mode, onRequest) => fetchAiDefense(aiCore(mode, onRequest).core, "t-1", aiDefenseWindow(NOW), NOW);
const sum = (rows, k) => rows.reduce((a, r) => a + r[k], 0);

// ------------------------------------------------------------------ guard

test("the flow read passes the guard only as its exact document, the client's copy; near misses are refused", () => {
  assert.equal(EXACT_GRAPHQL_QUERIES.get("ToolkitAiDefenseFlow"), AI_DEFENSE_FLOW, "guard and client copies match character for character");
  assert.equal(EXACT_GRAPHQL_QUERIES.get("ToolkitAiDefenseDetail"), AI_DEFENSE_DETAIL);
  assert.match(AI_DEFENSE_DETAIL, /entries \{ id name risk appsUsed/, "the detail read carries each user's actor id for the flow read");
  assertReadOnly(GQL, post(AI_DEFENSE_FLOW));
  assert.doesNotMatch(AI_DEFENSE_FLOW, /\bmutation\b|additionalData|ALLOWED/);
  assert.equal((AI_DEFENSE_FLOW.match(/: activities\(/g) ?? []).length, 4 * AI_FLOW_TOP, "a blocked and a warned count for each of 10 apps and 10 users");
  for (const doc of [
    AI_DEFENSE_FLOW.replace("first: 1", "first: 100"),
    AI_DEFENSE_FLOW.replace("actions: [BLOCKED] }, first: 1) { totalCount }", "actions: [BLOCKED] }, first: 1) { totalCount activities { actor { name } } }"),
    AI_DEFENSE_FLOW + " ",
    "query ToolkitAiDefenseFlow($timeRange: SecureAITimeRange) { activities(filter: { timeRange: $timeRange }) { totalCount } }",
  ]) {
    assert.throws(() => assertReadOnly(GQL, post(doc)), ReadOnlyViolationError, doc.slice(0, 60));
  }
});

// ------------------------------------------------------------------ the read

test("a tenant with blocked or warned activity gets one flow read: the top 10 app and user ids, unused slots padded", async () => {
  const { core, requests } = aiCore("active");
  const r = await fetchAiDefense(core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.deepEqual(requests.map((q) => q.operation), ["ToolkitAiDefenseOverview", "ToolkitAiDefensePolicies", "ToolkitAiDefenseDetail", "ToolkitAiDefenseFlow"]);
  assert.equal(r.calls, 4);
  const v = requests[3].variables;
  assert.deepEqual(v.timeRange, { startTime: "2026-11-01T02:17:00.000Z", endTime: "2026-11-08T02:17:00.000Z" });
  assert.deepEqual([v.app0, v.app1, v.app2, v.app3, v.app9], ["chatgpt", "deepseek", "newapp", AI_DEFENSE_FLOW_UNUSED, AI_DEFENSE_FLOW_UNUSED]);
  assert.deepEqual([v.user0, v.user1, v.user2, v.user9], ["S-1-5-21-1004", "203.0.113.5", AI_DEFENSE_FLOW_UNUSED, AI_DEFENSE_FLOW_UNUSED]);
  assert.equal(Object.keys(v).length, 21, "the window plus all 20 slots, every time");
  assert.deepEqual(r.topApps.map((a) => [a.id, a.blocked, a.warned]), [["chatgpt", 0, 860], ["deepseek", 300, 10], ["newapp", 0, 0]]);
  assert.deepEqual(r.topUsers.map((u) => [u.id, u.blocked, u.warned]), [["S-1-5-21-1004", 300, 20], ["203.0.113.5", 0, 0]]);
});

test("nothing blocked or warned needs no flow read; a failed flow read leaves the board standing, unsplit", async () => {
  const quiet = aiCore("active", (body) => (body.query.startsWith("query ToolkitAiDefenseOverview") ? aiDefenseAnswer(body.query, "allowed-only") : undefined));
  const r = await fetchAiDefense(quiet.core, "t-1", aiDefenseWindow(NOW), NOW);
  assert.ok(!quiet.requests.some((q) => q.operation === "ToolkitAiDefenseFlow"), "no call when every activity was allowed");
  assert.equal(r.calls, 3);
  assert.deepEqual(r.topApps.map((a) => [a.blocked, a.warned]), [[0, 0], [0, 0], [0, 0]]);

  const failing = await record("active", (body) => (body.query.startsWith("query ToolkitAiDefenseFlow") ? new Response(JSON.stringify({ message: "upstream timeout" }), { status: 400 }) : undefined));
  assert.equal(failing.state, "active");
  assert.ok(failing.topApps.every((a) => a.blocked === null && a.warned === null));
  assert.ok(failing.warnings.some((w) => /split by app and user/i.test(w)));
  const v = aiDefenseView([{ tenantId: "t-1", record: failing }]);
  assert.equal(v.flow.split, false);
  assert.ok(v.flow.apps.every((a) => a.blocked === null));
  assert.equal(sum(v.flow.apps, "total"), 5000, "unsplit bands still carry every activity");
});

// ------------------------------------------------------------------ shaping

test("one tenant: each app and user splits into blocked, warned and allowed, and the rest is one other bucket per side", async () => {
  const v = aiDefenseView([{ tenantId: "t-1", record: await record("active") }]);
  const f = v.flow;
  assert.equal(f.split, true);
  assert.deepEqual([f.total, f.blocked, f.warned, f.allowed, f.unsanctioned], [5000, 410, 900, 3690, 40]);
  assert.deepEqual(
    f.apps.map((a) => [a.kind, a.label, a.total, a.blocked, a.warned, a.allowed]),
    [
      ["app", "ChatGPT", 2100, 0, 860, 1240],
      ["app", "DeepSeek", 310, 300, 10, 0],
      ["app", "New App", 4, 0, 0, 4],
      ["other", "9 other apps", 2586, 110, 30, 2446],
    ],
  );
  assert.equal(f.apps[0].appId, "chatgpt");
  assert.equal(f.apps[0].provider, "OpenAI");
  assert.deepEqual(
    f.users.map((u) => [u.kind, u.label, u.total, u.blocked, u.warned, u.allowed]),
    [
      ["user", "pat@corp.example", 900, 300, 20, 580],
      ["user", "203.0.113.5", 12, 0, 0, 12],
      ["other", "28 other users", 4088, 110, 880, 3098],
    ],
  );
  for (const side of [f.apps, f.users]) {
    assert.deepEqual([sum(side, "blocked"), sum(side, "warned"), sum(side, "allowed"), sum(side, "total")], [410, 900, 3690, 5000], "each side adds up to the outcome totals");
  }
  assert.ok(f.users.every((u) => !("id" in u)), "actor ids never reach the screen");
  assert.ok(v.topUsers.every((u) => !("id" in u)));
  const masked = aiDefenseView([{ tenantId: "t-1", record: await record("active") }], true).flow;
  assert.match(masked.users[0].label, /^User [0-9A-F]{6}$/);
});

/** A tenant of `apps` apps and `users` users, its top 20 of each read and the top 10 of each split. */
async function bigTenant(apps, users) {
  const r = structuredClone(await record("active"));
  r.activity = { ...r.activity, total: 400_000, blocked: 61_000, warned: 90_000, unsanctioned: 12_000 };
  r.apps.total = apps;
  r.users.total = users;
  r.topApps = Array.from({ length: 20 }, (_, i) => ({ id: `app-${i}`, name: `App ${i}`, provider: "Vendor", risk: "low", usage: 30_000 - i * 1000, users: 300 - i, unsanctioned: 0, lastSeen: null, blocked: i < 10 ? 4000 - i * 100 : null, warned: i < 10 ? 5000 - i * 100 : null }));
  r.topUsers = Array.from({ length: 20 }, (_, i) => ({ id: `id-${i}`, name: `user${i}@big.example`, risk: "low", apps: 4, usage: 900 - i * 10, violations: 300, topApp: "App 0", unsanctioned: 0, lastSeen: null, blocked: i < 10 ? 100 : null, warned: i < 10 ? 150 + i : null }));
  return r;
}

test("a big tenant (200 apps, 2,000 users) keeps the top 10 on each side and puts the rest in one bucket", async () => {
  const f = aiDefenseView([{ tenantId: "t-1", record: await bigTenant(200, 2000) }]).flow;
  assert.equal(f.apps.length, AI_FLOW_TOP + 1);
  assert.equal(f.users.length, AI_FLOW_TOP + 1);
  assert.deepEqual(f.apps.slice(0, 10).map((a) => a.label), Array.from({ length: 10 }, (_, i) => `App ${i}`), "only apps with a known split are named");
  const otherApps = f.apps.at(-1);
  assert.equal(otherApps.label, "190 other apps");
  assert.equal(otherApps.count, 190);
  assert.equal(otherApps.blocked, 61_000 - sum(f.apps.slice(0, 10), "blocked"));
  assert.equal(f.users.at(-1).label, "1,990 other users");
  for (const side of [f.apps, f.users]) {
    assert.equal(sum(side, "total"), 400_000);
    assert.equal(sum(side, "blocked"), 61_000);
    assert.equal(sum(side, "warned"), 90_000);
    assert.ok(side.every((x) => x.blocked >= 0 && x.warned >= 0 && x.allowed >= 0));
  }
});

test("little activity: no other bucket, nothing invented; no activity at all is an empty flow", async () => {
  const r = structuredClone(await record("active"));
  r.activity = { ...r.activity, total: 3, blocked: 0, warned: 1, unsanctioned: 0 };
  r.apps.total = 1;
  r.users.total = 1;
  r.topApps = [{ id: "claude", name: "Claude", provider: "Anthropic", risk: "low", usage: 3, users: 1, unsanctioned: 0, lastSeen: null, blocked: 0, warned: 1 }];
  r.topUsers = [{ id: "S-1", name: "kim@small.example", risk: "low", apps: 1, usage: 3, violations: 1, topApp: "Claude", unsanctioned: 0, lastSeen: null, blocked: 0, warned: 1 }];
  const f = aiDefenseView([{ tenantId: "t-1", record: r }]).flow;
  assert.deepEqual(f.apps.map((a) => [a.label, a.blocked, a.warned, a.allowed]), [["Claude", 0, 1, 2]]);
  assert.deepEqual(f.users.map((u) => [u.label, u.total]), [["kim@small.example", 3]]);
  assert.deepEqual([f.total, f.blocked, f.warned, f.allowed], [3, 0, 1, 2]);

  r.activity = { ...r.activity, total: 0, blocked: 0, warned: 0 };
  r.topApps = [];
  r.topUsers = [];
  const empty = aiDefenseView([{ tenantId: "t-1", record: r }]).flow;
  assert.deepEqual([empty.total, empty.apps.length, empty.users.length], [0, 0, 0]);
});

test("activity no user was named for, and counts read a moment apart, never go negative or uneven", async () => {
  const r = structuredClone(await record("active"));
  r.users.total = 2;
  const f = aiDefenseView([{ tenantId: "t-1", record: r }]).flow;
  assert.equal(f.users.at(-1).label, "No user named", "every user is shown, so the rest had no user");
  // The flow read saw two more blocked than the overview did a second earlier.
  r.topApps[1].blocked = 412;
  const raced = aiDefenseView([{ tenantId: "t-1", record: r }]).flow;
  assert.ok(raced.apps.every((a) => a.blocked >= 0 && a.allowed >= 0));
  assert.equal(sum(raced.apps, "blocked"), raced.blocked);
  assert.equal(sum(raced.users, "blocked"), raced.blocked, "both sides add up to the same outcome totals");
  assert.equal(sum(raced.apps, "total"), sum(raced.users, "total"));
});

test("all tenants: apps merge by id across tenants, users keep their tenant, an unsplit tenant falls into other", async () => {
  const a = await record("active");
  const b = await record("active");
  const failed = await record("active", (body) => (body.query.startsWith("query ToolkitAiDefenseFlow") ? new Response("{}", { status: 400 }) : undefined));
  const v = aiDefenseView([
    { tenantId: "a", tenantName: "Tenant A", record: a },
    { tenantId: "b", tenantName: "Tenant B", record: b },
    { tenantId: "c", tenantName: "Tenant C", record: failed },
  ]);
  const f = v.flow;
  assert.equal(f.split, true);
  assert.equal(f.total, 15_000);
  const chat = f.apps.find((x) => x.appId === "chatgpt");
  assert.deepEqual([chat.total, chat.warned, chat.tenants], [4200, 1720, 2], "the two split tenants' ChatGPT, merged");
  assert.equal(f.apps.at(-1).label, "Other apps");
  assert.equal(f.users[0].tenantName, "Tenant A");
  assert.equal(f.users.filter((u) => u.kind === "user").length, 4, "two users from each split tenant");
  assert.match(f.note, /1 tenant/);
  for (const side of [f.apps, f.users]) assert.equal(sum(side, "total"), 15_000);
});

test("demo mode exercises the flow: a split board for one tenant, a big estate tenant and a quiet one", async () => {
  const { logoFor } = await logos();
  const single = new DemoProvider("tenant", NOW);
  const one = buildAi(single, scopeFor(single, single.tenants[0].id), DEFAULT_SETTINGS, NOW).model.flow;
  single.stop();
  assert.equal(one.split, true);
  assert.ok(one.blocked > 0 && one.warned > 0 && one.allowed > 0);
  assert.equal(one.apps.at(-1).kind, "other", "the demo tenant has more apps than the flow names");
  assert.ok(one.apps.some((x) => x.kind === "app" && logoFor({ name: x.label, id: x.appId, provider: x.provider })), "some demo apps have a logo");
  assert.ok(one.apps.some((x) => x.kind === "app" && !logoFor({ name: x.label, id: x.appId, provider: x.provider })), "and some get a monogram");
  for (const side of [one.apps, one.users]) assert.equal(sum(side, "blocked"), one.blocked);

  const partner = new DemoProvider("partner", NOW);
  const flows = partner.tenants.map((t) => buildAi(partner, scopeFor(partner, t.id), DEFAULT_SETTINGS, NOW).model);
  partner.stop();
  const big = flows.find((m) => m.apps.total >= 200);
  assert.ok(big, "one demo tenant has 200 or more AI apps");
  assert.ok(big.users.total >= 2000);
  assert.match(big.flow.apps.at(-1).label, /^\d+ other apps$/);
  const quiet = flows.find((m) => m.state === "active" && m.activity.total > 0 && m.activity.total < 20);
  assert.ok(quiet, "one demo tenant has AI Defense and little activity");
  assert.ok(!quiet.flow.apps.some((x) => x.kind === "other"));
});

// ------------------------------------------------------------------ logos

test("logos match by app id, name or provider; anything unmatched, or a brand whose terms rule it out, gets a monogram", async () => {
  const { logoFor, monogram, AI_LOGOS } = await logos();
  assert.equal(logoFor({ id: "deepseek", name: "DeepSeek", provider: "DeepSeek" }), "deepseek");
  assert.equal(logoFor({ id: "kimi", name: "Kimi", provider: "Moonshot AI PTE. LTD." }), "kimi");
  assert.equal(logoFor({ id: "", name: "Kimi Chat", provider: "Moonshot AI" }), "kimi", "by provider when the app name is new");
  assert.equal(logoFor({ id: "perplexity", name: "Perplexity", provider: "Perplexity" }), "perplexity");
  assert.equal(logoFor({ name: "perplexity ai" }), "perplexity");
  assert.equal(logoFor({ id: "poe", name: "Poe", provider: "Quora" }), "poe");
  assert.equal(logoFor({ name: "Hugging Face" }), "huggingface");
  assert.equal(logoFor({ name: "HuggingChat", provider: "Hugging Face" }), "huggingface");
  // Not in a licence-clean set, or the brand's terms need its approval first.
  for (const name of ["ChatGPT", "Claude", "Gemini", "Microsoft Copilot", "Meta AI", "Vibe", "Grok", "HeyGen", "Midjourney", "Character.AI"]) {
    assert.equal(logoFor({ name }), null, name);
  }
  // Simple Icons' "Monica" is a personal CRM, not the Monica AI assistant.
  assert.equal(logoFor({ id: "monica", name: "Monica", provider: "Butterfly Effect" }), null);
  assert.equal(logoFor({}), null);
  for (const [key, logo] of Object.entries(AI_LOGOS)) {
    assert.match(logo.path, /^M[\d.\-\s,MmLlHhVvCcSsQqTtAaZz]+$/, `${key}: a plain path`);
    assert.ok(logo.title && logo.terms, `${key}: names its brand and the terms checked`);
  }
  assert.deepEqual(["Microsoft Copilot", "ChatGPT", "Character.AI", "HeyGen", "meta-ai", "  grok ", "", "42 Labs"].map(monogram), ["MC", "C", "CA", "H", "MA", "G", "?", "4L"]);
});
