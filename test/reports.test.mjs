import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { inflateSync } from "node:zlib";
import { fakeSophos, UUID } from "./helpers/fake-sophos.mjs";

const root = mkdtempSync(path.join(tmpdir(), "secops-reports-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { assertReadOnly, ReadOnlyViolationError, EXACT_GRAPHQL_QUERIES, ALLOWED_GRAPHQL_MUTATIONS, ALLOWED_GRAPHQL_OPERATIONS } = await import("../backend/dist/sophos/guard.js");
const { DETECTION_DETAIL_DOC } = await import("../backend/dist/reports/live.js");
const Q = await import("../backend/dist/reports/queries.js");
const D = await import("../backend/dist/reports/data.js");
const { REPORTS, reportDefinition } = await import("../backend/dist/reports/catalogue.js");
const { checkRequest, runReport } = await import("../backend/dist/reports/runner.js");
const { DemoReportSource } = await import("../backend/dist/reports/demo.js");
const { LiveReportSource } = await import("../backend/dist/reports/source.js");
const { DemoProvider } = await import("../backend/dist/demo/demo-provider.js");
const { DEFAULT_SETTINGS } = await import("../backend/dist/store/settings.js");
const { csvField, tableCsv, exportName, tableIds, findTable } = await import("../backend/dist/reports/csv.js");
const { renderPdf, columnWidths, cellText } = await import("../backend/dist/reports/pdf/render.js");
const { encode, measure, wrap, fit } = await import("../backend/dist/reports/pdf/fonts.js");
const { formatDateTime, formatOffset, validTimeZone } = await import("../backend/dist/reports/format.js");
const { Engine, DATASET_SPECS } = await import("../backend/dist/services/engine.js");
const { EncryptedCache } = await import("../backend/dist/store/cache.js");

const GQL = "https://api.taegis.sophos.com/graphql";
const post = (body) => ({ method: "POST", body: JSON.stringify(body) });
const H = 3_600_000;
const WINDOW = { start: Date.parse("2026-10-30T02:00:00Z"), end: Date.parse("2026-11-06T02:00:00Z") };

// ------------------------------------------------------------------ guard

test("the reports' detection query passes the guard only as its exact document", () => {
  assert.equal(DETECTION_DETAIL_DOC, EXACT_GRAPHQL_QUERIES.get("ToolkitDetectionDetail"), "the reports' copy and the guard's copy are identical");
  assertReadOnly(GQL, post({ query: DETECTION_DETAIL_DOC, variables: { in: { cql_query: "from alert severity >= 0 EARLIEST=-24h", limit: 10, offset: 0 } } }));
  // Near misses: the same name with any other text.
  const nearMisses = [
    DETECTION_DETAIL_DOC.replace("title", "title description"),
    DETECTION_DETAIL_DOC.replace("    status\n", "    status\n    search_id\n"),
    `${DETECTION_DETAIL_DOC}\n`,
    DETECTION_DETAIL_DOC.replace(/\n {2}/g, "\n "),
    "query ToolkitDetectionDetail { tenant(id: \"x\") { id } }",
  ];
  for (const doc of nearMisses) {
    assert.throws(() => assertReadOnly(GQL, post({ query: doc, variables: {} })), (err) => err instanceof ReadOnlyViolationError && /exact document/.test(err.message), doc.slice(0, 60));
  }
  assert.ok(!ALLOWED_GRAPHQL_OPERATIONS.has("ToolkitDetectionDetail"), "not also allowed by name");
  assert.equal(ALLOWED_GRAPHQL_MUTATIONS.size, 2, "no new mutation");
});

test("a request that times out still counts as a call the report made", async () => {
  const { createGuardedFetch, callTally } = await import("../backend/dist/sophos/guard.js");
  const { RateLimiter } = await import("../backend/dist/sophos/rate-limiter.js");
  const logged = [];
  const fetchImpl = createGuardedFetch({ limiter: new RateLimiter(), onCall: (r) => logged.push(r), baseFetch: async () => { throw new Error("The operation was aborted due to timeout"); } });
  const tally = [];
  await assert.rejects(callTally.run(tally, () => fetchImpl(GQL, post({ query: DETECTION_DETAIL_DOC, variables: {} }))), /timeout/);
  assert.deepEqual([tally.length, tally[0].status, tally[0].operation, logged.length], [1, 0, "ToolkitDetectionDetail", 1]);
});

// ------------------------------------------------------------------ QL and input checks

test("a typed user, IP or device can never change the shape of the QL", () => {
  for (const bad of ["x' or 1=1", "a\\'", "ab'", "a", "", "x".repeat(129), "pat\"", 'a"b', "back\\slash", null, 42]) {
    assert.throws(() => Q.cleanUser(bad), Q.ReportInputError, String(bad));
  }
  assert.equal(Q.cleanUser("  j.smith@corp.example "), "j.smith@corp.example");
  assert.equal(Q.cleanUser("Zoë Müller-Łukasik"), "Zoë Müller-Łukasik");
  assert.equal(Q.cleanUser("CORP$ svc_backup"), "CORP$ svc_backup");
  assert.equal(Q.cleanIp("203.0.113.7"), "203.0.113.7");
  assert.equal(Q.cleanIp("2001:db8::1"), "2001:db8::1");
  for (const bad of ["203.0.113", "1.2.3.4'", "localhost", "203.0.113.7/24"]) assert.throws(() => Q.cleanIp(bad), Q.ReportInputError);
  assert.throws(() => Q.cleanHost("LT 01"), Q.ReportInputError);
  assert.deepEqual(Q.cleanSensorTypes(["MICROSOFT_GRAPH_SIGN_IN", "x') or ('1", "Cisco Duo", 7]), ["MICROSOFT_GRAPH_SIGN_IN", "Cisco Duo"]);
});

test("the user searches name only the schemas that take @user, with absolute bounds", () => {
  const ql = Q.userActivityQl("pat", WINDOW);
  assert.match(ql, /^from agentdetection, antivirus, auth, cloudaudit, email, filemod, forensicinfo, http, inventoryinfo, managementevent, netflow, nids, patchstate, persistence, process, processmodule, registry, softwareinfo, thirdparty where @user contains 'pat' earliest='2026-10-30T02:00:00Z' latest='2026-11-06T02:00:00Z' \| aggregate count by sensor_type$/);
  for (const s of ["dnsquery", "dhcp", "generic", "encrypt", "apicall", "scriptblock", "threadinjection"]) assert.doesNotMatch(ql, new RegExp(`\\b${s}\\b`), `${s} has no @user field (measured live)`);
  assert.match(Q.userSigninsQl("pat", WINDOW), /^from auth where @user contains 'pat' .* \| aggregate count, min\(event_time_usec\), max\(event_time_usec\) by target_user_name, source_user_name, sensor_type, action_result, failure_category, logon_type, mfa_used, application_name, source_address, host_id$/);
  assert.match(Q.userTimelineQl("pat", WINDOW), /by action_result, sensor_type, 1d$/, "a 7-day window counts by UTC day");
  assert.match(Q.userTimelineQl("pat", { start: WINDOW.end - 24 * H, end: WINDOW.end }), /, 1h$/, "a day counts by hour");
  assert.match(Q.userRecentQl("pat", WINDOW), /\| fields event_time_usec, .* \| head 100$/);
  assert.equal(Q.detectionQl("user", "pat", 720), "from alert where @user contains 'pat' EARLIEST=-720h");
  assert.equal(Q.detectionQl(null, null, 99999), "from alert severity >= 0 EARLIEST=-744h", "never past 31 days");
});

test("a log search groups only over the event types that have the field", () => {
  const spec = { kind: "ip", value: "203.0.113.7", schemas: Q.cleanSchemas("ip", []), sensors: ["SOPHOS_SFOS"], groupBy: "destination_port", rows: 500 };
  assert.ok(!spec.schemas.includes("patchstate") && !spec.schemas.includes("softwareinfo"), "inventory snapshots start unticked");
  assert.match(Q.logTimelineQl(spec, WINDOW), /where @ip = '203\.0\.113\.7' and sensor_type in \('SOPHOS_SFOS'\) earliest=/);
  assert.match(Q.logGroupQl(spec, WINDOW), /^from antivirus, encrypt, http, netflow, nids, thirdparty where .* \| aggregate count by destination_port$/);
  assert.equal(Q.logGroupQl({ ...spec, schemas: ["auth", "dnsquery"] }, WINDOW), null, "no chosen type has a destination port");
  assert.match(Q.logGroupQl({ ...spec, groupBy: "schema" }, WINDOW), /\| aggregate count by sensor_type$/);
  assert.match(Q.logRowsQl(spec, WINDOW), /\| head 500$/);
  assert.match(Q.logRowsQl(spec, WINDOW, ["netflow", "http"]), /^from netflow, http where /);
  const groups = Q.rowGroups([{ schema: "a", count: 1 }, { schema: "b", count: 9 }, { schema: "c", count: 0 }, { schema: "d", count: 5 }, { schema: "e", count: 2 }, { schema: "f", count: 3 }, { schema: "a", count: 9 }]);
  assert.deepEqual(groups, [["a", "b", "d", "f"], ["e"]], "rows are read four busy event types at a time, empty ones skipped");
  assert.throws(() => Q.cleanSchemas("host", ["email", "http"]), Q.ReportInputError, "neither takes @host");
});

test("a report's search pages wait 90 s: a log search's first page of whole events took 35 to 56 s on a busy tenant", async () => {
  const { fetchLogSearch } = await import("../backend/dist/reports/live.js");
  const spec = { kind: "user", value: "pat", schemas: ["auth", "http"], sensors: [], groupBy: "sensor_type", rows: 500 };
  const asked = [];
  const run = (rows) => ({ urn: "urn:search:fake", rows, total: rows.length, truncated: false, outcome: "ALL", failedPartitions: [], warnings: [], reused: false, createTime: "", expireTime: "", calls: 1 });
  const core = {
    search: {
      run: async (_tenant, ql, options) => {
        asked.push({ ql, options });
        if (/\| aggregate count by 1d$/.test(ql)) return run([{ event_time_usec_1d: "2026-11-05 00:00:00", schema_type: "http", row_count: 900 }]);
        return run([]);
      },
    },
  };
  await fetchLogSearch(core, "t1", spec, WINDOW);
  assert.ok(asked.length >= 2, "timeline and rows");
  for (const a of asked) assert.ok(a.options.pageTimeoutMs >= 90_000, `${a.ql.slice(-30)}: pages wait ${a.options.pageTimeoutMs} ms`);
});

// ------------------------------------------------------------------ parsing

test("search rows become sign-ins, timeline buckets and log rows", () => {
  const [row] = D.parseUserSignins([{ target_user_name: "pat", sensor_type: "SOPHOS_SFOS", action_result: "FAILED", failure_category: "INCORRECT_USER_OR_PASSWORD", logon_type: "NETWORK", mfa_used: "false", source_address: "198.51.100.9", row_count: "4", min_event_time_usec: 1793920000000000, max_event_time_usec: 1793929000000000 }, { row_count: 0 }]);
  assert.deepEqual([row.result, row.count, row.mfa, row.first, row.last], ["failed", 4, false, 1793920000000, 1793929000000]);
  const tl = D.parseUserTimeline([{ event_time_usec_1h: "2026-11-05 23:00:00", action_result: "SUCCESS", sensor_type: "X", row_count: 2 }, { event_time_usec_1d: "2026-11-05 00:00:00", row_count: 9 }], "1h");
  assert.deepEqual(tl, [{ at: Date.parse("2026-11-05T23:00:00Z"), result: "success", sensorType: "X", count: 2 }]);
  const log = D.parseLogRow({ event_time_usec: 1793920494759865, schema_type: "netflow", sensor_type: "SOPHOS_SFOS", host_id: "h1", source_address: "10.0.0.5", destination_address: "203.0.113.9", destination_port: "443", flow_action: "ALLOW", source_user_name: "pat" });
  assert.deepEqual(log, { at: 1793920494760, schema: "netflow", sensorType: "SOPHOS_SFOS", hostId: "h1", user: "pat", source: "10.0.0.5", destination: "203.0.113.9:443", action: "ALLOW", detail: "" });
  assert.equal(D.parseUserCloud([{ event_name: "Email messages removed after delivery\u200b", row_count: 2 }])[0].operation, "Email messages removed after delivery", "zero-width characters from Sophos are dropped");
});

test("detections keep their title and the users, devices and addresses they name", () => {
  const d = D.mapDetectionDetail({ id: "alert://1", attack_technique_ids: ["T1078"], enrichment_details: [{ mitre_attack_info: { technique_id: "T1078", technique: "Valid Accounts", tactics: ["Initial Access", "Persistence"] } }, { mitre_attack_info: null }], metadata: { title: "Succesfully admin login", severity: 0.4, created_at: { seconds: 1793920674 } }, source_entities: [{ display_name: "10.198.100.1", subtype: "IpAddress" }, { display_name: "proc", subtype: "Process" }], target_entities: [{ display_name: "WIN-01", subtype: "Endpoint" }, { display_name: "Administrator@corp", subtype: "User" }, { display_name: "10.198.100.1", subtype: "IpAddress" }] });
  assert.deepEqual([d.title, d.severity, d.users, d.hosts, d.ips, d.createdAt], ["Succesfully admin login", "medium", ["Administrator@corp"], ["WIN-01"], ["10.198.100.1"], 1793920674000]);
  assert.deepEqual([d.techniqueNames, d.tactics], [{ T1078: "Valid Accounts" }, ["Initial access", "Persistence"]], "ATT&CK names and tactics from the enrichment");
  const u = D.mapDirectoryUser({ name: "Pat", email: "p@x.example", source: { type: "azureActiveDirectory", domain: "x.example" }, groups: { total: 3 } });
  assert.deepEqual([u.source, u.domain, u.groups], ["Microsoft Entra ID sync", "x.example", 3]);
});

// ------------------------------------------------------------------ requests

test("a request outside what a report supports is refused with a reason", () => {
  const partner = new DemoProvider("partner");
  try {
    const fusion = partner.tenants.find((t) => partner.get("generation", t.id)?.generation === "fusion");
    const classic = partner.tenants.find((t) => partner.get("generation", t.id)?.generation === "classic");
    assert.throws(() => checkRequest(partner, { reportId: "nope" }), /No such report/);
    assert.throws(() => checkRequest(partner, { reportId: "user", tenant: "all" }), /runs on one tenant/);
    assert.throws(() => checkRequest(partner, { reportId: "executive", tenant: "all", window: "30d" }), /reads Sophos again for every tenant/);
    assert.throws(() => checkRequest(partner, { reportId: "logsearch", tenant: classic.id, window: "24h" }), /needs the tenant on Sophos Fusion/);
    assert.throws(() => checkRequest(partner, { reportId: "cases", tenant: "not-a-tenant" }), /not one this credential reaches/);
    const ok = checkRequest(partner, { reportId: "executive", tenant: fusion.id, window: "30d", timeZone: "Not/AZone", params: { user: "x", "bad key!": "y", list: ["a", 3] } });
    assert.equal(ok.windowKey, "30d");
    assert.ok(validTimeZone(ok.timeZone), "an unknown zone falls back to the server's");
    assert.deepEqual(ok.params, { user: "x", list: ["a"] });
  } finally {
    partner.stop();
  }
});

// ------------------------------------------------------------------ every report, demo, without the page

async function demoRun(context, req) {
  const provider = new DemoProvider(context);
  try {
    const checked = checkRequest(provider, req);
    return await runReport(checked, { source: new DemoReportSource(provider), settings: DEFAULT_SETTINGS });
  } finally {
    provider.stop();
  }
}

/** Only strings, finite numbers, booleans, null, arrays and plain objects: a scheduler can store and reload it as JSON. */
function assertPlainJson(value, where, path = "doc") {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") return assert.ok(Number.isFinite(value), `${where}: ${path} is ${value}`);
  if (value === undefined) return;
  assert.ok(Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype, `${where}: ${path} is not plain data`);
  for (const [k, v] of Object.entries(value)) assertPlainJson(v, where, `${path}.${k}`);
}

test("every report runs in demo mode with no server and no page, and names its gaps", async () => {
  for (const def of REPORTS) {
    for (const context of ["partner", "tenant"]) {
      const probe = new DemoProvider(context);
      const fusion = probe.tenants.find((t) => probe.get("generation", t.id)?.generation === "fusion");
      probe.stop();
      const tenant = def.scope === "tenant" || context === "tenant" ? fusion.id : "all";
      const params = def.id === "user" ? { user: "m.nguyen" } : def.id === "logsearch" ? { match: "user", value: "m.nguyen", groupBy: "source_address" } : {};
      const doc = await demoRun(context, { reportId: def.id, tenant, params, timeZone: "Australia/Sydney" });
      const where = `${def.id} (${context})`;
      assert.equal(doc.reportId, def.id, where);
      assert.equal(doc.demo, true);
      assert.equal(doc.calls.total, 0, `${where}: demo makes no Sophos calls`);
      assert.ok(doc.sections.length >= 1, where);
      assert.ok(doc.sections.every((s) => s.blocks.length > 0), `${where}: no empty section`);
      assert.ok(doc.summary.length >= 4, `${where}: a summary`);
      assert.equal(doc.timeZone, "Australia/Sydney");
      assertPlainJson(doc, where);
      if (def.windows) assert.ok(doc.window && doc.window.end - doc.window.start === def.windows.find((w) => w.key === def.defaultWindow).hours * H, where);
    }
  }
});

test("the user investigation finds the demo user's sign-ins, VPN, Microsoft 365, detections and cases", async () => {
  const doc = await demoRun("tenant", { reportId: "user", window: "7d", params: { user: "m.nguyen" } });
  assert.match(doc.subject, /^Minh Nguyen \(m\.nguyen@harbourline\.example\)$/);
  const ids = doc.sections.map((s) => s.id);
  assert.deepEqual(ids, ["identity", "signins", "m365", "vpn", "places", "devices", "accounts-used", "detections", "cases", "activity", "recent"]);
  const table = (id) => findTable(doc, id);
  assert.ok(table("vpn").rows.length >= 1, "the SSL VPN sign-ins");
  assert.ok(table("cloud-operations").rows.some((r) => r.operation === "New-InboxRule"));
  assert.ok(table("detections").rows.some((r) => r.title === "Inbox rule hides messages from a new sign-in location"));
  assert.ok(table("cases").rows.some((r) => /m\.nguyen/.test(r.title)));
  assert.ok(table("devices").rows.length <= 4, "a person has a couple of devices, not a tenth of the estate");
  const mfa = doc.sections.find((s) => s.id === "signins").blocks[0].items.find((k) => k.label === "Without MFA");
  assert.match(mfa.note, /interactive user sign-in/, "endpoint logons and token refreshes are not counted");
  assert.ok(doc.sections.find((s) => s.id === "identity").blocks.some((b) => b.kind === "note" && b.tone === "gap" && /Job title/.test(b.text)), "the directory fields no API has are named");
  const nobody = await demoRun("tenant", { reportId: "user", window: "24h", params: { user: "nobody.here" } });
  assert.equal(nobody.subject, "nobody.here");
  assert.equal(findTable(nobody, "accounts").rows.length, 0);
});

test("a sign-in from 0.0.0.0 has no address: it is not counted as a public address the report could not place", async () => {
  // Seen live, 06/11/2026: two endpoint logons from 0.0.0.0 read "Not placed" and "2 from public addresses with no location".
  class NoAddressSource extends DemoReportSource {
    async userActivity(tenantId, user, window) {
      const a = await super.userActivity(tenantId, user, window);
      const base = a.signins[0];
      return { ...a, signins: [...a.signins, { ...base, sensorType: "ENDPOINT_SOPHOS", result: "failed", failure: "No such account", ip: "0.0.0.0", count: 2 }] };
    }
  }
  const run = async (source) => {
    const provider = new DemoProvider("tenant");
    try {
      return await runReport(checkRequest(provider, { reportId: "user", window: "7d", params: { user: "m.nguyen" } }), { source: source(provider), settings: DEFAULT_SETTINGS });
    } finally {
      provider.stop();
    }
  };
  const placesNote = (doc) => doc.sections.find((s) => s.id === "places").blocks.find((b) => b.kind === "note").text;
  const before = placesNote(await run((p) => new DemoReportSource(p)));
  const doc = await run((p) => new NoAddressSource(p));
  assert.ok(findTable(doc, "failures").rows.some((r) => r.from === "0.0.0.0 (No address)"), "the failures table says there was no address");
  const unplaced = (t) => Number(/([\d,]+) from public addresses with no location/.exec(t)[1].replace(/,/g, ""));
  assert.equal(unplaced(placesNote(doc)), unplaced(before), "0.0.0.0 is not a public address");
});

test("a log search by user leaves the user column out of the PDF and keeps it in the CSV", async () => {
  const doc = await demoRun("tenant", { reportId: "logsearch", window: "24h", params: { match: "user", value: "m.nguyen", groupBy: "application_name", schemas: ["auth", "netflow", "process"] } });
  const events = findTable(doc, "events");
  assert.equal(events.columns.find((c) => c.key === "user").pdf, false);
  const csv = tableCsv(events, doc.timeZone);
  assert.match(csv.split("\r\n")[0], /User/);
  assert.doesNotMatch(csv.split("\r\n")[0], /Action and detail/, "the PDF-only column stays out of the CSV");
  const group = doc.sections.find((s) => s.id === "group-by");
  assert.ok(group.blocks.some((b) => b.kind === "note" && /Not included: Process starts\./.test(b.text)), "the event types without the field are named");
});

test("a detection read that times out leaves the report standing on cached data, and says so", async () => {
  const provider = new DemoProvider("tenant");
  try {
    class SlowSource extends DemoReportSource {
      async detections() {
        throw new Error("Sophos Fusion API request timed out after 30000ms");
      }
    }
    const doc = await runReport(checkRequest(provider, { reportId: "executive", window: "30d" }), { source: new SlowSource(provider), settings: DEFAULT_SETTINGS });
    const notes = doc.sections.flatMap((s) => s.blocks).filter((b) => b.kind === "note" && b.tone === "warn").map((b) => b.text);
    assert.ok(notes.some((t) => /did not answer in time/.test(t) && /cached detections for the last 7 days/.test(t)));
    assert.ok(doc.summary.find((k) => k.label === "Signals").value !== "0", "the cached week still counts");
  } finally {
    provider.stop();
  }
});

test("a sampled detection read says so beside the figures it limits: the severity tiles and the per-day chart", async () => {
  const provider = new DemoProvider("tenant");
  try {
    const fusion = provider.tenants.find((t) => provider.get("generation", t.id)?.generation === "fusion");
    // Seen live, 06/11/2026: 6,382 detections in 7 days, the newest 3,000 read, the caution three pages after the tiles.
    class BusySource extends DemoReportSource {
      async detections(tenantId, hours, match) {
        const set = await super.detections(tenantId, hours, match);
        return { ...set, total: set.items.length * 2, sampled: true };
      }
    }
    const run = (source) => runReport(checkRequest(provider, { reportId: "detections", tenant: fusion.id, window: "7d" }), { source, settings: DEFAULT_SETTINGS });
    const doc = await run(new BusySource(provider));
    const blocks = doc.sections.find((s) => s.id === "detections").blocks;
    const chart = blocks.findIndex((b) => b.kind === "series");
    assert.equal(blocks[chart + 1].kind, "note", "the caution sits right under the chart");
    assert.match(blocks[chart + 1].text, /reads the newest 3,000/);
    for (const label of ["Critical", "High", "Medium, low or info"]) assert.match(blocks[0].items.find((k) => k.label === label).note ?? "", /newest/, `${label} tile`);
    for (const label of ["Critical", "High"]) assert.match(doc.summary.find((k) => k.label === label).note ?? "", /newest/, `${label} at a glance`);
    const whole = await run(new DemoReportSource(provider));
    assert.equal(whole.summary.find((k) => k.label === "High").note, undefined, "a full read needs no note");
    // The executive summary's Signals tile counts critical and high from the same read.
    const exec = (source, window) => runReport(checkRequest(provider, { reportId: "executive", tenant: fusion.id, window }), { source, settings: DEFAULT_SETTINGS });
    assert.match((await exec(new BusySource(provider), "30d")).summary.find((k) => k.label === "Signals").note, /^[\d,]+ critical or high in the newest [\d,]+ read$/);
    assert.match((await exec(new DemoReportSource(provider), "7d")).summary.find((k) => k.label === "Signals").note, /^[\d,]+ critical or high$/);
  } finally {
    provider.stop();
  }
});

// ------------------------------------------------------------------ live path, through the guard, against a fake Sophos

test("a live report makes only reads, through the credential's guard and limiter, and counts them", async () => {
  const cache = new EncryptedCache(path.join(root, "data", `live-${Math.random()}.db`));
  await cache.open();
  const fake = fakeSophos({ kind: "tenant", xdrOwnership: "securityOperations" });
  const engine = new Engine({ credentialId: "cred-r", label: "Fake tenant", clientId: "fake-client-id-1234", clientSecret: "fake-client-secret-5678", cache, baseFetch: fake, autoSchedule: false });
  await engine.start();
  for (const spec of DATASET_SPECS) if (!spec.onDemand && spec.applies(engine, engine.tenants[0].id)) await engine.run(spec, engine.tenants[0].id);
  const before = fake.requests.length;
  const limiterBefore = engine.limiter.total;
  const checked = checkRequest(engine, { reportId: "user", window: "24h", params: { user: "pat" } });
  const doc = await runReport(checked, { source: new LiveReportSource(engine), settings: DEFAULT_SETTINGS });
  const sent = fake.requests.slice(before).filter((r) => r.host !== "id.sophos.com");
  assert.equal(doc.calls.total, sent.length, "the report counts every call it made");
  assert.equal(engine.limiter.total - limiterBefore, sent.length, "every call took a slot from the credential's limiter");
  const searchDocs = new Set(ALLOWED_GRAPHQL_MUTATIONS.values());
  for (const r of sent) {
    if (r.method === "GET") continue;
    assert.equal(r.host, "api.taegis.sophos.com", `${r.method} ${r.path}`);
    if (searchDocs.has(r.body.query)) {
      assert.deepEqual(Object.keys(r.body.variables.input), ["text"]);
      assert.match(r.body.variables.input.text, /@user contains 'pat'/);
      continue;
    }
    assert.doesNotMatch(r.body.query, /\bmutation\b/);
  }
  assert.deepEqual(Object.keys(doc.calls.byKind).sort(), ["GET", "GraphQL FusionListCases", "GraphQL GetOrCreateSearch", "GraphQL SearchResults", "GraphQL ToolkitDetectionDetail"]);
  assert.equal(doc.calls.byKind["GraphQL GetOrCreateSearch"], 5, "five searches");
  assert.equal(doc.subject, "Pat Example (pat@corp.example)");
  assert.equal(findTable(doc, "vpn").rows[0].ip, "198.51.100.9", "a Sophos Firewall SSL VPN sign-in");
  assert.equal(findTable(doc, "devices").rows[0].device, "LT-0001", "Fusion host_id is the Central endpoint ID");
  assert.equal(findTable(doc, "detections").rows[0].title, "Password spray");
  assert.ok(findTable(doc, "cases").rows.some((r) => r.ref === "CSE00301"), "a 90-day-old case found by its title");
  engine.stop();
  cache.close();
});

// ------------------------------------------------------------------ CSV

test("CSV cells can't run as spreadsheet formulas, and times carry their zone", () => {
  assert.equal(csvField("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
  assert.equal(csvField("+61 2"), "'+61 2");
  assert.equal(csvField("-cmd"), "'-cmd");
  assert.equal(csvField("-1.50"), "-1.50", "a plain negative number stays a number");
  assert.equal(csvField("-2+3+cmd|' /C calc'!A0"), "'-2+3+cmd|' /C calc'!A0");
  assert.equal(csvField("@SUM(A1)"), "'@SUM(A1)");
  assert.equal(csvField("a,b"), "\"a,b\"");
  assert.equal(csvField("plain"), "plain");
  const t = { kind: "table", id: "t", title: "T", columns: [{ key: "at", label: "Time", format: "datetime" }, { key: "n", label: "N", format: "number" }, { key: "d", label: "Took", format: "duration" }], rows: [{ at: Date.parse("2026-11-06T03:05:09Z"), n: 1234, d: 90 * 60_000 }] };
  const csv = tableCsv(t, "Australia/Sydney");
  assert.ok(csv.startsWith("\uFEFF"), "a byte order mark, so Excel reads UTF-8");
  assert.equal(csv.slice(1), "Time (Australia/Sydney),N,Took (hours)\r\n2026-11-06 14:05:09,1234,1.50\r\n");
});

// ------------------------------------------------------------------ PDF

function pdfParts(buf) {
  const text = buf.toString("latin1");
  const pages = [];
  const re = /(\d+) 0 obj\n<< \/Length (\d+) \/Filter \/FlateDecode >>\nstream\n/g;
  let m;
  while ((m = re.exec(text))) {
    const start = m.index + m[0].length;
    pages.push(inflateSync(buf.subarray(start, start + Number(m[2]))).toString("latin1"));
  }
  return { text, pages };
}

test("the PDF is well formed: every xref offset points at its object, pages counted and numbered", async () => {
  const doc = await demoRun("partner", { reportId: "executive", tenant: "all", window: "7d", timeZone: "America/Chicago" });
  for (const paper of ["a4", "letter"]) {
    const buf = renderPdf(doc, { paper });
    const { text, pages } = pdfParts(buf);
    assert.ok(text.startsWith("%PDF-1.7\n"));
    assert.ok(text.trimEnd().endsWith("%%EOF"));
    const startxref = Number(/startxref\n(\d+)/.exec(text)[1]);
    assert.ok(text.slice(startxref).startsWith("xref\n"));
    const entries = text.slice(startxref).split("\n").slice(3).filter((l) => / 00000 n $/.test(l));
    entries.forEach((line, i) => assert.ok(text.slice(Number(line.slice(0, 10))).startsWith(`${i + 1} 0 obj`), `object ${i + 1}`));
    const count = Number(/\/Type \/Pages \/Kids \[[^\]]*\] \/Count (\d+)/.exec(text)[1]);
    assert.equal(count, pages.length);
    assert.ok(count >= 3);
    pages.forEach((ops, i) => assert.ok(ops.includes(`(Page ${i + 1} of ${count}) Tj`), `page ${i + 1} is numbered`));
    assert.ok(pages[0].includes("(Executive summary) Tj"), "the cover names the report");
    assert.ok(pages[0].includes("(America/Chicago \\(UTC-06:00\\)) Tj"), "and the zone its times are in");
    const [W, Hh] = paper === "a4" ? [595.28, 841.89] : [612, 792];
    for (const ops of pages) {
      for (const [, x, y] of ops.matchAll(/ ([\d.-]+) ([\d.-]+) Td /g)) {
        assert.ok(Number(x) >= 0 && Number(x) <= W && Number(y) >= 0 && Number(y) <= Hh, `text at ${x},${y} is on the page`);
      }
    }
  }
});

test("long tables break across pages with their header repeated, and point to the CSV", async () => {
  const search = await demoRun("tenant", { reportId: "logsearch", window: "24h", params: { match: "host", value: "HL-LT" } });
  const { pages } = pdfParts(renderPdf(search));
  const continued = pages.filter((p) => p.includes("\\(continued\\)"));
  assert.ok(continued.length >= 1, "the 80 printed events run on");
  for (const p of continued) assert.ok(p.includes("(TIME) Tj") && p.includes("(DEVICE) Tj"), "and the header repeats");
  assert.ok(pages.some((p) => /The PDF shows the first 80 of 500 rows/.test(p)));
  const devices = await demoRun("partner", { reportId: "endpoints", tenant: "all" });
  const printed = pdfParts(renderPdf(devices, { csvName: (id) => exportName(devices, "csv", id) })).pages;
  assert.ok(printed.some((p) => /This table is in the CSV export only: secops-endpoint-health-and-agent-coverage-all-tenants-40-\d{4}-\d{2}-\d{2}-devices\.csv/.test(p)));
  assert.ok(tableIds(devices).includes("devices"));
});

test("the cover lists every section on A4 and US Letter, and cells wrap at separators with time units kept whole", async () => {
  const doc = await demoRun("tenant", { reportId: "user", window: "7d", params: { user: "m.nguyen" } });
  const titles = [...doc.sections.map((s) => s.title), "About this report"];
  assert.ok(titles.length >= 12, "a long contents list");
  for (const paper of ["a4", "letter"]) {
    const cover = pdfParts(renderPdf(doc, { paper })).pages[0];
    for (const t of titles) assert.ok(cover.includes(`(${t}) Tj`), `the ${paper} cover lists ${t}`);
  }
  // While the About section fits on one page, it is never split across a page break.
  const extra = "An extra gap, long enough to wrap onto a second line, so the About section grows a little with each variant of this report.";
  for (let k = 0; k <= 10; k++) { // up to the point where the section alone fills a page
    const pages = pdfParts(renderPdf({ ...doc, gaps: [...doc.gaps, ...Array(k).fill(extra)] })).pages;
    const at = pages.findIndex((p, i) => i > 0 && p.includes("(About this report) Tj")); // page 1 is the cover, whose contents name it too
    assert.equal(at, pages.length - 1, `with ${k} extra gaps the About section starts on the last page`);
  }
  assert.deepEqual(wrap("intranet.harbourline.example", "regular", 7.6, 80), ["intranet.harbourline.", "example"]);
  const cell = cellText("Over by 10 d 3 h", { key: "t", label: "Against target" }, "UTC");
  // Wide enough for "Over by 10" but not "Over by 10 d": a plain space would leave "10" ending the first line.
  const lines = wrap(cell, "regular", 7.6, measure("Over by 10", "regular", 7.6) + 1);
  assert.ok(lines.length > 1 && lines.every((l) => !/\d$/.test(l)), `no number is split from its unit: ${JSON.stringify(lines)}`);
});

test("text the standard fonts can't draw folds to a plain letter or a question mark, and wraps", () => {
  assert.deepEqual(encode("Zoë – ł\u200b日"), [90, 111, 235, 32, 0x96, 32, 108, 63]);
  assert.equal(measure("WWW", "regular", 10), 28.32);
  const long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const lines = wrap(long, "regular", 10, 50);
  assert.ok(lines.length > 1 && lines.join("") === long && lines.every((l) => measure(l, "regular", 10) <= 50), "a word longer than the line breaks, and nothing is lost");
  assert.equal(wrap("one two three four five six", "regular", 10, 40, 2).length, 2);
  assert.ok(fit("a long device name that will not fit", "regular", 8, 60).endsWith("\u2026"));
  const widths = columnWidths([{ key: "a", label: "Time", format: "datetime" }, { key: "b", label: "Title", width: 3 }, { key: "c", label: "Severity" }], [["6 Nov 2026 14:05", "x ".repeat(80), "Critical"]], 500, 7.6);
  assert.ok(Math.abs(widths.reduce((a, b) => a + b, 0) - 500) < 0.01);
  assert.ok(widths[0] >= measure("6 Nov 2026 14:05", "regular", 7.6) + 8, "a time never wraps");
  assert.ok(widths[2] >= measure("SEVERITY", "bold", 6.4, 0.3) + 8, "a header never breaks inside its word");
});

test("report times print in the run's zone with the month as a word", () => {
  const at = Date.parse("2026-11-06T03:05:00Z");
  assert.equal(formatDateTime(at, "Australia/Sydney"), "6 Nov 2026 14:05");
  assert.equal(formatDateTime(at, "America/Chicago"), "5 Nov 2026 21:05");
  assert.equal(formatOffset(at, "Australia/Adelaide"), "UTC+10:30");
  assert.equal(formatOffset(at, "UTC"), "UTC");
});

test("the catalogue lists every report with its windows and inputs", () => {
  assert.deepEqual(REPORTS.map((r) => r.id), ["user", "logsearch", "executive", "cases", "detections", "endpoints", "signins", "sources"]);
  assert.equal(reportDefinition("user").scope, "tenant");
  assert.ok(REPORTS.every((r) => !r.windows || r.windows.some((w) => w.key === r.defaultWindow)));
  assert.ok(REPORTS.filter((r) => r.windows).every((r) => r.windows.every((w) => w.hours <= 24 * 31)), "no window beyond the 31 days a search allows");
});


test("a log search group-by that names an inherited property falls back to the default", async () => {
  const { logSpec } = await import("../backend/dist/reports/builders/logsearch.js");
  for (const groupBy of ["constructor", "toString", "__proto__"]) {
    assert.equal(logSpec({ match: "user", value: "k.walsh", groupBy }).groupBy, "sensor_type", groupBy);
  }
});
