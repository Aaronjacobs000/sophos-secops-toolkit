import test from "node:test";
import assert from "node:assert/strict";
import {
  searchWindow,
  qlWindow,
  signinsQl,
  mfaQl,
  mfaUsersQl,
  sourcesQl,
  signinSet,
  mfaSet,
  mfaSources,
  sourceSet,
  searchMeta,
  osName,
  failureName,
  SEARCH_BUCKET_MS,
} from "../backend/dist/mappers/search.js";
import { signinView, sourcesView, smimeStatus, tenantTile, sensorLabel } from "../backend/dist/mappers/views.js";
import { mapSmimeCa, mapSmimeUsers } from "../backend/dist/mappers/api.js";
import { fetchSmime, fetchMfa } from "../backend/dist/data/fetchers.js";
import { SophosApiRequestError } from "../backend/dist/vendor/sophos-core/index.js";

const NOW = Date.parse("2026-10-29T03:07:41Z");
const H = 3_600_000;
const D = 24 * H;
const WINDOW = searchWindow(NOW);
const META = searchMeta([{ rows: [{}], truncated: false, outcome: "ALL", failedPartitions: [], reused: false, calls: 4 }], NOW);

// ------------------------------------------------------------------ QL

test("search windows end on a quarter hour and the QL carries absolute bounds", () => {
  assert.equal(WINDOW.end % SEARCH_BUCKET_MS, 0);
  assert.equal(WINDOW.end, Date.parse("2026-10-29T03:00:00Z"));
  assert.equal(WINDOW.end - WINDOW.start, 7 * D);
  assert.deepEqual(searchWindow(NOW + 5 * 60_000), WINDOW, "a refresh inside the same quarter hour asks the same question, so getOrCreateSearch can reuse it");
  assert.equal(qlWindow(WINDOW), "earliest='2026-10-22T03:00:00Z' latest='2026-10-29T03:00:00Z'");
  assert.match(signinsQl(WINDOW), /^from auth where action = 'LOGON' earliest='.+' latest='.+' \| aggregate count by source_address, action_result, failure_category, mfa_used, sensor_type, logon_type$/);
  assert.match(mfaQl(WINDOW), /action_result = 'SUCCESS'.*aggregate count by sensor_type, mfa_used, logon_type, application_name, os\.os$/);
  assert.match(sourcesQl(WINDOW), /^from agentdetection, .*threadinjection earliest=.* \| aggregate count, max\(event_time_usec\) by sensor_type, 1d$/);
  assert.doesNotMatch(sourcesQl(WINDOW), /alert|investigations|finding/, "derived findings and cases are not data sources");
});

test("the top-users search only names sensor types that look like sensor types", () => {
  assert.equal(mfaUsersQl(WINDOW, []), null);
  const ql = mfaUsersQl(WINDOW, ["MICROSOFT_GRAPH_SIGN_IN", "x') or (1=1", "OKTA"]);
  assert.match(ql, /sensor_type in \('MICROSOFT_GRAPH_SIGN_IN', 'OKTA'\)/);
  assert.doesNotMatch(ql, /1=1/);
  assert.match(mfaUsersQl(WINDOW, ["Cisco Duo", "Google Workspace"]), /sensor_type in \('Cisco Duo', 'Google Workspace'\)/, "the integration guides name sensor types with spaces");
  assert.match(ql, /aggregate count by target_user_name, sensor_type, logon_type$/, "service principals and non-interactive sign-ins are told apart from users");
});

// ------------------------------------------------------------------ X10

const SIGNIN_ROWS = [
  { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 4 },
  { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: true, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 6 },
  { source_address: "203.0.113.7", action_result: "FAILED", failure_category: "INCORRECT_USER_OR_PASSWORD", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 3 },
  { source_address: "198.51.100.9", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 2 },
  { source_address: "10.0.0.5", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: 8932 },
  { source_address: null, action_result: "FAILED", failure_category: "ACCOUNT_LOCKED_OUT", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: 5 },
  { source_address: "203.0.113.50", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: 7 },
];
const GEO = { "203.0.113.7": { city: "Sydney", country: "Australia", lat: -33.87, lon: 151.21, source: "dbip" }, "203.0.113.50": { city: "Sydney", country: "Australia", lat: -33.86, lon: 151.2, source: "dbip" } };
const isPublic = (ip) => !ip.startsWith("10.");

test("X10: sign-ins by result, reason and place; MFA gaps come only from sources that report MFA", () => {
  const s = signinSet({ values: SIGNIN_ROWS, window: WINDOW, geo: GEO, isPublic, meta: META });
  assert.equal(s.total, 8959);
  assert.equal(s.failed, 8);
  assert.equal(s.success, 8951);
  assert.deepEqual(s.failures, [{ reason: "Wrong user name or password", count: 3 }, { reason: "Account locked out", count: 5 }].sort((a, b) => b.count - a.count));
  assert.deepEqual(s.placement, { placed: 20, unplaced: 2, internal: 8937 });
  assert.equal(s.locations.length, 1, "two IPs in the same city merge into one point");
  const sydney = s.locations[0];
  assert.equal(sydney.total, 20);
  assert.equal(sydney.failed, 3);
  assert.equal(sydney.noMfa, 4, "the endpoint logon from Sydney is not an MFA gap");
  const graph = s.bySource.find((x) => x.sensorType === "MICROSOFT_GRAPH_SIGN_IN");
  const endpoint = s.bySource.find((x) => x.sensorType === "ENDPOINT_SOPHOS");
  assert.equal(graph.reportsMfa, true);
  assert.equal(endpoint.reportsMfa, false);
});

test("X10: service principal and non-interactive sign-ins are never a place without MFA", () => {
  // Shaped like a live Fusion tenant (29/10/2026): Entra ID sign-ins from Azure IPs were all service principals
  // (logon_type SERVICE) or token refreshes (NONINTERACTIVE), every one mfa_used false with UNKNOWN_MFA_RESULT.
  const rows = [
    { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "SERVICE", row_count: 900 },
    { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "NONINTERACTIVE", row_count: 80 },
    { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "INTERACTIVE", row_count: 3 },
  ];
  const s = signinSet({ values: rows, window: WINDOW, geo: GEO, isPublic, meta: META });
  assert.equal(s.locations[0].total, 983, "they still count as sign-ins from that place");
  assert.equal(s.locations[0].noMfa, 3, "only the interactive user sign-ins are without MFA");
});

test("MFA-aware sources: known identity providers and any non-endpoint source that reported MFA", () => {
  const aware = mfaSources([
    { sensorType: "ENDPOINT_SOPHOS", mfaUsed: true },
    { sensorType: "OKTA_SYSTEM_LOG", mfaUsed: false },
    { sensorType: "VPN_GATEWAY", mfaUsed: true },
    { sensorType: "LINUX_SYSLOG", mfaUsed: false },
  ]);
  assert.deepEqual([...aware].sort(), ["OKTA_SYSTEM_LOG", "VPN_GATEWAY"]);
});

test("known identity providers count however the sensor type is written", () => {
  // Fusion stores MICROSOFT_GRAPH_SIGN_IN; the Taegis Sensor Types page lists Cisco Duo, Google Workspace and OKTA.
  const forms = ["MICROSOFT_GRAPH_SIGN_IN", "Microsoft Graph Sign In", "OKTA", "Okta", "Cisco Duo", "CISCO_DUO", "cisco-duo", "Google Workspace", "GOOGLE_WORKSPACE", "GoogleWorkspace", "Azure AD", "JumpCloud"];
  const aware = mfaSources(forms.map((sensorType) => ({ sensorType, mfaUsed: false })));
  assert.deepEqual([...aware].sort(), [...forms].sort());
  assert.equal(mfaSources([{ sensorType: "Endpoint Sophos", mfaUsed: false }]).size, 0);
});

// ------------------------------------------------------------------ X11

const MFA_ROWS = [
  { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: true, application_name: "One Outlook Web", "os.os": "OS_WINDOWS", row_count: 6 },
  { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, application_name: "One Outlook Web", "os.os": "OS_IPHONE", row_count: 4 },
  { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, application_name: "Azure Portal", "os.os": "OS_WINDOWS", row_count: 9 },
  { sensor_type: "ENDPOINT_SOPHOS", mfa_used: false, application_name: null, "os.os": "OS_WINDOWS", row_count: 21477 },
];
const USER_ROWS = [
  { target_user_name: "a@example.com", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 9 },
  { target_user_name: "b@example.com", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 4 },
  { target_user_name: "SYSTEM", sensor_type: "ENDPOINT_SOPHOS", row_count: 9000 },
];

test("X11: share without MFA, by app and OS, leaves endpoint logons out", () => {
  const m = mfaSet({ values: MFA_ROWS, userValues: USER_ROWS, usersTruncated: false, window: WINDOW, meta: META });
  assert.equal(m.signins, 19);
  assert.equal(m.withMfa, 6);
  assert.equal(m.withoutMfa, 13);
  assert.deepEqual(m.byApp.map((a) => [a.name, a.withoutMfa, a.signins]), [["Azure Portal", 9, 9], ["One Outlook Web", 4, 10]]);
  assert.deepEqual(m.byOs.map((o) => [o.name, o.withoutMfa]), [["Windows", 9], ["iPhone", 4]]);
  assert.deepEqual(m.topUsers.map((u) => u.user), ["a@example.com", "b@example.com"], "an endpoint account never shows as a user without MFA");
  const endpoint = m.sources.find((s) => s.sensorType === "ENDPOINT_SOPHOS");
  assert.equal(endpoint.reportsMfa, false);
  assert.equal(endpoint.signins, 21477, "it is still listed, so the screen can say why it is not counted");
});

test("X11: service principal and non-interactive sign-ins are listed apart, not counted as without MFA", () => {
  // Measured on a live Fusion tenant (29/10/2026): the aggregate names the grouped os.os field os_os; service principal
  // sign-ins carry logon_type SERVICE and token refreshes NONINTERACTIVE, both mfa_used false with no MFA result.
  const values = [
    { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, logon_type: "SERVICE", application_name: "Example Sync App", os_os: "OS_UNKNOWN", row_count: 18076 },
    { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, logon_type: "NONINTERACTIVE", application_name: "Microsoft Edge", os_os: "OS_WINDOWS", row_count: 617 },
    { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: true, logon_type: "INTERACTIVE", application_name: "One Outlook Web", os_os: "OS_IPHONE", row_count: 5 },
    { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, logon_type: "INTERACTIVE", application_name: "Azure Portal", os_os: "OS_WINDOWS", row_count: 3 },
    { sensor_type: "ENDPOINT_SOPHOS", mfa_used: false, logon_type: "NETWORK", application_name: null, os_os: "OS_WINDOWS", row_count: 9000 },
  ];
  const userValues = [
    { target_user_name: "Example Sync App", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "SERVICE", row_count: 18076 },
    { target_user_name: "b@example.com", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "NONINTERACTIVE", row_count: 350 },
    { target_user_name: "a@example.com", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", logon_type: "INTERACTIVE", row_count: 3 },
  ];
  const m = mfaSet({ values, userValues, usersTruncated: false, window: WINDOW, meta: META });
  assert.deepEqual([m.signins, m.withMfa, m.withoutMfa], [8, 5, 3], "only interactive user sign-ins are counted");
  assert.deepEqual([m.service, m.nonInteractive], [18076, 617]);
  assert.deepEqual(m.byApp.map((a) => a.name), ["Azure Portal", "One Outlook Web"]);
  assert.deepEqual(m.byOs.map((o) => [o.name, o.withoutMfa]), [["Windows", 3], ["iPhone", 0]], "the OS comes from os_os");
  assert.deepEqual(m.topUsers.map((u) => u.user), ["a@example.com"]);
  const graph = m.sources.find((x) => x.sensorType === "MICROSOFT_GRAPH_SIGN_IN");
  assert.deepEqual([graph.signins, graph.withMfa, graph.withoutMfa, graph.service, graph.nonInteractive], [18701, 5, 3, 18076, 617]);

  // No interactive sign-in at all: nothing is counted, so the screen can say there is no MFA result rather than 100% without.
  const none = mfaSet({ values: values.slice(0, 2), userValues: userValues.slice(0, 2), usersTruncated: false, window: WINDOW, meta: META });
  assert.deepEqual([none.signins, none.withoutMfa, none.service, none.nonInteractive, none.topUsers.length], [0, 0, 18076, 617, 0]);
  const v = signinView([{ signins: null, mfa: none }]);
  assert.equal(v.mfa.reportsMfa, true);
  assert.equal(v.mfa.share, null);
  assert.deepEqual([v.mfa.service, v.mfa.nonInteractive], [18076, 617]);
  assert.deepEqual([v.mfa.sources[0].service, v.mfa.sources[0].nonInteractive], [18076, 617]);
});

test("X11 fetch runs the users search only for sources that report MFA", async () => {
  const runs = [];
  const fake = (rows) => ({ rows, truncated: false, outcome: "ALL", failedPartitions: [], reused: true, calls: 3 });
  const core = { search: { run: async (_t, ql) => (runs.push(ql), fake(ql.includes("target_user_name") ? USER_ROWS : MFA_ROWS)) } };
  const m = await fetchMfa(core, "t1", WINDOW, NOW);
  assert.equal(runs.length, 2);
  assert.match(runs[1], /sensor_type in \('MICROSOFT_GRAPH_SIGN_IN'\)/);
  assert.equal(m.search.calls, 6);
  assert.equal(m.search.reused, true);
  const endpointOnly = { search: { run: async (_t, ql) => (runs.push(ql), fake([MFA_ROWS[3]])) } };
  runs.length = 0;
  const none = await fetchMfa(endpointOnly, "t1", WINDOW, NOW);
  assert.equal(runs.length, 1, "no identity source: no second search");
  assert.equal(none.signins, 0);
});

test("labels for OS, failure reasons and sources read plainly", () => {
  assert.equal(osName("OS_MAC"), "macOS");
  assert.equal(osName(null), "Unknown");
  assert.equal(failureName("INCORRECT_MFA"), "MFA failed");
  assert.equal(failureName("SOME_NEW_REASON"), "Some new reason");
  assert.equal(sensorLabel("CLOUDFLARE_HTTP"), "Cloudflare", "a prefix counts only at a word boundary");
  assert.equal(sensorLabel("MICROSOFT_GRAPH_SIGN_IN"), "Entra ID Sign-ins");
  assert.equal(sensorLabel("ENDPOINT_SOPHOS"), "Endpoint");
});

test("the sign-ins screen merges tenants and hides user names in privacy mode", () => {
  const signins = signinSet({ values: SIGNIN_ROWS, window: WINDOW, geo: GEO, isPublic, meta: META });
  const mfa = mfaSet({ values: MFA_ROWS, userValues: USER_ROWS, usersTruncated: false, window: WINDOW, meta: { ...META, outcome: "PARTIAL", failedSchemas: ["auth"] } });
  const v = signinView([{ tenantName: "A", signins, mfa }, { tenantName: "B", signins, mfa }, { tenantName: "C", signins: null, mfa: null }], true);
  assert.equal(v.tenantsWithData, 2);
  assert.equal(v.total, 2 * 8959);
  assert.equal(v.locations[0].noMfa, 8);
  assert.equal(v.mfa.withoutMfa, 26);
  assert.equal(Math.round(v.mfa.share * 100), 68);
  assert.ok(v.mfa.topUsers.every((u) => /^User [0-9A-F]{6}$/.test(u.user)));
  assert.deepEqual(v.search.partial, ["auth"]);
  assert.equal(v.mfa.reportsMfa, true);
});

// ------------------------------------------------------------------ N3

test("N3: volume per day, last event, unparsed share and states per source", () => {
  const day = (offset) => `${new Date(WINDOW.end - offset * D).toISOString().slice(0, 10)} 00:00:00`;
  const usec = (ms) => ms * 1000;
  const values = [
    { sensor_type: "ENDPOINT_SOPHOS", schema_type: "process", event_time_usec_1d: day(0), row_count: 100, max_event_time_usec: usec(NOW - 5 * 60_000) },
    { sensor_type: "ENDPOINT_SOPHOS", schema_type: "netflow", event_time_usec_1d: day(1), row_count: 50, max_event_time_usec: usec(NOW - D) },
    { sensor_type: "CLOUDFLARE_HTTP", schema_type: "generic", event_time_usec_1d: day(0), row_count: 30, max_event_time_usec: usec(NOW - H) },
    { sensor_type: "OKTA_SYSTEM_LOG", schema_type: "auth", event_time_usec_1d: day(3), row_count: 12, max_event_time_usec: usec(NOW - 3 * D) },
  ];
  const previous = {
    days: [],
    sources: [
      { sensorType: "AWS_CLOUDTRAIL", schemas: ["cloudaudit"], events7d: 9, daily: [], unparsed7d: 0, lastEventAt: NOW - 9 * D, state: "quiet" },
      { sensorType: "OLD_FEED", schemas: ["generic"], events7d: 1, daily: [], unparsed7d: 1, lastEventAt: NOW - 40 * D, state: "silent" },
    ],
  };
  const s = sourceSet({ values, window: WINDOW, now: NOW, previous, meta: META });
  assert.equal(s.days.length, 8, "a 7-day window touches 8 UTC days");
  assert.deepEqual(s.sources.map((x) => [x.sensorType, x.state]), [
    ["AWS_CLOUDTRAIL", "silent"],
    ["OKTA_SYSTEM_LOG", "quiet"],
    ["ENDPOINT_SOPHOS", "live"],
    ["CLOUDFLARE_HTTP", "live"],
  ], "silent first, then quiet, then by volume; a source gone 30 days drops off");
  const ep = s.sources.find((x) => x.sensorType === "ENDPOINT_SOPHOS");
  assert.equal(ep.events7d, 150);
  assert.deepEqual(ep.schemas, ["netflow", "process"]);
  assert.equal(ep.daily.at(-1), 100);
  assert.equal(ep.daily.at(-2), 50);
  assert.equal(ep.lastEventAt, NOW - 5 * 60_000);
  assert.equal(s.unparsed7d, 30);
  assert.equal(s.events7d, 192);
  // A day later, without a refresh, a live source is no longer live.
  const v = sourcesView([{ set: s }], NOW + 2 * D);
  assert.equal(v.rows.find((r) => r.sensorType === "ENDPOINT_SOPHOS").state, "quiet");
  assert.deepEqual(v.counts, { sources: 4, live: 0, quiet: 3, silent: 1 });
  assert.equal(v.daily.at(-1), 130);
  assert.equal(v.days.length, 7, "the partial first day is left off the chart");
  assert.equal(v.days.at(-1), "2026-10-29");
  assert.equal(v.rows.find((r) => r.sensorType === "ENDPOINT_SOPHOS").daily.length, 7);
});

// ------------------------------------------------------------------ S/MIME

const at = (days) => new Date(NOW + days * D).toISOString();
const rec = (over = {}) => ({ available: true, note: null, ca: null, expiring: [], expiringTruncated: false, checkedBefore: "2026-11-28", ...over });
const TENANT = { id: "t1", name: "T", apiHost: "https://api-au01.central.sophos.com", dataRegion: "au01", billingType: null, status: null, products: [], city: null, countryCode: null };
const tile = (smime) => tenantTile({ tenant: TENANT, generation: "fusion", cases: { api: "v2", open: [], recentClosed: [], truncated: false, warnings: [] }, endpoints: [], health: null, licences: [], alerts: null, smime, fetchedAt: NOW, errors: 0 }, NOW);

test("S/MIME expiry follows the license rule: amber within 30 days, red within 7, expired ignored", () => {
  assert.equal(smimeStatus(null, NOW), null);
  assert.equal(smimeStatus(rec({ available: false }), NOW), null);
  assert.equal(smimeStatus(rec({ ca: { commonName: "CA", expiresAt: at(400), origin: "created" } }), NOW).level, null);
  const cert = smimeStatus(rec({ expiring: [{ email: "a@x", userName: null, expiresAt: at(12) }, { email: "b@x", userName: null, expiresAt: at(-40) }] }), NOW);
  assert.deepEqual([cert.days, cert.kind, cert.level, cert.expiring, cert.expired], [12, "cert", "warning", 1, 1]);
  const ca = smimeStatus(rec({ ca: { commonName: "CA", expiresAt: at(5), origin: "uploaded" }, expiring: [{ email: "a@x", userName: null, expiresAt: at(20) }] }), NOW);
  assert.deepEqual([ca.days, ca.kind, ca.level], [5, "ca", "critical"]);
  assert.equal(smimeStatus(rec({ expiring: [{ email: "a@x", userName: null, expiresAt: at(31) }] }), NOW).level, null);
  assert.equal(smimeStatus(rec({ expiring: [{ email: "a@x", userName: null, expiresAt: at(30) }] }), NOW).level, "warning");

  assert.equal(tile(null).state, "healthy");
  const amber = tile(rec({ expiring: [{ email: "a@x", userName: null, expiresAt: at(12) }] }));
  assert.equal(amber.state, "warning");
  assert.equal(amber.headline, "S/MIME certificate expires in 12 days");
  const red = tile(rec({ ca: { commonName: "CA", expiresAt: at(5), origin: "created" } }));
  assert.equal(red.state, "critical");
  assert.equal(red.headline, "S/MIME internal CA expires in 5 days");
  assert.equal(tile(rec({ expiring: [{ email: "a@x", userName: null, expiresAt: at(-3) }] })).state, "healthy", "an already expired certificate does not color the tile");
});

test("S/MIME answers map to the CA and to each user's latest certificate", () => {
  assert.equal(mapSmimeCa({}), null);
  assert.deepEqual(mapSmimeCa({ fingerprint: "ab", certificateDetails: { commonName: "Example Global", expiresAt: "2046-09-28T14:09:01Z", origin: "created", issuer: "x" } }), { commonName: "Example Global", expiresAt: "2046-09-28T14:09:01Z", origin: "created" });
  const users = mapSmimeUsers([
    { email: "john@example.com", userName: "John", associatedCertificatesInfo: [{ certificateDetails: { expiresAt: "2026-11-10T00:00:00Z" } }, { certificateDetails: { expiresAt: "2028-11-10T00:00:00Z" } }] },
    { email: "jane@example.com", associatedCertificatesInfo: [{ certificateDetails: { expiresAt: "2026-11-20T00:00:00Z" } }] },
    { email: "nobody@example.com", associatedCertificatesInfo: [] },
    { userName: "no email" },
  ]);
  assert.deepEqual(users, [
    { email: "john@example.com", userName: "John", expiresAt: "2028-11-10T00:00:00Z" },
    { email: "jane@example.com", userName: null, expiresAt: "2026-11-20T00:00:00Z" },
  ], "a replacement certificate already in place covers the one about to expire");
});

test("the S/MIME fetch makes GETs only: the CA, then certificates expiring within 30 days, page by page", async () => {
  const calls = [];
  const core = (answers) => ({
    rest: {
      tenantRequest: async (tenant, path, opts = {}) => {
        calls.push({ path, method: opts.method ?? "GET", params: opts.params });
        const a = answers(path, opts.params ?? {});
        if (a instanceof Error) throw a;
        return a;
      },
    },
  });
  const notFound = new SophosApiRequestError("not found", 404, "ResourceNotFound", null, null);
  const r = await fetchSmime(
    core((path, params) =>
      path.endsWith("/ca/internal") ? notFound : params.pageFromKey ? { items: [{ email: "b@x", associatedCertificatesInfo: [{ certificateDetails: { expiresAt: at(3) } }] }], pages: {} } : { items: [{ email: "a@x", associatedCertificatesInfo: [{ certificateDetails: { expiresAt: at(10) } }] }], pages: { nextKey: "k2" } },
    ),
    "t1",
    NOW,
  );
  assert.equal(r.available, true);
  assert.equal(r.ca, null, "a 404 means no internal CA");
  assert.deepEqual(r.expiring.map((c) => c.email), ["a@x", "b@x"]);
  assert.equal(r.checkedBefore, "2026-11-28");
  assert.ok(calls.every((c) => c.method === "GET"));
  assert.deepEqual(calls[1].params, { certExpiryBefore: "2026-11-28", pageSize: "200" });
  assert.equal(calls[2].params.pageFromKey, "k2");
  const denied = await fetchSmime(core(() => new SophosApiRequestError("forbidden", 403, "Forbidden", null, null)), "t1", NOW);
  assert.equal(denied.available, false);
  assert.match(denied.note, /403/);
  await assert.rejects(fetchSmime(core(() => new Error("network down")), "t1", NOW), /network down/);
});
