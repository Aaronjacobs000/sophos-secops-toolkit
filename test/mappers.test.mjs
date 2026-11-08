import test from "node:test";
import assert from "node:assert/strict";
import { mapAlert, mapCase, mapDetection, mapEndpoint, mapGeneration, mapHealth, mapLicence, mapTenant, caseSeverity, detectionSeverity } from "../backend/dist/mappers/api.js";
import { legacyCaseToFusion } from "../backend/dist/vendor/sophos-core/index.js";
import { caseBoard, endpointSummary, flowModel, laneOf, isUnassigned, signalSeries, tenantTile, mspWall, compareVersions, quantile, sensorLabel } from "../backend/dist/mappers/views.js";

const NOW = Date.parse("2026-10-05T03:00:00Z");
const H = 3_600_000;
const D = 24 * H;
const iso = (ms) => new Date(ms).toISOString();
const TARGETS = { critical: 8, high: 48, medium: 120, low: 240, info: 336 };

test("xdrOwnership decides the API generation", () => {
  assert.equal(mapGeneration("sophos"), "classic");
  assert.equal(mapGeneration("Sophos "), "classic");
  assert.equal(mapGeneration("securityOperations"), "fusion");
  assert.equal(mapGeneration(null), "unknown");
  assert.equal(mapGeneration(""), "unknown");
});

test("endpoint mapping prefers the core agent release over the 10.8 component version", () => {
  const e = mapEndpoint({
    id: "e1",
    hostname: "DC01",
    type: "server",
    os: { isServer: true, platform: "windows", name: "Windows Server 2022" },
    health: { overall: "Bad", threats: { status: "good" }, services: { status: "bad" } },
    tamperProtectionEnabled: false,
    assignedProducts: [{ code: "endpointProtection", version: "10.8.11.4" }, { code: "coreAgent", version: "2026.2.0.2" }],
    lastSeenAt: "2026-10-01T00:00:00Z",
    isolation: { status: "isolated" },
  });
  assert.equal(e.agentVersion, "2026.2.0.2");
  assert.equal(e.health, "bad");
  assert.equal(e.isServer, true);
  assert.equal(e.tamper, false);
  assert.equal(e.isolation, "isolated");
  assert.equal(mapEndpoint({}), null);
});

test("case severity reads both the 2 to 10 scale and v1 names", () => {
  assert.equal(caseSeverity(10), "critical");
  assert.equal(caseSeverity(8), "high");
  assert.equal(caseSeverity(6), "medium");
  assert.equal(caseSeverity(4), "low");
  assert.equal(caseSeverity(2), "info");
  assert.equal(caseSeverity("informational"), "info");
  assert.equal(caseSeverity("High"), "high");
  assert.equal(caseSeverity(0), "unset");
  assert.equal(detectionSeverity(0.85), "critical");
  assert.equal(detectionSeverity(0.6), "high");
  assert.equal(detectionSeverity(0.45), "medium");
  assert.equal(detectionSeverity(0.2), "low");
  assert.equal(detectionSeverity(0.05), "info");
});

test("a Fusion case and a v1 case map to the same record shape", () => {
  const v2 = mapCase({ id: "u1", shortId: "CSE00001", title: " Suspicious ", severity: 8, type: { name: "security_case" }, primaryStatus: { name: "awaiting_action", title: "Awaiting Action", isClosed: false }, managedBy: "CUSTOMER", assigneeId: "", createdAt: iso(NOW - D), updatedAt: iso(NOW - H), closedAt: null, tenantId: "t" }, "v2");
  assert.equal(v2.title, "Suspicious");
  assert.equal(v2.managedBy, "self");
  assert.equal(v2.assigneeId, null, "an empty assignee is unassigned");
  assert.equal(laneOf(v2), "waiting");
  const v1 = mapCase(legacyCaseToFusion({ id: "1-5", type: "investigation", name: "MDR case", tenant: { id: "t" }, managedBy: "sophos", createdAt: iso(NOW - 2 * D), updatedAt: iso(NOW - D), severity: "medium", status: "actionRequired" }), "v1");
  assert.equal(v1.managedBy, "mdr");
  assert.equal(v1.severity, "medium");
  assert.equal(laneOf(v1), "waiting");
  const closed = mapCase({ id: "u2", primaryStatus: { name: "closed", isClosed: true }, severity: 4, createdAt: iso(NOW - 3 * D), closedAt: iso(NOW - D) }, "v2");
  assert.equal(closed.closed, true);
  assert.equal(laneOf(closed), "resolved");
});

test("a case shown closed by status but missing closedAt still counts as closed", () => {
  const c = mapCase({ id: "u3", primaryStatus: { name: "closed", isClosed: true }, severity: 8, createdAt: iso(NOW - D), closedAt: null }, "v2");
  assert.equal(c.closed, true);
});

test("tenants, alerts, detections, health and licences map", () => {
  const t = mapTenant({ id: "t1", name: "Example", showAs: "Example Pty Ltd", apiHost: "https://api-au01.central.sophos.com", dataRegion: "au01", products: [{ code: "MDR-COMPLETE" }], contact: { address: { city: "Sydney", countryCode: "AU" } } });
  assert.equal(t.name, "Example Pty Ltd");
  assert.deepEqual(t.products, ["MDR-COMPLETE"]);
  assert.equal(t.city, "Sydney");
  assert.equal(mapTenant({ id: "x" }), null, "no apiHost, no tenant");
  assert.equal(mapAlert({ id: "a", severity: "HIGH", product: "endpoint", raisedAt: iso(NOW) }).severity, "high");
  const d = mapDetection({ id: "d", metadata: { severity: 0.7, created_at: { seconds: NOW / 1000 }, creator: { detector: { detector_name: "Impossible travel" } } }, sensor_types: ["IDENTITY"], attack_technique_ids: ["T1078"] });
  assert.equal(d.severity, "high");
  assert.equal(d.createdAt, NOW);
  assert.equal(d.detector, "Impossible travel");
  const health = mapHealth({ endpoint: { protection: { computer: { score: 100, notFullyProtected: 1 }, server: { score: 80 } }, policy: { computer: { "threat-protection": { score: 60 } } }, tamperProtection: { computer: { score: 0, disabled: 12 }, server: { score: 0, disabled: 13 } } } });
  assert.equal(health.sections.protection, 90);
  assert.equal(health.sections.policy, 60);
  assert.equal(health.tamperDisabled, 25);
  assert.equal(health.overall, Math.round((90 + 60 + 0) / 3), "overall is the average of the sections present");
  assert.equal(mapHealth({}).overall, null);
  const l = mapLicence({ product: { code: "CIXAXDR", name: "XDR" }, type: "term", endDate: "2027-01-01", quantity: 50, usage: { current: { count: 12 } } });
  assert.deepEqual([l.code, l.used, l.quantity], ["CIXAXDR", 12, 50]);
  assert.equal(mapLicence({ product: { code: "X" }, perpetual: true, unlimited: true }).endDate, null);
});

test("an alert description arrives HTML-escaped and is kept as plain text", () => {
  // Seen live, 06/11/2026: the access point alerts read `firmware &quot;1.10.3192&quot;.` in the PDF.
  const a = mapAlert({ id: "a", raisedAt: iso(NOW), description: "Access Point: Head office - first floor AP6-420E ceiling, failed to update to the new firmware &quot;1.10.3192&quot;." });
  assert.equal(a.description, 'Access Point: Head office - first floor AP6-420E ceiling, failed to update to the new firmware "1.10.3192".');
  assert.equal(mapAlert({ id: "b", raisedAt: iso(NOW), description: "R&amp;D &lt;share&gt; isn&#39;t &#x27;up&#x27;; &amp;quot; stays" }).description, "R&D <share> isn't 'up'; &quot; stays", "decoded once, never twice");
});

test("endpoint summary buckets staleness, health and per-platform agent drift", () => {
  const ep = (id, platform, version, daysSilent, health = "good", tamper = true) => ({ id, hostname: id, type: "computer", platform, osName: platform, isServer: false, health, threats: null, services: null, tamper, lastSeenAt: iso(NOW - daysSilent * D - 1000), agentVersion: version, products: [], isolation: null, group: null, person: null });
  const list = [
    ep("w1", "windows", "2026.2.0.2", 0),
    ep("w2", "windows", "2025.2.1.1", 8, "suspicious"),
    ep("w3", "windows", "2026.2.0.9", 15, "bad", false),
    ep("l1", "linux", "2025.2.0.1", 40),
    ep("m1", "macos", "2026.1.0.1", 120),
  ];
  const s = endpointSummary(list, NOW);
  assert.equal(s.total, 5);
  assert.deepEqual(s.stale, { d7: 1, d14: 1, d30: 1, d90: 1, never: 0 });
  assert.equal(s.staleOver7, 4);
  assert.equal(s.health.bad, 1);
  assert.equal(s.tamperOff, 1);
  assert.equal(s.versions.outdated, 1, "only w2 is behind: Linux and macOS have their own newest");
  assert.equal(s.worst[0].id, "w3", "the bad, tamper-off device is worst");
  const filtered = endpointSummary(list, NOW, null, "linux");
  assert.equal(filtered.total, 1);
});

test("egress IPs place devices; missing ones are counted, not guessed", () => {
  const ep = (id) => ({ id, hostname: id.toUpperCase(), type: "computer", platform: "windows", osName: "w", isServer: false, health: id === "a" ? "bad" : "good", threats: null, services: null, tamper: true, lastSeenAt: iso(NOW), agentVersion: null, products: [], isolation: null, group: null, person: null });
  const egress = { hosts: [{ hostname: "a", ip: "203.0.113.5" }, { hostname: "b", ip: "203.0.113.5" }, { hostname: "c", ip: "198.51.100.1" }], geo: { "203.0.113.5": { city: "Sydney", country: "Australia", lat: -33.8, lon: 151.2, source: "sophos" } }, unplaced: ["198.51.100.1"], notes: [] };
  const s = endpointSummary([ep("a"), ep("b"), ep("c"), ep("d")], NOW, egress);
  assert.deepEqual(s.placement, { placed: 2, unplaced: 1, noEgress: 1, sources: { sophos: 2, dbip: 0 } });
  assert.equal(s.locations.length, 1);
  assert.equal(s.locations[0].devices, 2);
  assert.equal(s.locations[0].worst, "bad");
});

function caseRec(over) {
  return { id: "c", ref: "C-1", title: "t", severity: "high", status: "in_progress", statusTitle: "In Progress", closed: false, secondary: null, managedBy: "self", assigneeId: "u", createdAt: iso(NOW - 10 * H), updatedAt: iso(NOW - H), closedAt: null, type: "investigation", tenantId: "t", api: "v2", ...over };
}

test("the case board puts cases in lanes and measures age against the local targets", () => {
  const set = {
    api: "v2",
    open: [
      caseRec({ id: "1", status: "new", assigneeId: null, severity: "critical", createdAt: iso(NOW - 9 * H) }),
      caseRec({ id: "2", status: "in_progress", createdAt: iso(NOW - 50 * H) }),
      caseRec({ id: "3", status: "customer_action_required", managedBy: "mdr", assigneeId: null, createdAt: iso(NOW - 4 * D), updatedAt: iso(NOW - 4 * D) }),
      caseRec({ id: "4", status: "on_hold" }),
    ],
    recentClosed: [caseRec({ id: "5", closed: true, status: "closed", createdAt: iso(NOW - 3 * D), closedAt: iso(NOW - 2 * D), managedBy: "mdr" }), caseRec({ id: "6", closed: true, status: "closed", createdAt: iso(NOW - 2 * D), closedAt: iso(NOW - 2 * D + 2 * H) })],
    truncated: false,
    warnings: [],
  };
  const b = caseBoard([{ set }], TARGETS, NOW);
  const lane = (k) => b.lanes.find((l) => l.key === k);
  assert.deepEqual(b.lanes.map((l) => l.count), [1, 1, 1, 1, 2]);
  const crit = lane("new").cards[0];
  assert.equal(crit.over, true, "a critical case 9 h old is over an 8 h target");
  assert.equal(crit.owner, "Unassigned");
  assert.equal(lane("investigating").cards[0].over, true, "50 h against 48 h");
  const waiting = lane("waiting").cards[0];
  assert.equal(waiting.over, false, "a waiting case's clock is paused");
  assert.equal(waiting.owner, "Sophos MDR");
  assert.equal(waiting.autoCloseInMs, D, "MDR closes Customer Action Required after 5 idle days");
  assert.equal(b.unassigned, 1);
  assert.equal(b.overTarget, 2);
  assert.equal(b.timeToClose.mdr.median, D);
  assert.equal(b.timeToClose.self.median, 2 * H);
  const mdrOnly = caseBoard([{ set }], TARGETS, NOW, "mdr");
  assert.equal(mdrOnly.open, 1);
  assert.equal(isUnassigned(caseRec({ assigneeId: null, managedBy: "mdr" })), false, "Sophos MDR is working it");
});

test("signals bucket by hour and prefer detections over alerts for the label", () => {
  const det = { windowHours: 168, total: 3, sampled: false, count30d: 9, items: [{ id: "1", createdAt: NOW - 10 * 60_000, severity: "high", detector: null, sensorTypes: ["ENDPOINT_AGENT"], techniques: [], status: null }, { id: "2", createdAt: NOW - 5 * H, severity: "low", detector: null, sensorTypes: [], techniques: [], status: null }, { id: "3", createdAt: NOW - 30 * H, severity: "low", detector: null, sensorTypes: [], techniques: [], status: null }] };
  const s = signalSeries([det], null, NOW, 24);
  assert.equal(s.total, 2, "the 30 h old one is outside 24 h");
  assert.equal(s.lastHour, 1);
  assert.equal(s.hourly.length, 24);
  assert.equal(s.hourly[23], 1);
  assert.equal(s.label, "Detections");
  const a = signalSeries(null, [{ sinceHours: 168, total: 1, items: [{ id: "a", raisedAt: iso(NOW - H / 2), severity: "medium", category: "malware", product: "endpoint", type: "", description: "" }] }], NOW, 24);
  assert.equal(a.label, "Alerts");
  assert.equal(a.bySeverity.medium, 1);
});

test("the front page flow counts sources, who works the cases and the outcome", () => {
  const det = { windowHours: 168, total: 2, sampled: false, count30d: 0, items: [{ id: "1", createdAt: NOW - H, severity: "high", detector: null, sensorTypes: ["ENDPOINT_AGENT"], techniques: [], status: null }, { id: "2", createdAt: NOW - H, severity: "low", detector: null, sensorTypes: ["FIREWALL"], techniques: [], status: null }] };
  const set = { api: "v2", open: [caseRec({ id: "1", managedBy: "mdr", severity: "critical", createdAt: iso(NOW - H) }), caseRec({ id: "2", managedBy: null, createdAt: iso(NOW - 3 * D) })], recentClosed: [caseRec({ id: "3", closed: true, createdAt: iso(NOW - 2 * D), closedAt: iso(NOW - 2 * H), managedBy: "self" })], truncated: false, warnings: [] };
  const f = flowModel({ detections: [det], alerts: [], cases: [{ set }], baseline: ["Endpoint", "Server"] }, NOW, 24);
  assert.deepEqual(f.sources.map((s) => [s.label, s.count]), [["Endpoint", 1], ["Firewall", 1], ["Server", 0]]);
  assert.equal(f.signals.total, 2);
  assert.equal(f.cases.open, 2);
  assert.equal(f.cases.mdr.open, 1);
  assert.equal(f.cases.unclaimed.open, 1);
  assert.equal(f.cases.self.resolved, 1);
  assert.equal(f.cases.openBySeverity.critical, 1);
  assert.equal(f.cases.opened, 1);
  const partner = flowModel({ detections: [], alerts: [], cases: [], perTenant: Array.from({ length: 12 }, (_, i) => ({ name: `T${i}`, count: i })) }, NOW, 24, 9);
  assert.equal(partner.sources.length, 9);
  assert.equal(partner.sources[0].label, "T11");
  assert.deepEqual(partner.moreSources, { count: 2, total: 3 }, "T2 and T1 fold into more; T0 has nothing");
});

test("MSP tiles rank tenants worst first with the reasons spelled out", () => {
  const tenant = (id) => ({ id, name: id, apiHost: "h", dataRegion: "au01", billingType: null, status: "active", products: [], city: null, countryCode: null });
  const ep = (health, tamper = true, days = 0) => ({ id: Math.random().toString(), hostname: "x", type: "computer", platform: "windows", osName: "w", isServer: false, health, threats: null, services: null, tamper, lastSeenAt: iso(NOW - days * D), agentVersion: null, products: [], isolation: null, group: null, person: null });
  const cases = (sevs) => ({ api: "v1", open: sevs.map((s, i) => caseRec({ id: String(i), severity: s })), recentClosed: [], truncated: false, warnings: [] });
  const quiet = tenantTile({ tenant: tenant("quiet"), generation: "classic", cases: cases([]), endpoints: Array.from({ length: 50 }, () => ep("good")).concat([ep("good", true, 9)]), health: { overall: 92, sections: {}, tamperDisabled: 0, notFullyProtected: 0 }, licences: [], alerts: null, fetchedAt: NOW, errors: 0 }, NOW);
  assert.equal(quiet.state, "healthy", "one stale device in 51 does not raise a warning");
  const crit = tenantTile({ tenant: tenant("crit"), generation: "fusion", cases: cases(["critical", "high"]), endpoints: [ep("good")], health: { overall: 90, sections: {}, tamperDisabled: 0, notFullyProtected: 0 }, licences: [], alerts: null, fetchedAt: NOW, errors: 0 }, NOW);
  assert.equal(crit.state, "critical");
  assert.equal(crit.headline, "1 critical case open");
  const warn = tenantTile({ tenant: tenant("warn"), generation: "classic", cases: cases(["high"]), endpoints: [ep("good")], health: null, licences: [{ code: "X", name: "X", type: "term", endDate: iso(NOW + 20 * D).slice(0, 10), quantity: 1, used: 1 }], alerts: null, fetchedAt: NOW, errors: 0 }, NOW);
  assert.equal(warn.state, "warning");
  assert.ok(warn.reasons.some((r) => /Licence expires in 2[01] days/.test(r)));
  const expiring = tenantTile({ tenant: tenant("lic"), generation: null, cases: cases([]), endpoints: [], health: null, licences: [{ code: "X", name: "X", type: "term", endDate: iso(NOW + 3 * D).slice(0, 10), quantity: 1, used: 1 }], alerts: null, fetchedAt: NOW, errors: 0 }, NOW);
  assert.equal(expiring.state, "critical", "a licence ending within a week is critical");
  const pending = tenantTile({ tenant: tenant("p"), generation: null, cases: null, endpoints: null, health: null, licences: null, alerts: null, fetchedAt: null, errors: 0 }, NOW);
  assert.equal(pending.state, "pending");
  const wall = mspWall([quiet, warn, pending, crit]);
  assert.deepEqual(wall.tiles.map((t) => t.id), ["crit", "warn", "quiet", "p"]);
  assert.equal(wall.counts.critical, 1);
  assert.equal(wall.counts.fusion, 1);
});

test("a newest-first sample short of the window is scaled to Sophos's exact total", () => {
  // 100 detections read, all in the last 48 h, of 400 Sophos counted over 7 days.
  const items = Array.from({ length: 100 }, (_, i) => ({ id: String(i), createdAt: NOW - (i / 100) * 48 * H, severity: i % 2 ? "high" : "low", detector: null, sensorTypes: [i < 75 ? "SOPHOS_EMAIL" : "ENDPOINT_AGENT"], techniques: [], status: null }));
  const set = { windowHours: 168, total: 400, items, sampled: true, coveredFrom: NOW - 48 * H, count30d: 900 };
  const week = signalSeries([set], null, NOW, 168);
  assert.equal(week.total, 400, "the 7-day total is Sophos's count, not the sample");
  assert.equal(week.bySeverity.high + week.bySeverity.low, 400);
  const day = signalSeries([set], null, NOW, 24);
  assert.equal(day.total, 51, "the last 24 h (inclusive) are inside the sample, so they are counted exactly");
  const f = flowModel({ detections: [set], alerts: [], cases: [] }, NOW, 168);
  assert.deepEqual(f.sources.map((s) => [s.label, s.count]), [["Sophos Email", 300], ["Endpoint", 100]]);
  assert.equal(f.signals.sampled, true);
});

test("small helpers", () => {
  assert.ok(compareVersions("2026.2.0.10", "2026.2.0.9") > 0);
  assert.ok(compareVersions("10.8.11.4", "2026.1") < 0);
  assert.equal(quantile([1, 2, 3, 4], 0.5), 3);
  assert.equal(quantile([], 0.5), null);
  assert.equal(sensorLabel("ENDPOINT_TAEGIS"), "Endpoint");
  assert.equal(sensorLabel("cloud audit"), "Cloud");
  assert.equal(sensorLabel("SOMETHING_NEW"), "Something New");
  assert.equal(sensorLabel("CLOUDFLARE_HTTP"), "Cloudflare", "a prefix counts only at a word boundary");
});

test("the overview names a Cloudflare source the way the Search screens do, not as Cloud", () => {
  const item = (id, sensor) => ({ id, createdAt: NOW - H, severity: "low", detector: null, sensorTypes: [sensor], techniques: [], status: null });
  const det = { windowHours: 168, total: 3, sampled: false, count30d: 0, items: [item("1", "CLOUDFLARE_HTTP"), item("2", "CLOUDFLARE_HTTP"), item("3", "CLOUD_AUDIT")] };
  const f = flowModel({ detections: [det], alerts: [], cases: [] }, NOW, 24);
  assert.deepEqual(f.sources.map((s) => [s.label, s.count]), [["Cloudflare", 2], ["Cloud", 1]]);
});

test("sensor types the fallback would mangle read as their integration guides name them", () => {
  const cases = {
    CLOUDFLARE_HTTP: "Cloudflare",
    Cloudflare: "Cloudflare",
    iSensor: "Taegis NDR",
    redcloak: "Endpoint",
    AbnormalSecurity: "Abnormal Security",
    "Akamai App & API Protector": "Akamai App & API Protector",
    "Akamai EAA": "Akamai EAA",
    Cisco_ISE: "Cisco ISE",
    "Claroty xDome": "Claroty xDome",
    CyberArk: "CyberArk",
    MCAFEE_EPO: "McAfee ePO",
    SCADAfence: "SCADAfence",
    VMWARE_VCENTER: "VMware vCenter",
  };
  for (const [raw, label] of Object.entries(cases)) assert.equal(sensorLabel(raw), label, raw);
  assert.equal(sensorLabel("Claroty"), "Claroty", "a one word name still reads well from the fallback");
});

test("third-party EDR, firewall and other sensor types on the Taegis Sensor Types page read as their product names", () => {
  // Spelled as the page lists them (docs.taegis.secureworks.com/search/sensor_types/, read 29/10/2026). Each was
  // swallowed by a family prefix (Endpoint, AWS) or title-cased by the fallback (Fortigate Fw, Paloalto Firewall).
  const cases = {
    ENDPOINT_MICROSOFT_ATP: "Microsoft Defender for Endpoint",
    ENDPOINT_CROWD_STRIKE: "CrowdStrike Falcon",
    ENDPOINT_SENTINELONE: "SentinelOne",
    ENDPOINT_CARBON_BLACK_PSC: "Carbon Black Cloud",
    ENDPOINT_HARFANG_LAB: "HarfangLab",
    FORTIGATE_FW: "Fortinet FortiGate",
    PALOALTO_FIREWALL: "Palo Alto Networks Firewall",
    BARRACUDA_FW: "Barracuda Firewall",
    BARRACUDA_WAF: "Barracuda WAF",
    CISCO_FIREWALL_ASA: "Cisco Secure Firewall ASA",
    CISCO_FIREWALL_FTD: "Cisco Secure Firewall Threat Defense",
    "Juniper SRX Firewall": "Juniper SRX Firewall",
    "pfSense Firewall": "pfSense Firewall",
    SonicWall: "SonicWall",
    "Watchguard Firewall": "WatchGuard Firewall",
    "Zscaler Firewall DNS": "Zscaler Firewall DNS",
    "Zscaler NSS": "Zscaler NSS",
    ARUBA_CLEARPASS: "Aruba ClearPass",
    "BlueCoat ProxySG": "Blue Coat ProxySG",
    "Cisco IOS": "Cisco IOS",
    "Cisco IronPort": "Cisco IronPort",
    "Fortinet FortiWeb": "Fortinet FortiWeb",
    "Imperva SecureSphere": "Imperva SecureSphere",
    "McAfee WebGateway": "McAfee Web Gateway",
    named: "BIND DNS (named)",
    Netscaler: "NetScaler",
    PulseSecure_SA: "Pulse Secure",
    SilentDefense: "SilentDefense",
    sshd: "sshd",
    sudo: "sudo",
    SuricataEve: "Suricata EVE",
    VMware_esxi: "VMware ESXi",
    "Amazon GuardDuty": "Amazon GuardDuty",
    "AWS Application Load Balancer": "AWS Application Load Balancer",
    "AWS CloudTrail": "AWS CloudTrail",
    "AWS VPC Flow": "AWS VPC Flow Logs",
    "AWS WAF": "AWS WAF",
    "Cisco eStreamer": "Cisco eStreamer",
    ORACLE_OCI: "Oracle Cloud Infrastructure",
    ORACLE_OCI_AUDIT: "Oracle Cloud Audit",
    ORACLE_OCI_LOADBALANCER: "Oracle Cloud Load Balancer",
    ORACLE_OCI_VCNFLOW: "Oracle Cloud VCN Flow Logs",
  };
  for (const [raw, label] of Object.entries(cases)) assert.equal(sensorLabel(raw), label, raw);
  for (const raw of ["ENDPOINT_SOPHOS", "ENDPOINT_TAEGIS", "ENDPOINT_REDCLOAK"]) assert.equal(sensorLabel(raw), "Endpoint", `${raw} is still the Sophos endpoint row`);
  assert.equal(sensorLabel("AWS_SOMETHING_NEW"), "AWS", "an unlisted AWS type still reads as AWS");
});

test("each Microsoft sensor type on the Taegis Sensor Types page reads as its own source, not Microsoft 365", () => {
  // Spelled as the page lists them; Graph sign-ins, directory audits and risk detections are Entra ID sources.
  const cases = {
    MICROSOFT_WINDOWS_SNARE: "Windows Events (Snare)",
    MICROSOFT_WINDOWS_SPLUNK: "Windows Events (Splunk)",
    "Microsoft IIS": "Microsoft IIS",
    MSDHCP: "Microsoft DHCP",
    MSDNS: "Microsoft DNS",
    ENDPOINT_MICROSOFT_ATP: "Microsoft Defender for Endpoint",
    "Azure Application Gateway": "Azure Application Gateway",
    "Azure Firewall": "Azure Firewall",
    "Azure Flow Logs": "Azure Flow Logs",
    "Azure Front Door": "Azure Front Door",
    "Azure Risk Detection": "Entra ID Risk Detection",
    MICROSOFT_AZURE_ACTIVITY: "Azure Activity Log",
    MICROSOFT_GRAPH_ALERTS: "Microsoft Graph Security",
    MICROSOFT_GRAPH_SIGN_IN: "Entra ID Sign-ins",
    MICROSOFT_GRAPH_DIRECTORY_AUDIT: "Entra ID Audit Logs",
    MICROSOFT_OFFICE_MANAGEMENT: "Microsoft 365",
  };
  for (const [raw, label] of Object.entries(cases)) assert.equal(sensorLabel(raw), label, raw);
  assert.equal(sensorLabel("MICROSOFT_SOMETHING_NEW"), "Microsoft Something New", "an unknown Microsoft type is not called Microsoft 365");
  assert.equal(sensorLabel("AZURE_SOMETHING_NEW"), "Azure Something New");
  assert.equal(sensorLabel("MICROSOFT"), "Microsoft 365");
  assert.equal(sensorLabel("AZURE"), "Azure");
});
