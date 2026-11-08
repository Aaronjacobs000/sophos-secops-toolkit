/**
 * Report reads in demo mode: fictional sign-ins, searches, detections,
 * directory users and cases, made up from a seed and the demo tenants, so
 * every report runs with no credential and no Sophos call. Every person and
 * name is invented, every domain ends in .example and every address comes from
 * the documentation ranges (RFC 5737) or private space.
 */

import type { AlertSet, CaseRecord, EndpointRecord, GeoPoint, SearchMeta } from "../data/types.js";
import type { Provider } from "../services/provider.js";
import { rng } from "../demo/demo-provider.js";
import { tacticLabel, type DetectionDetail, type DetectionDetailSet, type DirectoryUser, type LogRow, type LogSearchResult, type UserActivity, type UserCloudRow, type UserRecentRow, type UserSigninRow, type UserTimelineRow } from "./data.js";
import { bucketFor, groupSchemas, type LogSearchSpec, type MatchKind } from "./queries.js";
import type { ReportSource } from "./source.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** The demo people. Handles match the people the demo endpoints are assigned to. */
export const DEMO_PEOPLE = [
  { handle: "j.patel", name: "Jaya Patel", title: "Finance Manager" },
  { handle: "m.nguyen", name: "Minh Nguyen", title: "Operations Lead" },
  { handle: "k.walsh", name: "Kate Walsh", title: "Payroll Officer" },
  { handle: "s.bui", name: "Son Bui", title: "IT Support" },
  { handle: "r.okafor", name: "Ruth Okafor", title: "Sales Director" },
  { handle: "t.lam", name: "Tony Lam", title: "Warehouse Supervisor" },
  { handle: "a.costa", name: "Ana Costa", title: "HR Advisor" },
  { handle: "l.harris", name: "Liam Harris", title: "Engineer" },
];

const PLACES: Record<string, GeoPoint & { ip: string }> = {
  office: { ip: "192.0.2.24", city: "Sydney", country: "Australia", lat: -33.87, lon: 151.21, source: "dbip" },
  home: { ip: "203.0.113.57", city: "Wollongong", country: "Australia", lat: -34.42, lon: 150.89, source: "dbip" },
  travel: { ip: "198.51.100.61", city: "Singapore", country: "Singapore", lat: 1.35, lon: 103.82, source: "dbip" },
  attacker: { ip: "198.51.100.200", city: "Amsterdam", country: "Netherlands", lat: 52.37, lon: 4.9, source: "dbip" },
};

/** MITRE ATT&CK names and tactics for the techniques the demo detections use (public ATT&CK data). */
const DEMO_MITRE: Record<string, [string, string[]]> = {
  "T1059.001": ["PowerShell", ["Execution"]],
  "T1003.001": ["LSASS Memory", ["Credential Access"]],
  T1078: ["Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"]],
  "T1021.002": ["SMB/Windows Admin Shares", ["Lateral Movement"]],
  T1486: ["Data Encrypted for Impact", ["Impact"]],
  "T1566.001": ["Spearphishing Attachment", ["Initial Access"]],
  "T1110.003": ["Password Spraying", ["Credential Access"]],
  "T1564.008": ["Email Hiding Rules", ["Defense Evasion"]],
};

function mitre(techniques: string[]): Pick<DetectionDetail, "techniqueNames" | "tactics"> {
  const techniqueNames: Record<string, string> = {};
  const tactics = new Set<string>();
  for (const t of techniques) {
    const m = DEMO_MITRE[t];
    if (!m) continue;
    techniqueNames[t] = m[0];
    m[1].forEach((x) => tactics.add(tacticLabel(x)));
  }
  return { techniqueNames, tactics: [...tactics] };
}

function hash(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 16777619) >>> 0;
  return h;
}

function pick<T>(r: () => number, list: readonly T[]): T {
  return list[Math.floor(r() * list.length)]!;
}

function meta(rows: number, calls: number): SearchMeta {
  return { ranAt: Date.now(), reused: false, outcome: "ALL", failedSchemas: [], rows, truncated: false, calls };
}

function domainOf(provider: Provider, tenantId: string): string {
  return `${(provider.tenant(tenantId)?.name ?? "demo").split(/\s+/)[0]!.toLowerCase()}.example`;
}

function findPerson(text: string) {
  const q = text.toLowerCase();
  return DEMO_PEOPLE.find((p) => p.handle.includes(q) || p.name.toLowerCase().includes(q) || q.includes(p.handle));
}

/** Spreads `n` events over the window's buckets, more in office hours. */
function spread(r: () => number, n: number, start: number, end: number, step: number): Map<number, number> {
  const out = new Map<number, number>();
  const first = Math.floor(start / step) * step;
  const slots: number[] = [];
  for (let t = first; t < end; t += step) slots.push(t);
  if (!slots.length) return out;
  const weights = slots.map((t) => {
    const hourOfDay = new Date(t).getUTCHours();
    // Business hours in eastern Australia (UTC+10/11) are about 21:00 to 08:00 UTC.
    const busy = step < DAY && (hourOfDay >= 21 || hourOfDay < 8) ? 3 : 1;
    return busy * (0.5 + r());
  });
  const total = weights.reduce((a, b) => a + b, 0);
  let left = n;
  slots.forEach((t, i) => {
    const share = i === slots.length - 1 ? left : Math.min(left, Math.round((n * weights[i]!) / total));
    left -= share;
    if (share > 0) out.set(t, share);
  });
  return out;
}

export class DemoReportSource implements ReportSource {
  readonly kind = "demo" as const;

  constructor(readonly provider: Provider) {}

  private endpoints(tenantId: string): EndpointRecord[] {
    return this.provider.get("endpoints", tenantId) ?? [];
  }

  async userActivity(tenantId: string, user: string, window: { start: number; end: number }): Promise<UserActivity> {
    const bucket = bucketFor(window);
    const person = findPerson(user);
    const empty: UserActivity = { window, bucket, signins: [], signinsTruncated: false, timeline: [], activity: [], recent: [], cloud: [], geo: {}, search: meta(0, 15) };
    if (!person) return empty;
    const r = rng(hash(`${tenantId}:${person.handle}`));
    const domain = domainOf(this.provider, tenantId);
    const upn = `${person.handle}@${domain}`;
    const devices = this.endpoints(tenantId);
    const laptop = devices.find((e) => e.person === person.handle && !e.isServer) ?? devices.find((e) => !e.isServer) ?? null;
    const server = devices.find((e) => e.isServer) ?? null;
    const days = Math.max(1 / 24, (window.end - window.start) / DAY);
    const span = (fromAgo: number, toAgo: number) => ({ first: Math.max(window.start, window.end - fromAgo), last: Math.max(window.start, window.end - toAgo) });
    const rows: UserSigninRow[] = [];
    const add = (row: Omit<UserSigninRow, "count" | "first" | "last">, perDay: number, when = span(window.end - window.start, r() * 3 * HOUR)) => {
      const count = Math.max(1, Math.round(perDay * days * (0.7 + r() * 0.6)));
      rows.push({ ...row, count, ...when });
    };
    const graph = { user: upn, sourceUser: "", sensorType: "MICROSOFT_GRAPH_SIGN_IN", failure: null, hostId: null } as const;
    for (const app of ["Exchange Online", "Microsoft Teams", "SharePoint Online", "Office 365 Portal"]) {
      add({ ...graph, result: "success", logonType: "INTERACTIVE", mfa: true, app, ip: PLACES.office!.ip }, app === "Exchange Online" ? 5 : 2);
      add({ ...graph, result: "success", logonType: "INTERACTIVE", mfa: true, app, ip: PLACES.home!.ip }, 1.2);
      add({ ...graph, result: "success", logonType: "NONINTERACTIVE", mfa: null, app, ip: PLACES.office!.ip }, 14);
    }
    add({ ...graph, result: "success", logonType: "INTERACTIVE", mfa: false, app: "Office 365 Portal", ip: PLACES.office!.ip }, 0.6);
    if (days >= 3) add({ ...graph, result: "success", logonType: "INTERACTIVE", mfa: true, app: "Microsoft Teams", ip: PLACES.travel!.ip }, 3 / days, span(2.6 * DAY, 1.4 * DAY));
    const attack = span(Math.min(days, 1.8) * DAY, Math.min(days, 1.8) * DAY - 40 * 60_000);
    rows.push({ ...graph, result: "failed", failure: "INCORRECT_USER_OR_PASSWORD", logonType: "INTERACTIVE", mfa: false, app: "Office 365 Portal", ip: PLACES.attacker!.ip, count: 9, ...attack });
    rows.push({ ...graph, result: "failed", failure: "INCORRECT_MFA", logonType: "INTERACTIVE", mfa: false, app: "Exchange Online", ip: PLACES.attacker!.ip, count: 3, ...attack });
    if (laptop) {
      add({ user: person.handle, sourceUser: "", sensorType: "ENDPOINT_SOPHOS", result: "success", failure: null, logonType: "INTERACTIVE", mfa: false, app: "", ip: null, hostId: laptop.id }, 3);
      add({ user: person.handle, sourceUser: "", sensorType: "ENDPOINT_SOPHOS", result: "success", failure: null, logonType: "UNLOCK", mfa: false, app: "", ip: null, hostId: laptop.id }, 6);
    }
    if (server) {
      add({ user: person.handle, sourceUser: "", sensorType: "ENDPOINT_SOPHOS", result: "success", failure: null, logonType: "NETWORK", mfa: false, app: "", ip: "10.20.0.41", hostId: server.id }, 22);
      add({ user: `adm.${person.handle}`, sourceUser: person.handle, sensorType: "ENDPOINT_SOPHOS", result: "success", failure: null, logonType: "REMOTEINTERACTIVE", mfa: false, app: "", ip: "10.20.0.41", hostId: server.id }, 0.4);
    }
    add({ user: person.handle, sourceUser: "", sensorType: "SOPHOS_SFOS", result: "success", failure: null, logonType: "NETWORK", mfa: false, app: "SSL VPN", ip: PLACES.home!.ip, hostId: null }, 1.5);
    rows.push({ user: person.handle, sourceUser: "", sensorType: "SOPHOS_SFOS", result: "failed", failure: "INCORRECT_USER_OR_PASSWORD", logonType: "NETWORK", mfa: false, app: "SSL VPN", ip: PLACES.home!.ip, hostId: null, count: 2, ...span(Math.min(days, 4) * DAY, Math.min(days, 4) * DAY - HOUR) });
    const signins = rows.filter((x) => x.first !== null && x.last !== null && x.last! >= window.start);

    const step = bucket === "1h" ? HOUR : DAY;
    const timeline: UserTimelineRow[] = [];
    for (const s of signins) {
      for (const [at, n] of spread(r, s.count, s.first ?? window.start, (s.last ?? window.end) + 1, step)) timeline.push({ at, result: s.result, sensorType: s.sensorType, count: n });
    }
    timeline.sort((a, b) => a.at - b.at);

    const ops: Array<[string, number, string | null]> = [
      ["MailItemsAccessed", 60, PLACES.office!.ip],
      ["FileAccessed", 18, PLACES.office!.ip],
      ["FileModified", 6, PLACES.office!.ip],
      ["UserLoggedIn", 4, PLACES.office!.ip],
      ["Send", 9, PLACES.office!.ip],
      ["MessageBind", 3, PLACES.home!.ip],
      ["New-InboxRule", 1 / Math.max(days, 1), PLACES.attacker!.ip],
    ];
    const cloud: UserCloudRow[] = ops.map(([operation, perDay, ip]) => ({ sensorType: "MICROSOFT_OFFICE_MANAGEMENT", operation, ip, count: Math.max(1, Math.round(perDay * days * (0.7 + r() * 0.6))), last: operation === "New-InboxRule" ? attack.last : window.end - Math.round(r() * 6 * HOUR) }));
    const cloudTotal = cloud.reduce((a, c) => a + c.count, 0);
    const activity = [
      { schema: "netflow", sensorType: "ENDPOINT_SOPHOS", count: Math.round(1300 * days) },
      { schema: "process", sensorType: "ENDPOINT_SOPHOS", count: Math.round(420 * days) },
      { schema: "http", sensorType: "SOPHOS_SFOS", count: Math.round(310 * days) },
      { schema: "auth", sensorType: "MICROSOFT_GRAPH_SIGN_IN", count: signins.filter((s) => s.sensorType === "MICROSOFT_GRAPH_SIGN_IN").reduce((a, s) => a + s.count, 0) },
      { schema: "auth", sensorType: "ENDPOINT_SOPHOS", count: signins.filter((s) => s.sensorType === "ENDPOINT_SOPHOS").reduce((a, s) => a + s.count, 0) },
      { schema: "auth", sensorType: "SOPHOS_SFOS", count: signins.filter((s) => s.sensorType === "SOPHOS_SFOS").reduce((a, s) => a + s.count, 0) },
      { schema: "filemod", sensorType: "ENDPOINT_SOPHOS", count: Math.round(160 * days) },
      { schema: "cloudaudit", sensorType: "MICROSOFT_OFFICE_MANAGEMENT", count: cloudTotal },
      { schema: "email", sensorType: "SOPHOS_EMAIL", count: Math.round(38 * days) },
      { schema: "registry", sensorType: "ENDPOINT_SOPHOS", count: Math.round(24 * days) },
    ].filter((a) => a.count > 0).sort((a, b) => b.count - a.count);

    const recent: UserRecentRow[] = [];
    const weighted = signins.filter((s) => (s.last ?? 0) >= window.end - 2 * DAY || s.result === "failed");
    for (let i = 0; i < 80 && weighted.length; i++) {
      const s = pick(r, weighted);
      const at = Math.max(s.first ?? window.start, (s.last ?? window.end) - Math.round(r() * Math.min(2 * DAY, (s.last ?? window.end) - (s.first ?? window.start))));
      recent.push({ at, user: s.user, sourceUser: s.sourceUser, sensorType: s.sensorType, result: s.result, failure: s.failure, logonType: s.logonType, mfa: s.mfa, app: s.app, ip: s.ip, hostId: s.hostId });
    }
    recent.sort((a, b) => b.at - a.at);
    const geo: Record<string, GeoPoint> = {};
    for (const p of Object.values(PLACES)) geo[p.ip] = { city: p.city, country: p.country, lat: p.lat, lon: p.lon, source: p.source };
    return { window, bucket, signins, signinsTruncated: false, timeline, activity, recent: recent.slice(0, 100), cloud, geo, search: meta(signins.length + timeline.length + activity.length + recent.length + cloud.length, 17) };
  }

  /** The demo's cached detections, given titles and entities; weeks before the cache are rebuilt from it with a different seed. */
  async detections(tenantId: string, hours: number, match: { kind: MatchKind; value: string } | null = null): Promise<DetectionDetailSet> {
    const cached = this.provider.get("detections", tenantId);
    if (!cached) return { hours, total: 0, items: [], sampled: false };
    const now = Date.now();
    const start = now - hours * HOUR;
    const devices = this.endpoints(tenantId);
    const domain = domainOf(this.provider, tenantId);
    const weeks = Math.ceil(hours / 168);
    const items: DetectionDetail[] = [];
    for (let w = 0; w < weeks; w++) {
      const r = rng(hash(`${tenantId}:week:${w}`));
      for (const d of cached.items) {
        if (w > 0 && r() < 0.25) continue;
        const createdAt = d.createdAt - w * 7 * DAY;
        if (createdAt < start) continue;
        const h = hash(d.id);
        // About one detection in six names a person, as identity and email detections do.
        const person = h % 6 === 0 ? DEMO_PEOPLE[(h >>> 3) % DEMO_PEOPLE.length]! : null;
        // A detection that names a person happens on one of that person's devices when they have one.
        const own = person ? devices.filter((e) => e.person === person.handle) : [];
        const pool = own.length ? own : devices;
        const device = pool.length ? pool[h % pool.length]! : null;
        items.push({
          id: w ? `${d.id}:w${w}` : d.id,
          createdAt,
          severity: d.severity,
          title: d.detector ?? "Detection",
          detector: d.detector,
          sensorTypes: d.sensorTypes,
          techniques: d.techniques,
          ...mitre(d.techniques),
          status: d.status,
          users: person ? [`${person.handle}@${domain}`] : [],
          hosts: device ? [device.hostname] : [],
          ips: [`${["192.0.2", "198.51.100", "203.0.113"][h % 3]}.${10 + (h % 200)}`],
        });
      }
    }
    // The demo user report's story: a password spray, then a mailbox rule, from the documentation range.
    const spray = findPerson(match?.value ?? "");
    if (match?.kind === "user" && spray) {
      const at = now - Math.min(hours, 43.2) * HOUR;
      const user = `${spray.handle}@${domain}`;
      items.push(
        { id: `alert://priv:demo:spray:${spray.handle}`, createdAt: at + 20 * 60_000, severity: "high", title: "Password spray against Microsoft 365", detector: "Brute force sign-in", sensorTypes: ["MICROSOFT_GRAPH_SIGN_IN"], techniques: ["T1110.003"], ...mitre(["T1110.003"]), status: "OPEN", users: [user], hosts: [], ips: [PLACES.attacker!.ip] },
        { id: `alert://priv:demo:rule:${spray.handle}`, createdAt: at + 50 * 60_000, severity: "critical", title: "Inbox rule hides messages from a new sign-in location", detector: "Mailbox rule created", sensorTypes: ["MICROSOFT_OFFICE_MANAGEMENT"], techniques: ["T1564.008"], ...mitre(["T1564.008"]), status: "OPEN", users: [user], hosts: [], ips: [PLACES.attacker!.ip] },
      );
    }
    let filtered = items;
    if (match) {
      const v = match.value.toLowerCase();
      filtered = items.filter((d) => (match.kind === "user" ? d.users : match.kind === "host" ? d.hosts : d.ips).some((x) => (match.kind === "ip" ? x === match.value : x.toLowerCase().includes(v))));
    }
    filtered.sort((a, b) => b.createdAt - a.createdAt);
    return { hours, total: filtered.length, items: filtered.slice(0, 3_000), sampled: filtered.length > 3_000 };
  }

  async alerts(tenantId: string, hours: number): Promise<AlertSet> {
    const cached = this.provider.get("alerts", tenantId);
    if (!cached) return { sinceHours: hours, total: 0, items: [] };
    const now = Date.now();
    const items = [];
    for (let w = 0; w < Math.ceil(hours / 168); w++) {
      const r = rng(hash(`${tenantId}:alerts:${w}`));
      for (const a of cached.items) {
        if (w > 0 && r() < 0.3) continue;
        const at = Date.parse(a.raisedAt) - w * 7 * DAY;
        if (at >= now - hours * HOUR) items.push({ ...a, id: w ? `${a.id}-w${w}` : a.id, raisedAt: new Date(at).toISOString() });
      }
    }
    return { sinceHours: hours, total: items.length, items };
  }

  async directory(tenantId: string, text: string): Promise<{ users: DirectoryUser[]; total: number }> {
    const q = text.toLowerCase();
    const domain = domainOf(this.provider, tenantId);
    const users = DEMO_PEOPLE.filter((p) => p.handle.includes(q) || p.name.toLowerCase().includes(q) || `${p.handle}@${domain}`.includes(q) || q.includes(p.handle)).map((p) => {
      const h = hash(`${tenantId}:${p.handle}`);
      const [firstName, lastName] = p.name.split(" ");
      return {
        name: p.name,
        firstName: firstName ?? null,
        lastName: lastName ?? null,
        email: `${p.handle}@${domain}`,
        exchangeLogin: `${p.handle}@${domain}`,
        source: "Microsoft Entra ID sync",
        domain,
        groups: 2 + (h % 6),
        createdAt: new Date(Date.UTC(2023 + (h % 3), h % 12, 1 + (h % 27))).toISOString(),
        updatedAt: new Date(Date.now() - (h % 9) * DAY).toISOString(),
      };
    });
    return { users, total: users.length };
  }

  async casesByTitle(tenantId: string, text: string): Promise<{ cases: CaseRecord[]; more: boolean } | null> {
    const set = this.provider.get("cases", tenantId);
    if (!set || set.api !== "v2") return null;
    const q = text.toLowerCase();
    const cases = [...set.open, ...set.recentClosed].filter((c) => c.title.toLowerCase().includes(q));
    return { cases, more: false };
  }

  async logSearch(tenantId: string, spec: LogSearchSpec, window: { start: number; end: number }): Promise<LogSearchResult> {
    const bucket = bucketFor(window);
    const r = rng(hash(`${tenantId}:${spec.kind}:${spec.value}:${spec.schemas.join()}`));
    const empty: LogSearchResult = { window, bucket, timeline: [], groups: null, rows: [], rowsTruncated: false, search: meta(0, 10) };
    if (spec.kind === "user" && !findPerson(spec.value)) return empty;
    const devices = this.endpoints(tenantId);
    const domain = domainOf(this.provider, tenantId);
    const hours = (window.end - window.start) / HOUR;
    const perHour = spec.kind === "user" ? 90 : spec.kind === "ip" ? 160 : 260;
    const WEIGHTS: Record<string, number> = { netflow: 0.34, process: 0.2, http: 0.12, dnsquery: 0.14, auth: 0.06, filemod: 0.05, cloudaudit: 0.02, email: 0.02, registry: 0.02, nids: 0.01, antivirus: 0.004, thirdparty: 0.006, managementevent: 0.004, persistence: 0.002 };
    const SENSORS: Record<string, string[]> = {
      netflow: ["ENDPOINT_SOPHOS", "SOPHOS_SFOS"],
      process: ["ENDPOINT_SOPHOS"],
      http: ["SOPHOS_SFOS", "ENDPOINT_SOPHOS"],
      dnsquery: ["ENDPOINT_SOPHOS"],
      auth: ["MICROSOFT_GRAPH_SIGN_IN", "ENDPOINT_SOPHOS", "SOPHOS_SFOS"],
      filemod: ["ENDPOINT_SOPHOS"],
      cloudaudit: ["MICROSOFT_OFFICE_MANAGEMENT"],
      email: ["SOPHOS_EMAIL"],
      registry: ["ENDPOINT_SOPHOS"],
      nids: ["SOPHOS_SFOS"],
    };
    const schemas = spec.schemas.filter((s) => (WEIGHTS[s] ?? 0) > 0);
    const sensorsFor = (s: string) => (SENSORS[s] ?? ["ENDPOINT_SOPHOS"]).filter((x) => !spec.sensors.length || spec.sensors.includes(x));
    const step = bucket === "1h" ? HOUR : DAY;
    const timeline: LogSearchResult["timeline"] = [];
    for (const s of schemas) {
      if (!sensorsFor(s).length) continue;
      const n = Math.round(perHour * hours * WEIGHTS[s]! * (0.6 + r() * 0.8));
      for (const [at, c] of spread(r, n, window.start, window.end, step)) timeline.push({ at, schema: s, count: c });
    }
    timeline.sort((a, b) => a.at - b.at);
    const bySchema = new Map<string, number>();
    for (const t of timeline) bySchema.set(t.schema, (bySchema.get(t.schema) ?? 0) + t.count);
    const person = findPerson(spec.value);
    const user = person ? `${person.handle}@${domain}` : DEMO_PEOPLE[hash(spec.value) % DEMO_PEOPLE.length]!.handle;
    const ip = (i: number) => `${["192.0.2", "198.51.100", "203.0.113"][i % 3]}.${20 + ((i * 37) % 200)}`;
    const values: Record<string, (i: number) => string> = {
      host_id: (i) => (devices.length ? devices[(hash(spec.value) + i * 7) % devices.length]!.id : "unknown"),
      source_address: (i) => (spec.kind === "ip" && i === 0 ? spec.value : i % 2 ? `10.20.${i}.${30 + i}` : ip(i)),
      destination_address: (i) => (spec.kind === "ip" && i === 0 ? spec.value : ip(i + 5)),
      destination_port: (i) => ["443", "53", "80", "445", "3389", "22", "8080", "123"][i % 8]!,
      target_user_name: (i) => (i === 0 ? user : `${DEMO_PEOPLE[i % DEMO_PEOPLE.length]!.handle}@${domain}`),
      action_result: (i) => ["SUCCESS", "FAILED"][i % 2]!,
      application_name: (i) => ["Exchange Online", "Microsoft Teams", "SharePoint Online", "SSL VPN", "OneDrive"][i % 5]!,
      query_name: (i) => [`mail.${domain}`, "update.vendor.example", "cdn.static.example", "login.identity.example", "files.share.example", "telemetry.app.example"][i % 6]!,
      uri_host: (i) => ["portal.office.example", "update.vendor.example", "intranet." + domain, "cdn.static.example"][i % 4]!,
      event_name: (i) => ["MailItemsAccessed", "FileAccessed", "UserLoggedIn", "Send", "FileModified"][i % 5]!,
      image_path: (i) => ["C:\\Windows\\System32\\svchost.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"][i % 5]!,
    };
    let groups: LogSearchResult["groups"] = null;
    const gSchemas = groupSchemas(spec).filter((s) => bySchema.has(s));
    if (gSchemas.length) {
      const rows: Array<{ value: string; schema: string; sensorType: string | null; count: number }> = [];
      for (const s of gSchemas) {
        const total = bySchema.get(s) ?? 0;
        if (spec.groupBy === "sensor_type" || spec.groupBy === "schema") {
          const sensors = sensorsFor(s);
          sensors.forEach((sensor, i) => rows.push({ value: sensor, schema: s, sensorType: sensor, count: Math.round(total * (i === 0 ? 0.75 : 0.25 / Math.max(1, sensors.length - 1))) }));
          continue;
        }
        const make = values[spec.groupBy] ?? ((i: number) => `value ${i + 1}`);
        let left = total;
        for (let i = 0; i < 12 && left > 0; i++) {
          const c = i === 11 ? left : Math.max(1, Math.round(left * (0.35 + r() * 0.2)));
          rows.push({ value: make(i), schema: s, sensorType: null, count: c });
          left -= c;
        }
      }
      groups = { field: spec.groupBy, schemas: groupSchemas(spec), rows };
    }
    const events: LogRow[] = [];
    const totalEvents = [...bySchema.values()].reduce((a, b) => a + b, 0);
    for (let i = 0; i < Math.min(spec.rows, totalEvents); i++) {
      const s = pick(r, [...bySchema.keys()].flatMap((k) => new Array(Math.max(1, Math.round((WEIGHTS[k] ?? 0.01) * 50))).fill(k)));
      const at = window.end - Math.round(Math.pow(r(), 1.6) * Math.min(window.end - window.start, 6 * HOUR));
      const host = devices.length ? devices[(hash(spec.value) + i) % Math.min(devices.length, 6)]! : null;
      const k = Math.floor(r() * 6);
      events.push({
        at,
        schema: s,
        sensorType: pick(r, sensorsFor(s).length ? sensorsFor(s) : ["ENDPOINT_SOPHOS"]),
        hostId: host?.id ?? null,
        user: s === "netflow" || s === "dnsquery" || s === "http" ? (spec.kind === "user" ? user : "") : user,
        source: spec.kind === "ip" && r() < 0.5 ? spec.value : `10.20.${k}.${40 + k}`,
        destination: s === "dnsquery" ? values.query_name!(k) : s === "http" ? values.uri_host!(k) : s === "netflow" ? `${spec.kind === "ip" && r() < 0.5 ? spec.value : ip(k + 3)}:${values.destination_port!(k)}` : "",
        action: s === "auth" ? (r() < 0.9 ? "SUCCESS" : "FAILED") : s === "netflow" ? "ALLOW" : s === "http" ? "GET" : "",
        detail: s === "process" ? values.image_path!(k) : s === "cloudaudit" ? values.event_name!(k) : s === "auth" ? values.application_name!(k) : s === "filemod" ? `C:\\Users\\${person?.handle ?? "user"}\\Documents\\report-${k + 1}.xlsx` : "",
      });
    }
    events.sort((a, b) => b.at - a.at);
    return { window, bucket, timeline, groups, rows: events, rowsTruncated: events.length >= spec.rows, search: meta(timeline.length + events.length, 12) };
  }
}

