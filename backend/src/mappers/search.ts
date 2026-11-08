/**
 * Search GraphQL views X10 (sign-in map), X11 (sign-ins without MFA) and N3
 * (data source health): the QL each one runs and the pure shaping of the
 * aggregate rows Sophos returns into the cached records. No I/O here.
 *
 * Measured on live tenants 29/10/2026:
 * - Aggregate rows carry the group fields, schema_type and row_count;
 *   `max(event_time_usec)` comes back as max_event_time_usec, and a `1d` time
 *   group as event_time_usec_1d ("2026-10-28 00:00:00", UTC).
 * - The API refuses a time range over 31 days.
 * - Structured fields (src_ipgeo_summary, os) can't be grouped; os.os can.
 * - Only identity sources fill the MFA fields: Microsoft Graph sign-ins
 *   (MICROSOFT_GRAPH_SIGN_IN) reported mfa_used true and MFA_SUCCESS, while
 *   Sophos endpoint logons (ENDPOINT_SOPHOS) always say mfa_used false with
 *   UNKNOWN_MFA_RESULT. Counting those as "without MFA" would be wrong.
 * - Within Graph sign-ins, only interactive user sign-ins carry an MFA answer.
 *   Service principal sign-ins (logon_type SERVICE, a client secret or
 *   assertion) can't use MFA, and non-interactive ones (NONINTERACTIVE, a
 *   refresh token) report none of their own: on one tenant all 23,201 were
 *   one or the other, mfa_used false and UNKNOWN_MFA_RESULT throughout.
 * - A grouped os.os comes back as os_os.
 */

import type { GeoPoint, MfaSet, SearchMeta, SigninLocation, SigninSet, SourceRecord, SourceSet, SourceState } from "../data/types.js";
import type { SearchRun } from "../vendor/sophos-core/index.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** Every search window ends on a quarter hour, so a repeat inside it reuses the same search. */
export const SEARCH_BUCKET_MS = 15 * 60_000;
export const SEARCH_WINDOW_DAYS = 7;

export function searchWindow(now: number, days = SEARCH_WINDOW_DAYS): { start: number; end: number } {
  const end = Math.floor(now / SEARCH_BUCKET_MS) * SEARCH_BUCKET_MS;
  return { start: end - days * DAY, end };
}

function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Absolute bounds: getOrCreateSearch only matches a query with fixed times. */
export function qlWindow(window: { start: number; end: number }): string {
  return `earliest='${iso(window.start)}' latest='${iso(window.end)}'`;
}

const LOGON = "action = 'LOGON'";

export function signinsQl(window: { start: number; end: number }): string {
  return `from auth where ${LOGON} ${qlWindow(window)} | aggregate count by source_address, action_result, failure_category, mfa_used, sensor_type, logon_type`;
}

export function mfaQl(window: { start: number; end: number }): string {
  return `from auth where ${LOGON} and action_result = 'SUCCESS' ${qlWindow(window)} | aggregate count by sensor_type, mfa_used, logon_type, application_name, os.os`;
}

/** Top users without MFA, limited to the sources that report MFA (sensor types are checked, never pasted raw). */
export function mfaUsersQl(window: { start: number; end: number }, sensorTypes: string[]): string | null {
  // Spaces are allowed: the integration guides name sensor types such as 'Google Workspace'.
  const safe = sensorTypes.filter((s) => /^[A-Za-z0-9_. -]{1,80}$/.test(s));
  if (!safe.length) return null;
  return `from auth where ${LOGON} and action_result = 'SUCCESS' and mfa_used = false and sensor_type in (${safe.map((s) => `'${s}'`).join(", ")}) ${qlWindow(window)} | aggregate count by target_user_name, sensor_type, logon_type`;
}

/** Event schemas a data source can feed. Derived findings, alerts and cases are left out. */
export const SOURCE_SCHEMAS = [
  "agentdetection", "antivirus", "apicall", "auth", "cloudaudit", "dhcp", "dnsquery", "email", "encrypt", "filemod", "forensicinfo", "generic", "http",
  "inventoryinfo", "managementevent", "netflow", "nids", "patchstate", "persistence", "process", "processmodule", "registry", "scriptblock", "softwareinfo",
  "thirdparty", "threadinjection",
];

export function sourcesQl(window: { start: number; end: number }): string {
  return `from ${SOURCE_SCHEMAS.join(", ")} ${qlWindow(window)} | aggregate count, max(event_time_usec) by sensor_type, 1d`;
}

// ---------------------------------------------------------------- helpers

type Row = Record<string, unknown>;

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function count(v: unknown): number {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function bool(v: unknown): boolean | null {
  if (v === true || v === "true" || v === "TRUE") return true;
  if (v === false || v === "false" || v === "FALSE") return false;
  return null;
}

export function searchMeta(runs: SearchRun[], ranAt: number): SearchMeta {
  return {
    ranAt,
    reused: runs.length > 0 && runs.every((r) => r.reused),
    outcome: runs.some((r) => r.outcome === "PARTIAL") ? "PARTIAL" : "ALL",
    failedSchemas: [...new Set(runs.flatMap((r) => r.failedPartitions.map((p) => p.schemaType ?? "unnamed")))],
    rows: runs.reduce((a, r) => a + r.rows.length, 0),
    truncated: runs.some((r) => r.truncated),
    calls: runs.reduce((a, r) => a + r.calls, 0),
  };
}

/**
 * Identity providers known to fill the MFA fields, even in a week when nobody used MFA.
 * Matched with case and separators ignored: Fusion stores MICROSOFT_GRAPH_SIGN_IN, while
 * the Taegis Sensor Types page lists Cisco Duo and Google Workspace.
 */
const IDENTITY_SOURCES = /^(MICROSOFTGRAPH|AZUREAD|ENTRA|OKTA|DUO|CISCODUO|GOOGLEWORKSPACE|GSUITE|ONELOGIN|PING|JUMPCLOUD|AUTH0)/i;

/**
 * Sensor types whose sign-ins can be counted for MFA: a known identity
 * provider, or any non-endpoint source that reported MFA in the window.
 * Endpoint logons never are: they always say mfa_used false.
 */
export function mfaSources(rows: Array<{ sensorType: string; mfaUsed: boolean | null }>): Set<string> {
  const out = new Set<string>();
  for (const r of rows) {
    if (/^ENDPOINT/i.test(r.sensorType)) continue;
    if (IDENTITY_SOURCES.test(r.sensorType.replace(/[^A-Za-z0-9]+/g, "")) || r.mfaUsed === true) out.add(r.sensorType);
  }
  return out;
}

/**
 * Who signed in, from logon_type: a service principal (SERVICE) can't use MFA,
 * and a non-interactive sign-in (NONINTERACTIVE, a token refresh) reports no
 * MFA of its own, so only the rest are counted for MFA.
 */
export type SigninKind = "user" | "service" | "nonInteractive";

export function signinKind(logonType: string | null): SigninKind {
  const t = logonType?.toUpperCase();
  return t === "SERVICE" ? "service" : t === "NONINTERACTIVE" ? "nonInteractive" : "user";
}

const OS_NAMES: Record<string, string> = {
  OS_WINDOWS: "Windows",
  OS_MAC: "macOS",
  OS_IPHONE: "iPhone",
  OS_IPAD: "iPad",
  OS_ANDROID: "Android",
  OS_LINUX: "Linux",
  OS_UNKNOWN: "Unknown",
};

export function osName(raw: string | null): string {
  if (!raw) return "Unknown";
  return OS_NAMES[raw.toUpperCase()] ?? raw.replace(/^OS_/i, "").toLowerCase().replace(/\b\w/g, (m) => m.toUpperCase());
}

const FAILURE_NAMES: Record<string, string> = {
  INCORRECT_USER_OR_PASSWORD: "Wrong user name or password",
  INCORRECT_MFA: "MFA failed",
  ACCOUNT_DISABLED: "Account disabled",
  ACCOUNT_LOCKED_OUT: "Account locked out",
  EXPIRED_PASSWORD: "Password expired",
  OVERDUE_PASSWORD_CHANGE: "Password change overdue",
  INVALID_ACCOUNT: "No such account",
  OUTSIDE_PERMISSIBLE_HOURS: "Outside allowed hours",
  OTHER_ERROR: "Other error",
  UNKNOWN_FAILURE_CATEGORY: "Reason not given",
};

export function failureName(raw: string | null): string {
  if (!raw) return "Reason not given";
  return FAILURE_NAMES[raw.toUpperCase()] ?? raw.toLowerCase().replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase());
}

function rank<T>(map: Map<string, T>, by: (v: T) => number, limit: number): T[] {
  return [...map.values()].sort((a, b) => by(b) - by(a)).slice(0, limit);
}

// ---------------------------------------------------------------- X10 sign-ins

interface SigninRow {
  ip: string | null;
  success: boolean;
  failed: boolean;
  failure: string | null;
  mfaUsed: boolean | null;
  sensorType: string;
  kind: SigninKind;
  count: number;
}

export function parseSigninRows(values: Row[]): SigninRow[] {
  return values.map((v) => {
    const result = str(v.action_result)?.toUpperCase() ?? "";
    return {
      ip: str(v.source_address),
      success: result === "SUCCESS",
      failed: result === "FAILED",
      failure: str(v.failure_category),
      mfaUsed: bool(v.mfa_used),
      sensorType: str(v.sensor_type) ?? "UNKNOWN",
      kind: signinKind(str(v.logon_type)),
      count: count(v.row_count),
    };
  });
}

/**
 * Shapes the X10 aggregate. `geo` holds a location for each public IP the
 * fetcher could place; `isPublic` decides which addresses count as internal.
 */
export function signinSet(args: {
  values: Row[];
  window: { start: number; end: number };
  geo: Record<string, GeoPoint>;
  isPublic: (ip: string) => boolean;
  meta: SearchMeta;
}): SigninSet {
  const rows = parseSigninRows(args.values);
  const aware = mfaSources(rows);
  const bySource = new Map<string, { sensorType: string; total: number; failed: number; reportsMfa: boolean }>();
  const failures = new Map<string, { reason: string; count: number }>();
  const locations = new Map<string, SigninLocation>();
  let total = 0;
  let success = 0;
  let failed = 0;
  const placement = { placed: 0, unplaced: 0, internal: 0 };
  for (const r of rows) {
    if (!r.count) continue;
    total += r.count;
    if (r.success) success += r.count;
    if (r.failed) failed += r.count;
    const src = bySource.get(r.sensorType) ?? { sensorType: r.sensorType, total: 0, failed: 0, reportsMfa: aware.has(r.sensorType) };
    src.total += r.count;
    if (r.failed) src.failed += r.count;
    bySource.set(r.sensorType, src);
    if (r.failed) {
      const reason = failureName(r.failure);
      const f = failures.get(reason) ?? { reason, count: 0 };
      f.count += r.count;
      failures.set(reason, f);
    }
    if (!r.ip || !args.isPublic(r.ip)) {
      placement.internal += r.count;
      continue;
    }
    const g = args.geo[r.ip];
    if (!g) {
      placement.unplaced += r.count;
      continue;
    }
    placement.placed += r.count;
    const key = `${g.city ?? ""}|${g.country ?? ""}|${g.lat.toFixed(1)}|${g.lon.toFixed(1)}`;
    const loc = locations.get(key) ?? { key, city: g.city, country: g.country, lat: g.lat, lon: g.lon, source: g.source, total: 0, failed: 0, noMfa: 0 };
    loc.total += r.count;
    if (r.failed) loc.failed += r.count;
    if (r.success && r.mfaUsed === false && r.kind === "user" && aware.has(r.sensorType)) loc.noMfa += r.count;
    locations.set(key, loc);
  }
  return {
    windowStart: args.window.start,
    windowEnd: args.window.end,
    total,
    success,
    failed,
    bySource: rank(bySource, (s) => s.total, 50),
    failures: rank(failures, (f) => f.count, 12),
    locations: [...locations.values()].sort((a, b) => b.total - a.total),
    placement,
    search: args.meta,
  };
}

// ---------------------------------------------------------------- X11 MFA

export interface MfaRow {
  sensorType: string;
  mfaUsed: boolean | null;
  kind: SigninKind;
  app: string;
  os: string;
  count: number;
}

export function parseMfaRows(values: Row[]): MfaRow[] {
  return values.map((v) => ({
    sensorType: str(v.sensor_type) ?? "UNKNOWN",
    mfaUsed: bool(v.mfa_used),
    kind: signinKind(str(v.logon_type)),
    app: str(v.application_name) ?? "Not named",
    os: osName(str(v.os_os) ?? str(v["os.os"]) ?? str((v.os as Row | undefined)?.os)),
    count: count(v.row_count),
  }));
}

/**
 * Shapes the X11 aggregates: successful sign-ins by source, app and OS, then
 * the top users without MFA. Service principal and non-interactive sign-ins
 * from an MFA-aware source are totalled apart and never counted.
 */
export function mfaSet(args: { values: Row[]; userValues: Row[]; usersTruncated: boolean; window: { start: number; end: number }; meta: SearchMeta }): MfaSet {
  const rows = parseMfaRows(args.values);
  const aware = mfaSources(rows);
  const sources = new Map<string, MfaSet["sources"][number]>();
  const apps = new Map<string, { name: string; signins: number; withoutMfa: number }>();
  const oses = new Map<string, { name: string; signins: number; withoutMfa: number }>();
  let signins = 0;
  let withMfa = 0;
  let withoutMfa = 0;
  let service = 0;
  let nonInteractive = 0;
  for (const r of rows) {
    if (!r.count) continue;
    const reports = aware.has(r.sensorType);
    const s = sources.get(r.sensorType) ?? { sensorType: r.sensorType, signins: 0, withMfa: 0, withoutMfa: 0, service: 0, nonInteractive: 0, reportsMfa: reports };
    s.signins += r.count;
    sources.set(r.sensorType, s);
    if (reports && r.kind !== "user") {
      s[r.kind] += r.count;
      if (r.kind === "service") service += r.count;
      else nonInteractive += r.count;
      continue;
    }
    if (r.mfaUsed === true) s.withMfa += r.count;
    if (r.mfaUsed === false) s.withoutMfa += r.count;
    // Sources that don't report MFA are listed but never counted below.
    if (!reports) continue;
    signins += r.count;
    if (r.mfaUsed === true) withMfa += r.count;
    const without = r.mfaUsed === false ? r.count : 0;
    withoutMfa += without;
    const a = apps.get(r.app) ?? { name: r.app, signins: 0, withoutMfa: 0 };
    a.signins += r.count;
    a.withoutMfa += without;
    apps.set(r.app, a);
    const o = oses.get(r.os) ?? { name: r.os, signins: 0, withoutMfa: 0 };
    o.signins += r.count;
    o.withoutMfa += without;
    oses.set(r.os, o);
  }
  const users = new Map<string, { user: string; withoutMfa: number; sensorType: string }>();
  for (const v of args.userValues) {
    const user = str(v.target_user_name) ?? "Not named";
    const sensorType = str(v.sensor_type) ?? "UNKNOWN";
    if (!aware.has(sensorType) || signinKind(str(v.logon_type)) !== "user") continue;
    const u = users.get(user) ?? { user, withoutMfa: 0, sensorType };
    u.withoutMfa += count(v.row_count);
    users.set(user, u);
  }
  return {
    windowStart: args.window.start,
    windowEnd: args.window.end,
    sources: rank(sources, (s) => s.signins, 50),
    signins,
    withMfa,
    withoutMfa,
    service,
    nonInteractive,
    byApp: rank(apps, (a) => a.withoutMfa * 1e6 + a.signins, 12),
    byOs: rank(oses, (o) => o.withoutMfa * 1e6 + o.signins, 8),
    topUsers: [...users.values()].filter((u) => u.withoutMfa > 0).sort((a, b) => b.withoutMfa - a.withoutMfa || a.user.localeCompare(b.user)).slice(0, 25),
    usersTruncated: args.usersTruncated,
    search: args.meta,
  };
}

// ---------------------------------------------------------------- N3 data sources

/** No event for this long makes a source quiet. */
export const SOURCE_QUIET_MS = 24 * HOUR;
/** A source missing from the window stays listed as silent for this long after its last event. */
export const SOURCE_KEEP_MS = 30 * DAY;

function dayKey(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

function bucketDay(v: unknown): string | null {
  const s = str(v);
  if (!s) return null;
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(s);
  return m ? m[1]! : null;
}

function usec(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? Math.round(n / 1000) : null;
}

export function sourceState(lastEventAt: number | null, now: number, inWindow: boolean): SourceState {
  if (!inWindow) return "silent";
  return lastEventAt !== null && now - lastEventAt <= SOURCE_QUIET_MS ? "live" : "quiet";
}

/**
 * Shapes the N3 aggregate (count and newest event per sensor type, schema and
 * UTC day). A source the previous refresh saw that is missing now is kept as
 * silent until its last event is 30 days old.
 */
export function sourceSet(args: { values: Row[]; window: { start: number; end: number }; now: number; previous: SourceSet | null; meta: SearchMeta }): SourceSet {
  const days: string[] = [];
  for (let t = Date.parse(`${dayKey(args.window.start)}T00:00:00Z`); t <= args.window.end; t += DAY) days.push(dayKey(t));
  const index = new Map(days.map((d, i) => [d, i]));
  const map = new Map<string, { sensorType: string; schemas: Set<string>; events7d: number; daily: number[]; unparsed7d: number; lastEventAt: number | null }>();
  for (const v of args.values) {
    const n = count(v.row_count);
    if (!n) continue;
    const sensorType = str(v.sensor_type) ?? "UNKNOWN";
    const schema = str(v.schema_type) ?? "unknown";
    const s = map.get(sensorType) ?? { sensorType, schemas: new Set<string>(), events7d: 0, daily: days.map(() => 0), unparsed7d: 0, lastEventAt: null };
    s.schemas.add(schema);
    s.events7d += n;
    if (schema === "generic") s.unparsed7d += n;
    const i = index.get(bucketDay(v.event_time_usec_1d) ?? "");
    if (i !== undefined) s.daily[i]! += n;
    const last = usec(v.max_event_time_usec);
    if (last !== null && (s.lastEventAt === null || last > s.lastEventAt)) s.lastEventAt = last;
    map.set(sensorType, s);
  }
  const sources: SourceRecord[] = [...map.values()].map((s) => ({
    sensorType: s.sensorType,
    schemas: [...s.schemas].sort(),
    events7d: s.events7d,
    daily: s.daily,
    unparsed7d: s.unparsed7d,
    lastEventAt: s.lastEventAt,
    state: sourceState(s.lastEventAt, args.now, true),
  }));
  for (const p of args.previous?.sources ?? []) {
    if (map.has(p.sensorType) || p.lastEventAt === null || args.now - p.lastEventAt > SOURCE_KEEP_MS) continue;
    sources.push({ ...p, events7d: 0, daily: days.map(() => 0), unparsed7d: 0, state: "silent" });
  }
  const order: Record<SourceState, number> = { silent: 0, quiet: 1, live: 2 };
  sources.sort((a, b) => order[a.state] - order[b.state] || b.events7d - a.events7d || a.sensorType.localeCompare(b.sensorType));
  return {
    windowStart: args.window.start,
    windowEnd: args.window.end,
    days,
    sources,
    events7d: sources.reduce((a, s) => a + s.events7d, 0),
    unparsed7d: sources.reduce((a, s) => a + s.unparsed7d, 0),
    search: args.meta,
  };
}
