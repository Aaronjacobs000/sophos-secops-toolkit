/**
 * The QL behind the user investigation and log search reports, and the input
 * checks that keep a typed value from ever changing the query's shape. Pure:
 * no I/O, so the tests drive every builder directly.
 *
 * Measured on a live Fusion tenant, 06/11/2026:
 * - The logical fields are valid on only some schemas, and a query naming one
 *   on any other schema fails validation as a whole. @user: 19 schemas, @ip:
 *   17, @host: 13 (the lists below). The unparsed generic schema takes none.
 * - `| fields` fails unless every field exists in every schema queried, so
 *   multi-schema rows are read unprojected (every field of every schema in
 *   the query, about 6 KB a row).
 * - `| head N` caps the rows of a multi-schema search as a whole, newest
 *   first. Rows from a search over nine event types came back without most
 *   per-type fields (a process row had no user or image path); eight or
 *   fewer came back whole. Rows are therefore read a few event types at a time. `min(event_time_usec)` and `max(event_time_usec)` aggregate, and a
 *   `1h` or `1d` time group comes back as event_time_usec_1h or _1d in UTC.
 * - Fusion's host_id for a Sophos endpoint is its Sophos Central endpoint ID.
 * - Detection QL accepts the logical fields too: from alert where @user ...
 */

import net from "node:net";
import { qlWindow, SOURCE_SCHEMAS } from "../mappers/search.js";

export const USER_SCHEMAS = [
  "agentdetection", "antivirus", "auth", "cloudaudit", "email", "filemod", "forensicinfo", "http", "inventoryinfo", "managementevent",
  "netflow", "nids", "patchstate", "persistence", "process", "processmodule", "registry", "softwareinfo", "thirdparty",
] as const;

export const IP_SCHEMAS = [
  "antivirus", "apicall", "auth", "cloudaudit", "dhcp", "dnsquery", "email", "encrypt", "forensicinfo", "http", "inventoryinfo",
  "managementevent", "netflow", "nids", "patchstate", "softwareinfo", "thirdparty",
] as const;

export const HOST_SCHEMAS = [
  "antivirus", "auth", "cloudaudit", "dhcp", "dnsquery", "forensicinfo", "inventoryinfo", "managementevent", "netflow", "patchstate",
  "process", "softwareinfo", "thirdparty",
] as const;

export type MatchKind = "user" | "ip" | "host";

export const MATCH_SCHEMAS: Record<MatchKind, readonly string[]> = { user: USER_SCHEMAS, ip: IP_SCHEMAS, host: HOST_SCHEMAS };

/** Daily inventory snapshots rather than activity: off unless asked for. */
export const SNAPSHOT_SCHEMAS = new Set(["inventoryinfo", "softwareinfo", "patchstate", "forensicinfo"]);

/** Plain names for the event schemas (the Schema Atlas "friendly" names, shortened). */
export const SCHEMA_LABELS: Record<string, string> = {
  agentdetection: "Agent detections",
  antivirus: "Antivirus",
  apicall: "API calls",
  auth: "Authentication",
  cloudaudit: "Cloud audit",
  dhcp: "DHCP",
  dnsquery: "DNS queries",
  email: "Email",
  encrypt: "Encryption",
  filemod: "File changes",
  forensicinfo: "Forensic snapshots",
  generic: "Unparsed (generic)",
  http: "Web (HTTP)",
  inventoryinfo: "Device inventory",
  managementevent: "Management events",
  netflow: "Network flows",
  nids: "Network IDS",
  patchstate: "Patch state",
  persistence: "Persistence",
  process: "Process starts",
  processmodule: "Process modules",
  registry: "Registry",
  scriptblock: "Script blocks",
  softwareinfo: "Installed software",
  thirdparty: "Third-party alerts",
  threadinjection: "Thread injection",
};

export function schemaLabel(schema: string): string {
  return SCHEMA_LABELS[schema] ?? schema;
}

/**
 * Fields a log search can group by, with the schemas that aggregate each one
 * (from the qlSchemaMapV1 snapshot in the Schema Atlas). "sensor_type" also
 * gives the event type, because every aggregate row carries schema_type.
 */
export const GROUP_FIELDS: Record<string, { label: string; schemas: readonly string[] | "all"; ip?: boolean }> = {
  sensor_type: { label: "Data source", schemas: "all" },
  schema: { label: "Event type", schemas: "all" },
  host_id: { label: "Device", schemas: "all" },
  source_address: { label: "Source IP", schemas: ["antivirus", "auth", "cloudaudit", "dnsquery", "encrypt", "http", "managementevent", "netflow", "nids", "thirdparty"], ip: true },
  destination_address: { label: "Destination IP", schemas: ["antivirus", "dnsquery", "encrypt", "http", "netflow", "nids", "thirdparty"], ip: true },
  destination_port: { label: "Destination port", schemas: ["antivirus", "encrypt", "http", "netflow", "nids", "thirdparty"] },
  target_user_name: { label: "Account signed in to", schemas: ["auth", "cloudaudit", "thirdparty"] },
  action_result: { label: "Sign-in result", schemas: ["auth"] },
  application_name: { label: "Application", schemas: ["antivirus", "auth", "cloudaudit", "netflow", "nids"] },
  query_name: { label: "DNS name", schemas: ["antivirus", "dnsquery"] },
  uri_host: { label: "Web host", schemas: ["http"] },
  event_name: { label: "Cloud operation", schemas: ["cloudaudit"] },
  image_path: { label: "Process path", schemas: ["agentdetection", "process"] },
};

export class ReportInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReportInputError";
  }
}

/** A user name or part of one. No quote or backslash can reach the QL string. */
export function cleanUser(raw: unknown): string {
  const v = typeof raw === "string" ? raw.trim() : "";
  if (!/^[\p{L}\p{N}@._\-$ +#:/]{2,128}$/u.test(v)) {
    throw new ReportInputError("Enter a user name, email address or part of one: 2 to 128 letters, digits and @ . _ - $ + # : /. Quotes and backslashes are not accepted.");
  }
  return v;
}

export function cleanIp(raw: unknown): string {
  const v = typeof raw === "string" ? raw.trim() : "";
  if (!net.isIP(v)) throw new ReportInputError("Enter one IPv4 or IPv6 address.");
  return v;
}

export function cleanHost(raw: unknown): string {
  const v = typeof raw === "string" ? raw.trim() : "";
  if (!/^[\p{L}\p{N}._\-]{2,128}$/u.test(v)) throw new ReportInputError("Enter a device name or part of one: 2 to 128 letters, digits, dots, hyphens and underscores.");
  return v;
}

export function cleanValue(kind: MatchKind, raw: unknown): string {
  return kind === "user" ? cleanUser(raw) : kind === "ip" ? cleanIp(raw) : cleanHost(raw);
}

export function predicate(kind: MatchKind, value: string): string {
  if (kind === "ip") return `@ip = '${value}'`;
  if (kind === "host") return `@host contains '${value}'`;
  return `@user contains '${value}'`;
}

/** Sensor types are checked, never pasted raw (the same rule as the MFA users search). */
export function cleanSensorTypes(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  return [...new Set(list.filter((s): s is string => typeof s === "string" && /^[A-Za-z0-9_. -]{1,80}$/.test(s)))].slice(0, 30);
}

export function cleanSchemas(kind: MatchKind, list: unknown): string[] {
  const allowed = MATCH_SCHEMAS[kind];
  const asked = Array.isArray(list) ? list.filter((s): s is string => typeof s === "string") : [];
  const picked = asked.length ? allowed.filter((s) => asked.includes(s)) : allowed.filter((s) => !SNAPSHOT_SCHEMAS.has(s));
  if (!picked.length) throw new ReportInputError(`None of the chosen event types can be searched by ${kind === "ip" ? "IP address" : kind}.`);
  return [...picked];
}

type Window = { start: number; end: number };

function where(kind: MatchKind, value: string, sensors: string[]): string {
  const p = predicate(kind, value);
  return sensors.length ? `${p} and sensor_type in (${sensors.map((s) => `'${s}'`).join(", ")})` : p;
}

/** Hourly buckets up to 3 days (shown in the report's zone), daily UTC buckets beyond. */
export function bucketFor(window: Window): "1h" | "1d" {
  return window.end - window.start <= 3 * 86_400_000 ? "1h" : "1d";
}

// ---------------------------------------------------------------- user investigation

const SIGNIN_GROUP = "target_user_name, source_user_name, sensor_type, action_result, failure_category, logon_type, mfa_used, application_name, source_address, host_id";
const RECENT_FIELDS = "event_time_usec, target_user_name, source_user_name, sensor_type, action_result, failure_category, logon_type, mfa_used, application_name, source_address, host_id";

export function userSigninsQl(user: string, window: Window): string {
  return `from auth where ${predicate("user", user)} ${qlWindow(window)} | aggregate count, min(event_time_usec), max(event_time_usec) by ${SIGNIN_GROUP}`;
}

export function userTimelineQl(user: string, window: Window): string {
  return `from auth where ${predicate("user", user)} ${qlWindow(window)} | aggregate count by action_result, sensor_type, ${bucketFor(window)}`;
}

export function userActivityQl(user: string, window: Window): string {
  return `from ${USER_SCHEMAS.join(", ")} where ${predicate("user", user)} ${qlWindow(window)} | aggregate count by sensor_type`;
}

export function userRecentQl(user: string, window: Window, rows = 100): string {
  return `from auth where ${predicate("user", user)} ${qlWindow(window)} | fields ${RECENT_FIELDS} | head ${rows}`;
}

export function userCloudQl(user: string, window: Window): string {
  return `from cloudaudit where ${predicate("user", user)} ${qlWindow(window)} | aggregate count, max(event_time_usec) by sensor_type, event_name, source_address`;
}

/** Detection search for one user, IP or device, newest first. */
export function detectionQl(kind: MatchKind | null, value: string | null, hours: number): string {
  const h = Math.max(1, Math.min(24 * 31, Math.ceil(hours)));
  if (!kind || !value) return `from alert severity >= 0 EARLIEST=-${h}h`;
  return `from alert where ${predicate(kind, value)} EARLIEST=-${h}h`;
}

// ---------------------------------------------------------------- log search

export interface LogSearchSpec {
  kind: MatchKind;
  value: string;
  schemas: string[];
  sensors: string[];
  groupBy: string;
  rows: number;
}

export function logTimelineQl(spec: LogSearchSpec, window: Window): string {
  return `from ${spec.schemas.join(", ")} where ${where(spec.kind, spec.value, spec.sensors)} ${qlWindow(window)} | aggregate count by ${bucketFor(window)}`;
}

/** The schemas a group-by can run on: those chosen that aggregate the field. */
export function groupSchemas(spec: LogSearchSpec): string[] {
  const f = GROUP_FIELDS[spec.groupBy];
  if (!f || f.schemas === "all") return spec.schemas;
  return spec.schemas.filter((s) => (f.schemas as readonly string[]).includes(s));
}

export function logGroupQl(spec: LogSearchSpec, window: Window): string | null {
  const schemas = groupSchemas(spec);
  if (!schemas.length) return null;
  const field = spec.groupBy === "schema" ? "sensor_type" : spec.groupBy;
  return `from ${schemas.join(", ")} where ${where(spec.kind, spec.value, spec.sensors)} ${qlWindow(window)} | aggregate count by ${field}`;
}

/** Event types per rows search: well under the nine at which Sophos dropped per-type fields. */
export const ROWS_SCHEMAS_PER_SEARCH = 4;

export function logRowsQl(spec: LogSearchSpec, window: Window, schemas: string[] = spec.schemas): string {
  return `from ${schemas.join(", ")} where ${where(spec.kind, spec.value, spec.sensors)} ${qlWindow(window)} | head ${spec.rows}`;
}

/** The event types with events, busiest first, in groups for the rows searches. */
export function rowGroups(timeline: Array<{ schema: string; count: number }>, size = ROWS_SCHEMAS_PER_SEARCH): string[][] {
  const totals = new Map<string, number>();
  for (const t of timeline) totals.set(t.schema, (totals.get(t.schema) ?? 0) + t.count);
  const hit = [...totals.entries()].filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([s]) => s);
  const groups: string[][] = [];
  for (let i = 0; i < hit.length; i += size) groups.push(hit.slice(i, i + size));
  return groups;
}

export { SOURCE_SCHEMAS };
