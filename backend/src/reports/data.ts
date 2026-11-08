/**
 * Records the reports read beyond the dashboard cache, and the pure parsing
 * of Sophos answers into them. Live fetchers (live.ts) and the demo source
 * (demo.ts) both produce these shapes, so the report builders never see a
 * raw API answer.
 */

import type { GeoPoint, SearchMeta, Severity } from "../data/types.js";
import { detectionSeverity } from "../mappers/api.js";

type Row = Record<string, unknown>;

export function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

export function count(v: unknown): number {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/** event_time_usec (microseconds) to milliseconds. */
export function usec(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) && n > 0 ? Math.round(n / 1000) : null;
}

function bool(v: unknown): boolean | null {
  if (v === true || v === "true" || v === "TRUE") return true;
  if (v === false || v === "false" || v === "FALSE") return false;
  return null;
}

/** "2026-11-05 23:00:00" (a UTC time group) to milliseconds. */
export function bucketTime(v: unknown): number | null {
  const s = str(v);
  if (!s) return null;
  const t = Date.parse(`${s.replace(" ", "T")}Z`);
  return Number.isFinite(t) ? t : null;
}

export type SigninResult = "success" | "failed" | "other";

function result(v: unknown): SigninResult {
  const r = str(v)?.toUpperCase();
  return r === "SUCCESS" ? "success" : r === "FAILED" ? "failed" : "other";
}

// ---------------------------------------------------------------- user investigation

export interface UserSigninRow {
  user: string;
  sourceUser: string;
  sensorType: string;
  result: SigninResult;
  failure: string | null;
  logonType: string;
  mfa: boolean | null;
  app: string;
  ip: string | null;
  hostId: string | null;
  count: number;
  first: number | null;
  last: number | null;
}

export interface UserTimelineRow {
  at: number;
  result: SigninResult;
  sensorType: string;
  count: number;
}

export interface UserActivityRow {
  schema: string;
  sensorType: string;
  count: number;
}

export interface UserRecentRow {
  at: number;
  user: string;
  sourceUser: string;
  sensorType: string;
  result: SigninResult;
  failure: string | null;
  logonType: string;
  mfa: boolean | null;
  app: string;
  ip: string | null;
  hostId: string | null;
}

export interface UserCloudRow {
  sensorType: string;
  operation: string;
  ip: string | null;
  count: number;
  last: number | null;
}

export interface UserActivity {
  window: { start: number; end: number };
  bucket: "1h" | "1d";
  signins: UserSigninRow[];
  signinsTruncated: boolean;
  timeline: UserTimelineRow[];
  activity: UserActivityRow[];
  recent: UserRecentRow[];
  cloud: UserCloudRow[];
  /** Public source IPs placed with the local DB-IP file. */
  geo: Record<string, GeoPoint>;
  search: SearchMeta;
}

export function parseUserSignins(values: Row[]): UserSigninRow[] {
  return values
    .map((v) => ({
      user: str(v.target_user_name) ?? "",
      sourceUser: str(v.source_user_name) ?? "",
      sensorType: str(v.sensor_type) ?? "UNKNOWN",
      result: result(v.action_result),
      failure: str(v.failure_category),
      logonType: str(v.logon_type) ?? "UNKNOWN",
      mfa: bool(v.mfa_used),
      app: str(v.application_name) ?? "",
      ip: str(v.source_address),
      hostId: str(v.host_id),
      count: count(v.row_count),
      first: usec(v.min_event_time_usec),
      last: usec(v.max_event_time_usec),
    }))
    .filter((r) => r.count > 0);
}

export function parseUserTimeline(values: Row[], bucket: "1h" | "1d"): UserTimelineRow[] {
  const out: UserTimelineRow[] = [];
  for (const v of values) {
    const at = bucketTime(v[`event_time_usec_${bucket}`]);
    const n = count(v.row_count);
    if (at === null || !n) continue;
    out.push({ at, result: result(v.action_result), sensorType: str(v.sensor_type) ?? "UNKNOWN", count: n });
  }
  return out.sort((a, b) => a.at - b.at);
}

export function parseUserActivity(values: Row[]): UserActivityRow[] {
  return values
    .map((v) => ({ schema: str(v.schema_type) ?? "unknown", sensorType: str(v.sensor_type) ?? "UNKNOWN", count: count(v.row_count) }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count);
}

export function parseUserRecent(values: Row[]): UserRecentRow[] {
  const out: UserRecentRow[] = [];
  for (const v of values) {
    const at = usec(v.event_time_usec);
    if (at === null) continue;
    out.push({
      at,
      user: str(v.target_user_name) ?? "",
      sourceUser: str(v.source_user_name) ?? "",
      sensorType: str(v.sensor_type) ?? "UNKNOWN",
      result: result(v.action_result),
      failure: str(v.failure_category),
      logonType: str(v.logon_type) ?? "UNKNOWN",
      mfa: bool(v.mfa_used),
      app: str(v.application_name) ?? "",
      ip: str(v.source_address),
      hostId: str(v.host_id),
    });
  }
  return out.sort((a, b) => b.at - a.at);
}

export function parseUserCloud(values: Row[]): UserCloudRow[] {
  return values
    .map((v) => ({ sensorType: str(v.sensor_type) ?? "UNKNOWN", operation: (str(v.event_name) ?? "Not named").replace(/[\u200B-\u200D\uFEFF]/g, ""), ip: str(v.source_address), count: count(v.row_count), last: usec(v.max_event_time_usec) }))
    .filter((r) => r.count > 0)
    .sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------- log search

export interface LogRow {
  at: number;
  schema: string;
  sensorType: string;
  hostId: string | null;
  user: string;
  source: string;
  destination: string;
  action: string;
  detail: string;
}

export interface LogSearchResult {
  window: { start: number; end: number };
  bucket: "1h" | "1d";
  timeline: Array<{ at: number; schema: string; count: number }>;
  groups: { field: string; schemas: string[]; rows: Array<{ value: string; schema: string; sensorType: string | null; count: number }> } | null;
  rows: LogRow[];
  rowsTruncated: boolean;
  search: SearchMeta;
}

function first(v: Row, keys: string[]): string {
  for (const k of keys) {
    const s = str(v[k]);
    if (s) return s;
  }
  return "";
}

function nested(v: Row, path: string): unknown {
  let cur: unknown = v;
  for (const p of path.split(".")) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Row)[p];
  }
  return cur;
}

/**
 * One event from an unprojected search row, reduced to the columns a log
 * export needs. Field names differ per schema, so each column takes the first
 * field present.
 */
export function parseLogRow(v: Row): LogRow | null {
  const at = usec(v.event_time_usec);
  if (at === null) return null;
  const schema = str(v.schema_type) ?? "unknown";
  const port = first(v, ["destination_port"]);
  const dest = first(v, ["destination_address", "target_address", "uri_host", "query_name", "to_email_address", "target_host_name"]);
  const detail =
    first(v, ["commandline", "event_name", "subject", "query_name", "summary", "title", "image_path", "name", "path", "registry_key", "file_path", "uri_path", "status"]) ||
    (str(nested(v, "process_file_hash.sha256")) ?? "");
  return {
    at,
    schema,
    sensorType: str(v.sensor_type) ?? "UNKNOWN",
    hostId: str(v.host_id),
    user:
      first(v, ["target_user_name", "source_user_name", "username", "user_name", "member_name", "from_email_address", "destination_username", "source_username"]) ||
      (str(nested(v, "user.original_name")) ?? str(nested(v, "user.name")) ?? str(nested(v, "target_user.name")) ?? str(nested(v, "source_user.name")) ?? ""),
    source: first(v, ["source_address", "sender_ip", "true_source_address"]),
    destination: dest && port && /^[\d.:a-f]+$/i.test(dest) ? `${dest}:${port}` : dest,
    action: first(v, ["action_result", "action", "flow_action", "action_taken", "event_type", "status", "response_code", "http_method"]),
    detail: detail.replace(/\s+/g, " ").slice(0, 300),
  };
}

// ---------------------------------------------------------------- detections with titles and entities

export interface DetectionDetail {
  id: string;
  createdAt: number;
  severity: Severity;
  title: string;
  detector: string | null;
  sensorTypes: string[];
  techniques: string[];
  /** Technique ID to name, and the tactics, from the detection's MITRE ATT&CK enrichment. */
  techniqueNames: Record<string, string>;
  tactics: string[];
  status: string | null;
  users: string[];
  hosts: string[];
  ips: string[];
}

/** "initial-access" or "Initial Access" to "Initial access". */
export function tacticLabel(raw: string): string {
  const t = raw.trim().replace(/[-_]+/g, " ").toLowerCase();
  return t.charAt(0).toUpperCase() + t.slice(1);
}

export interface DetectionDetailSet {
  hours: number;
  /** total_results from Sophos for the query. */
  total: number;
  items: DetectionDetail[];
  /** More detections matched than were read (the newest are read first). */
  sampled: boolean;
}

function entities(list: unknown, subtypes: string[]): string[] {
  if (!Array.isArray(list)) return [];
  const out: string[] = [];
  for (const e of list) {
    const o = e && typeof e === "object" ? (e as Row) : {};
    const sub = str(o.subtype);
    const name = str(o.display_name);
    if (sub && name && subtypes.includes(sub)) out.push(name);
  }
  return out;
}

export function mapDetectionDetail(raw: unknown): DetectionDetail | null {
  const d = raw && typeof raw === "object" ? (raw as Row) : {};
  const id = str(d.id);
  if (!id) return null;
  const meta = d.metadata && typeof d.metadata === "object" ? (d.metadata as Row) : {};
  const seconds = Number((meta.created_at as Row | undefined)?.seconds);
  const detector = str(((meta.creator as Row | undefined)?.detector as Row | undefined)?.detector_name);
  const all = [...(Array.isArray(d.source_entities) ? d.source_entities : []), ...(Array.isArray(d.target_entities) ? d.target_entities : [])];
  const uniq = (xs: string[]) => [...new Set(xs)];
  const techniqueNames: Record<string, string> = {};
  const tactics: string[] = [];
  for (const e of Array.isArray(d.enrichment_details) ? d.enrichment_details : []) {
    const info = e && typeof e === "object" ? ((e as Row).mitre_attack_info as Row | null | undefined) : null;
    const tid = str(info?.technique_id);
    const name = str(info?.technique);
    if (tid && name) techniqueNames[tid] = name;
    if (Array.isArray(info?.tactics)) for (const t of info.tactics) if (typeof t === "string" && t.trim()) tactics.push(tacticLabel(t));
  }
  return {
    id,
    createdAt: Number.isFinite(seconds) ? seconds * 1000 : 0,
    severity: detectionSeverity(meta.severity),
    title: (str(meta.title) ?? detector ?? "Untitled detection").replace(/\s+/g, " "),
    detector,
    sensorTypes: Array.isArray(d.sensor_types) ? d.sensor_types.filter((s): s is string => typeof s === "string") : [],
    techniques: Array.isArray(d.attack_technique_ids) ? d.attack_technique_ids.filter((s): s is string => typeof s === "string") : [],
    techniqueNames,
    tactics: uniq(tactics),
    status: str(d.status),
    users: uniq(entities(all, ["User"])),
    hosts: uniq(entities(all, ["Endpoint", "Host", "Asset"])),
    ips: uniq(entities(all, ["IpAddress"])),
  };
}

// ---------------------------------------------------------------- directory users

export interface DirectoryUser {
  name: string;
  firstName: string | null;
  lastName: string | null;
  email: string | null;
  exchangeLogin: string | null;
  source: string;
  domain: string | null;
  groups: number | null;
  createdAt: string | null;
  updatedAt: string | null;
}

const SOURCE_NAMES: Record<string, string> = { custom: "Added in Sophos", activedirectory: "Active Directory sync", azureactivedirectory: "Microsoft Entra ID sync" };

export function mapDirectoryUser(raw: unknown): DirectoryUser | null {
  const u = raw && typeof raw === "object" ? (raw as Row) : {};
  const name = str(u.name);
  if (!name) return null;
  const source = u.source && typeof u.source === "object" ? (u.source as Row) : {};
  const type = (str(source.type) ?? "").toLowerCase();
  const groups = u.groups && typeof u.groups === "object" ? Number((u.groups as Row).total ?? (Array.isArray((u.groups as Row).items) ? ((u.groups as Row).items as unknown[]).length : NaN)) : Array.isArray(u.groupIds) ? (u.groupIds as unknown[]).length : NaN;
  return {
    name,
    firstName: str(u.firstName),
    lastName: str(u.lastName),
    email: str(u.email),
    exchangeLogin: str(u.exchangeLogin),
    source: SOURCE_NAMES[type] ?? (type || "Not given"),
    domain: str(source.domain) ?? str(source.domainName),
    groups: Number.isFinite(groups) ? groups : null,
    createdAt: str(u.createdAt),
    updatedAt: str(u.updatedAt),
  };
}
