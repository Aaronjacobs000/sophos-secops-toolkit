/**
 * Pure view models for the screens, computed from cached records. The
 * routes call these on every request; nothing here touches the network or
 * the disk, so the tests drive them with fixed records and a fixed clock.
 */

import type {
  AiDefenseRecord,
  AlertSet,
  CaseRecord,
  CaseSet,
  DetectionSet,
  EgressSet,
  EndpointRecord,
  EndpointSnapshot,
  Generation,
  HealthRecord,
  LicenceRecord,
  MfaSet,
  SearchMeta,
  Severity,
  SigninLocation,
  SigninSet,
  SmimeRecord,
  SourceRecord,
  SourceSet,
  TenantRecord,
} from "../data/types.js";
import { sourceState } from "./search.js";
import { aiTile, type AiTileLine } from "./ai-defense.js";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export type Targets = Record<Severity, number>;

function sevKey(s: Severity | "unset"): Severity {
  return s === "unset" ? "info" : s;
}

function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function parse(ts: string | null | undefined): number | null {
  if (!ts) return null;
  const n = Date.parse(ts);
  return Number.isFinite(n) ? n : null;
}

export function quantile(values: number[], q: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return Math.round(sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (pos - lo));
}

/** Compares dotted version strings numerically. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.\-]/).map((x) => Number.parseInt(x, 10));
  const pb = b.split(/[.\-]/).map((x) => Number.parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number.isFinite(pa[i]) ? pa[i]! : 0;
    const y = Number.isFinite(pb[i]) ? pb[i]! : 0;
    if (x !== y) return x - y;
  }
  return 0;
}

const PLATFORM_NAMES: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

function versionBase(v: string, parts = 3): string {
  return v.split(".").slice(0, parts).join(".");
}

// ---------------------------------------------------------------- endpoints

export interface WorstDevice {
  id: string;
  hostname: string;
  os: string;
  platform: string;
  lastSeenAt: string | null;
  silentDays: number | null;
  health: string;
  tamper: boolean | null;
  agentVersion: string | null;
  outdated: boolean;
  isolation: string | null;
  location: string | null;
  tenantName?: string;
  score: number;
}

export interface LocationPoint {
  key: string;
  city: string | null;
  country: string | null;
  lat: number;
  lon: number;
  devices: number;
  bad: number;
  suspicious: number;
  stale: number;
  worst: "bad" | "suspicious" | "good";
  source: "sophos" | "dbip";
}

export interface EndpointSummary {
  total: number;
  servers: number;
  byPlatform: Array<{ platform: string; count: number }>;
  health: { good: number; suspicious: number; bad: number; unknown: number };
  stale: { d7: number; d14: number; d30: number; d90: number; never: number };
  staleOver7: number;
  tamperOff: number;
  isolated: number;
  versions: { newest: string | null; current: number; outdated: number; list: Array<{ version: string; platform: string; platformName: string; count: number; outdated: boolean }> };
  worst: WorstDevice[];
  withIssues: number;
  locations: LocationPoint[] | null;
  placement: { placed: number; unplaced: number; noEgress: number; sources: { sophos: number; dbip: number } } | null;
}

export function silentDays(lastSeenAt: string | null, now: number): number | null {
  const t = parse(lastSeenAt);
  return t === null ? null : Math.max(0, Math.floor((now - t) / DAY));
}

export function endpointSummary(
  endpoints: Array<EndpointRecord & { tenantName?: string }>,
  now: number,
  egress: EgressSet | null = null,
  platformFilter: string | null = null,
): EndpointSummary {
  const list = platformFilter ? endpoints.filter((e) => e.platform === platformFilter) : endpoints;
  const health = { good: 0, suspicious: 0, bad: 0, unknown: 0 };
  const stale = { d7: 0, d14: 0, d30: 0, d90: 0, never: 0 };
  const platforms = new Map<string, number>();
  const versions = new Map<string, number>();
  let tamperOff = 0;
  let isolated = 0;
  let servers = 0;
  // "Behind" is measured against the newest agent seen on the same platform:
  // Sophos releases Windows, macOS and Linux agents on separate trains.
  const newestBy = new Map<string, string>();
  for (const e of list) {
    if (!e.agentVersion) continue;
    const cur = newestBy.get(e.platform);
    if (!cur || compareVersions(e.agentVersion, cur) > 0) newestBy.set(e.platform, e.agentVersion);
  }
  const isOutdatedOn = (platform: string, v: string | null) => {
    const top = newestBy.get(platform);
    return !!(v && top && compareVersions(versionBase(v), versionBase(top)) < 0);
  };
  const newest = newestBy.size ? [...newestBy.entries()].map(([p, v]) => `${PLATFORM_NAMES[p] ?? p} ${v}`).join(", ") : null;
  const worst: WorstDevice[] = [];
  const hostIp = new Map((egress?.hosts ?? []).map((h) => [h.hostname.toLowerCase(), h.ip]));
  const points = new Map<string, LocationPoint>();
  let placed = 0;
  let unplaced = 0;
  let noEgress = 0;
  const sources = { sophos: 0, dbip: 0 };

  for (const e of list) {
    const h = e.health in health ? (e.health as keyof typeof health) : "unknown";
    health[h]++;
    if (e.isServer) servers++;
    platforms.set(e.platform, (platforms.get(e.platform) ?? 0) + 1);
    if (e.agentVersion) versions.set(`${e.platform}|${e.agentVersion}`, (versions.get(`${e.platform}|${e.agentVersion}`) ?? 0) + 1);
    if (e.tamper === false) tamperOff++;
    if (e.isolation === "isolated") isolated++;
    const days = silentDays(e.lastSeenAt, now);
    if (days === null) stale.never++;
    else if (days >= 90) stale.d90++;
    else if (days >= 30) stale.d30++;
    else if (days >= 14) stale.d14++;
    else if (days >= 7) stale.d7++;
    const outdated = isOutdatedOn(e.platform, e.agentVersion);

    let location: string | null = null;
    if (egress) {
      const ip = hostIp.get(e.hostname.toLowerCase());
      const geo = ip ? egress.geo[ip] : undefined;
      if (!ip) noEgress++;
      else if (!geo) unplaced++;
      else {
        placed++;
        sources[geo.source]++;
        const key = `${geo.city ?? ""}|${geo.country ?? ""}|${geo.lat.toFixed(1)}|${geo.lon.toFixed(1)}`;
        const p = points.get(key) ?? { key, city: geo.city, country: geo.country, lat: geo.lat, lon: geo.lon, devices: 0, bad: 0, suspicious: 0, stale: 0, worst: "good" as const, source: geo.source };
        p.devices++;
        if (h === "bad") p.bad++;
        if (h === "suspicious") p.suspicious++;
        if (days !== null && days >= 7) p.stale++;
        p.worst = p.bad ? "bad" : p.suspicious || p.stale ? "suspicious" : "good";
        points.set(key, p);
        location = geo.city ?? geo.country;
      }
    }

    const score = (h === "bad" ? 100 : h === "suspicious" ? 40 : h === "unknown" ? 10 : 0) + (e.tamper === false ? 30 : 0) + (days !== null && days >= 7 ? Math.min(60, 10 + days / 3) : 0) + (outdated ? 15 : 0) + (e.isolation === "isolated" ? 20 : 0);
    if (score > 0) {
      worst.push({
        id: e.id,
        hostname: e.hostname,
        os: e.osName,
        platform: e.platform,
        lastSeenAt: e.lastSeenAt,
        silentDays: days,
        health: h,
        tamper: e.tamper,
        agentVersion: e.agentVersion,
        outdated,
        isolation: e.isolation,
        location,
        tenantName: e.tenantName,
        score,
      });
    }
  }
  worst.sort((a, b) => b.score - a.score || a.hostname.localeCompare(b.hostname));
  const versionList = [...versions.entries()]
    .map(([key, count]) => {
      const [platform, version] = key.split("|") as [string, string];
      return { version, platform, platformName: PLATFORM_NAMES[platform] ?? platform, count, outdated: isOutdatedOn(platform, version) };
    })
    .sort((a, b) => b.count - a.count || compareVersions(b.version, a.version));
  const outdatedCount = versionList.filter((v) => v.outdated).reduce((a, v) => a + v.count, 0);
  return {
    total: list.length,
    servers,
    byPlatform: [...platforms.entries()].map(([platform, count]) => ({ platform, count })).sort((a, b) => b.count - a.count),
    health,
    stale,
    staleOver7: stale.d7 + stale.d14 + stale.d30 + stale.d90,
    tamperOff,
    isolated,
    versions: { newest, current: list.filter((e) => e.agentVersion && !isOutdatedOn(e.platform, e.agentVersion)).length, outdated: outdatedCount, list: versionList.slice(0, 8) },
    worst: worst.slice(0, 40),
    withIssues: worst.length,
    locations: egress ? [...points.values()].sort((a, b) => b.devices - a.devices) : null,
    placement: egress ? { placed, unplaced, noEgress, sources } : null,
  };
}

export function endpointSnapshot(endpoints: EndpointRecord[], now: number): EndpointSnapshot {
  const s = endpointSummary(endpoints, now);
  return { total: s.total, bad: s.health.bad, suspicious: s.health.suspicious, stale7: s.staleOver7, tamperOff: s.tamperOff };
}

// ---------------------------------------------------------------- cases

export type Lane = "new" | "investigating" | "waiting" | "hold" | "resolved";

const WAITING = new Set(["customer_action_required", "awaiting_action", "actionrequired", "action_required", "awaiting_customer"]);
const HOLD = new Set(["on_hold", "onhold", "suspended"]);
const NEW = new Set(["new", "open", "awaiting_sophos_assignment", "unassigned"]);

export function laneOf(c: CaseRecord): Lane {
  if (c.closed) return "resolved";
  const s = c.status.toLowerCase();
  const s2 = (c.secondary ?? "").toLowerCase();
  if (WAITING.has(s) || WAITING.has(s2)) return "waiting";
  if (HOLD.has(s) || HOLD.has(s2)) return "hold";
  if (NEW.has(s)) return "new";
  return "investigating";
}

/** True when the case waits for an owner: no assignee, and not one Sophos MDR is working. */
export function isUnassigned(c: CaseRecord): boolean {
  if (c.closed) return false;
  if (c.status === "awaiting_sophos_assignment") return true;
  return !c.assigneeId && c.managedBy !== "mdr";
}

export interface CaseCard {
  id: string;
  ref: string;
  title: string;
  severity: Severity | "unset";
  managedBy: "mdr" | "self" | null;
  owner: string;
  statusTitle: string;
  lane: Lane;
  ageMs: number;
  targetMs: number;
  /** Age as a share of the target, 0 to 2 (capped). */
  pct: number;
  over: boolean;
  /** Waiting on customer: the age the case had when it was last updated (the clock pauses). */
  pausedAtMs: number | null;
  /** MDR closes a Customer Action Required case after 5 days with no activity. */
  autoCloseInMs: number | null;
  closedAgoMs: number | null;
  timeToCloseMs: number | null;
  metTarget: boolean | null;
  tenantId: string;
  tenantName?: string;
}

export interface CaseInput {
  set: CaseSet;
  tenantName?: string;
}

function card(c: CaseRecord, targets: Targets, now: number, tenantName?: string): CaseCard {
  const lane = laneOf(c);
  const created = parse(c.createdAt) ?? now;
  const updated = parse(c.updatedAt) ?? created;
  const closed = parse(c.closedAt);
  const targetMs = targets[sevKey(c.severity)] * HOUR;
  const end = lane === "resolved" && closed ? closed : lane === "waiting" ? updated : now;
  const ageMs = Math.max(0, end - created);
  const waitingMdr = lane === "waiting" && c.managedBy === "mdr" && (c.status === "customer_action_required" || c.secondary === "customer_action_required");
  return {
    id: c.id,
    ref: c.ref,
    title: c.title,
    severity: c.severity,
    managedBy: c.managedBy,
    owner: c.managedBy === "mdr" ? "Sophos MDR" : c.assigneeId ? "Assigned" : "Unassigned",
    statusTitle: c.statusTitle,
    lane,
    ageMs,
    targetMs,
    pct: Math.min(2, targetMs ? ageMs / targetMs : 0),
    over: lane !== "waiting" && ageMs > targetMs,
    pausedAtMs: lane === "waiting" ? ageMs : null,
    autoCloseInMs: waitingMdr ? Math.max(0, updated + 5 * DAY - now) : null,
    closedAgoMs: closed !== null ? Math.max(0, now - closed) : null,
    timeToCloseMs: closed !== null ? Math.max(0, closed - created) : null,
    metTarget: closed !== null ? closed - created <= targetMs : null,
    tenantId: c.tenantId,
    tenantName,
  };
}

const LANE_ORDER: Array<{ key: Lane; title: string; note?: string }> = [
  { key: "new", title: "New" },
  { key: "investigating", title: "Investigating" },
  { key: "waiting", title: "Waiting on customer", note: "Clock paused" },
  { key: "hold", title: "On hold", note: "Clock paused" },
  { key: "resolved", title: "Resolved, last 7 days", note: "Time to close" },
];

export interface CaseBoard {
  api: Array<"v1" | "v2" | "none">;
  open: number;
  overTarget: number;
  unassigned: number;
  bySeverity: Record<Severity, number>;
  lanes: Array<{ key: Lane; title: string; note?: string; count: number; cards: CaseCard[] }>;
  timeToClose: Record<"mdr" | "self", { median: number | null; p90: number | null; n: number }>;
  warnings: string[];
  truncated: boolean;
}

function severityRank(s: Severity | "unset"): number {
  return s === "unset" ? 5 : SEVERITIES.indexOf(s);
}

export function caseBoard(inputs: CaseInput[], targets: Targets, now: number, managed: "all" | "mdr" | "self" = "all", perLane = 40): CaseBoard {
  const cards: CaseCard[] = [];
  const closedCards: CaseCard[] = [];
  const warnings = new Set<string>();
  const api = new Set<"v1" | "v2" | "none">();
  let truncated = false;
  for (const { set, tenantName } of inputs) {
    api.add(set.api);
    set.warnings.forEach((w) => warnings.add(w));
    truncated ||= set.truncated;
    for (const c of set.open) {
      if (managed !== "all" && c.managedBy !== managed) continue;
      cards.push(card(c, targets, now, tenantName));
    }
    for (const c of set.recentClosed) {
      if (managed !== "all" && c.managedBy !== managed) continue;
      closedCards.push(card(c, targets, now, tenantName));
    }
  }
  const bySeverity = emptySeverityCounts();
  for (const c of cards) bySeverity[sevKey(c.severity)]++;
  const lanes = LANE_ORDER.map((l) => {
    let laneCards =
      l.key === "resolved"
        ? closedCards.filter((c) => (c.closedAgoMs ?? Infinity) <= 7 * DAY).sort((a, b) => (a.closedAgoMs ?? 0) - (b.closedAgoMs ?? 0))
        : cards
            .filter((c) => c.lane === l.key)
            .sort((a, b) => Number(b.over) - Number(a.over) || severityRank(a.severity) - severityRank(b.severity) || b.pct - a.pct);
    const count = laneCards.length;
    laneCards = laneCards.slice(0, perLane);
    return { ...l, count, cards: laneCards };
  });
  const ttc = (who: "mdr" | "self") => {
    const values = closedCards.filter((c) => c.managedBy === who && c.timeToCloseMs !== null).map((c) => c.timeToCloseMs!);
    return { median: quantile(values, 0.5), p90: quantile(values, 0.9), n: values.length };
  };
  return {
    api: [...api],
    open: cards.length,
    overTarget: cards.filter((c) => c.over).length,
    unassigned: cards.filter((c) => c.owner === "Unassigned").length,
    bySeverity,
    lanes,
    timeToClose: { mdr: ttc("mdr"), self: ttc("self") },
    warnings: [...warnings],
    truncated,
  };
}

// ---------------------------------------------------------------- signals (detections or alerts)

export interface SignalSeries {
  source: "detections" | "alerts" | "none";
  label: string;
  windowHours: number;
  total: number;
  lastHour: number;
  avgPerHour: number;
  /** Hourly counts, oldest first. */
  hourly: number[];
  bySeverity: Record<Severity, number>;
  sampled: boolean;
}

function alertSeverity(s: string): Severity {
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}

/**
 * How much to scale a sampled detection set to cover a window. Above 1 only
 * when the newest-first sample stops short of the window start and Sophos's
 * total_results is for this same window, so the total is known exactly.
 */
export function detectionScale(set: DetectionSet, start: number, now: number): number {
  if (!set.sampled || !set.coveredFrom || set.coveredFrom <= start) return 1;
  const windowMatches = Math.abs(now - set.windowHours * HOUR - start) < HOUR;
  if (!windowMatches) return 1;
  const inWindow = set.items.filter((d) => d.createdAt >= start).length;
  return inWindow ? Math.max(1, set.total / inWindow) : 1;
}

export function signalSeries(detections: DetectionSet[] | null, alerts: AlertSet[] | null, now: number, windowHours = 24): SignalSeries {
  const hourly = new Array<number>(windowHours).fill(0);
  const bySeverity = emptySeverityCounts();
  const start = now - windowHours * HOUR;
  let total = 0;
  let lastHour = 0;
  let sampled = false;
  const bucket = (t: number, sev: Severity) => {
    if (t < start || t > now + 5 * 60_000) return;
    const i = Math.min(windowHours - 1, Math.floor((t - start) / HOUR));
    hourly[i]!++;
    total++;
    bySeverity[sev]++;
    if (t >= now - HOUR) lastHour++;
  };
  let source: SignalSeries["source"] = "none";
  if (detections && detections.length) {
    source = "detections";
    for (const set of detections) {
      const before = total;
      const sevBefore = { ...bySeverity };
      for (const d of set.items) bucket(d.createdAt, d.severity);
      const scale = detectionScale(set, start, now);
      if (scale > 1) {
        // The sample does not reach back to the window start: the total is
        // Sophos's own count, the severity split is scaled from the sample.
        sampled = true;
        const counted = total - before;
        total = before + set.total;
        for (const k of SEVERITIES) bySeverity[k] = sevBefore[k] + Math.round((bySeverity[k] - sevBefore[k]) * (set.total / Math.max(1, counted)));
      } else if (set.sampled && set.coveredFrom && set.coveredFrom > start) sampled = true;
    }
  }
  if (alerts && alerts.length) {
    if (source === "none") source = "alerts";
    for (const set of alerts) for (const a of set.items) bucket(parse(a.raisedAt) ?? 0, alertSeverity(a.severity));
  }
  return {
    source,
    label: source === "detections" ? (alerts && alerts.length ? "Detections and alerts" : "Detections") : source === "alerts" ? "Alerts" : "Detections",
    windowHours,
    total,
    lastHour,
    avgPerHour: windowHours ? Math.round((total / windowHours) * 10) / 10 : 0,
    hourly,
    bySeverity,
    sampled,
  };
}

// ---------------------------------------------------------------- now wall

export interface NowWall {
  open: number;
  bySeverity: Record<Severity, number>;
  unassigned: { total: number; bySeverity: Record<Severity, number>; oldestMs: number | null };
  waiting: { total: number; autoCloseSoon: number; mdr: number };
  signals: SignalSeries;
  oldest: CaseCard | null;
}

export function nowWall(inputs: CaseInput[], signals: SignalSeries, targets: Targets, now: number): NowWall {
  const board = caseBoard(inputs, targets, now, "all", 10_000);
  const open = board.lanes.filter((l) => l.key !== "resolved").flatMap((l) => l.cards);
  const unassigned = open.filter((c) => c.owner === "Unassigned");
  const ubs = emptySeverityCounts();
  for (const c of unassigned) ubs[sevKey(c.severity)]++;
  const waiting = open.filter((c) => c.lane === "waiting");
  const working = open.filter((c) => c.lane !== "waiting" && c.lane !== "hold");
  const oldest = working.sort((a, b) => b.pct - a.pct || b.ageMs - a.ageMs)[0] ?? null;
  return {
    open: open.length,
    bySeverity: board.bySeverity,
    unassigned: { total: unassigned.length, bySeverity: ubs, oldestMs: unassigned.length ? Math.max(...unassigned.map((c) => c.ageMs)) : null },
    waiting: { total: waiting.length, autoCloseSoon: waiting.filter((c) => c.autoCloseInMs !== null && c.autoCloseInMs <= 2 * DAY).length, mdr: waiting.filter((c) => c.managedBy === "mdr").length },
    signals,
    oldest,
  };
}

// ---------------------------------------------------------------- MSP wall

export type TileState = "critical" | "warning" | "healthy" | "pending";

export interface TenantTileInput {
  tenant: TenantRecord;
  generation: Generation | null;
  cases: CaseSet | null;
  endpoints: EndpointRecord[] | null;
  health: HealthRecord | null;
  licences: LicenceRecord[] | null;
  alerts: AlertSet | null;
  /** S/MIME internal CA and user certificates (Email API). */
  smime?: SmimeRecord | null;
  /** AI Defense for the window: shown on the tile, it does not change the tile's state. */
  aiDefense?: AiDefenseRecord | null;
  /** Sophos refused the AI Defense reads. */
  aiNoAccess?: boolean;
  fetchedAt: number | null;
  errors: number;
  /** Datasets Sophos refused with 403 (no licence, or the role does not cover them). */
  noAccess?: number;
}

export interface TenantTile {
  id: string;
  name: string;
  state: TileState;
  score: number;
  headline: string;
  reasons: string[];
  metrics: Array<{ label: string; value: string; state: "bad" | "warn" | "ok" | "none" }>;
  generation: Generation | null;
  mdr: boolean;
  region: string;
  fetchedAt: number | null;
  loading: boolean;
  errors: number;
  /** The AI Defense line, or null before the first read. */
  ai: AiTileLine | null;
}

const MDR_CODES = /MDR/i;

function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}

export function tenantTile(input: TenantTileInput, now: number): TenantTile {
  const { tenant, cases, endpoints, health, licences, alerts } = input;
  const reasons: Array<{ text: string; weight: number; level: "critical" | "warning" }> = [];
  const open = cases?.open ?? [];
  const critHigh = open.filter((c) => c.severity === "critical" || c.severity === "high").length;
  const crit = open.filter((c) => c.severity === "critical").length;
  // Thresholds (documented in the README): a critical case, three or more
  // high cases, three bad-health devices (or a tenth of 10 or more), tamper protection
  // off on a quarter of devices, health under 50 or a licence ending within a
  // week make a tenant critical. Smaller versions of the same make it a
  // warning; a few stale devices alone do not.
  if (crit) reasons.push({ text: `${plural(crit, "critical case")} open`, weight: 100 + crit, level: "critical" });
  else if (critHigh) reasons.push({ text: `${plural(critHigh, "high case")} open`, weight: 60 + critHigh, level: critHigh >= 3 ? "critical" : "warning" });

  let bad = 0;
  let staleN = 0;
  let tamperOff = 0;
  if (endpoints) {
    for (const e of endpoints) {
      if (e.health === "bad") bad++;
      const d = silentDays(e.lastSeenAt, now);
      if (d !== null && d >= 7) staleN++;
      if (e.tamper === false) tamperOff++;
    }
    const n = Math.max(1, endpoints.length);
    if (bad) reasons.push({ text: `${plural(bad, "device")} in bad health`, weight: 70 + bad, level: bad >= 3 || (n >= 10 && bad / n >= 0.1) ? "critical" : "warning" });
    if (tamperOff >= 5 || (tamperOff > 0 && tamperOff / n >= 0.05)) {
      reasons.push({ text: `Tamper protection off on ${plural(tamperOff, "device")}`, weight: 30 + (tamperOff / n) * 40, level: tamperOff >= 3 && tamperOff / n >= 0.25 ? "critical" : "warning" });
    }
    if (staleN >= 25 || staleN / n >= 0.1) reasons.push({ text: `${plural(staleN, "stale device")}`, weight: 20 + (staleN / n) * 30, level: "warning" });
  }
  if (health?.overall !== null && health?.overall !== undefined) {
    if (health.overall < 50) reasons.push({ text: `Health ${health.overall} of 100`, weight: 70 - health.overall / 2, level: "critical" });
    else if (health.overall < 70) reasons.push({ text: `Health ${health.overall} of 100`, weight: 40 - health.overall / 4, level: "warning" });
  }
  let soonest: number | null = null;
  for (const l of licences ?? []) {
    const end = parse(l.endDate);
    if (end === null) continue;
    const days = Math.ceil((end - now) / DAY);
    if (days >= 0 && (soonest === null || days < soonest)) soonest = days;
  }
  if (soonest !== null && soonest <= 30) reasons.push({ text: `Licence expires in ${plural(soonest, "day")}`, weight: soonest <= 7 ? 75 : 25, level: soonest <= 7 ? "critical" : "warning" });
  // S/MIME follows the license rule: amber within 30 days, red within 7.
  const smime = smimeStatus(input.smime ?? null, now);
  if (smime?.level && smime.days !== null) {
    reasons.push({ text: `S/MIME ${smime.kind === "ca" ? "internal CA" : "certificate"} expires in ${plural(smime.days, "day")}`, weight: smime.days <= 7 ? 75 : 25, level: smime.level });
  }
  const integrationAlerts = (alerts?.items ?? []).filter((a) => a.category === "integrations" && now - (parse(a.raisedAt) ?? 0) < DAY).length;
  if (integrationAlerts) reasons.push({ text: `${plural(integrationAlerts, "integration alert")} today`, weight: 15, level: "warning" });

  reasons.sort((a, b) => b.weight - a.weight);
  const loading = !cases && !endpoints && !health;
  const state: TileState = loading ? "pending" : reasons.some((r) => r.level === "critical") ? "critical" : reasons.length ? "warning" : "healthy";
  const score = (state === "critical" ? 1000 : state === "warning" ? 500 : state === "pending" ? -1 : 0) + reasons.reduce((a, r) => a + r.weight, 0);
  const metric = (label: string, value: number | null, badAt: number, warnAt: number, invert = false): TenantTile["metrics"][number] => {
    if (value === null) return { label, value: "-", state: "none" };
    const s = invert ? (value <= badAt ? "bad" : value <= warnAt ? "warn" : "ok") : value >= badAt ? "bad" : value >= warnAt ? "warn" : "ok";
    return { label, value: String(value), state: s };
  };
  const products = tenant.products.join(" ");
  return {
    id: tenant.id,
    name: tenant.name,
    state,
    score,
    headline: reasons[0]?.text ?? (loading ? ((input.noAccess ?? 0) > 0 ? "No access to this tenant's data (HTTP 403)" : "Loading") : "Healthy"),
    reasons: reasons.map((r) => r.text),
    metrics: [
      metric("Crit/High", cases ? critHigh : null, 1, 1),
      metric("Stale", endpoints ? staleN : null, 25, 1),
      metric("Health", health?.overall ?? null, 49, 79, true),
    ],
    generation: input.generation,
    mdr: MDR_CODES.test(products) || open.some((c) => c.managedBy === "mdr"),
    region: tenant.dataRegion,
    fetchedAt: input.fetchedAt,
    loading,
    errors: input.errors,
    ai: aiTile(input.aiDefense ?? null, input.aiNoAccess ?? false),
  };
}

export interface MspWall {
  tiles: TenantTile[];
  counts: { critical: number; warning: number; healthy: number; pending: number; total: number; classic: number; fusion: number; mdr: number };
}

export function mspWall(tiles: TenantTile[]): MspWall {
  const sorted = [...tiles].sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  const counts = { critical: 0, warning: 0, healthy: 0, pending: 0, total: tiles.length, classic: 0, fusion: 0, mdr: 0 };
  for (const t of tiles) {
    counts[t.state]++;
    if (t.generation === "classic") counts.classic++;
    if (t.generation === "fusion") counts.fusion++;
    if (t.mdr) counts.mdr++;
  }
  return { tiles: sorted, counts };
}

// ---------------------------------------------------------------- front page flow

export interface FlowSource {
  key: string;
  label: string;
  count: number;
  kind: string;
}

export interface FlowModel {
  windowHours: number;
  sources: FlowSource[];
  moreSources: { count: number; total: number } | null;
  signals: { label: string; total: number; source: SignalSeries["source"]; sampled: boolean; bySeverity: Record<Severity, number> };
  cases: {
    opened: number;
    open: number;
    mdr: { open: number; resolved: number };
    self: { open: number; resolved: number };
    unclaimed: { open: number; resolved: number };
    resolved: number;
    openBySeverity: Record<Severity, number>;
  };
}

const SENSOR_LABELS: Record<string, string> = {
  SOPHOS_SFOS: "Sophos Firewall",
  SFOS: "Sophos Firewall",
  SOPHOS_EMAIL: "Sophos Email",
  SOPHOS_NDR: "Sophos NDR",
  SOPHOS_ZTNA: "Sophos ZTNA",
  ENDPOINT_AGENT: "Endpoint",
  ENDPOINT: "Endpoint",
  ENDPOINT_TAEGIS: "Endpoint",
  ENDPOINT_SOPHOS: "Endpoint",
  ENDPOINT_REDCLOAK: "Endpoint",
  REDCLOAK: "Endpoint",
  SERVER: "Server",
  FIREWALL: "Firewall",
  NETWORK: "Network",
  CLOUD: "Cloud",
  EMAIL: "Email",
  IDENTITY: "Identity",
  MICROSOFT: "Microsoft 365",
  O365: "Microsoft 365",
  AZURE: "Azure",
  AWS: "AWS",
  GCP: "Google Cloud",
  NDR: "NDR",
  ISENSOR: "Taegis NDR",
  ITDR: "ITDR",
  MDR: "MDR",
  INTEGRATION: "Integrations",
  // Integrations whose sensor_type the fallback would mangle, named as their integration guides name them.
  ABNORMALSECURITY: "Abnormal Security",
  "AKAMAI_APP_&_API_PROTECTOR": "Akamai App & API Protector",
  AKAMAI_EAA: "Akamai EAA",
  CISCO_ISE: "Cisco ISE",
  CLAROTY_XDOME: "Claroty xDome",
  CLOUDFLARE: "Cloudflare",
  CYBERARK: "CyberArk",
  MCAFEE_EPO: "McAfee ePO",
  SCADAFENCE: "SCADAfence",
  VMWARE_VCENTER: "VMware vCenter",
  // Microsoft sensor types from the Taegis Sensor Types page, each its own source.
  MICROSOFT_WINDOWS_SNARE: "Windows Events (Snare)",
  MICROSOFT_WINDOWS_SPLUNK: "Windows Events (Splunk)",
  MICROSOFT_IIS: "Microsoft IIS",
  MSDHCP: "Microsoft DHCP",
  MSDNS: "Microsoft DNS",
  MICROSOFT_AZURE_ACTIVITY: "Azure Activity Log",
  MICROSOFT_GRAPH_ALERTS: "Microsoft Graph Security",
  MICROSOFT_GRAPH_SIGN_IN: "Entra ID Sign-ins",
  MICROSOFT_GRAPH_DIRECTORY_AUDIT: "Entra ID Audit Logs",
  MICROSOFT_OFFICE_MANAGEMENT: "Microsoft 365",
  AZURE_RISK_DETECTION: "Entra ID Risk Detection",
  // Third-party EDR: the ENDPOINT prefix would name each of them as the Sophos endpoint row.
  ENDPOINT_MICROSOFT_ATP: "Microsoft Defender for Endpoint",
  ENDPOINT_CROWD_STRIKE: "CrowdStrike Falcon",
  ENDPOINT_SENTINELONE: "SentinelOne",
  ENDPOINT_CARBON_BLACK_PSC: "Carbon Black Cloud",
  ENDPOINT_HARFANG_LAB: "HarfangLab",
  // Other types on the Taegis Sensor Types page that the fallback or the AWS prefix would mangle.
  FORTIGATE_FW: "Fortinet FortiGate",
  PALOALTO_FIREWALL: "Palo Alto Networks Firewall",
  BARRACUDA_FW: "Barracuda Firewall",
  BARRACUDA_WAF: "Barracuda WAF",
  CISCO_FIREWALL_ASA: "Cisco Secure Firewall ASA",
  CISCO_FIREWALL_FTD: "Cisco Secure Firewall Threat Defense",
  JUNIPER_SRX_FIREWALL: "Juniper SRX Firewall",
  PFSENSE_FIREWALL: "pfSense Firewall",
  SONICWALL: "SonicWall",
  WATCHGUARD_FIREWALL: "WatchGuard Firewall",
  ZSCALER_FIREWALL_DNS: "Zscaler Firewall DNS",
  ZSCALER_NSS: "Zscaler NSS",
  ARUBA_CLEARPASS: "Aruba ClearPass",
  BLUECOAT_PROXYSG: "Blue Coat ProxySG",
  CISCO_IOS: "Cisco IOS",
  CISCO_IRONPORT: "Cisco IronPort",
  FORTINET_FORTIWEB: "Fortinet FortiWeb",
  IMPERVA_SECURESPHERE: "Imperva SecureSphere",
  MCAFEE_WEBGATEWAY: "McAfee Web Gateway",
  NAMED: "BIND DNS (named)",
  NETSCALER: "NetScaler",
  PULSESECURE_SA: "Pulse Secure",
  SILENTDEFENSE: "SilentDefense",
  SSHD: "sshd",
  SUDO: "sudo",
  SURICATAEVE: "Suricata EVE",
  VMWARE_ESXI: "VMware ESXi",
  AMAZON_GUARDDUTY: "Amazon GuardDuty",
  AWS_APPLICATION_LOAD_BALANCER: "AWS Application Load Balancer",
  AWS_CLOUDTRAIL: "AWS CloudTrail",
  AWS_VPC_FLOW: "AWS VPC Flow Logs",
  AWS_WAF: "AWS WAF",
  CISCO_ESTREAMER: "Cisco eStreamer",
  ORACLE_OCI: "Oracle Cloud Infrastructure",
  ORACLE_OCI_AUDIT: "Oracle Cloud Audit",
  ORACLE_OCI_LOADBALANCER: "Oracle Cloud Load Balancer",
  ORACLE_OCI_VCNFLOW: "Oracle Cloud VCN Flow Logs",
};

/** Vendor names that are not a family prefix: MICROSOFT_WINDOWS_SNARE is not Microsoft 365, Azure Firewall is not just Azure. */
const WHOLE_NAME_ONLY = new Set(["MICROSOFT", "AZURE"]);

/**
 * A readable name for a Fusion sensor type such as ENDPOINT_TAEGIS or cloud
 * audit, for the Overview and the Search screens alike. A prefix only counts
 * at a word boundary, so CLOUDFLARE_HTTP is not "Cloud".
 */
export function sensorLabel(raw: string): string {
  const key = raw.toUpperCase().replace(/[\s-]+/g, "_");
  if (SENSOR_LABELS[key]) return SENSOR_LABELS[key]!;
  for (const [prefix, label] of Object.entries(SENSOR_LABELS)) if (!WHOLE_NAME_ONLY.has(prefix) && key.startsWith(`${prefix}_`)) return label;
  return raw
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

const PRODUCT_LABELS: Record<string, string> = {
  endpoint: "Endpoint",
  server: "Server",
  firewall: "Firewall",
  email: "Email",
  mobile: "Mobile",
  wireless: "Wireless",
  ztna: "ZTNA",
  ndr: "NDR",
  integrations: "Integrations",
  other: "Other",
};

export function productLabel(raw: string): string {
  return PRODUCT_LABELS[raw.toLowerCase()] ?? raw.replace(/\b\w/g, (m) => m.toUpperCase());
}

export function flowModel(
  args: {
    detections: DetectionSet[];
    alerts: AlertSet[];
    cases: CaseInput[];
    /** For a partner: the alert and detection count per tenant becomes the left fan. */
    perTenant?: Array<{ name: string; count: number }>;
    /** Source labels always shown for one tenant, even with no signals (Endpoint, Server). */
    baseline?: string[];
  },
  now: number,
  windowHours = 24,
  maxSources = 9,
): FlowModel {
  const start = now - windowHours * HOUR;
  const signals = signalSeries(args.detections.length ? args.detections : null, args.alerts.length ? args.alerts : null, now, windowHours);
  let sources: FlowSource[] = [];
  let moreSources: FlowModel["moreSources"] = null;
  if (args.perTenant) {
    const ranked = args.perTenant.filter((t) => t.count > 0).sort((a, b) => b.count - a.count);
    sources = ranked.slice(0, maxSources).map((t, i) => ({ key: `t${i}`, label: t.name, count: t.count, kind: "tenant" }));
    const rest = ranked.slice(maxSources);
    if (rest.length) moreSources = { count: rest.length, total: rest.reduce((a, t) => a + t.count, 0) };
  } else {
    const counts = new Map<string, number>();
    for (const set of args.detections) {
      // A sample short of the window is scaled up to Sophos's exact total, source by source.
      const scale = detectionScale(set, start, now);
      const local = new Map<string, number>();
      for (const d of set.items) {
        if (d.createdAt < start) continue;
        const label = d.sensorTypes.length ? sensorLabel(d.sensorTypes[0]!) : d.detector ? "Detectors" : "Other";
        local.set(label, (local.get(label) ?? 0) + 1);
      }
      for (const [label, n] of local) counts.set(label, (counts.get(label) ?? 0) + Math.round(n * scale));
    }
    for (const set of args.alerts) {
      for (const a of set.items) {
        if ((parse(a.raisedAt) ?? 0) < start) continue;
        const label = productLabel(a.product);
        counts.set(label, (counts.get(label) ?? 0) + 1);
      }
    }
    for (const label of args.baseline ?? []) if (!counts.has(label)) counts.set(label, 0);
    const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    sources = ranked.slice(0, maxSources).map(([label, count]) => ({ key: label.toLowerCase().replace(/\W+/g, "-"), label, count, kind: label.toLowerCase() }));
    const rest = ranked.slice(maxSources);
    if (rest.length) moreSources = { count: rest.length, total: rest.reduce((a, [, n]) => a + n, 0) };
  }
  const opened = { n: 0 };
  const mdr = { open: 0, resolved: 0 };
  const self = { open: 0, resolved: 0 };
  const unclaimed = { open: 0, resolved: 0 };
  const openBySeverity = emptySeverityCounts();
  let open = 0;
  let resolved = 0;
  for (const { set } of args.cases) {
    for (const c of set.open) {
      open++;
      openBySeverity[sevKey(c.severity)]++;
      (c.managedBy === "mdr" ? mdr : c.managedBy === "self" ? self : unclaimed).open++;
      if ((parse(c.createdAt) ?? 0) >= start) opened.n++;
    }
    for (const c of set.recentClosed) {
      if ((parse(c.closedAt) ?? 0) < start) continue;
      resolved++;
      (c.managedBy === "mdr" ? mdr : c.managedBy === "self" ? self : unclaimed).resolved++;
      if ((parse(c.createdAt) ?? 0) >= start) opened.n++;
    }
  }
  return {
    windowHours,
    sources,
    moreSources,
    signals: { label: signals.label, total: signals.total, source: signals.source, sampled: signals.sampled, bySeverity: signals.bySeverity },
    cases: { opened: opened.n, open, mdr, self, unclaimed, resolved, openBySeverity },
  };
}

// ---------------------------------------------------------------- S/MIME expiry

export interface SmimeStatus {
  /** Days to the soonest expiry still ahead (internal CA or a user certificate), or null. */
  days: number | null;
  kind: "ca" | "cert" | null;
  /** User certificates that expire within 30 days. */
  expiring: number;
  /** User certificates already expired (listed, but they don't color the tile). */
  expired: number;
  level: "critical" | "warning" | null;
  caExpiresAt: string | null;
  /** Days until the internal CA expires (negative once it has). */
  caDays: number | null;
  /** The tenant has an internal CA or user certificates at all. */
  inUse: boolean;
}

/** Same rule as licenses: an expiry 0 to 30 days ahead is a warning, 0 to 7 days critical. */
export function smimeStatus(record: SmimeRecord | null, now: number): SmimeStatus | null {
  if (!record || !record.available) return null;
  const daysTo = (at: string | null) => {
    const t = parse(at);
    return t === null ? null : Math.ceil((t - now) / DAY);
  };
  let days: number | null = null;
  let kind: SmimeStatus["kind"] = null;
  const caDays = daysTo(record.ca?.expiresAt ?? null);
  if (caDays !== null && caDays >= 0 && caDays <= 30) {
    days = caDays;
    kind = "ca";
  }
  let expiring = 0;
  let expired = 0;
  for (const c of record.expiring) {
    const d = daysTo(c.expiresAt);
    if (d === null) continue;
    if (d < 0) {
      expired++;
      continue;
    }
    if (d > 30) continue;
    expiring++;
    if (days === null || d < days) {
      days = d;
      kind = "cert";
    }
  }
  return {
    days,
    kind,
    expiring,
    expired,
    level: days === null ? null : days <= 7 ? "critical" : "warning",
    caExpiresAt: record.ca?.expiresAt ?? null,
    caDays,
    inUse: !!record.ca || record.expiring.length > 0,
  };
}

// ---------------------------------------------------------------- Search screens (X10, X11, N3)

export interface SearchBadge {
  partial: string[];
  truncated: boolean;
  reused: boolean;
}

function badge(metas: SearchMeta[]): SearchBadge {
  return {
    partial: [...new Set(metas.flatMap((m) => (m.outcome === "PARTIAL" ? m.failedSchemas : [])))],
    truncated: metas.some((m) => m.truncated),
    reused: metas.length > 0 && metas.every((m) => m.reused),
  };
}

export interface SigninInput {
  tenantName?: string;
  signins: SigninSet | null;
  mfa: MfaSet | null;
}

export interface SigninView {
  tenantsWithData: number;
  windowStart: number | null;
  windowEnd: number | null;
  total: number;
  success: number;
  failed: number;
  failures: Array<{ reason: string; count: number }>;
  bySource: Array<{ sensorType: string; label: string; total: number; failed: number; reportsMfa: boolean }>;
  locations: SigninLocation[];
  placement: { placed: number; unplaced: number; internal: number };
  mfa: {
    reportsMfa: boolean;
    signins: number;
    withMfa: number;
    withoutMfa: number;
    /** Service principal and non-interactive sign-ins from MFA-aware sources, never counted. */
    service: number;
    nonInteractive: number;
    /** Share of counted sign-ins without MFA, 0 to 1. */
    share: number | null;
    byApp: Array<{ name: string; signins: number; withoutMfa: number }>;
    byOs: Array<{ name: string; signins: number; withoutMfa: number }>;
    topUsers: Array<{ user: string; withoutMfa: number; source: string; tenantName?: string }>;
    sources: Array<{ sensorType: string; label: string; signins: number; withMfa: number; withoutMfa: number; service: number; nonInteractive: number; reportsMfa: boolean }>;
  };
  search: SearchBadge;
}

function addTo<T>(map: Map<string, T>, key: string, make: () => T, add: (t: T) => void): void {
  const v = map.get(key) ?? make();
  add(v);
  map.set(key, v);
}

/** X10 and X11 for one tenant or merged across tenants; user names masked in privacy mode. */
export function signinView(inputs: SigninInput[], privacy = false): SigninView {
  const failures = new Map<string, { reason: string; count: number }>();
  const sources = new Map<string, SigninView["bySource"][number]>();
  const locations = new Map<string, SigninLocation>();
  const apps = new Map<string, { name: string; signins: number; withoutMfa: number }>();
  const oses = new Map<string, { name: string; signins: number; withoutMfa: number }>();
  const mfaSources = new Map<string, SigninView["mfa"]["sources"][number]>();
  const users: SigninView["mfa"]["topUsers"] = [];
  const placement = { placed: 0, unplaced: 0, internal: 0 };
  const metas: SearchMeta[] = [];
  let total = 0;
  let success = 0;
  let failed = 0;
  let mfaSignins = 0;
  let withMfa = 0;
  let withoutMfa = 0;
  let service = 0;
  let nonInteractive = 0;
  const starts: number[] = [];
  const ends: number[] = [];
  let tenantsWithData = 0;
  for (const { tenantName, signins, mfa } of inputs) {
    if (signins || mfa) tenantsWithData++;
    if (signins) {
      metas.push(signins.search);
      starts.push(signins.windowStart);
      ends.push(signins.windowEnd);
      total += signins.total;
      success += signins.success;
      failed += signins.failed;
      placement.placed += signins.placement.placed;
      placement.unplaced += signins.placement.unplaced;
      placement.internal += signins.placement.internal;
      for (const f of signins.failures) addTo(failures, f.reason, () => ({ reason: f.reason, count: 0 }), (x) => (x.count += f.count));
      for (const b of signins.bySource) addTo(sources, b.sensorType, () => ({ sensorType: b.sensorType, label: sensorLabel(b.sensorType), total: 0, failed: 0, reportsMfa: false }), (x) => {
        x.total += b.total;
        x.failed += b.failed;
        x.reportsMfa ||= b.reportsMfa;
      });
      for (const l of signins.locations) addTo(locations, l.key, () => ({ ...l, total: 0, failed: 0, noMfa: 0 }), (x) => {
        x.total += l.total;
        x.failed += l.failed;
        x.noMfa += l.noMfa;
      });
    }
    if (mfa) {
      metas.push(mfa.search);
      starts.push(mfa.windowStart);
      ends.push(mfa.windowEnd);
      mfaSignins += mfa.signins;
      withMfa += mfa.withMfa;
      withoutMfa += mfa.withoutMfa;
      // A record cached before these were counted has neither.
      service += mfa.service ?? 0;
      nonInteractive += mfa.nonInteractive ?? 0;
      for (const a of mfa.byApp) addTo(apps, a.name, () => ({ name: a.name, signins: 0, withoutMfa: 0 }), (x) => {
        x.signins += a.signins;
        x.withoutMfa += a.withoutMfa;
      });
      for (const o of mfa.byOs) addTo(oses, o.name, () => ({ name: o.name, signins: 0, withoutMfa: 0 }), (x) => {
        x.signins += o.signins;
        x.withoutMfa += o.withoutMfa;
      });
      for (const src of mfa.sources) addTo(mfaSources, src.sensorType, () => ({ sensorType: src.sensorType, label: sensorLabel(src.sensorType), signins: 0, withMfa: 0, withoutMfa: 0, service: 0, nonInteractive: 0, reportsMfa: false }), (x) => {
        x.signins += src.signins;
        x.withMfa += src.withMfa;
        x.withoutMfa += src.withoutMfa;
        x.service += src.service ?? 0;
        x.nonInteractive += src.nonInteractive ?? 0;
        x.reportsMfa ||= src.reportsMfa;
      });
      for (const u of mfa.topUsers) users.push({ user: privacy ? maskName("User", u.user) : u.user, withoutMfa: u.withoutMfa, source: sensorLabel(u.sensorType), tenantName });
    }
  }
  const byCount = <T extends { count?: number; total?: number }>(a: T, b: T) => (b.count ?? b.total ?? 0) - (a.count ?? a.total ?? 0);
  const mfaRank = (a: { withoutMfa: number; signins: number }, b: { withoutMfa: number; signins: number }) => b.withoutMfa - a.withoutMfa || b.signins - a.signins;
  return {
    tenantsWithData,
    windowStart: starts.length ? Math.min(...starts) : null,
    windowEnd: ends.length ? Math.max(...ends) : null,
    total,
    success,
    failed,
    failures: [...failures.values()].sort(byCount).slice(0, 8),
    bySource: [...sources.values()].sort(byCount),
    locations: [...locations.values()].sort((a, b) => b.total - a.total).slice(0, 60),
    placement,
    mfa: {
      reportsMfa: [...mfaSources.values()].some((x) => x.reportsMfa),
      signins: mfaSignins,
      withMfa,
      withoutMfa,
      service,
      nonInteractive,
      share: mfaSignins ? withoutMfa / mfaSignins : null,
      byApp: [...apps.values()].sort(mfaRank).slice(0, 8),
      byOs: [...oses.values()].sort(mfaRank).slice(0, 7),
      topUsers: users.sort((a, b) => b.withoutMfa - a.withoutMfa || a.user.localeCompare(b.user)).slice(0, 25),
      sources: [...mfaSources.values()].sort((a, b) => Number(b.reportsMfa) - Number(a.reportsMfa) || b.signins - a.signins),
    },
    search: badge(metas),
  };
}

export interface SourceInput {
  tenantName?: string;
  set: SourceSet | null;
}

export interface SourceRow extends SourceRecord {
  label: string;
  tenantName?: string;
}

export interface SourcesView {
  tenantsWithData: number;
  days: string[];
  rows: SourceRow[];
  counts: { sources: number; live: number; quiet: number; silent: number };
  events7d: number;
  unparsed7d: number;
  /** Daily events across every source, oldest first. */
  daily: number[];
  search: SearchBadge;
}

/**
 * N3 for one tenant or every tenant. State is worked out again from the last
 * event, so a day-old read doesn't say live. A 7-day window touches 8 UTC
 * days; the first is partial and older, so the per-day series start at the
 * second (the last, today, is partial too and the screen labels it so).
 */
export function sourcesView(inputs: SourceInput[], now: number, maxRows = 200): SourcesView {
  const rows: SourceRow[] = [];
  const metas: SearchMeta[] = [];
  let days: string[] = [];
  let tenantsWithData = 0;
  const shown = (set: SourceSet) => (set.days.length > 7 ? 1 : 0);
  for (const { tenantName, set } of inputs) {
    if (!set) continue;
    tenantsWithData++;
    metas.push(set.search);
    const visible = set.days.slice(shown(set));
    if (!days.length || (visible.at(-1) ?? "") > (days.at(-1) ?? "")) days = visible;
    for (const s of set.sources) rows.push({ ...s, daily: s.daily.slice(shown(set)), state: sourceState(s.lastEventAt, now, s.state !== "silent"), label: sensorLabel(s.sensorType), tenantName });
  }
  const index = new Map(days.map((d, i) => [d, i]));
  const daily = days.map(() => 0);
  for (const { set } of inputs) {
    if (!set) continue;
    set.sources.forEach((s) => s.daily.forEach((n, i) => {
      const at = index.get(set.days[i] ?? "");
      if (at !== undefined) daily[at]! += n;
    }));
  }
  const order = { silent: 0, quiet: 1, live: 2 } as const;
  rows.sort((a, b) => order[a.state] - order[b.state] || b.events7d - a.events7d || a.label.localeCompare(b.label));
  return {
    tenantsWithData,
    days,
    rows: rows.slice(0, maxRows),
    counts: { sources: rows.length, live: rows.filter((r) => r.state === "live").length, quiet: rows.filter((r) => r.state === "quiet").length, silent: rows.filter((r) => r.state === "silent").length },
    events7d: rows.reduce((a, r) => a + r.events7d, 0),
    unparsed7d: rows.reduce((a, r) => a + r.unparsed7d, 0),
    daily,
    search: badge(metas),
  };
}

// ---------------------------------------------------------------- privacy (lobby screens)

function hashCode(text: string): number {
  let h = 0;
  for (let i = 0; i < text.length; i++) h = (Math.imul(31, h) + text.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/** A stable stand-in name: six hex digits keep 150 tenants from colliding. */
export function maskName(kind: "Tenant" | "Device" | "Case" | "User", value: string): string {
  return `${kind} ${(hashCode(value) % 0xffffff).toString(16).toUpperCase().padStart(6, "0")}`;
}
