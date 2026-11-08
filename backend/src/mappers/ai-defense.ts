/**
 * AI Defense: the Activity and Policy GraphQL answers shaped into one record
 * per tenant, the AI usage board's model, and the line on each MSP wall
 * tile. Pure: no network, no disk, so the tests drive it with fixed answers.
 *
 * A tenant without AI Defense is a state, never an error: not set up (no
 * settings record, or onboarding not finished), not licensed (the licence
 * expired), or unavailable (Sophos Fusion does not hold the tenant). Every
 * tenant tried answers the reads, licensed or not (measured 07/11/2026), so
 * the state comes from the settings record and whether anything happened in
 * the window.
 */

import type { AiDefenseActivity, AiDefenseApp, AiDefenseRecord, AiDefenseState, AiDefenseUser, AiRisk, AiRiskCounts } from "../data/types.js";
import type { AiDefenseDetailResponse, AiDefenseFlowResponse, AiDefenseOverviewResponse, AiDefensePoliciesResponse } from "../vendor/sophos-core/index.js";
import { AI_DEFENSE_FLOW_SLOTS } from "../vendor/sophos-core/fusion/queries/ai-defense.js";
import { maskName } from "./views.js";

const MIN = 60_000;
const DAY = 86_400_000;

export const AI_RISKS: AiRisk[] = ["critical", "high", "medium", "low", "info", "unknown"];
export const AI_RISK_LABEL: Record<AiRisk, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", unknown: "Unknown" };

/** The last 7 days, ending on the current minute. */
export function aiDefenseWindow(now: number): { start: number; end: number } {
  const end = Math.floor(now / MIN) * MIN;
  return { start: end - 7 * DAY, end };
}

const RISK: Record<string, AiRisk> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info" };

/** UNKNOWN, ERROR and anything new read as unknown. */
export function aiRisk(level: unknown): AiRisk {
  return RISK[String(level ?? "").toUpperCase()] ?? "unknown";
}

/** Int64 may arrive as a number or a digit string. */
function n(value: unknown): number {
  const v = typeof value === "number" ? value : Number(value);
  return Number.isFinite(v) && v > 0 ? v : 0;
}

function zeroRisks(): AiRiskCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
}

/**
 * Counts by risk for one action. The API's risks filter refuses ERROR, so
 * only CRITICAL to INFO are counted directly; the rest of the action's total
 * (UNKNOWN and ERROR) is unknown.
 */
function actionRisks(o: AiDefenseOverviewResponse, action: "blocked" | "warned"): AiRiskCounts {
  const c = zeroRisks();
  c.critical = n(o[`${action}Critical`]?.totalCount);
  c.high = n(o[`${action}High`]?.totalCount);
  c.medium = n(o[`${action}Medium`]?.totalCount);
  c.low = n(o[`${action}Low`]?.totalCount);
  c.info = n(o[`${action}Info`]?.totalCount);
  c.unknown = Math.max(0, n(o[action]?.totalCount) - (c.critical + c.high + c.medium + c.low + c.info));
  return c;
}

function stateOf(settings: AiDefenseOverviewResponse["secureAITenantSettings"], hasData: boolean): { state: AiDefenseState; note: string | null } {
  if (hasData) return { state: "active", note: null };
  if (!settings) return { state: "not-set-up", note: "AI Defense is not set up on this tenant: onboarding has not been started." };
  if (settings.licenseState === "EXPIRED") return { state: "not-licensed", note: "The AI Defense licence expired, and there is no AI activity in the last 7 days." };
  const status = settings.onboarding?.status ?? null;
  if (status !== "COMPLETED") return { state: "not-set-up", note: `AI Defense set-up is not finished on this tenant (onboarding ${status === "IN_PROGRESS" ? "in progress" : "not started"}).` };
  return { state: "active", note: null };
}

function emptyRecord(window: { start: number; end: number }): AiDefenseRecord {
  return {
    state: "not-set-up",
    note: null,
    windowStart: window.start,
    windowEnd: window.end,
    onboarding: null,
    licence: null,
    policies: null,
    activity: { total: 0, unsanctioned: 0, blocked: 0, warned: 0, blockedByRisk: zeroRisks(), warnedByRisk: zeroRisks() },
    apps: { total: 0, byRisk: zeroRisks(), trainsOnData: null, unsanctioned: 0 },
    users: { total: 0, byRisk: zeroRisks(), withViolations: 0, unsanctioned: 0 },
    topApps: [],
    topUsers: [],
    recent: [],
    recentOf: 0,
    warnings: [],
    calls: 1,
  };
}

/** A tenant Sophos Fusion does not hold: its AI Defense data can't be read with this credential. */
export function unavailableAiDefense(window: { start: number; end: number }): AiDefenseRecord {
  return { ...emptyRecord(window), state: "unavailable", note: "Sophos Fusion does not hold this tenant, so its AI Defense data can't be read." };
}

/** The overview answer as a record: settings, state, inventory totals and blocked and warned counts by risk. */
export function mapAiDefenseOverview(o: AiDefenseOverviewResponse, window: { start: number; end: number }, warnings: string[] = []): AiDefenseRecord {
  const r = emptyRecord(window);
  const s = o.secureAITenantSettings;
  const apps = o.inventorySummary?.apps;
  const users = o.inventorySummary?.users;
  r.activity = { total: n(o.all?.totalCount), unsanctioned: n(o.unsanctioned?.totalCount), blocked: n(o.blocked?.totalCount), warned: n(o.warned?.totalCount), blockedByRisk: actionRisks(o, "blocked"), warnedByRisk: actionRisks(o, "warned") };
  if (apps) {
    r.apps = {
      total: n(apps.totalApps),
      byRisk: { critical: n(apps.criticalRisk), high: n(apps.highRisk), medium: n(apps.mediumRisk), low: n(apps.lowRisk), info: n(apps.infoRisk), unknown: n(apps.unknownRisk) + n(apps.errorRisk) },
      trainsOnData: apps.trainsOnData === null || apps.trainsOnData === undefined ? null : n(apps.trainsOnData),
      unsanctioned: n(apps.unsanctionedCount),
    };
  }
  if (users) {
    r.users = {
      total: n(users.totalUsers),
      byRisk: { critical: n(users.criticalRisk), high: n(users.highRisk), medium: n(users.mediumRisk), low: n(users.lowRisk), info: n(users.infoRisk), unknown: n(users.unknownRisk) },
      withViolations: n(users.withViolations),
      unsanctioned: n(users.unsanctionedCount),
    };
  }
  r.onboarding = s?.onboarding?.status ?? null;
  r.licence = s ? { state: s.licenseState ?? null, type: s.licenseType ?? null, expiresAt: s.licenseExpiryDate ?? null, graceEndsAt: s.gracePeriodEndsAt ?? null } : null;
  const { state, note } = stateOf(s, hasAiData(r));
  r.state = state;
  r.note = note;
  r.warnings = [...warnings];
  return r;
}

export function hasAiData(r: AiDefenseRecord): boolean {
  return r.activity.total > 0 || r.apps.total > 0 || r.users.total > 0;
}

export function mapAiDefensePolicies(p: AiDefensePoliciesResponse): AiDefenseRecord["policies"] {
  return p.policies ? { total: n(p.policies.totalCount), enabled: n(p.policies.enabledCount), failed: n(p.policies.failedCount) } : null;
}

/** The detail answer: top apps and users by activity, and the newest blocked and warned activities. */
export function mapAiDefenseDetail(d: AiDefenseDetailResponse): Pick<AiDefenseRecord, "topApps" | "topUsers" | "recent" | "recentOf"> {
  const topApps: AiDefenseApp[] = (d.appInventory?.entries ?? []).map((a) => ({
    id: String(a.id ?? ""),
    name: String(a.name || a.id || ""),
    provider: String(a.provider ?? ""),
    risk: aiRisk(a.risk),
    usage: n(a.usage),
    users: n(a.uniqueUsers),
    unsanctioned: n(a.unsanctionedCount),
    lastSeen: a.lastSeen ?? null,
    blocked: null,
    warned: null,
  }));
  const topUsers: AiDefenseUser[] = (d.userInventory?.entries ?? []).map((u) => ({
    id: String(u.id ?? ""),
    name: String(u.name ?? ""),
    risk: aiRisk(u.risk),
    apps: n(u.appsUsed),
    usage: n(u.usage),
    violations: n(u.policyViolations),
    topApp: u.topApp ?? null,
    unsanctioned: n(u.unsanctionedCount),
    lastSeen: u.lastSeen ?? null,
    blocked: null,
    warned: null,
  }));
  const recent: AiDefenseActivity[] = [];
  for (const a of d.activities?.activities ?? []) {
    const action = a.action === "BLOCKED" ? "blocked" : a.action === "WARNED" ? "warned" : null;
    const at = Date.parse(a.timestamp?.startTime ?? "");
    if (!action || !Number.isFinite(at)) continue;
    recent.push({
      at,
      user: String(a.actor?.name ?? ""),
      userType: String(a.actor?.type ?? ""),
      appId: String(a.application?.id ?? ""),
      app: String(a.application?.name || a.application?.id || ""),
      action,
      risk: aiRisk(a.risk),
      policy: String(a.policy ?? ""),
      device: String(a.device?.name ?? ""),
      platform: String(a.device?.platform ?? ""),
      count: Math.max(1, n(a.aggregationCount)),
    });
  }
  return { topApps, topUsers, recent, recentOf: n(d.activities?.totalCount) };
}

// ---------------------------------------------------------------- the flow read

/** The ids the flow read counts: the top apps and users, an empty string where one has no id. */
export function aiFlowSlots(r: Pick<AiDefenseRecord, "topApps" | "topUsers">): { apps: string[]; users: string[] } {
  return { apps: r.topApps.slice(0, AI_DEFENSE_FLOW_SLOTS).map((a) => a.id), users: r.topUsers.slice(0, AI_DEFENSE_FLOW_SLOTS).map((u) => u.id) };
}

/**
 * Puts the flow read's counts on the record's top apps and users. A slot
 * sent with no id (the unused id) counts nothing, so its app or user stays
 * unread. With `answer` null nothing was blocked or warned, so every slot is 0.
 */
export function applyAiDefenseFlow(r: Pick<AiDefenseRecord, "topApps" | "topUsers">, answer: AiDefenseFlowResponse | null): void {
  const slots = aiFlowSlots(r);
  const count = (key: string) => (answer ? n(answer[key]?.totalCount) : 0);
  slots.apps.forEach((id, i) => {
    const a = r.topApps[i]!;
    a.blocked = id || !answer ? count(`app${i}Blocked`) : null;
    a.warned = id || !answer ? count(`app${i}Warned`) : null;
  });
  slots.users.forEach((id, i) => {
    const u = r.topUsers[i]!;
    u.blocked = id || !answer ? count(`user${i}Blocked`) : null;
    u.warned = id || !answer ? count(`user${i}Warned`) : null;
  });
}

// ---------------------------------------------------------------- the AI usage board

export type AiViewState = AiDefenseState | "pending" | "no-access" | "none";

export interface AiInput {
  tenantId: string;
  /** Set when the board shows more than one tenant. */
  tenantName?: string;
  record: AiDefenseRecord | null;
  /** Sophos refused the reads (403 or a permission error). */
  noAccess?: boolean;
}

export interface AiTenantRow {
  tenantId: string;
  name: string;
  state: AiViewState;
  note: string | null;
  total: number | null;
  blocked: number | null;
  warned: number | null;
  apps: number | null;
  users: number | null;
  policies: number | null;
}

export interface AiView {
  state: AiViewState;
  note: string | null;
  scope: { tenants: number; active: number; notSetUp: number; notLicensed: number; unavailable: number; pending: number; noAccess: number };
  windowStart: number | null;
  windowEnd: number | null;
  activity: AiDefenseRecord["activity"];
  apps: { total: number; byRisk: AiRiskCounts; trainsOnData: number | null; unsanctioned: number };
  users: { total: number; byRisk: AiRiskCounts; withViolations: number; unsanctioned: number };
  /** Summed over the tenants whose policy read answered; null when none did. */
  policies: { total: number; enabled: number; failed: number } | null;
  /** One tenant only. */
  licence: AiDefenseRecord["licence"];
  risks: Array<{ risk: AiRisk; label: string; blocked: number; warned: number }>;
  /** The flow: apps and users on either side of what AI Defense did. */
  flow: AiFlow;
  topApps: Array<Omit<AiDefenseApp, "blocked" | "warned"> & { tenants: number }>;
  topUsers: Array<Omit<AiDefenseUser, "id" | "blocked" | "warned"> & { tenantName?: string }>;
  recent: Array<AiDefenseActivity & { tenantName?: string }>;
  /** Blocked and warned activities in the window across the tenants, of which `recent` holds the newest. */
  recentOf: number;
  tenantRows: AiTenantRow[];
  warnings: string[];
}

const STATE_ORDER: Record<AiViewState, number> = { active: 0, "not-licensed": 1, "not-set-up": 2, unavailable: 3, "no-access": 4, pending: 5, none: 6 };
const RISK_ORDER: Record<AiRisk, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function inputState(i: AiInput): AiViewState {
  return i.record?.state ?? (i.noAccess ? "no-access" : "pending");
}

function addRisks(into: AiRiskCounts, from: AiRiskCounts): void {
  for (const k of AI_RISKS) into[k] += from[k];
}

const NO_ACCESS_NOTE = "Sophos refused the AI Defense reads: the tenant has no licence for this data, or the credential's role does not include AI Defense.";

/** The board for one tenant or every tenant in scope. Privacy hides user and device names. */
export function aiDefenseView(inputs: AiInput[], privacy = false): AiView {
  const scope = { tenants: inputs.length, active: 0, notSetUp: 0, notLicensed: 0, unavailable: 0, pending: 0, noAccess: 0 };
  const activity: AiView["activity"] = { total: 0, unsanctioned: 0, blocked: 0, warned: 0, blockedByRisk: zeroRisks(), warnedByRisk: zeroRisks() };
  const apps: AiView["apps"] = { total: 0, byRisk: zeroRisks(), trainsOnData: null, unsanctioned: 0 };
  const users: AiView["users"] = { total: 0, byRisk: zeroRisks(), withViolations: 0, unsanctioned: 0 };
  let policies = null as AiView["policies"];
  const appMap = new Map<string, AiView["topApps"][number]>();
  const actives: FlowTenant[] = [];
  const topUsers: AiView["topUsers"] = [];
  const recent: AiView["recent"] = [];
  const warnings = new Set<string>();
  let recentOf = 0;
  let windowStart: number | null = null;
  let windowEnd: number | null = null;
  const tenantRows: AiTenantRow[] = [];
  const mask = (kind: "User" | "Device", value: string) => (privacy && value ? maskName(kind, value) : value);

  for (const input of inputs) {
    const state = inputState(input);
    if (state === "active") scope.active++;
    else if (state === "not-set-up") scope.notSetUp++;
    else if (state === "not-licensed") scope.notLicensed++;
    else if (state === "unavailable") scope.unavailable++;
    else if (state === "no-access") scope.noAccess++;
    else scope.pending++;
    const r = input.record;
    const active = state === "active" && r;
    tenantRows.push({
      tenantId: input.tenantId,
      name: input.tenantName ?? "",
      state,
      note: r?.note ?? (state === "no-access" ? NO_ACCESS_NOTE : null),
      total: active ? r.activity.total : null,
      blocked: active ? r.activity.blocked : null,
      warned: active ? r.activity.warned : null,
      apps: active ? r.apps.total : null,
      users: active ? r.users.total : null,
      policies: active ? (r.policies?.total ?? null) : null,
    });
    if (!active) continue;
    actives.push({ record: r, tenantName: input.tenantName });
    windowStart = windowStart === null ? r.windowStart : Math.min(windowStart, r.windowStart);
    windowEnd = windowEnd === null ? r.windowEnd : Math.max(windowEnd, r.windowEnd);
    activity.total += r.activity.total;
    activity.unsanctioned += r.activity.unsanctioned;
    activity.blocked += r.activity.blocked;
    activity.warned += r.activity.warned;
    addRisks(activity.blockedByRisk, r.activity.blockedByRisk);
    addRisks(activity.warnedByRisk, r.activity.warnedByRisk);
    apps.total += r.apps.total;
    addRisks(apps.byRisk, r.apps.byRisk);
    if (r.apps.trainsOnData !== null) apps.trainsOnData = (apps.trainsOnData ?? 0) + r.apps.trainsOnData;
    apps.unsanctioned += r.apps.unsanctioned;
    users.total += r.users.total;
    addRisks(users.byRisk, r.users.byRisk);
    users.withViolations += r.users.withViolations;
    users.unsanctioned += r.users.unsanctioned;
    if (r.policies) policies = { total: (policies?.total ?? 0) + r.policies.total, enabled: (policies?.enabled ?? 0) + r.policies.enabled, failed: (policies?.failed ?? 0) + r.policies.failed };
    for (const a of r.topApps) {
      const key = a.id || a.name;
      const have = appMap.get(key);
      const { blocked: _b, warned: _w, ...row } = a;
      if (!have) appMap.set(key, { ...row, tenants: 1 });
      else {
        have.usage += a.usage;
        have.users += a.users;
        have.unsanctioned += a.unsanctioned;
        have.tenants++;
        if (RISK_ORDER[a.risk] < RISK_ORDER[have.risk]) have.risk = a.risk;
        if ((a.lastSeen ?? "") > (have.lastSeen ?? "")) have.lastSeen = a.lastSeen;
      }
    }
    for (const { id: _id, blocked: _b, warned: _w, ...u } of r.topUsers) topUsers.push({ ...u, name: mask("User", u.name), ...(input.tenantName !== undefined ? { tenantName: input.tenantName } : {}) });
    for (const a of r.recent) recent.push({ ...a, user: mask("User", a.user), device: mask("Device", a.device), ...(input.tenantName !== undefined ? { tenantName: input.tenantName } : {}) });
    recentOf += r.recentOf;
    for (const w of r.warnings) warnings.add(w);
  }

  let state: AiViewState;
  let note: string | null = null;
  if (inputs.length === 1) {
    state = inputState(inputs[0]!);
    note = tenantRows[0]!.note ?? (state === "pending" ? "Reading AI Defense for this tenant." : null);
  } else if (scope.active) state = "active";
  else if (scope.pending + scope.noAccess === scope.tenants) {
    state = scope.pending ? "pending" : "no-access";
    note = state === "pending" ? "Reading AI Defense for each tenant." : NO_ACCESS_NOTE;
  } else {
    state = "none";
    const parts = [scope.notSetUp ? `${scope.notSetUp} not set up` : "", scope.notLicensed ? `${scope.notLicensed} with an expired licence` : "", scope.unavailable ? `${scope.unavailable} not on Sophos Fusion` : "", scope.noAccess ? `${scope.noAccess} refused` : "", scope.pending ? `${scope.pending} not read yet` : ""].filter(Boolean);
    note = `No tenant here has AI Defense set up: ${parts.join(", ")}.`;
  }

  tenantRows.sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || (b.total ?? 0) - (a.total ?? 0) || a.name.localeCompare(b.name));
  return {
    state,
    note,
    scope,
    windowStart,
    windowEnd,
    activity,
    apps,
    users,
    policies,
    licence: inputs.length === 1 ? (inputs[0]!.record?.licence ?? null) : null,
    risks: AI_RISKS.map((risk) => ({ risk, label: AI_RISK_LABEL[risk], blocked: activity.blockedByRisk[risk], warned: activity.warnedByRisk[risk] })),
    flow: aiFlow(actives, activity, { multi: inputs.length > 1, appsTotal: apps.total, usersTotal: users.total, mask: (name) => mask("User", name) }),
    topApps: [...appMap.values()].sort((a, b) => b.usage - a.usage || a.name.localeCompare(b.name)).slice(0, 20),
    topUsers: topUsers.sort((a, b) => b.usage - a.usage).slice(0, 25),
    recent: recent.sort((a, b) => b.at - a.at).slice(0, 50),
    recentOf,
    tenantRows,
    warnings: [...warnings],
  };
}

// ---------------------------------------------------------------- the flow

/** Apps and users the flow names on each side; the rest share one bucket per side. */
export const AI_FLOW_TOP = AI_DEFENSE_FLOW_SLOTS;

export interface AiFlowEntity {
  key: string;
  kind: "app" | "user" | "other";
  label: string;
  total: number;
  /** Null when the split by outcome could not be read (the board says so). */
  blocked: number | null;
  warned: number | null;
  allowed: number | null;
  /** Allowed with no policy covering the app. */
  unsanctioned: number;
  /** Apps: the logo match and the tooltip use these. */
  appId?: string;
  provider?: string;
  risk?: AiRisk;
  users?: number;
  /** All tenants: the tenants an app's figures come from. */
  tenants?: number;
  /** All tenants: this app's activity in tenants where its split was not read, counted under other apps. */
  elsewhere?: number;
  /** Users. */
  tenantName?: string;
  apps?: number;
  topApp?: string | null;
  /** The user is an IP address AI Defense could not tie to a person. */
  network?: boolean;
  /** Other: how many apps or users it gathers, when that is known. */
  count?: number | null;
}

export interface AiFlow {
  /** False when no tenant's split by app and user was read: the bands then carry activity only. */
  split: boolean;
  total: number;
  blocked: number;
  warned: number;
  /** Everything not blocked or warned. */
  allowed: number;
  unsanctioned: number;
  /** AI apps, most active first, then the other bucket. */
  apps: AiFlowEntity[];
  /** Users, most active first, then the other bucket. */
  users: AiFlowEntity[];
  note: string | null;
}

interface FlowTenant {
  record: AiDefenseRecord;
  tenantName?: string;
}

const IP_ADDRESS = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)$/i;

function known(x: { blocked?: number | null; warned?: number | null }): x is { blocked: number; warned: number } {
  return typeof x.blocked === "number" && typeof x.warned === "number";
}

function count(value: number, one: string, many: string): string {
  return `${value.toLocaleString("en-US")} ${value === 1 ? one : many}`;
}

/** A tenant whose flow read answered (or had nothing blocked or warned to split). */
function tenantSplit(r: AiDefenseRecord): boolean {
  if (!r.topApps.length && !r.topUsers.length) return true;
  return r.topApps.some(known) || r.topUsers.some(known);
}

function split(usage: number, blocked: number, warned: number) {
  const allowed = Math.max(0, usage - blocked - warned);
  return { blocked, warned, allowed, total: blocked + warned + allowed };
}

function byTotal(a: AiFlowEntity, b: AiFlowEntity): number {
  return b.total - a.total || a.label.localeCompare(b.label) || (a.tenantName ?? "").localeCompare(b.tenantName ?? "");
}

/**
 * The flow model: AI apps on one side, users on the other, both meeting at
 * what AI Defense did (blocked, warned or allowed). Each side names its top
 * 10 and puts the rest in one bucket, so both sides always add up to the
 * same outcome totals, which are the overview's counts. An app or user is
 * named only when its split was read, so no band is guessed; a tenant whose
 * split could not be read falls into the buckets and the note says so. With
 * no split at all, the bands carry activity only.
 */
export function aiFlow(actives: FlowTenant[], activity: AiDefenseRecord["activity"], opts: { multi: boolean; appsTotal: number; usersTotal: number; mask: (name: string) => string }): AiFlow {
  const total = activity.total;
  const allowedTotal = Math.max(0, total - activity.blocked - activity.warned);
  const base = { total, blocked: activity.blocked, warned: activity.warned, allowed: allowedTotal, unsanctioned: activity.unsanctioned };
  if (!total) return { split: true, ...base, apps: [], users: [], note: null };
  const splitTenants = actives.filter((t) => tenantSplit(t.record));
  const isSplit = splitTenants.length > 0;
  const source = isSplit ? splitTenants : actives;
  const take = (x: { blocked: number | null; warned: number | null }) => !isSplit || known(x);

  const appMap = new Map<string, AiFlowEntity>();
  const userRows: AiFlowEntity[] = [];
  for (const { record, tenantName } of source) {
    for (const a of record.topApps) {
      if (!take(a)) continue;
      const key = `app:${a.id || a.name}`;
      const s = isSplit && known(a) ? split(a.usage, a.blocked, a.warned) : null;
      const have = appMap.get(key);
      if (!have) {
        appMap.set(key, {
          key,
          kind: "app",
          label: a.name || a.id || "Unnamed app",
          total: s ? s.total : a.usage,
          blocked: s?.blocked ?? null,
          warned: s?.warned ?? null,
          allowed: s?.allowed ?? null,
          unsanctioned: a.unsanctioned,
          appId: a.id,
          provider: a.provider,
          risk: a.risk,
          users: a.users,
          ...(opts.multi ? { tenants: 1, elsewhere: 0 } : {}),
        });
      } else {
        have.total += s ? s.total : a.usage;
        if (s) {
          have.blocked = (have.blocked ?? 0) + s.blocked;
          have.warned = (have.warned ?? 0) + s.warned;
          have.allowed = (have.allowed ?? 0) + s.allowed;
        }
        have.unsanctioned += a.unsanctioned;
        have.users = (have.users ?? 0) + a.users;
        have.tenants = (have.tenants ?? 1) + 1;
        if (RISK_ORDER[a.risk] < RISK_ORDER[have.risk ?? "unknown"]) have.risk = a.risk;
      }
    }
    record.topUsers.forEach((u, i) => {
      if (!take(u)) return;
      const s = isSplit && known(u) ? split(u.usage, u.blocked, u.warned) : null;
      const name = u.name || "Unknown";
      userRows.push({
        key: `user:${tenantName ?? ""}:${i}`,
        kind: "user",
        label: u.name ? opts.mask(u.name) : name,
        total: s ? s.total : u.usage,
        blocked: s?.blocked ?? null,
        warned: s?.warned ?? null,
        allowed: s?.allowed ?? null,
        unsanctioned: u.unsanctioned,
        apps: u.apps,
        topApp: u.topApp,
        network: IP_ADDRESS.test(u.name),
        ...(tenantName !== undefined ? { tenantName } : {}),
      });
    });
  }
  // All tenants: an app's activity in tenants where its split was not read is under other apps.
  if (opts.multi && isSplit) {
    for (const { record } of actives) {
      for (const a of record.topApps) {
        if (tenantSplit(record) && known(a)) continue;
        const have = appMap.get(`app:${a.id || a.name}`);
        if (have) have.elsewhere = (have.elsewhere ?? 0) + a.usage;
      }
    }
  }
  const apps = [...appMap.values()].sort(byTotal).slice(0, AI_FLOW_TOP);
  const users = userRows.sort(byTotal).slice(0, AI_FLOW_TOP);
  const sum = (rows: AiFlowEntity[], k: "blocked" | "warned" | "allowed" | "total" | "unsanctioned") => rows.reduce((acc, r) => acc + (r[k] ?? 0), 0);

  const out: AiFlow = { split: isSplit, ...base, apps, users, note: null };
  if (isSplit) {
    // Counts read a moment apart can disagree by a few: both sides take the larger, so they always meet.
    out.blocked = Math.max(activity.blocked, sum(apps, "blocked"), sum(users, "blocked"));
    out.warned = Math.max(activity.warned, sum(apps, "warned"), sum(users, "warned"));
    out.allowed = Math.max(allowedTotal, sum(apps, "allowed"), sum(users, "allowed"));
    out.total = out.blocked + out.warned + out.allowed;
  }
  const other = (rows: AiFlowEntity[], key: string, label: string, n: number | null): AiFlowEntity | null => {
    const unsanctioned = Math.max(0, activity.unsanctioned - sum(rows, "unsanctioned"));
    if (!isSplit) {
      const rest = out.total - sum(rows, "total");
      return rest > 0 ? { key, kind: "other", label, total: rest, blocked: null, warned: null, allowed: null, unsanctioned, count: n } : null;
    }
    const blocked = out.blocked - sum(rows, "blocked");
    const warned = out.warned - sum(rows, "warned");
    const allowed = out.allowed - sum(rows, "allowed");
    const rest = blocked + warned + allowed;
    return rest > 0 ? { key, kind: "other", label, total: rest, blocked, warned, allowed, unsanctioned, count: n } : null;
  };
  const otherApps = opts.multi ? null : Math.max(0, opts.appsTotal - apps.length);
  const otherUsers = Math.max(0, opts.usersTotal - users.length);
  const appsRest = other(apps, "other:apps", otherApps ? count(otherApps, "other app", "other apps") : "Other apps", otherApps);
  const usersRest = other(users, "other:users", otherUsers ? count(otherUsers, "other user", "other users") : "No user named", otherUsers || null);
  if (appsRest) apps.push(appsRest);
  if (usersRest) users.push(usersRest);
  if (!isSplit) out.note = "AI Defense's split by app and user could not be read, so the bands show activity only. The outcome totals are exact.";
  else if (splitTenants.length < actives.length) {
    const missing = actives.length - splitTenants.length;
    out.note = `The split by app and user could not be read for ${count(missing, "tenant", "tenants")}, so ${missing === 1 ? "its" : "their"} activity is under other apps and other users.`;
  }
  return out;
}

// ---------------------------------------------------------------- MSP wall tile

export interface AiTileLine {
  state: AiDefenseState | "no-access";
  text: string;
  apps: number | null;
  users: number | null;
  blocked: number | null;
  warned: number | null;
}

function plural(count: number, word: string): string {
  return `${count} ${count === 1 ? word : `${word}s`}`;
}

/** The AI Defense line on a tenant's tile, or null before the first read. */
export function aiTile(record: AiDefenseRecord | null, noAccess = false): AiTileLine | null {
  const blank = { apps: null, users: null, blocked: null, warned: null };
  if (!record) return noAccess ? { state: "no-access", text: "AI Defense: no access", ...blank } : null;
  switch (record.state) {
    case "active":
      return { state: "active", text: `${plural(record.apps.total, "AI app")} · ${plural(record.users.total, "user")}`, apps: record.apps.total, users: record.users.total, blocked: record.activity.blocked, warned: record.activity.warned };
    case "not-licensed":
      return { state: "not-licensed", text: "AI Defense licence expired", ...blank };
    case "unavailable":
      return { state: "unavailable", text: "AI Defense: not on Sophos Fusion", ...blank };
    default:
      return { state: "not-set-up", text: "AI Defense not set up", ...blank };
  }
}
