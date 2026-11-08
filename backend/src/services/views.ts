/**
 * Builds each screen's JSON from the provider's cache: picks the tenants in
 * scope, runs the pure mappers, adds freshness, and applies privacy masking
 * for lobby screens. Each build also tells the provider what is on screen,
 * so the scheduler refreshes that first.
 */

import type { Provider } from "./provider.js";
import type { DatasetName, Freshness } from "./engine.js";
import type { Settings } from "../store/settings.js";
import type { AlertSet, CaseSet, DetectionSet, TenantRecord } from "../data/types.js";
import {
  caseBoard,
  endpointSummary,
  flowModel,
  maskName,
  mspWall,
  nowWall,
  signalSeries,
  signinView,
  smimeStatus,
  sourcesView,
  tenantTile,
  type CaseInput,
  type EndpointSummary,
} from "../mappers/views.js";
import { aiDefenseView } from "../mappers/ai-defense.js";

const DATASET_LABELS: Record<DatasetName, string> = {
  generation: "API generation",
  cases: "Cases",
  detections: "Detections",
  alerts: "Alerts",
  endpoints: "Endpoints",
  health: "Health check",
  licences: "Licences",
  egress: "Device egress IPs",
  signins: "Sign-ins (Search)",
  mfa: "MFA (Search)",
  sources: "Data sources (Search)",
  smime: "S/MIME certificates",
  aidefense: "AI Defense",
};

export interface FreshnessRow {
  dataset: DatasetName;
  label: string;
  fetchedAt: number | null;
  intervalMs: number;
  coverage: { have: number; of: number };
  errors: number;
  lastError: string | null;
  running: boolean;
  /** failed: nothing usable came back; partial: some tenants failed, the rest are fresh. */
  state: "fresh" | "aging" | "failed" | "partial" | "pending";
}

export function summariseFreshness(rows: Freshness[], now = Date.now()): FreshnessRow[] {
  const by = new Map<DatasetName, Freshness[]>();
  for (const r of rows) by.set(r.dataset, [...(by.get(r.dataset) ?? []), r]);
  const out: FreshnessRow[] = [];
  for (const [dataset, list] of by) {
    const have = list.filter((r) => r.fetchedAt !== null);
    const oldest = have.length ? Math.min(...have.map((r) => r.fetchedAt!)) : null;
    const errors = list.filter((r) => r.lastError && !r.noAccess).length;
    const intervalMs = Math.max(...list.map((r) => r.intervalMs));
    let state: FreshnessRow["state"] = "fresh";
    if (oldest === null) state = errors ? "failed" : "pending";
    else if (errors && errors >= have.length) state = "failed";
    else if (now - oldest > intervalMs * 2) state = "aging";
    else if (errors) state = "partial";
    out.push({
      dataset,
      label: DATASET_LABELS[dataset],
      fetchedAt: oldest,
      intervalMs,
      coverage: { have: have.length, of: list.length },
      errors,
      lastError: list.find((r) => r.lastError)?.lastError ?? null,
      running: list.some((r) => r.running),
      state,
    });
  }
  return out;
}

export interface Scope {
  tenants: TenantRecord[];
  all: boolean;
  tenantId: string | null;
}

export function scopeFor(provider: Provider, tenantParam: unknown): Scope {
  const ctx = provider.context;
  if (!ctx?.multiTenant) return { tenants: provider.tenants.slice(0, 1), all: false, tenantId: provider.tenants[0]?.id ?? null };
  const id = typeof tenantParam === "string" ? tenantParam : "all";
  if (id !== "all") {
    const t = provider.tenant(id);
    if (t) return { tenants: [t], all: false, tenantId: t.id };
  }
  return { tenants: provider.tenants, all: true, tenantId: null };
}

function displayName(settings: Settings, name: string): string {
  return settings.privacy ? maskName("Tenant", name) : name;
}

function caseInputs(provider: Provider, scope: Scope, settings: Settings): CaseInput[] {
  const out: CaseInput[] = [];
  for (const t of scope.tenants) {
    const set = provider.get("cases", t.id);
    if (set) out.push({ set: privacyCases(set, settings), tenantName: scope.all ? displayName(settings, t.name) : undefined });
  }
  return out;
}

function privacyCases(set: CaseSet, settings: Settings): CaseSet {
  if (!settings.privacy) return set;
  const mask = (c: CaseSet["open"][number]) => ({ ...c, title: "Case title hidden" });
  return { ...set, open: set.open.map(mask), recentClosed: set.recentClosed.map(mask) };
}

function collect<T>(provider: Provider, dataset: "detections" | "alerts", scope: Scope): T[] {
  const out: T[] = [];
  for (const t of scope.tenants) {
    const v = provider.get(dataset, t.id);
    if (v) out.push(v as T);
  }
  return out;
}

function header(provider: Provider, scope: Scope, settings: Settings) {
  const t = scope.tenantId ? provider.tenant(scope.tenantId) : null;
  return {
    scope: scope.all ? "all" : "tenant",
    tenantId: scope.tenantId,
    tenantName: scope.all ? `All tenants (${provider.tenants.length})` : t ? displayName(settings, t.name) : provider.label,
    generation: scope.tenantId ? (provider.get("generation", scope.tenantId)?.generation ?? null) : null,
    tenantCount: provider.tenants.length,
  };
}

export function buildFront(provider: Provider, scope: Scope, settings: Settings, windowHours: number, now = Date.now()) {
  const datasets: DatasetName[] = ["cases", "detections", "alerts", "endpoints", "health"];
  provider.focus(datasets, scope.all ? [] : scope.tenants.map((t) => t.id));
  const detections = collect<DetectionSet>(provider, "detections", scope);
  const alerts = collect<AlertSet>(provider, "alerts", scope);
  const cases = caseInputs(provider, scope, settings);
  const perTenant = scope.all
    ? scope.tenants.map((t) => {
        const series = signalSeries(
          provider.get("detections", t.id) ? [provider.get("detections", t.id)!] : null,
          provider.get("alerts", t.id) ? [provider.get("alerts", t.id)!] : null,
          now,
          windowHours,
        );
        return { name: displayName(settings, t.name), count: series.total };
      })
    : undefined;
  const baseline: string[] = [];
  if (!scope.all && scope.tenants[0]) {
    const list = provider.get("endpoints", scope.tenants[0].id) ?? [];
    if (list.some((e) => !e.isServer)) baseline.push("Endpoint");
    if (list.some((e) => e.isServer)) baseline.push("Server");
  }
  const flow = flowModel({ detections, alerts, cases, perTenant, baseline }, now, windowHours);
  // The strip always shows the last 24 hours, whatever window the flow uses.
  const series = signalSeries(detections.length ? detections : null, alerts.length ? alerts : null, now, 24);

  // Bottom strip
  let endpoints = 0;
  let unhealthy = 0;
  let stale = 0;
  let healthSum = 0;
  let healthN = 0;
  for (const t of scope.tenants) {
    const list = provider.get("endpoints", t.id);
    if (list) {
      const s = endpointSummary(list, now);
      endpoints += s.total;
      unhealthy += s.health.bad + s.health.suspicious;
      stale += s.staleOver7;
    }
    const h = provider.get("health", t.id);
    if (h?.overall !== null && h?.overall !== undefined) {
      healthSum += h.overall;
      healthN++;
    }
  }
  const trend = scope.tenants.length === 1 ? provider.snapshots<{ total: number; bad: number; suspicious: number }>("endpoints", scope.tenants[0]!.id, now - 30 * 86_400_000) : [];
  const board = caseBoard(cases, settings.targets, now, "all", 1);
  const wall = nowWall(cases, series, settings.targets, now);
  const smime = smimeStrip(provider, scope, settings, now);
  let needAction: number | null = null;
  if (scope.all) {
    const tiles = scope.tenants.map((t) => tileFor(provider, t, settings, now));
    needAction = tiles.filter((x) => x.state === "critical").length;
  }
  return {
    view: "front",
    ...header(provider, scope, settings),
    windowHours,
    flow,
    strip: {
      endpoints: { total: endpoints, unhealthy, stale, trend: trend.map((s) => s.value.total) },
      signals: { label: series.label, total: series.total, hourly: series.hourly.slice(-24), lastHour: series.lastHour },
      health: { average: healthN ? Math.round(healthSum / healthN) : null, tenants: healthN },
      cases: { open: board.open, bySeverity: board.bySeverity, oldestMs: wall.oldest?.ageMs ?? null, overTarget: board.overTarget },
      needAction,
      smime,
    },
    freshness: summariseFreshness(provider.freshness(scope.tenants.map((t) => t.id), datasets), now),
  };
}

/**
 * The S/MIME tile on the overview strip: the soonest expiry ahead across the
 * tenants in scope that use S/MIME, or null when none does (the tile hides).
 */
function smimeStrip(provider: Provider, scope: Scope, settings: Settings, now: number) {
  let tenants = 0;
  let atRisk = 0;
  let expiring = 0;
  let expired = 0;
  let soonest: { days: number; kind: "ca" | "cert"; tenantName: string | null } | null = null;
  let caExpiresAt: string | null = null;
  for (const t of scope.tenants) {
    const st = smimeStatus(provider.get("smime", t.id), now);
    if (!st?.inUse) continue;
    tenants++;
    expiring += st.expiring + (st.caDays !== null && st.caDays >= 0 && st.caDays <= 30 ? 1 : 0);
    expired += st.expired;
    if (st.level) atRisk++;
    if (!scope.all) caExpiresAt = st.caExpiresAt;
    if (st.days !== null && st.kind && (!soonest || st.days < soonest.days)) soonest = { days: st.days, kind: st.kind, tenantName: scope.all ? displayName(settings, t.name) : null };
  }
  if (!tenants) return null;
  return { tenants, atRisk, expiring, expired, soonest, caExpiresAt, level: soonest ? (soonest.days <= 7 ? "critical" : "warning") : null };
}

export function buildNow(provider: Provider, scope: Scope, settings: Settings, now = Date.now()) {
  const datasets: DatasetName[] = ["cases", "detections", "alerts", "endpoints"];
  provider.focus(datasets, scope.all ? [] : scope.tenants.map((t) => t.id));
  const detections = collect<DetectionSet>(provider, "detections", scope);
  const alerts = collect<AlertSet>(provider, "alerts", scope);
  const series = signalSeries(detections.length ? detections : null, alerts.length ? alerts : null, now, 24);
  const wall = nowWall(caseInputs(provider, scope, settings), series, settings.targets, now);
  return {
    view: "now",
    ...header(provider, scope, settings),
    targets: settings.targets,
    wall,
    freshness: summariseFreshness(provider.freshness(scope.tenants.map((t) => t.id), datasets), now),
  };
}

export function buildCases(provider: Provider, scope: Scope, settings: Settings, managed: "all" | "mdr" | "self", now = Date.now()) {
  provider.focus(["cases"], scope.all ? [] : scope.tenants.map((t) => t.id));
  const board = caseBoard(caseInputs(provider, scope, settings), settings.targets, now, managed);
  return {
    view: "cases",
    ...header(provider, scope, settings),
    managed,
    targets: settings.targets,
    board,
    freshness: summariseFreshness(provider.freshness(scope.tenants.map((t) => t.id), ["cases"]), now),
  };
}

export function buildEndpoints(provider: Provider, scope: Scope, settings: Settings, platform: string | null, now = Date.now()) {
  const single = !scope.all;
  const datasets: DatasetName[] = single ? ["endpoints", "egress"] : ["endpoints"];
  provider.focus(datasets, single ? scope.tenants.map((t) => t.id) : []);
  const list = scope.tenants.flatMap((t) => (provider.get("endpoints", t.id) ?? []).map((e) => ({ ...e, tenantName: scope.all ? displayName(settings, t.name) : undefined })));
  const egress = single && scope.tenants[0] ? provider.get("egress", scope.tenants[0].id) : null;
  let summary: EndpointSummary = endpointSummary(list, now, egress, platform);
  if (settings.privacy) {
    summary = { ...summary, worst: summary.worst.map((w) => ({ ...w, hostname: maskName("Device", w.hostname) })) };
  }
  const platforms = endpointSummary(list, now).byPlatform;
  const trend = single && scope.tenants[0] ? provider.snapshots<{ total: number; bad: number; suspicious: number; stale7: number; tamperOff: number }>("endpoints", scope.tenants[0].id, now - 30 * 86_400_000).map((s) => ({ at: s.takenAt, ...s.value })) : [];
  return {
    view: "endpoints",
    ...header(provider, scope, settings),
    platform,
    platforms,
    summary,
    trend,
    egressNotes: egress?.notes ?? [],
    mapAvailable: single,
    freshness: summariseFreshness(provider.freshness(scope.tenants.map((t) => t.id), datasets), now),
  };
}

function tileFor(provider: Provider, t: TenantRecord, settings: Settings, now: number) {
  const fetched = [provider.fetchedAt("cases", t.id), provider.fetchedAt("endpoints", t.id), provider.fetchedAt("health", t.id)].filter((x): x is number => x !== null);
  const rows = provider.freshness([t.id], ["cases", "endpoints", "health"]);
  const errors = rows.filter((f) => f.lastError && !f.noAccess).length;
  const noAccess = rows.filter((f) => f.noAccess).length;
  const tile = tenantTile(
    {
      tenant: t,
      generation: provider.get("generation", t.id)?.generation ?? null,
      cases: provider.get("cases", t.id),
      endpoints: provider.get("endpoints", t.id),
      health: provider.get("health", t.id),
      licences: provider.get("licences", t.id),
      alerts: provider.get("alerts", t.id),
      smime: provider.get("smime", t.id),
      aiDefense: provider.get("aidefense", t.id),
      aiNoAccess: provider.freshness([t.id], ["aidefense"]).some((f) => f.noAccess),
      fetchedAt: fetched.length ? Math.min(...fetched) : null,
      errors,
      noAccess,
    },
    now,
  );
  return settings.privacy ? { ...tile, name: maskName("Tenant", tile.name) } : tile;
}

export function buildMsp(provider: Provider, settings: Settings, now = Date.now()) {
  provider.focus(["cases", "endpoints", "health", "alerts", "licences"], []);
  const tiles = provider.tenants.map((t) => tileFor(provider, t, settings, now));
  const wall = mspWall(tiles);
  provider.setFastTenants(wall.tiles.filter((t) => t.state !== "pending").slice(0, 8).map((t) => t.id));
  const ids = provider.tenants.map((t) => t.id);
  return {
    view: "msp",
    tenantCount: provider.tenants.length,
    tenantsOverCap: provider.tenantsOverCap,
    progress: provider.progress(),
    ...wall,
    freshness: summariseFreshness(provider.freshness(ids, ["generation", "cases", "endpoints", "health", "alerts", "licences", "smime", "aidefense"]), now),
  };
}

/** Search GraphQL runs on Fusion tenants only; a Classic tenant has nothing for these screens. */
function fusionTenants(provider: Provider, scope: Scope) {
  const known = scope.tenants.filter((t) => provider.get("generation", t.id));
  const fusion = scope.tenants.filter((t) => provider.get("generation", t.id)?.generation === "fusion");
  return { fusion, classic: known.length - fusion.length, unknown: scope.tenants.length - known.length };
}

/** X10 and X11: the sign-in map and sign-ins without MFA. */
export function buildSignins(provider: Provider, scope: Scope, settings: Settings, now = Date.now()) {
  const datasets: DatasetName[] = ["signins", "mfa"];
  // Only a screen showing one tenant speeds Search up; all tenants read what the daily refresh left.
  provider.focus(datasets, scope.all ? [] : scope.tenants.map((t) => t.id));
  const gens = fusionTenants(provider, scope);
  const model = signinView(
    gens.fusion.map((t) => ({ tenantName: scope.all ? displayName(settings, t.name) : undefined, signins: provider.get("signins", t.id), mfa: provider.get("mfa", t.id) })),
    settings.privacy,
  );
  return {
    view: "signins",
    ...header(provider, scope, settings),
    tenants: { fusion: gens.fusion.length, classic: gens.classic, unknown: gens.unknown },
    model,
    freshness: summariseFreshness(provider.freshness(gens.fusion.map((t) => t.id), datasets), now),
  };
}

/** N3: event volume and last event per data source. */
export function buildSources(provider: Provider, scope: Scope, settings: Settings, now = Date.now()) {
  const datasets: DatasetName[] = ["sources"];
  provider.focus(datasets, scope.all ? [] : scope.tenants.map((t) => t.id));
  const gens = fusionTenants(provider, scope);
  const model = sourcesView(gens.fusion.map((t) => ({ tenantName: scope.all ? displayName(settings, t.name) : undefined, set: provider.get("sources", t.id) })), now);
  return {
    view: "sources",
    ...header(provider, scope, settings),
    tenants: { fusion: gens.fusion.length, classic: gens.classic, unknown: gens.unknown },
    model,
    freshness: summariseFreshness(provider.freshness(gens.fusion.map((t) => t.id), datasets), now),
  };
}

/** The AI usage board: AI Defense activity, apps and users for one tenant or every tenant. */
export function buildAi(provider: Provider, scope: Scope, settings: Settings, now = Date.now()) {
  const datasets: DatasetName[] = ["aidefense"];
  provider.focus(datasets, scope.all ? [] : scope.tenants.map((t) => t.id));
  const fresh = provider.freshness(scope.tenants.map((t) => t.id), datasets);
  const denied = new Set(fresh.filter((f) => f.noAccess).map((f) => f.tenantId));
  const model = aiDefenseView(
    scope.tenants.map((t) => ({ tenantId: t.id, tenantName: scope.all ? displayName(settings, t.name) : undefined, record: provider.get("aidefense", t.id), noAccess: denied.has(t.id) })),
    settings.privacy,
  );
  return {
    view: "ai",
    ...header(provider, scope, settings),
    model,
    freshness: summariseFreshness(fresh, now),
  };
}

const SEARCH_SCREENS = new Set(["signins", "sources"]);

/** The screens to offer: the Search screens drop out once every tenant is known to be Classic. */
export function screensFor(provider: Provider): string[] {
  const views = provider.context?.views ?? [];
  const gens = provider.tenants.map((t) => provider.get("generation", t.id)?.generation ?? null);
  const allClassic = gens.length > 0 && gens.every((g) => g === "classic");
  return allClassic ? views.filter((v) => !SEARCH_SCREENS.has(v)) : views;
}

export function tenantList(provider: Provider, settings: Settings) {
  return provider.tenants.map((t) => ({
    id: t.id,
    name: displayName(settings, t.name),
    region: t.dataRegion,
    generation: provider.get("generation", t.id)?.generation ?? null,
  }));
}
