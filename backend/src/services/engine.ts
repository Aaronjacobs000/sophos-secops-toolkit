/**
 * The engine for the active credential: who it is (context detection), which
 * tenants it reaches, and a scheduler that keeps every dataset in the
 * encrypted cache fresh within the rate limit. Browsers and wall screens only
 * ever read the cache; they never cause a Sophos call directly.
 *
 * Refresh tiers follow the build plan: what is on screen refreshes fast (cases
 * and detections every 5 minutes), everything else slowly (hourly for a
 * partner's other tenants, 2 hours for their endpoints, 6 hours for health,
 * daily for the tenant list, licences, API generation, egress IPs and S/MIME).
 *
 * AI Defense costs one call a day for a tenant without it, and up to three a
 * refresh (every 15 minutes on screen, hourly otherwise) for one with it.
 *
 * Search GraphQL jobs (sign-ins, MFA, data sources) cost at least three calls
 * a search, so they refresh every 15 minutes only while a screen shows that
 * tenant, and daily otherwise; the MSP wall's worst tenants don't speed them
 * up, and no more than two run at once.
 */

import { EventEmitter } from "node:events";
import { createSophosCore, SophosApiRequestError, type SophosCore, type SophosTenant } from "../vendor/sophos-core/index.js";
import { callPriority, createGuardedFetch, type CallRecord } from "../sophos/guard.js";
import { PRIORITY, RateLimiter } from "../sophos/rate-limiter.js";
import { detectContext, type AppContext } from "../sophos/context.js";
import { mapTenant } from "../mappers/api.js";
import type { EncryptedCache } from "../store/cache.js";
import type {
  AiDefenseRecord,
  AlertSet,
  CaseSet,
  CaseStatusSnapshot,
  DetectionSet,
  EgressSet,
  EndpointRecord,
  EndpointSnapshot,
  GenerationRecord,
  HealthRecord,
  LicenceRecord,
  MfaSet,
  SigninSet,
  SmimeRecord,
  SourceSet,
  TenantRecord,
} from "../data/types.js";
import {
  fetchAiDefense,
  fetchAlerts,
  fetchCases,
  fetchDetections,
  fetchEgress,
  fetchEndpoints,
  fetchGeneration,
  fetchHealth,
  fetchLicences,
  fetchMfa,
  fetchSignins,
  fetchSmime,
  fetchSources,
} from "../data/fetchers.js";
import { searchWindow } from "../mappers/search.js";
import { aiDefenseWindow } from "../mappers/ai-defense.js";
import { endpointSnapshot } from "../mappers/views.js";
import { log, maskSecrets, registerSecret } from "../log.js";

const MIN = 60_000;
const HOUR = 60 * MIN;

export type DatasetName = "generation" | "endpoints" | "cases" | "detections" | "alerts" | "health" | "licences" | "egress" | "signins" | "mfa" | "sources" | "smime" | "aidefense";

export interface DatasetValueMap {
  generation: GenerationRecord;
  endpoints: EndpointRecord[];
  cases: CaseSet;
  detections: DetectionSet;
  alerts: AlertSet;
  health: HealthRecord;
  licences: LicenceRecord[];
  egress: EgressSet;
  signins: SigninSet;
  mfa: MfaSet;
  sources: SourceSet;
  smime: SmimeRecord;
  aidefense: AiDefenseRecord;
}

interface DatasetSpec {
  name: DatasetName;
  base: number;
  interval(multi: boolean, fast: boolean, engine: Engine, tenantId: string): number;
  /** Only fetched while a screen asks for it. */
  onDemand?: boolean;
  /** A Search GraphQL job: fast only while a screen shows this tenant. */
  search?: boolean;
  applies(engine: Engine, tenantId: string): boolean;
  fetch(engine: Engine, tenantId: string): Promise<unknown>;
}

function searchInterval(_multi: boolean, onScreen: boolean): number {
  return onScreen ? 15 * MIN : 24 * HOUR;
}

function onFusion(e: Engine, t: string): boolean {
  return e.get("generation", t)?.generation === "fusion";
}

const SPECS: DatasetSpec[] = [
  { name: "generation", base: 0, interval: () => 24 * HOUR, applies: () => true, fetch: (e, t) => fetchGeneration(e.core, t) },
  {
    name: "cases",
    base: 1,
    interval: (multi, fast) => (!multi || fast ? 5 * MIN : HOUR),
    applies: (e, t) => e.has("generation", t),
    fetch: (e, t) => fetchCases(e.core, t, e.get("generation", t)!),
  },
  { name: "endpoints", base: 1, interval: (multi, fast) => (!multi || fast ? 30 * MIN : 2 * HOUR), applies: () => true, fetch: (e, t) => fetchEndpoints(e.core, t) },
  { name: "health", base: 2, interval: () => 6 * HOUR, applies: () => true, fetch: (e, t) => fetchHealth(e.core, t) },
  {
    name: "detections",
    base: 2,
    interval: (multi, fast) => (!multi ? 5 * MIN : fast ? 10 * MIN : HOUR),
    applies: (e, t) => e.get("generation", t)?.generation === "fusion",
    fetch: (e, t) => fetchDetections(e.core, t),
  },
  { name: "alerts", base: 3, interval: (multi, fast) => (!multi ? 5 * MIN : fast ? 10 * MIN : HOUR), applies: () => true, fetch: (e, t) => fetchAlerts(e.core, t) },
  { name: "licences", base: 4, interval: () => 24 * HOUR, applies: () => true, fetch: (e, t) => fetchLicences(e.core, t) },
  { name: "egress", base: 2, interval: () => 24 * HOUR, onDemand: true, applies: () => true, fetch: (e, t) => fetchEgress(e.core, t) },
  { name: "smime", base: 4, interval: () => 24 * HOUR, applies: () => true, fetch: (e, t) => fetchSmime(e.core, t) },
  // AI Defense: daily for a tenant without it (hourly while on screen); with it, like alerts.
  {
    name: "aidefense",
    base: 4,
    interval: (multi, fast, e, t) => ((e.get("aidefense", t)?.state ?? "active") !== "active" ? (fast ? HOUR : 24 * HOUR) : !multi || fast ? 15 * MIN : HOUR),
    applies: () => true,
    fetch: (e, t) => fetchAiDefense(e.core, t, aiDefenseWindow(Date.now())),
  },
  // Search GraphQL answers for Fusion tenants only.
  { name: "signins", base: 3, search: true, interval: searchInterval, applies: onFusion, fetch: (e, t) => fetchSignins(e.core, t, searchWindow(Date.now())) },
  { name: "mfa", base: 3, search: true, interval: searchInterval, applies: onFusion, fetch: (e, t) => fetchMfa(e.core, t, searchWindow(Date.now())) },
  { name: "sources", base: 4, search: true, interval: searchInterval, applies: onFusion, fetch: (e, t) => fetchSources(e.core, t, searchWindow(Date.now()), e.get("sources", t)) },
];

/** Most Search GraphQL jobs running at once, so polling never ties up the other refreshes. */
const MAX_SEARCH_JOBS = 2;

export interface JobState {
  running: boolean;
  lastAttempt: number;
  lastError: string | null;
  failures: number;
  retryAt: number;
  /** Sophos answered 403: the tenant has no licence or the credential no right for this data. */
  noAccess: boolean;
}

export interface Freshness {
  dataset: DatasetName;
  tenantId: string;
  fetchedAt: number | null;
  intervalMs: number;
  lastError: string | null;
  running: boolean;
  noAccess?: boolean;
}

const NO_ACCESS_RETRY_MS = 6 * HOUR;

export type EngineStatus = "starting" | "ready" | "auth-failed" | "error";

export interface EngineOptions {
  credentialId: string;
  label: string;
  clientId: string;
  clientSecret: string;
  cache: EncryptedCache;
  maxTenants?: number;
  excludeTenantIds?: string[];
  /** Tests pass a fake Sophos; the server passes nothing. */
  baseFetch?: Parameters<typeof createGuardedFetch>[0]["baseFetch"];
  limiter?: RateLimiter;
  tickMs?: number;
  concurrency?: number;
  /** False keeps the scheduler off (tests and the smoke script run datasets by hand). */
  autoSchedule?: boolean;
  /** First wait before trying a failed start again; doubles each time, to 5 minutes. */
  retryBaseMs?: number;
}

export class Engine extends EventEmitter {
  readonly kind = "live" as const;
  readonly credentialId: string;
  readonly label: string;
  readonly core: SophosCore;
  readonly limiter: RateLimiter;
  readonly cache: EncryptedCache;
  context: AppContext | null = null;
  tenants: TenantRecord[] = [];
  /** Tenants the credential reaches beyond the per-install cap. */
  tenantsOverCap = 0;
  status: EngineStatus = "starting";
  statusMessage = "";
  private jobs = new Map<string, JobState>();
  private focusTenants = new Map<string, number>();
  private focusDatasets = new Map<DatasetName, number>();
  private fastTenants = new Set<string>();
  private timer: NodeJS.Timeout | null = null;
  private budgetTimer: NodeJS.Timeout | null = null;
  private retryTimer: NodeJS.Timeout | null = null;
  private retries = 0;
  private readonly retryBaseMs: number;
  private stopped = false;
  private inFlight = 0;
  private searchInFlight = 0;
  private readonly concurrency: number;
  private readonly tickMs: number;
  private readonly autoSchedule: boolean;
  private readonly maxTenants: number;
  private readonly exclude: Set<string>;
  private calls: CallRecord[] = [];
  private downloadsAllowed = false;
  private tenantsLoadedAt = 0;
  readonly guardedFetch: ReturnType<typeof createGuardedFetch>;

  constructor(options: EngineOptions) {
    super();
    this.setMaxListeners(100);
    this.credentialId = options.credentialId;
    this.label = options.label;
    this.cache = options.cache;
    this.limiter = options.limiter ?? new RateLimiter();
    this.concurrency = options.concurrency ?? 4;
    this.tickMs = options.tickMs ?? 1000;
    this.autoSchedule = options.autoSchedule !== false;
    this.retryBaseMs = options.retryBaseMs ?? 15_000;
    this.maxTenants = options.maxTenants ?? (Number(process.env.SECOPS_MAX_TENANTS ?? 150) || 150);
    this.exclude = new Set((options.excludeTenantIds ?? (process.env.SECOPS_EXCLUDE_TENANTS ?? "").split(",")).map((s) => s.trim()).filter(Boolean));
    registerSecret(options.clientId);
    registerSecret(options.clientSecret);
    this.guardedFetch = createGuardedFetch({
      limiter: this.limiter,
      baseFetch: options.baseFetch,
      allowDownloads: () => this.downloadsAllowed,
      onCall: (record) => {
        this.calls.push(record);
        if (this.calls.length > 5000) this.calls.splice(0, this.calls.length - 5000);
      },
    });
    this.core = createSophosCore({ clientId: options.clientId, clientSecret: options.clientSecret, fetch: this.guardedFetch });
  }

  private key(dataset: string, tenantId: string): string {
    return `${this.credentialId}:${dataset}:${tenantId}`;
  }

  has(dataset: DatasetName, tenantId: string): boolean {
    return this.cache.get(this.key(dataset, tenantId)) !== null;
  }

  get<K extends DatasetName>(dataset: K, tenantId: string): DatasetValueMap[K] | null {
    return (this.cache.get<DatasetValueMap[K]>(this.key(dataset, tenantId))?.value ?? null) as DatasetValueMap[K] | null;
  }

  fetchedAt(dataset: DatasetName, tenantId: string): number | null {
    return this.cache.get(this.key(dataset, tenantId))?.fetchedAt ?? null;
  }

  snapshots<T>(name: string, tenantId: string, sinceMs: number): Array<{ takenAt: number; value: T }> {
    return this.cache.snapshots<T>(this.key(`snap-${name}`, tenantId), sinceMs);
  }

  /** whoami, then the tenant list for a partner or organization. */
  async start(): Promise<void> {
    // Calls made in the last hour before a restart still count against the hourly budget.
    const saved = this.cache.get<number[]>(this.key("budget", "calls"));
    if (saved) this.limiter.seedStamps(saved.value);
    this.budgetTimer = setInterval(() => this.saveBudget(), 30_000);
    this.budgetTimer.unref?.();
    await this.connect();
  }

  /**
   * One attempt at whoami and the tenant list. A failure other than a refused
   * credential (no network yet, a Sophos 5xx) tries again after 15 s, doubling
   * to at most 5 minutes, so a wall board that starts before its network
   * recovers by itself. Nothing carries on once the engine is stopped.
   */
  private async connect(): Promise<void> {
    this.retryTimer = null;
    try {
      const identity = await callPriority.run(PRIORITY.interactive, () => this.core.tenants.init());
      if (this.stopped) return;
      this.context = detectContext(identity);
      await this.loadTenants();
      if (this.stopped) return;
      this.tenantsLoadedAt = Date.now();
      this.status = "ready";
      this.statusMessage = "";
      this.retries = 0;
    } catch (err) {
      if (this.stopped) return;
      const message = maskSecrets(err instanceof Error ? err.message : String(err));
      this.status = /auth failed|401|invalid_client/i.test(message) ? "auth-failed" : "error";
      this.statusMessage = message;
      log.emit("error", "engine", `Could not start: ${message}`);
      if (this.status === "error" && this.autoSchedule) {
        const delay = Math.min(5 * 60_000, this.retryBaseMs * 2 ** this.retries++);
        this.retryTimer = setTimeout(() => void this.connect(), delay);
        this.retryTimer.unref?.();
      }
      this.emit("status");
      return;
    }
    this.emit("status");
    if (!this.autoSchedule) return;
    this.timer = setInterval(() => this.tick(), this.tickMs);
    this.timer.unref?.();
    this.tick();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    if (this.budgetTimer) clearInterval(this.budgetTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.timer = null;
    this.budgetTimer = null;
    this.retryTimer = null;
    this.saveBudget();
    this.removeAllListeners();
  }

  private saveBudget(): void {
    try {
      this.cache.put(this.key("budget", "calls"), this.limiter.exportStamps());
    } catch {
      // The cache may be closed or mid-wipe; the next save catches up.
    }
  }

  private async loadTenants(): Promise<void> {
    const ctx = this.context!;
    if (!ctx.multiTenant) {
      this.tenants = [{ id: ctx.id, name: this.label, apiHost: ctx.apiHost!, dataRegion: "", billingType: null, status: null, products: [], city: null, countryCode: null }];
      return;
    }
    // Listing every tenant takes one call per page and also tells the resolver each tenant's regional host.
    this.core.tenants.resetTenants();
    await callPriority.run(PRIORITY.interactive, () => this.core.tenants.loadTenants());
    const records = this.core.tenants
      .getTenantRecords()
      .map((t: SophosTenant) => mapTenant(t))
      .filter((t): t is TenantRecord => !!t)
      .sort((a, b) => a.name.localeCompare(b.name));
    this.cache.put(this.key("tenants", ctx.id), records);
    // SECOPS_EXCLUDE_TENANTS takes tenant IDs or ID prefixes.
    const excluded = (id: string) => [...this.exclude].some((x) => id === x || id.startsWith(x));
    const allowed = records.filter((t) => !excluded(t.id) && (t.status ?? "active") !== "deleted");
    this.tenantsOverCap = Math.max(0, allowed.length - this.maxTenants);
    this.tenants = allowed.slice(0, this.maxTenants);
  }

  /** Re-reads the tenant list once a day. */
  private async refreshTenants(): Promise<void> {
    if (!this.context?.multiTenant || Date.now() - this.tenantsLoadedAt < 24 * HOUR) return;
    this.tenantsLoadedAt = Date.now();
    try {
      await this.loadTenants();
      this.emit("update", { dataset: "tenants", tenantId: this.context.id });
    } catch (err) {
      log.emit("warn", "refresh", `tenant list: ${maskSecrets(err instanceof Error ? err.message : String(err))}`);
    }
  }

  tenant(id: string): TenantRecord | null {
    return this.tenants.find((t) => t.id === id) ?? null;
  }

  /** A screen is showing these datasets for these tenants: refresh them on the fast tier for two minutes. */
  focus(datasets: DatasetName[], tenantIds: string[]): void {
    const until = Date.now() + 2 * MIN;
    for (const d of datasets) this.focusDatasets.set(d, until);
    for (const t of tenantIds) this.focusTenants.set(t, until);
  }

  /** The partner tenants shown worst first get the fast tier too. */
  setFastTenants(ids: string[]): void {
    this.fastTenants = new Set(ids);
  }

  private isFocused(dataset: DatasetName, tenantId: string, now: number): boolean {
    return (this.focusDatasets.get(dataset) ?? 0) > now && (!this.context?.multiTenant || (this.focusTenants.get(tenantId) ?? 0) > now || this.fastTenants.has(tenantId));
  }

  /** A screen shows this dataset for this tenant now (the MSP wall's fast tenants don't count). */
  private isOnScreen(dataset: DatasetName, tenantId: string, now: number): boolean {
    return (this.focusDatasets.get(dataset) ?? 0) > now && (!this.context?.multiTenant || (this.focusTenants.get(tenantId) ?? 0) > now);
  }

  private jobState(key: string): JobState {
    let state = this.jobs.get(key);
    if (!state) {
      state = { running: false, lastAttempt: 0, lastError: null, failures: 0, retryAt: 0, noAccess: false };
      this.jobs.set(key, state);
    }
    return state;
  }

  intervalFor(spec: DatasetSpec, tenantId: string, now = Date.now()): number {
    const multi = !!this.context?.multiTenant;
    if (spec.search) return spec.interval(multi, this.isOnScreen(spec.name, tenantId, now), this, tenantId);
    const fast = !multi || this.isFocused(spec.name, tenantId, now) || this.fastTenants.has(tenantId);
    return spec.interval(multi, fast, this, tenantId);
  }

  /** Every applicable job that is due, most urgent first. */
  dueJobs(now = Date.now()): Array<{ spec: DatasetSpec; tenantId: string; priority: number; age: number }> {
    const due: Array<{ spec: DatasetSpec; tenantId: string; priority: number; age: number }> = [];
    for (const tenant of this.tenants) {
      for (const spec of SPECS) {
        const focused = spec.search ? this.isOnScreen(spec.name, tenant.id, now) : this.isFocused(spec.name, tenant.id, now);
        if (spec.onDemand && !focused) continue;
        if (!spec.applies(this, tenant.id)) continue;
        const key = this.key(spec.name, tenant.id);
        const state = this.jobState(key);
        if (state.running || state.retryAt > now) continue;
        const fetchedAt = this.cache.get(key)?.fetchedAt ?? 0;
        const age = now - fetchedAt;
        if (age < this.intervalFor(spec, tenant.id, now)) continue;
        due.push({ spec, tenantId: tenant.id, priority: (focused ? 0 : 10) + spec.base + (fetchedAt ? 5 : 0), age });
      }
    }
    return due.sort((a, b) => a.priority - b.priority || b.age - a.age);
  }

  private tick(): void {
    if (this.status !== "ready") return;
    void this.refreshTenants();
    const now = Date.now();
    if (this.inFlight >= this.concurrency) return;
    const due = this.dueJobs(now);
    let searches = this.searchInFlight;
    for (const job of due) {
      if (this.inFlight >= this.concurrency) break;
      if (job.spec.search) {
        if (searches >= MAX_SEARCH_JOBS) continue;
        searches++;
      }
      void this.run(job.spec, job.tenantId, job.priority < 10 ? PRIORITY.onScreen : PRIORITY.background);
    }
  }

  /** Runs one dataset refresh now (also used by the tests). */
  async run(spec: DatasetSpec, tenantId: string, priority: number = PRIORITY.background): Promise<void> {
    const key = this.key(spec.name, tenantId);
    const state = this.jobState(key);
    if (state.running) return;
    state.running = true;
    state.lastAttempt = Date.now();
    this.inFlight++;
    if (spec.search) this.searchInFlight++;
    try {
      const value = await callPriority.run(priority, () => spec.fetch(this, tenantId));
      this.cache.put(key, value);
      this.afterFetch(spec.name, tenantId, value);
      state.lastError = null;
      state.failures = 0;
      state.retryAt = 0;
      state.noAccess = false;
      this.emit("update", { dataset: spec.name, tenantId });
    } catch (err) {
      state.failures++;
      // A search the credential's role or the tenant may not run says so with noAccess.
      state.noAccess = (err instanceof SophosApiRequestError && err.status === 403) || (err as { noAccess?: unknown } | null)?.noAccess === true;
      state.lastError = state.noAccess
        ? "No access (HTTP 403): the tenant has no licence for this data, or the credential's role does not cover it."
        : maskSecrets(err instanceof Error ? err.message : String(err)).slice(0, 400);
      // A 403 will not change in minutes; look again in 6 hours.
      state.retryAt = Date.now() + (state.noAccess ? NO_ACCESS_RETRY_MS : Math.min(30 * MIN, MIN * 2 ** Math.min(state.failures - 1, 5)));
      log.emit("warn", "refresh", `${spec.name} for ${this.tenant(tenantId)?.name ?? tenantId}: ${state.noAccess ? "403 no access" : state.lastError}`);
      this.emit("update", { dataset: spec.name, tenantId, error: true });
    } finally {
      state.running = false;
      this.inFlight--;
      if (spec.search) this.searchInFlight--;
    }
  }

  async runNow(dataset: DatasetName, tenantId: string): Promise<void> {
    const spec = SPECS.find((s) => s.name === dataset);
    if (spec) await this.run(spec, tenantId, PRIORITY.interactive);
  }

  private afterFetch(dataset: DatasetName, tenantId: string, value: unknown): void {
    const now = Date.now();
    if (dataset === "endpoints") {
      const last = this.snapshots<EndpointSnapshot>("endpoints", tenantId, now - 20 * HOUR);
      if (last.length === 0) this.cache.snapshot<EndpointSnapshot>(this.key("snap-endpoints", tenantId), endpointSnapshot(value as EndpointRecord[], now), now);
    }
    if (dataset === "cases") {
      const set = value as CaseSet;
      const statuses: Record<string, string> = {};
      for (const c of [...set.open, ...set.recentClosed]) statuses[c.id] = c.closed ? "closed" : c.status;
      const last = this.snapshots<CaseStatusSnapshot>("cases", tenantId, now - 2 * HOUR).pop();
      const changed = !last || JSON.stringify(last.value.statuses) !== JSON.stringify(statuses);
      if (changed) this.cache.snapshot<CaseStatusSnapshot>(this.key("snap-cases", tenantId), { statuses }, now);
    }
  }

  freshness(tenantIds: string[], datasets: DatasetName[]): Freshness[] {
    const now = Date.now();
    const out: Freshness[] = [];
    for (const tenantId of tenantIds) {
      for (const dataset of datasets) {
        const spec = SPECS.find((s) => s.name === dataset)!;
        if (!spec.applies(this, tenantId) && dataset !== "cases") continue;
        const state = this.jobs.get(this.key(dataset, tenantId));
        out.push({
          dataset,
          tenantId,
          fetchedAt: this.fetchedAt(dataset, tenantId),
          intervalMs: this.intervalFor(spec, tenantId, now),
          lastError: state?.lastError ?? null,
          running: state?.running ?? false,
          noAccess: state?.noAccess ?? false,
        });
      }
    }
    return out;
  }

  budget(): ReturnType<RateLimiter["stats"]> & { total: number } {
    return { ...this.limiter.stats(), total: this.limiter.total };
  }

  /** Calls per minute over the last hour, for the budget meter and the scheduler log check. */
  callLog(): CallRecord[] {
    return [...this.calls];
  }

  /** Lets the guard reach the DB-IP host for the one download the person started. */
  async withDownloads<T>(fn: () => Promise<T>): Promise<T> {
    this.downloadsAllowed = true;
    try {
      return await fn();
    } finally {
      this.downloadsAllowed = false;
    }
  }

  progress(): { done: number; total: number } {
    let done = 0;
    // A tenant has answered once both datasets came back, or Sophos refused them.
    const answered = (dataset: DatasetName, id: string) => this.has(dataset, id) || !!this.jobs.get(this.key(dataset, id))?.lastError;
    for (const t of this.tenants) if (answered("endpoints", t.id) && answered("cases", t.id)) done++;
    return { done, total: this.tenants.length };
  }
}

export { SPECS as DATASET_SPECS };
