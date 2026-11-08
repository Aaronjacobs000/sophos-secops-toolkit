/**
 * The calls behind each cached dataset. Every one is a read: GETs, a Data
 * Lake SELECT run, an allowlisted GraphQL query, or a Search GraphQL search
 * (started by one of the two search mutations the guard allows as exact
 * documents; a search changes no tenant setting). The read-only guard in
 * sophos/guard.ts enforces that whatever this file asks for.
 */

import { LIST_CASES, TENANT_XDR_OWNERSHIP } from "../vendor/sophos-core/fusion/queries/cases.js";
import {
  buildCasesQl,
  legacyCaseToFusion,
  type FusionCasesResponse,
  type FusionTenantXdrOwnershipResponse,
  type LegacyCasePage,
  type SophosCore,
} from "../vendor/sophos-core/index.js";
import { SophosApiRequestError, isTenantNotOnFusion } from "../vendor/sophos-core/index.js";
import { mapAlert, mapCase, mapDetection, mapEndpoint, mapGeneration, mapHealth, mapLicence, mapSmimeCa, mapSmimeUsers } from "../mappers/api.js";
import { mfaSet, mfaSources, mfaUsersQl, mfaQl, parseMfaRows, searchMeta, signinSet, signinsQl, sourceSet, sourcesQl } from "../mappers/search.js";
import type { SearchRun, SearchRunOptions } from "../vendor/sophos-core/index.js";
import { aiFlowSlots, applyAiDefenseFlow, hasAiData, mapAiDefenseDetail, mapAiDefenseOverview, mapAiDefensePolicies, unavailableAiDefense } from "../mappers/ai-defense.js";
import type {
  AiDefenseRecord,
  AlertSet,
  CaseRecord,
  CaseSet,
  DetectionSet,
  EgressSet,
  EndpointRecord,
  GenerationRecord,
  GeoPoint,
  HealthRecord,
  LicenceRecord,
  MfaSet,
  SigninSet,
  SmimeCert,
  SmimeRecord,
  SourceSet,
} from "./types.js";
import { isPublicIp, lookupIp } from "../services/geoip.js";

const DAY = 86_400_000;

export async function fetchGeneration(core: SophosCore, tenantId: string): Promise<GenerationRecord> {
  try {
    const { data } = await core.fusion.query<FusionTenantXdrOwnershipResponse>(tenantId, TENANT_XDR_OWNERSHIP, { id: tenantId });
    const value = data.tenant?.centralTenant?.xdrOwnership ?? null;
    return { generation: mapGeneration(value), xdrOwnership: value };
  } catch (error) {
    // Fusion answers 503 "tenant ... not found or not accessible" for a tenant
    // it does not hold; only the Classic APIs can serve that tenant.
    if (isTenantNotOnFusion(error)) return { generation: "classic", xdrOwnership: null };
    return { generation: "unknown", xdrOwnership: null };
  }
}

/** Every endpoint, 500 a page, trimmed to what the screens use. */
export async function fetchEndpoints(core: SophosCore, tenantId: string, maxPages = 40): Promise<EndpointRecord[]> {
  const out: EndpointRecord[] = [];
  let key: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const result = await core.endpoints.search(tenantId, { pageSize: 500, pageFromKey: key });
    for (const raw of result.items) {
      const mapped = mapEndpoint(raw);
      if (mapped) out.push(mapped);
    }
    if (!result.nextKey) break;
    key = result.nextKey;
  }
  return out;
}

async function listV2(core: SophosCore, tenantId: string, query: string, maxPages: number): Promise<{ cases: CaseRecord[]; truncated: boolean; warnings: string[] }> {
  const cases: CaseRecord[] = [];
  const warnings: string[] = [];
  let after: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const pagination = after ? { cursor: { first: 100, after } } : { offset: { page: 1, perPage: 100 } };
    const { data, warnings: w } = await core.fusion.query<FusionCasesResponse>(tenantId, LIST_CASES, { arguments: { query, pagination } });
    warnings.push(...w);
    for (const raw of data.cases.cases) {
      const mapped = mapCase(raw, "v2");
      if (mapped) cases.push(mapped);
    }
    if (!data.cases.pageInfo.hasNextPage || !data.cases.pageInfo.endCursor) return { cases, truncated: false, warnings };
    after = data.cases.pageInfo.endCursor;
  }
  return { cases, truncated: true, warnings };
}

async function listV1(core: SophosCore, tenantId: string, params: Record<string, string>, maxPages: number): Promise<{ cases: CaseRecord[]; truncated: boolean }> {
  const cases: CaseRecord[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const data: LegacyCasePage = await core.legacyCases.list(tenantId, { ...params, page: String(page), pageSize: "50" });
    for (const item of data.items ?? []) {
      const mapped = mapCase(legacyCaseToFusion(item), "v1");
      if (mapped) cases.push(mapped);
    }
    const total = data.pages?.total ?? page;
    if ((data.items ?? []).length < 50 || page >= total) return { cases, truncated: false };
  }
  return { cases, truncated: true };
}

/**
 * Open cases plus the cases closed in the last 30 days, from whichever API
 * holds the tenant's cases: Cases v2 (GraphQL) for a Fusion tenant, cases v1
 * (REST) for a tenant Sophos Central still owns.
 */
export async function fetchCases(core: SophosCore, tenantId: string, generation: GenerationRecord, now = Date.now()): Promise<CaseSet> {
  const since = new Date(now - 30 * DAY).toISOString();
  if (generation.generation !== "classic") {
    try {
      const open = await listV2(core, tenantId, buildCasesQl({ openOnly: true }) ?? "closedAt is null", 10);
      let closed: CaseRecord[] = [];
      const warnings = [...open.warnings];
      try {
        closed = (await listV2(core, tenantId, `closedAt >= '${since}'`, 3)).cases;
      } catch {
        // The cases search may not filter on closedAt; fall back to recently updated, closed client side.
        closed = (await listV2(core, tenantId, buildCasesQl({ updatedAfter: since }) ?? "", 3)).cases.filter((c) => c.closed);
        warnings.push("Closed cases are those updated in the last 30 days.");
      }
      if (open.cases.length > 0 || closed.length > 0 || generation.generation === "fusion") {
        return { api: "v2", open: open.cases.filter((c) => !c.closed), recentClosed: closed.filter((c) => c.closed), truncated: open.truncated, warnings };
      }
    } catch (error) {
      if (generation.generation === "fusion") throw error;
    }
  }
  try {
    const open = await listV1(core, tenantId, { status: "new,investigating,onHold,actionRequired", sort: "createdAt:desc" }, 10);
    const closed = await listV1(core, tenantId, { status: "resolved", sort: "createdAt:desc", createdAfter: since }, 2);
    return {
      api: "v1",
      open: open.cases.filter((c) => !c.closed),
      recentClosed: closed.cases.filter((c) => c.closed && c.closedAt && Date.parse(c.closedAt) >= now - 30 * DAY),
      truncated: open.truncated,
      warnings: ["Classic cases API: resolved cases are those created in the last 30 days."],
    };
  } catch (error) {
    if (error instanceof SophosApiRequestError && error.status === 403 && /not allowed to access cases/i.test(error.message)) {
      return { api: "none", open: [], recentClosed: [], truncated: false, warnings: ["This tenant has no cases (no XDR or MDR licence)."] };
    }
    throw error;
  }
}

export const DETECTION_SEARCH_DOC = `query ToolkitDetectionSearch($in: SearchRequestInput!) {
  detectionSearch(in: $in) {
    status
    reason
    alerts {
      total_results
      next_offset
      list {
        id
        status
        sensor_types
        attack_technique_ids
        metadata {
          severity
          created_at { seconds }
          creator { detector { detector_name } }
        }
      }
    }
  }
}`;

export const DETECTION_COUNT_DOC = `query ToolkitDetectionCount($in: AlertsCountByTenantInput!) {
  detectionCountByTenant(in: $in) {
    items { count tenant { id } }
  }
}`;

interface DetectionSearchResponse {
  detectionSearch: {
    status?: string;
    reason?: string;
    alerts?: { total_results?: number; next_offset?: number; list?: unknown[] } | null;
  } | null;
}

interface DetectionCountResponse {
  detectionCountByTenant: { items?: Array<{ count: number; tenant?: { id?: string } }> } | null;
}

/**
 * Fusion detections for the last `hours`, newest first, up to `cap` in one
 * search (the API serves up to 10,000 a request), plus the 30-day count.
 * When the window holds more than `cap`, `coveredFrom` says how far back the
 * records reach, so the hourly chart only claims the hours it has.
 */
export async function fetchDetections(core: SophosCore, tenantId: string, hours = 168, cap = 3000): Promise<DetectionSet> {
  const { data } = await core.fusion.query<DetectionSearchResponse>(tenantId, DETECTION_SEARCH_DOC, {
    in: { cql_query: `from alert severity >= 0 EARLIEST=-${hours}h`, limit: cap, offset: 0 },
  });
  const alerts = data.detectionSearch?.alerts;
  const items = (alerts?.list ?? []).map(mapDetection).filter((d): d is NonNullable<typeof d> => !!d);
  items.sort((a, b) => b.createdAt - a.createdAt);
  const total = Math.max(alerts?.total_results ?? 0, items.length);
  let count30d: number | null = null;
  try {
    const { data: counted } = await core.fusion.query<DetectionCountResponse>(tenantId, DETECTION_COUNT_DOC, { in: { ql_query: "from alert EARLIEST=-30d" } });
    const rows = counted.detectionCountByTenant?.items ?? [];
    const row = rows.find((i) => i.tenant?.id === tenantId) ?? rows[0];
    count30d = row ? row.count : 0;
  } catch {
    count30d = null;
  }
  const sampled = total > items.length;
  return { windowHours: hours, total, items, sampled, coveredFrom: sampled && items.length ? items[items.length - 1]!.createdAt : null, count30d };
}

/** Central product alerts (Common API) for the last `hours`, newest first, one page of up to 1,000. */
export async function fetchAlerts(core: SophosCore, tenantId: string, hours = 168, now = Date.now()): Promise<AlertSet> {
  const page = await core.alerts.list(tenantId, { from: new Date(now - hours * 3_600_000).toISOString(), sort: "raisedAt:desc", pageSize: 1000, pageTotal: true });
  const items = page.items.map(mapAlert).filter((a): a is NonNullable<typeof a> => !!a);
  return { sinceHours: hours, total: page.total ?? items.length, items };
}

export async function fetchHealth(core: SophosCore, tenantId: string): Promise<HealthRecord> {
  return mapHealth(await core.rest.tenantRequest(tenantId, "/account-health-check/v1/health-check"));
}

export async function fetchLicences(core: SophosCore, tenantId: string): Promise<LicenceRecord[]> {
  const data = await core.rest.globalRequest<{ licenses?: unknown[]; items?: unknown[] }>("/licenses/v1/licenses", { headers: { "X-Tenant-ID": tenantId } });
  return (data.licenses ?? data.items ?? []).map(mapLicence).filter((l): l is LicenceRecord => !!l);
}

interface XdrRun {
  id: string;
  status?: string;
  result?: string;
}

/** Runs one Data Lake SELECT through the XDR Query API and returns up to `maxRows` rows. */
export async function runXdrQuery(
  core: SophosCore,
  tenantId: string,
  sql: string,
  windowHours: number,
  options: { maxRows?: number; timeoutMs?: number; pollMs?: number; now?: number } = {},
): Promise<{ rows: Record<string, unknown>[]; result: string }> {
  const now = options.now ?? Date.now();
  const run = await core.rest.tenantRequest<XdrRun>(tenantId, "/xdr-query/v1/queries/runs", {
    method: "POST",
    // A retried POST after a timeout or 5xx would start a second run of the same query.
    idempotent: false,
    body: { adHocQuery: { template: sql }, from: new Date(now - windowHours * 3_600_000).toISOString(), to: new Date(now).toISOString() },
  });
  const deadline = Date.now() + (options.timeoutMs ?? 90_000);
  let state = run;
  while (state.status !== "finished") {
    if (Date.now() > deadline) return { rows: [], result: "timedOut" };
    await new Promise((r) => setTimeout(r, options.pollMs ?? 2500));
    state = await core.rest.tenantRequest<XdrRun>(tenantId, `/xdr-query/v1/queries/runs/${encodeURIComponent(run.id)}`);
  }
  if (state.result !== "succeeded") return { rows: [], result: state.result ?? "failed" };
  const rows: Record<string, unknown>[] = [];
  const maxRows = options.maxRows ?? 4000;
  // Results page by number (pages.total), 2,000 rows a page.
  for (let page = 1; page <= 10 && rows.length < maxRows; page++) {
    const data = await core.rest.tenantRequest<{ items?: Record<string, unknown>[]; pages?: { total?: number; nextKey?: string } }>(
      tenantId,
      `/xdr-query/v1/queries/runs/${encodeURIComponent(run.id)}/results`,
      { params: { pageSize: "2000", page: String(page) } },
    );
    rows.push(...(data.items ?? []));
    if ((data.items ?? []).length < 2000 || page >= (data.pages?.total ?? page)) break;
  }
  return { rows: rows.slice(0, maxRows), result: "succeeded" };
}

export const EGRESS_SQL = `SELECT meta_hostname, meta_public_ip, MAX(calendar_time) AS last_seen
FROM xdr_data
WHERE meta_public_ip IS NOT NULL AND meta_public_ip <> ''
GROUP BY meta_hostname, meta_public_ip`;

export const EGRESS_GEO_SQL = `SELECT meta_public_ip, meta_public_ip_city, meta_public_ip_country, meta_public_ip_latitude, meta_public_ip_longitude
FROM xdr_ioc_view
WHERE meta_public_ip_latitude IS NOT NULL
GROUP BY meta_public_ip, meta_public_ip_city, meta_public_ip_country, meta_public_ip_latitude, meta_public_ip_longitude`;

/**
 * Each device's latest public egress IP from the Data Lake, placed by Sophos's
 * own IP geolocation where xdr_ioc_view has it, then by the local DB-IP file
 * when one is installed. Egress is where traffic leaves, not where the device is.
 */
export async function fetchEgress(core: SophosCore, tenantId: string): Promise<EgressSet> {
  const notes: string[] = [];
  const ips = await runXdrQuery(core, tenantId, EGRESS_SQL, 24 * 30, { maxRows: 8000 });
  if (ips.result !== "succeeded") notes.push(`Data Lake egress query ${ips.result}.`);
  const latest = new Map<string, { ip: string; seen: string }>();
  for (const row of ips.rows) {
    const host = typeof row.meta_hostname === "string" ? row.meta_hostname : null;
    const ip = typeof row.meta_public_ip === "string" ? row.meta_public_ip : null;
    const seen = String(row.last_seen ?? "");
    if (!host || !ip) continue;
    const prev = latest.get(host.toLowerCase());
    if (!prev || seen > prev.seen) latest.set(host.toLowerCase(), { ip, seen });
  }
  const hosts = [...latest.entries()].map(([hostname, v]) => ({ hostname, ip: v.ip }));
  const geo: EgressSet["geo"] = {};
  const geoRows = await runXdrQuery(core, tenantId, EGRESS_GEO_SQL, 24 * 30, { maxRows: 4000 });
  if (geoRows.result !== "succeeded") notes.push(`Data Lake geo query ${geoRows.result}.`);
  for (const row of geoRows.rows) {
    const ip = typeof row.meta_public_ip === "string" ? row.meta_public_ip : null;
    const lat = Number(row.meta_public_ip_latitude);
    const lon = Number(row.meta_public_ip_longitude);
    if (!ip || !Number.isFinite(lat) || !Number.isFinite(lon)) continue;
    geo[ip] = { city: typeof row.meta_public_ip_city === "string" ? row.meta_public_ip_city : null, country: typeof row.meta_public_ip_country === "string" ? row.meta_public_ip_country : null, lat, lon, source: "sophos" };
  }
  const unplaced: string[] = [];
  for (const { ip } of hosts) {
    if (geo[ip]) continue;
    const found = await lookupIp(ip);
    if (found) geo[ip] = found;
    else if (!unplaced.includes(ip)) unplaced.push(ip);
  }
  return { hosts, geo, unplaced, notes };
}

// ---------------------------------------------------------------- Search GraphQL (X10, X11, N3)

/** The scheduler's settings for a Search GraphQL run: reuse a matching search, 5 s polls, a 150 s deadline. */
export const SEARCH_RUN: SearchRunOptions = { reuse: true, pollMs: 5_000, deadlineMs: 150_000, maxRows: 5_000, partial: "accept" };

type Window = { start: number; end: number };

/** X10: sign-ins over the window by source IP, result, failure reason, MFA and source, with each public IP placed by DB-IP. */
export async function fetchSignins(core: SophosCore, tenantId: string, window: Window, now = Date.now(), options: SearchRunOptions = SEARCH_RUN): Promise<SigninSet> {
  const run = await core.search.run(tenantId, signinsQl(window), options);
  const geo: Record<string, GeoPoint> = {};
  const ips = new Set<string>();
  for (const row of run.rows) if (typeof row.source_address === "string" && isPublicIp(row.source_address)) ips.add(row.source_address);
  for (const ip of ips) {
    const found = await lookupIp(ip);
    if (found) geo[ip] = found;
  }
  return signinSet({ values: run.rows, window, geo, isPublic: isPublicIp, meta: searchMeta([run], now) });
}

/** X11: successful sign-ins by source, MFA, app and OS; then the top users without MFA from the sources that report it. */
export async function fetchMfa(core: SophosCore, tenantId: string, window: Window, now = Date.now(), options: SearchRunOptions = SEARCH_RUN): Promise<MfaSet> {
  const runs: SearchRun[] = [await core.search.run(tenantId, mfaQl(window), options)];
  const aware = [...mfaSources(parseMfaRows(runs[0]!.rows))].sort();
  const usersQl = mfaUsersQl(window, aware);
  let userRows: Array<Record<string, unknown>> = [];
  let usersTruncated = false;
  // No identity source reports MFA: there are no users to list, and no reason to run the second search.
  if (usersQl) {
    const users = await core.search.run(tenantId, usersQl, { ...options, maxRows: 2_000 });
    runs.push(users);
    userRows = users.rows;
    usersTruncated = users.truncated;
  }
  return mfaSet({ values: runs[0]!.rows, userValues: userRows, usersTruncated, window, meta: searchMeta(runs, now) });
}

/** N3: event count and newest event per data source, schema and day across the event schemas. */
export async function fetchSources(core: SophosCore, tenantId: string, window: Window, previous: SourceSet | null, now = Date.now(), options: SearchRunOptions = SEARCH_RUN): Promise<SourceSet> {
  const run = await core.search.run(tenantId, sourcesQl(window), options);
  return sourceSet({ values: run.rows, window, now, previous, meta: searchMeta([run], now) });
}

// ---------------------------------------------------------------- S/MIME (Email API, GETs only)

const SMIME_PAGES = 10;

/**
 * The internal CA and the internal user certificates that expire within 30
 * days (certExpiryBefore). A tenant with no CA answers 404; a tenant or
 * credential without the Email API answers 403, which is kept as "not
 * available" for a day rather than retried.
 */
export async function fetchSmime(core: SophosCore, tenantId: string, now = Date.now()): Promise<SmimeRecord> {
  const checkedBefore = new Date(now + 30 * DAY).toISOString().slice(0, 10);
  const unavailable = (status: number): SmimeRecord => ({ available: false, note: `S/MIME API answered HTTP ${status}.`, ca: null, expiring: [], expiringTruncated: false, checkedBefore });
  let ca: SmimeRecord["ca"] = null;
  try {
    ca = mapSmimeCa(await core.rest.tenantRequest(tenantId, "/email/v1/smime/ca/internal"));
  } catch (error) {
    if (error instanceof SophosApiRequestError && (error.status === 403 || error.status === 401)) return unavailable(error.status);
    if (!(error instanceof SophosApiRequestError && error.status === 404)) throw error;
  }
  const expiring: SmimeCert[] = [];
  let key: string | undefined;
  let truncated = false;
  for (let page = 0; ; page++) {
    if (page >= SMIME_PAGES) {
      truncated = true;
      break;
    }
    let data: { items?: unknown[]; pages?: { nextKey?: string } };
    try {
      data = await core.rest.tenantRequest(tenantId, "/email/v1/smime/users/internal", { params: { certExpiryBefore: checkedBefore, pageSize: "200", ...(key ? { pageFromKey: key } : {}) } });
    } catch (error) {
      if (error instanceof SophosApiRequestError && error.status === 404) break;
      if (error instanceof SophosApiRequestError && (error.status === 403 || error.status === 401)) return unavailable(error.status);
      throw error;
    }
    expiring.push(...mapSmimeUsers(data.items ?? []));
    key = data.pages?.nextKey || undefined;
    if (!key) break;
  }
  return { available: true, note: null, ca, expiring, expiringTruncated: truncated, checkedBefore };
}

// ---------------------------------------------------------------- AI Defense (Activity and Policy GraphQL, queries only)

/** A refusal: HTTP 403, or a GraphQL error that says the credential may not read AI Defense. */
function aiDenied(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Sophos Fusion API error 403\b/.test(message) || /\b(permission|forbidden|not authori[sz]ed|unauthori[sz]ed|access denied)\b/i.test(message);
}

function noAccessError(error: unknown): Error {
  const err = new Error(error instanceof Error ? error.message : String(error)) as Error & { noAccess: boolean };
  err.noAccess = true;
  return err;
}

/**
 * One tenant's AI Defense picture for the window. One call (settings,
 * inventory summary, blocked and warned counts by risk) decides the state; a
 * tenant without AI Defense stops there. A tenant with it gets the policy
 * counts (a separate permission, so a refusal there only leaves them out)
 * and, when anything happened in the window, the top apps and users and the
 * newest blocked or warned activity. When anything was blocked or warned, one
 * more call counts blocked and warned for each of the top 10 apps and users
 * (the AI usage flow); a failure there only leaves the flow unsplit. A tenant
 * Fusion does not hold (its 503) is a state, not an error; a refusal is
 * thrown as no access.
 */
export async function fetchAiDefense(core: SophosCore, tenantId: string, window: Window, _now = Date.now()): Promise<AiDefenseRecord> {
  const range = { startTime: new Date(window.start).toISOString(), endTime: new Date(window.end).toISOString() };
  let record: AiDefenseRecord;
  try {
    const { data, warnings } = await core.aiDefense.overview(tenantId, range);
    record = mapAiDefenseOverview(data, window, warnings);
  } catch (error) {
    if (isTenantNotOnFusion(error)) return unavailableAiDefense(window);
    if (aiDenied(error)) throw noAccessError(error);
    throw error;
  }
  if (record.state !== "active") return record;
  try {
    const { data, warnings } = await core.aiDefense.policies(tenantId);
    record.policies = mapAiDefensePolicies(data);
    record.warnings.push(...warnings);
  } catch (error) {
    record.warnings.push(`AI Defense policies could not be read: ${error instanceof Error ? error.message : String(error)}`.slice(0, 300));
  }
  record.calls++;
  if (!hasAiData(record)) return record;
  try {
    const { data, warnings } = await core.aiDefense.detail(tenantId, range);
    Object.assign(record, mapAiDefenseDetail(data));
    record.warnings.push(...warnings);
  } catch (error) {
    if (aiDenied(error)) throw noAccessError(error);
    throw error;
  }
  record.calls++;
  if (!record.activity.blocked && !record.activity.warned) {
    applyAiDefenseFlow(record, null);
    return record;
  }
  const slots = aiFlowSlots(record);
  if (!slots.apps.length && !slots.users.length) return record;
  try {
    const { data, warnings } = await core.aiDefense.flow(tenantId, range, slots.apps, slots.users);
    applyAiDefenseFlow(record, data);
    record.warnings.push(...warnings);
  } catch (error) {
    record.warnings.push(`AI Defense's split by app and user could not be read: ${error instanceof Error ? error.message : String(error)}`.slice(0, 300));
  }
  record.calls++;
  return record;
}
