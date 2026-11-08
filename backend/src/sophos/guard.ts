/**
 * The read-only transport. Every Sophos call the toolkit makes goes through
 * the fetch this module builds, and it refuses anything that could change a
 * tenant before a byte leaves the machine:
 *
 *   - only Sophos API hosts (and, when the person asks for it, the DB-IP
 *     download host) are reachable at all;
 *   - GET and HEAD only, apart from these POSTs: the OAuth token request,
 *     starting an XDR Data Lake query run (a SELECT), a Fusion GraphQL query
 *     whose operation is on the allowlist below (or, for the reports' query
 *     and the AI Defense reads, that is the exact document below), and the
 *     two Search GraphQL mutations below;
 *   - those two mutations, CreateSearch and GetOrCreateSearch, start a search
 *     job (Sophos runs a QL query and keeps the rows for a while). They change
 *     no tenant setting, policy, case or device. They pass only as the exact
 *     documents below, character for character, with a QL text as their only
 *     input. A name or pattern match would let another mutation through, and
 *     some installs run on a Super Admin key behind this guard;
 *   - any other GraphQL document containing a mutation or subscription is
 *     refused, whatever its name;
 *   - a redirect is refused, not followed, from a Sophos host and from the
 *     DB-IP download host alike. These checks look only at the address a
 *     request starts at, and a followed 307 or 308 would send the same
 *     request, the token request's client secret included, to wherever the
 *     Location header points. The download carries no credential, but a
 *     followed redirect would fetch the GeoIP file from an address the path
 *     check never saw.
 *
 * It also takes a slot from the credential's rate limiter for every API call
 * and tells the limiter about a 429, so the whole credential backs off.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { refuseRedirect, type FetchLike } from "../vendor/sophos-core/index.js";
import { PRIORITY, type RateLimiter } from "./rate-limiter.js";

export class ReadOnlyViolationError extends Error {
  constructor(message: string) {
    super(`Blocked by the read-only guard: ${message}`);
    this.name = "ReadOnlyViolationError";
  }
}

/** GraphQL operations the toolkit may send. All are queries. */
export const ALLOWED_GRAPHQL_OPERATIONS = new Set([
  "FusionListCases",
  "FusionTenantXdrOwnership",
  "FusionCaseReferenceData",
  "ToolkitDetectionSearch",
  "ToolkitDetectionCount",
  "SearchStatus",
  "SearchResults",
]);

/**
 * Queries allowed only as these exact documents, compared character for
 * character: a document with the same operation name and any other text is
 * refused. The reports' copy (reports/live.ts) and the AI Defense client's
 * copies must be identical; tests check that. No AI Defense write (the
 * settings mutation, any policy change) is on any list, so none can pass.
 */
export const EXACT_GRAPHQL_QUERIES: ReadonlyMap<string, string> = new Map([
  [
    "ToolkitDetectionDetail",
    `query ToolkitDetectionDetail($in: SearchRequestInput!) {
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
          title
          severity
          created_at { seconds }
          creator { detector { detector_name } }
        }
        enrichment_details { mitre_attack_info { technique_id technique tactics } }
        source_entities { display_name subtype }
        target_entities { display_name subtype }
      }
    }
  }
}`,
  ],
  // The AI Defense reads. The client's copies are in
  // vendor/sophos-core/fusion/queries/ai-defense.ts.
  [
    "ToolkitAiDefenseOverview",
    `query ToolkitAiDefenseOverview($timeRange: SecureAITimeRange) {
  secureAITenantSettings {
    onboarding { status }
    licenseState
    licenseType
    licenseExpiryDate
    gracePeriodEndsAt
  }
  inventorySummary(filter: { timeRange: $timeRange }) {
    apps { totalApps criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk errorRisk trainsOnData unsanctionedCount }
    users { totalUsers criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk withViolations unsanctionedCount }
  }
  all: activities(filter: { timeRange: $timeRange }, first: 1) { totalCount }
  unsanctioned: activities(filter: { timeRange: $timeRange, isUnsanctioned: true }, first: 1) { totalCount }
  blocked: activities(filter: { timeRange: $timeRange, actions: [BLOCKED] }, first: 1) { totalCount }
  blockedCritical: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [CRITICAL] }, first: 1) { totalCount }
  blockedHigh: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [HIGH] }, first: 1) { totalCount }
  blockedMedium: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [MEDIUM] }, first: 1) { totalCount }
  blockedLow: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [LOW] }, first: 1) { totalCount }
  blockedInfo: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [INFO] }, first: 1) { totalCount }
  warned: activities(filter: { timeRange: $timeRange, actions: [WARNED] }, first: 1) { totalCount }
  warnedCritical: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [CRITICAL] }, first: 1) { totalCount }
  warnedHigh: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [HIGH] }, first: 1) { totalCount }
  warnedMedium: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [MEDIUM] }, first: 1) { totalCount }
  warnedLow: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [LOW] }, first: 1) { totalCount }
  warnedInfo: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [INFO] }, first: 1) { totalCount }
}`,
  ],
  [
    "ToolkitAiDefenseDetail",
    `query ToolkitAiDefenseDetail($timeRange: SecureAITimeRange) {
  appInventory(filter: { timeRange: $timeRange }, sort: { field: USAGE, order: DESC }, limit: 20, offset: 0) {
    totalCount
    entries { id name provider risk usage uniqueUsers lastSeen unsanctionedCount }
  }
  userInventory(filter: { timeRange: $timeRange }, sort: { field: USAGE, order: DESC }, limit: 20, offset: 0) {
    totalCount
    entries { id name risk appsUsed usage policyViolations topApp lastSeen unsanctionedCount }
  }
  activities(filter: { timeRange: $timeRange, actions: [BLOCKED, WARNED] }, sort: { field: TIMESTAMP, order: DESC }, first: 50) {
    totalCount
    activities {
      timestamp { startTime }
      actor { name type }
      application { id name }
      action
      policy
      device { name platform }
      risk
      aggregationCount
    }
  }
}`,
  ],
  [
    "ToolkitAiDefenseFlow",
    `query ToolkitAiDefenseFlow(
  $timeRange: SecureAITimeRange
  $app0: ID! $app1: ID! $app2: ID! $app3: ID! $app4: ID! $app5: ID! $app6: ID! $app7: ID! $app8: ID! $app9: ID!
  $user0: String! $user1: String! $user2: String! $user3: String! $user4: String! $user5: String! $user6: String! $user7: String! $user8: String! $user9: String!
) {
  app0Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app0], actions: [BLOCKED] }, first: 1) { totalCount }
  app0Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app0], actions: [WARNED] }, first: 1) { totalCount }
  app1Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app1], actions: [BLOCKED] }, first: 1) { totalCount }
  app1Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app1], actions: [WARNED] }, first: 1) { totalCount }
  app2Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app2], actions: [BLOCKED] }, first: 1) { totalCount }
  app2Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app2], actions: [WARNED] }, first: 1) { totalCount }
  app3Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app3], actions: [BLOCKED] }, first: 1) { totalCount }
  app3Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app3], actions: [WARNED] }, first: 1) { totalCount }
  app4Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app4], actions: [BLOCKED] }, first: 1) { totalCount }
  app4Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app4], actions: [WARNED] }, first: 1) { totalCount }
  app5Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app5], actions: [BLOCKED] }, first: 1) { totalCount }
  app5Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app5], actions: [WARNED] }, first: 1) { totalCount }
  app6Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app6], actions: [BLOCKED] }, first: 1) { totalCount }
  app6Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app6], actions: [WARNED] }, first: 1) { totalCount }
  app7Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app7], actions: [BLOCKED] }, first: 1) { totalCount }
  app7Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app7], actions: [WARNED] }, first: 1) { totalCount }
  app8Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app8], actions: [BLOCKED] }, first: 1) { totalCount }
  app8Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app8], actions: [WARNED] }, first: 1) { totalCount }
  app9Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app9], actions: [BLOCKED] }, first: 1) { totalCount }
  app9Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app9], actions: [WARNED] }, first: 1) { totalCount }
  user0Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user0], actions: [BLOCKED] }, first: 1) { totalCount }
  user0Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user0], actions: [WARNED] }, first: 1) { totalCount }
  user1Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user1], actions: [BLOCKED] }, first: 1) { totalCount }
  user1Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user1], actions: [WARNED] }, first: 1) { totalCount }
  user2Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user2], actions: [BLOCKED] }, first: 1) { totalCount }
  user2Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user2], actions: [WARNED] }, first: 1) { totalCount }
  user3Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user3], actions: [BLOCKED] }, first: 1) { totalCount }
  user3Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user3], actions: [WARNED] }, first: 1) { totalCount }
  user4Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user4], actions: [BLOCKED] }, first: 1) { totalCount }
  user4Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user4], actions: [WARNED] }, first: 1) { totalCount }
  user5Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user5], actions: [BLOCKED] }, first: 1) { totalCount }
  user5Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user5], actions: [WARNED] }, first: 1) { totalCount }
  user6Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user6], actions: [BLOCKED] }, first: 1) { totalCount }
  user6Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user6], actions: [WARNED] }, first: 1) { totalCount }
  user7Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user7], actions: [BLOCKED] }, first: 1) { totalCount }
  user7Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user7], actions: [WARNED] }, first: 1) { totalCount }
  user8Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user8], actions: [BLOCKED] }, first: 1) { totalCount }
  user8Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user8], actions: [WARNED] }, first: 1) { totalCount }
  user9Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user9], actions: [BLOCKED] }, first: 1) { totalCount }
  user9Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user9], actions: [WARNED] }, first: 1) { totalCount }
}`,
  ],
  [
    "ToolkitAiDefensePolicies",
    `query ToolkitAiDefensePolicies {
  policies(first: 1) { totalCount enabledCount failedCount }
}`,
  ],
]);

/**
 * The only GraphQL mutations the toolkit may send, as whole documents. Each
 * starts a Search GraphQL search and changes nothing in the tenant. The
 * client's copies (vendor/sophos-core/fusion/queries/search.ts) must be
 * identical; a test checks that.
 */
export const ALLOWED_GRAPHQL_MUTATIONS: ReadonlyMap<string, string> = new Map([
  [
    "CreateSearch",
    `mutation CreateSearch($input: CreateSearchInput) {
  createSearch(input: $input) {
    urn
    status
    errors
    outcome { success errors { urn errors } }
    searchPartitions { urn schemaType status errors }
    createTime
    expireTime
  }
}`,
  ],
  [
    "GetOrCreateSearch",
    `mutation GetOrCreateSearch($input: CreateSearchInput) {
  getOrCreateSearch(input: $input) {
    urn
    status
    errors
    outcome { success errors { urn errors } }
    searchPartitions { urn schemaType status errors }
    createTime
    expireTime
  }
}`,
  ],
]);

/** Longest QL text a search may carry. */
const MAX_QL_LENGTH = 8_000;

export const AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
const GRAPHQL_HOST = "api.taegis.sophos.com";
const DOWNLOAD_HOST = "download.db-ip.com";

function isCentralHost(host: string): boolean {
  return host === "api.central.sophos.com" || /^api-[a-z0-9]+\.central\.sophos\.com$/.test(host);
}

/** True for hosts whose calls count against the Sophos API rate limit. */
export function isRateLimitedHost(host: string): boolean {
  return isCentralHost(host) || host === GRAPHQL_HOST;
}

/**
 * Strips strings and comments so keywords inside them don't count. One pass,
 * left to right, as the GraphQL lexer reads it: a quote inside a comment is
 * part of the comment, a plain string ends at its line, and a block string
 * ends at the next unescaped triple quote. A string left open is refused,
 * so it can't hide the code after it.
 */
function graphqlTokens(document: string): string {
  let out = "";
  let i = 0;
  const n = document.length;
  while (i < n) {
    const ch = document[i]!;
    if (ch === "#") {
      while (i < n && document[i] !== "\n" && document[i] !== "\r") i++;
      continue;
    }
    if (document.startsWith('"""', i)) {
      i += 3;
      for (;;) {
        if (i >= n) throw new ReadOnlyViolationError("a GraphQL block string is not closed");
        if (document.startsWith('\\"""', i)) i += 4;
        else if (document.startsWith('"""', i)) break;
        else i++;
      }
      i += 3;
      out += '""';
      continue;
    }
    if (ch === '"') {
      i++;
      for (;;) {
        const c = document[i];
        if (c === undefined || c === "\n" || c === "\r") throw new ReadOnlyViolationError("a GraphQL string is not closed on its line");
        if (c === "\\") {
          const next = document[i + 1];
          if (next === undefined || next === "\n" || next === "\r") throw new ReadOnlyViolationError("a GraphQL string is not closed on its line");
          i += 2;
        }
        else if (c === '"') break;
        else i++;
      }
      i++;
      out += '""';
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/** The operation name of a read-only GraphQL document, or a violation. */
export function graphqlOperation(document: unknown): string {
  if (typeof document !== "string" || !document.trim()) throw new ReadOnlyViolationError("a GraphQL request with no document");
  const code = graphqlTokens(document);
  if (/\b(mutation|subscription)\b/.test(code)) throw new ReadOnlyViolationError("GraphQL mutations and subscriptions are never sent");
  const match = /^\s*query\s+([_A-Za-z][_0-9A-Za-z]*)/.exec(code);
  if (!match) throw new ReadOnlyViolationError("GraphQL documents must be named queries");
  const operations = code.match(/\bquery\b/g) ?? [];
  if (operations.length !== 1) throw new ReadOnlyViolationError("one operation per GraphQL document");
  return match[1]!;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/**
 * The name of the allowed Search mutation when the request body is exactly
 * one of them with a QL text as its only input; null when the document is not
 * one of them. Throws when the document matches but anything else in the body
 * does not.
 */
export function allowedSearchMutation(body: unknown): string | null {
  if (!plainObject(body)) return null;
  const { query, variables, operationName, ...rest } = body;
  for (const [name, document] of ALLOWED_GRAPHQL_MUTATIONS) {
    if (query !== document) continue;
    if (Object.keys(rest).length) throw new ReadOnlyViolationError("a search request carries only query, variables and operationName");
    if (operationName !== undefined && operationName !== name) throw new ReadOnlyViolationError(`operationName must be ${name}`);
    if (!plainObject(variables) || Object.keys(variables).join() !== "input") throw new ReadOnlyViolationError("a search takes one variable, input");
    const input = variables.input;
    if (!plainObject(input) || Object.keys(input).join() !== "text") throw new ReadOnlyViolationError("a search input carries only text");
    if (typeof input.text !== "string" || !input.text.trim() || input.text.length > MAX_QL_LENGTH) throw new ReadOnlyViolationError("a search needs a QL text");
    return name;
  }
  return null;
}

function bodyText(body: unknown): string {
  if (typeof body === "string") return body;
  if (body === undefined || body === null) return "";
  throw new ReadOnlyViolationError("request bodies must be text");
}

/**
 * Throws ReadOnlyViolationError unless the request is one the read-only
 * toolkit may send. Pure: it looks only at the URL, method and body.
 */
export function assertReadOnly(input: string, init: globalThis.RequestInit = {}, options: { allowDownloads?: boolean } = {}): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new ReadOnlyViolationError("not a URL");
  }
  if (url.protocol !== "https:") throw new ReadOnlyViolationError(`${url.protocol} is not allowed, only https`);
  const method = (init.method ?? "GET").toUpperCase();
  const host = url.hostname.toLowerCase();

  if (host === DOWNLOAD_HOST) {
    if (!options.allowDownloads) throw new ReadOnlyViolationError("the GeoIP download host is reachable only when you start a download");
    if (method !== "GET" || !/^\/free\/dbip-city-lite-\d{4}-\d{2}\.mmdb\.gz$/.test(url.pathname)) {
      throw new ReadOnlyViolationError("only the DB-IP City Lite file can be downloaded");
    }
    return url;
  }

  if (url.href === AUTH_URL) {
    if (method !== "POST") throw new ReadOnlyViolationError("the token endpoint takes POST only");
    return url;
  }

  if (isCentralHost(host)) {
    if (method === "GET" || method === "HEAD") return url;
    if (method === "POST" && /^\/xdr-query\/v1\/queries\/runs\/?$/.test(url.pathname)) {
      let parsed: { adHocQuery?: { template?: unknown } };
      try {
        parsed = JSON.parse(bodyText(init.body));
      } catch {
        throw new ReadOnlyViolationError("an XDR query run needs a JSON body");
      }
      const sql = parsed.adHocQuery?.template;
      if (typeof sql !== "string" || !/^\s*(select|with)\b/i.test(sql)) {
        throw new ReadOnlyViolationError("XDR query runs must be a SELECT");
      }
      return url;
    }
    throw new ReadOnlyViolationError(`${method} ${url.pathname} would change something`);
  }

  if (host === GRAPHQL_HOST) {
    if (method !== "POST" || url.pathname !== "/graphql") throw new ReadOnlyViolationError("Fusion GraphQL takes POST /graphql only");
    let parsed: { query?: unknown };
    try {
      parsed = JSON.parse(bodyText(init.body));
    } catch {
      throw new ReadOnlyViolationError("a GraphQL request needs a JSON body");
    }
    if (allowedSearchMutation(parsed)) return url;
    const operation = graphqlOperation(parsed?.query);
    const { operationName, ...fields } = (plainObject(parsed) ? parsed : {}) as Record<string, unknown>;
    if (Object.keys(fields).some((k) => k !== "query" && k !== "variables")) throw new ReadOnlyViolationError("a GraphQL request carries only query, variables and operationName");
    if (operationName !== undefined && operationName !== null && operationName !== operation) throw new ReadOnlyViolationError(`operationName must be ${operation}`);
    const exact = EXACT_GRAPHQL_QUERIES.get(operation);
    if (exact !== undefined) {
      if (parsed.query !== exact) throw new ReadOnlyViolationError(`GraphQL operation ${operation} is allowed only as its exact document`);
      return url;
    }
    if (!ALLOWED_GRAPHQL_OPERATIONS.has(operation)) throw new ReadOnlyViolationError(`GraphQL operation ${operation} is not on the allowlist`);
    return url;
  }

  throw new ReadOnlyViolationError(`${host} is not a Sophos API host`);
}

/** Carries the caller's priority down to the limiter without threading it through sophos-core. */
export const callPriority = new AsyncLocalStorage<number>();

/** Collects the calls made inside one piece of work (a report run), so the work can say exactly what it sent. */
export const callTally = new AsyncLocalStorage<CallRecord[]>();

export interface CallRecord {
  at: number;
  method: string;
  host: string;
  path: string;
  status: number;
  ms: number;
  /** The GraphQL operation name, for Fusion GraphQL calls. */
  operation?: string;
}

/** The operation name of a GraphQL call the guard already let through. */
function operationOf(init: globalThis.RequestInit): string | undefined {
  try {
    const parsed = JSON.parse(bodyText(init.body)) as { query?: unknown };
    return allowedSearchMutation(parsed) ?? graphqlOperation(parsed?.query);
  } catch {
    return undefined;
  }
}

export interface GuardOptions {
  limiter: RateLimiter;
  /** The underlying fetch. Tests pass a fake Sophos. */
  baseFetch?: FetchLike;
  allowDownloads?: () => boolean;
  onCall?: (record: CallRecord) => void;
}

export function createGuardedFetch(options: GuardOptions): FetchLike {
  const base = options.baseFetch ?? ((input, init) => globalThis.fetch(input, init));
  return async (input, init = {}) => {
    const url = assertReadOnly(input, init, { allowDownloads: options.allowDownloads?.() ?? false });
    const limited = isRateLimitedHost(url.hostname);
    const sophos = url.hostname !== DOWNLOAD_HOST;
    if (limited) await options.limiter.acquire(callPriority.getStore() ?? PRIORITY.background);
    const started = Date.now();
    let response: Response;
    try {
      response = await base(input, { ...init, redirect: "manual" });
    } catch (err) {
      // A request that got no answer (a timeout) was still sent: it counts, with status 0.
      if (limited) {
        const record: CallRecord = { at: started, method: (init.method ?? "GET").toUpperCase(), host: url.hostname, path: url.pathname, status: 0, ms: Date.now() - started, operation: url.hostname === GRAPHQL_HOST ? operationOf(init) : undefined };
        options.onCall?.(record);
        callTally.getStore()?.push(record);
      }
      throw err;
    }
    if (response.status === 429) {
      const retryAfter = Number(response.headers.get("Retry-After"));
      options.limiter.backoff(Number.isFinite(retryAfter) ? retryAfter : null);
    }
    if (limited) {
      const record: CallRecord = {
        at: started,
        method: (init.method ?? "GET").toUpperCase(),
        host: url.hostname,
        path: url.pathname,
        status: response.status,
        ms: Date.now() - started,
        operation: url.hostname === GRAPHQL_HOST ? operationOf(init) : undefined,
      };
      options.onCall?.(record);
      callTally.getStore()?.push(record);
    }
    if (sophos) refuseRedirect(response, input);
    else if (response.status >= 300 && response.status <= 399) {
      response.body?.cancel().catch(() => {});
      let target = "";
      try {
        const location = response.headers.get("Location");
        if (location) target = ` to ${new URL(location, input).host}`;
      } catch {
        // an unreadable Location names no host
      }
      throw new ReadOnlyViolationError(`DB-IP answered the download with a ${response.status} redirect${target}. Redirects are never followed, so nothing was fetched there.`);
    }
    return response;
  };
}
