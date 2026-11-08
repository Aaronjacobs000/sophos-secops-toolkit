// SPDX-License-Identifier: MIT
// The flow follows sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/tools/fusion-search.ts at release 0.9.2, MIT License, Copyright (c) 2026; the full notice
// is in LICENSE-MIT at the root of this package. (SecOps Toolkit local modification, 29/10/2026.)

/**
 * Search GraphQL (Fusion Data Lake search in QL) as one call: start a
 * search, poll it every 5 seconds until it completes or a deadline passes,
 * then read every page of rows by cursor.
 *
 * Policies, all measured or documented on 29/10/2026:
 * - Reuse: getOrCreateSearch returns a matching search that is running or
 *   complete. Only queries with absolute time bounds match a second time, so
 *   callers that want reuse put absolute earliest and latest values in the QL.
 * - PARTIAL: a COMPLETE search can still have failed partitions (one per
 *   output schema). "accept" (the default) returns the rows that did arrive
 *   and names the failed partitions; "reject" throws.
 * - Failure: outcome NONE, or UNKNOWN once complete, throws. A reused search
 *   that failed, or is about to expire, is run again once with createSearch.
 * - Expiry: results are gone after expireTime (30 days in testing). A results
 *   read that finds them gone is retried once as a new search.
 * - Deadline: a search still running at the deadline throws a timeout. It
 *   keeps running at Sophos, and the next getOrCreateSearch with the same QL
 *   picks it up rather than starting another.
 */

import { FusionGraphQLError, type FusionClient } from "../client/fusion-client.js";
import { CREATE_SEARCH, GET_OR_CREATE_SEARCH, SEARCH_RESULTS, SEARCH_STATUS } from "../fusion/queries/search.js";

export type SearchExecutionStatus = "QUEUED" | "IN_PROGRESS" | "COMPLETE";
export type SearchSuccess = "UNKNOWN" | "ALL" | "PARTIAL" | "NONE";
export type SearchPartitionStatus = "WAITING" | "IN_PROGRESS" | "SUCCEEDED" | "FAILED" | "CANCELED";

export interface FusionSearchPartition {
  urn: string;
  schemaType: string | null;
  status: SearchPartitionStatus;
  errors: string[];
}

export interface FusionSearch {
  urn: string;
  status: SearchExecutionStatus;
  /** Non-fatal validation warnings about the query. */
  errors: string[];
  outcome: { success: SearchSuccess; errors: Array<{ urn: string; errors: string[] }> };
  searchPartitions: FusionSearchPartition[];
  createTime: string;
  expireTime: string;
}

export interface FusionSearchResultPage {
  values: Array<Record<string, unknown>> | null;
  totals: { total: { value: number | string } | null; subtotals: Array<{ schemaType: string; value: number | string }> | null } | null;
  nextCursor: string | null;
}

/** Poll interval the Search guide suggests. */
export const SEARCH_POLL_MS = 5_000;
export const SEARCH_DEADLINE_MS = 120_000;
/** searchResults refuses a limit above 1000 (live tenant, 29/10/2026). */
export const MAX_SEARCH_PAGE = 1_000;
/** A reused search with less life left than this is run again. */
export const SEARCH_MIN_LIFE_MS = 5 * 60_000;
/** The API refuses a QL time range longer than this ("MAX: 31 days", live tenant, 29/10/2026). */
export const MAX_SEARCH_RANGE_DAYS = 31;

export type PartialPolicy = "accept" | "reject";

export interface SearchRunOptions {
  /** getOrCreateSearch (reuse a matching search) rather than createSearch. Default true. */
  reuse?: boolean;
  pollMs?: number;
  deadlineMs?: number;
  /** Rows per results page, 1 to 1000. Default 1000. */
  pageSize?: number;
  /** Stop reading after this many rows and mark the run truncated. Default 5000. */
  maxRows?: number;
  /** Per-attempt timeout for each results page, in place of the client's. (SecOps Toolkit local modification, 06/11/2026.) */
  pageTimeoutMs?: number;
  partial?: PartialPolicy;
  /** Test hooks. */
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export interface SearchRun {
  urn: string;
  rows: Array<Record<string, unknown>>;
  /** Sophos's count of the whole result set, when it gave one. */
  total: number | null;
  /** True when more rows existed than maxRows allowed. */
  truncated: boolean;
  outcome: "ALL" | "PARTIAL";
  failedPartitions: Array<{ schemaType: string | null; errors: string[] }>;
  /** Query warnings from Sophos, and GraphQL errors that came beside usable data. */
  warnings: string[];
  /** True when getOrCreateSearch handed back an existing search. */
  reused: boolean;
  createTime: string;
  expireTime: string;
  /** GraphQL calls this run made (start, polls, result pages). */
  calls: number;
}

export type SearchErrorKind = "failed" | "timeout" | "expired" | "denied";

export class SearchError extends Error {
  constructor(
    message: string,
    readonly kind: SearchErrorKind,
    readonly urn: string | null = null
  ) {
    super(message);
    this.name = "SearchError";
  }

  /** The credential or the tenant may not run searches. Retrying soon will not help. */
  get noAccess(): boolean {
    return this.kind === "denied";
  }
}

const DENIED = /unauthori[sz]ed|forbidden|permission|access denied|not authori[sz]ed|insufficient/i;
const GONE = /expired|no longer available|not found|does not exist/i;

function isDenied(error: unknown): boolean {
  if (error instanceof FusionGraphQLError) {
    return error.errors.some((e) => DENIED.test(e.message ?? "") || e.extensions?.code === "FORBIDDEN" || e.extensions?.code === "UNAUTHENTICATED");
  }
  return error instanceof Error && /Sophos Fusion API error 403\b/.test(error.message);
}

function isGone(error: unknown): boolean {
  if (error instanceof FusionGraphQLError) return error.errors.some((e) => GONE.test(e.message ?? ""));
  return error instanceof Error && /Sophos Fusion API error 404\b/.test(error.message);
}

function toNumber(value: unknown): number | null {
  const n = typeof value === "number" ? value : typeof value === "string" && value.trim() ? Number(value) : NaN;
  return Number.isFinite(n) ? n : null;
}

export class SearchService {
  constructor(private readonly fusion: FusionClient) {}

  /** Calls Fusion, turning a refusal into SearchError("denied"). */
  private async call<T extends object>(tenantId: string, document: string, variables: Record<string, unknown>, idempotent = true, timeoutMs?: number) {
    try {
      return await this.fusion.query<T>(tenantId, document, variables, { idempotent, ...(timeoutMs ? { timeoutMs } : {}) });
    } catch (error) {
      if (isDenied(error)) {
        throw new SearchError(`Sophos refused the search: ${error instanceof Error ? error.message : String(error)}`, "denied");
      }
      throw error;
    }
  }

  /** Starts a search: getOrCreateSearch when `reuse`, else createSearch. */
  async start(tenantId: string, ql: string, reuse = true): Promise<{ search: FusionSearch; warnings: string[] }> {
    if (reuse) {
      const { data, warnings } = await this.call<{ getOrCreateSearch: FusionSearch | null }>(tenantId, GET_OR_CREATE_SEARCH, { input: { text: ql } });
      if (!data.getOrCreateSearch) throw new SearchError("getOrCreateSearch returned no search.", "failed");
      return { search: data.getOrCreateSearch, warnings };
    }
    // createSearch is not safe to repeat after a 5xx: the first attempt may have started a search.
    const { data, warnings } = await this.call<{ createSearch: FusionSearch | null }>(tenantId, CREATE_SEARCH, { input: { text: ql } }, false);
    if (!data.createSearch) throw new SearchError("createSearch returned no search.", "failed");
    return { search: data.createSearch, warnings };
  }

  async status(tenantId: string, urn: string): Promise<FusionSearch> {
    const { data } = await this.call<{ search: FusionSearch | null }>(tenantId, SEARCH_STATUS, { urn });
    if (!data.search) throw new SearchError(`Search ${urn} not found.`, "expired", urn);
    return data.search;
  }

  async results(tenantId: string, urn: string, cursor?: string, limit = MAX_SEARCH_PAGE, timeoutMs?: number): Promise<FusionSearchResultPage> {
    const variables: Record<string, unknown> = { urn, limit: Math.max(1, Math.min(MAX_SEARCH_PAGE, limit)) };
    if (cursor) variables.cursor = cursor;
    const { data } = await this.call<{ searchResults: FusionSearchResultPage | null }>(tenantId, SEARCH_RESULTS, variables, true, timeoutMs);
    if (!data.searchResults) throw new SearchError(`searchResults returned nothing for ${urn}.`, "expired", urn);
    return data.searchResults;
  }

  /** Start, wait, read every page. See the policies at the top of this file. */
  async run(tenantId: string, ql: string, options: SearchRunOptions = {}): Promise<SearchRun> {
    const now = options.now ?? Date.now;
    const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
    const pollMs = options.pollMs ?? SEARCH_POLL_MS;
    const deadlineMs = options.deadlineMs ?? SEARCH_DEADLINE_MS;
    const pageSize = Math.max(1, Math.min(MAX_SEARCH_PAGE, options.pageSize ?? MAX_SEARCH_PAGE));
    const maxRows = Math.max(1, options.maxRows ?? 5_000);
    const policy = options.partial ?? "accept";
    const deadline = now() + deadlineMs;
    let reuse = options.reuse !== false;
    let rerun = false;
    let calls = 0;

    for (;;) {
      const startedAt = now();
      const started = await this.start(tenantId, ql, reuse);
      calls++;
      let search = started.search;
      // Clocks differ a little; a search created more than 2 s before the call was already there.
      const reused = reuse && Date.parse(search.createTime) < startedAt - 2_000;
      const again = () => {
        rerun = true;
        reuse = false;
      };
      const failed = (s: FusionSearch) => s.status === "COMPLETE" && (s.outcome.success === "NONE" || s.outcome.success === "UNKNOWN");
      if (reused && !rerun && (failed(search) || Date.parse(search.expireTime) - now() < SEARCH_MIN_LIFE_MS)) {
        again();
        continue;
      }

      while (search.status !== "COMPLETE") {
        if (now() >= deadline) {
          throw new SearchError(`The search did not finish within ${Math.round(deadlineMs / 1000)} s. It keeps running at Sophos, and the next refresh picks it up.`, "timeout", search.urn);
        }
        await sleep(pollMs);
        search = await this.status(tenantId, search.urn);
        calls++;
      }

      if (failed(search)) {
        if (reused && !rerun) {
          again();
          continue;
        }
        const messages = [...search.outcome.errors.flatMap((e) => e.errors), ...search.errors].filter(Boolean);
        throw new SearchError(`The search failed${messages.length ? `: ${messages.join("; ").slice(0, 400)}` : "."}`, "failed", search.urn);
      }

      const failedPartitions = search.searchPartitions
        .filter((p) => p.status === "FAILED" || p.status === "CANCELED")
        .map((p) => ({ schemaType: p.schemaType, errors: [...p.errors, ...(search.outcome.errors.find((e) => e.urn === p.urn)?.errors ?? [])] }));
      if (search.outcome.success === "PARTIAL" && policy === "reject") {
        throw new SearchError(`The search was partial: ${failedPartitions.map((p) => p.schemaType ?? "a partition").join(", ")} failed.`, "failed", search.urn);
      }

      if (Date.parse(search.expireTime) <= now()) {
        if (!rerun) {
          again();
          continue;
        }
        throw new SearchError("The search results expired before they could be read.", "expired", search.urn);
      }

      const rows: Array<Record<string, unknown>> = [];
      let total: number | null = null;
      let truncated = false;
      let cursor: string | undefined;
      try {
        for (;;) {
          const page = await this.results(tenantId, search.urn, cursor, pageSize, options.pageTimeoutMs);
          calls++;
          if (total === null) total = toNumber(page.totals?.total?.value);
          for (const value of page.values ?? []) {
            if (rows.length >= maxRows) {
              truncated = true;
              break;
            }
            rows.push(value);
          }
          if (truncated || !page.nextCursor) break;
          if (rows.length >= maxRows) {
            truncated = true;
            break;
          }
          cursor = page.nextCursor;
        }
      } catch (error) {
        if (error instanceof SearchError && error.kind === "denied") throw error;
        if (isGone(error) || (error instanceof SearchError && error.kind === "expired")) {
          if (!rerun) {
            again();
            continue;
          }
          throw new SearchError("The search results expired before they could be read.", "expired", search.urn);
        }
        throw error;
      }

      return {
        urn: search.urn,
        rows,
        total,
        truncated,
        outcome: search.outcome.success === "PARTIAL" ? "PARTIAL" : "ALL",
        failedPartitions,
        warnings: [...search.errors, ...started.warnings],
        reused,
        createTime: search.createTime,
        expireTime: search.expireTime,
        calls,
      };
    }
  }
}
