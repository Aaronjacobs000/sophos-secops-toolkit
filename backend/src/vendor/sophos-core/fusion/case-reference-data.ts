// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/fusion/case-reference-data.ts at commit 9471c18. MIT License, Copyright (c) 2026; the full notice
// is in LICENSE-MIT at the root of this package.

/**
 * Per-tenant cache of the Cases reference data: case types, primary statuses
 * and primary verdicts. Fusion filters and sets these by UUID, and the set a
 * tenant gets depends on its licensed services, so names are resolved at
 * runtime and the cache is refreshed on a TTL rather than resolved once.
 * The same read decides which cases API holds the tenant's cases (`api`), and
 * a tenant still on the legacy cases v1 API gets v1's fixed lists instead.
 */

import type { FusionClient, FusionQueryResult } from "../client/fusion-client.js";
import { CASE_REFERENCE_DATA, TENANT_XDR_OWNERSHIP } from "./queries/cases.js";
import { isUuid } from "./format.js";
import { LEGACY_REFERENCE } from "../legacy/cases-v1.js";
import type {
  FusionCasePrimaryStatus,
  FusionCaseReferenceDataResponse,
  FusionCaseType,
  FusionReferenceItem,
  FusionTenantXdrOwnershipResponse,
} from "./types.js";

/**
 * Where a tenant's cases live: Sophos Fusion cases (Cases v2, GraphQL), the
 * legacy cases v1 REST API for a tenant that hasn't migrated, or nowhere
 * NotFusion can reach (no case types on Fusion and no access to v1).
 */
export type CasesApi = "v2" | "v1" | "none";

export interface CaseReferenceData {
  /**
   * Which API holds the tenant's cases, decided in this order:
   * 1. The tenant record's xdrOwnership: "sophos" means cases v1, any other
   *    value means Cases v2 (live, 27/09/2026).
   * 2. When the record can't be read: Cases v2 if Fusion lists case types for
   *    the tenant, as before; cases v1 if Fusion doesn't know the tenant,
   *    since only v1 can hold its cases.
   * A v1 answer is then checked against v1 itself: a tenant v1 refuses with
   * "not allowed to access cases" has no cases anywhere, so it reads "none".
   */
  api: CasesApi;
  /**
   * The case types, statuses and verdicts of that API. For v1 these are its
   * fixed lists in the same shapes, each ID being the v1 value. Empty for
   * "none".
   */
  types: FusionCaseType[];
  primaryStatuses: FusionCasePrimaryStatus[];
  primaryVerdicts: FusionReferenceItem[];
  fetchedAt: string;
}

const DEFAULT_TTL_MS = 15 * 60_000;

/** False when the tenant has no access to cases v1; throws on any other failure. */
export type LegacyCasesAccess = (tenantId: string) => Promise<boolean>;

export class CaseReferenceDataCache {
  private cache = new Map<string, { data: CaseReferenceData; expiresAt: number }>();
  private inflight = new Map<string, Promise<CaseReferenceData>>();

  /**
   * `legacyAccess` checks a tenant against cases v1. Without it a v1 tenant
   * is taken to have access, which is how the unit tests run.
   */
  constructor(
    private client: FusionClient,
    private ttlMs: number = DEFAULT_TTL_MS,
    private legacyAccess?: LegacyCasesAccess
  ) {}

  async get(tenantId: string, options: { refresh?: boolean } = {}): Promise<CaseReferenceData> {
    const cached = this.cache.get(tenantId);
    if (cached && !options.refresh && Date.now() < cached.expiresAt) {
      return cached.data;
    }

    const pending = this.inflight.get(tenantId);
    if (pending) return pending;

    const promise = this.fetch(tenantId);
    this.inflight.set(tenantId, promise);
    try {
      const data = await promise;
      this.cache.set(tenantId, { data, expiresAt: Date.now() + this.ttlMs });
      return data;
    } finally {
      this.inflight.delete(tenantId);
    }
  }

  invalidate(tenantId: string): void {
    this.cache.delete(tenantId);
  }

  /** Accepts a UUID (passed through) or a type name or title (case-insensitive). */
  async resolveTypeId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { types } = await this.get(tenantId);
    return matchReference("case type", types, nameOrId).id;
  }

  async resolveStatusId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { primaryStatuses } = await this.get(tenantId);
    return matchReference("primary status", primaryStatuses, nameOrId).id;
  }

  async resolveStatus(tenantId: string, nameOrId: string): Promise<FusionCasePrimaryStatus> {
    const { primaryStatuses } = await this.get(tenantId);
    if (isUuid(nameOrId)) {
      const byId = primaryStatuses.find((s) => s.id === nameOrId);
      if (byId) return byId;
      // An ID the cache does not know may still be valid for the tenant (the
      // cache can be up to 15 minutes old). Let the API decide; assume open.
      return { id: nameOrId, name: nameOrId, title: null, isClosed: false };
    }
    return matchReference("primary status", primaryStatuses, nameOrId);
  }

  async resolveVerdictId(tenantId: string, nameOrId: string): Promise<string> {
    if (isUuid(nameOrId)) return nameOrId;
    const { primaryVerdicts } = await this.get(tenantId);
    return matchReference("primary verdict", primaryVerdicts, nameOrId).id;
  }

  private async fetch(tenantId: string): Promise<CaseReferenceData> {
    // Both reads start together. The ownership read never throws.
    const ownership = this.readXdrOwnership(tenantId);
    const fusion = this.readFusionReference(tenantId);
    // A v1 tenant never waits for the Fusion lists, so their failure mustn't go unhandled.
    fusion.catch(() => undefined);
    const owner = await ownership;
    if (isLegacyXdrOwnership(owner)) return this.legacyData(tenantId);
    const lists = await fusion;
    if (lists === null) {
      // Fusion doesn't know the tenant. With no record to say otherwise, only v1 can hold its cases.
      return owner === null ? this.legacyData(tenantId) : noCases();
    }
    return { api: "v2", ...lists, fetchedAt: new Date().toISOString() };
  }

  /** The v1 lists, or "none" when v1 refuses the tenant. */
  private async legacyData(tenantId: string): Promise<CaseReferenceData> {
    if (this.legacyAccess && !(await this.legacyAccess(tenantId))) return noCases();
    return {
      api: "v1",
      types: [...LEGACY_REFERENCE.types],
      primaryStatuses: [...LEGACY_REFERENCE.primaryStatuses],
      primaryVerdicts: [...LEGACY_REFERENCE.primaryVerdicts],
      fetchedAt: new Date().toISOString(),
    };
  }

  /**
   * The Cases v2 lists, or null when Fusion doesn't hold the tenant: no case
   * types (Phase 0, 22/09/2026) or the 503 "not found or not accessible".
   */
  private async readFusionReference(
    tenantId: string
  ): Promise<Pick<CaseReferenceData, "types" | "primaryStatuses" | "primaryVerdicts"> | null> {
    let result: FusionQueryResult<FusionCaseReferenceDataResponse>;
    try {
      result = await this.client.query<FusionCaseReferenceDataResponse>(tenantId, CASE_REFERENCE_DATA);
    } catch (error) {
      if (isTenantNotOnFusion(error)) return null;
      throw error;
    }
    const { data, warnings } = result;
    const missing = (["caseTypes", "casePrimaryStatuses", "casePrimaryVerdicts"] as const).filter(
      (key) => data[key] === null || data[key] === undefined
    );
    if (missing.length > 0) {
      throw new Error(
        `Case reference data incomplete for tenant ${tenantId} (missing ${missing.join(", ")})${warnings.length ? `: ${warnings.join("; ")}` : ""}`
      );
    }
    if (data.caseTypes!.types.length === 0) return null;
    return {
      types: data.caseTypes!.types,
      primaryStatuses: data.casePrimaryStatuses!.primaryStatuses,
      primaryVerdicts: data.casePrimaryVerdicts!.primaryVerdicts,
    };
  }

  /** Who owns the tenant's XDR data, or null when the record can't be read. */
  private async readXdrOwnership(tenantId: string): Promise<string | null> {
    try {
      const { data } = await this.client.query<FusionTenantXdrOwnershipResponse>(tenantId, TENANT_XDR_OWNERSHIP, {
        id: tenantId,
      });
      const value = data.tenant?.centralTenant?.xdrOwnership;
      return typeof value === "string" && value.trim() ? value : null;
    } catch {
      return null;
    }
  }
}

function noCases(): CaseReferenceData {
  return { api: "none", types: [], primaryStatuses: [], primaryVerdicts: [], fetchedAt: new Date().toISOString() };
}

/**
 * True when a tenant record's xdrOwnership says Sophos Central still owns the
 * tenant's XDR data, which means its cases are still on the legacy cases v1
 * API. Measured live on 27/09/2026: five tenants a partner has not migrated
 * yet answered "sophos"; three tenants on Cases v2 answered
 * "securityOperations". Anything but "sophos" reads as migrated.
 */
export function isLegacyXdrOwnership(value: string | null | undefined): boolean {
  return typeof value === "string" && value.trim().toLowerCase() === "sophos";
}

/**
 * True for the 503 Fusion returns for a tenant it can't find for this
 * credential: "error invoking downstream api ... tenant <id> not found or not
 * accessible" (a tenant under the test partner, 27/09/2026, while its REST
 * APIs answered normally). The app reads it as not on Fusion, like a tenant
 * that returns no case types. Any other 503 is still an error.
 */
export function isTenantNotOnFusion(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return (
    /^Sophos Fusion API error 503:/.test(error.message) &&
    /\btenant \S+ not found or not accessible\b/i.test(error.message)
  );
}

/** Matches on `name` first, then `title`, both case-insensitive. */
export function matchReference<T extends FusionReferenceItem>(
  kind: string,
  items: T[],
  nameOrTitle: string
): T {
  const wanted = nameOrTitle.trim().toLowerCase();
  const found =
    items.find((item) => item.name.toLowerCase() === wanted) ??
    items.find((item) => (item.title ?? "").toLowerCase() === wanted);
  if (!found) {
    const available = items.map((item) => item.name).join(", ") || "none";
    throw new Error(
      `Unknown ${kind} "${nameOrTitle}" for this tenant. Available: ${available}.`
    );
  }
  return found;
}
