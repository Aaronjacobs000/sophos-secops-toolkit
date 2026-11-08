// SPDX-License-Identifier: Apache-2.0
/**
 * The legacy Sophos cases API (cases v1) over the Sophos Central REST client:
 * the tenant's regional host and an X-Tenant-ID header, which is how both a
 * tenant credential and a partner credential reach it. Reads retry the way
 * every REST read does; a write is sent once and never repeated after a 5xx
 * or a timeout, because it may have landed.
 *
 * Also the one detections query v1 case creation needs: v1 opens a case from
 * a detection of the last 30 days, so the new case sheet lists them.
 */

import { SophosApiRequestError, type MetaResult, type SophosClient } from "../client/sophos-client.js";
import type {
  LegacyCase,
  LegacyCaseCreate,
  LegacyCasePage,
  LegacyCasePatch,
  LegacyDetection,
  LegacyDetectionPage,
} from "../legacy/cases-v1.js";

const CASES = "/cases/v1/cases";
const DETECTION_QUERIES = "/detections/v1/queries/detections";

/** The largest page cases v1 serves (pageSize 100 is a 400, live 28/09/2026). */
export const LEGACY_PAGE_MAX = 50;

/** A new case can only start from a detection this recent (the spec's create rule). */
export const LEGACY_DETECTION_DAYS = 30;

/**
 * True for the 403 Sophos answers for a tenant that has no cases at all:
 * "Tenant is not allowed to access cases" (four of AJ's tenants with no XDR
 * or MDR licence, live 28/09/2026). Any other 403 is still an error.
 */
export function isNoCasesAccess(error: unknown): boolean {
  return error instanceof SophosApiRequestError && error.status === 403 && /not allowed to access cases/i.test(error.message);
}

export interface RecentDetectionsOptions {
  /** How far back, in days. Default and maximum 30. */
  days?: number;
  /** How many, newest first. Default 50. */
  limit?: number;
  /** Between polls of the query run. Default 1000 ms. */
  pollMs?: number;
  /** Give up on the query run after this long. Default 30 s. */
  timeoutMs?: number;
  now?: () => number;
}

interface DetectionRun {
  id: string;
  status?: "pending" | "started" | "finished";
  result?: "succeeded" | "canceled" | "failed" | "notAvailable" | "timedOut";
  resultCount?: number;
}

export class LegacyCasesService {
  constructor(private client: Pick<SophosClient, "tenantRequest" | "tenantRequestWithMeta">) {}

  /** False when the tenant has no cases to reach (the 403 above); other failures throw. */
  async hasAccess(tenantId: string): Promise<boolean> {
    try {
      await this.client.tenantRequest<LegacyCasePage>(tenantId, CASES, { params: { pageSize: "1" } });
      return true;
    } catch (error) {
      if (isNoCasesAccess(error)) return false;
      throw error;
    }
  }

  async list(tenantId: string, params: Record<string, string>): Promise<LegacyCasePage> {
    return this.client.tenantRequest<LegacyCasePage>(tenantId, CASES, { params });
  }

  async get(tenantId: string, caseId: string): Promise<LegacyCase> {
    return this.client.tenantRequest<LegacyCase>(tenantId, `${CASES}/${encodeURIComponent(caseId)}`);
  }

  /** POST, sent once. Only self-managed cases can be created. */
  async create(tenantId: string, body: LegacyCaseCreate): Promise<MetaResult<LegacyCase>> {
    return this.client.tenantRequestWithMeta<LegacyCase>(tenantId, CASES, { method: "POST", body, idempotent: false });
  }

  /** PATCH, sent once. Only self-managed cases can be updated. */
  async update(tenantId: string, caseId: string, patch: LegacyCasePatch): Promise<MetaResult<LegacyCase>> {
    return this.client.tenantRequestWithMeta<LegacyCase>(tenantId, `${CASES}/${encodeURIComponent(caseId)}`, {
      method: "PATCH",
      body: patch,
      idempotent: false,
    });
  }

  /** One page of a case's detections, pageSize 1 to 50. */
  async detections(tenantId: string, caseId: string, page: number, pageSize: number): Promise<LegacyDetectionPage> {
    return this.client.tenantRequest<LegacyDetectionPage>(tenantId, `${CASES}/${encodeURIComponent(caseId)}/detections`, {
      params: { page: String(page), pageSize: String(Math.min(LEGACY_PAGE_MAX, Math.max(1, pageSize))) },
    });
  }

  /**
   * The tenant's detections from the last `days` days, newest first, for
   * opening a case from. The detections API runs a query and then serves
   * its results: start the run, poll it until it finishes, read one page.
   * Starting a run changes nothing in the tenant.
   */
  async recentDetections(tenantId: string, options: RecentDetectionsOptions = {}): Promise<LegacyDetection[]> {
    const now = options.now ?? Date.now;
    const days = Math.min(LEGACY_DETECTION_DAYS, Math.max(1, options.days ?? LEGACY_DETECTION_DAYS));
    const limit = Math.min(LEGACY_PAGE_MAX, Math.max(1, options.limit ?? LEGACY_PAGE_MAX));
    const pollMs = options.pollMs ?? 1000;
    const deadline = now() + (options.timeoutMs ?? 30_000);
    const to = new Date(now());
    const from = new Date(to.getTime() - days * 86_400_000);

    let run = await this.client.tenantRequest<DetectionRun>(tenantId, DETECTION_QUERIES, {
      method: "POST",
      body: { from: from.toISOString(), to: to.toISOString(), sort: [{ field: "time", direction: "desc" }] },
    });
    while (run.status !== "finished") {
      if (now() >= deadline) throw new Error("Sophos took too long to search the tenant's detections. Try again.");
      await new Promise((resolve) => setTimeout(resolve, pollMs));
      run = await this.client.tenantRequest<DetectionRun>(tenantId, `${DETECTION_QUERIES}/${encodeURIComponent(run.id)}`);
    }
    if (run.result !== "succeeded") {
      throw new Error(`Sophos couldn't search the tenant's detections (the search ${run.result ?? "ended without a result"}).`);
    }
    if (run.resultCount === 0) return [];
    const page = await this.client.tenantRequest<LegacyDetectionPage>(
      tenantId,
      `${DETECTION_QUERIES}/${encodeURIComponent(run.id)}/results`,
      { params: { page: "1", pageSize: String(limit) } }
    );
    return page.items ?? [];
  }
}
