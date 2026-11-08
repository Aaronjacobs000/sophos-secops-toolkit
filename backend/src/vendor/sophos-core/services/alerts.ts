// SPDX-License-Identifier: Apache-2.0
/**
 * Alerts on the Common API (/common/v1/alerts): list, detail and the actions
 * an alert itself offers in allowedActions.
 */

import type { MetaResult, SophosClient } from "../client/sophos-client.js";
import type { SophosAlert } from "../types/sophos.js";

export type AlertSeverity = "high" | "medium" | "low";

export interface AlertListOptions {
  /**
   * One severity. The API ignores a list without an error: severity=high,low
   * and severity=high&severity=low both returned every alert, including
   * medium ones (live tenant, 23/09/2026). So the filter takes one value.
   */
  severity?: AlertSeverity;
  /** One category, for example "malware" or "policy". */
  category?: string;
  /** One product, for example "endpoint" or "server". */
  product?: string;
  /** ISO 8601; alerts raised at or after this time. */
  from?: string;
  /**
   * "raisedAt:desc" for newest first. Without a sort the API lists oldest
   * first. The order holds across pages (live tenants, 02/10/2026).
   */
  sort?: "raisedAt:desc" | "raisedAt:asc";
  /** 1 to 1000, default 50. */
  pageSize?: number;
  /** nextKey from the previous page. The API ignores `page`, so paging is by key only. */
  pageFromKey?: string;
  /** Ask for the total count (costs the API a count). */
  pageTotal?: boolean;
}

export interface AlertPage {
  items: SophosAlert[];
  nextKey: string | null;
  /** Present only when pageTotal was requested. */
  total: number | null;
}

export interface AlertActionResult {
  id?: string;
  alertId?: string;
  action?: string;
  status?: string;
  result?: string;
  requestedAt?: string;
  startedAt?: string;
  completedAt?: string;
}

interface AlertListResponse {
  items: SophosAlert[];
  pages: { nextKey?: string; items?: number };
}

const SEVERITIES: readonly AlertSeverity[] = ["high", "medium", "low"];

export class AlertsService {
  constructor(private client: SophosClient) {}

  async list(tenantId: string, options: AlertListOptions = {}): Promise<AlertPage> {
    if (options.severity !== undefined && !SEVERITIES.includes(options.severity)) {
      throw new Error(`Alert severity must be one of ${SEVERITIES.join(", ")}, got ${JSON.stringify(options.severity)}.`);
    }
    const pageSize = Math.min(1000, Math.max(1, options.pageSize ?? 50));
    const data = await this.client.tenantRequest<AlertListResponse>(tenantId, "/common/v1/alerts", {
      params: {
        pageSize: String(pageSize),
        ...(options.pageFromKey ? { pageFromKey: options.pageFromKey } : {}),
        ...(options.pageTotal ? { pageTotal: "true" } : {}),
        ...(options.severity ? { severity: options.severity } : {}),
        ...(options.category ? { category: options.category } : {}),
        ...(options.product ? { product: options.product } : {}),
        ...(options.from ? { from: options.from } : {}),
        ...(options.sort ? { sort: options.sort } : {}),
      },
    });
    return {
      items: data.items,
      nextKey: data.pages?.nextKey ?? null,
      // pages.items is the item count; pages.total is the number of pages.
      total: options.pageTotal ? (data.pages?.items ?? null) : null,
    };
  }

  async get(tenantId: string, alertId: string): Promise<SophosAlert> {
    return this.client.tenantRequest<SophosAlert>(tenantId, `/common/v1/alerts/${encodeURIComponent(alertId)}`);
  }

  /**
   * Runs one of the actions the alert offers. The alert is read first, so an
   * action that is no longer in allowedActions is refused before any write.
   * The API takes no reason for an alert action; the app records it locally.
   * A POST that changes device state, so a failed attempt is not repeated.
   */
  async performAction(tenantId: string, alertId: string, action: string): Promise<MetaResult<AlertActionResult>> {
    const alert = await this.get(tenantId, alertId);
    const allowed = alert.allowedActions ?? [];
    if (!allowed.includes(action)) {
      throw new Error(
        `Alert ${alertId} does not offer the action ${JSON.stringify(action)}. It offers: ${allowed.join(", ") || "none"}.`
      );
    }
    return this.client.tenantRequestWithMeta<AlertActionResult>(
      tenantId,
      `/common/v1/alerts/${encodeURIComponent(alertId)}/actions`,
      { method: "POST", body: { action }, idempotent: false }
    );
  }
}
