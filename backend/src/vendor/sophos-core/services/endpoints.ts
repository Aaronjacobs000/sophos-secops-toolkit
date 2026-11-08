// SPDX-License-Identifier: Apache-2.0
/**
 * Endpoints on the Endpoint API (/endpoint/v1/endpoints): search, detail,
 * isolation state, isolate, release and scan.
 */

import type { MetaResult, SophosClient } from "../client/sophos-client.js";
import type { SophosEndpoint } from "../types/sophos.js";

export type EndpointHealth = "good" | "suspicious" | "bad" | "unknown";

export interface EndpointSearchOptions {
  /** Substring of the hostname. */
  hostname?: string;
  /** Any of these (the API takes a list here). */
  healthStatus?: EndpointHealth[];
  isolationStatus?: "isolated" | "notIsolated";
  type?: "computer" | "server" | "securityVm";
  /**
   * "hostname:asc" for A to Z, ignoring case. Without a sort the API's order
   * follows no visible field. The order holds across pages (live tenants,
   * 02/10/2026).
   */
  sort?: "hostname:asc" | "hostname:desc";
  /** 1 to 500, default 50. */
  pageSize?: number;
  /** nextKey from the previous page. */
  pageFromKey?: string;
  /** Ask for the total count, for example for the Home counters. */
  pageTotal?: boolean;
}

export interface EndpointPage {
  items: SophosEndpoint[];
  nextKey: string | null;
  /** Present only when pageTotal was requested. */
  total: number | null;
}

/** The detail view adds fields the list omits (serial number, maintenance mode, last update times). */
export type EndpointDetail = SophosEndpoint & {
  online?: boolean;
  mdrManaged?: boolean;
  tamperProtectionSupported?: boolean;
  serialNumber?: string;
  lastOsUpdateAt?: string;
  lastAgentUpdateAt?: string;
  registeredAt?: string;
};

export interface IsolationState {
  enabled: boolean;
  /** When isolation was last turned on, as Sophos formats it ("2024-06-30 01.54.22 UTC"). */
  lastEnabledAt?: string;
  lastEnabledBy?: { id?: string };
  lastDisabledAt?: string;
  lastDisabledBy?: { id?: string };
  comment?: string;
  [field: string]: unknown;
}

interface EndpointListResponse {
  items: SophosEndpoint[];
  pages: { nextKey?: string; items?: number };
}

export class EndpointsService {
  constructor(private client: SophosClient) {}

  async search(tenantId: string, options: EndpointSearchOptions = {}): Promise<EndpointPage> {
    const pageSize = Math.min(500, Math.max(1, options.pageSize ?? 50));
    const data = await this.client.tenantRequest<EndpointListResponse>(tenantId, "/endpoint/v1/endpoints", {
      params: {
        pageSize: String(pageSize),
        ...(options.pageFromKey ? { pageFromKey: options.pageFromKey } : {}),
        ...(options.pageTotal ? { pageTotal: "true" } : {}),
        ...(options.hostname ? { hostnameContains: options.hostname } : {}),
        ...(options.healthStatus?.length ? { healthStatus: options.healthStatus.join(",") } : {}),
        ...(options.isolationStatus ? { isolationStatus: options.isolationStatus } : {}),
        ...(options.type ? { type: options.type } : {}),
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

  async get(tenantId: string, endpointId: string): Promise<EndpointDetail> {
    return this.client.tenantRequest<EndpointDetail>(tenantId, `/endpoint/v1/endpoints/${encodeURIComponent(endpointId)}`, {
      params: { view: "full" },
    });
  }

  async getIsolation(tenantId: string, endpointId: string): Promise<IsolationState> {
    return this.client.tenantRequest<IsolationState>(
      tenantId,
      `/endpoint/v1/endpoints/${encodeURIComponent(endpointId)}/isolation`
    );
  }

  /**
   * Isolate. The comment is the reason and is sent to Sophos with the change.
   * The PATCH is idempotent, so a retry after a timeout is safe.
   */
  async isolate(tenantId: string, endpointId: string, comment: string): Promise<MetaResult<IsolationState>> {
    return this.setIsolation(tenantId, endpointId, true, comment);
  }

  /** Release from isolation. The comment is sent to Sophos with the change. */
  async release(tenantId: string, endpointId: string, comment: string): Promise<MetaResult<IsolationState>> {
    return this.setIsolation(tenantId, endpointId, false, comment);
  }

  /**
   * Starts a scan. The API returns once the request is accepted, not when the
   * scan ends, and there is no call to read a scan back. A POST, so a failed
   * attempt is not repeated: the first one may have started a scan.
   */
  async scan(tenantId: string, endpointId: string): Promise<MetaResult<unknown>> {
    return this.client.tenantRequestWithMeta(
      tenantId,
      `/endpoint/v1/endpoints/${encodeURIComponent(endpointId)}/scans`,
      { method: "POST", body: {}, idempotent: false }
    );
  }

  private async setIsolation(
    tenantId: string,
    endpointId: string,
    enabled: boolean,
    comment: string
  ): Promise<MetaResult<IsolationState>> {
    if (!comment.trim()) {
      throw new Error("A reason is required to change isolation; it is sent to Sophos as the comment.");
    }
    return this.client.tenantRequestWithMeta<IsolationState>(
      tenantId,
      `/endpoint/v1/endpoints/${encodeURIComponent(endpointId)}/isolation`,
      { method: "PATCH", body: { enabled, comment } }
    );
  }
}
