// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/client/sophos-client.ts at commit 9471c18. MIT License, Copyright (c) 2026; the full notice
// is in LICENSE-MIT at the root of this package.

/**
 * HTTP client for Sophos Central APIs.
 * Handles region-aware routing, auth headers, retries, and error mapping.
 */

import type { TokenManager } from "../auth/token-manager.js";
import type { TenantResolver } from "./tenant-resolver.js";
import type { SophosApiError } from "../types/sophos.js";
import { buildUrl, defaultFetch, SophosRedirectError, type FetchLike } from "../http.js";
import { log } from "../logger.js";

/**
 * A non-2xx response from a Sophos Central REST API. The message keeps the
 * MCP server's wording; the fields carry what an error sheet and the audit
 * log need, correlationId above all, because Sophos support asks for it.
 */
export class SophosApiRequestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly error: string | null,
    readonly correlationId: string | null,
    readonly requestId: string | null
  ) {
    super(message);
    this.name = "SophosApiRequestError";
  }
}

/** What a response said about itself, for the audit log and a ticket to Sophos. */
export interface ResponseMeta {
  status: number;
  /** The x-correlation-id header. Sophos support asks for it. */
  correlationId: string | null;
  /** The x-request-id header. */
  requestId: string | null;
}

/** A response body with its ResponseMeta. */
export interface MetaResult<T> {
  data: T;
  meta: ResponseMeta;
}

export interface RequestOptions {
  /** HTTP method */
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Query parameters */
  params?: Record<string, string>;
  /** JSON request body */
  body?: unknown;
  /** Additional headers */
  headers?: Record<string, string>;
  /**
   * False for a call that is not safe to repeat, such as starting a scan or
   * running an alert action. A 5xx or a network failure is then not retried,
   * because the first attempt may already have reached Sophos. A 429 is still
   * retried: Sophos turned it away before doing anything. Default true.
   */
  idempotent?: boolean;
}

export class SophosClient {
  constructor(
    private tokenManager: TokenManager,
    private tenantResolver: TenantResolver,
    private fetchImpl: FetchLike = defaultFetch
  ) {}

  /**
   * Make a request to a tenant-scoped API endpoint.
   * Automatically resolves the regional API host for the tenant.
   */
  async tenantRequest<T>(
    tenantId: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<T> {
    return (await this.tenantRequestWithMeta<T>(tenantId, path, options)).data;
  }

  /** tenantRequest, plus the correlation and request IDs Sophos sent back. Writes use it for the audit log. */
  async tenantRequestWithMeta<T>(
    tenantId: string,
    path: string,
    options: RequestOptions = {}
  ): Promise<MetaResult<T>> {
    const apiHost = await this.tenantResolver.resolveApiHost(tenantId);
    const token = await this.tokenManager.getToken();

    const url = buildUrl(apiHost, path, options.params);

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      "X-Tenant-ID": tenantId,
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    };

    const fetchOptions: globalThis.RequestInit = {
      method: options.method || "GET",
      headers,
    };

    if (options.body) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    return this.executeWithRetry<T>(url, fetchOptions, options.idempotent !== false);
  }

  /**
   * Make a request to a global API endpoint (partner/org level).
   */
  async globalRequest<T>(
    path: string,
    options: RequestOptions = {}
  ): Promise<T> {
    const identity = this.tenantResolver.getIdentity();
    const token = await this.tokenManager.getToken();
    const idHeader = this.tenantResolver.getIdHeader();

    const url = buildUrl(identity.apiHosts.global, path, options.params);

    // Some global-host APIs (licensing, accounts, audit, business automation) are
    // scoped by an explicit X-Tenant-ID / X-Distributor-ID header. Sending the
    // caller's identity header alongside those can be rejected, so skip it when
    // the caller provides its own scope header.
    const hasOwnScopeHeader =
      options.headers &&
      Object.keys(options.headers).some((h) =>
        ["x-tenant-id", "x-distributor-id"].includes(h.toLowerCase())
      );

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      ...(hasOwnScopeHeader ? {} : { [idHeader.name]: idHeader.value }),
      ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    };

    const fetchOptions: globalThis.RequestInit = {
      method: options.method || "GET",
      headers,
    };

    if (options.body) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    return (await this.executeWithRetry<T>(url, fetchOptions, options.idempotent !== false)).data;
  }

  private async executeWithRetry<T>(
    url: string,
    options: globalThis.RequestInit,
    retryOnFailure: boolean,
    retries = 2
  ): Promise<MetaResult<T>> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30_000);
        let response: globalThis.Response;
        try {
          response = await this.fetchImpl(url, { ...options, signal: controller.signal });
        } finally {
          clearTimeout(timeout);
        }

        if (response.status === 429) {
          // Rate limited: wait and retry
          const retryAfter = response.headers.get("Retry-After");
          const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
          log().warn(`[sophos-client] Rate limited, waiting ${waitMs}ms (attempt ${attempt + 1})`);
          await this.sleep(waitMs);
          continue;
        }

        if (!response.ok) {
          const errorBody = await response.text();
          let parsed: SophosApiError | null = null;
          try {
            parsed = JSON.parse(errorBody) as SophosApiError;
          } catch {
            // Not JSON
          }

          const msg = parsed
            ? `Sophos API error ${response.status}: ${parsed.error ?? "UnknownError"}${parsed.message ? ` - ${parsed.message}` : ""}${parsed.correlationId ? ` (correlationId: ${parsed.correlationId})` : ""}`
            : `Sophos API error (${response.status}): ${errorBody.slice(0, 500)}`;

          throw new SophosApiRequestError(
            msg,
            response.status,
            parsed?.error ?? null,
            parsed?.correlationId ?? null,
            parsed?.requestId ?? null
          );
        }

        const meta: ResponseMeta = {
          status: response.status,
          correlationId: response.headers.get("x-correlation-id"),
          requestId: response.headers.get("x-request-id"),
        };

        // Some endpoints return 204 No Content
        if (response.status === 204) {
          return { data: {} as T, meta };
        }

        return { data: (await response.json()) as T, meta };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // A redirect gets the same answer every time, and Sophos did nothing
        // with the request. (SecOps Toolkit local modification, 30/10/2026.)
        if (lastError instanceof SophosRedirectError) {
          throw lastError;
        }

        // Don't retry on 4xx client errors (message contains "error NNN:" where NNN is 4xx)
        if (/Sophos API error 4\d\d:/.test(lastError.message)) {
          throw lastError;
        }

        // A call that is not safe to repeat may already have reached Sophos.
        if (!retryOnFailure) {
          throw lastError;
        }

        if (attempt < retries) {
          const backoff = Math.pow(2, attempt) * 1000;
          log().warn(`[sophos-client] Request failed, retrying in ${backoff}ms: ${lastError.message}`);
          await this.sleep(backoff);
        }
      }
    }

    throw lastError || new Error("Request failed after retries");
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
