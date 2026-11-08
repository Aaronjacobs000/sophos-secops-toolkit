// SPDX-License-Identifier: Apache-2.0
/**
 * @notfusion/sophos-core: the Sophos Central REST and Sophos Fusion GraphQL
 * layer for NotFusion. No React, no Node built-ins: it needs only fetch,
 * AbortController, setTimeout and encodeURIComponent, which React Native
 * provides.
 */

import { TokenManager } from "./auth/token-manager.js";
import { FusionClient, type FusionClientOptions } from "./client/fusion-client.js";
import { SophosClient } from "./client/sophos-client.js";
import { TenantResolver } from "./client/tenant-resolver.js";
import { CaseReferenceDataCache } from "./fusion/case-reference-data.js";
import { AlertsService } from "./services/alerts.js";
import { CasesService } from "./services/cases.js";
import { EndpointsService } from "./services/endpoints.js";
import { LegacyCasesService } from "./services/legacy-cases.js";
import { PoliciesService } from "./services/policies.js";
import { SearchService } from "./services/search.js";
import { AiDefenseService } from "./services/ai-defense.js";

export * from "./config.js";
export * from "./logger.js";
export { buildUrl, formEncode, defaultFetch, refuseRedirect, SophosRedirectError, type FetchLike } from "./http.js";
import type { FetchLike } from "./http.js";
export * from "./auth/token-manager.js";
export * from "./client/tenant-resolver.js";
export * from "./client/sophos-client.js";
export * from "./client/fusion-client.js";
export * from "./types/sophos.js";
export * from "./fusion/types.js";
export * from "./fusion/format.js";
export * from "./fusion/cases-ql.js";
export * from "./fusion/case-reference-data.js";
export * from "./fusion/mitre.js";
export * from "./services/alerts.js";
export * from "./services/endpoints.js";
export * from "./services/policies.js";
export * from "./services/cases.js";
export * from "./services/legacy-cases.js";
export * from "./services/search.js";
export * from "./services/ai-defense.js";
export * from "./legacy/cases-v1.js";

export interface SophosCoreOptions {
  clientId: string;
  clientSecret: string;
  /** Fusion GraphQL client options, for example a new `url` when the host changes. */
  fusion?: FusionClientOptions;
  /** The transport every client calls. Defaults to the global fetch. (SecOps Toolkit local modification.) */
  fetch?: FetchLike;
}

/** Everything for one credential profile, sharing one token. */
export interface SophosCore {
  tokens: TokenManager;
  tenants: TenantResolver;
  rest: SophosClient;
  fusion: FusionClient;
  alerts: AlertsService;
  endpoints: EndpointsService;
  policies: PoliciesService;
  /** Cases on either API: CasesService sends a tenant still on cases v1 through legacyCases. */
  cases: CasesService;
  legacyCases: LegacyCasesService;
  /** Search GraphQL (QL Data Lake search). (SecOps Toolkit local modification, 29/10/2026.) */
  search: SearchService;
  /** AI Defense Activity and Policy GraphQL reads. (SecOps Toolkit local modification, 08/11/2026.) */
  aiDefense: AiDefenseService;
}

/**
 * Wires one credential profile. Call `tenants.init()` before anything else:
 * it runs /whoami/v1 and decides whether the profile is a tenant, partner or
 * organization credential.
 */
export function createSophosCore(options: SophosCoreOptions): SophosCore {
  const tokens = new TokenManager(options.clientId, options.clientSecret, options.fetch);
  const tenants = new TenantResolver(tokens, options.fetch);
  const rest = new SophosClient(tokens, tenants, options.fetch);
  const fusion = new FusionClient(tokens, { ...options.fusion, fetch: options.fusion?.fetch ?? options.fetch });
  const legacyCases = new LegacyCasesService(rest);
  const referenceData = new CaseReferenceDataCache(fusion, undefined, (tenantId) => legacyCases.hasAccess(tenantId));
  return {
    tokens,
    tenants,
    rest,
    fusion,
    alerts: new AlertsService(rest),
    endpoints: new EndpointsService(rest),
    policies: new PoliciesService(rest),
    cases: new CasesService(fusion, referenceData, legacyCases),
    legacyCases,
    search: new SearchService(fusion),
    aiDefense: new AiDefenseService(fusion),
  };
}
