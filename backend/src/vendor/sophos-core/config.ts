// SPDX-License-Identifier: Apache-2.0
/**
 * Fixed Sophos endpoints and page sizes. The MCP server read overrides from
 * process.env; there is no process.env in React Native, so an override is
 * passed as an option instead (FusionClient takes `url`).
 */

export const SOPHOS_AUTH_URL = "https://id.sophos.com/api/v2/oauth2/token";
export const SOPHOS_GLOBAL_API = "https://api.central.sophos.com";

/**
 * Sophos Fusion GraphQL endpoint. One host for every tenant, no regional
 * lookup. The host is expected to change to a Fusion branded name in November
 * 2026; FusionClient's `url` option takes the new one without a code change.
 */
export const SOPHOS_FUSION_GRAPHQL_URL = "https://api.taegis.sophos.com/graphql";

export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 100;
