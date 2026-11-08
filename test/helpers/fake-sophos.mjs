// A fake Sophos for the tests: token, whoami, partner tenant list, and the
// read endpoints the toolkit uses. It records every request it receives, so a
// test can prove what the toolkit sent (and that nothing was a write).

const UUID = (n) => `00000000-0000-4000-a000-${String(n).padStart(12, "0")}`;

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

export function fakeSophos(options = {}) {
  const kind = options.kind ?? "tenant";
  const id = options.id ?? UUID(1);
  const tenants = options.tenants ?? [
    { id: UUID(11), name: "Tenant A", apiHost: "https://api-au01.central.sophos.com", dataRegion: "au01", dataGeography: "AU", billingType: "term", status: "active", products: [{ code: "MDR-COMPLETE" }], contact: { address: { city: "Sydney", countryCode: "AU" } } },
    { id: UUID(12), name: "Tenant B", apiHost: "https://api-us01.central.sophos.com", dataRegion: "us01", dataGeography: "US", billingType: "trial", status: "active", products: [] },
  ];
  const requests = [];
  const now = Date.now();
  const endpoints = options.endpoints ?? [
    { id: UUID(101), hostname: "LT-0001", type: "computer", tenant: { id }, os: { isServer: false, platform: "windows", name: "Windows 11" }, health: { overall: "good", threats: { status: "good" }, services: { status: "good" } }, tamperProtectionEnabled: true, assignedProducts: [{ code: "coreAgent", version: "2026.2.0.2", status: "installed" }], lastSeenAt: new Date(now - 3600_000).toISOString() },
    { id: UUID(102), hostname: "SRV-01", type: "server", tenant: { id }, os: { isServer: true, platform: "windows", name: "Windows Server 2022" }, health: { overall: "bad", threats: { status: "bad" }, services: { status: "good" } }, tamperProtectionEnabled: false, assignedProducts: [{ code: "coreAgent", version: "2025.2.1.1", status: "installed" }], lastSeenAt: new Date(now - 40 * 86_400_000).toISOString() },
  ];
  const handler = async (input, init = {}) => {
    const url = new URL(input);
    const method = (init.method ?? "GET").toUpperCase();
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    let body = null;
    try {
      body = init.body ? JSON.parse(init.body) : null;
    } catch {
      body = init.body ?? null;
    }
    requests.push({ method, host: url.hostname, path: url.pathname, search: url.search, headers, body });
    if (options.failWith429Once && !handler.sent429 && url.hostname !== "id.sophos.com") {
      handler.sent429 = true;
      return json({ error: "TooManyRequests" }, 429, { "Retry-After": "1" });
    }
    if (url.hostname === "id.sophos.com") {
      if (options.badCredential) return json({ errorCode: "INVALID_CLIENT", message: "bad" }, 401);
      return json({ access_token: "fake-access-token-value", token_type: "bearer", expires_in: 3600, errorCode: "success" });
    }
    if (url.pathname === "/whoami/v1") {
      return json({ id, idType: kind, apiHosts: kind === "tenant" ? { global: "https://api.central.sophos.com", dataRegion: "https://api-au01.central.sophos.com" } : { global: "https://api.central.sophos.com" } });
    }
    if (url.pathname === "/partner/v1/tenants" || url.pathname === "/organization/v1/tenants") {
      return json({ pages: { current: 1, size: 50, total: 1, maxSize: 100 }, items: tenants });
    }
    if (url.pathname === "/endpoint/v1/endpoints") return json({ items: endpoints, pages: { size: endpoints.length, maxSize: 500 } });
    if (url.pathname === "/account-health-check/v1/health-check") {
      return json({ endpoint: { protection: { computer: { score: 90, total: 1, notFullyProtected: 0 } }, tamperProtection: { computer: { score: 50, total: 2, disabled: 1 }, server: { score: 100, disabled: 0 } } } });
    }
    if (url.pathname === "/common/v1/alerts") {
      return json({ items: [{ id: "a1", raisedAt: new Date(now - 600_000).toISOString(), severity: "high", category: "malware", product: "endpoint", type: "Event::Endpoint::Threat", description: "Malware found", tenant: { id }, allowedActions: [] }], pages: { items: 1 } });
    }
    if (url.pathname === "/email/v1/smime/ca/internal") {
      if (!options.smimeCa) return json({ error: "ResourceNotFound", errorDetails: [{ code: "SMIME_INTERNAL_CA_NOT_FOUND" }] }, 404);
      return json({ fingerprint: "ab".repeat(32), certificateDetails: { commonName: "Fake CA", expiresAt: options.smimeCa, origin: "created" } });
    }
    if (url.pathname === "/email/v1/smime/users/internal") {
      return json({ items: options.smimeUsers ?? [], pages: { size: (options.smimeUsers ?? []).length, maxSize: 200 } });
    }
    if (url.pathname === "/common/v1/directory/users") {
      const users = [{ id: UUID(201), name: "Pat Example", firstName: "Pat", lastName: "Example", email: "pat@corp.example", exchangeLogin: "pat@corp.example", source: { type: "activeDirectory", domain: "corp.example" }, groups: { total: 2 }, createdAt: "2025-03-01T00:00:00Z", updatedAt: "2026-10-01T00:00:00Z" }];
      const q = (url.searchParams.get("search") ?? "").toLowerCase();
      const items = users.filter((u) => u.name.toLowerCase().includes(q) || u.email.includes(q));
      return json({ items, pages: { current: 1, size: items.length, total: 1, items: items.length } });
    }
    if (url.pathname === "/licenses/v1/licenses") return json({ licenses: [{ product: { code: "MDR-COMPLETE", name: "MDR Complete" }, type: "term", endDate: new Date(now + 5 * 86_400_000).toISOString().slice(0, 10), quantity: 10, usage: { current: { count: 2 } } }] });
    if (url.pathname === "/cases/v1/cases") {
      return json({ items: [{ id: "1-100", type: "investigation", name: "Suspicious login", tenant: { id }, managedBy: "self", createdAt: new Date(now - 30 * 3600_000).toISOString(), updatedAt: new Date(now - 3600_000).toISOString(), severity: "high", status: "investigating", assignee: { name: "Unassigned" } }], pages: { current: 1, size: 50, total: 1, items: 1 } });
    }
    if (url.pathname.startsWith("/xdr-query/v1/queries/runs")) {
      if (method === "POST") return json({ id: "run-1", status: "finished", result: "succeeded" }, 201);
      if (url.pathname.endsWith("/results")) return json({ items: [{ meta_hostname: "lt-0001", meta_public_ip: "203.0.113.9", last_seen: new Date().toISOString() }], pages: { total: 1 } });
      return json({ id: "run-1", status: "finished", result: "succeeded" });
    }
    if (url.hostname === "api.taegis.sophos.com") {
      const q = String(body?.query ?? "");
      if (q.includes("FusionTenantXdrOwnership")) return json({ data: { tenant: { id: body.variables.id, centralTenant: { xdrOwnership: options.xdrOwnership ?? "sophos" } } } });
      if (q.includes("FusionListCases") && /title contains/.test(String(body.variables?.arguments?.query))) {
        const created = new Date(now - 90 * 86_400_000).toISOString();
        return json({ data: { cases: { totalCount: 1, pageInfo: { hasNextPage: false, endCursor: null }, cases: [{ id: UUID(301), shortId: "CSE00301", title: "Impossible travel: pat", severity: 8, primaryStatus: { name: "closed", title: "Closed", isClosed: true }, managedBy: "PROVIDER", createdAt: created, updatedAt: created, closedAt: created, tenantId: id }] } } });
      }
      if (q.includes("FusionListCases")) return json({ data: { cases: { totalCount: 0, pageInfo: { hasNextPage: false, endCursor: null }, cases: [] } } });
      if (q.includes("ToolkitDetectionDetail")) {
        const list = [{ id: "alert://priv:fake:1", status: "OPEN", sensor_types: ["MICROSOFT_GRAPH_SIGN_IN"], attack_technique_ids: ["T1110.003"], metadata: { title: "Password spray", severity: 0.7, created_at: { seconds: Math.floor((now - 3_600_000) / 1000) }, creator: { detector: { detector_name: "Brute force" } } }, source_entities: [{ display_name: "203.0.113.7", subtype: "IpAddress" }], target_entities: [{ display_name: "pat@corp.example", subtype: "User" }, { display_name: "LT-0001", subtype: "Endpoint" }] }];
        return json({ data: { detectionSearch: { status: "OK", reason: "success", alerts: { total_results: list.length, next_offset: 0, list } } } });
      }
      if (q.includes("ToolkitDetectionSearch")) return json({ data: { detectionSearch: { status: "OK", alerts: { total_results: 0, list: [] } } } });
      if (q.includes("ToolkitDetectionCount")) return json({ data: { detectionCountByTenant: { items: [] } } });
      // Search GraphQL: every search completes at once; rows depend on the QL.
      if (/^mutation (CreateSearch|GetOrCreateSearch)\b/.test(q)) {
        const urn = `urn:search:fake:${++handler.searches}`;
        handler.searchText.set(urn, body.variables.input.text);
        const search = { urn, status: "COMPLETE", errors: [], outcome: { success: "ALL", errors: [] }, searchPartitions: [], createTime: new Date().toISOString(), expireTime: new Date(Date.now() + 30 * 86_400_000).toISOString() };
        return json({ data: { [q.startsWith("mutation CreateSearch") ? "createSearch" : "getOrCreateSearch"]: search } });
      }
      if (q.startsWith("query ToolkitAiDefense")) return json(aiDefenseAnswer(q, options.aiDefense ?? "none", body.variables));
      if (q.startsWith("query SearchResults")) {
        const text = handler.searchText.get(body.variables.urn) ?? "";
        return json({ data: { searchResults: { values: searchRows(text), totals: { total: { value: searchRows(text).length } }, nextCursor: null } } });
      }
      return json({ errors: [{ message: "unknown query in fake" }] }, 400);
    }
    return json({ error: "NotFound", path: url.pathname }, 404);
  };
  handler.requests = requests;
  handler.sent429 = false;
  handler.searches = 0;
  handler.searchText = new Map();
  return handler;
}

/** Aggregate rows shaped like the live answers (29/10/2026) for each Search view's QL. */
export function searchRows(ql) {
  if (ql.includes("| aggregate count by source_address")) {
    return [
      { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 4, schema_type: "auth" },
      { source_address: "203.0.113.7", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: true, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 6, schema_type: "auth" },
      { source_address: "10.0.0.5", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: 90, schema_type: "auth" },
    ];
  }
  if (ql.includes("| aggregate count by sensor_type, mfa_used")) {
    return [
      { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: true, application_name: "One Outlook Web", "os.os": "OS_WINDOWS", row_count: 6, schema_type: "auth" },
      { sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, application_name: "One Outlook Web", "os.os": "OS_IPHONE", row_count: 4, schema_type: "auth" },
      { sensor_type: "ENDPOINT_SOPHOS", mfa_used: false, application_name: null, "os.os": "OS_WINDOWS", row_count: 90, schema_type: "auth" },
    ];
  }
  // The reports' user investigation searches.
  if (ql.includes("aggregate count, min(event_time_usec), max(event_time_usec) by target_user_name")) {
    const at = Date.now() * 1000;
    return [
      { target_user_name: "pat@corp.example", source_user_name: "", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", logon_type: "INTERACTIVE", mfa_used: false, application_name: "Exchange Online", source_address: "203.0.113.7", host_id: "", row_count: 3, min_event_time_usec: at - 7.2e9, max_event_time_usec: at - 3.6e9, schema_type: "auth" },
      { target_user_name: "pat", source_user_name: "", sensor_type: "SOPHOS_SFOS", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", logon_type: "NETWORK", mfa_used: false, application_name: "SSL VPN", source_address: "198.51.100.9", host_id: "", row_count: 2, min_event_time_usec: at - 7.2e9, max_event_time_usec: at - 3.6e9, schema_type: "auth" },
      { target_user_name: "pat", source_user_name: "", sensor_type: "ENDPOINT_SOPHOS", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", logon_type: "INTERACTIVE", mfa_used: false, application_name: "", source_address: "10.0.0.5", host_id: UUID(101), row_count: 5, min_event_time_usec: at - 7.2e9, max_event_time_usec: at - 3.6e9, schema_type: "auth" },
    ];
  }
  if (ql.includes("| fields event_time_usec, target_user_name")) return [{ event_time_usec: Date.now() * 1000 - 3.6e9, target_user_name: "pat", sensor_type: "ENDPOINT_SOPHOS", action_result: "SUCCESS", logon_type: "INTERACTIVE", mfa_used: false, host_id: UUID(101), schema_type: "auth" }];
  if (ql.includes("| aggregate count by target_user_name")) return [{ target_user_name: "user@example.com", sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: 4, schema_type: "auth" }];
  if (ql.includes("max(event_time_usec) by sensor_type, 1d")) {
    const day = new Date().toISOString().slice(0, 10);
    return [{ sensor_type: "ENDPOINT_SOPHOS", schema_type: "process", event_time_usec_1d: `${day} 00:00:00`, row_count: 120, max_event_time_usec: Date.now() * 1000 }];
  }
  return [];
}

// AI Defense answers, shaped like the live ones (08/11/2026). Figures are invented.
const COUNT = (n) => ({ totalCount: n });
const ZERO_SUMMARY = {
  apps: { totalApps: 0, criticalRisk: 0, highRisk: 0, mediumRisk: 0, lowRisk: 0, infoRisk: 0, unknownRisk: 0, errorRisk: 0, trainsOnData: 0, unsanctionedCount: 0 },
  users: { totalUsers: 0, criticalRisk: 0, highRisk: 0, mediumRisk: 0, lowRisk: 0, infoRisk: 0, unknownRisk: 0, withViolations: 0, unsanctionedCount: 0 },
};
const ZERO_COUNTS = Object.fromEntries(["all", "unsanctioned", "blocked", "warned", ...["blocked", "warned"].flatMap((a) => ["Critical", "High", "Medium", "Low", "Info"].map((r) => `${a}${r}`))].map((k) => [k, COUNT(0)]));

export const AI_OVERVIEW_ACTIVE = {
  secureAITenantSettings: { onboarding: { status: "COMPLETED" }, licenseState: "ACTIVE", licenseType: "TERM", licenseExpiryDate: "2030-01-31T23:59:59.999Z", gracePeriodEndsAt: "2030-03-01T23:59:59.999Z" },
  inventorySummary: {
    apps: { totalApps: 12, criticalRisk: 2, highRisk: 1, mediumRisk: 1, lowRisk: 7, infoRisk: 0, unknownRisk: 0, errorRisk: 1, trainsOnData: 3, unsanctionedCount: 2 },
    users: { totalUsers: 30, criticalRisk: 2, highRisk: 3, mediumRisk: 0, lowRisk: 25, infoRisk: 0, unknownRisk: 0, withViolations: 5, unsanctionedCount: 4 },
  },
  ...ZERO_COUNTS,
  all: COUNT(5000),
  unsanctioned: COUNT(40),
  blocked: COUNT(410),
  blockedCritical: COUNT(300),
  blockedHigh: COUNT(50),
  blockedLow: COUNT(50),
  warned: COUNT(900),
  warnedCritical: COUNT(20),
  warnedLow: COUNT(870),
};

export const AI_DETAIL = {
  appInventory: {
    totalCount: 12,
    entries: [
      { id: "chatgpt", name: "ChatGPT", provider: "OpenAI", risk: "LOW", usage: 2100, uniqueUsers: 22, lastSeen: "2026-11-08T01:00:00Z", unsanctionedCount: 0 },
      { id: "deepseek", name: "DeepSeek", provider: "DeepSeek", risk: "CRITICAL", usage: 310, uniqueUsers: 3, lastSeen: "2026-11-07T22:10:00.123456Z", unsanctionedCount: 0 },
      { id: "newapp", name: "New App", provider: "", risk: "ERROR", usage: 4, uniqueUsers: 1, lastSeen: null, unsanctionedCount: 4 },
    ],
  },
  userInventory: {
    totalCount: 30,
    entries: [
      { id: "S-1-5-21-1004", name: "pat@corp.example", risk: "CRITICAL", appsUsed: 5, usage: 900, policyViolations: 320, topApp: "ChatGPT", lastSeen: "2026-11-08T01:00:00Z", unsanctionedCount: 0 },
      { id: "203.0.113.5", name: "203.0.113.5", risk: "LOW", appsUsed: 1, usage: 12, policyViolations: 0, topApp: null, lastSeen: "2026-11-07T10:00:00Z", unsanctionedCount: 2 },
    ],
  },
  activities: {
    totalCount: 1310,
    activities: [
      { timestamp: { startTime: "2026-11-08T01:00:00.5Z" }, actor: { name: "pat@corp.example", type: "USER" }, application: { id: "deepseek", name: "DeepSeek" }, action: "BLOCKED", policy: "Block high-risk AI", device: { name: "LT-0001", platform: "WINDOWS" }, risk: "CRITICAL", aggregationCount: 3 },
      { timestamp: { startTime: "2026-11-08T00:30:00Z" }, actor: { name: "", type: "NETWORK_ENTITY" }, application: { id: "chatgpt", name: "ChatGPT" }, action: "WARNED", policy: "", device: { name: "", platform: "UNKNOWN" }, risk: "LOW", aggregationCount: 1 },
      { timestamp: { startTime: "2026-11-08T00:20:00Z" }, actor: { name: "pat@corp.example", type: "USER" }, application: { id: "chatgpt", name: "ChatGPT" }, action: "ALLOWED", policy: "", device: { name: "LT-0001", platform: "WINDOWS" }, risk: "LOW", aggregationCount: 1 },
    ],
  },
};

/** Blocked and warned for each app id and actor id the flow read asks about; anything else counts 0. */
export const AI_FLOW_COUNTS = {
  apps: { chatgpt: [0, 860], deepseek: [300, 10], newapp: [0, 0] },
  users: { "S-1-5-21-1004": [300, 20], "203.0.113.5": [0, 0] },
};

function aiFlowAnswer(variables = {}) {
  const data = {};
  for (let i = 0; i < 10; i++) {
    const [ab, aw] = AI_FLOW_COUNTS.apps[variables[`app${i}`]] ?? [0, 0];
    const [ub, uw] = AI_FLOW_COUNTS.users[variables[`user${i}`]] ?? [0, 0];
    Object.assign(data, { [`app${i}Blocked`]: COUNT(ab), [`app${i}Warned`]: COUNT(aw), [`user${i}Blocked`]: COUNT(ub), [`user${i}Warned`]: COUNT(uw) });
  }
  return { data };
}

/** The body Fusion answers an AI Defense read with. mode: active, allowed-only (nothing blocked or warned), none (never set up), expired, policies-denied, denied. */
export function aiDefenseAnswer(query, mode = "none", variables = {}) {
  const denied = { errors: [{ message: "permission denied: missing SecureAI read", path: ["secureAITenantSettings"], extensions: { code: "FORBIDDEN" } }], data: null };
  if (mode === "denied") return denied;
  if (query.startsWith("query ToolkitAiDefensePolicies")) {
    if (mode === "policies-denied") return { errors: [{ message: "permission denied", path: ["policies"], extensions: { code: "FORBIDDEN" } }], data: null };
    return { data: { policies: mode === "none" ? { totalCount: 0, enabledCount: 0, failedCount: 0 } : { totalCount: 5, enabledCount: 2, failedCount: 1 } } };
  }
  if (query.startsWith("query ToolkitAiDefenseDetail")) return { data: AI_DETAIL };
  if (query.startsWith("query ToolkitAiDefenseFlow")) return aiFlowAnswer(variables);
  if (mode === "allowed-only") return { data: { ...AI_OVERVIEW_ACTIVE, ...ZERO_COUNTS, all: COUNT(5000) } };
  if (mode === "none") return { data: { secureAITenantSettings: null, inventorySummary: ZERO_SUMMARY, ...ZERO_COUNTS } };
  if (mode === "expired") return { data: { secureAITenantSettings: { onboarding: { status: "COMPLETED" }, licenseState: "EXPIRED", licenseType: "TRIAL", licenseExpiryDate: "2026-10-01T23:59:59.999Z", gracePeriodEndsAt: null }, inventorySummary: ZERO_SUMMARY, ...ZERO_COUNTS } };
  return { data: AI_OVERVIEW_ACTIVE };
}

export { UUID };
