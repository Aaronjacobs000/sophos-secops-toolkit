/**
 * Works out what a credential can see from GET /whoami/v1, and so which
 * screens the toolkit shows. Sophos answers idType "tenant" (one tenant, whose
 * regional host comes back in apiHosts.dataRegion), "partner" or
 * "organization" (many tenants, listed through the partner or organization
 * API and then called one by one with X-Tenant-ID).
 */

export type ContextKind = "tenant" | "partner" | "organization";

export interface WhoamiLike {
  id?: unknown;
  idType?: unknown;
  apiHosts?: { global?: unknown; dataRegion?: unknown } | null;
}

export interface AppContext {
  kind: ContextKind;
  /** The tenant, partner or organization ID. */
  id: string;
  /** True for partner and organization credentials. */
  multiTenant: boolean;
  /** The header partner and organization calls carry. */
  idHeader: "X-Tenant-ID" | "X-Partner-ID" | "X-Organization-ID";
  /** The regional API host, for a tenant credential. */
  apiHost: string | null;
  globalHost: string;
  /** Screens that make sense for this context, in nav order. */
  views: string[];
  /** Plain-language name for the header chip. */
  label: string;
}

export class ContextError extends Error {}

const SINGLE_VIEWS = ["front", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas"];
const MULTI_VIEWS = ["front", "msp", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas"];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function host(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !/(^|\.)sophos\.com$/i.test(url.hostname)) return null;
    return `${url.protocol}//${url.host}`;
  } catch {
    return null;
  }
}

export function detectContext(whoami: WhoamiLike | null | undefined): AppContext {
  if (!whoami || typeof whoami !== "object") throw new ContextError("Sophos did not say who this credential is (empty whoami answer).");
  const id = typeof whoami.id === "string" ? whoami.id.trim() : "";
  if (!UUID.test(id)) throw new ContextError("Sophos returned no usable ID for this credential.");
  const globalHost = host(whoami.apiHosts?.global) ?? "https://api.central.sophos.com";
  switch (whoami.idType) {
    case "tenant": {
      const apiHost = host(whoami.apiHosts?.dataRegion);
      if (!apiHost) throw new ContextError("A tenant credential must come with its data region host, and this one did not.");
      return { kind: "tenant", id, multiTenant: false, idHeader: "X-Tenant-ID", apiHost, globalHost, views: SINGLE_VIEWS, label: "Tenant" };
    }
    case "partner":
      return { kind: "partner", id, multiTenant: true, idHeader: "X-Partner-ID", apiHost: null, globalHost, views: MULTI_VIEWS, label: "Partner" };
    case "organization":
      return { kind: "organization", id, multiTenant: true, idHeader: "X-Organization-ID", apiHost: null, globalHost, views: MULTI_VIEWS, label: "Organization" };
    default:
      throw new ContextError(`Unknown credential type ${JSON.stringify(whoami.idType)}. The toolkit supports tenant, partner and organization credentials.`);
  }
}

/** The tenant list path for a multi-tenant context. */
export function tenantListPath(kind: ContextKind): string | null {
  if (kind === "partner") return "/partner/v1/tenants";
  if (kind === "organization") return "/organization/v1/tenants";
  return null;
}
