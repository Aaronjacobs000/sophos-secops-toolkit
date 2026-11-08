/**
 * Pure mappers from Sophos API answers to the toolkit's records. No I/O here:
 * the tests feed them recorded and hand-built answers.
 */

import type {
  AlertRecord,
  CaseRecord,
  DetectionRecord,
  EndpointRecord,
  Generation,
  HealthRecord,
  LicenceRecord,
  Severity,
  SmimeCert,
  SmimeRecord,
  TenantRecord,
} from "../data/types.js";

type Json = Record<string, unknown>;

function obj(v: unknown): Json {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : {};
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}

function num(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

/** A partner or organization tenant record. */
export function mapTenant(raw: unknown): TenantRecord | null {
  const t = obj(raw);
  const id = str(t.id);
  const apiHost = str(t.apiHost);
  if (!id || !apiHost) return null;
  const contact = obj(t.contact);
  const address = obj(contact.address);
  const products = Array.isArray(t.products) ? t.products.map((p) => str(obj(p).code)).filter((c): c is string => !!c) : [];
  return {
    id,
    name: str(t.showAs) ?? str(t.name) ?? id,
    apiHost,
    dataRegion: str(t.dataRegion) ?? "unknown",
    billingType: str(t.billingType),
    status: str(t.status),
    products,
    city: str(address.city),
    countryCode: str(address.countryCode),
  };
}

/** xdrOwnership "sophos" means Sophos Central still holds the tenant's XDR data (cases v1); anything else is Fusion. */
export function mapGeneration(xdrOwnership: string | null | undefined): Generation {
  if (typeof xdrOwnership !== "string" || !xdrOwnership.trim()) return "unknown";
  return xdrOwnership.trim().toLowerCase() === "sophos" ? "classic" : "fusion";
}

export function mapEndpoint(raw: unknown): EndpointRecord | null {
  const e = obj(raw);
  const id = str(e.id);
  if (!id) return null;
  const os = obj(e.os);
  const health = obj(e.health);
  const products = Array.isArray(e.assignedProducts) ? e.assignedProducts.map(obj) : [];
  // coreAgent carries the agent release (2026.2 and so on) on every platform;
  // the Windows endpointProtection component still reports 10.8.x.
  const protection = products.find((p) => p.code === "coreAgent") ?? products.find((p) => p.code === "endpointProtection") ?? products[0];
  return {
    id,
    hostname: str(e.hostname) ?? id.slice(0, 8),
    type: str(e.type) ?? "computer",
    platform: (str(os.platform) ?? "unknown").toLowerCase(),
    osName: str(os.name) ?? str(os.platform) ?? "Unknown OS",
    isServer: os.isServer === true || e.type === "server",
    health: (str(health.overall) ?? "unknown").toLowerCase(),
    threats: str(obj(health.threats).status),
    services: str(obj(health.services).status),
    tamper: typeof e.tamperProtectionEnabled === "boolean" ? e.tamperProtectionEnabled : null,
    lastSeenAt: str(e.lastSeenAt),
    agentVersion: protection ? str(protection.version) : null,
    products: products.map((p) => str(p.code)).filter((c): c is string => !!c),
    isolation: str(obj(e.isolation).status),
    group: str(e.groupName),
    person: str(obj(e.associatedPerson).viaLogin) ?? str(obj(e.associatedPerson).name),
  };
}

const CASE_SEVERITY: Record<number, Severity> = { 10: "critical", 8: "high", 6: "medium", 4: "low", 2: "info" };

/** Case severity on the 2 to 10 scale (Fusion) or a v1 name. */
export function caseSeverity(value: unknown): Severity | "unset" {
  if (typeof value === "number") {
    if (CASE_SEVERITY[value]) return CASE_SEVERITY[value]!;
    if (value >= 9) return "critical";
    if (value >= 7) return "high";
    if (value >= 5) return "medium";
    if (value >= 3) return "low";
    if (value > 0) return "info";
    return "unset";
  }
  if (typeof value === "string") {
    const v = value.toLowerCase();
    if (v === "informational") return "info";
    if (["critical", "high", "medium", "low", "info"].includes(v)) return v as Severity;
  }
  return "unset";
}

/** Fusion detection severity is 0 to 1. Bands follow the Fusion console. */
export function detectionSeverity(value: unknown): Severity {
  const n = num(value) ?? 0;
  if (n >= 0.8) return "critical";
  if (n >= 0.6) return "high";
  if (n >= 0.4) return "medium";
  if (n >= 0.2) return "low";
  return "info";
}

/** A case in the shape sophos-core returns for both APIs (FusionCaseSummary, or a v1 case mapped to it). */
export function mapCase(raw: unknown, api: "v1" | "v2"): CaseRecord | null {
  const c = obj(raw);
  const id = str(c.id);
  if (!id) return null;
  const primary = obj(c.primaryStatus);
  const secondary = obj(c.secondaryStatus);
  const type = obj(c.type);
  const managed = c.managedBy === "PROVIDER" ? "mdr" : c.managedBy === "CUSTOMER" ? "self" : null;
  const closedAt = str(c.closedAt);
  return {
    id,
    ref: str(c.shortId) ?? id,
    title: (str(c.title) ?? "(untitled case)").trim(),
    severity: caseSeverity(c.severity),
    status: str(primary.name) ?? "unknown",
    statusTitle: str(primary.title) ?? str(primary.name) ?? "Unknown",
    closed: primary.isClosed === true || (!!closedAt && primary.isClosed !== false),
    secondary: str(secondary.name),
    managedBy: managed,
    assigneeId: str(c.assigneeId),
    createdAt: str(c.createdAt) ?? new Date(0).toISOString(),
    updatedAt: str(c.updatedAt) ?? str(c.createdAt) ?? new Date(0).toISOString(),
    closedAt,
    type: str(type.name) ?? "",
    tenantId: str(c.tenantId) ?? "",
    api,
  };
}

export function mapDetection(raw: unknown): DetectionRecord | null {
  const d = obj(raw);
  const id = str(d.id);
  if (!id) return null;
  const meta = obj(d.metadata);
  const created = obj(meta.created_at);
  const seconds = num(created.seconds);
  const detector = obj(obj(obj(meta.creator).detector));
  return {
    id,
    createdAt: seconds ? seconds * 1000 : 0,
    severity: detectionSeverity(meta.severity),
    detector: str(detector.detector_name),
    sensorTypes: Array.isArray(d.sensor_types) ? d.sensor_types.filter((s): s is string => typeof s === "string") : [],
    techniques: Array.isArray(d.attack_technique_ids) ? d.attack_technique_ids.filter((s): s is string => typeof s === "string") : [],
    status: str(d.status),
  };
}

const NAMED_ENTITIES: Record<string, string> = { quot: '"', amp: "&", lt: "<", gt: ">", apos: "'" };

/** Alert descriptions arrive HTML-escaped (`firmware &quot;1.10.3192&quot;`); decoded in one pass, so `&amp;quot;` stays `&quot;`. */
function unescapeHtml(text: string): string {
  return text.replace(/&(?:(quot|amp|lt|gt|apos)|#(\d{1,7})|#x([0-9a-f]{1,6}));/gi, (whole, name: string | undefined, dec: string | undefined, hex: string | undefined) => {
    if (name) return NAMED_ENTITIES[name.toLowerCase()] ?? whole;
    const code = dec ? Number(dec) : parseInt(hex!, 16);
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

export function mapAlert(raw: unknown): AlertRecord | null {
  const a = obj(raw);
  const id = str(a.id);
  if (!id) return null;
  return {
    id,
    raisedAt: str(a.raisedAt) ?? new Date(0).toISOString(),
    severity: (str(a.severity) ?? "low").toLowerCase(),
    category: str(a.category) ?? "other",
    product: str(a.product) ?? "other",
    type: str(a.type) ?? "",
    description: unescapeHtml(str(a.description) ?? "").slice(0, 240),
  };
}

/**
 * The account health check. Sophos returns a score per section and no overall
 * score, so `overall` is the plain average of the section scores present
 * (protection, policy, exclusions, tamper protection), labelled as such.
 */
export function mapHealth(raw: unknown): HealthRecord {
  const h = obj(raw);
  const endpoint = obj(h.endpoint);
  const sections: Record<string, number> = {};
  const scores = (node: unknown): number[] => {
    const out: number[] = [];
    const walk = (v: unknown, depth: number) => {
      if (depth > 4) return;
      const o = obj(v);
      const s = num(o.score);
      if (s !== null && o.snoozed !== true) out.push(s);
      for (const [k, child] of Object.entries(o)) if (k !== "score" && typeof child === "object") walk(child, depth + 1);
    };
    walk(node, 0);
    return out;
  };
  const avg = (xs: number[]) => (xs.length ? Math.round(xs.reduce((a, b) => a + b, 0) / xs.length) : null);
  for (const key of ["protection", "policy", "exclusions", "tamperProtection"]) {
    const s = avg(scores(endpoint[key]));
    if (s !== null) sections[key] = s;
  }
  const values = Object.values(sections);
  const tamper = obj(endpoint.tamperProtection);
  const protection = obj(endpoint.protection);
  return {
    overall: values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : null,
    sections,
    tamperDisabled: (num(obj(tamper.computer).disabled) ?? 0) + (num(obj(tamper.server).disabled) ?? 0),
    notFullyProtected: (num(obj(protection.computer).notFullyProtected) ?? 0) + (num(obj(protection.server).notFullyProtected) ?? 0),
  };
}

export function mapLicence(raw: unknown): LicenceRecord | null {
  const l = obj(raw);
  const product = obj(l.product);
  const code = str(product.code) ?? str(l.licenseCode);
  if (!code) return null;
  return {
    code,
    name: str(product.name) ?? code,
    type: str(l.type) ?? "unknown",
    endDate: l.perpetual === true ? null : str(l.endDate),
    quantity: l.unlimited === true ? null : num(l.quantity),
    used: num(obj(obj(l.usage).current).count),
  };
}

/** GET /email/v1/smime/ca/internal: the internal CA's name, expiry and origin. */
export function mapSmimeCa(raw: unknown): SmimeRecord["ca"] {
  const details = obj(obj(raw).certificateDetails);
  if (!Object.keys(details).length && !str(obj(raw).fingerprint)) return null;
  return { commonName: str(details.commonName), expiresAt: str(details.expiresAt), origin: str(details.origin) };
}

/**
 * GET /email/v1/smime/users/internal items: one entry per user, carrying the
 * certificate that expires last. A user can hold two certificates so a
 * replacement goes in before the old one ends; when the answer lists both,
 * the later one is what counts. When it lists only the certificates that
 * matched the expiry filter, the earlier one is all there is to go on.
 */
export function mapSmimeUsers(items: unknown[]): SmimeCert[] {
  const out: SmimeCert[] = [];
  for (const item of items) {
    const u = obj(item);
    const email = str(u.email);
    if (!email) continue;
    const certs = Array.isArray(u.associatedCertificatesInfo) ? u.associatedCertificatesInfo : [];
    let latest: string | null = null;
    for (const c of certs) {
      const at = str(obj(obj(c).certificateDetails).expiresAt);
      if (at && Number.isFinite(Date.parse(at)) && (!latest || Date.parse(at) > Date.parse(latest))) latest = at;
    }
    if (latest) out.push({ email, userName: str(u.userName), expiresAt: latest });
  }
  return out;
}
