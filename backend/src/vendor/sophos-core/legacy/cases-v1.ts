// SPDX-License-Identifier: Apache-2.0
/**
 * The legacy Sophos cases API (cases v1, REST under /cases/v1): its record
 * shapes, its fixed reference lists, and the mapping onto the Fusion case
 * shapes the app already shows. A tenant keeps its cases here until it moves
 * to Sophos Fusion cases (customers now; partners from late November 2026 to
 * March 2027). What v1 doesn't hold maps to null or empty, never to an
 * invented value.
 *
 * Source: the cases-v1 OpenAPI spec (1.2.0) on developer.sophos.com and the
 * migration guide beside it, checked against live tenants on 28/09/2026:
 *
 * - List and detail carry `pages.items` (the item count) and `pages.total`
 *   (the page count) without being asked. pageSize is 1 to 50; 100 is a 400.
 * - List filters take comma-separated lists (status=new,investigating).
 * - Some records omit `type` or `severity` (an MDR health check had no type;
 *   older self-managed cases had no severity).
 * - `assignee` is an object whose `name` is an email address, "Unassigned",
 *   or mdr-ops@sophos.com on a case Sophos MDR works.
 * - `overview` is plain text, or HTML on a case Sophos MDR wrote.
 * - A tenant with no XDR or MDR licence answers 403 "Tenant is not allowed to
 *   access cases".
 */

import type {
  FusionCaseDetail,
  FusionCasePrimaryStatus,
  FusionCaseType,
  FusionReferenceItem,
} from "../fusion/types.js";
import type { MitreSummary, MitreTechniqueCount } from "../fusion/mitre.js";

export const LEGACY_CASE_STATUSES = ["new", "investigating", "onHold", "resolved", "actionRequired"] as const;
export type LegacyCaseStatus = (typeof LEGACY_CASE_STATUSES)[number];

export const LEGACY_CASE_SEVERITIES = ["critical", "high", "medium", "low", "informational", "notSet"] as const;
export type LegacyCaseSeverity = (typeof LEGACY_CASE_SEVERITIES)[number];

export const LEGACY_CASE_TYPES = [
  "investigation",
  "incident",
  "hunt",
  "activeThreat",
  "exposure",
  "healthCheck",
  "postureImprovement",
  "customerRequest",
  "duplicate",
  "managedRisk",
  "generalRequest",
] as const;
export type LegacyCaseType = (typeof LEGACY_CASE_TYPES)[number];

export const LEGACY_CASE_VERDICTS = [
  "falsePositive",
  "truePositiveMalicious",
  "truePositiveBenign",
  "truePositive",
  "inconclusive",
] as const;
export type LegacyCaseVerdict = (typeof LEGACY_CASE_VERDICTS)[number];

/** Every status but resolved. actionRequired only ever appears on a case Sophos MDR works. */
export const LEGACY_OPEN_STATUSES: readonly LegacyCaseStatus[] = ["new", "investigating", "onHold", "actionRequired"];

/** The statuses a new case can start in. */
export const LEGACY_CREATE_STATUSES: readonly LegacyCaseStatus[] = ["new", "investigating"];

/** The spec refuses these two on create. */
export const LEGACY_UNCREATABLE_TYPES: readonly LegacyCaseType[] = ["managedRisk", "generalRequest"];

const STATUS_TITLES: Record<LegacyCaseStatus, string> = {
  new: "New",
  investigating: "Investigating",
  onHold: "On hold",
  resolved: "Resolved",
  actionRequired: "Action required",
};

const TYPE_TITLES: Record<LegacyCaseType, string> = {
  investigation: "Investigation",
  incident: "Incident",
  hunt: "Hunt",
  activeThreat: "Active threat",
  exposure: "Exposure",
  healthCheck: "Health check",
  postureImprovement: "Posture improvement",
  customerRequest: "Customer request",
  duplicate: "Duplicate",
  managedRisk: "Managed risk",
  generalRequest: "General request",
};

const VERDICT_TITLES: Record<LegacyCaseVerdict, string> = {
  falsePositive: "False positive",
  truePositiveMalicious: "True positive, malicious",
  truePositiveBenign: "True positive, benign",
  truePositive: "True positive",
  inconclusive: "Inconclusive",
};

/**
 * v1 severity names on the Fusion 2 to 10 scale (the migration guide's own
 * table). notSet has no Fusion value; it maps to 0, below informational.
 */
export const LEGACY_SEVERITY_VALUE: Record<LegacyCaseSeverity, number> = {
  critical: 10,
  high: 8,
  medium: 6,
  low: 4,
  informational: 2,
  notSet: 0,
};

/** The v1 name for a Fusion case severity of 2, 4, 6, 8 or 10. */
export function legacySeverityName(value: number): LegacyCaseSeverity {
  const found = (Object.entries(LEGACY_SEVERITY_VALUE) as Array<[LegacyCaseSeverity, number]>).find(
    ([name, v]) => v === value && name !== "notSet"
  );
  if (!found) {
    throw new Error(
      `The old Sophos cases take severity 2, 4, 6, 8 or 10 (informational, low, medium, high, critical), got ${value}.`
    );
  }
  return found[0];
}

export interface LegacyPrincipal {
  id?: string;
  type?: "user" | "service";
  name?: string;
  accountType?: "partner" | "tenant" | "organization";
  accountId?: string;
}

export interface LegacyMitreAttack {
  tactic?: {
    id?: string;
    name?: string;
    techniques?: Array<{ id?: string; name?: string }>;
  };
}

export interface LegacyCase {
  id: string;
  type?: LegacyCaseType;
  name: string;
  tenant?: { id: string };
  managedBy?: "self" | "sophos";
  createdAt: string;
  createdBy?: LegacyPrincipal;
  resolvedAt?: string;
  updatedAt?: string;
  severity?: LegacyCaseSeverity;
  status: LegacyCaseStatus;
  initialDetection?: { id?: string; severity?: number; type?: string; detectionRule?: string; time?: string };
  assignee?: LegacyPrincipal;
  assignedAt?: string;
  overview?: string;
  detectionCount?: number;
  verdict?: LegacyCaseVerdict;
  escalated?: boolean;
}

export interface LegacyPages {
  current: number;
  size: number;
  /** The number of pages. */
  total?: number;
  /** The number of items across all pages. */
  items?: number;
  maxSize?: number;
}

export interface LegacyCasePage {
  items: LegacyCase[];
  pages: LegacyPages;
}

/**
 * A detection as the case detections endpoint and the detections query both
 * return it. Severity is an integer 0 to 10: not the case scale and not the
 * Fusion detection 0 to 1 score, and the migration guide says not to convert
 * between them.
 */
export interface LegacyDetection {
  id: string;
  detectionRule: string;
  severity: number;
  time: string;
  type: string;
  attackType?: string;
  detectionAttack?: string;
  sensorGeneratedAt?: string;
  sensor?: { id?: string; type?: string; source?: string; name?: string; version?: string };
  device?: { id?: string; type?: string; entity?: string };
  mitreAttacks?: LegacyMitreAttack[];
  ruleDescription?: string;
}

export interface LegacyDetectionPage {
  items: LegacyDetection[];
  pages: LegacyPages;
}

/** A PATCH body. Only these fields exist; v1 has no verdict, close reason, tags or archive to write. */
export interface LegacyCasePatch {
  name?: string;
  severity?: LegacyCaseSeverity;
  status?: LegacyCaseStatus;
  /** An email address, or "Unassigned". */
  assignee?: string;
  overview?: string;
}

export interface LegacyCaseCreate {
  name: string;
  type: LegacyCaseType;
  severity: LegacyCaseSeverity;
  status: LegacyCaseStatus;
  managedBy: "self";
  /** An email address, or "Unassigned". The API refuses a create without one. */
  assignee: string;
  initialDetectionId: string;
  otherDetectionIds?: string[];
  overview?: string;
}

// --- reference data in the Fusion shapes ---

function statusItem(status: string): FusionCasePrimaryStatus {
  const known = STATUS_TITLES[status as LegacyCaseStatus];
  return { id: status, name: status, title: known ?? status, isClosed: status === "resolved" };
}

function typeItem(type: LegacyCaseType): FusionCaseType {
  return {
    id: type,
    name: type,
    title: TYPE_TITLES[type],
    managedBy: null,
    supportedPrimaryStatusIds: [],
    supportedPrimaryVerdictIds: [],
  };
}

function verdictItem(verdict: string): FusionReferenceItem {
  return { id: verdict, name: verdict, title: VERDICT_TITLES[verdict as LegacyCaseVerdict] ?? verdict };
}

/**
 * The v1 types, statuses and verdicts in the shapes the Fusion reference
 * data uses, so the same pickers and filters serve both APIs. Each ID is the
 * v1 value itself.
 */
export const LEGACY_REFERENCE: {
  types: FusionCaseType[];
  primaryStatuses: FusionCasePrimaryStatus[];
  primaryVerdicts: FusionReferenceItem[];
} = {
  types: LEGACY_CASE_TYPES.map(typeItem),
  primaryStatuses: LEGACY_CASE_STATUSES.map(statusItem),
  primaryVerdicts: LEGACY_CASE_VERDICTS.map(verdictItem),
};

/** Matches a v1 value by the value itself or its title, ignoring case. Null when nothing matches. */
export function matchLegacy<T extends string>(values: readonly T[], titles: Record<T, string>, wanted: string): T | null {
  const w = wanted.trim().toLowerCase();
  return values.find((v) => v.toLowerCase() === w) ?? values.find((v) => titles[v].toLowerCase() === w) ?? null;
}

export function legacyStatus(wanted: string): LegacyCaseStatus | null {
  return matchLegacy(LEGACY_CASE_STATUSES, STATUS_TITLES, wanted);
}

export function legacyType(wanted: string): LegacyCaseType | null {
  return matchLegacy(LEGACY_CASE_TYPES, TYPE_TITLES, wanted);
}

export function legacyVerdict(wanted: string): LegacyCaseVerdict | null {
  return matchLegacy(LEGACY_CASE_VERDICTS, VERDICT_TITLES, wanted);
}

// --- validation ---

/** The name rule from the spec: letters, digits, spaces and - , ! ( ) \ / . " ' : ? # $ + _ |, up to 510. */
const LEGACY_NAME_PATTERN = /^[-\p{L}\p{Nl}\d ,!()\\/."':?#$+_|]+$/u;
export const LEGACY_NAME_MAX = 510;

/** Null when the title is a valid v1 case name, or what is wrong with it. */
export function legacyNameProblem(title: string): string | null {
  if (!title.trim()) return "A case name can't be empty.";
  if (title.length > LEGACY_NAME_MAX) return `A case name can be at most ${LEGACY_NAME_MAX} characters.`;
  if (!LEGACY_NAME_PATTERN.test(title)) {
    const bad = [...new Set([...title].filter((ch) => !LEGACY_NAME_PATTERN.test(ch)))].join(" ");
    return `The old Sophos cases allow letters, digits, spaces and - , ! ( ) \\ / . " ' : ? # $ + _ | in a case name. Remove: ${bad}`;
  }
  return null;
}

const LEGACY_DETECTION_ID_PATTERN = /^[a-f0-9_-]{1,150}$/;

export function isLegacyDetectionId(value: string): boolean {
  return LEGACY_DETECTION_ID_PATTERN.test(value);
}

export const LEGACY_OVERVIEW_MAX = 20_000;

// --- mapping ---

const UNASSIGNED = "unassigned";

/** The assignee as the app keeps it: the email (or ID) Sophos names, null when unassigned. */
export function legacyAssignee(principal: LegacyPrincipal | undefined): string | null {
  const value = principal?.name?.trim() || principal?.id?.trim() || "";
  return value && value.toLowerCase() !== UNASSIGNED ? value : null;
}

/**
 * A v1 case in the Fusion detail shape. The v1 case ID stands in for both
 * `id` and `shortId`. Fields v1 has no equivalent for are null, empty or 0,
 * and `legacy` carries what only v1 has.
 */
export function legacyCaseToFusion(c: LegacyCase): FusionCaseDetail {
  const status = statusItem(c.status);
  return {
    id: c.id,
    shortId: c.id,
    title: c.name,
    severity: LEGACY_SEVERITY_VALUE[c.severity ?? "notSet"] ?? 0,
    // A few records have no type (an MDR health check, live 28/09/2026).
    type: c.type ? typeItem(c.type) : { id: "", name: "", title: null },
    primaryStatus: status,
    secondaryStatus: null,
    tags: null,
    assigneeId: legacyAssignee(c.assignee),
    managedBy: c.managedBy === "self" ? "CUSTOMER" : c.managedBy === "sophos" ? "PROVIDER" : null,
    tenantId: c.tenant?.id ?? "",
    createdAt: c.createdAt,
    updatedAt: c.updatedAt ?? c.createdAt,
    closedAt: status.isClosed ? (c.resolvedAt ?? null) : null,
    archivedAt: null,
    riskScore: null,
    keyFindings: null,
    primaryVerdict: c.verdict ? verdictItem(c.verdict) : null,
    secondaryVerdict: null,
    secondaryStatusReason: [],
    closeReason: null,
    closedById: null,
    // A service principal's client ID comes back as `id`, or in `name` on older records.
    createdById: c.createdBy?.id ?? c.createdBy?.name ?? "",
    updatedById: "",
    contributorIds: [],
    incidentAdvisorId: null,
    ruleId: null,
    source: null,
    links: [],
    processingStatus: { assets: null, events: null, detections: null },
    isCreatedByPartner: c.createdBy?.accountType === "partner",
    isCreatedByMDRProvider: false,
    detectionsCount: c.detectionCount ?? 0,
    eventsCount: 0,
    assetsCount: 0,
    legacy: {
      overview: c.overview ?? null,
      escalated: c.escalated ?? null,
      initialDetectionId: c.initialDetection?.id ?? null,
    },
  };
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'" };

/**
 * An overview as plain text. Sophos MDR writes it as HTML (for example
 * "<p>No action required ...</p>"); a self-managed case holds plain text.
 * Block tags become line breaks, other tags go, common entities decode.
 */
export function legacyOverviewText(overview: string | null | undefined): string {
  if (!overview) return "";
  return overview
    .replace(/<\s*br\s*\/?>/gi, "\n")
    .replace(/<\/\s*(p|div|li|h[1-6])\s*>/gi, "\n")
    .replace(/<\s*li[^>]*>/gi, "- ")
    .replace(/<[^>]+>/g, "")
    .replace(/&(amp|lt|gt|quot|apos|nbsp|#39);/g, (_, name: string) => ENTITIES[name] ?? "")
    .split("\n")
    .map((line) => line.replace(/[ \t]+/g, " ").trim())
    .filter((line, index, lines) => line !== "" || (index > 0 && lines[index - 1] !== ""))
    .join("\n")
    .trim();
}

/**
 * The MITRE ATT&CK roll-up across a v1 case's detections, in the same shape
 * and with the same counting as the Fusion one: each technique counts the
 * detections that name it, under every tactic they name it with.
 */
export function legacyMitreSummary(detections: LegacyDetection[]): MitreSummary {
  const techniques = new Map<string, { techniqueId: string; technique: string | null; tactics: Set<string>; detections: Set<string> }>();
  detections.forEach((detection, index) => {
    // Two detections can share an ID with different rules (live, 28/09/2026), so the position keeps them apart.
    const key = `${index}:${detection.id}`;
    for (const attack of detection.mitreAttacks ?? []) {
      const tactic = attack.tactic?.name;
      for (const technique of attack.tactic?.techniques ?? []) {
        if (!technique.id) continue;
        const entry = techniques.get(technique.id) ?? {
          techniqueId: technique.id,
          technique: technique.name ?? null,
          tactics: new Set<string>(),
          detections: new Set<string>(),
        };
        if (tactic) entry.tactics.add(tactic);
        entry.detections.add(key);
        techniques.set(technique.id, entry);
      }
    }
  });
  const byTactic = new Map<string, MitreTechniqueCount[]>();
  const withoutTactic: MitreTechniqueCount[] = [];
  for (const entry of techniques.values()) {
    const row = { techniqueId: entry.techniqueId, technique: entry.technique, detectionCount: entry.detections.size };
    if (entry.tactics.size === 0) withoutTactic.push(row);
    for (const tactic of entry.tactics) byTactic.set(tactic, [...(byTactic.get(tactic) ?? []), row]);
  }
  return {
    detectionCount: detections.length,
    techniqueCount: techniques.size,
    tactics: [...byTactic.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([tactic, list]) => ({ tactic, techniques: list.sort((a, b) => b.detectionCount - a.detectionCount) })),
    techniquesWithoutTactic: withoutTactic,
  };
}
