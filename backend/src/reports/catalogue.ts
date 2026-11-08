/**
 * The reports the module offers, what each needs, and the windows each can
 * cover. A window marked allTenants:false reads Sophos again for one tenant;
 * the others come from the dashboard cache and cost no calls.
 */

import type { ReportId } from "./types.js";

export interface WindowOption {
  key: string;
  label: string;
  hours: number;
  /** Offered with "All tenants" selected. */
  allTenants: boolean;
}

export type ReportInput = "user" | "match" | "schemas" | "sensors" | "groupBy";

export interface ReportDefinition {
  id: ReportId;
  title: string;
  summary: string;
  audience: string;
  /** One tenant only, or one tenant or all tenants. */
  scope: "tenant" | "any";
  /** required: nothing without Sophos Fusion. partial: some sections need it. */
  fusion: "required" | "partial" | "no";
  windows: WindowOption[] | null;
  defaultWindow: string | null;
  inputs: ReportInput[];
  apis: string;
  /** What it answers, for the catalogue card. */
  shows: string[];
}

const W = {
  h1: { key: "1h", label: "Last hour", hours: 1, allTenants: false },
  h24: { key: "24h", label: "Last 24 hours", hours: 24, allTenants: true },
  d7: { key: "7d", label: "Last 7 days", hours: 168, allTenants: true },
  d30: { key: "30d", label: "Last 30 days", hours: 720, allTenants: false },
  d30all: { key: "30d", label: "Last 30 days", hours: 720, allTenants: true },
} as const;

export const REPORTS: ReportDefinition[] = [
  {
    id: "user",
    title: "User investigation",
    summary: "Everything one person did: who they are, where and how they signed in (VPN and Microsoft 365 included), the devices they used, and the detections and cases that name them.",
    audience: "Analysts and incident responders",
    scope: "tenant",
    fusion: "partial",
    windows: [{ ...W.h24, allTenants: false }, { ...W.d7, allTenants: false }, W.d30],
    defaultWindow: "7d",
    inputs: ["user"],
    apis: "Directory API, Search GraphQL (5 searches), Detections v2, Cases v2, Endpoint API (cached)",
    shows: ["Directory record and accounts seen", "Sign-ins by source, result, MFA and place", "VPN and Microsoft 365 activity", "Detections and cases naming the user", "Activity by event type"],
  },
  {
    id: "logsearch",
    title: "Log search export",
    summary: "Every event for a user, IP address or device across the event types you choose, with a timeline, a group-by breakdown and the newest events as rows.",
    audience: "Analysts",
    scope: "tenant",
    fusion: "required",
    windows: [W.h1, { ...W.h24, allTenants: false }, { ...W.d7, allTenants: false }, W.d30],
    defaultWindow: "24h",
    inputs: ["match", "schemas", "sensors", "groupBy"],
    apis: "Search GraphQL: a timeline and a group-by search, then one search per four event types with events for the rows",
    shows: ["Events over time by event type", "Top values for the field you group by", "The newest events, exported in full to CSV"],
  },
  {
    id: "executive",
    title: "Executive summary",
    summary: "One page per estate on what happened and what needs a decision: signals, cases and how fast they closed, device health, identity and data sources, and AI use under AI Defense.",
    audience: "IT and business leaders, MSP account reviews",
    scope: "any",
    fusion: "partial",
    windows: [W.d7, W.d30],
    defaultWindow: "7d",
    inputs: [],
    apis: "Cached cases, detections, alerts, endpoints, health check, licences, Search GraphQL and AI Defense datasets; 30 days for one tenant rereads detections and alerts",
    shows: ["Headline figures and what changed", "Cases opened and closed, time to close", "Device health and coverage", "AI Defense: blocked and warned AI activity by risk, top AI apps and users", "Per-tenant table for partners"],
  },
  {
    id: "cases",
    title: "Case activity and response times",
    summary: "Cases opened and closed, who worked them, how long they took against your targets, and the open cases most over target.",
    audience: "SOC managers",
    scope: "any",
    fusion: "no",
    windows: [W.d7, W.d30all],
    defaultWindow: "30d",
    inputs: [],
    apis: "Cases v2 (Fusion) or cases v1 (Classic), cached",
    shows: ["Opened and closed per day", "Time to close by severity and by MDR or your team", "Open cases over target", "Closed cases in the window"],
  },
  {
    id: "detections",
    title: "Detections and alerts",
    summary: "Detection volume and trend by severity, the detections, users, devices and addresses seen most, MITRE ATT&CK techniques, and product alerts.",
    audience: "Analysts and SOC managers",
    scope: "any",
    fusion: "partial",
    windows: [W.h24, W.d7, W.d30],
    defaultWindow: "7d",
    inputs: [],
    apis: "Detections v2 (one tenant: read now, with titles and entities; all tenants: cached), Common alerts API",
    shows: ["Per day by severity", "Top detections, users, devices and IPs", "MITRE ATT&CK techniques", "Product alerts by category"],
  },
  {
    id: "endpoints",
    title: "Endpoint health and agent coverage",
    summary: "Every device's health, how many are stale, unprotected or on an old agent, and the devices to fix first.",
    audience: "IT operations",
    scope: "any",
    fusion: "no",
    windows: null,
    defaultWindow: null,
    inputs: [],
    apis: "Endpoint API, health check, licences (cached)",
    shows: ["Health, staleness and tamper protection", "Agent versions behind", "Devices to fix first", "Every device in the CSV"],
  },
  {
    id: "signins",
    title: "Sign-ins and MFA",
    summary: "Where sign-ins came from, why they failed, and the successful sign-ins that used no MFA, by app, OS, place and user.",
    audience: "Identity and security owners",
    scope: "any",
    fusion: "required",
    windows: [W.d7],
    defaultWindow: "7d",
    inputs: [],
    apis: "Search GraphQL datasets the Sign-ins screen keeps (cached)",
    shows: ["Sign-ins, failures and reasons", "Without MFA by app, OS and user", "Places"],
  },
  {
    id: "sources",
    title: "Data source health",
    summary: "Which data sources sent events, how many, when each last spoke, and how much arrived unparsed.",
    audience: "SIEM and platform owners",
    scope: "any",
    fusion: "required",
    windows: [W.d7],
    defaultWindow: "7d",
    inputs: [],
    apis: "Search GraphQL dataset the Sources screen keeps (cached)",
    shows: ["Sources live, quiet and silent", "Events per day", "Unparsed volume"],
  },
];

export function reportDefinition(id: string): ReportDefinition | null {
  return REPORTS.find((r) => r.id === id) ?? null;
}

/** Reports other platforms offer that this module does not build, and why. Shown in the catalogue. */
export const NOT_BUILT: Array<{ title: string; reason: string }> = [
  { title: "Vulnerability and exposure", reason: "No Sophos API returns vulnerability findings (Managed Risk has no API)." },
  { title: "Firewall traffic and web activity", reason: "Firewall Reporting (CFR) has its own reports and no API; Sophos Fusion holds only the firewall events sent to it." },
  { title: "Identity threat posture (ITDR)", reason: "No ITDR API on the Sophos developer portal." },
  { title: "Email and licence usage summaries", reason: "Sophos Fusion already offers these as scheduled reports (Logs & Reports)." },
  { title: "Admin audit trail", reason: "Possible through the audit events API; planned for a later release." },
  { title: "Asset (device) investigation", reason: "Possible with the same searches as the user report; planned for a later release. The log search export covers a device today." },
];
