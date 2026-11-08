/**
 * The trimmed records the toolkit caches. Each fetcher maps a Sophos answer
 * to one of these, so the mappers and the screens never see raw API shapes,
 * and the cache holds only the fields the screens use.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Generation = "fusion" | "classic" | "unknown";

export interface TenantRecord {
  id: string;
  name: string;
  apiHost: string;
  dataRegion: string;
  billingType: string | null;
  status: string | null;
  products: string[];
  city: string | null;
  countryCode: string | null;
}

export interface GenerationRecord {
  generation: Generation;
  /** The tenant record's xdrOwnership, or null when it could not be read. */
  xdrOwnership: string | null;
}

export interface EndpointRecord {
  id: string;
  hostname: string;
  type: string;
  platform: string;
  osName: string;
  isServer: boolean;
  health: string;
  threats: string | null;
  services: string | null;
  tamper: boolean | null;
  lastSeenAt: string | null;
  agentVersion: string | null;
  products: string[];
  isolation: string | null;
  group: string | null;
  person: string | null;
}

export interface CaseRecord {
  id: string;
  ref: string;
  title: string;
  severity: Severity | "unset";
  status: string;
  statusTitle: string;
  closed: boolean;
  secondary: string | null;
  managedBy: "mdr" | "self" | null;
  assigneeId: string | null;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  type: string;
  tenantId: string;
  api: "v1" | "v2";
}

export interface CaseSet {
  api: "v1" | "v2" | "none";
  open: CaseRecord[];
  recentClosed: CaseRecord[];
  /** True when more open cases exist than were read. */
  truncated: boolean;
  warnings: string[];
}

export interface DetectionRecord {
  id: string;
  createdAt: number;
  severity: Severity;
  detector: string | null;
  sensorTypes: string[];
  techniques: string[];
  status: string | null;
}

export interface DetectionSet {
  windowHours: number;
  /** total_results from Sophos for the window. */
  total: number;
  items: DetectionRecord[];
  /** True when the window held more detections than were read. */
  sampled: boolean;
  /** When sampled: the oldest record read, so charts claim only the hours covered. */
  coveredFrom?: number | null;
  count30d: number | null;
}

export interface AlertRecord {
  id: string;
  raisedAt: string;
  severity: string;
  category: string;
  product: string;
  type: string;
  description: string;
}

export interface AlertSet {
  sinceHours: number;
  total: number;
  items: AlertRecord[];
}

export interface HealthRecord {
  /** Average of the section scores Sophos returned, 0 to 100. Sophos returns no overall score. */
  overall: number | null;
  sections: Record<string, number>;
  tamperDisabled: number;
  notFullyProtected: number;
}

export interface LicenceRecord {
  code: string;
  name: string;
  type: string;
  endDate: string | null;
  quantity: number | null;
  used: number | null;
}

export interface EgressHost {
  hostname: string;
  ip: string;
}

export interface GeoPoint {
  city: string | null;
  country: string | null;
  lat: number;
  lon: number;
  source: "sophos" | "dbip";
}

export interface EgressSet {
  hosts: EgressHost[];
  geo: Record<string, GeoPoint>;
  /** IPs with no location from Sophos or DB-IP. */
  unplaced: string[];
  /** What the Data Lake answered, for the gap labels. */
  notes: string[];
}

export interface CaseStatusSnapshot {
  /** case id -> status name */
  statuses: Record<string, string>;
}

export interface EndpointSnapshot {
  total: number;
  bad: number;
  suspicious: number;
  stale7: number;
  tamperOff: number;
}

/** How a Search GraphQL dataset was read, for the screens' badges and the tests. */
export interface SearchMeta {
  ranAt: number;
  /** getOrCreateSearch handed back a search already running or finished. */
  reused: boolean;
  /** PARTIAL: some partitions (output schemas) failed and their rows are missing. */
  outcome: "ALL" | "PARTIAL";
  failedSchemas: string[];
  rows: number;
  /** More rows existed than the toolkit reads. */
  truncated: boolean;
  calls: number;
}

export interface SigninLocation {
  key: string;
  city: string | null;
  country: string | null;
  lat: number;
  lon: number;
  source: "sophos" | "dbip";
  total: number;
  failed: number;
  /** Successful interactive user sign-ins without MFA, counted only for sources that report MFA. */
  noMfa: number;
}

/** X10: sign-ins by result, reason, source and location (auth schema, last 7 days). */
export interface SigninSet {
  windowStart: number;
  windowEnd: number;
  total: number;
  success: number;
  failed: number;
  bySource: Array<{ sensorType: string; total: number; failed: number; reportsMfa: boolean }>;
  failures: Array<{ reason: string; count: number }>;
  locations: SigninLocation[];
  /** Sign-ins from a public IP placed on the map, from one not placed, and from a private or missing address. */
  placement: { placed: number; unplaced: number; internal: number };
  search: SearchMeta;
}

/** X11: successful sign-ins without MFA, from the identity sources that report MFA. */
export interface MfaSet {
  windowStart: number;
  windowEnd: number;
  /** signins is every successful sign-in; service and nonInteractive are the ones not counted for MFA. */
  sources: Array<{ sensorType: string; signins: number; withMfa: number; withoutMfa: number; service: number; nonInteractive: number; reportsMfa: boolean }>;
  /** Interactive user sign-ins from MFA-aware sources: the only ones counted. */
  signins: number;
  withMfa: number;
  withoutMfa: number;
  /** Service principal sign-ins from MFA-aware sources: they can't use MFA. */
  service: number;
  /** Non-interactive sign-ins (token refreshes) from MFA-aware sources: they report no MFA of their own. */
  nonInteractive: number;
  byApp: Array<{ name: string; signins: number; withoutMfa: number }>;
  byOs: Array<{ name: string; signins: number; withoutMfa: number }>;
  topUsers: Array<{ user: string; withoutMfa: number; sensorType: string }>;
  usersTruncated: boolean;
  search: SearchMeta;
}

export type SourceState = "live" | "quiet" | "silent";

export interface SourceRecord {
  sensorType: string;
  schemas: string[];
  events7d: number;
  /** Events per UTC day, oldest first, across the window. */
  daily: number[];
  /** Unparsed events (generic schema) from this source. */
  unparsed7d: number;
  lastEventAt: number | null;
  state: SourceState;
}

/** N3: event volume and last event per data source (sensor type), last 7 days. */
export interface SourceSet {
  windowStart: number;
  windowEnd: number;
  days: string[];
  sources: SourceRecord[];
  events7d: number;
  unparsed7d: number;
  search: SearchMeta;
}

export interface SmimeCert {
  email: string;
  userName: string | null;
  expiresAt: string;
}

/** S/MIME internal CA and internal user certificates expiring within 30 days. */
export interface SmimeRecord {
  /** False when the tenant or the credential has no access to the S/MIME API. */
  available: boolean;
  note: string | null;
  ca: { commonName: string | null; expiresAt: string | null; origin: string | null } | null;
  /** Internal user certificates that expire before `checkedBefore` (some may already have expired). */
  expiring: SmimeCert[];
  expiringTruncated: boolean;
  checkedBefore: string;
}

// ---------------------------------------------------------------- AI Defense (Activity and Policy GraphQL)

/** AI Defense risk levels, with UNKNOWN and ERROR (the catalog could not resolve one) folded into unknown. */
export type AiRisk = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type AiRiskCounts = Record<AiRisk, number>;

/**
 * active: AI Defense is set up (or has data in the window). not-set-up: no
 * settings record, or onboarding not finished, and nothing in the window.
 * not-licensed: the licence expired and nothing in the window. unavailable:
 * Sophos Fusion does not hold the tenant, so AI Defense can't be read.
 */
export type AiDefenseState = "active" | "not-set-up" | "not-licensed" | "unavailable";

export interface AiDefenseApp {
  id: string;
  name: string;
  provider: string;
  /** The app's catalog risk. */
  risk: AiRisk;
  /** Activities with the app in the window. */
  usage: number;
  users: number;
  /** Allowed activities for the app when no policy covers it. */
  unsanctioned: number;
  lastSeen: string | null;
  /** Blocked and warned activities for the app (the flow read, top 10 apps only); null when not read. */
  blocked: number | null;
  warned: number | null;
}

export interface AiDefenseUser {
  /** AI Defense's public actor id, which the flow read filters on. Never sent to the screen. */
  id: string;
  /** Usually an email address; an IP address when AI Defense could not resolve who it was. */
  name: string;
  /** Worst risk observed for the user in the window. */
  risk: AiRisk;
  apps: number;
  usage: number;
  /** Activities that were blocked, warned or modified. */
  violations: number;
  topApp: string | null;
  unsanctioned: number;
  lastSeen: string | null;
  /** Blocked and warned activities for the user (the flow read, top 10 users only); null when not read. */
  blocked: number | null;
  warned: number | null;
}

export interface AiDefenseActivity {
  at: number;
  user: string;
  userType: string;
  appId: string;
  app: string;
  action: "blocked" | "warned";
  risk: AiRisk;
  policy: string;
  device: string;
  platform: string;
  /** Correlated records AI Defense gathered into this activity. */
  count: number;
}

/** One tenant's AI Defense picture for the window (the last 7 days). */
export interface AiDefenseRecord {
  state: AiDefenseState;
  /** Why the state is not active, in plain words. */
  note: string | null;
  windowStart: number;
  windowEnd: number;
  onboarding: string | null;
  licence: { state: string | null; type: string | null; expiresAt: string | null; graceEndsAt: string | null } | null;
  /** Null when the policy read was refused or not made. */
  policies: { total: number; enabled: number; failed: number } | null;
  activity: { total: number; unsanctioned: number; blocked: number; warned: number; blockedByRisk: AiRiskCounts; warnedByRisk: AiRiskCounts };
  apps: { total: number; byRisk: AiRiskCounts; trainsOnData: number | null; unsanctioned: number };
  /** byRisk counts each user once, under the worst risk seen. */
  users: { total: number; byRisk: AiRiskCounts; withViolations: number; unsanctioned: number };
  topApps: AiDefenseApp[];
  topUsers: AiDefenseUser[];
  /** The newest blocked and warned activities. */
  recent: AiDefenseActivity[];
  /** Blocked and warned activities in the window, of which `recent` holds the newest. */
  recentOf: number;
  warnings: string[];
  calls: number;
}
