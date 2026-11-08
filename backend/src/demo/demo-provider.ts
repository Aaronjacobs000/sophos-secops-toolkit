/**
 * Demo mode: a fictional partner (or a single fictional tenant) with made-up
 * customers, devices, cases and detections, so the toolkit can be explored,
 * screenshotted and tested with no Sophos credential and no Sophos calls.
 * Every name is invented; every IP address is from the documentation ranges
 * (RFC 5737). Nothing here is, or is derived from, real tenant data. AI
 * application names are public products as the AI Defense catalog lists
 * them, with the catalog's risk; how much each is used here is invented.
 *
 * The data moves: every few seconds a detection arrives, a case changes lane,
 * or a device goes stale, so the update animations have something to show.
 */

import { EventEmitter } from "node:events";
import type { AppContext } from "../sophos/context.js";
import type {
  AiDefenseRecord,
  AlertRecord,
  AlertSet,
  CaseRecord,
  CaseSet,
  DetectionRecord,
  DetectionSet,
  EgressSet,
  EndpointRecord,
  GenerationRecord,
  HealthRecord,
  LicenceRecord,
  MfaSet,
  SearchMeta,
  Severity,
  SigninSet,
  SmimeRecord,
  SourceSet,
  TenantRecord,
} from "../data/types.js";
import type { DatasetName, DatasetValueMap, EngineStatus, Freshness } from "../services/engine.js";
import type { Provider } from "../services/provider.js";
import { mfaSet, searchWindow, signinSet, sourceSet } from "../mappers/search.js";
import { aiDefenseWindow, applyAiDefenseFlow, mapAiDefenseDetail, mapAiDefenseOverview, unavailableAiDefense } from "../mappers/ai-defense.js";
import type { AiDefenseDetailResponse, AiDefenseFlowResponse, AiDefenseOverviewResponse, AiDefenseRiskLevel } from "../vendor/sophos-core/index.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const DEMO_INTERVALS: Record<string, number> = { cases: 5 * 60_000, detections: 5 * 60_000, alerts: 5 * 60_000, endpoints: 30 * 60_000, health: 6 * HOUR, licences: DAY, generation: DAY, egress: DAY, signins: 15 * 60_000, mfa: 15 * 60_000, sources: 15 * 60_000, smime: DAY, aidefense: 15 * 60_000 };
const DATASETS = ["generation", "endpoints", "cases", "detections", "alerts", "health", "licences", "egress", "signins", "mfa", "sources", "smime", "aidefense"];

/** Mulberry32: small, seeded, repeatable. */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NAMES = [
  "Harbourline Logistics", "Kestrel Dental Group", "Bluegum Shire Council", "Tidewater Health", "Southerly Freight", "Copperleaf Legal",
  "Ironbark Civil", "Wattle Grove Schools", "Riverbend Motors", "Granite Peak Mining", "Saltbush Agriculture", "Magpie Creek Vets",
  "Coastline Property", "Brolga Aviation Services", "Paperbark Accounting", "Lyrebird Media", "Banksia Aged Care", "Redgum Engineering",
  "Kookaburra Childcare", "Stringybark Timber", "Bellbird Pharmacy", "Mallee Grain Co-op", "Seachange Realty", "Coral Bay Tourism",
  "Emu Plains Plumbing", "Jacaranda Dental", "Blackwood Architects", "Platypus Labs", "Warrigal Transport", "Westerly Wines",
  "Gumleaf Insurance", "Quokka Retail", "Driftwood Hotels", "Sandstone Surveyors", "Tasman Marine", "Cockatoo Electrical",
  "Ochre Studio", "Flinders Clinic", "Myall Lakes Resort", "Barramundi Foods",
];

const CITIES: Array<[string, string, number, number, number]> = [
  ["Sydney", "Australia", -33.87, 151.21, 30],
  ["Melbourne", "Australia", -37.81, 144.96, 22],
  ["Brisbane", "Australia", -27.47, 153.03, 14],
  ["Perth", "Australia", -31.95, 115.86, 9],
  ["Adelaide", "Australia", -34.93, 138.6, 7],
  ["Wollongong", "Australia", -34.42, 150.89, 5],
  ["Canberra", "Australia", -35.28, 149.13, 4],
  ["Hobart", "Australia", -42.88, 147.33, 2],
  ["Auckland", "New Zealand", -36.85, 174.76, 5],
  ["Wellington", "New Zealand", -41.29, 174.78, 2],
  ["Singapore", "Singapore", 1.35, 103.82, 3],
  ["Frankfurt", "Germany", 50.11, 8.68, 1],
];

const DETECTORS = [
  "Suspicious PowerShell", "Credential dumping", "Impossible travel", "Malicious document", "Lateral movement via SMB", "Ransomware behaviour",
  "Suspicious service install", "Brute force sign-in", "Encoded command line", "Living-off-the-land binary", "C2 beacon", "Mailbox rule created",
];

const SENSORS = ["ENDPOINT_AGENT", "ENDPOINT_AGENT", "ENDPOINT_AGENT", "FIREWALL", "MICROSOFT", "EMAIL", "IDENTITY", "NDR", "CLOUD", "INTEGRATION"];

const CASE_TITLES = [
  "Suspicious PowerShell on {h}", "LSASS memory access on {h}", "Encoded PowerShell from Word macro", "Impossible travel: {u}", "New local admin on {h}",
  "Blocked C2 beacon, {h}", "Mass file rename on finance share", "Cobalt Strike beacon, {h}", "RDP brute force from 203.0.113.44", "Phishing link clicked, 3 users",
  "Unsigned driver loaded", "Approve isolation of {h}", "Confirm VPN sign-in from Frankfurt", "Approve block of 198.51.100.23", "User to confirm USB transfer",
  "Firewall rule change pending CAB", "Legacy scanner false positives", "Malicious OneNote attachment", "Tamper protection re-enabled", "PUA: remote admin tool",
];

const USERS = ["j.patel", "m.nguyen", "k.walsh", "s.bui", "r.okafor", "t.lam", "a.costa", "l.harris"];

/** Where demo sign-ins come from, beyond the office cities: travel, VPN exits and the odd attacker. */
const SIGNIN_CITIES: Array<[string, string, number, number, number]> = [
  ["Amsterdam", "Netherlands", 52.37, 4.9, 2],
  ["Dallas", "United States", 32.78, -96.8, 1.5],
  ["Jakarta", "Indonesia", -6.2, 106.85, 1],
  ["Sao Paulo", "Brazil", -23.55, -46.63, 0.8],
];

const APPS = ["Exchange Online", "Exchange Online", "SharePoint Online", "Microsoft Teams", "Azure Portal", "Office 365 Portal", "OneDrive"];
const DEMO_OSES = ["OS_WINDOWS", "OS_WINDOWS", "OS_WINDOWS", "OS_IPHONE", "OS_IPHONE", "OS_ANDROID", "OS_MAC", "OS_UNKNOWN"];
const VERSIONS = ["2026.3.2.1", "2026.3.2.1", "2026.3.2.1", "2026.3.2.1", "2026.2.4.7", "2026.1.7.3", "2025.4.1.6"];

interface TenantData {
  generation: GenerationRecord;
  endpoints: EndpointRecord[];
  cases: CaseSet;
  detections: DetectionSet | null;
  alerts: AlertSet;
  health: HealthRecord;
  licences: LicenceRecord[];
  egress: EgressSet;
  signins: SigninSet | null;
  mfa: MfaSet | null;
  sources: SourceSet | null;
  smime: SmimeRecord | null;
  aidefense: AiDefenseRecord;
}

function demoPerson(index: number, prefix: string, _picked: string): string {
  return index < USERS.length * 2 ? USERS[index % USERS.length]! : `${prefix.toLowerCase()}.user${String(index + 1).padStart(4, "0")}`;
}

function pick<T>(r: () => number, list: T[]): T {
  return list[Math.floor(r() * list.length)]!;
}

function weightedCity(r: () => number): (typeof CITIES)[number] {
  const total = CITIES.reduce((a, c) => a + c[4], 0);
  let x = r() * total;
  for (const c of CITIES) {
    x -= c[4];
    if (x <= 0) return c;
  }
  return CITIES[0]!;
}

function prefixOf(name: string): string {
  return name
    .split(/\s+/)
    .map((w) => w[0])
    .join("")
    .slice(0, 3)
    .toUpperCase();
}

function uuid(r: () => number): string {
  const h = () => Math.floor(r() * 0x10000).toString(16).padStart(4, "0");
  return `${h()}${h()}-${h()}-4${h().slice(1)}-a${h().slice(1)}-${h()}${h()}${h()}`;
}

function demoMeta(now: number, rows: number): SearchMeta {
  return { ranAt: now, reused: false, outcome: "ALL", failedSchemas: [], rows, truncated: false, calls: 4 };
}

/**
 * Search GraphQL views for a demo Fusion tenant, built by the same shaping
 * code as live data from made-up aggregate rows. IPs are documentation ranges.
 */
function buildSearch(tenant: TenantRecord, index: number, now: number, single: boolean, homeCity: (typeof CITIES)[number]) {
  // Its own generator: the shared one must not shift, or the rest of the demo would change with the time of day.
  const r = rng(0x5ea7c4 + index);
  const window = searchWindow(now);
  const scale = single ? 1 : 0.15 + r() * 0.5;
  const domain = `${tenant.name.split(/\s+/)[0]!.toLowerCase()}.example`;
  const geo: Record<string, { city: string; country: string; lat: number; lon: number; source: "dbip" }> = {};
  const cities = [homeCity, ...CITIES.filter((c) => c[0] !== homeCity[0]).slice(0, 5), ...SIGNIN_CITIES];
  const signinRows: Array<Record<string, unknown>> = [];
  cities.forEach((c, i) => {
    const ip = `${["192.0.2", "198.51.100", "203.0.113"][i % 3]}.${100 + ((index * 11 + i * 17) % 150)}`;
    geo[ip] = { city: c[0], country: c[1], lat: c[2], lon: c[3], source: "dbip" };
    const home = i === 0 ? 6 : 1;
    const base = Math.round(c[4] * 9 * home * scale * (0.6 + r() * 0.8));
    const foreign = i >= cities.length - SIGNIN_CITIES.length;
    const noMfaShare = foreign ? 0.55 : 0.08 + r() * 0.12;
    signinRows.push(
      { source_address: ip, action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: true, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: Math.round(base * (1 - noMfaShare)) },
      { source_address: ip, action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: Math.round(base * noMfaShare) },
      { source_address: ip, action_result: "FAILED", failure_category: pick(r, ["INCORRECT_USER_OR_PASSWORD", "INCORRECT_USER_OR_PASSWORD", "INCORRECT_MFA", "ACCOUNT_LOCKED_OUT"]), mfa_used: false, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: Math.round(base * (foreign ? 0.6 : 0.04) + r() * 3) },
    );
  });
  signinRows.push(
    { source_address: "10.20.0.15", action_result: "SUCCESS", failure_category: "UNKNOWN_FAILURE_CATEGORY", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: Math.round(4200 * scale) },
    { source_address: "10.20.0.15", action_result: "FAILED", failure_category: "INCORRECT_USER_OR_PASSWORD", mfa_used: false, sensor_type: "ENDPOINT_SOPHOS", row_count: Math.round(60 * scale) },
  );
  const signins = signinSet({ values: signinRows, window, geo, isPublic: (ip) => !ip.startsWith("10."), meta: demoMeta(now, signinRows.length) });

  const mfaRows: Array<Record<string, unknown>> = [];
  for (const app of new Set(APPS)) {
    for (const os of new Set(DEMO_OSES)) {
      const base = (app === "Exchange Online" ? 60 : 14) * (os === "OS_WINDOWS" ? 3 : 1) * scale * (0.5 + r());
      const noMfa = os === "OS_UNKNOWN" || app === "Office 365 Portal" ? 0.5 : 0.1 + r() * 0.15;
      mfaRows.push({ sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: true, application_name: app, "os.os": os, row_count: Math.round(base * (1 - noMfa)) });
      mfaRows.push({ sensor_type: "MICROSOFT_GRAPH_SIGN_IN", mfa_used: false, application_name: app, "os.os": os, row_count: Math.round(base * noMfa) });
    }
  }
  mfaRows.push({ sensor_type: "ENDPOINT_SOPHOS", mfa_used: false, application_name: null, "os.os": "OS_WINDOWS", row_count: Math.round(4200 * scale) });
  const userRows = [...USERS, "svc_scanner", "reception", "printer.admin", "a.chen"].map((u, i) => ({ target_user_name: `${u}@${domain}`, sensor_type: "MICROSOFT_GRAPH_SIGN_IN", row_count: Math.max(1, Math.round((i < 2 ? 70 : 30 - i * 2) * scale * (0.6 + r()))) }));
  const mfa = mfaSet({ values: mfaRows, userValues: userRows, usersTruncated: false, window, meta: demoMeta(now, mfaRows.length + userRows.length) });

  const sourceRows: Array<Record<string, unknown>> = [];
  const day = (i: number) => new Date(Date.parse(`${new Date(window.start).toISOString().slice(0, 10)}T00:00:00Z`) + i * DAY).toISOString().slice(0, 10) + " 00:00:00";
  const feeds: Array<{ type: string; schemas: Array<[string, number]>; lastAgoH: number; stopAfterDay?: number }> = [
    { type: "ENDPOINT_SOPHOS", schemas: [["process", 9000], ["netflow", 52000], ["dnsquery", 11000], ["http", 13000], ["auth", 1300], ["filemod", 6500]], lastAgoH: 0.05 },
    { type: "MICROSOFT_GRAPH_SIGN_IN", schemas: [["auth", 320]], lastAgoH: 0.3 },
    { type: "SOPHOS_SFOS", schemas: [["netflow", 41000], ["http", 9000], ["nids", 120]], lastAgoH: 0.02 },
    { type: "MICROSOFT_DEFENDER_O365", schemas: [["email", 2100], ["cloudaudit", 900]], lastAgoH: 0.8 },
    { type: "OKTA_SYSTEM_LOG", schemas: [["auth", 610], ["cloudaudit", 80]], lastAgoH: 31, stopAfterDay: 5 },
    { type: "CLOUDFLARE_HTTP", schemas: [["generic", 2600]], lastAgoH: 1.2 },
  ];
  for (const f of feeds) {
    const lastAt = now - f.lastAgoH * HOUR;
    for (const [schema, perDay] of f.schemas) {
      for (let i = 0; i < 8; i++) {
        const t = Date.parse(day(i).replace(" ", "T") + "Z");
        if (t > lastAt || (f.stopAfterDay !== undefined && i > f.stopAfterDay)) continue;
        const n = Math.round(perDay * scale * (0.7 + r() * 0.6) * (i === 0 || i === 7 ? 0.5 : 1));
        sourceRows.push({ sensor_type: f.type, schema_type: schema, event_time_usec_1d: day(i), row_count: n, max_event_time_usec: Math.min(lastAt, t + DAY - 1) * 1000 });
      }
    }
  }
  const previous: SourceSet = { windowStart: window.start - DAY, windowEnd: window.end - DAY, days: [], events7d: 0, unparsed7d: 0, search: demoMeta(now, 0), sources: [{ sensorType: "AWS_CLOUDTRAIL", schemas: ["cloudaudit"], events7d: 1200, daily: [], unparsed7d: 0, lastEventAt: now - 9 * DAY, state: "quiet" }] };
  const sources = sourceSet({ values: sourceRows, window, now, previous: index % 3 === 0 ? previous : null, meta: demoMeta(now, sourceRows.length) });
  return { signins, mfa, sources };
}

/** S/MIME for a few demo tenants: one certificate near expiry, one internal CA about to lapse. */
function buildSmime(index: number, now: number, single: boolean, domain: string): SmimeRecord | null {
  const checkedBefore = new Date(now + 30 * DAY).toISOString().slice(0, 10);
  const at = (days: number) => new Date(now + days * DAY).toISOString().replace(/\.\d{3}Z$/, "Z");
  if (single) {
    return { available: true, note: null, ca: { commonName: "Harbourline Logistics", expiresAt: at(1640), origin: "created" }, expiring: [{ email: `j.patel@${domain}`, userName: "J Patel", expiresAt: at(19) }, { email: `m.nguyen@${domain}`, userName: "M Nguyen", expiresAt: at(26) }], expiringTruncated: false, checkedBefore };
  }
  if (index === 3) return { available: true, note: null, ca: { commonName: "Demo CA", expiresAt: at(2400), origin: "created" }, expiring: [{ email: `k.walsh@${domain}`, userName: "K Walsh", expiresAt: at(12) }], expiringTruncated: false, checkedBefore };
  if (index === 5) return { available: true, note: null, ca: { commonName: "Demo CA", expiresAt: at(5), origin: "uploaded" }, expiring: [], expiringTruncated: false, checkedBefore };
  if (index % 4 === 1) return { available: true, note: null, ca: { commonName: "Demo CA", expiresAt: at(900 + index * 30), origin: "created" }, expiring: [], expiringTruncated: false, checkedBefore };
  return { available: true, note: null, ca: null, expiring: [], expiringTruncated: false, checkedBefore };
}

/** AI applications in the AI Defense catalog: id, name, provider, catalog risk, how popular it is in the demo. */
const AI_APPS: Array<[string, string, string, AiDefenseRiskLevel, number]> = [
  ["microsoft-copilot", "Microsoft Copilot", "Microsoft", "LOW", 10],
  ["chatgpt", "ChatGPT", "OpenAI", "LOW", 9],
  ["claude", "Claude", "Anthropic", "LOW", 5],
  ["gemini", "Gemini", "Google", "LOW", 5],
  ["deepseek", "DeepSeek", "DeepSeek", "CRITICAL", 3],
  ["heygen", "HeyGen", "HeyGen", "LOW", 2],
  ["vibe", "Vibe", "Mistral AI", "LOW", 2],
  ["kimi", "Kimi", "Moonshot AI", "HIGH", 1.2],
  ["midjourney", "Midjourney", "Midjourney", "CRITICAL", 1],
  ["perplexity", "Perplexity", "Perplexity", "LOW", 2.4],
  ["cursor", "Cursor", "Anysphere", "LOW", 1.6],
  ["poe", "Poe", "Quora", "CRITICAL", 0.6],
];

/** More catalog apps a large estate uses. */
const AI_APPS_MORE: Array<[string, string, string, AiDefenseRiskLevel, number]> = [
  ["github-copilot", "GitHub Copilot", "GitHub", "LOW", 2.2],
  ["grammarly", "Grammarly", "Grammarly", "LOW", 1.4],
  ["notion-ai", "Notion AI", "Notion Labs", "LOW", 1.3],
  ["otter-ai", "Otter.ai", "Otter.ai", "MEDIUM", 0.9],
  ["grok", "Grok", "xAI", "LOW", 0.9],
  ["hugging-face", "Hugging Face", "Hugging Face", "MEDIUM", 0.8],
  ["elevenlabs", "ElevenLabs", "ElevenLabs", "MEDIUM", 0.7],
  ["character-ai", "Character.AI", "Character.AI", "CRITICAL", 0.5],
  ["windsurf", "Windsurf", "Windsurf", "LOW", 0.5],
  ["meta-ai", "Meta AI", "Meta", "CRITICAL", 0.4],
];

/** Of each app's activity: the share blocked and the share warned, by catalog risk. */
const AI_ACTION_SHARE: Record<string, [number, number]> = { CRITICAL: [0.86, 0.06], HIGH: [0.25, 0.55], MEDIUM: [0.3, 0.35], LOW: [0.06, 0.16] };

/** More people for a large estate's top users. */
const AI_MORE_USERS = ["d.morgan", "p.singh", "e.rossi", "h.kim", "c.dubois", "f.ali", "g.brown", "n.tanaka", "o.reyes", "v.ivanova", "w.chen", "y.haddad"];

/** Of all blocked and warned activity, the share each top user carries; the rest stays with everyone else. */
const AI_VIOLATION_SHARE = [0.42, 0.2, 0.11, 0.07, 0.06, 0.05, 0.04, 0.03, 0.01, 0.01];

/**
 * AI Defense for a demo tenant, through the same shaping code as live
 * answers. Its own generator: the shared one must not shift, or the rest of
 * the demo would change. Partner tenants spread over every state.
 */
function buildAiDefense(tenant: TenantRecord, index: number, now: number, single: boolean): AiDefenseRecord {
  const window = aiDefenseWindow(now);
  const zero = { totalCount: 0 };
  const counts = { all: zero, unsanctioned: zero, blocked: zero, warned: zero, blockedCritical: zero, blockedHigh: zero, blockedMedium: zero, blockedLow: zero, blockedInfo: zero, warnedCritical: zero, warnedHigh: zero, warnedMedium: zero, warnedLow: zero, warnedInfo: zero };
  const emptySummary = { apps: { totalApps: 0, criticalRisk: 0, highRisk: 0, mediumRisk: 0, lowRisk: 0, infoRisk: 0, unknownRisk: 0, errorRisk: 0, trainsOnData: 0, unsanctionedCount: 0 }, users: { totalUsers: 0, criticalRisk: 0, highRisk: 0, mediumRisk: 0, lowRisk: 0, infoRisk: 0, unknownRisk: 0, withViolations: 0, unsanctionedCount: 0 } };
  const iso = (t: number) => new Date(t).toISOString();
  if (!single) {
    if (index === 13 || index === 29) return unavailableAiDefense(window);
    if (index === 11) return mapAiDefenseOverview({ secureAITenantSettings: { onboarding: { status: "COMPLETED" }, licenseState: "EXPIRED", licenseType: "TRIAL", licenseExpiryDate: iso(now - 20 * DAY), gracePeriodEndsAt: null }, inventorySummary: emptySummary, ...counts }, window);
    if (index % 5 !== 0 && index % 5 !== 2) {
      const settings = index % 7 === 3 ? { onboarding: { status: "IN_PROGRESS" as const }, licenseState: null, licenseType: null, licenseExpiryDate: null, gracePeriodEndsAt: null } : null;
      return mapAiDefenseOverview({ secureAITenantSettings: settings, inventorySummary: emptySummary, ...counts }, window);
    }
  }
  const r = rng(0xa1de0000 + index);
  // Partner index 0 is a large estate (hundreds of apps, thousands of people); index 7 barely uses AI.
  const big = !single && index === 0;
  const quiet = !single && index === 7;
  const scale = single ? 1 : big ? 9 : 0.15 + r() * 0.6;
  const domain = `${tenant.name.split(/\s+/)[0]!.toLowerCase()}.example`;
  const prefix = prefixOf(tenant.name);
  const catalog = big ? [...AI_APPS, ...AI_APPS_MORE] : AI_APPS;
  const apps = quiet
    ? [
        { id: "claude", name: "Claude", provider: "Anthropic", risk: "LOW" as AiDefenseRiskLevel, usage: 4, blocked: 0, warned: 1, unsanctioned: 0, lastSeen: iso(now - 5 * HOUR) },
        { id: "gemini", name: "Gemini", provider: "Google", risk: "LOW" as AiDefenseRiskLevel, usage: 2, blocked: 0, warned: 0, unsanctioned: 0, lastSeen: iso(now - 26 * HOUR) },
      ]
    : catalog.filter((_, i) => single || big || i < 5 || r() < 0.55).map(([id, name, provider, risk, weight]) => {
        const usage = Math.max(3, Math.round(weight * 130 * scale * (0.6 + r() * 0.8)));
        const [b, w] = AI_ACTION_SHARE[risk]!;
        const blocked = Math.round(usage * b * (0.8 + r() * 0.4));
        const warned = Math.round(usage * w * (0.8 + r() * 0.4));
        const unsanctioned = id === "heygen" || id === "vibe" ? Math.round((usage - blocked - warned) * 0.6) : 0;
        return { id, name, provider, risk, usage, blocked, warned, unsanctioned, lastSeen: iso(now - Math.round(r() * 5 * HOUR)) };
      });
  apps.sort((a, b) => b.usage - a.usage);
  const sum = (f: (a: (typeof apps)[number]) => number, risk?: AiDefenseRiskLevel) => apps.filter((a) => !risk || a.risk === risk).reduce((acc, a) => acc + f(a), 0);
  // A large estate's long tail: the inventory lists 20 apps, and nearly 200 more share this.
  const tail = big ? { apps: 192, usage: Math.round(sum((a) => a.usage) * 0.3), share: [0.1, 0.12] as const } : null;
  const tailBlocked = tail ? Math.round(tail.usage * tail.share[0]) : 0;
  const tailWarned = tail ? Math.round(tail.usage * tail.share[1]) : 0;
  const total = sum((a) => a.usage) + (tail?.usage ?? 0);
  const blockedAll = sum((a) => a.blocked) + tailBlocked;
  const warnedAll = sum((a) => a.warned) + tailWarned;
  const named = big
    ? [...USERS, ...AI_MORE_USERS].map((u) => `${u}@${domain}`)
    : quiet
      ? [`k.walsh@${domain}`, `reception@${domain}`]
      : [...USERS.map((u) => `${u}@${domain}`), `reception@${domain}`, `a.chen@${domain}`, "192.0.2.41", "198.51.100.77"].slice(0, single ? 12 : 3 + Math.floor(r() * 8));
  const people = named.slice(0, 20);
  const usersTotal = big ? 2140 : people.length;
  // Everyone the inventory names shares this much of the activity; a large estate's other 2,120 people have the rest.
  const namedShare = big ? 0.32 : 1;
  const weights = people.map((_, i) => 1 / (i + 1.4));
  const wsum = weights.reduce((a, b) => a + b, 0);
  const users = people.map((name, i) => {
    const usage = quiet ? [4, 2][i]! : Math.max(1, Math.round(total * namedShare * (weights[i]! / wsum)));
    const share = (AI_VIOLATION_SHARE[i] ?? 0) * (big ? 0.45 : 1);
    // Rounded down, so the named people never carry more than the tenant's totals.
    const blocked = quiet ? 0 : Math.min(usage, Math.floor(blockedAll * share));
    const warned = quiet ? (i === 0 ? 1 : 0) : Math.min(usage - blocked, Math.floor(warnedAll * share));
    const used = apps.filter((_, k) => k < 2 || r() < 0.5);
    const network = /^\d/.test(name);
    return {
      id: network ? name : `S-1-5-21-${4100 + index}-${1100 + i}`,
      name,
      risk: (quiet || blocked + warned === 0 ? "LOW" : i === 0 ? "CRITICAL" : i === 1 ? "HIGH" : "LOW") as AiDefenseRiskLevel,
      appsUsed: quiet ? (i === 0 ? 2 : 1) : used.length,
      usage,
      blocked,
      warned,
      policyViolations: blocked + warned,
      topApp: used[0]?.name ?? null,
      lastSeen: iso(now - Math.round(r() * 30 * HOUR)),
      unsanctionedCount: name.startsWith("192.0.2") ? 4 : 0,
    };
  });
  const flagged = apps.filter((a) => a.blocked + a.warned > 0);
  const weightOf = flagged.reduce((acc, a) => acc + a.blocked + a.warned, 0);
  const policyFor = (risk: AiDefenseRiskLevel, action: "BLOCKED" | "WARNED") => (risk === "CRITICAL" ? "Block high-risk AI apps" : action === "WARNED" ? "Warn on public AI chat" : "Block uploads to AI chat");
  const activities: NonNullable<AiDefenseDetailResponse["activities"]>["activities"] = [];
  const stoppers = users.filter((u) => u.blocked + u.warned > 0);
  let at = now - Math.round(r() * 20 * 60_000);
  for (let i = 0; i < 50 && weightOf > 0 && stoppers.length; i++) {
    let x = r() * weightOf;
    const app = flagged.find((a) => (x -= a.blocked + a.warned) <= 0) ?? flagged[0]!;
    const action = r() < app.blocked / Math.max(1, app.blocked + app.warned) ? "BLOCKED" : "WARNED";
    const who = stoppers[Math.min(stoppers.length - 1, Math.floor(Math.pow(r(), 1.8) * stoppers.length))]!.name;
    const network = /^\d/.test(who);
    activities.push({
      timestamp: { startTime: iso(at) },
      actor: { name: who, type: network ? "NETWORK_ENTITY" : "USER" },
      application: { id: app.id, name: app.name },
      action,
      policy: policyFor(app.risk, action),
      device: network ? { name: "", platform: "UNKNOWN" } : { name: `${prefix}-${r() < 0.85 ? "LT" : "MAC"}-${String(1 + Math.floor(r() * 400)).padStart(4, "0")}`, platform: r() < 0.85 ? "WINDOWS" : "MACOS" },
      risk: app.risk,
      aggregationCount: 1 + Math.floor(r() * r() * 6),
    });
    at -= Math.round((20 + r() * 80) * 60_000 / (single ? 1 : 0.5 + scale));
  }
  const count = (n: number) => ({ totalCount: n });
  const riskCount = (k: AiDefenseRiskLevel) => apps.filter((a) => a.risk === k).length + (k === "LOW" ? (tail?.apps ?? 0) : 0);
  const withViolations = users.filter((u) => u.policyViolations > 0).length + (big ? 310 : 0);
  const overview: AiDefenseOverviewResponse = {
    secureAITenantSettings: { onboarding: { status: "COMPLETED" }, licenseState: "ACTIVE", licenseType: "TERM", licenseExpiryDate: iso(now + (200 + index * 9) * DAY), gracePeriodEndsAt: iso(now + (230 + index * 9) * DAY) },
    inventorySummary: {
      apps: { totalApps: apps.length + (tail?.apps ?? 0), criticalRisk: riskCount("CRITICAL"), highRisk: riskCount("HIGH"), mediumRisk: riskCount("MEDIUM"), lowRisk: riskCount("LOW"), infoRisk: 0, unknownRisk: 0, errorRisk: 0, trainsOnData: Math.min(3, apps.length) + (big ? 41 : 0), unsanctionedCount: apps.filter((a) => a.unsanctioned > 0).length },
      users: { totalUsers: usersTotal, criticalRisk: users.some((u) => u.risk === "CRITICAL") ? 1 : 0, highRisk: users.some((u) => u.risk === "HIGH") ? 1 : 0, mediumRisk: 0, lowRisk: usersTotal - (users.some((u) => u.risk === "CRITICAL") ? 1 : 0) - (users.some((u) => u.risk === "HIGH") ? 1 : 0), infoRisk: 0, unknownRisk: 0, withViolations, unsanctionedCount: users.filter((u) => u.unsanctionedCount > 0).length },
    },
    all: count(total),
    unsanctioned: count(sum((a) => a.unsanctioned)),
    blocked: count(blockedAll),
    blockedCritical: count(sum((a) => a.blocked, "CRITICAL")),
    blockedHigh: count(sum((a) => a.blocked, "HIGH")),
    blockedMedium: count(sum((a) => a.blocked, "MEDIUM")),
    blockedLow: count(sum((a) => a.blocked, "LOW") + tailBlocked),
    blockedInfo: zero,
    warned: count(warnedAll),
    warnedCritical: count(sum((a) => a.warned, "CRITICAL")),
    warnedHigh: count(sum((a) => a.warned, "HIGH")),
    warnedMedium: count(sum((a) => a.warned, "MEDIUM")),
    warnedLow: count(sum((a) => a.warned, "LOW") + tailWarned),
    warnedInfo: zero,
  };
  const listed = apps.slice(0, 20);
  const record = mapAiDefenseOverview(overview, window);
  Object.assign(
    record,
    mapAiDefenseDetail({
      appInventory: { totalCount: apps.length + (tail?.apps ?? 0), entries: listed.map((a) => ({ id: a.id, name: a.name, provider: a.provider, risk: a.risk, usage: a.usage, uniqueUsers: Math.max(1, Math.round(usersTotal * Math.min(1, (a.usage / Math.max(1, total)) * 3))), lastSeen: a.lastSeen, unsanctionedCount: a.unsanctioned })) },
      userInventory: { totalCount: usersTotal, entries: users.map(({ blocked: _b, warned: _w, ...u }) => u) },
      activities: { totalCount: blockedAll + warnedAll, activities },
    }),
  );
  // The flow read's answer, through the same code as a live one.
  const flow: AiDefenseFlowResponse = {};
  listed.slice(0, 10).forEach((a, i) => Object.assign(flow, { [`app${i}Blocked`]: count(a.blocked), [`app${i}Warned`]: count(a.warned) }));
  users.slice(0, 10).forEach((u, i) => Object.assign(flow, { [`user${i}Blocked`]: count(u.blocked), [`user${i}Warned`]: count(u.warned) }));
  applyAiDefenseFlow(record, blockedAll + warnedAll ? flow : null);
  record.policies = { total: single ? 5 : 2 + (index % 3), enabled: single ? 4 : 2, failed: index === 5 ? 1 : 0 };
  record.calls = blockedAll + warnedAll ? 4 : 3;
  return record;
}

/** Severity is skewed per tenant so the MSP wall has a spread of states. */
function buildTenant(r: () => number, tenant: TenantRecord, index: number, now: number, single: boolean): TenantData {
  const risk = single ? 0.8 : index < 6 ? 0.85 : index < 16 ? 0.5 : 0.12;
  const fusion = single || r() < 0.25;
  const size = single ? 640 : Math.round(12 + r() * r() * 380);
  const prefix = prefixOf(tenant.name);
  const homeCity = weightedCity(r);
  const endpoints: EndpointRecord[] = [];
  const egressHosts: EgressSet["hosts"] = [];
  const geo: EgressSet["geo"] = {};
  const sites: Array<(typeof CITIES)[number]> = [homeCity, weightedCity(r), weightedCity(r)];
  const ipFor = new Map<string, string>();
  sites.forEach((s, i) => {
    const ip = `${["192.0.2", "198.51.100", "203.0.113"][i % 3]}.${10 + ((index * 7 + i * 13) % 240)}`;
    ipFor.set(s[0], ip);
    geo[ip] = { city: s[0], country: s[1], lat: s[2] + (r() - 0.5) * 0.05, lon: s[3] + (r() - 0.5) * 0.05, source: "sophos" };
  });
  for (let i = 0; i < size; i++) {
    const roll = r();
    const isServer = roll < 0.12;
    const platform = isServer ? (r() < 0.85 ? "windows" : "linux") : r() < 0.84 ? "windows" : r() < 0.85 ? "macOS" : "linux";
    const healthRoll = r();
    const health = healthRoll < 0.012 * risk * 3 ? "bad" : healthRoll < 0.05 * risk * 2 ? "suspicious" : healthRoll < 0.06 ? "unknown" : "good";
    const staleRoll = r();
    const silent = staleRoll < 0.035 * (0.5 + risk) ? Math.floor(7 + r() * r() * 140) : r() * 0.9;
    const hostname = `${prefix}-${isServer ? "SRV" : platform === "macOS" ? "MAC" : "LT"}-${String(i + 1).padStart(4, "0")}`;
    const site = i % 10 < 7 ? sites[0]! : i % 10 < 9 ? sites[1]! : sites[2]!;
    endpoints.push({
      id: uuid(r),
      hostname,
      type: isServer ? "server" : "computer",
      platform: platform.toLowerCase(),
      osName: isServer ? (platform === "windows" ? "Windows Server 2022" : "Ubuntu 24.04 LTS") : platform === "windows" ? pick(r, ["Windows 11 24H2", "Windows 11 23H2", "Windows 10 22H2"]) : platform === "macOS" ? "macOS 15.6" : "Ubuntu 24.04 LTS",
      isServer,
      health,
      threats: health === "bad" ? "bad" : "good",
      services: health === "suspicious" ? "suspicious" : "good",
      tamper: r() > 0.03 * (0.4 + risk * 1.6),
      lastSeenAt: new Date(now - silent * DAY - r() * HOUR).toISOString(),
      agentVersion: pick(r, VERSIONS),
      products: ["endpointProtection", "interceptX", ...(r() < 0.5 ? ["xdr"] : [])],
      isolation: health === "bad" && r() < 0.3 ? "isolated" : null,
      group: null,
      // Each demo person is assigned to a couple of laptops and the rest to their own users, as Sophos records the last user who signed in.
      // pick() still runs for every computer, so the rest of the demo stays the same.
      person: isServer ? null : demoPerson(i, prefix, pick(r, USERS)),
    });
    if (r() < 0.93) egressHosts.push({ hostname: hostname.toLowerCase(), ip: ipFor.get(site[0])! });
  }

  const mdr = single || r() < 0.4;
  const cases: CaseRecord[] = [];
  const closed: CaseRecord[] = [];
  const caseCount = Math.round((single ? 34 : 1 + r() * 9) * (0.4 + risk));
  const statusesV2Mdr = ["new", "in_progress", "in_progress", "customer_action_required", "on_hold", "awaiting_sophos_assignment"];
  const statusesV2Self = ["open", "active", "active", "awaiting_action", "suspended"];
  const statusesV1 = ["new", "investigating", "investigating", "actionRequired", "onHold"];
  const titles: Record<string, string> = { new: "New", in_progress: "In Progress", customer_action_required: "Customer Action Required", on_hold: "On Hold", awaiting_sophos_assignment: "Awaiting Sophos Assignment", open: "Open", active: "Active", awaiting_action: "Awaiting Action", suspended: "Suspended", investigating: "Investigating", actionRequired: "Action required", onHold: "On hold" };
  const sevPool: Severity[] = risk > 0.6 ? ["critical", "high", "high", "medium", "medium", "low", "info"] : risk > 0.3 ? ["high", "medium", "medium", "low", "low", "info"] : ["medium", "low", "low", "info"];
  let seq = 24000 + index * 300;
  const mk = (open: boolean): CaseRecord => {
    const managed = mdr && r() < 0.6 ? "mdr" : "self";
    const pool = fusion ? (managed === "mdr" ? statusesV2Mdr : statusesV2Self) : statusesV1;
    const status = open ? pick(r, pool) : fusion ? "closed" : "resolved";
    const ageH = open ? Math.pow(r(), 1.6) * 24 * 12 : 2 + r() * 24 * 25;
    const created = now - ageH * HOUR;
    const closeAfterH = Math.min(ageH - 0.2, 0.5 + Math.pow(r(), 1.4) * 70);
    const closedAt = open ? null : new Date(created + closeAfterH * HOUR).toISOString();
    const host = endpoints[Math.floor(r() * endpoints.length)]?.hostname ?? `${prefix}-LT-0001`;
    seq++;
    return {
      id: fusion ? uuid(r) : `1-${seq * 7}`,
      ref: fusion ? `CSE${String(seq).padStart(5, "0")}` : `C-${seq}`,
      title: pick(r, CASE_TITLES).replace("{h}", host).replace("{u}", pick(r, USERS)),
      severity: pick(r, sevPool),
      status,
      statusTitle: titles[status] ?? (fusion ? "Closed" : "Resolved"),
      closed: !open,
      secondary: null,
      managedBy: managed,
      assigneeId: managed === "self" && (status === "new" || status === "open") && r() < 0.6 ? null : managed === "self" ? uuid(r) : null,
      createdAt: new Date(created).toISOString(),
      updatedAt: new Date(open ? created + (now - created) * r() : Date.parse(closedAt!)).toISOString(),
      closedAt,
      type: managed === "mdr" ? "investigation" : "security_case",
      tenantId: tenant.id,
      api: fusion ? "v2" : "v1",
    };
  };
  for (let i = 0; i < caseCount; i++) cases.push(mk(true));
  for (let i = 0; i < Math.round(caseCount * 1.3) + 2; i++) closed.push(mk(false));

  const detections: DetectionRecord[] = [];
  if (fusion) {
    const perHour = single ? 9 : 1 + r() * 4 * risk;
    for (let h = 0; h < 168; h++) {
      const wave = 1 + 0.7 * Math.sin(((h % 24) / 24) * Math.PI * 2 - 1.2);
      const n = Math.round(perHour * wave * (0.6 + r() * 0.8));
      for (let k = 0; k < n; k++) {
        const sevRoll = r();
        detections.push({
          id: `alert://priv:demo:${index}:${h}:${k}`,
          createdAt: now - h * HOUR - r() * HOUR,
          severity: sevRoll < 0.03 ? "critical" : sevRoll < 0.15 ? "high" : sevRoll < 0.45 ? "medium" : sevRoll < 0.8 ? "low" : "info",
          detector: pick(r, DETECTORS),
          sensorTypes: [pick(r, SENSORS)],
          techniques: [pick(r, ["T1059.001", "T1003.001", "T1078", "T1021.002", "T1486", "T1566.001"])],
          status: "OPEN",
        });
      }
    }
    detections.sort((a, b) => b.createdAt - a.createdAt);
  }
  const alerts: AlertRecord[] = [];
  const alertCount = Math.round((single ? 60 : 3 + r() * 40) * (0.3 + risk));
  for (let i = 0; i < alertCount; i++) {
    alerts.push({
      id: uuid(r),
      raisedAt: new Date(now - Math.pow(r(), 1.3) * 7 * DAY).toISOString(),
      severity: pick(r, ["high", "medium", "medium", "low", "low", "low"]),
      category: pick(r, ["malware", "pua", "runtimeDetections", "policy", "integrations", "updating", "protection"]),
      product: pick(r, ["endpoint", "endpoint", "endpoint", "server", "firewall", "email", "mobile", "integrations"]),
      type: "Event::Endpoint::Threat::Detected",
      description: "Demo alert",
    });
  }
  const search = fusion ? buildSearch(tenant, index, now, single, homeCity) : null;
  const tamperDisabled = endpoints.filter((e) => e.tamper === false).length;
  const healthScore = Math.max(18, Math.min(100, Math.round(100 - risk * 50 - r() * 16)));
  const licenceDays = index === 2 ? 2 : index === 8 ? 12 : index === 12 ? 21 : 80 + Math.floor(r() * 500);
  return {
    generation: { generation: fusion ? "fusion" : "classic", xdrOwnership: fusion ? "securityOperations" : "sophos" },
    endpoints,
    cases: { api: fusion ? "v2" : "v1", open: cases, recentClosed: closed, truncated: false, warnings: [] },
    detections: fusion ? { windowHours: 168, total: detections.length, items: detections, sampled: false, count30d: Math.round(detections.length * 4.1) } : null,
    alerts: { sinceHours: 168, total: alerts.length, items: alerts },
    health: { overall: healthScore, sections: { protection: Math.min(100, healthScore + 8), policy: healthScore, exclusions: Math.min(100, healthScore + 12), tamperProtection: Math.max(0, healthScore - 15) }, tamperDisabled, notFullyProtected: Math.round(size * 0.02) },
    licences: [
      { code: mdr ? "MDR-COMPLETE" : "CIXAXDR", name: mdr ? "Sophos MDR Complete" : "Sophos XDR", type: "term", endDate: new Date(now + licenceDays * DAY).toISOString().slice(0, 10), quantity: size + 20, used: size },
    ],
    egress: { hosts: egressHosts, geo, unplaced: [], notes: [] },
    signins: search?.signins ?? null,
    mfa: search?.mfa ?? null,
    sources: search?.sources ?? null,
    smime: buildSmime(index, now, single, `${tenant.name.split(/\s+/)[0]!.toLowerCase()}.example`),
    aidefense: buildAiDefense(tenant, index, now, single),
  };
}

export class DemoProvider extends EventEmitter implements Provider {
  readonly kind = "demo" as const;
  readonly label: string;
  context: AppContext;
  tenants: TenantRecord[];
  tenantsOverCap = 0;
  status: EngineStatus = "ready";
  statusMessage = "";
  private data = new Map<string, TenantData>();
  private fetched = new Map<string, number>();
  private timer: NodeJS.Timeout | null = null;
  private r: () => number;
  private seq = 0;

  constructor(mode: "partner" | "tenant", now = Date.now(), seed = 20261005) {
    super();
    this.setMaxListeners(100);
    this.r = rng(seed);
    const single = mode === "tenant";
    const id = "d3m0d3m0-0000-4000-a000-000000000001";
    this.label = single ? "Harbourline Logistics (demo)" : "Southern Cross IT (demo partner)";
    this.context = single
      ? { kind: "tenant", id, multiTenant: false, idHeader: "X-Tenant-ID", apiHost: "https://api-demo.central.sophos.com", globalHost: "https://api.central.sophos.com", views: ["front", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas"], label: "Tenant" }
      : { kind: "partner", id, multiTenant: true, idHeader: "X-Partner-ID", apiHost: null, globalHost: "https://api.central.sophos.com", views: ["front", "msp", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas"], label: "Partner" };
    const names = single ? [NAMES[0]!] : NAMES;
    this.tenants = names.map((name, i) => {
      const c = weightedCity(this.r);
      return { id: `d3m0${String(i).padStart(4, "0")}-0000-4000-a000-${String(i).padStart(12, "0")}`, name, apiHost: "https://api-demo.central.sophos.com", dataRegion: pick(this.r, ["au01", "au01", "au01", "us01", "eu01"]), billingType: "term", status: "active", products: [], city: c[0], countryCode: c[1] === "Australia" ? "AU" : "NZ" };
    });
    this.tenants.forEach((t, i) => {
      const d = buildTenant(this.r, t, i, now, single);
      t.products = d.licences.map((l) => l.code);
      this.data.set(t.id, d);
    });
    for (const t of this.tenants) for (const ds of DATASETS) this.fetched.set(`${ds}:${t.id}`, now - Math.floor(this.r() * 4 * 60_000));
    this.timer = setInterval(() => this.tick(), 6000);
    this.timer.unref?.();
  }

  get<K extends DatasetName>(dataset: K, tenantId: string): DatasetValueMap[K] | null {
    const d = this.data.get(tenantId);
    if (!d) return null;
    return ((d as unknown as Record<string, unknown>)[dataset] ?? null) as DatasetValueMap[K] | null;
  }

  /** Demo data is always "fresh": a stable offset inside each dataset's refresh interval. */
  fetchedAt(dataset: DatasetName, tenantId: string): number | null {
    if (!this.get(dataset, tenantId)) return null;
    const last = this.fetched.get(`${dataset}:${tenantId}`) ?? 0;
    const interval = DEMO_INTERVALS[dataset] ?? HOUR;
    let h = 0;
    for (const ch of `${dataset}${tenantId}`) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    const now = Date.now();
    return Math.max(last, now - (h % Math.min(interval * 0.8, 4 * 60_000)));
  }

  snapshots<T>(name: string, tenantId: string, sinceMs: number): Array<{ takenAt: number; value: T }> {
    if (name !== "endpoints") return [];
    const d = this.data.get(tenantId);
    if (!d) return [];
    const out: Array<{ takenAt: number; value: T }> = [];
    const r = rng(tenantId.length * 97 + d.endpoints.length);
    const now = Date.now();
    for (let i = 29; i >= 0; i--) {
      const at = now - i * DAY;
      if (at < sinceMs) continue;
      const total = d.endpoints.length - Math.round(i * 0.4 * r());
      out.push({ takenAt: at, value: { total, bad: Math.round(r() * 3), suspicious: Math.round(r() * 8), stale7: Math.round(4 + r() * 6), tamperOff: Math.round(r() * 5) } as T });
    }
    return out;
  }

  freshness(tenantIds: string[], datasets: DatasetName[]): Freshness[] {
    const out: Freshness[] = [];
    for (const tenantId of tenantIds) {
      for (const dataset of datasets) {
        if (!this.get(dataset, tenantId)) continue;
        out.push({ dataset, tenantId, fetchedAt: this.fetchedAt(dataset, tenantId), intervalMs: DEMO_INTERVALS[dataset] ?? HOUR, lastError: null, running: false });
      }
    }
    return out;
  }

  focus(): void {}
  setFastTenants(): void {}

  budget() {
    const m = new Date().getMinutes();
    return { lastMinute: 0, lastHour: 0, queued: 0, pausedFor: 0, perMinute: 80, perHour: 900, total: m };
  }

  progress() {
    return { done: this.tenants.length, total: this.tenants.length };
  }

  tenant(id: string): TenantRecord | null {
    return this.tenants.find((t) => t.id === id) ?? null;
  }

  /** One small change, so screens have something to animate. */
  tick(now = Date.now()): void {
    const r = this.r;
    const t = this.tenants[Math.floor(r() * Math.min(this.tenants.length, 10))]!;
    const d = this.data.get(t.id)!;
    const roll = r();
    this.seq++;
    if (d.detections && roll < 0.6) {
      const n = 1 + Math.floor(r() * 3);
      for (let k = 0; k < n; k++) {
        d.detections.items.unshift({ id: `alert://priv:demo:live:${this.seq}:${k}`, createdAt: now - r() * 30_000, severity: pick(r, ["high", "medium", "low", "low", "info", "critical"] as Severity[]), detector: pick(r, DETECTORS), sensorTypes: [pick(r, SENSORS)], techniques: [], status: "OPEN" });
      }
      d.detections.total += n;
      this.fetched.set(`detections:${t.id}`, now);
      this.emit("update", { dataset: "detections", tenantId: t.id });
    } else if (roll < 0.85 && d.cases.open.length) {
      const c = d.cases.open[Math.floor(r() * d.cases.open.length)]!;
      const flow = c.api === "v2" ? (c.managedBy === "mdr" ? ["new", "in_progress", "customer_action_required", "in_progress"] : ["open", "active", "awaiting_action", "active"]) : ["new", "investigating", "actionRequired", "investigating"];
      const next = flow[(flow.indexOf(c.status) + 1) % flow.length]!;
      if (r() < 0.25) {
        c.closed = true;
        c.status = c.api === "v2" ? "closed" : "resolved";
        c.statusTitle = c.api === "v2" ? "Closed" : "Resolved";
        c.closedAt = new Date(now).toISOString();
        d.cases.open = d.cases.open.filter((x) => x.id !== c.id);
        d.cases.recentClosed.unshift(c);
      } else {
        c.status = next;
        c.statusTitle = next.replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase()).replace("ActionRequired", "Action required");
        if (c.managedBy === "self" && !c.assigneeId) c.assigneeId = "demo-analyst";
      }
      c.updatedAt = new Date(now).toISOString();
      this.fetched.set(`cases:${t.id}`, now);
      this.emit("update", { dataset: "cases", tenantId: t.id });
    } else {
      const e = d.endpoints[Math.floor(r() * d.endpoints.length)];
      if (e) e.health = pick(r, ["good", "good", "suspicious", "bad"]);
      this.fetched.set(`endpoints:${t.id}`, now);
      this.emit("update", { dataset: "endpoints", tenantId: t.id });
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.removeAllListeners();
  }
}
