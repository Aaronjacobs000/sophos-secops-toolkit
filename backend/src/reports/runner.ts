/**
 * Runs a report: checks the request against the catalogue and the active
 * credential, works out the window, calls the builder inside a call tally,
 * and returns the finished document. Nothing here touches HTTP or the page,
 * so a scheduler (phase 2) can call runReport directly.
 */

import type { Provider } from "../services/provider.js";
import type { Settings } from "../store/settings.js";
import { scopeFor } from "../services/views.js";
import { callTally, type CallRecord } from "../sophos/guard.js";
import { reportDefinition, type ReportDefinition } from "./catalogue.js";
import type { BuildContext, BuiltReport, ReportWindow } from "./context.js";
import { serverTimeZone, validTimeZone, windowLabel } from "./format.js";
import { ReportInputError, cleanUser } from "./queries.js";
import type { ReportSource } from "./source.js";
import type { ReportDocument, ReportId } from "./types.js";
import { buildUser } from "./builders/user.js";
import { buildLogSearch, logSpec } from "./builders/logsearch.js";
import { buildExecutive } from "./builders/executive.js";
import { buildCases } from "./builders/cases.js";
import { buildDetections } from "./builders/detections.js";
import { buildEndpoints } from "./builders/endpoints.js";
import { buildSignins, buildSources } from "./builders/identity.js";

const BUILDERS: Record<ReportId, (ctx: BuildContext) => Promise<BuiltReport>> = {
  user: buildUser,
  logsearch: buildLogSearch,
  executive: buildExecutive,
  cases: buildCases,
  detections: buildDetections,
  endpoints: buildEndpoints,
  signins: buildSignins,
  sources: buildSources,
};

export interface ReportRequest {
  reportId: string;
  /** A tenant ID, or "all" for a partner or organization credential. */
  tenant?: string;
  window?: string;
  timeZone?: string;
  params?: Record<string, unknown>;
}

export interface CheckedRequest {
  def: ReportDefinition;
  tenant: string;
  windowKey: string | null;
  timeZone: string;
  params: Record<string, string | string[]>;
}

/** Search windows end on a quarter hour, so a rerun inside it reuses the same searches. */
const QUARTER = 15 * 60_000;

function cleanParams(raw: Record<string, unknown> | undefined): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(raw ?? {})) {
    if (!/^[a-zA-Z]{1,20}$/.test(k)) continue;
    if (typeof v === "string") out[k] = v.slice(0, 200);
    else if (Array.isArray(v)) out[k] = v.filter((x): x is string => typeof x === "string").slice(0, 40).map((x) => x.slice(0, 80));
  }
  return out;
}

/** Throws ReportInputError with a message for the person when the request can't run. */
export function checkRequest(provider: Provider, req: ReportRequest): CheckedRequest {
  const def = reportDefinition(req.reportId);
  if (!def) throw new ReportInputError("No such report.");
  const multi = !!provider.context?.multiTenant;
  let tenant = multi ? (typeof req.tenant === "string" ? req.tenant : "all") : (provider.tenants[0]?.id ?? "");
  if (multi && tenant !== "all" && !provider.tenant(tenant)) throw new ReportInputError("That tenant is not one this credential reaches.");
  if (!tenant) throw new ReportInputError("The credential has not said which tenant it reaches yet.");
  if (def.scope === "tenant" && tenant === "all") throw new ReportInputError(`${def.title} runs on one tenant. Pick one.`);
  const all = tenant === "all";
  let windowKey: string | null = null;
  if (def.windows) {
    const asked = typeof req.window === "string" ? req.window : def.defaultWindow;
    const w = def.windows.find((x) => x.key === asked);
    if (!w) throw new ReportInputError(`${def.title} covers ${def.windows.map((x) => x.label.toLowerCase()).join(", ")}.`);
    if (all && !w.allTenants) throw new ReportInputError(`${w.label} reads Sophos again for every tenant, so it runs on one tenant. Pick one, or a shorter window.`);
    windowKey = w.key;
  }
  if (def.fusion === "required" && !all && provider.get("generation", tenant)?.generation === "classic") {
    throw new ReportInputError(`${def.title} needs the tenant on Sophos Fusion (Search GraphQL). This tenant is still on the Classic APIs.`);
  }
  const params = cleanParams(req.params);
  // Inputs that reach a query are checked now, so a bad one is refused before anything starts.
  if (def.inputs.includes("user")) cleanUser(params.user);
  if (def.inputs.includes("match")) logSpec(params);
  return { def, tenant, windowKey, timeZone: validTimeZone(req.timeZone) ?? serverTimeZone(), params };
}

export interface RunOptions {
  source: ReportSource;
  settings: Settings;
  now?: number;
  progress?: (step: string) => void;
}

function tallyCalls(calls: CallRecord[]): ReportDocument["calls"] {
  const byKind: Record<string, number> = {};
  for (const c of calls) {
    const k = c.method === "GET" ? "GET" : c.operation ? `GraphQL ${c.operation}` : `${c.method} ${c.path}`;
    byKind[k] = (byKind[k] ?? 0) + 1;
  }
  return { total: calls.length, byKind };
}

export async function runReport(checked: CheckedRequest, options: RunOptions): Promise<ReportDocument> {
  const provider = options.source.provider;
  const now = options.now ?? Date.now();
  const { def } = checked;
  const scope = scopeFor(provider, checked.tenant);
  let window: ReportWindow | null = null;
  if (checked.windowKey && def.windows) {
    const w = def.windows.find((x) => x.key === checked.windowKey)!;
    const end = def.id === "user" || def.id === "logsearch" ? Math.floor(now / QUARTER) * QUARTER : now;
    window = { key: w.key, label: w.label, hours: w.hours, start: end - w.hours * 3_600_000, end };
  }
  const calls: CallRecord[] = [];
  const ctx: BuildContext = {
    source: options.source,
    provider,
    settings: options.settings,
    scope,
    window,
    tz: checked.timeZone,
    now,
    params: checked.params,
    progress: options.progress ?? (() => undefined),
  };
  const built = await callTally.run(calls, () => BUILDERS[def.id](ctx));
  const credential = provider.context ? `${provider.label} (${provider.context.label.toLowerCase()} credential)` : provider.label;
  const params: Record<string, string> = { ...(built.params ?? {}) };
  return {
    version: 1,
    reportId: def.id,
    title: def.title,
    subject: built.subject,
    scope: { label: scope.all ? `All tenants (${scope.tenants.length})` : (scope.tenants[0]?.name ?? provider.label), tenantId: scope.tenantId, all: scope.all, tenants: scope.tenants.length, credential },
    window: window ? { start: window.start, end: window.end, label: `${window.label}: ${windowLabel(window.start, window.end, checked.timeZone)}` } : null,
    timeZone: checked.timeZone,
    generatedAt: Date.now(),
    demo: options.source.kind === "demo",
    summary: built.summary,
    sections: built.sections,
    gaps: [...new Set(built.gaps)],
    provenance: built.provenance,
    calls: tallyCalls(calls),
    params,
  };
}
