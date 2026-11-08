/**
 * Case activity and response times, from the cached cases (open now, and
 * closed in the last 30 days): opened and closed per day, time to close by
 * severity and by who worked them against the targets set in Setup, and the
 * open cases most over target.
 */

import type { CaseRecord, Severity } from "../../data/types.js";
import { caseBoard, quantile, type CaseInput } from "../../mappers/views.js";
import { SEVERITIES, SEV_LABEL, asOfText, cachedAsOf, kpi, section, sevTone, table, tenantName, type BuildContext, type BuiltReport } from "../context.js";
import { formatDuration, formatNumber, formatPercent, plural } from "../format.js";
import type { Block, Tone } from "../types.js";
import { buckets } from "./series.js";

const HOUR = 3_600_000;

function sevKey(s: CaseRecord["severity"]): Severity {
  return s === "unset" ? "info" : s;
}

const OWNER: Record<string, string> = { mdr: "Sophos MDR", self: "Your team" };

export interface CaseFacts {
  opened: CaseRecord[];
  closed: CaseRecord[];
  open: CaseRecord[];
  inputs: CaseInput[];
  warnings: string[];
  truncated: boolean;
}

export function caseFacts(ctx: BuildContext): CaseFacts {
  const start = ctx.window!.start;
  const opened: CaseRecord[] = [];
  const closed: CaseRecord[] = [];
  const open: CaseRecord[] = [];
  const inputs: CaseInput[] = [];
  const warnings = new Set<string>();
  let truncated = false;
  for (const t of ctx.scope.tenants) {
    const set = ctx.provider.get("cases", t.id);
    if (!set) continue;
    inputs.push({ set, tenantName: ctx.scope.all ? t.name : undefined });
    set.warnings.forEach((w) => warnings.add(w));
    truncated ||= set.truncated;
    for (const c of set.open) {
      open.push(c);
      if (Date.parse(c.createdAt) >= start) opened.push(c);
    }
    for (const c of set.recentClosed) {
      if (Date.parse(c.createdAt) >= start) opened.push(c);
      if (c.closedAt && Date.parse(c.closedAt) >= start) closed.push(c);
    }
  }
  return { opened, closed, open, inputs, warnings: [...warnings], truncated };
}

export function closeStats(cases: CaseRecord[], targets: Record<Severity, number>) {
  const ttc = cases.filter((c) => c.closedAt).map((c) => ({ c, ms: Math.max(0, Date.parse(c.closedAt!) - Date.parse(c.createdAt)) }));
  const met = ttc.filter((x) => x.ms <= targets[sevKey(x.c.severity)] * HOUR).length;
  return { n: ttc.length, median: quantile(ttc.map((x) => x.ms), 0.5), p90: quantile(ttc.map((x) => x.ms), 0.9), met, metShare: ttc.length ? met / ttc.length : null };
}

export async function buildCases(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  const window = ctx.window!;
  const targets = ctx.settings.targets;
  ctx.progress("Reading cached cases");
  const f = caseFacts(ctx);
  const board = caseBoard(f.inputs, targets, ctx.now, "all", 100_000);
  const openCards = board.lanes.filter((l) => l.key !== "resolved").flatMap((l) => l.cards);
  const over = openCards.filter((c) => c.over);
  const waiting = openCards.filter((c) => c.lane === "waiting");
  const all = closeStats(f.closed, targets);

  const b = buckets(window, tz);
  const perDay = b.labels.map((label) => ({ label, values: [0, 0] }));
  for (const c of f.opened) {
    const i = b.index(Date.parse(c.createdAt));
    if (i >= 0) perDay[i]!.values[0]!++;
  }
  for (const c of f.closed) {
    const i = b.index(Date.parse(c.closedAt!));
    if (i >= 0) perDay[i]!.values[1]!++;
  }

  const activity: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("Opened", formatNumber(f.opened.length)),
        kpi("Closed", formatNumber(f.closed.length)),
        kpi("Open now", formatNumber(openCards.length), `${formatNumber(board.bySeverity.critical + board.bySeverity.high)} critical or high`, board.bySeverity.critical ? "bad" : undefined),
        kpi("Over target", formatNumber(over.length), openCards.length ? `${formatPercent(over.length, openCards.length)} of open cases` : undefined, over.length ? "bad" : "good"),
      ],
    },
    { kind: "series", title: b.hourly ? "Cases opened and closed per hour" : "Cases opened and closed per day", unit: "cases", series: [{ key: "opened", label: "Opened", tone: "accent" }, { key: "closed", label: "Closed", tone: "good" }], buckets: perDay, empty: "No case opened or closed in the window." },
    { kind: "bars", title: "Open cases by severity", unit: "cases", rows: SEVERITIES.map((s) => ({ label: SEV_LABEL[s], value: board.bySeverity[s], tone: sevTone(s) })) },
    { kind: "bars", title: "Open cases by stage", unit: "cases", rows: board.lanes.filter((l) => l.key !== "resolved").map((l) => ({ label: l.title, value: l.count, note: l.note, tone: (l.key === "waiting" ? "warn" : "accent") as Tone })) },
  ];

  const bySev = SEVERITIES.map((s) => {
    const st = closeStats(f.closed.filter((c) => sevKey(c.severity) === s), targets);
    return { severity: SEV_LABEL[s], closed: st.n, median: st.median, p90: st.p90, target: targets[s] * HOUR, met: st.metShare === null ? "-" : formatPercent(st.met, st.n) };
  }).filter((r) => r.closed > 0);
  const byOwner = (["mdr", "self", null] as const).map((who) => {
    const st = closeStats(f.closed.filter((c) => c.managedBy === who), targets);
    return { owner: who ? OWNER[who]! : "Not set", closed: st.n, median: st.median, p90: st.p90, met: st.metShare === null ? "-" : formatPercent(st.met, st.n) };
  }).filter((r) => r.closed > 0);
  const response: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("Median time to close", formatDuration(all.median), `${plural(all.n, "case")} closed`),
        kpi("90th percentile", formatDuration(all.p90)),
        kpi("Closed within target", all.metShare === null ? "-" : formatPercent(all.met, all.n), undefined, all.metShare !== null && all.metShare < 0.8 ? "warn" : undefined),
        kpi("Waiting on customer", formatNumber(waiting.length), waiting.length ? `${formatNumber(waiting.filter((c) => c.autoCloseInMs !== null && c.autoCloseInMs <= 2 * 86_400_000).length)} MDR cases auto-close within 2 days` : undefined, waiting.length ? "warn" : undefined),
      ],
    },
    table("time-to-close-severity", "Time to close by severity", [
      { key: "severity", label: "Severity", width: 1.4 },
      { key: "closed", label: "Closed", format: "number", width: 1 },
      { key: "median", label: "Median", format: "duration", width: 1.2 },
      { key: "p90", label: "90th percentile", format: "duration", width: 1.3 },
      { key: "target", label: "Target", format: "duration", width: 1.1 },
      { key: "met", label: "Within target", width: 1.1 },
    ], bySev, { empty: "No case closed in the window." }),
    table("time-to-close-owner", "Time to close by who worked the case", [
      { key: "owner", label: "Worked by", width: 1.6 },
      { key: "closed", label: "Closed", format: "number", width: 1 },
      { key: "median", label: "Median", format: "duration", width: 1.2 },
      { key: "p90", label: "90th percentile", format: "duration", width: 1.3 },
      { key: "met", label: "Within target", width: 1.1 },
    ], byOwner, { empty: "No case closed in the window." }),
  ];

  const tenantCol = ctx.scope.all ? [{ key: "tenant", label: "Tenant", width: 1.8 }] : [];
  const openRows = [...openCards].sort((a, b) => b.pct - a.pct || b.ageMs - a.ageMs).map((c) => ({
    ref: c.ref,
    title: c.title,
    severity: SEV_LABEL[c.severity],
    stage: c.statusTitle,
    owner: c.owner,
    age: c.ageMs,
    target: c.targetMs,
    state: c.lane === "waiting" ? "Clock paused" : c.lane === "hold" ? "On hold" : c.over ? `Over by ${formatDuration(c.ageMs - c.targetMs)}` : `${formatDuration(c.targetMs - c.ageMs)} left`,
    ...(ctx.scope.all ? { tenant: c.tenantName ?? tenantName(ctx.provider, c.tenantId) } : {}),
  }));
  const closedRows = [...f.closed].sort((a, b) => Date.parse(b.closedAt!) - Date.parse(a.closedAt!)).map((c) => {
    const ms = Date.parse(c.closedAt!) - Date.parse(c.createdAt);
    return {
      ref: c.ref,
      title: c.title,
      severity: SEV_LABEL[c.severity],
      owner: c.managedBy ? OWNER[c.managedBy]! : "Not set",
      created: Date.parse(c.createdAt),
      closed: Date.parse(c.closedAt!),
      ttc: ms,
      met: ms <= targets[sevKey(c.severity)] * HOUR ? "Yes" : "No",
      ...(ctx.scope.all ? { tenant: tenantName(ctx.provider, c.tenantId) } : {}),
    };
  });
  const lists: Block[] = [
    table("open-cases", "Open cases, most over target first", [
      { key: "ref", label: "Case", format: "mono", width: 1.1 },
      { key: "title", label: "Title", width: 3.4 },
      ...tenantCol,
      { key: "severity", label: "Severity", width: 0.9 },
      { key: "stage", label: "Status", width: 1.5 },
      { key: "owner", label: "Worked by", width: 1.1 },
      { key: "age", label: "Age", format: "duration", width: 1 },
      { key: "state", label: "Against target", width: 1.5 },
    ], openRows, { empty: "No open cases.", pdfRows: 40 }),
    table("closed-cases", "Cases closed in the window", [
      { key: "ref", label: "Case", format: "mono", width: 1.1 },
      { key: "title", label: "Title", width: 3.2 },
      ...tenantCol,
      { key: "severity", label: "Severity", width: 0.9 },
      { key: "owner", label: "Worked by", width: 1.1 },
      { key: "created", label: "Created", format: "datetime", width: 1.6 },
      { key: "closed", label: "Closed", format: "datetime", width: 1.6 },
      { key: "ttc", label: "Time to close", format: "duration", width: 1.1 },
      { key: "met", label: "In target", width: 0.8 },
    ], closedRows, { empty: "No case closed in the window.", pdfRows: 40 }),
  ];

  const gaps = [
    `No Sophos API carries a case SLA, due date, first response time or status change time. Targets are the ones set in Setup: ${SEVERITIES.map((s) => `${SEV_LABEL[s]} ${formatDuration(targets[s] * HOUR)}`).join(", ")}. A case waiting on the customer counts its age only to its last update.`,
    ...f.warnings,
  ];
  if (f.truncated) gaps.push("Some tenants hold more open cases than the toolkit reads (1,000); the oldest are missing.");
  const noCases = ctx.scope.tenants.filter((t) => ctx.provider.get("cases", t.id)?.api === "none").length;
  if (noCases) gaps.push(`${plural(noCases, "tenant")} have no cases (no XDR or MDR licence).`);
  return {
    subject: ctx.scope.all ? `All tenants (${ctx.scope.tenants.length})` : ctx.scope.tenants[0]?.name ?? "",
    summary: [
      kpi("Opened", formatNumber(f.opened.length)),
      kpi("Closed", formatNumber(f.closed.length)),
      kpi("Open now", formatNumber(openCards.length), undefined, board.bySeverity.critical ? "bad" : undefined),
      kpi("Over target", formatNumber(over.length), undefined, over.length ? "bad" : "good"),
      kpi("Median time to close", formatDuration(all.median)),
      kpi("Unassigned", formatNumber(board.unassigned), undefined, board.unassigned ? "warn" : undefined),
    ],
    sections: [
      section("activity", "Case activity", activity),
      section("response", "Response times", response, "Time to close runs from when Sophos created the case to when it was closed, measured against the targets in Setup."),
      section("lists", "The cases", lists),
    ],
    gaps,
    provenance: [{ label: "Cases", detail: `Cases v2 and cases v1, refreshed every 5 to 60 minutes, ${asOfText(cachedAsOf(ctx.provider, "cases", ctx.scope.tenants), tz)}`, asOf: cachedAsOf(ctx.provider, "cases", ctx.scope.tenants) }],
  };
}

