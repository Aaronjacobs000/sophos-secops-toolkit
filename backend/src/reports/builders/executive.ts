/**
 * Executive summary: what happened in the window and what needs a decision,
 * for one tenant or a whole partner estate, with AI Defense usage. Built from
 * the dashboard cache;
 * 30 days on one tenant rereads detections and alerts, because the cache
 * keeps 7 days of them.
 */

import { caseBoard, endpointSummary, signinView, smimeStatus, sourcesView, tenantTile } from "../../mappers/views.js";
import { SEVERITIES, SEV_LABEL, asOfText, cachedAsOf, kpi, section, sevTone, table, type BuildContext, type BuiltReport } from "../context.js";
import { formatCalendarDate, formatDuration, formatNumber, formatPercent, plural } from "../format.js";
import type { Block, Tone } from "../types.js";
import { caseFacts, closeStats } from "./cases.js";
import { signalFacts } from "./detections.js";
import { buckets } from "./series.js";
import { aiDefenseSection } from "./ai-defense.js";

const DAY = 86_400_000;

export async function buildExecutive(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  const w = ctx.window!;
  const tenants = ctx.scope.tenants;
  const sig = await signalFacts(ctx, { detail: false });
  ctx.progress("Summarising cases, devices and identity");
  const cf = caseFacts(ctx);
  const board = caseBoard(cf.inputs, ctx.settings.targets, ctx.now, "all", 100_000);
  const openCards = board.lanes.filter((l) => l.key !== "resolved").flatMap((l) => l.cards);
  const closed = closeStats(cf.closed, ctx.settings.targets);
  const mdrClosed = cf.closed.filter((c) => c.managedBy === "mdr").length;
  const devices = tenants.flatMap((t) => ctx.provider.get("endpoints", t.id) ?? []);
  const es = endpointSummary(devices, ctx.now);
  const healthScores = tenants.map((t) => ctx.provider.get("health", t.id)?.overall).filter((x): x is number => typeof x === "number");
  const health = healthScores.length ? Math.round(healthScores.reduce((a, b) => a + b, 0) / healthScores.length) : null;
  const fusion = tenants.filter((t) => ctx.provider.get("generation", t.id)?.generation === "fusion");
  const si = signinView(fusion.map((t) => ({ signins: ctx.provider.get("signins", t.id), mfa: ctx.provider.get("mfa", t.id) })), false);
  const so = sourcesView(fusion.map((t) => ({ set: ctx.provider.get("sources", t.id) })), ctx.now, 5_000);
  const signalTotal = sig.total + sig.alerts.length;
  const critHighSignals = sig.items.filter((d) => d.severity === "critical" || d.severity === "high").length + sig.alerts.filter((a) => a.severity === "high").length;

  // ------------------------------------------------------------ what needs a decision
  const attention: Array<{ item: string; detail: string; where: string; tone: Tone }> = [];
  const where = (id: string) => (ctx.scope.all ? (ctx.provider.tenant(id)?.name ?? id) : "");
  const overCrit = openCards.filter((c) => c.over && (c.severity === "critical" || c.severity === "high"));
  if (overCrit.length) attention.push({ item: `${plural(overCrit.length, "critical or high case")} over target`, detail: `Oldest: ${overCrit.sort((a, b) => b.ageMs - a.ageMs)[0]!.ref}, open ${formatDuration(overCrit[0]!.ageMs)}`, where: ctx.scope.all ? [...new Set(overCrit.map((c) => where(c.tenantId)))].slice(0, 3).join(", ") : "", tone: "bad" });
  const waitingMdr = openCards.filter((c) => c.autoCloseInMs !== null && c.autoCloseInMs <= 2 * DAY);
  if (waitingMdr.length) attention.push({ item: `${plural(waitingMdr.length, "MDR case")} waiting on you`, detail: "Sophos MDR closes a Customer Action Required case after 5 days with no reply", where: ctx.scope.all ? [...new Set(waitingMdr.map((c) => where(c.tenantId)))].slice(0, 3).join(", ") : "", tone: "warn" });
  if (es.health.bad) attention.push({ item: `${plural(es.health.bad, "device")} in bad health`, detail: "Threats or services reported unhealthy", where: "", tone: "bad" });
  if (es.tamperOff) attention.push({ item: `Tamper protection off on ${plural(es.tamperOff, "device")}`, detail: "Anyone with admin rights on them can turn protection off", where: "", tone: "bad" });
  if (es.staleOver7) attention.push({ item: `${plural(es.staleOver7, "device")} silent 7 days or more`, detail: `${formatNumber(es.stale.d30 + es.stale.d90)} of them 30 days or more: retire them or find out why`, where: "", tone: "warn" });
  if (si.mfa.reportsMfa && si.mfa.withoutMfa) attention.push({ item: `${plural(si.mfa.withoutMfa, "sign-in")} without MFA`, detail: `${formatPercent(si.mfa.withoutMfa, si.mfa.signins)} of interactive user sign-ins, last 7 days`, where: "", tone: "bad" });
  if (so.counts.silent) attention.push({ item: `${plural(so.counts.silent, "data source")} stopped sending`, detail: [...new Set(so.rows.filter((r) => r.state === "silent").map((r) => r.label))].slice(0, 3).join(", "), where: "", tone: "bad" });
  for (const t of tenants) {
    for (const l of ctx.provider.get("licences", t.id) ?? []) {
      const end = l.endDate ? Date.parse(l.endDate) : NaN;
      if (Number.isFinite(end) && end >= ctx.now && end - ctx.now <= 30 * DAY) attention.push({ item: `${l.name} ends ${formatCalendarDate(l.endDate, tz)}`, detail: `${plural(Math.ceil((end - ctx.now) / DAY), "day")} left`, where: where(t.id), tone: end - ctx.now <= 7 * DAY ? "bad" : "warn" });
    }
    const sm = smimeStatus(ctx.provider.get("smime", t.id), ctx.now);
    if (sm?.level && sm.days !== null) attention.push({ item: `S/MIME ${sm.kind === "ca" ? "internal CA" : "certificate"} expires in ${plural(sm.days, "day")}`, detail: "Signed and encrypted email stops working when it does", where: where(t.id), tone: sm.level === "critical" ? "bad" : "warn" });
  }

  const summary = [
    kpi("Signals", formatNumber(signalTotal), `${formatNumber(critHighSignals)} critical or high${sig.sampled ? ` in the newest ${formatNumber(sig.items.length + sig.alerts.length)} read` : ""}`, critHighSignals ? "high" : undefined),
    kpi("Cases opened", formatNumber(cf.opened.length), `${formatNumber(cf.closed.length)} closed`),
    kpi("Open cases", formatNumber(openCards.length), `${formatNumber(openCards.filter((c) => c.over).length)} over target`, openCards.some((c) => c.over) ? "bad" : undefined),
    kpi("Median time to close", formatDuration(closed.median), closed.n ? `${formatPercent(closed.met, closed.n)} within target` : undefined),
    kpi("Devices", formatNumber(es.total), `${formatNumber(es.health.bad + es.health.suspicious)} unhealthy`, es.health.bad ? "bad" : undefined),
    kpi("Health score", health === null ? "-" : `${health} / 100`, health === null ? undefined : `Average of ${plural(healthScores.length, "tenant")}`, health !== null && health < 70 ? "warn" : undefined),
  ];

  const sections = [];
  sections.push(section("attention", "What needs a decision", [
    table("attention", "Needs attention", [
      { key: "item", label: "Item", width: 3 },
      { key: "detail", label: "Why it matters", width: 3.4 },
      ...(ctx.scope.all ? [{ key: "where", label: "Tenants", width: 2 }] : []),
    ], attention.map((a) => ({ item: a.item, detail: a.detail, ...(ctx.scope.all ? { where: a.where || "Across the estate" } : {}) })), { empty: "Nothing in the toolkit's data needs a decision." }),
  ], "Taken from the figures in the rest of this report."));

  // ------------------------------------------------------------ signals
  const b = buckets(w, tz);
  const per = b.labels.map((label) => ({ label, values: SEVERITIES.map(() => 0) }));
  for (const d of sig.items) {
    const i = b.index(d.createdAt);
    if (i >= 0) per[i]!.values[SEVERITIES.indexOf(d.severity)]!++;
  }
  for (const a of sig.alerts) {
    const i = b.index(Date.parse(a.raisedAt));
    if (i >= 0) per[i]!.values[SEVERITIES.indexOf(a.severity === "high" ? "high" : a.severity === "medium" ? "medium" : a.severity === "low" ? "low" : "info")]!++;
  }
  const detectors = new Map<string, number>();
  for (const d of sig.items) detectors.set(d.title, (detectors.get(d.title) ?? 0) + 1);
  const signals: Block[] = [
    { kind: "series", title: b.hourly ? "Detections and alerts per hour by severity" : "Detections and alerts per day by severity", unit: "signals", series: SEVERITIES.map((s) => ({ key: s, label: SEV_LABEL[s], tone: sevTone(s) })), buckets: per, empty: "No detections or alerts in the window." },
    { kind: "bars", title: sig.fresh ? "Most frequent detections" : "Detectors that fired most", unit: "detections", rows: [...detectors.entries()].sort((a, b2) => b2[1] - a[1]).slice(0, 8).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: sig.fusionTenants ? "No detections in the window." : "No Fusion tenant: Classic tenants raise product alerts, counted above." },
  ];
  for (const n of sig.notes) signals.push({ kind: "note", tone: "warn", text: n });
  sections.push(section("signals", "Signals", signals, sig.fusionTenants ? `${plural(sig.total, "detection")} from ${plural(sig.fusionTenants, "Fusion tenant")} and ${plural(sig.alerts.length, "product alert")}.` : `No tenant here is on Sophos Fusion, so there are no detections; ${plural(sig.alerts.length, "product alert")}.`));

  // ------------------------------------------------------------ cases
  sections.push(section("cases", "Cases", [
    { kind: "kpis", items: [kpi("Opened", formatNumber(cf.opened.length)), kpi("Closed", formatNumber(cf.closed.length), cf.closed.length ? `${formatPercent(mdrClosed, cf.closed.length)} by Sophos MDR` : undefined), kpi("Open now", formatNumber(openCards.length)), kpi("90th percentile to close", formatDuration(closed.p90))] },
    { kind: "bars", title: "Open cases by severity", unit: "cases", rows: SEVERITIES.map((s) => ({ label: SEV_LABEL[s], value: board.bySeverity[s], tone: sevTone(s) })) },
    { kind: "stack", title: "Cases closed in the window, by who worked them", segments: [{ label: "Sophos MDR", value: mdrClosed, tone: "mdr" }, { label: "Your team", value: cf.closed.filter((c) => c.managedBy === "self").length, tone: "self" }, { label: "Not set", value: cf.closed.filter((c) => !c.managedBy).length, tone: "neutral" }] },
  ]));

  // ------------------------------------------------------------ devices
  sections.push(section("devices", "Devices", [
    { kind: "stack", title: `Health of ${plural(es.total, "device")}`, segments: [{ label: "Good", value: es.health.good, tone: "good" }, { label: "Suspicious", value: es.health.suspicious, tone: "warn" }, { label: "Bad", value: es.health.bad, tone: "bad" }, { label: "Unknown", value: es.health.unknown, tone: "neutral" }] },
    { kind: "kpis", items: [kpi("Silent 7 days+", formatNumber(es.staleOver7), undefined, es.staleOver7 ? "warn" : undefined), kpi("Tamper protection off", formatNumber(es.tamperOff), undefined, es.tamperOff ? "bad" : "good"), kpi("Agent behind", formatNumber(es.versions.outdated), undefined, es.versions.outdated ? "warn" : undefined), kpi("Isolated", formatNumber(es.isolated))] },
  ]));

  // ------------------------------------------------------------ identity and sources
  if (fusion.length && (si.tenantsWithData || so.tenantsWithData)) {
    const ib: Block[] = [];
    if (si.tenantsWithData) ib.push({ kind: "kpis", items: [kpi("Sign-ins", formatNumber(si.total)), kpi("Failed", formatNumber(si.failed), undefined, si.failed ? "warn" : undefined), kpi("Without MFA", si.mfa.reportsMfa && si.mfa.signins ? formatNumber(si.mfa.withoutMfa) : "-", si.mfa.reportsMfa ? undefined : "No source reports MFA", si.mfa.withoutMfa ? "bad" : undefined), kpi("Places", formatNumber(si.locations.length))] });
    if (so.tenantsWithData) ib.push({ kind: "kpis", items: [kpi("Data sources", formatNumber(so.counts.sources)), kpi("Live", formatNumber(so.counts.live), undefined, "good"), kpi("Quiet or silent", formatNumber(so.counts.quiet + so.counts.silent), undefined, so.counts.silent ? "bad" : so.counts.quiet ? "warn" : undefined), kpi("Unparsed events", formatNumber(so.unparsed7d))] });
    ib.push({ kind: "note", tone: "info", text: "Sign-ins and data sources cover the last 7 days whatever window the report uses: the toolkit keeps one 7-day search of each per Fusion tenant." });
    sections.push(section("identity", "Identity and data sources", ib));
  }

  // ------------------------------------------------------------ AI Defense
  const ai = aiDefenseSection(ctx);
  sections.push(ai.section);

  // ------------------------------------------------------------ tenants
  if (ctx.scope.all) {
    const tiles = tenants.map((t) =>
      tenantTile({ tenant: t, generation: ctx.provider.get("generation", t.id)?.generation ?? null, cases: ctx.provider.get("cases", t.id), endpoints: ctx.provider.get("endpoints", t.id), health: ctx.provider.get("health", t.id), licences: ctx.provider.get("licences", t.id), alerts: ctx.provider.get("alerts", t.id), smime: ctx.provider.get("smime", t.id), fetchedAt: null, errors: 0 }, ctx.now),
    ).sort((a, b2) => b2.score - a.score || a.name.localeCompare(b2.name));
    const STATE: Record<string, string> = { critical: "Critical", warning: "Warning", healthy: "Healthy", pending: "Not read yet" };
    sections.push(section("tenants", "Tenants, worst first", [
      table("tenants", "Tenants", [
        { key: "name", label: "Tenant", width: 2.6 },
        { key: "state", label: "State", width: 1 },
        { key: "headline", label: "Main reason", width: 2.8 },
        { key: "critHigh", label: "Crit/high cases", format: "number", width: 1 },
        { key: "stale", label: "Stale devices", format: "number", width: 1 },
        { key: "health", label: "Health", format: "number", width: 0.8 },
        { key: "gen", label: "APIs", width: 0.8 },
      ], tiles.map((t) => ({ name: t.name, state: STATE[t.state] ?? t.state, headline: t.headline, critHigh: t.metrics[0]?.value === "-" ? null : Number(t.metrics[0]?.value), stale: t.metrics[1]?.value === "-" ? null : Number(t.metrics[1]?.value), health: t.metrics[2]?.value === "-" ? null : Number(t.metrics[2]?.value), gen: t.generation === "fusion" ? "Fusion" : t.generation === "classic" ? "Classic" : "-" })), { pdfRows: 60 }),
      { kind: "note", tone: "info", text: "A tenant is critical with an open critical case, three or more high cases, three devices in bad health, tamper protection off on a quarter of its devices, a health score under 50, or a licence or S/MIME certificate ending within 7 days. Smaller versions of the same make it a warning, as on the MSP wall." },
    ]));
  }

  const asOf = (d: "cases" | "endpoints" | "detections" | "alerts") => cachedAsOf(ctx.provider, d, tenants);
  return {
    subject: ctx.scope.all ? `All tenants (${tenants.length})` : tenants[0]?.name ?? "",
    summary,
    sections,
    gaps: [
      "No Sophos API carries a case SLA or first response time; targets come from Setup.",
      "Sophos returns no overall health score; the toolkit averages the health check sections.",
      ...(sig.fusionTenants < tenants.length ? [`${plural(tenants.length - sig.fusionTenants, "tenant")} on the Classic APIs have product alerts but no Fusion detections, sign-in or data source figures.`] : []),
    ],
    provenance: [
      { label: "Detections and alerts", detail: sig.fresh ? "Read for this report" : `Cached: ${sig.fusionTenants ? `detections ${asOfText(asOf("detections"), tz)}, alerts` : "alerts (no Fusion tenant, so no detections)"} ${asOfText(asOf("alerts"), tz)}`, asOf: sig.fresh ? ctx.now : asOf("alerts") },
      { label: "Cases", detail: `Cached ${asOfText(asOf("cases"), tz)}`, asOf: asOf("cases") },
      { label: "Devices", detail: `Cached ${asOfText(asOf("endpoints"), tz)}`, asOf: asOf("endpoints") },
      ai.provenance,
    ],
  };
}
