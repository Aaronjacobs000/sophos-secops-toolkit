/**
 * Sign-ins and MFA, and data source health: the two Search GraphQL datasets
 * the Sign-ins and Sources screens keep (7 days), as reports. No extra calls.
 */

import { signinView, sourcesView } from "../../mappers/views.js";
import { asOfText, cachedAsOf, kpi, section, table, type BuildContext, type BuiltReport } from "../context.js";
import { dayLabel, formatNumber, formatPercent, plural } from "../format.js";
import type { Block, ReportSection, Tone } from "../types.js";

function fusionScope(ctx: BuildContext) {
  const fusion = ctx.scope.tenants.filter((t) => ctx.provider.get("generation", t.id)?.generation === "fusion");
  return { fusion, classic: ctx.scope.tenants.length - fusion.length };
}

function notFusion(ctx: BuildContext, what: string): ReportSection {
  return section("none", what, [{ kind: "note", tone: "gap", text: ctx.scope.all ? "None of these tenants is on Sophos Fusion yet. Search GraphQL, which this report reads, serves Fusion tenants only." : "This tenant's data is still on the Classic APIs. Search GraphQL, which this report reads, serves Fusion tenants only." }]);
}

export async function buildSignins(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  const { fusion, classic } = fusionScope(ctx);
  const subject = ctx.scope.all ? `All tenants (${ctx.scope.tenants.length})` : ctx.scope.tenants[0]?.name ?? "";
  const m = signinView(fusion.map((t) => ({ tenantName: ctx.scope.all ? t.name : undefined, signins: ctx.provider.get("signins", t.id), mfa: ctx.provider.get("mfa", t.id) })), false);
  const asOf = cachedAsOf(ctx.provider, "signins", fusion);
  const gaps: string[] = [];
  if (classic) gaps.push(`${plural(classic, "tenant")} in scope are on the Classic APIs and are not in this report.`);
  if (!m.tenantsWithData) {
    return { subject, summary: [], sections: [fusion.length ? section("none", "Sign-ins and MFA", [{ kind: "note", tone: "gap", text: "No sign-in search has finished for these tenants yet. Open the Sign-ins screen on one tenant to run it now." }]) : notFusion(ctx, "Sign-ins and MFA")], gaps, provenance: [] };
  }
  const mfa = m.mfa;
  const noAnswer = mfa.reportsMfa && !mfa.signins;
  const countries = new Set(m.locations.map((l) => l.country).filter(Boolean)).size;
  const sb: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("Sign-ins", formatNumber(m.total), `${formatNumber(m.success)} succeeded`),
        kpi("Failed", formatNumber(m.failed), m.total ? `${formatPercent(m.failed, m.total)} of sign-ins` : undefined, m.failed ? "warn" : undefined),
        kpi("Without MFA", mfa.reportsMfa && !noAnswer ? formatNumber(mfa.withoutMfa) : "-", noAnswer ? "No user sign-in with an MFA result" : mfa.reportsMfa ? `${formatPercent(mfa.withoutMfa, mfa.signins)} of ${plural(mfa.signins, "user sign-in")}` : "No source here reports MFA", mfa.withoutMfa ? "bad" : undefined),
        kpi("Places", formatNumber(m.locations.length), `${plural(countries, "country", "countries")}`),
      ],
    },
    { kind: "stack", title: "Results", segments: [{ label: "Succeeded", value: m.success, tone: "good" }, { label: "Failed", value: m.failed, tone: "warn" }, { label: "Other", value: Math.max(0, m.total - m.success - m.failed), tone: "neutral" }] },
    { kind: "bars", title: "Failure reasons", unit: "failed sign-ins", rows: m.failures.map((f) => ({ label: f.reason, value: f.count, tone: "warn" as Tone })), empty: "No failed sign-ins." },
    table("sources", "Sign-ins by source", [
      { key: "label", label: "Source", width: 2.4 },
      { key: "type", label: "Sensor type", format: "mono", width: 2.4 },
      { key: "total", label: "Sign-ins", format: "number", width: 1 },
      { key: "failed", label: "Failed", format: "number", width: 1 },
      { key: "mfa", label: "Reports MFA", width: 1 },
    ], m.bySource.map((s) => ({ label: s.label, type: s.sensorType, total: s.total, failed: s.failed, mfa: s.reportsMfa ? "Yes" : "No" }))),
  ];
  const mb: Block[] = [];
  if (mfa.reportsMfa && !noAnswer) {
    mb.push({ kind: "bars", title: "Without MFA, by application", unit: "sign-ins without MFA", rows: mfa.byApp.map((a) => ({ label: a.name, value: a.withoutMfa, note: `of ${formatNumber(a.signins)}`, tone: "bad" as Tone })) });
    mb.push({ kind: "bars", title: "Without MFA, by operating system", unit: "sign-ins without MFA", rows: mfa.byOs.map((o) => ({ label: o.name, value: o.withoutMfa, note: `of ${formatNumber(o.signins)}`, tone: "bad" as Tone })) });
    mb.push(table("users-without-mfa", "Users signing in without MFA", [
      { key: "user", label: "User", format: "mono", width: 3 },
      ...(ctx.scope.all ? [{ key: "tenant", label: "Tenant", width: 2 }] : []),
      { key: "count", label: "Without MFA", format: "number", width: 1.2 },
      { key: "source", label: "Source", width: 1.8 },
    ], mfa.topUsers.map((u) => ({ user: u.user, ...(ctx.scope.all ? { tenant: u.tenantName ?? "" } : {}), count: u.withoutMfa, source: u.source })), { empty: "Every counted sign-in used MFA." }));
  } else {
    mb.push({ kind: "note", tone: "gap", text: noAnswer ? "No interactive user sign-in in the window, so there is no MFA result to count. Service principal and non-interactive sign-ins carry none." : "No identity source in this data reports MFA. Microsoft Entra ID sign-ins do; Sophos endpoint logons never carry MFA fields." });
  }
  mb.push(table("mfa-sources", "Identity sources", [
    { key: "label", label: "Source", width: 2.4 },
    { key: "signins", label: "Successful", format: "number", width: 1.1 },
    { key: "withMfa", label: "With MFA", format: "number", width: 1 },
    { key: "withoutMfa", label: "Without MFA", format: "number", width: 1.1 },
    { key: "excluded", label: "Not counted", format: "number", width: 1.1 },
  ], mfa.sources.map((s) => ({ label: s.label, signins: s.signins, withMfa: s.reportsMfa ? s.withMfa : null, withoutMfa: s.reportsMfa ? s.withoutMfa : null, excluded: s.reportsMfa ? s.service + s.nonInteractive : null }))));
  mb.push({ kind: "note", tone: "info", text: `Only interactive user sign-ins from sources that fill the MFA fields are counted.${mfa.service + mfa.nonInteractive ? ` Not counted: ${formatNumber(mfa.service)} service principal and ${formatNumber(mfa.nonInteractive)} non-interactive sign-ins.` : ""} Sophos endpoint logons always report no MFA, so counting them would make every Windows logon a gap.` });
  const places = [
    table("places", "Where sign-ins come from", [
      { key: "place", label: "Place", width: 2.6 },
      { key: "total", label: "Sign-ins", format: "number", width: 1 },
      { key: "failed", label: "Failed", format: "number", width: 1 },
      { key: "noMfa", label: "Without MFA", format: "number", width: 1.1 },
    ], m.locations.map((l) => ({ place: [l.city, l.country].filter(Boolean).join(", ") || "Unknown", total: l.total, failed: l.failed, noMfa: l.noMfa })), { empty: "No sign-in came from a public address the toolkit could place." }),
    { kind: "note", tone: "info", text: `Placed by source IP with DB-IP City Lite where installed. ${formatNumber(m.placement.placed)} of ${formatNumber(m.total)} placed; ${formatNumber(m.placement.internal)} from internal addresses; ${formatNumber(m.placement.unplaced)} public but not located.` } as Block,
  ];
  return {
    subject,
    summary: [kpi("Sign-ins", formatNumber(m.total)), kpi("Failed", formatNumber(m.failed), undefined, m.failed ? "warn" : undefined), kpi("Without MFA", mfa.reportsMfa && !noAnswer ? formatNumber(mfa.withoutMfa) : "-", undefined, mfa.withoutMfa ? "bad" : undefined), kpi("Places", formatNumber(m.locations.length)), kpi("Sources", formatNumber(m.bySource.length)), kpi("Tenants with data", formatNumber(m.tenantsWithData))],
    sections: [section("signins", "Sign-ins", sb), section("mfa", "Sign-ins without MFA", mb), section("places", "Places", places)],
    gaps,
    provenance: [{ label: "Sign-ins and MFA", detail: `Search GraphQL, the Sign-ins screen's 7-day searches, ${asOfText(asOf, tz)}${m.search.partial.length ? `; partial: ${m.search.partial.join(", ")}` : ""}`, asOf }],
  };
}

export async function buildSources(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  const { fusion, classic } = fusionScope(ctx);
  const subject = ctx.scope.all ? `All tenants (${ctx.scope.tenants.length})` : ctx.scope.tenants[0]?.name ?? "";
  const m = sourcesView(fusion.map((t) => ({ tenantName: ctx.scope.all ? t.name : undefined, set: ctx.provider.get("sources", t.id) })), ctx.now, 5_000);
  const asOf = cachedAsOf(ctx.provider, "sources", fusion);
  const gaps: string[] = classic ? [`${plural(classic, "tenant")} in scope are on the Classic APIs and are not in this report.`] : [];
  if (!m.tenantsWithData) {
    return { subject, summary: [], sections: [fusion.length ? section("none", "Data sources", [{ kind: "note", tone: "gap", text: "No data source search has finished for these tenants yet. Open the Sources screen on one tenant to run it now." }]) : notFusion(ctx, "Data sources")], gaps, provenance: [] };
  }
  const c = m.counts;
  const STATE: Record<string, string> = { live: "Live", quiet: "Quiet 24 h or more", silent: "Not seen this week" };
  const blocks: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("Sources sending", formatNumber(c.live + c.quiet), `${formatNumber(c.live)} in the last 24 hours`),
        kpi("Quiet 24 h or more", formatNumber(c.quiet), undefined, c.quiet ? "warn" : "good"),
        kpi("Not seen this week", formatNumber(c.silent), undefined, c.silent ? "bad" : undefined),
        kpi("Unparsed", formatNumber(m.unparsed7d), m.events7d ? `${((m.unparsed7d / m.events7d) * 100).toFixed(1)}% of ${formatNumber(m.events7d)} events` : undefined),
      ],
    },
    { kind: "series", title: "Events per day, all sources (UTC days)", unit: "events", series: [{ key: "events", label: "Events", tone: "accent" }], buckets: m.days.map((d, i) => ({ label: i === m.days.length - 1 ? `${dayLabel(d)} (so far)` : dayLabel(d), values: [m.daily[i] ?? 0] })), note: "A 7-day window starts part way through a UTC day; that first partial day is left out of the chart, so its total is a little under the 7-day figure." },
    table("sources", "Data sources", [
      { key: "label", label: "Source", width: 2.4 },
      ...(ctx.scope.all ? [{ key: "tenant", label: "Tenant", width: 1.8 }] : []),
      { key: "state", label: "State", width: 1.5 },
      { key: "last", label: "Last event", format: "datetime", width: 1.6 },
      { key: "events", label: "Events, 7 days", format: "number", width: 1.2 },
      { key: "unparsed", label: "Unparsed", format: "number", width: 1 },
      { key: "schemas", label: "Event types", width: 2.4 },
    ], m.rows.map((r) => ({ label: r.label, ...(ctx.scope.all ? { tenant: r.tenantName ?? "" } : {}), state: STATE[r.state] ?? r.state, last: r.lastEventAt, events: r.events7d, unparsed: r.unparsed7d, schemas: r.schemas.join(", ") }))),
    { kind: "note", tone: "info", text: "A source is a sensor type, such as Sophos endpoints or a firewall integration. Unparsed events land in the generic schema: stored and searchable, but no detection reads them. A source the last search saw that has gone missing stays listed as not seen for 30 days." },
  ];
  return {
    subject,
    summary: [kpi("Sources", formatNumber(c.sources)), kpi("Live", formatNumber(c.live), undefined, "good" as Tone), kpi("Quiet", formatNumber(c.quiet), undefined, c.quiet ? "warn" : undefined), kpi("Not seen", formatNumber(c.silent), undefined, c.silent ? "bad" : undefined), kpi("Events, 7 days", formatNumber(m.events7d)), kpi("Unparsed", formatNumber(m.unparsed7d))],
    sections: [section("sources", "Data sources", blocks)],
    gaps,
    provenance: [{ label: "Data sources", detail: `Search GraphQL, the Sources screen's 7-day search, ${asOfText(asOf, tz)}`, asOf }],
  };
}
