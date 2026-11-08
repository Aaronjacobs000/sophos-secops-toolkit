/**
 * Endpoint health and agent coverage: the state of every device now, the
 * 30-day trend the toolkit has kept, the devices to fix first, the health
 * check sections and licence use. Every device goes to the CSV.
 */

import type { EndpointRecord } from "../../data/types.js";
import { compareVersions, endpointSummary, silentDays } from "../../mappers/views.js";
import { asOfText, cachedAsOf, kpi, section, table, tenantName, type BuildContext, type BuiltReport } from "../context.js";
import { dayLabel, dayKey, formatCalendarDate, formatNumber, formatPercent, plural } from "../format.js";
import type { Block, Tone } from "../types.js";

const HEALTH_LABEL: Record<string, string> = { good: "Good", suspicious: "Suspicious", bad: "Bad", unknown: "Unknown" };
const SECTION_LABEL: Record<string, string> = { protection: "Protection installed", policy: "Policies as recommended", exclusions: "Exclusions", tamperProtection: "Tamper protection" };

function issues(e: EndpointRecord, days: number | null, outdated: boolean): string {
  const out: string[] = [];
  if (e.health === "bad") out.push("bad health");
  else if (e.health === "suspicious") out.push("suspicious health");
  if (days !== null && days >= 7) out.push(`silent ${plural(days, "day")}`);
  if (days === null) out.push("never seen");
  if (e.tamper === false) out.push("tamper protection off");
  if (outdated) out.push("agent behind");
  if (e.isolation === "isolated") out.push("isolated");
  return out.join(", ") || "-";
}

export async function buildEndpoints(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  ctx.progress("Reading cached devices");
  const all = ctx.scope.tenants.flatMap((t) => (ctx.provider.get("endpoints", t.id) ?? []).map((e) => ({ ...e, tenantName: ctx.scope.all ? t.name : undefined, tenantId: t.id })));
  const s = endpointSummary(all, ctx.now);
  const unhealthy = s.health.bad + s.health.suspicious;
  // Behind: older than the newest agent seen on the same platform, compared to three parts, as the Endpoints screen does.
  const base = (v: string) => v.split(".").slice(0, 3).join(".");
  const newest = new Map<string, string>();
  for (const e of all) if (e.agentVersion && (!newest.has(e.platform) || compareVersions(e.agentVersion, newest.get(e.platform)!) > 0)) newest.set(e.platform, e.agentVersion);
  const behind = (e: EndpointRecord) => !!e.agentVersion && newest.has(e.platform) && compareVersions(base(e.agentVersion), base(newest.get(e.platform)!)) < 0;

  const state: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("Devices", formatNumber(s.total), `${formatNumber(s.servers)} servers`),
        kpi("Unhealthy", formatNumber(unhealthy), `${formatNumber(s.health.bad)} bad, ${formatNumber(s.health.suspicious)} suspicious`, s.health.bad ? "bad" : unhealthy ? "warn" : "good"),
        kpi("Silent 7 days or more", formatNumber(s.staleOver7), s.total ? `${formatPercent(s.staleOver7, s.total)} of devices` : undefined, s.staleOver7 ? "warn" : undefined),
        kpi("Tamper protection off", formatNumber(s.tamperOff), undefined, s.tamperOff ? "bad" : "good"),
      ],
    },
    { kind: "stack", title: "Device health", segments: [{ label: "Good", value: s.health.good, tone: "good" }, { label: "Suspicious", value: s.health.suspicious, tone: "warn" }, { label: "Bad", value: s.health.bad, tone: "bad" }, { label: "Unknown", value: s.health.unknown, tone: "neutral" }] },
    { kind: "bars", title: "Devices by last contact", unit: "devices", rows: [
      { label: "Last 7 days", value: s.total - s.staleOver7 - s.stale.never, tone: "good" },
      { label: "7 to 13 days", value: s.stale.d7, tone: "warn" },
      { label: "14 to 29 days", value: s.stale.d14, tone: "warn" },
      { label: "30 to 89 days", value: s.stale.d30, tone: "bad" },
      { label: "90 days or more", value: s.stale.d90, tone: "bad" },
      { label: "Never", value: s.stale.never, tone: "neutral" },
    ] },
    { kind: "bars", title: "Devices by platform", unit: "devices", rows: s.byPlatform.map((p) => ({ label: p.platform === "macos" ? "macOS" : p.platform[0]!.toUpperCase() + p.platform.slice(1), value: p.count, tone: "accent" as Tone })), empty: "No devices." },
    { kind: "bars", title: "Agent versions", unit: "devices", rows: s.versions.list.map((v) => ({ label: `${v.platformName} ${v.version}`, value: v.count, note: v.outdated ? "behind" : undefined, tone: (v.outdated ? "warn" : "good") as Tone })), empty: "No agent versions reported.", note: s.versions.newest ? `Newest seen: ${s.versions.newest}. A device is behind when its agent is older than the newest on the same platform in this scope.` : undefined },
  ];

  const trend: Block[] = [];
  if (!ctx.scope.all && ctx.scope.tenants[0]) {
    const snaps = ctx.provider.snapshots<{ total: number; bad: number; suspicious: number; stale7: number; tamperOff: number }>("endpoints", ctx.scope.tenants[0].id, ctx.now - 30 * 86_400_000);
    if (snaps.length >= 2) {
      trend.push({ kind: "series", levels: true, title: "Devices needing attention, daily for 30 days", unit: "devices", series: [{ key: "unhealthy", label: "Unhealthy", tone: "bad" }, { key: "stale", label: "Silent 7 days or more", tone: "warn" }, { key: "tamper", label: "Tamper protection off", tone: "mdr" }], buckets: snaps.map((x) => ({ label: dayLabel(dayKey(x.takenAt, tz)), values: [x.value.bad + x.value.suspicious, x.value.stale7, x.value.tamperOff] })) });
    } else {
      trend.push({ kind: "note", tone: "gap", text: "The Endpoint API returns current state only. The toolkit keeps one summary a day from the day it first read this tenant, so a trend appears after two days." });
    }
  }

  const worst = s.worst.map((w) => ({ device: w.hostname, ...(ctx.scope.all ? { tenant: w.tenantName ?? "" } : {}), os: w.os, health: HEALTH_LABEL[w.health] ?? w.health, lastSeen: w.lastSeenAt ? Date.parse(w.lastSeenAt) : null, agent: w.agentVersion ?? "-", issues: issues({ health: w.health, tamper: w.tamper, isolation: w.isolation } as EndpointRecord, w.silentDays, w.outdated) }));
  const tenantCol = ctx.scope.all ? [{ key: "tenant", label: "Tenant", width: 1.8 }] : [];
  const fix: Block[] = [
    table("fix-first", "Devices to fix first", [
      { key: "device", label: "Device", format: "mono", width: 1.8 },
      ...tenantCol,
      { key: "os", label: "OS", width: 1.8 },
      { key: "health", label: "Health", width: 1 },
      { key: "lastSeen", label: "Last seen", format: "datetime", width: 1.6 },
      { key: "agent", label: "Agent", format: "mono", width: 1.2 },
      { key: "issues", label: "Why", width: 2.8 },
    ], worst, { empty: "Every device is healthy, current and protected.", ...(s.withIssues > worst.length ? { note: `The ${formatNumber(worst.length)} devices with the most issues, of ${formatNumber(s.withIssues)} with any. Every device is in the devices CSV.` } : {}) }),
    table("devices", "Every device", [
      { key: "device", label: "Device", format: "mono", width: 1.8 },
      ...tenantCol,
      { key: "type", label: "Type", width: 0.9 },
      { key: "os", label: "OS", width: 1.8 },
      { key: "health", label: "Health", width: 1 },
      { key: "lastSeen", label: "Last seen", format: "datetime", width: 1.6 },
      { key: "silent", label: "Days silent", format: "number", width: 0.9 },
      { key: "tamper", label: "Tamper protection", width: 1 },
      { key: "agent", label: "Agent", format: "mono", width: 1.2 },
      { key: "behind", label: "Behind", width: 0.8 },
      { key: "isolation", label: "Isolation", width: 0.9 },
      { key: "person", label: "Assigned to", width: 1.4 },
    ], all.map((e) => ({ device: e.hostname, ...(ctx.scope.all ? { tenant: e.tenantName ?? tenantName(ctx.provider, e.tenantId) } : {}), type: e.isServer ? "Server" : "Computer", os: e.osName, health: HEALTH_LABEL[e.health] ?? e.health, lastSeen: e.lastSeenAt ? Date.parse(e.lastSeenAt) : null, silent: silentDays(e.lastSeenAt, ctx.now), tamper: e.tamper === false ? "Off" : e.tamper === true ? "On" : "-", agent: e.agentVersion ?? "-", behind: behind(e) ? "Yes" : "No", isolation: e.isolation ?? "-", person: e.person ?? "-" })), { pdfRows: 0, empty: "No devices." }),
  ];

  const extra: Block[] = [];
  if (!ctx.scope.all && ctx.scope.tenants[0]) {
    const h = ctx.provider.get("health", ctx.scope.tenants[0].id);
    if (h) {
      extra.push(table("health-check", "Health check", [
        { key: "section", label: "Section", width: 3 },
        { key: "score", label: "Score of 100", format: "number", width: 1 },
      ], Object.entries(h.sections).map(([k, v]) => ({ section: SECTION_LABEL[k] ?? k, score: v })), { note: `Sophos returns a score per section and no overall score. The toolkit's overall figure is their average: ${h.overall ?? "-"}.` }));
    }
  }
  const licences = ctx.scope.tenants.flatMap((t) => (ctx.provider.get("licences", t.id) ?? []).map((l) => ({ ...l, tenant: t.name })));
  extra.push(table("licences", "Licences", [
    { key: "name", label: "Product", width: 2.6 },
    ...tenantCol,
    { key: "code", label: "Code", format: "mono", width: 1.6 },
    { key: "type", label: "Type", width: 0.9 },
    { key: "ends", label: "Ends", width: 1.2 },
    { key: "quantity", label: "Quantity", format: "number", width: 1 },
    { key: "used", label: "In use", format: "number", width: 1 },
  ], licences.sort((a, b) => (a.endDate ?? "9").localeCompare(b.endDate ?? "9")).map((l) => ({ name: l.name, ...(ctx.scope.all ? { tenant: l.tenant } : {}), code: l.code, type: l.type, ends: formatCalendarDate(l.endDate, tz), quantity: l.quantity, used: l.used })), { empty: "No licences read.", pdfRows: 40 }));

  const asOf = cachedAsOf(ctx.provider, "endpoints", ctx.scope.tenants);
  return {
    subject: ctx.scope.all ? `All tenants (${ctx.scope.tenants.length})` : ctx.scope.tenants[0]?.name ?? "",
    summary: [
      kpi("Devices", formatNumber(s.total)),
      kpi("Unhealthy", formatNumber(unhealthy), undefined, s.health.bad ? "bad" : unhealthy ? "warn" : "good"),
      kpi("Silent 7 days+", formatNumber(s.staleOver7), undefined, s.staleOver7 ? "warn" : undefined),
      kpi("Tamper off", formatNumber(s.tamperOff), undefined, s.tamperOff ? "bad" : "good"),
      kpi("Agent behind", formatNumber(s.versions.outdated), undefined, s.versions.outdated ? "warn" : undefined),
      kpi("Isolated", formatNumber(s.isolated)),
    ],
    sections: [section("state", "Device state", state, `${plural(s.total, "device")} ${asOfText(asOf, tz)}.`), ...(trend.length ? [section("trend", "Trend", trend)] : []), section("fix", "Devices", fix), section("coverage", "Health check and licences", extra)],
    gaps: ["The Endpoint API reports current state only; trends come from the daily summaries the toolkit keeps.", "No Sophos API returns where a device is. The Endpoints screen's map uses each device's public egress IP."],
    provenance: [
      { label: "Devices", detail: `Endpoint API, refreshed every 30 minutes to 2 hours, ${asOfText(asOf, tz)}`, asOf },
      { label: "Health check and licences", detail: `Account health check API and licensing API, ${asOfText(cachedAsOf(ctx.provider, "health", ctx.scope.tenants), tz)}`, asOf: cachedAsOf(ctx.provider, "health", ctx.scope.tenants) },
    ],
  };
}
