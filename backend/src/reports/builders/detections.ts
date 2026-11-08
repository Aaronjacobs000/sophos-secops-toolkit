/**
 * Detections and alerts. One Fusion tenant: detections read now for the
 * window, with titles and the users, devices and addresses they name. All
 * tenants: the cached detections (detector names, no entities). Classic
 * tenants have no detections; their signals are product alerts (Common API), which
 * every scope lists.
 */

import type { AlertRecord, Severity } from "../../data/types.js";
import { productLabel, sensorLabel } from "../../mappers/views.js";
import type { DetectionDetail } from "../data.js";
import { SEVERITIES, SEV_LABEL, asOfText, cachedAsOf, kpi, list, section, sevTone, table, tenantName, type BuildContext, type BuiltReport } from "../context.js";
import { formatDateTime, formatNumber } from "../format.js";
import type { Block, Tone } from "../types.js";
import { buckets } from "./series.js";

type Item = Pick<DetectionDetail, "createdAt" | "severity" | "title" | "detector" | "sensorTypes" | "techniques" | "techniqueNames" | "tactics" | "status" | "users" | "hosts" | "ips"> & { tenantId: string };

const ALERT_SEV: Record<string, Severity> = { high: "high", medium: "medium", low: "low" };

/** "runtimeDetections" to "Runtime detections". */
function categoryLabel(raw: string): string {
  const t = raw.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").toLowerCase();
  return t.charAt(0).toUpperCase() + t.slice(1);
}

function top<T>(items: T[], key: (t: T) => string[], n = 10) {
  const m = new Map<string, number>();
  for (const it of items) for (const k of new Set(key(it))) if (k) m.set(k, (m.get(k) ?? 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n);
}

export interface SignalFacts {
  items: Item[];
  /** Sophos's total for the window where known (fresh reads), else the items counted. */
  total: number;
  sampled: boolean;
  fresh: boolean;
  alerts: Array<AlertRecord & { tenantId: string }>;
  fusionTenants: number;
  notes: string[];
}

/** Detections and alerts for the window: read now for one Fusion tenant past the cache, else from the cache. */
export async function signalFacts(ctx: BuildContext, opts: { detail: boolean }): Promise<SignalFacts> {
  const w = ctx.window!;
  const items: Item[] = [];
  const alerts: SignalFacts["alerts"] = [];
  const notes: string[] = [];
  let total = 0;
  let sampled = false;
  let fresh = false;
  let fusionTenants = 0;
  for (const t of ctx.scope.tenants) {
    const fusion = ctx.provider.get("generation", t.id)?.generation === "fusion";
    if (fusion) fusionTenants++;
    let read: Awaited<ReturnType<typeof ctx.source.detections>> | null = null;
    if (fusion && !ctx.scope.all && (opts.detail || w.hours > 168)) {
      ctx.progress("Reading detections for the window");
      try {
        read = await ctx.source.detections(t.id, w.hours);
      } catch (err) {
        // A slow or refused read leaves the report standing on the cached 7 days, and says so.
        const why = err instanceof Error && /timed out/i.test(err.message) ? "did not answer in time" : "refused the read";
        notes.push(`Sophos ${why} when the report asked for detections${w.hours > 168 ? ` over ${w.label.toLowerCase()}` : ""}, so this section shows the toolkit's cached detections for the last 7 days, without the users, devices and addresses each names. Run the report again to retry.`);
      }
    }
    if (read) {
      fresh = true;
      total += read.total;
      sampled ||= read.sampled;
      for (const d of read.items) if (d.createdAt >= w.start) items.push({ ...d, tenantId: t.id });
    } else if (fusion) {
      const set = ctx.provider.get("detections", t.id);
      if (set) {
        const inWindow = set.items.filter((d) => d.createdAt >= w.start);
        for (const d of inWindow) items.push({ createdAt: d.createdAt, severity: d.severity, title: d.detector ?? "Detection", detector: d.detector, sensorTypes: d.sensorTypes, techniques: d.techniques, techniqueNames: {}, tactics: [], status: d.status, users: [], hosts: [], ips: [], tenantId: t.id });
        total += set.sampled && set.coveredFrom && set.coveredFrom > w.start && w.hours === set.windowHours ? set.total : inWindow.length;
        if (set.sampled && set.coveredFrom && set.coveredFrom > w.start) sampled = true;
      }
    }
    let alertSet = ctx.provider.get("alerts", t.id);
    if (w.hours > (alertSet?.sinceHours ?? 168) && !ctx.scope.all) {
      ctx.progress("Reading product alerts for the window");
      try {
        alertSet = await ctx.source.alerts(t.id, w.hours);
      } catch {
        notes.push("Sophos did not answer the alerts read for the window, so the alerts are the toolkit's cached 7 days. Run the report again to retry.");
      }
    }
    for (const a of alertSet?.items ?? []) if (Date.parse(a.raisedAt) >= w.start) alerts.push({ ...a, tenantId: t.id });
  }
  if (sampled) {
    const oldest = items.length ? Math.min(...items.map((d) => d.createdAt)) : null;
    notes.push(`Sophos holds ${formatNumber(Math.max(total, items.length))} detections in the window; the toolkit reads the newest 3,000 per tenant${oldest ? `, which reach back to ${formatDateTime(oldest, ctx.tz)}` : ""}. Totals are Sophos's own; the charts and lists cover only the detections read, so days before that show none.`);
  }
  return { items, total: Math.max(total, items.length), sampled, fresh, alerts, fusionTenants, notes };
}

export async function buildDetections(ctx: BuildContext): Promise<BuiltReport> {
  const tz = ctx.tz;
  const w = ctx.window!;
  const f = await signalFacts(ctx, { detail: true });
  const b = buckets(w, tz);
  const sevSeries = SEVERITIES.map((s) => ({ key: s, label: SEV_LABEL[s], tone: sevTone(s) }));
  const perBucket = b.labels.map((label) => ({ label, values: SEVERITIES.map(() => 0) }));
  for (const d of f.items) {
    const i = b.index(d.createdAt);
    if (i >= 0) perBucket[i]!.values[SEVERITIES.indexOf(d.severity)]!++;
  }
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, f.items.filter((d) => d.severity === s).length])) as Record<Severity, number>;
  // Past the read cap the split covers only the detections read, so each severity figure says so.
  const inRead = f.sampled ? `in the newest ${formatNumber(f.items.length)} read` : undefined;
  const db: Block[] = [];
  if (!f.fusionTenants) {
    db.push({ kind: "note", tone: "gap", text: ctx.scope.all ? "None of these tenants is on Sophos Fusion yet, so none has detections. Their signals are product alerts, listed below." : "This tenant is still on the Classic APIs, so it has no Fusion detections. Its signals are product alerts, listed below." });
  } else {
    db.push({
      kind: "kpis",
      items: [
        kpi("Detections", formatNumber(f.total)),
        kpi("Critical", formatNumber(bySev.critical), inRead, bySev.critical ? "critical" : undefined),
        kpi("High", formatNumber(bySev.high), inRead, bySev.high ? "high" : undefined),
        kpi("Medium, low or info", formatNumber(bySev.medium + bySev.low + bySev.info), inRead),
      ],
    });
    db.push({ kind: "series", title: b.hourly ? "Detections per hour by severity" : "Detections per day by severity", unit: "detections", series: sevSeries, buckets: perBucket, empty: "No detections in the window." });
    for (const n of f.notes) db.push({ kind: "note", tone: "warn", text: n });
    db.push({ kind: "bars", title: f.fresh ? "Most frequent detections" : "Most frequent detectors", unit: "detections", rows: top(f.items, (d) => [d.title]).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No detections in the window." });
    db.push({ kind: "bars", title: "By data source", unit: "detections", rows: top(f.items, (d) => d.sensorTypes.map(sensorLabel)).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No data source named." });
    const names: Record<string, string> = {};
    for (const d of f.items) Object.assign(names, d.techniqueNames);
    db.push({ kind: "bars", title: "MITRE ATT&CK techniques", unit: "detections", rows: top(f.items, (d) => d.techniques).map(([id, value]) => ({ label: names[id] ? `${id} ${names[id]}` : id, value, tone: "mdr" as Tone })), empty: "No technique named." });
    if (f.items.some((d) => d.tactics.length)) db.push({ kind: "bars", title: "MITRE ATT&CK tactics", unit: "detections", rows: top(f.items, (d) => d.tactics).map(([label, value]) => ({ label, value, tone: "mdr" as Tone })) });
    if (f.fresh) {
      db.push({ kind: "bars", title: "Users named most", unit: "detections", rows: top(f.items, (d) => d.users).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No user named." });
      db.push({ kind: "bars", title: "Devices named most", unit: "detections", rows: top(f.items, (d) => d.hosts).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No device named." });
      db.push({ kind: "bars", title: "Addresses named most", unit: "detections", rows: top(f.items, (d) => d.ips).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No address named." });
      db.push(table("detections", "Detections, newest first", [
        { key: "at", label: "Time", format: "datetime", width: 1.6 },
        { key: "severity", label: "Severity", width: 0.9 },
        { key: "title", label: "Detection", width: 3 },
        { key: "users", label: "Users", format: "mono", width: 1.8 },
        { key: "hosts", label: "Devices", format: "mono", width: 1.5 },
        { key: "ips", label: "Addresses", format: "mono", width: 1.5 },
        { key: "techniques", label: "Techniques", format: "mono", width: 1.2, pdf: false },
      ], [...f.items].sort((a, b2) => b2.createdAt - a.createdAt).map((d) => ({ at: d.createdAt, severity: SEV_LABEL[d.severity], title: d.title, users: list(d.users, 2), hosts: list(d.hosts, 2), ips: list(d.ips, 2), techniques: list(d.techniques, 2) })), { pdfRows: 50, total: f.total > f.items.length ? f.total : undefined }));
    } else {
      const perTenant = ctx.scope.tenants.map((t) => {
        const mine = f.items.filter((d) => d.tenantId === t.id);
        return { tenant: t.name, detections: mine.length, critical: mine.filter((d) => d.severity === "critical").length, high: mine.filter((d) => d.severity === "high").length, top: top(mine, (d) => [d.title], 1)[0]?.[0] ?? "-" };
      }).filter((r) => r.detections > 0).sort((a, b2) => b2.critical - a.critical || b2.high - a.high || b2.detections - a.detections);
      db.push(table("detections-by-tenant", "Detections by tenant", [
        { key: "tenant", label: "Tenant", width: 2.6 },
        { key: "detections", label: "Detections", format: "number", width: 1 },
        { key: "critical", label: "Critical", format: "number", width: 0.9 },
        { key: "high", label: "High", format: "number", width: 0.9 },
        { key: "top", label: "Most frequent", width: 2.6 },
      ], perTenant, { empty: "No detections in the window." }));
      db.push({ kind: "note", tone: "info", text: "With all tenants selected the report reads the toolkit's cache, which keeps detector names but not the users, devices and addresses each detection names. Pick one tenant to read them." });
    }
    db.push({ kind: "note", tone: "info", text: "Fusion rates detections 0 to 1. The report bands them as the Fusion console does: critical from 0.8, high from 0.6, medium from 0.4, low from 0.2." });
  }

  const ab: Block[] = [];
  const alertSev = (a: AlertRecord): Severity => ALERT_SEV[a.severity] ?? "info";
  ab.push({ kind: "kpis", items: [kpi("Alerts", formatNumber(f.alerts.length)), kpi("High", formatNumber(f.alerts.filter((a) => a.severity === "high").length), undefined, f.alerts.some((a) => a.severity === "high") ? "high" : undefined), kpi("Medium", formatNumber(f.alerts.filter((a) => a.severity === "medium").length)), kpi("Low", formatNumber(f.alerts.filter((a) => a.severity === "low").length))] });
  ab.push({ kind: "bars", title: "Alerts by category", unit: "alerts", rows: top(f.alerts, (a) => [categoryLabel(a.category)]).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No alerts in the window." });
  ab.push({ kind: "bars", title: "Alerts by product", unit: "alerts", rows: top(f.alerts, (a) => [productLabel(a.product)]).map(([label, value]) => ({ label, value, tone: "accent" as Tone })), empty: "No alerts in the window." });
  ab.push(table("alerts", "Alerts, newest first", [
    { key: "at", label: "Raised", format: "datetime", width: 1.6 },
    { key: "severity", label: "Severity", width: 0.9 },
    ...(ctx.scope.all ? [{ key: "tenant", label: "Tenant", width: 1.8 }] : []),
    { key: "category", label: "Category", width: 1.3 },
    { key: "product", label: "Product", width: 1.1 },
    { key: "description", label: "Description", width: 4 },
  ], [...f.alerts].sort((a, b2) => Date.parse(b2.raisedAt) - Date.parse(a.raisedAt)).map((a) => ({ at: Date.parse(a.raisedAt), severity: SEV_LABEL[alertSev(a)], ...(ctx.scope.all ? { tenant: tenantName(ctx.provider, a.tenantId) } : {}), category: categoryLabel(a.category), product: productLabel(a.product), description: a.description || a.type })), { empty: "No alerts in the window.", pdfRows: 40 }));
  ab.push({ kind: "note", tone: "info", text: "Product alerts come from the Common API: product events such as malware cleaned, policy and update problems, and integration alerts. The toolkit reads up to 1,000 per tenant a refresh." });

  const asOf = cachedAsOf(ctx.provider, "alerts", ctx.scope.tenants);
  return {
    subject: ctx.scope.all ? `All tenants (${ctx.scope.tenants.length})` : ctx.scope.tenants[0]?.name ?? "",
    summary: [
      kpi("Detections", f.fusionTenants ? formatNumber(f.total) : "-", f.fusionTenants ? undefined : "No Fusion tenant"),
      kpi("Critical", f.fusionTenants ? formatNumber(bySev.critical) : "-", inRead, bySev.critical ? "critical" : undefined),
      kpi("High", f.fusionTenants ? formatNumber(bySev.high) : "-", inRead, bySev.high ? "high" : undefined),
      kpi("Alerts", formatNumber(f.alerts.length)),
      kpi("Techniques", f.fusionTenants ? formatNumber(new Set(f.items.flatMap((d) => d.techniques)).size) : "-"),
      kpi("Sources", f.fusionTenants ? formatNumber(new Set(f.items.flatMap((d) => d.sensorTypes)).size) : "-"),
    ],
    sections: [section("detections", "Detections", db), section("alerts", "Product alerts", ab)],
    gaps: [],
    provenance: [
      { label: "Detections", detail: f.fresh ? "Detections v2, read for this report" : !f.fusionTenants ? "Detections v2: no tenant here is on Sophos Fusion" : `Detections v2, cached ${asOfText(cachedAsOf(ctx.provider, "detections", ctx.scope.tenants), tz)}`, asOf: f.fresh ? ctx.now : cachedAsOf(ctx.provider, "detections", ctx.scope.tenants) },
      { label: "Alerts", detail: `Common API alerts, ${w.hours > 168 && !ctx.scope.all ? "read for this report" : asOfText(asOf, tz)}`, asOf: w.hours > 168 && !ctx.scope.all ? ctx.now : asOf },
    ],
  };
}

