/**
 * Log search export: every event that names a user, IP address or device
 * across the event types chosen, as a timeline, a group-by breakdown and the
 * newest events as rows. The answer to "search a user or an IP across my data
 * sources and export it" without CSV exports from several consoles.
 */

import { sensorLabel } from "../../mappers/views.js";
import { SOURCE_SCHEMAS } from "../../mappers/search.js";
import { GROUP_FIELDS, MATCH_SCHEMAS, cleanSchemas, cleanSensorTypes, cleanValue, groupSchemas, schemaLabel, ReportInputError, type LogSearchSpec, type MatchKind } from "../queries.js";
import { hostNames, kpi, list, section, table, type BuildContext, type BuiltReport } from "../context.js";
import { dayLabel, dayKey, formatDate, formatDateTime, formatNumber, hourLabel, plural } from "../format.js";
import type { Block, Tone } from "../types.js";

const KIND_LABEL: Record<MatchKind, string> = { user: "user", ip: "IP address", host: "device" };
const SERIES_TONES: Tone[] = ["accent", "mdr", "medium", "good", "high", "low"];
export const LOG_ROWS = 500;

export function logSpec(params: Record<string, string | string[]>): LogSearchSpec {
  const kind = (["user", "ip", "host"] as const).find((k) => k === params.match) ?? null;
  if (!kind) throw new ReportInputError("Choose what to search for: a user, an IP address or a device.");
  const value = cleanValue(kind, params.value);
  const schemas = cleanSchemas(kind, params.schemas);
  const sensors = cleanSensorTypes(params.sensors);
  const groupBy = typeof params.groupBy === "string" && Object.hasOwn(GROUP_FIELDS, params.groupBy) ? params.groupBy : "sensor_type";
  return { kind, value, schemas, sensors, groupBy, rows: LOG_ROWS };
}

export async function buildLogSearch(ctx: BuildContext): Promise<BuiltReport> {
  const spec = logSpec(ctx.params);
  const tenant = ctx.scope.tenants[0]!;
  const window = ctx.window!;
  const tz = ctx.tz;
  ctx.progress("Running the timeline, group-by and event searches");
  const result = await ctx.source.logSearch(tenant.id, spec, window);
  const devices = hostNames(ctx.provider, [tenant.id]);
  const deviceName = (id: string | null) => (id ? (devices.get(id)?.hostname ?? id) : "-");

  const total = result.timeline.reduce((a, t) => a + t.count, 0);
  const bySchema = new Map<string, number>();
  for (const t of result.timeline) bySchema.set(t.schema, (bySchema.get(t.schema) ?? 0) + t.count);
  const schemasHit = [...bySchema.entries()].sort((a, b) => b[1] - a[1]);
  const perBucket = new Map<number, number>();
  for (const t of result.timeline) perBucket.set(t.at, (perBucket.get(t.at) ?? 0) + t.count);
  const busiest = [...perBucket.entries()].sort((a, b) => b[1] - a[1]).map(([at, count]) => ({ at, count }))[0] ?? null;
  const lastRow = result.rows[0]?.at ?? null;

  const sections = [];
  // ------------------------------------------------------------ timeline
  const top = schemasHit.slice(0, 5).map(([s]) => s);
  const hasOther = schemasHit.length > top.length;
  const series = [...top.map((s, i) => ({ key: s, label: schemaLabel(s), tone: SERIES_TONES[i]! })), ...(hasOther ? [{ key: "other", label: "Other types", tone: "neutral" as Tone }] : [])];
  const hourly = result.bucket === "1h";
  const step = hourly ? 3_600_000 : 86_400_000;
  const startBucket = hourly ? Math.floor(window.start / step) * step : Date.parse(`${new Date(window.start).toISOString().slice(0, 10)}T00:00:00Z`);
  const buckets = new Map<number, number[]>();
  for (let t = startBucket; t < window.end; t += step) buckets.set(t, series.map(() => 0));
  for (const t of result.timeline) {
    const b = buckets.get(t.at);
    if (!b) continue;
    const i = top.indexOf(t.schema);
    b[i === -1 ? series.length - 1 : i]! += t.count;
  }
  const multiDay = window.end - window.start > 86_400_000;
  const timeline: Block = {
    kind: "series",
    title: hourly ? "Events per hour" : "Events per day (UTC days)",
    unit: "events",
    series,
    buckets: [...buckets.entries()].map(([at, values]) => ({ label: hourly ? (multiDay ? `${dayLabel(dayKey(at, tz))} ${hourLabel(at, tz)}` : hourLabel(at, tz)) : dayLabel(new Date(at).toISOString().slice(0, 10)), values })),
    empty: `No events name this ${KIND_LABEL[spec.kind]} in the window.`,
  };
  sections.push(section("timeline", "Events over time", [
    timeline,
    table("event-types", "Events by type", [
      { key: "type", label: "Event type", width: 2.4 },
      { key: "schema", label: "Schema", format: "mono", width: 1.6 },
      { key: "events", label: "Events", format: "number", width: 1 },
    ], schemasHit.map(([s, n]) => ({ type: schemaLabel(s), schema: s, events: n })), { empty: "No events." }),
  ]));

  // ------------------------------------------------------------ group by
  const field = GROUP_FIELDS[spec.groupBy]!;
  const gb: Block[] = [];
  if (result.groups) {
    const merged = new Map<string, { value: string; count: number; schemas: Set<string> }>();
    for (const r of result.groups.rows) {
      const raw = spec.groupBy === "schema" ? r.schema : r.value;
      const label = spec.groupBy === "schema" ? schemaLabel(raw) : spec.groupBy === "sensor_type" ? sensorLabel(raw || "UNKNOWN") : spec.groupBy === "host_id" ? deviceName(raw || null) : raw || "(empty)";
      const m = merged.get(label) ?? { value: label, count: 0, schemas: new Set<string>() };
      m.count += r.count;
      m.schemas.add(schemaLabel(r.schema));
      merged.set(label, m);
    }
    const rows = [...merged.values()].sort((a, b) => b.count - a.count);
    gb.push({ kind: "bars", title: `Top ${Math.min(15, rows.length)} by ${field.label.toLowerCase()}`, unit: "events", rows: rows.slice(0, 15).map((r) => ({ label: r.value, value: r.count, tone: "accent" as Tone })), empty: "No values." });
    gb.push(table("group-by", `Every ${field.label.toLowerCase()}`, [
      { key: "value", label: field.label, format: field.ip || spec.groupBy === "host_id" ? "mono" : "text", width: 3 },
      { key: "events", label: "Events", format: "number", width: 1 },
      ...(spec.groupBy === "schema" ? [] : [{ key: "types", label: "Event types", width: 2.6 }]),
    ], rows.map((r) => ({ value: r.value, events: r.count, types: [...r.schemas].join(", ") })), { pdfRows: 40 }));
    const skipped = spec.schemas.filter((s) => !result.groups!.schemas.includes(s));
    if (skipped.length) gb.push({ kind: "note", tone: "info", text: `${field.label} exists only on some event types, so the group-by covers ${result.groups.schemas.map(schemaLabel).join(", ")}. Not included: ${skipped.map(schemaLabel).join(", ")}.` });
  } else {
    gb.push({ kind: "note", tone: "gap", text: `None of the chosen event types has a ${field.label.toLowerCase()} field (${groupSchemas(spec).length} of ${spec.schemas.length}). Choose another field to group by.` });
  }
  sections.push(section("group-by", `By ${field.label.toLowerCase()}`, gb));

  // ------------------------------------------------------------ events
  sections.push(section("events", "Events", [
    table("events", `Newest ${formatNumber(result.rows.length)} events`, [
      { key: "at", label: "Time", format: "datetime", width: 1.6 },
      { key: "type", label: "Event type", width: 1.4 },
      { key: "source", label: "Source", width: 1.5, pdf: false },
      { key: "device", label: "Device", format: "mono", width: 1.4 },
      // Searching by user, every row names that user: the PDF leaves the column out.
      { key: "user", label: "User", format: "mono", width: 1.7, ...(spec.kind === "user" ? { pdf: false } : {}) },
      { key: "from", label: "Source IP", format: "mono", width: 1.3 },
      { key: "to", label: "Destination", format: "mono", width: 1.7 },
      { key: "action", label: "Action", width: 0.9, pdf: false },
      { key: "detail", label: "Detail", width: 2.6, pdf: false },
      { key: "what", label: "Action and detail", width: 3, csv: false },
    ], result.rows.map((r) => {
      const action = r.action ? r.action.toLowerCase().replace(/_/g, " ") : "";
      return { at: r.at, type: schemaLabel(r.schema), source: sensorLabel(r.sensorType), device: deviceName(r.hostId), user: r.user || "-", from: r.source || "-", to: r.destination || "-", action: action || "-", detail: r.detail || "-", what: [action, r.detail].filter(Boolean).join(": ") || "-" };
    }), { empty: "No events.", pdfRows: 80 }),
    ...(result.rowsTruncated ? [{ kind: "note", tone: "info", text: `The ${formatNumber(LOG_ROWS)} newest events are listed and exported; the timeline and the group-by count all ${formatNumber(total)}. Narrow the window to export the rest.` } as Block] : []),
  ]));

  const notSearched = SOURCE_SCHEMAS.filter((s) => !MATCH_SCHEMAS[spec.kind].includes(s));
  const gaps = [
    `Searched ${plural(spec.schemas.length, "event type")}: ${spec.schemas.map(schemaLabel).join(", ")}. ${notSearched.length ? `${notSearched.map(schemaLabel).join(", ")} carry no ${KIND_LABEL[spec.kind]} field, so Sophos can't search them by one.` : ""}`.trim(),
  ];
  if (result.search.outcome === "PARTIAL") gaps.push(`Sophos returned part of the answer: ${result.search.failedSchemas.join(", ")} failed, so their events are missing.`);
  return {
    subject: `${KIND_LABEL[spec.kind][0]!.toUpperCase()}${KIND_LABEL[spec.kind].slice(1)} ${spec.value}`,
    summary: [
      kpi("Events", formatNumber(total)),
      kpi("Event types", formatNumber(schemasHit.length), `of ${formatNumber(spec.schemas.length)} searched`),
      kpi("Sources", formatNumber(new Set(result.rows.map((r) => r.sensorType)).size), "in the newest events"),
      kpi("Devices", formatNumber(new Set(result.rows.map((r) => r.hostId).filter(Boolean)).size), "in the newest events"),
      kpi(hourly ? "Busiest hour" : "Busiest day", busiest ? formatNumber(busiest.count) : "-", busiest ? (hourly ? formatDateTime(busiest.at, tz) : `${formatDate(busiest.at, "UTC")} (UTC day)`) : undefined),
      kpi("Newest event", lastRow ? formatDateTime(lastRow, tz).split(" ").slice(-1)[0]! : "-", lastRow ? formatDate(lastRow, tz) : undefined),
    ],
    sections,
    gaps,
    provenance: [{ label: "Events", detail: `Search GraphQL, ${plural(result.search.calls, "call")}${spec.sensors.length ? `, sources ${list(spec.sensors.map(sensorLabel), 4)}` : ""}`, asOf: result.search.ranAt }],
    params: { match: spec.kind, value: spec.value, schemas: spec.schemas.join(","), groupBy: spec.groupBy, ...(spec.sensors.length ? { sensors: spec.sensors.join(",") } : {}) },
  };
}
