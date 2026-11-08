/**
 * The report document: what a report run produces, before any rendering.
 * The in-app preview, the PDF and the CSV files are all drawn from this one
 * JSON model, so a scheduled run (phase 2) needs no browser to produce them.
 */

export type ReportId = "user" | "logsearch" | "executive" | "cases" | "detections" | "endpoints" | "signins" | "sources";

/** What a figure or a bar means. Renderers map tones to colors; text never depends on color alone. */
export type Tone = "bad" | "warn" | "good" | "neutral" | "accent" | "critical" | "high" | "medium" | "low" | "info" | "mdr" | "self";

export interface Kpi {
  label: string;
  value: string;
  note?: string;
  tone?: Tone;
}

export type ColumnFormat = "text" | "number" | "datetime" | "date" | "duration" | "percent" | "mono";

export interface Column {
  key: string;
  label: string;
  format?: ColumnFormat;
  /** Relative width in the PDF. */
  width?: number;
  /** False keeps a column out of the PDF (it stays in the preview and the CSV). */
  pdf?: boolean;
  /** False makes a column PDF-only: a compact form of columns the CSV and preview carry separately. */
  csv?: boolean;
}

export type Cell = string | number | boolean | null;

export interface TableBlock {
  kind: "table";
  /** Stable within the document: the CSV export names the table by it. */
  id: string;
  title: string;
  columns: Column[];
  rows: Array<Record<string, Cell>>;
  /** Rows the source held when more than `rows` (the CSV still carries only `rows`). */
  total?: number;
  note?: string;
  empty?: string;
  /** The PDF prints at most this many rows and says the CSV has the rest. */
  pdfRows?: number;
}

export interface BarsBlock {
  kind: "bars";
  title: string;
  unit: string;
  rows: Array<{ label: string; value: number; note?: string; tone?: Tone }>;
  empty?: string;
  note?: string;
}

/** Stacked columns over time (or any ordered buckets). */
export interface SeriesBlock {
  kind: "series";
  /** Values are levels on each day (a count of devices), not events: no totals. */
  levels?: boolean;
  title: string;
  unit: string;
  series: Array<{ key: string; label: string; tone: Tone }>;
  buckets: Array<{ label: string; values: number[] }>;
  note?: string;
  empty?: string;
}

export interface StackBlock {
  kind: "stack";
  title: string;
  segments: Array<{ label: string; value: number; tone: Tone }>;
  note?: string;
}

export interface KpisBlock {
  kind: "kpis";
  items: Kpi[];
}

/** A labelled fact list, such as a directory record. */
export interface FactsBlock {
  kind: "facts";
  title?: string;
  items: Array<{ label: string; value: string }>;
}

/** gap: data the API can't supply. info: how a figure was worked out. warn: a figure to read with care. */
export interface NoteBlock {
  kind: "note";
  tone: "gap" | "info" | "warn";
  text: string;
}

export interface TextBlock {
  kind: "text";
  text: string;
}

export type Block = TableBlock | BarsBlock | SeriesBlock | StackBlock | KpisBlock | FactsBlock | NoteBlock | TextBlock;

export interface ReportSection {
  id: string;
  title: string;
  lead?: string;
  blocks: Block[];
}

export interface ReportDocument {
  version: 1;
  reportId: ReportId;
  title: string;
  /** What the report is about: a user, an IP, a tenant, an estate. */
  subject: string;
  scope: { label: string; tenantId: string | null; all: boolean; tenants: number; credential: string };
  window: { start: number; end: number; label: string } | null;
  /** IANA zone every time in the document is shown in. */
  timeZone: string;
  generatedAt: number;
  demo: boolean;
  summary: Kpi[];
  sections: ReportSection[];
  /** Data the Sophos APIs could not supply for this report, named rather than faked. */
  gaps: string[];
  /** Where each part of the report came from and how old it is. */
  provenance: Array<{ label: string; detail: string; asOf: number | null }>;
  /** Sophos API calls this run made, by kind. All reads. */
  calls: { total: number; byKind: Record<string, number> };
  params: Record<string, string>;
}
