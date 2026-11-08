/**
 * What a report builder gets, and small helpers the builders share.
 */

import type { Provider } from "../services/provider.js";
import type { DatasetName } from "../services/engine.js";
import type { Settings } from "../store/settings.js";
import type { Scope } from "../services/views.js";
import type { EndpointRecord, Severity, TenantRecord } from "../data/types.js";
import type { ReportSource } from "./source.js";
import type { Column, Kpi, ReportDocument, ReportSection, TableBlock, Tone } from "./types.js";
import { formatDateTime } from "./format.js";

export interface ReportWindow {
  key: string;
  label: string;
  hours: number;
  start: number;
  end: number;
}

export interface BuildContext {
  source: ReportSource;
  provider: Provider;
  settings: Settings;
  scope: Scope;
  window: ReportWindow | null;
  tz: string;
  now: number;
  params: Record<string, string | string[]>;
  progress(step: string): void;
}

/** The part of a document a builder writes; the runner adds the rest. */
export type BuiltReport = Pick<ReportDocument, "subject" | "summary" | "sections" | "gaps" | "provenance"> & { params?: Record<string, string> };

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEV_LABEL: Record<Severity | "unset", string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", unset: "Not set" };

export function sevTone(s: Severity | "unset"): Tone {
  return s === "unset" ? "info" : s;
}

export function kpi(label: string, value: string, note?: string, tone?: Tone): Kpi {
  return { label, value, ...(note ? { note } : {}), ...(tone ? { tone } : {}) };
}

export function table(id: string, title: string, columns: Column[], rows: TableBlock["rows"], extra: Partial<TableBlock> = {}): TableBlock {
  return { kind: "table", id, title, columns, rows, ...extra };
}

export function section(id: string, title: string, blocks: ReportSection["blocks"], lead?: string): ReportSection {
  return { id, title, ...(lead ? { lead } : {}), blocks };
}

/** The oldest fetch time across the tenants that hold the dataset, for "as of" lines. */
export function cachedAsOf(provider: Provider, dataset: DatasetName, tenants: TenantRecord[]): number | null {
  const times = tenants.map((t) => provider.fetchedAt(dataset, t.id)).filter((x): x is number => x !== null);
  return times.length ? Math.min(...times) : null;
}

export function asOfText(at: number | null, tz: string): string {
  return at ? `as of ${formatDateTime(at, tz)}` : "not read yet";
}

/** Endpoint ID (and Fusion host_id) to hostname for one tenant. */
export function hostNames(provider: Provider, tenantIds: string[]): Map<string, EndpointRecord> {
  const out = new Map<string, EndpointRecord>();
  for (const t of tenantIds) for (const e of provider.get("endpoints", t) ?? []) out.set(e.id, e);
  return out;
}

export function tenantName(provider: Provider, id: string): string {
  return provider.tenant(id)?.name ?? id;
}

export function list(values: string[], max = 3): string {
  if (values.length <= max) return values.join(", ");
  return `${values.slice(0, max).join(", ")} +${values.length - max}`;
}
