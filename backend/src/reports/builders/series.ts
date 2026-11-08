/** Time buckets in the report's zone, for the per-day and per-hour charts built from cached records. */

import type { ReportWindow } from "../context.js";
import { dayKey, dayLabel, hourLabel } from "../format.js";

export interface Buckets {
  labels: string[];
  index(ms: number): number;
  hourly: boolean;
}

/** Hourly up to 2 days, else one bucket per local day. */
export function buckets(window: ReportWindow, tz: string): Buckets {
  const hourly = window.hours <= 48;
  if (hourly) {
    const first = Math.floor(window.start / 3_600_000) * 3_600_000;
    const labels: string[] = [];
    for (let t = first; t < window.end; t += 3_600_000) labels.push(window.hours > 24 ? `${dayLabel(dayKey(t, tz))} ${hourLabel(t, tz)}` : hourLabel(t, tz));
    return { labels, hourly, index: (ms) => (ms < window.start || ms > window.end ? -1 : Math.min(labels.length - 1, Math.floor((ms - first) / 3_600_000))) };
  }
  const keys: string[] = [];
  for (let t = window.start; t <= window.end; t += 3_600_000) {
    const k = dayKey(t, tz);
    if (keys[keys.length - 1] !== k) keys.push(k);
  }
  const at = new Map(keys.map((k, i) => [k, i]));
  return { labels: keys.map(dayLabel), hourly, index: (ms) => (ms < window.start || ms > window.end ? -1 : (at.get(dayKey(ms, tz)) ?? -1)) };
}
