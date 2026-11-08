/**
 * Formatting for report documents. Dates print as "6 Nov 2026 14:05": the
 * month is a word, so a reader in Sydney and one in Chicago read the same
 * date. Every time is shown in the zone the run asked for (the browser's, or
 * the computer's for a headless run), and the document says which zone that is.
 */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function validTimeZone(tz: unknown): string | null {
  if (typeof tz !== "string" || !tz.trim() || tz.length > 64) return null;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz }).format(0);
    return tz;
  } catch {
    return null;
  }
}

export function serverTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

const partsCache = new Map<string, Intl.DateTimeFormat>();

function formatter(tz: string): Intl.DateTimeFormat {
  let f = partsCache.get(tz);
  if (!f) {
    f = new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric", hourCycle: "h23" });
    partsCache.set(tz, f);
  }
  return f;
}

export interface LocalParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

export function localParts(ms: number, tz: string): LocalParts {
  const out: Record<string, number> = {};
  for (const p of formatter(tz).formatToParts(ms)) if (p.type !== "literal") out[p.type] = Number(p.value);
  return { year: out.year!, month: out.month!, day: out.day!, hour: out.hour === 24 ? 0 : out.hour!, minute: out.minute!, second: out.second! };
}

const pad = (n: number) => String(n).padStart(2, "0");

export function formatDate(ms: number | null | undefined, tz: string): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "-";
  const p = localParts(ms, tz);
  return `${p.day} ${MONTHS[p.month - 1]} ${p.year}`;
}

/**
 * A date the API sends as a calendar day ("2027-01-01", a licence end) prints
 * as that day in every zone; read as UTC midnight it would print the day
 * before west of UTC. A full timestamp is formatted in the zone.
 */
export function formatCalendarDate(value: string | null | undefined, tz: string): string {
  if (!value) return "-";
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (m) return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1] ?? "?"} ${m[1]}`;
  return formatDate(Date.parse(value), tz);
}

export function formatDateTime(ms: number | null | undefined, tz: string, seconds = false): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "-";
  const p = localParts(ms, tz);
  return `${p.day} ${MONTHS[p.month - 1]} ${p.year} ${pad(p.hour)}:${pad(p.minute)}${seconds ? `:${pad(p.second)}` : ""}`;
}

/** "UTC+11:00" for the zone at that moment. */
export function formatOffset(ms: number, tz: string): string {
  const p = localParts(ms, tz);
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  const minutes = Math.round((asUtc - Math.floor(ms / 1000) * 1000) / 60_000);
  if (minutes === 0) return "UTC";
  const sign = minutes > 0 ? "+" : "-";
  const abs = Math.abs(minutes);
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

export function zoneLabel(ms: number, tz: string): string {
  return tz === "UTC" ? "UTC" : `${tz} (${formatOffset(ms, tz)})`;
}

/** Local calendar day "2026-11-06" in the zone. */
export function dayKey(ms: number, tz: string): string {
  const p = localParts(ms, tz);
  return `${p.year}-${pad(p.month)}-${pad(p.day)}`;
}

/** "6 Nov" for a day key. */
export function dayLabel(key: string): string {
  const [, m, d] = key.split("-").map(Number);
  return `${d} ${MONTHS[(m ?? 1) - 1]}`;
}

/** "14:00", or "13:30" in a zone half an hour off UTC (India, Adelaide), where an hour bucket starts on the half hour. */
export function hourLabel(ms: number, tz: string): string {
  const p = localParts(ms, tz);
  return `${pad(p.hour)}:${pad(p.minute)}`;
}

/** "3 d 7 h", "1 h 50 m", "47 m". */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "-";
  let s = Math.max(0, Math.round(ms / 1000));
  const units: Array<[string, number]> = [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
    ["s", 1],
  ];
  const first = units.findIndex(([, size]) => s >= size);
  if (first === -1) return "0 m";
  const out: string[] = [];
  for (const [u, size] of units.slice(first, first + 2)) {
    const v = Math.floor(s / size);
    s -= v * size;
    out.push(`${v} ${u}`);
  }
  while (out.length > 1 && out[out.length - 1]!.startsWith("0 ")) out.pop();
  return out.join(" ");
}

const nf = new Intl.NumberFormat("en-US");

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return "-";
  return nf.format(Math.round(n));
}

export function formatPercent(part: number, whole: number, digits = 0): string {
  if (!whole) return "-";
  return `${((part / whole) * 100).toFixed(digits)}%`;
}

export function plural(n: number, word: string, many = `${word}s`): string {
  return `${formatNumber(n)} ${n === 1 ? word : many}`;
}

export function windowLabel(start: number, end: number, tz: string): string {
  return `${formatDateTime(start, tz)} to ${formatDateTime(end, tz)}`;
}
