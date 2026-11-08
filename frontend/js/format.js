// Number, time and duration formatting. Times are in the viewer's own time zone (the
// browser's). Dates print as "9 Nov 2026", the reports' form, so nobody reads 03/11 as
// 11 March or the other way round; the clock is 24-hour.

const nf = new Intl.NumberFormat("en-US");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function num(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return "-";
  return nf.format(Math.round(n));
}

export function compact(n) {
  if (n === null || n === undefined) return "-";
  if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M`;
  if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(n >= 1e5 ? 0 : 1)}K`;
  return nf.format(Math.round(n));
}

/** "3 d 7 h", "1 h 50 m", "47 m", "12 s". */
export function duration(ms, parts = 2) {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "-";
  let s = Math.max(0, Math.round(ms / 1000));
  const units = [
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
    ["s", 1],
  ];
  // Start at the largest unit that fits, then take the next ones in order (so "11 d 0 h", never "11 d 48 s").
  const first = units.findIndex(([, size]) => s >= size);
  if (first === -1) return "0 s";
  const out = [];
  for (const [u, size] of units.slice(first, first + parts)) {
    const v = Math.floor(s / size);
    s -= v * size;
    out.push(`${v} ${u}`);
  }
  while (out.length > 1 && out[out.length - 1].startsWith("0 ")) out.pop();
  return out.join(" ");
}

export function hours(h) {
  if (h % 24 === 0 && h >= 24) return `${h / 24} d`;
  return `${h} h`;
}

export function ago(ts, now = Date.now()) {
  if (!ts) return "never";
  const ms = now - ts;
  if (ms < 45_000) return "just now";
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)} min ago`;
  if (ms < 86_400_000) return `${Math.round(ms / 3_600_000)} h ago`;
  return `${Math.round(ms / 86_400_000)} d ago`;
}

export function clock(ts = Date.now(), seconds = false) {
  return new Date(ts).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: seconds ? "2-digit" : undefined, hourCycle: "h23" });
}

/**
 * "9 Nov 2026" in the viewer's zone, from a timestamp or an ISO string. A calendar day
 * ("2026-10-05") prints as that day everywhere: read as UTC midnight it would show the
 * day before west of UTC.
 */
export function date(ts) {
  if (!ts) return "-";
  const day = typeof ts === "string" ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(ts) : null;
  if (day) return `${Number(day[3])} ${MONTHS[Number(day[2]) - 1] ?? "?"} ${day[1]}`;
  const d = new Date(typeof ts === "string" ? Date.parse(ts) : ts);
  if (Number.isNaN(d.getTime())) return "-";
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

export function dateTime(ts) {
  if (!ts) return "-";
  return `${date(ts)} ${clock(ts)}`;
}

export function weekday(ts = Date.now()) {
  return new Date(ts).toLocaleDateString("en-US", { weekday: "short" });
}

export function greeting(ts = Date.now()) {
  const hr = new Date(ts).getHours();
  return hr < 12 ? "Good morning" : hr < 18 ? "Good afternoon" : "Good evening";
}

export function plural(n, word, many = `${word}s`) {
  return `${num(n)} ${n === 1 ? word : many}`;
}

export const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", unset: "Not set" };
