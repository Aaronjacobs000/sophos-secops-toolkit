/**
 * One table of a report as CSV (RFC 4180, UTF-8 with a byte order mark so
 * Excel reads non-English names). Times are written in the report's zone,
 * named in the column header. A cell that a spreadsheet would run as a
 * formula (= + - @, tab or carriage return first) is prefixed with an
 * apostrophe: tenant data is not trusted input.
 */

import type { Cell, Column, ReportDocument, TableBlock } from "./types.js";
import { localParts } from "./format.js";

const pad = (n: number) => String(n).padStart(2, "0");

export function findTable(doc: ReportDocument, id: string): TableBlock | null {
  for (const s of doc.sections) for (const b of s.blocks) if (b.kind === "table" && b.id === id) return b;
  return null;
}

export function tableIds(doc: ReportDocument): string[] {
  return doc.sections.flatMap((s) => s.blocks.filter((b): b is TableBlock => b.kind === "table").map((b) => b.id));
}

function cellText(value: Cell, col: Column, tz: string): string {
  if (value === null || value === undefined) return "";
  if (col.format === "datetime" || col.format === "date") {
    if (typeof value !== "number") return String(value);
    const p = localParts(value, tz);
    const date = `${p.year}-${pad(p.month)}-${pad(p.day)}`;
    return col.format === "date" ? date : `${date} ${pad(p.hour)}:${pad(p.minute)}:${pad(p.second)}`;
  }
  if (col.format === "duration" && typeof value === "number") return (value / 3_600_000).toFixed(2);
  return String(value);
}

export function csvField(text: string): string {
  let t = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "");
  // A leading = + - @ could start a formula in a spreadsheet; a plain negative number can't.
  if (/^[=+\-@\t\r]/.test(t) && !/^-\d+(\.\d+)?$/.test(t)) t = `'${t}`;
  return /[",\r\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
}

function header(col: Column, tz: string): string {
  if (col.format === "datetime" || col.format === "date") return `${col.label} (${tz})`;
  if (col.format === "duration") return `${col.label} (hours)`;
  return col.label;
}

export function tableCsv(table: TableBlock, tz: string): string {
  const columns = table.columns.filter((c) => c.csv !== false);
  const lines = [columns.map((c) => csvField(header(c, tz))).join(",")];
  for (const row of table.rows) lines.push(columns.map((c) => csvField(cellText(row[c.key] ?? null, c, tz))).join(","));
  return `\uFEFF${lines.join("\r\n")}\r\n`;
}

let graphemes: Intl.Segmenter | null = null;

/**
 * A file name part: letters and digits of any script, marks on them, and . @ _ -, so nothing a file system
 * or a header treats specially. A letter that is an ASCII letter with accents comes out as it always has (the
 * accent as a hyphen); any other letter stays itself, so a subject in Chinese or Polish is kept, not dropped.
 */
function slug(s: string): string {
  const mapped = [...s.normalize("NFC")]
    .map((ch) => {
      const d = ch.normalize("NFKD");
      return /[A-Za-z0-9]/.test(d) && !/(?![\x00-\x7f])[\p{L}\p{N}]/u.test(d) ? d.replace(/\p{M}/gu, "-") : ch;
    })
    .join("")
    .replace(/[^\w.@\p{L}\p{N}\p{M}-]+/gu, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  graphemes ??= new Intl.Segmenter(undefined, { granularity: "grapheme" });
  return [...graphemes.segment(mapped)].slice(0, 48).map((g) => g.segment).join("").toLowerCase();
}

/** "secops-user-investigation-jsmith-2026-11-06-devices.csv": safe on every file system. */
export function exportName(doc: ReportDocument, ext: "pdf" | "csv", tableId?: string): string {
  const p = localParts(doc.generatedAt, doc.timeZone);
  const parts = ["secops", slug(doc.title), slug(doc.subject), `${p.year}-${pad(p.month)}-${pad(p.day)}`, tableId ? slug(tableId) : ""].filter(Boolean);
  return `${parts.join("-")}.${ext}`;
}

/**
 * The Content-Disposition header for an export. A name beyond ASCII goes in filename* as UTF-8 (RFC 6266,
 * RFC 8187), which every current browser reads, with the ASCII part of it in filename for anything older.
 */
export function contentDisposition(kind: "attachment" | "inline", name: string): string {
  if (/^[\x20-\x7e]*$/.test(name)) return `${kind}; filename="${name}"`;
  const ascii = name.replace(/[^\x20-\x7e]+/g, "").replace(/-{2,}/g, "-").replace(/^-/, "");
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `${kind}; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}
