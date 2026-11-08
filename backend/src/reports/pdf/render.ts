/**
 * Lays a report document out as a print-ready PDF: a cover with the tenant,
 * the time range and a contents list, then the sections with a running header
 * and "Page N of M" footer. Headings stay with what follows them, charts and
 * table rows never split across pages, and a table that runs on repeats its
 * header. Long tables print their first rows and point to the CSV.
 */

import type { BarsBlock, Block, Cell, Column, FactsBlock, Kpi, KpisBlock, NoteBlock, ReportDocument, SeriesBlock, StackBlock, TableBlock, Tone } from "../types.js";
import { formatDate, formatDateTime, formatDuration, formatNumber, zoneLabel } from "../format.js";
import { fit, measure, wrap, type FontFace } from "./fonts.js";
import { PdfPage, writePdf, type Rgb } from "./writer.js";

export type Paper = "a4" | "letter";

const PAPER: Record<Paper, [number, number]> = { a4: [595.28, 841.89], letter: [612, 792] };

const C = {
  ink0: [11, 13, 18],
  ink1: [29, 33, 43],
  ink2: [82, 87, 106],
  ink3: [107, 113, 130],
  line: [214, 217, 225],
  rule: [228, 230, 235],
  zebra: [246, 247, 249],
  panel: [240, 242, 246],
  track: [236, 238, 242],
  accent: [42, 111, 208],
  band: [11, 16, 32],
  bandInk: [223, 228, 239],
  bandDim: [163, 172, 192],
  bandAccent: [122, 184, 255],
  white: [255, 255, 255],
} as const satisfies Record<string, Rgb>;

const TONE: Record<Tone, Rgb> = {
  bad: [208, 59, 59],
  warn: [214, 150, 10],
  good: [12, 143, 74],
  neutral: [160, 164, 176],
  accent: [42, 111, 208],
  critical: [208, 59, 59],
  high: [226, 112, 60],
  medium: [222, 160, 20],
  low: [42, 120, 214],
  info: [150, 148, 140],
  mdr: [194, 48, 106],
  self: [42, 120, 214],
};

const MARGIN_X = 46;
const TOP = 58;
const BOTTOM = 52;
const GAP = 14;
const BODY = 8.6;
const LEAD = 1.32;
/** Widest a paragraph runs at a type size: about 75 characters of Helvetica, so lines stay readable. */
const measureAt = (size: number): number => Math.round(34 * size);

interface SectionStart {
  title: string;
  page: number;
}

class Layout {
  readonly pages: PdfPage[] = [];
  page!: PdfPage;
  y = TOP;
  readonly w: number;
  readonly contents: SectionStart[] = [];

  constructor(
    readonly doc: ReportDocument,
    readonly size: [number, number],
  ) {
    this.w = size[0] - MARGIN_X * 2;
  }

  get bottom(): number {
    return this.size[1] - BOTTOM;
  }

  newPage(): void {
    this.page = new PdfPage(this.size[0], this.size[1]);
    this.pages.push(this.page);
    this.y = TOP;
  }

  room(): number {
    return this.bottom - this.y;
  }

  /** Starts a new page unless `h` fits; a block taller than a page starts at the top. */
  ensure(h: number): void {
    if (this.y > TOP && h > this.room()) this.newPage();
  }

  text(x: number, baseline: number, s: string, size: number, color: Rgb, face: FontFace = "regular", align: "left" | "right" | "center" = "left", tracking = 0): number {
    return this.page.text(x, baseline, s, { size, color, face, align, tracking });
  }

  /** Wrapped paragraph from the cursor; returns its height. */
  para(s: string, size: number, color: Rgb, width = Math.min(this.w, measureAt(size)), x = MARGIN_X, face: FontFace = "regular", maxLines = Infinity): number {
    const lines = prose(s, face, size, width, maxLines);
    const lh = size * LEAD;
    lines.forEach((l, i) => this.text(x, this.y + size + i * lh, l, size, color, face));
    return lines.length * lh;
  }
}

/** Wraps a paragraph so its last line is never one word on its own (narrowing the measure a little if it must). */
export function prose(text: string, face: FontFace, size: number, width: number, maxLines = Infinity): string[] {
  let lines = wrap(text, face, size, width, maxLines);
  for (let w = width - 8, tries = 0; tries < 8 && lines.length > 1 && !lines[lines.length - 1]!.includes(" ") && w > width * 0.7; w -= 8, tries++) {
    const next = wrap(text, face, size, w, maxLines);
    if (next.length > lines.length) break;
    lines = next;
  }
  return lines;
}

// ---------------------------------------------------------------- cell formatting

export function cellText(value: Cell, col: Column, tz: string): string {
  return keepUnits(rawCellText(value, col, tz));
}

/** Keeps a number with its time unit ("19 m") on one line when a cell wraps. */
function keepUnits(text: string): string {
  return text.replace(/(\d) ([dhms])\b/g, "$1\u00a0$2");
}

function rawCellText(value: Cell, col: Column, tz: string): string {
  if (value === null || value === undefined || value === "") return "-";
  switch (col.format) {
    case "number":
      return typeof value === "number" ? formatNumber(value) : String(value);
    case "datetime":
      return typeof value === "number" ? formatDateTime(value, tz) : String(value);
    case "date":
      return typeof value === "number" ? formatDate(value, tz) : String(value);
    case "duration":
      return typeof value === "number" ? formatDuration(value) : String(value);
    default:
      return String(value);
  }
}

const numeric = (c: Column) => c.format === "number" || c.format === "duration" || c.format === "percent";

// ---------------------------------------------------------------- blocks

function kpiTiles(L: Layout, items: Kpi[], perRow = 4): void {
  const gap = 8;
  for (let i = 0; i < items.length; i += perRow) {
    const row = items.slice(i, i + perRow);
    const cols = Math.min(perRow, Math.max(row.length, Math.min(perRow, items.length)));
    const tw = (L.w - gap * (cols - 1)) / cols;
    const inner = tw - 18;
    const labelLines = row.map((k) => wrap(k.label.toUpperCase(), "bold", 6.6, inner, 2).length);
    const noteLines = row.map((k) => (k.note ? wrap(k.note, "regular", 7.2, inner, 2).length : 0));
    const valueSize = row.some((k) => measure(k.value, "bold", 17) > inner) ? 12.5 : 17;
    const h = 10 + Math.max(...labelLines) * 8.4 + 4 + valueSize + 4 + Math.max(...noteLines) * 9 + 9;
    L.ensure(h);
    row.forEach((k, j) => {
      const x = MARGIN_X + j * (tw + gap);
      L.page.roundRect(x, L.y, tw, h, 5, null, C.line, 0.7);
      if (k.tone) L.page.rect(x + 0.35, L.y + 6, 2.6, h - 12, TONE[k.tone]);
      const lx = x + 10;
      let yy = L.y + 10;
      for (const line of wrap(k.label.toUpperCase(), "bold", 6.6, inner, 2)) {
        L.text(lx, yy + 6.6, line, 6.6, C.ink2, "bold", "left", 0.35);
        yy += 8.4;
      }
      yy += 4;
      L.text(lx, yy + valueSize * 0.85, fit(k.value, "bold", valueSize, inner), valueSize, C.ink0, "bold");
      yy += valueSize + 4;
      if (k.note) for (const line of wrap(k.note, "regular", 7.2, inner, 2)) {
        L.text(lx, yy + 7.2, line, 7.2, C.ink2);
        yy += 9;
      }
    });
    L.y += h + (i + perRow < items.length ? gap : 0);
  }
}

function blockTitle(L: Layout, title: string, right?: string): number {
  const h = 15;
  L.text(MARGIN_X, L.y + 9.5, fit(title, "bold", 9.5, L.w - (right ? measure(right, "regular", 7.6) + 12 : 0)), 9.5, C.ink0, "bold");
  if (right) L.text(MARGIN_X + L.w, L.y + 9.5, right, 7.6, C.ink3, "regular", "right");
  L.y += h;
  return h;
}

function emptyLine(L: Layout, text: string): void {
  L.text(MARGIN_X, L.y + 8.4, text, 8.2, C.ink3);
  L.y += 13;
}

function bars(L: Layout, b: BarsBlock): void {
  const rows = b.rows;
  const rowH = 13.5;
  const noteH = b.note ? prose(b.note, "regular", 7.6, Math.min(L.w, measureAt(7.6))).length * 10 + 4 : 0;
  L.ensure(15 + Math.max(1, rows.length) * rowH + noteH + 4);
  blockTitle(L, b.title);
  if (!rows.length || rows.every((r) => r.value === 0)) {
    emptyLine(L, b.empty ?? "Nothing to show.");
    return;
  }
  const labelW = Math.min(L.w * 0.38, 210);
  const valueW = 46;
  const trackX = MARGIN_X + labelW + 8;
  const trackW = L.w - labelW - 8 - valueW - 6;
  const max = Math.max(1, ...rows.map((r) => r.value));
  for (const r of rows) {
    const base = L.y + 9.2;
    const note = r.note ? ` ${r.note}` : "";
    const label = fit(r.label, "regular", 8, labelW - (note ? Math.min(measure(note, "regular", 7.2), labelW * 0.45) : 0));
    const lw = L.text(MARGIN_X, base, label, 8, C.ink1);
    if (note) L.text(MARGIN_X + lw, base, fit(note, "regular", 7.2, labelW - lw), 7.2, C.ink3);
    L.page.rect(trackX, L.y + 3, trackW, 8, C.track);
    const bw = r.value > 0 ? Math.max(1.5, (r.value / max) * trackW) : 0;
    L.page.rect(trackX, L.y + 3, bw, 8, TONE[r.tone ?? "accent"]);
    L.text(MARGIN_X + L.w, base, formatNumber(r.value), 8, C.ink0, "bold", "right");
    L.y += rowH;
  }
  if (b.note) {
    L.y += 2;
    L.y += L.para(b.note, 7.6, C.ink2);
  }
}

function legend(L: Layout, items: Array<{ label: string; tone: Tone; value?: string }>): void {
  let x = MARGIN_X;
  const base = L.y + 8;
  for (const it of items) {
    const text = it.value ? `${it.label} ${it.value}` : it.label;
    const w = 9 + measure(text, "regular", 7.6) + 14;
    if (x + w > MARGIN_X + L.w) break;
    L.page.rect(x, base - 6, 6, 6, TONE[it.tone]);
    L.text(x + 9, base, text, 7.6, C.ink2);
    x += w;
  }
  L.y += 13;
}

function series(L: Layout, s: SeriesBlock): void {
  const totals = s.series.map((_, i) => s.buckets.reduce((a, b) => a + (b.values[i] ?? 0), 0));
  const all = totals.reduce((a, b) => a + b, 0);
  const chartH = 112;
  const noteH = s.note ? prose(s.note, "regular", 7.6, Math.min(L.w, measureAt(7.6))).length * 10 + 4 : 0;
  L.ensure(15 + (all ? 13 + chartH + 16 : 13) + noteH);
  blockTitle(L, s.title, all && !s.levels ? `${formatNumber(all)} ${s.unit}` : undefined);
  if (!all || !s.buckets.length) {
    emptyLine(L, s.empty ?? "Nothing to show.");
    return;
  }
  const latest = s.buckets[s.buckets.length - 1]!.values;
  if (s.series.length > 1) legend(L, s.series.map((x, i) => ({ label: x.label, tone: x.tone, value: s.levels ? `${formatNumber(latest[i] ?? 0)} now` : formatNumber(totals[i]!) })));
  const axisW = 30;
  const plotX = MARGIN_X;
  const plotW = L.w - axisW;
  const top = L.y + 4;
  const bottom = top + chartH - 18;
  const maxStack = Math.max(1, ...s.buckets.map((b) => b.values.reduce((a, v) => a + v, 0)));
  const nice = (v: number) => {
    if (v <= 4) return 4;
    const p = 10 ** Math.floor(Math.log10(v));
    const m = v / p;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 4 ? 4 : m <= 5 ? 5 : 10) * p;
  };
  const max = nice(maxStack);
  for (const f of [0, 0.5, 1]) {
    const y = bottom - (bottom - top) * f;
    L.page.line(plotX, y, plotX + plotW, y, f === 0 ? C.line : C.rule, f === 0 ? 0.7 : 0.5);
    L.text(plotX + plotW + 4, y + 2.6, formatNumber(max * f), 7, C.ink3);
  }
  const n = s.buckets.length;
  const colW = plotW / n;
  const barW = Math.max(0.8, Math.min(colW * 0.72, 26));
  s.buckets.forEach((b, i) => {
    let y = bottom;
    const x = plotX + i * colW + (colW - barW) / 2;
    b.values.forEach((v, j) => {
      if (v <= 0) return;
      const h = Math.max(0.6, ((bottom - top) * v) / max);
      L.page.rect(x, y - h, barW, h, TONE[s.series[j]?.tone ?? "accent"]);
      y -= h;
    });
  });
  // X labels: as many as fit without touching, always the first and the last.
  const labelW = Math.max(...s.buckets.map((b) => measure(b.label, "regular", 6.8))) + 8;
  const every = Math.max(1, Math.ceil(labelW / colW));
  s.buckets.forEach((b, i) => {
    if (i % every !== 0 && i !== n - 1) return;
    if (i === n - 1 && i % every !== 0 && (n - 1) % every < every * 0.6 && n > every) return;
    const cx = plotX + i * colW + colW / 2;
    const w = measure(b.label, "regular", 6.8);
    const x = Math.min(Math.max(cx - w / 2, plotX), plotX + plotW - w);
    L.text(x, bottom + 10, b.label, 6.8, C.ink3);
  });
  L.y = bottom + 16;
  if (s.note) {
    L.y += 2;
    L.y += L.para(s.note, 7.6, C.ink2);
  }
}

function stack(L: Layout, s: StackBlock): void {
  const total = s.segments.reduce((a, x) => a + x.value, 0);
  L.ensure(15 + 14 + 13 + (s.note ? 12 : 0));
  blockTitle(L, s.title);
  if (!total) {
    emptyLine(L, "None in the window.");
    return;
  }
  const y = L.y + 1;
  if (total) {
    let x = MARGIN_X;
    const visible = s.segments.filter((x2) => x2.value > 0);
    const gaps = Math.max(0, visible.length - 1) * 1.5;
    visible.forEach((seg) => {
      const w = Math.max(1.5, ((L.w - gaps) * seg.value) / total);
      L.page.rect(x, y, w, 10, TONE[seg.tone]);
      x += w + 1.5;
    });
  } else L.page.rect(MARGIN_X, y, L.w, 10, C.track);
  L.y += 16;
  legend(L, s.segments.map((x) => ({ label: x.label, tone: x.tone, value: total ? `${formatNumber(x.value)} (${Math.round((x.value / total) * 100)}%)` : "0" })));
  if (s.note) L.y += L.para(s.note, 7.6, C.ink2);
}

function facts(L: Layout, f: FactsBlock): void {
  const labelW = 120;
  const rows = f.items.map((it) => ({ it, lines: wrap(it.value, "regular", 8.6, L.w - labelW - 8, 3) }));
  const h = (f.title ? 15 : 0) + rows.reduce((a, r) => a + r.lines.length * 11.4 + 6, 0);
  L.ensure(h);
  if (f.title) blockTitle(L, f.title);
  for (const r of rows) {
    L.text(MARGIN_X, L.y + 9, r.it.label, 8, C.ink2);
    r.lines.forEach((line, i) => L.text(MARGIN_X + labelW, L.y + 9 + i * 11.4, line, 8.6, C.ink1));
    L.y += r.lines.length * 11.4 + 6;
    L.page.line(MARGIN_X, L.y - 2.5, MARGIN_X + L.w, L.y - 2.5, C.rule, 0.5);
  }
}

function note(L: Layout, nb: NoteBlock): void {
  const lead = nb.tone === "gap" ? "Gap. " : nb.tone === "warn" ? "Caution. " : "";
  const width = Math.min(L.w - 12, measureAt(7.9));
  const lines = prose(`${lead}${nb.text}`, "regular", 7.9, width);
  const h = lines.length * 10.4 + 6;
  L.ensure(h);
  L.page.rect(MARGIN_X, L.y + 1, 2, h - 3, nb.tone === "gap" ? TONE.warn : nb.tone === "warn" ? TONE.high : C.line);
  lines.forEach((line, i) => {
    const base = L.y + 8.8 + i * 10.4;
    if (i === 0 && lead) {
      const lw = L.text(MARGIN_X + 10, base, lead.trim(), 7.9, C.ink0, "bold");
      L.text(MARGIN_X + 10 + lw + measure(" ", "regular", 7.9), base, line.slice(lead.length), 7.9, C.ink1);
    } else L.text(MARGIN_X + 10, base, line, 7.9, C.ink1);
  });
  L.y += h;
}

const rigidFormat = (c: Column) => numeric(c) || c.format === "datetime" || c.format === "date";

/**
 * Column widths that suit the content: dates, times and numbers never wrap,
 * headers never break inside a word, and text columns share what is left by
 * their weights, wrapping where they must.
 */
export function columnWidths(columns: Column[], cells: string[][], total: number, fontSize: number): number[] {
  const pad = 9; // both sides of the cell, plus a point so a word that just fits is never broken by rounding
  const head = columns.map((c) => Math.max(...c.label.toUpperCase().split(/\s+/).map((w) => measure(w, "bold", 6.4, 0.3))) + pad);
  const natural = columns.map((_, i) => Math.min(total, Math.max(head[i]!, ...cells.map((r) => measure(r[i] ?? "", "regular", fontSize) + pad))));
  const word = columns.map((_, i) => Math.max(head[i]!, ...cells.map((r) => Math.max(0, ...(r[i] ?? "").split(/[^\S\u00a0]+/).map((w) => measure(w, "regular", fontSize))) + pad)));
  const rigid = columns.map((c, i) => rigidFormat(c) || natural[i]! <= Math.max(head[i]!, 54));
  const min = columns.map((_, i) => (rigid[i] ? natural[i]! : Math.max(head[i]!, Math.min(word[i]!, total * 0.16))));
  const weights = columns.map((c) => c.width ?? 1);
  const flexWeight = columns.reduce((a, _, i) => a + (rigid[i] ? 0 : weights[i]!), 0) || 1;
  const rigidSum = min.reduce((a, m, i) => a + (rigid[i] ? m : 0), 0);
  const widths = columns.map((_, i) => (rigid[i] ? min[i]! : Math.max(min[i]!, Math.min(natural[i]!, ((total - rigidSum) * weights[i]!) / flexWeight))));
  let sum = widths.reduce((a, b) => a + b, 0);
  if (sum < total) {
    // Room left: first to text columns that would wrap, then to every text column, by weight.
    const wrapping = columns.map((_, i) => !rigid[i] && natural[i]! > widths[i]!);
    const pool = wrapping.some(Boolean) ? wrapping : columns.map((_, i) => !rigid[i]);
    const poolWeight = columns.reduce((a, _, i) => a + (pool[i] ? weights[i]! : 0), 0);
    if (poolWeight) columns.forEach((_, i) => pool[i] && (widths[i]! += ((total - sum) * weights[i]!) / poolWeight));
    else columns.forEach((_, i) => (widths[i]! += (total - sum) / columns.length));
  } else if (sum > total) {
    // Too wide: text columns give back down to their minimum, then everything shrinks alike.
    const give = columns.map((_, i) => (rigid[i] ? 0 : widths[i]! - min[i]!));
    const giveSum = give.reduce((a, b) => a + b, 0);
    const need = sum - total;
    if (giveSum > 0) columns.forEach((_, i) => (widths[i]! -= Math.min(give[i]!, (need * give[i]!) / giveSum)));
    sum = widths.reduce((a, b) => a + b, 0);
    // Still too wide: text columns go below their longest word (it breaks), never below their header word.
    if (sum > total) {
      const room = columns.map((_, i) => (rigid[i] ? 0 : Math.max(0, widths[i]! - head[i]!)));
      const roomSum = room.reduce((a, b) => a + b, 0);
      const over = sum - total;
      if (roomSum > 0) columns.forEach((_, i) => (widths[i]! -= Math.min(room[i]!, (over * room[i]!) / roomSum)));
      sum = widths.reduce((a, b) => a + b, 0);
    }
    // Only then do dates and numbers give way.
    if (sum > total) for (let i = 0; i < widths.length; i++) widths[i] = (widths[i]! * total) / sum;
  }
  return widths;
}

function tableBlock(L: Layout, t: TableBlock, tz: string, csvName: (id: string) => string): void {
  const limit = t.pdfRows ?? 300;
  const total = t.rows.length;
  if (limit === 0) {
    const text = total ? `${formatNumber(total)} rows. This table is in the CSV export only: ${csvName(t.id)}.` : (t.empty ?? "No rows.");
    L.ensure(15 + 13);
    blockTitle(L, t.title);
    emptyLine(L, text);
    return;
  }
  const rows = t.rows.slice(0, limit);
  // A column with nothing in it on the printed rows only takes room from the others.
  const blank = (v: Cell | undefined) => v === null || v === undefined || v === "" || v === "-";
  const emptyCols = rows.length ? t.columns.filter((c) => c.pdf !== false && rows.every((r) => blank(r[c.key]))) : [];
  const columns = t.columns.filter((c) => c.pdf !== false && !emptyCols.includes(c));
  const fontSize = columns.length >= 8 ? 7 : 7.6;
  const lh = fontSize * 1.24;
  const pad = 4;
  const cells = rows.map((r) => columns.map((c) => cellText(r[c.key] ?? null, c, tz)));
  const widths = columnWidths(columns, cells, L.w, fontSize);
  const headerLines = columns.map((c, i) => wrap(c.label.toUpperCase(), "bold", 6.4, widths[i]! - pad * 2, 2));
  const headerH = Math.max(...headerLines.map((l) => l.length)) * 7.8 + 8;
  const rowLines = cells.map((r) => columns.map((c, i) => wrap(r[i]!, "regular", fontSize, widths[i]! - pad * 2, rigidFormat(c) ? 1 : 3)));
  const rowH = rowLines.map((r) => Math.max(...r.map((l) => l.length)) * lh + 6);
  const countText = total > rows.length ? `${formatNumber(rows.length)} of ${formatNumber(total)} rows` : total ? `${formatNumber(total)} ${total === 1 ? "row" : "rows"}` : "";
  const drawHeader = (title: string) => {
    blockTitle(L, title, countText);
    L.page.rect(MARGIN_X, L.y, L.w, headerH, C.panel);
    let x = MARGIN_X;
    columns.forEach((c, i) => {
      headerLines[i]!.forEach((line, k) => L.text(numeric(c) ? x + widths[i]! - pad : x + pad, L.y + 9.6 + k * 7.8, line, 6.4, C.ink2, "bold", numeric(c) ? "right" : "left", 0.3));
      x += widths[i]!;
    });
    L.y += headerH;
  };
  L.ensure(15 + headerH + (rows.length ? rowH.slice(0, 3).reduce((a, b) => a + b, 0) : 16));
  drawHeader(t.title);
  if (!rows.length) {
    L.text(MARGIN_X + pad, L.y + 11, t.empty ?? "No rows.", fontSize, C.ink3);
    L.y += 17;
  }
  const after: string[] = [];
  const hidden = t.columns.filter((c) => c.pdf === false && !t.columns.some((x) => x.csv === false && x.label.toLowerCase().includes(c.label.toLowerCase()))).map((c) => c.label.toLowerCase());
  if (total > rows.length) after.push(`The PDF shows the first ${formatNumber(rows.length)} of ${formatNumber(total)} rows; the CSV export (${csvName(t.id)}) has all of them${hidden.length ? `, with the ${hidden.join(" and ")} column${hidden.length > 1 ? "s" : ""}` : ""}.`);
  else if (hidden.length) after.push(`The CSV export (${csvName(t.id)}) adds the ${hidden.join(" and ")} column${hidden.length > 1 ? "s" : ""}.`);
  if (t.total && t.total > total) after.push(`Sophos held ${formatNumber(t.total)}; the report read ${formatNumber(total)}.`);
  if (t.note) after.push(t.note);
  const afterText = after.join(" ");
  const afterH = after.length ? 4 + prose(afterText, "regular", 7.6, Math.min(L.w, measureAt(7.6))).length * 10 : 0;
  rows.forEach((_, r) => {
    // The last row keeps the note under the table with it.
    if (rowH[r]! + (r === rows.length - 1 ? afterH : 0) > L.room()) {
      L.newPage();
      drawHeader(`${t.title} (continued)`);
    }
    if (r % 2 === 1) L.page.rect(MARGIN_X, L.y, L.w, rowH[r]!, C.zebra);
    let x = MARGIN_X;
    columns.forEach((c, i) => {
      rowLines[r]![i]!.forEach((line, k) => L.text(numeric(c) ? x + widths[i]! - pad : x + pad, L.y + 3 + fontSize + k * lh, line, fontSize, C.ink1, "regular", numeric(c) ? "right" : "left"));
      x += widths[i]!;
    });
    L.y += rowH[r]!;
  });
  L.page.line(MARGIN_X, L.y, MARGIN_X + L.w, L.y, C.line, 0.6);
  if (after.length) {
    L.y += 4;
    L.ensure(afterH - 4);
    L.y += L.para(afterText, 7.6, C.ink2);
  }
}

function block(L: Layout, b: Block, tz: string, csvName: (id: string) => string): void {
  switch (b.kind) {
    case "kpis":
      kpiTiles(L, (b as KpisBlock).items);
      break;
    case "bars":
      bars(L, b);
      break;
    case "series":
      series(L, b);
      break;
    case "stack":
      stack(L, b);
      break;
    case "facts":
      facts(L, b);
      break;
    case "note":
      note(L, b);
      break;
    case "table":
      tableBlock(L, b, tz, csvName);
      break;
    case "text": {
      const lines = wrap(b.text, "regular", BODY, Math.min(L.w, measureAt(BODY)));
      L.ensure(lines.length * BODY * LEAD);
      L.y += L.para(b.text, BODY, C.ink1);
      break;
    }
  }
}

/** About how tall the start of a block is: what has to fit under a heading for the heading to stay with it. */
function startHeight(b: Block | undefined): number {
  if (!b) return 40;
  switch (b.kind) {
    case "table":
      return 15 + 26 + (b.pdfRows === 0 ? 13 : Math.max(1, Math.min(3, b.rows.length)) * 24);
    case "series":
      return b.buckets.some((x) => x.values.some((v) => v > 0)) ? 160 : 30;
    case "bars":
      return 15 + Math.max(1, Math.min(4, b.rows.length)) * 13.5;
    case "kpis":
      return 76;
    case "facts":
      return 15 + b.items.length * 17;
    case "stack":
      return 45;
    default:
      return 40;
  }
}

/** Space a section title, its lead and the start of its first block need, so a heading never ends a page. */
function headingNeed(L: Layout, title: string, lead: string | undefined, first: Block | undefined): number {
  const t = wrap(title, "bold", 14, L.w).length * 17;
  const l = lead ? prose(lead, "regular", 8.6, Math.min(L.w, measureAt(8.6))).length * 8.6 * LEAD + 4 : 0;
  return 10 + t + l + 8 + startHeight(first);
}

function sectionHeading(L: Layout, title: string, lead?: string, first?: Block): void {
  L.ensure(headingNeed(L, title, lead, first));
  if (L.y > TOP + 1) {
    L.y += 6;
    L.page.line(MARGIN_X, L.y, MARGIN_X + L.w, L.y, C.line, 0.6);
    L.y += 12;
  }
  L.contents.push({ title, page: L.pages.length });
  for (const line of wrap(title, "bold", 14, L.w)) {
    L.text(MARGIN_X, L.y + 13, line, 14, C.ink0, "bold", "left", -0.15);
    L.y += 17;
  }
  if (lead) {
    L.y += 2;
    L.y += L.para(lead, 8.6, C.ink2);
  }
  L.y += 8;
}

function aboutSection(L: Layout, doc: ReportDocument): void {
  const items = [
    { label: "Report", value: `${doc.title}: ${doc.subject}` },
    { label: "Scope", value: doc.scope.label },
    ...(doc.window ? [{ label: "Time range", value: doc.window.label }] : []),
    { label: "Times shown in", value: zoneLabel(doc.generatedAt, doc.timeZone) },
    { label: "Generated", value: formatDateTime(doc.generatedAt, doc.timeZone) },
    { label: "Credential", value: doc.demo ? "Demo mode: every tenant, person, device and figure is fictional" : doc.scope.credential },
    { label: "Sophos calls", value: doc.demo ? "None (demo)" : doc.calls.total ? `${formatNumber(doc.calls.total)} for this report, all reads: ${Object.entries(doc.calls.byKind).map(([k, v]) => `${k} ${formatNumber(v)}`).join(", ")}` : "None for this report: it read the toolkit's cache" },
  ];
  const about: FactsBlock = { kind: "facts", items };
  // The section is short: when it will not fit under the last section, it starts a page of its own
  // rather than leaving a note or two alone on the next one. A dry run on a blank page measures it.
  if (L.y > TOP) {
    const dry = new Layout(doc, L.size);
    dry.newPage();
    aboutBody(dry, doc, about);
    // Away from the top the heading adds its rule (18); the last 6 after the final note need not fit.
    const total = dry.pages.length === 1 ? dry.y - TOP + 12 : Infinity;
    if (total !== Infinity && total > L.room()) L.newPage();
  }
  aboutBody(L, doc, about);
}

function aboutBody(L: Layout, doc: ReportDocument, about: FactsBlock): void {
  // The whole fact list stays with its heading.
  sectionHeading(L, "About this report", undefined, about);
  facts(L, about);
  L.y += GAP;
  if (doc.provenance.length) {
    tableBlock(L, { kind: "table", id: "provenance", title: "Where the figures come from", columns: [{ key: "label", label: "Data", width: 1.4 }, { key: "detail", label: "Source", width: 4 }, { key: "asOf", label: "As of", format: "datetime", width: 1.4 }], rows: doc.provenance.map((p) => ({ label: p.label, detail: p.detail, asOf: p.asOf })) }, doc.timeZone, (id) => id);
    L.y += GAP;
  }
  if (doc.gaps.length) {
    for (const g of doc.gaps) {
      note(L, { kind: "note", tone: "gap", text: g });
      L.y += 6;
    }
  }
}

function chrome(L: Layout, doc: ReportDocument): void {
  const total = L.pages.length;
  L.pages.forEach((page, i) => {
    const [W, H] = L.size;
    if (i > 0) {
      const left = `${doc.title}: ${doc.subject}`;
      const right = doc.scope.label !== doc.subject ? doc.scope.label : doc.window ? doc.window.label.split(":")[0]! : "";
      const rw = Math.min(measure(right, "regular", 7.4), L.w * 0.4);
      page.text(MARGIN_X, 32, fit(left, "regular", 7.4, L.w - rw - 16), { size: 7.4, color: C.ink3 });
      page.text(W - MARGIN_X, 32, fit(right, "regular", 7.4, L.w * 0.4), { size: 7.4, color: C.ink3, align: "right" });
      page.line(MARGIN_X, 38, W - MARGIN_X, 38, C.rule, 0.6);
    }
    page.line(MARGIN_X, H - 36, W - MARGIN_X, H - 36, C.rule, 0.6);
    page.text(MARGIN_X, H - 24, doc.demo ? "SecOps Toolkit. Demo data, fictional." : "SecOps Toolkit. Unofficial. Uses the public Sophos APIs.", { size: 7, color: C.ink3 });
    page.text(W / 2, H - 24, `Generated ${formatDateTime(doc.generatedAt, doc.timeZone)}`, { size: 7, color: C.ink3, align: "center" });
    page.text(W - MARGIN_X, H - 24, `Page ${i + 1} of ${total}`, { size: 7, color: C.ink2, align: "right", face: "bold" });
  });
}

function cover(L: Layout, doc: ReportDocument, page: PdfPage): void {
  const [W] = L.size;
  const bandH = 236;
  page.rect(0, 0, W, bandH, C.band);
  // The toolkit's mark: a rounded square with a flow into a dot.
  page.roundRect(MARGIN_X, 40, 22, 22, 6, null, C.bandAccent, 1);
  page.line(MARGIN_X + 5, 47, MARGIN_X + 13, 51, C.bandAccent, 1.3);
  page.line(MARGIN_X + 5, 51, MARGIN_X + 13, 51, C.bandAccent, 1.3);
  page.line(MARGIN_X + 5, 55, MARGIN_X + 13, 51, C.bandAccent, 1.3);
  page.circle(MARGIN_X + 15.5, 51, 2.6, C.bandAccent);
  page.text(MARGIN_X + 30, 50, "SecOps Toolkit", { size: 10.5, color: C.white, face: "bold" });
  page.text(MARGIN_X + 30, 60.5, "Unofficial. Uses the public Sophos APIs.", { size: 7.4, color: C.bandDim });
  page.text(MARGIN_X, 112, doc.demo ? "REPORT  \u00B7  DEMO DATA" : "REPORT", { size: 7.6, color: C.bandAccent, face: "bold", tracking: 1.4 });
  let y = 122;
  for (const line of wrap(doc.title, "bold", 28, L.w, 2)) {
    page.text(MARGIN_X, y + 25, line, { size: 28, color: C.white, face: "bold", tracking: -0.4 });
    y += 32;
  }
  for (const line of wrap(doc.subject, "regular", 13, L.w, 2)) {
    page.text(MARGIN_X, y + 16, line, { size: 13, color: C.bandInk });
    y += 17;
  }
  // Details
  y = bandH + 30;
  const details = [
    { label: doc.scope.all ? "SCOPE" : "TENANT", value: doc.scope.label },
    { label: "TIME RANGE", value: doc.window ? doc.window.label : "Current state, read from Sophos" },
    { label: "TIMES SHOWN IN", value: zoneLabel(doc.generatedAt, doc.timeZone) },
    { label: "GENERATED", value: formatDateTime(doc.generatedAt, doc.timeZone) },
    { label: "DATA", value: doc.demo ? "Demo mode. Every tenant, person, device and figure is fictional." : `${doc.scope.credential}. ${doc.calls.total ? `${formatNumber(doc.calls.total)} Sophos ${doc.calls.total === 1 ? "call" : "calls"} for this report, all reads.` : "Read from the toolkit's cache, no new Sophos calls."}` },
  ];
  const colW = (L.w - 24) / 2;
  for (let i = 0; i < details.length; i += 2) {
    const pair = i === details.length - 1 ? [details[i]!] : [details[i]!, details[i + 1]!];
    const width = pair.length === 1 ? L.w : colW;
    let tallest = 0;
    pair.forEach((d, col) => {
      const x = MARGIN_X + col * (colW + 24);
      page.text(x, y + 7, d.label, { size: 6.6, color: C.ink3, face: "bold", tracking: 0.6 });
      const lines = wrap(d.value, "regular", 10, width, 2);
      lines.forEach((line, k) => page.text(x, y + 21 + k * 13, line, { size: 10, color: C.ink1 }));
      tallest = Math.max(tallest, lines.length);
    });
    y += 26 + tallest * 13;
  }
  // At a glance
  if (doc.summary.length) {
    y += 8;
    page.text(MARGIN_X, y + 11, "At a glance", { size: 11, color: C.ink0, face: "bold" });
    y += 20;
    const saved = { page: L.page, y: L.y };
    L.page = page;
    L.y = y;
    kpiTiles(L, doc.summary, 3);
    y = L.y + 18;
    L.page = saved.page;
    L.y = saved.y;
  }
  // Contents
  const rows = L.contents;
  const smallPrint = "Produced by SecOps Toolkit, an unofficial tool that reads the public Sophos APIs. Not a Sophos product. It changes nothing in the tenant: every call it can make is a read, enforced before the request leaves the computer. This report holds tenant data; handle it as confidential.";
  const smallLines = wrap(smallPrint, "regular", 7.2, L.w);
  const smallTop = L.size[1] - BOTTOM - 4 - smallLines.length * 9.4;
  smallLines.forEach((line, i) => page.text(MARGIN_X, smallTop + 7.2 + i * 9.4, line, { size: 7.2, color: C.ink3 }));
  const room = smallTop - 14 - y - 18;
  // One column when every entry fits, two when not (US Letter is shorter), tighter rows as a last resort; never a silently cut list.
  const cols = rows.length > Math.floor(room / 14) ? 2 : 1;
  const perCol = Math.ceil(rows.length / cols);
  const rowH = Math.max(11, Math.min(14, room / Math.max(1, perCol)));
  const fitRows = Math.max(0, Math.floor(room / rowH));
  if (rows.length && fitRows > 0) {
    page.text(MARGIN_X, y + 11, "Contents", { size: 11, color: C.ink0, face: "bold" });
    y += 18;
    const colW = cols === 1 ? L.w : (L.w - 24) / 2;
    const shown = rows.slice(0, fitRows * cols);
    shown.forEach((r, i) => {
      const x = MARGIN_X + Math.floor(i / perCol) * (colW + 24);
      const ry = y + (i % perCol) * rowH;
      page.text(x, ry + rowH - 4.5, fit(r.title, "regular", 8.8, colW - 40), { size: 8.8, color: C.ink1 });
      page.text(x + colW, ry + rowH - 4.5, String(r.page), { size: 8.8, color: C.ink2, align: "right" });
      page.line(x, ry + rowH - 0.5, x + colW, ry + rowH - 0.5, C.rule, 0.5);
    });
  }
}

export function renderPdf(doc: ReportDocument, options: { paper?: Paper; csvName?: (tableId: string) => string } = {}): Buffer {
  const L = new Layout(doc, PAPER[options.paper ?? "a4"]);
  const csvName = options.csvName ?? ((id: string) => `${id}.csv`);
  // Page 1 is the cover; it is drawn last, once the contents know their pages.
  L.newPage();
  const coverPage = L.page;
  L.newPage();
  for (const s of doc.sections) {
    sectionHeading(L, s.title, s.lead, s.blocks[0]);
    s.blocks.forEach((b, i) => {
      block(L, b, doc.timeZone, csvName);
      if (i < s.blocks.length - 1) L.y += GAP;
    });
    L.y += GAP;
  }
  aboutSection(L, doc);
  cover(L, doc, coverPage);
  chrome(L, doc);
  return writePdf(L.pages, { title: `${doc.title}: ${doc.subject}`, subject: doc.scope.label, createdAt: doc.generatedAt });
}
