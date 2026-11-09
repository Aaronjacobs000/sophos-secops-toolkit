/**
 * A small PDF 1.7 writer: pages of filled and stroked shapes and text in the
 * two standard Helvetica faces, Flate-compressed, plus the bundled Noto fonts
 * (embedded, subset to the glyphs drawn) for text Helvetica can't draw. Enough
 * for a report, with no browser, so a scheduled run can write the same PDF the
 * Export button does. Coordinates are in points from the top-left corner.
 */

import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { encode, layoutLine, lineWidth, measure, needsEmbedded, type FontFace, type FontRun } from "./fonts.js";
import { fontObjects, pdfWidth } from "./embedded.js";

export type Rgb = readonly [number, number, number];

export interface TextStyle {
  face?: FontFace;
  size: number;
  color: Rgb;
  /** Extra space between characters, in points. */
  tracking?: number;
  align?: "left" | "right" | "center";
}

const n = (v: number) => (Math.round(v * 100) / 100).toString();
const rgb = (c: Rgb) => `${n(c[0] / 255)} ${n(c[1] / 255)} ${n(c[2] / 255)}`;

function pdfString(codes: number[]): string {
  let out = "(";
  for (const c of codes) {
    if (c === 0x28 || c === 0x29 || c === 0x5c) out += `\\${String.fromCharCode(c)}`;
    else if (c < 32 || c > 126) out += `\\${c.toString(8).padStart(3, "0")}`;
    else out += String.fromCharCode(c);
  }
  return `${out})`;
}

/** How much an emboldened run's outline adds, as a share of the type size. */
const FAUX_BOLD = 0.03;

const hex4 = (v: number) => v.toString(16).toUpperCase().padStart(4, "0");

/** A glyph a page draws from a bundled font, and the characters it stands for. */
interface GlyphUse {
  text: string;
  /** The glyph is the font's own glyph for that one character (the surest ToUnicode entry). */
  nominal: boolean;
}

/**
 * A shaped run as text operators: TJ arrays whose numbers move each glyph from
 * where the font's widths would put it to where HarfBuzz placed it, and a text
 * rise for a glyph lifted or lowered (Thai and Hebrew marks).
 */
function glyphOps(run: FontRun, size: number): string {
  const f = run.face;
  const k = 1000 / f.upem;
  const out: string[] = [];
  let parts: string[] = [];
  let hex = "";
  let move = 0;
  let rise = 0;
  const flushHex = () => {
    if (hex) parts.push(`<${hex}>`);
    hex = "";
  };
  const flushMove = () => {
    if (Math.abs(move) >= 0.005) {
      flushHex();
      parts.push(n(move));
    }
    move = 0;
  };
  const closeArray = () => {
    flushHex();
    if (parts.length) out.push(`[${parts.join(" ")}] TJ`);
    parts = [];
  };
  for (const g of run.glyphs) {
    const dy = (g.dy * size) / f.upem;
    if (Math.abs(dy - rise) >= 0.005) {
      closeArray();
      out.push(`${n(dy)} Ts`);
      rise = dy;
    }
    // A TJ number moves the next glyph left by that many thousandths of an em.
    move -= g.dx * k;
    flushMove();
    hex += hex4(g.gid);
    move = g.dx * k + pdfWidth(f, g.gid) - g.advance * k;
  }
  flushMove();
  closeArray();
  if (rise) out.push("0 Ts");
  return out.join(" ");
}

export class PdfPage {
  readonly ops: string[] = [];
  /** Glyphs drawn from the bundled fonts, by resource name. */
  readonly glyphs = new Map<string, Map<number, GlyphUse>>();

  constructor(
    readonly width: number,
    readonly height: number,
  ) {}

  private y(top: number): number {
    return this.height - top;
  }

  rect(x: number, top: number, w: number, h: number, fill: Rgb | null, stroke: Rgb | null = null, lineWidth = 0.6): void {
    if (w <= 0 || h <= 0) return;
    const parts: string[] = [];
    if (fill) parts.push(`${rgb(fill)} rg`);
    if (stroke) parts.push(`${rgb(stroke)} RG ${n(lineWidth)} w`);
    parts.push(`${n(x)} ${n(this.y(top + h))} ${n(w)} ${n(h)} re ${fill && stroke ? "B" : fill ? "f" : "S"}`);
    this.ops.push(parts.join(" "));
  }

  roundRect(x: number, top: number, w: number, h: number, r: number, fill: Rgb | null, stroke: Rgb | null = null, lineWidth = 0.6): void {
    if (w <= 0 || h <= 0) return;
    const rr = Math.min(r, w / 2, h / 2);
    const k = 0.5523 * rr;
    const x0 = x;
    const x1 = x + w;
    const y0 = this.y(top);
    const y1 = this.y(top + h);
    const path = [
      `${n(x0 + rr)} ${n(y0)} m`,
      `${n(x1 - rr)} ${n(y0)} l`,
      `${n(x1 - rr + k)} ${n(y0)} ${n(x1)} ${n(y0 - rr + k)} ${n(x1)} ${n(y0 - rr)} c`,
      `${n(x1)} ${n(y1 + rr)} l`,
      `${n(x1)} ${n(y1 + rr - k)} ${n(x1 - rr + k)} ${n(y1)} ${n(x1 - rr)} ${n(y1)} c`,
      `${n(x0 + rr)} ${n(y1)} l`,
      `${n(x0 + rr - k)} ${n(y1)} ${n(x0)} ${n(y1 + rr - k)} ${n(x0)} ${n(y1 + rr)} c`,
      `${n(x0)} ${n(y0 - rr)} l`,
      `${n(x0)} ${n(y0 - rr + k)} ${n(x0 + rr - k)} ${n(y0)} ${n(x0 + rr)} ${n(y0)} c`,
      "h",
    ].join(" ");
    const parts: string[] = [];
    if (fill) parts.push(`${rgb(fill)} rg`);
    if (stroke) parts.push(`${rgb(stroke)} RG ${n(lineWidth)} w`);
    parts.push(`${path} ${fill && stroke ? "B" : fill ? "f" : "S"}`);
    this.ops.push(parts.join(" "));
  }

  line(x1: number, top1: number, x2: number, top2: number, color: Rgb, width = 0.6): void {
    this.ops.push(`${rgb(color)} RG ${n(width)} w ${n(x1)} ${n(this.y(top1))} m ${n(x2)} ${n(this.y(top2))} l S`);
  }

  circle(cx: number, cy: number, r: number, fill: Rgb): void {
    this.roundRect(cx - r, cy - r, r * 2, r * 2, r, fill);
  }

  /** Text with its baseline at `baseline`; returns the width drawn. */
  text(x: number, baseline: number, text: string, style: TextStyle): number {
    if (needsEmbedded(text)) return this.mixedText(x, baseline, text, style);
    const codes = encode(text);
    if (!codes.length) return 0;
    const face = style.face ?? "regular";
    const tracking = style.tracking ?? 0;
    const w = measure(text, face, style.size, tracking);
    const left = style.align === "right" ? x - w : style.align === "center" ? x - w / 2 : x;
    this.ops.push(`BT /${face === "bold" ? "F2" : "F1"} ${n(style.size)} Tf ${tracking ? `${n(tracking)} Tc ` : ""}${rgb(style.color)} rg ${n(left)} ${n(this.y(baseline))} Td ${pdfString(codes)} Tj ${tracking ? "0 Tc " : ""}ET`);
    return w;
  }

  /**
   * Text that needs a bundled font: Helvetica and Noto runs in drawing order
   * in one text object. Tracking spaces the Helvetica letters only, as it
   * would break Arabic joins and Thai marks. A line that reads right to left
   * in part, or holds glyphs the ToUnicode map can't name exactly (Arabic
   * letters share glyph pieces), carries its characters in reading order as
   * ActualText, for copying and search in the viewers that read it.
   */
  private mixedText(x: number, baseline: number, text: string, style: TextStyle): number {
    const face = style.face ?? "regular";
    const tracking = style.tracking ?? 0;
    const line = layoutLine(text, face);
    if (!line.runs.length) return 0;
    const w = lineWidth(line, style.size, tracking);
    const left = style.align === "right" ? x - w : style.align === "center" ? x - w / 2 : x;
    const ops = [`${line.needsActualText ? `/Span << /ActualText ${infoString(line.text)} >> BDC ` : ""}BT ${rgb(style.color)} rg ${n(left)} ${n(this.y(baseline))} Td`];
    let spacing = 0;
    let outlined = false;
    let anyOutline = false;
    for (const run of line.runs) {
      const wantSpacing = run.kind === "std" ? tracking : 0;
      if (wantSpacing !== spacing) ops.push(`${n(wantSpacing)} Tc`);
      spacing = wantSpacing;
      const wantOutline = run.kind === "font" && run.fauxBold;
      if (wantOutline && !outlined) ops.push(`2 Tr ${n(style.size * FAUX_BOLD)} w ${rgb(style.color)} RG`);
      else if (!wantOutline && outlined) ops.push("0 Tr");
      outlined = wantOutline;
      anyOutline ||= wantOutline;
      if (run.kind === "std") {
        ops.push(`/${face === "bold" ? "F2" : "F1"} ${n(style.size)} Tf ${pdfString(run.codes)} Tj`);
        continue;
      }
      ops.push(`/${run.face.key} ${n(style.size)} Tf ${glyphOps(run, style.size)}`);
      let used = this.glyphs.get(run.face.key);
      if (!used) {
        used = new Map();
        this.glyphs.set(run.face.key, used);
      }
      for (const g of run.glyphs) {
        const cps = [...g.text];
        const nominal = cps.length === 1 && run.face.nominal(cps[0]!.codePointAt(0)!) === g.gid;
        const had = used.get(g.gid);
        if (!had || (!had.text && g.text) || (nominal && !had.nominal)) used.set(g.gid, { text: g.text, nominal });
      }
    }
    if (spacing) ops.push("0 Tc");
    if (outlined) ops.push("0 Tr");
    ops.push(line.needsActualText ? "ET EMC" : "ET");
    // The outline's width and colour are graphics state, kept to this text by q and Q.
    this.ops.push(anyOutline ? `q ${ops.join(" ")} Q` : ops.join(" "));
    return w;
  }
}

function pdfDate(ms: number): string {
  const d = new Date(ms);
  const p = (v: number) => String(v).padStart(2, "0");
  return `D:${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

/** A PDF text string for the document info: UTF-16BE with a byte order mark, as hex. */
function infoString(text: string): string {
  const buf = Buffer.from(`\uFEFF${text}`, "utf16le");
  for (let i = 0; i < buf.length; i += 2) {
    const a = buf[i]!;
    buf[i] = buf[i + 1]!;
    buf[i + 1] = a;
  }
  return `<${buf.toString("hex")}>`;
}

export interface PdfInfo {
  title: string;
  subject?: string;
  createdAt: number;
}

export function writePdf(pages: PdfPage[], info: PdfInfo): Buffer {
  const chunks: Buffer[] = [];
  const offsets: number[] = [];
  let length = 0;
  const put = (b: Buffer | string) => {
    const buf = typeof b === "string" ? Buffer.from(b, "latin1") : b;
    chunks.push(buf);
    length += buf.length;
  };
  const obj = (id: number, body: Buffer | string) => {
    offsets[id] = length;
    put(`${id} 0 obj\n`);
    put(body);
    put("\nendobj\n");
  };
  put("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n");
  const firstPage = 6;
  const kids = pages.map((_, i) => `${firstPage + i * 2} 0 R`).join(" ");
  obj(1, "<< /Type /Catalog /Pages 2 0 R /ViewerPreferences << /DisplayDocTitle true >> /Lang (en-US) >>");
  obj(2, `<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`);
  obj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
  obj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
  obj(5, `<< /Title ${infoString(info.title)}${info.subject ? ` /Subject ${infoString(info.subject)}` : ""} /Producer (SecOps Toolkit) /Creator (SecOps Toolkit reports) /CreationDate (${pdfDate(info.createdAt)}) >>`);
  // Bundled fonts the pages drew from: five objects each, after the pages.
  const glyphs = new Map<string, Map<number, string>>();
  for (const page of pages) {
    for (const [key, used] of page.glyphs) {
      const all = glyphs.get(key) ?? new Map<number, string>();
      for (const [gid, u] of used) if (!all.get(gid) || u.nominal) all.set(gid, u.text);
      glyphs.set(key, all);
    }
  }
  const fontKeys = [...glyphs.keys()].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
  const fontBase = new Map(fontKeys.map((key, i) => [key, firstPage + pages.length * 2 + i * 5]));
  const hash = createHash("md5");
  pages.forEach((page, i) => {
    const pageId = firstPage + i * 2;
    const content = deflateSync(Buffer.from(page.ops.join("\n"), "latin1"));
    hash.update(content);
    const extra = fontKeys.filter((key) => page.glyphs.has(key)).map((key) => ` /${key} ${fontBase.get(key)} 0 R`).join("");
    obj(pageId, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${n(page.width)} ${n(page.height)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R${extra} >> >> /Contents ${pageId + 1} 0 R >>`);
    offsets[pageId + 1] = length;
    put(`${pageId + 1} 0 obj\n<< /Length ${content.length} /Filter /FlateDecode >>\nstream\n`);
    put(content);
    put("\nendstream\nendobj\n");
  });
  for (const key of fontKeys) fontObjects(key, glyphs.get(key)!, fontBase.get(key)!).forEach((body, k) => obj(fontBase.get(key)! + k, body));
  const size = firstPage + pages.length * 2 + fontKeys.length * 5;
  const xref = length;
  let table = `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (let id = 1; id < size; id++) table += `${String(offsets[id] ?? 0).padStart(10, "0")} 00000 n \n`;
  const id = hash.update(info.title).update(String(info.createdAt)).digest("hex");
  put(table);
  put(`trailer\n<< /Size ${size} /Root 1 0 R /Info 5 0 R /ID [<${id}> <${id}>] >>\nstartxref\n${xref}\n%%EOF\n`);
  return Buffer.concat(chunks);
}
