/**
 * A small PDF 1.7 writer: pages of filled and stroked shapes and text in the
 * two standard Helvetica faces, Flate-compressed. Enough for a report, with
 * no dependency and no browser, so a scheduled run can write the same PDF the
 * Export button does. Coordinates are in points from the top-left corner.
 */

import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { encode, measure, type FontFace } from "./fonts.js";

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

export class PdfPage {
  readonly ops: string[] = [];

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
    const codes = encode(text);
    if (!codes.length) return 0;
    const face = style.face ?? "regular";
    const tracking = style.tracking ?? 0;
    const w = measure(text, face, style.size, tracking);
    const left = style.align === "right" ? x - w : style.align === "center" ? x - w / 2 : x;
    this.ops.push(`BT /${face === "bold" ? "F2" : "F1"} ${n(style.size)} Tf ${tracking ? `${n(tracking)} Tc ` : ""}${rgb(style.color)} rg ${n(left)} ${n(this.y(baseline))} Td ${pdfString(codes)} Tj ${tracking ? "0 Tc " : ""}ET`);
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
  const hash = createHash("md5");
  pages.forEach((page, i) => {
    const pageId = firstPage + i * 2;
    const content = deflateSync(Buffer.from(page.ops.join("\n"), "latin1"));
    hash.update(content);
    obj(pageId, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${n(page.width)} ${n(page.height)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${pageId + 1} 0 R >>`);
    offsets[pageId + 1] = length;
    put(`${pageId + 1} 0 obj\n<< /Length ${content.length} /Filter /FlateDecode >>\nstream\n`);
    put(content);
    put("\nendstream\nendobj\n");
  });
  const size = firstPage + pages.length * 2;
  const xref = length;
  let table = `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (let id = 1; id < size; id++) table += `${String(offsets[id] ?? 0).padStart(10, "0")} 00000 n \n`;
  const id = hash.update(info.title).update(String(info.createdAt)).digest("hex");
  put(table);
  put(`trailer\n<< /Size ${size} /Root 1 0 R /Info 5 0 R /ID [<${id}> <${id}>] >>\nstartxref\n${xref}\n%%EOF\n`);
  return Buffer.concat(chunks);
}
