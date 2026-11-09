/**
 * The bundled Noto fonts a PDF draws with when Helvetica can't: Latin letters
 * beyond Western European with Greek and Cyrillic (Noto Sans), Arabic, Hebrew,
 * Thai, Korean Hangul, and CJK ideographs and kana
 * (built by scripts/build-pdf-fonts.mjs, listed in backend/fonts/fonts.json).
 * fonts.json says which characters each font covers, so a font is read from
 * disk only when a report needs it. HarfBuzz shapes the text (Arabic joining,
 * Thai and Hebrew marks), and a PDF embeds each font it uses as a Type 0 font,
 * subset to the glyphs it draws, with a ToUnicode map so the text can be
 * searched and copied.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { deflateSync, brotliDecompressSync } from "node:zlib";
import * as hb from "harfbuzzjs";
import { SubsetFace, SUBSET_FLAGS } from "./hb-subset.js";

export type Weight = "regular" | "bold";

interface ManifestFont {
  id: string;
  name: string;
  files: { regular: string; bold?: string };
  sha256: { regular: string; bold?: string };
  ranges: Array<[number, number]>;
}

const DIR = new URL("../../../fonts/", import.meta.url);
const FONTS: ManifestFont[] = (JSON.parse(readFileSync(new URL("fonts.json", DIR), "utf8")) as { fonts: ManifestFont[] }).fonts;

/** The index of the first bundled font that has a glyph for `cp`, or -1. */
export function fontFor(cp: number): number {
  for (let i = 0; i < FONTS.length; i++) {
    const r = FONTS[i]!.ranges;
    let lo = 0;
    let hi = r.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (cp < r[mid]![0]) hi = mid - 1;
      else if (cp > r[mid]![1]) lo = mid + 1;
      else return i;
    }
  }
  return -1;
}

/** Noto Sans: Latin, Greek and Cyrillic. A Latin word with a letter Helvetica lacks is drawn from it whole. */
export const LATIN = FONTS.findIndex((f) => f.id === "latin-greek-cyrillic");
if (LATIN < 0) throw new Error("backend/fonts/fonts.json lists no latin-greek-cyrillic font; run scripts/build-pdf-fonts.mjs again");

export function coveredBy(font: number, cp: number): boolean {
  return FONTS[font]!.ranges.some(([a, b]) => cp >= a && cp <= b);
}

export function fontIds(): string[] {
  return FONTS.map((f) => f.id);
}

/** One weight of one bundled font, loaded. A bold run in a font with no bold is drawn from the regular, emboldened. */
export class EmbeddedFace {
  /** The PDF resource name, the same in every document: F3 and up (F1 and F2 are Helvetica). */
  readonly key: string;
  readonly fontName: string;
  readonly upem: number;
  readonly bytes: Buffer;
  private readonly font: hb.Font;
  private readonly advances = new Map<number, number>();
  private subsetter: SubsetFace | null = null;

  constructor(
    readonly index: number,
    readonly weight: Weight,
  ) {
    const f = FONTS[index]!;
    const file = f.files[weight]!;
    this.key = `F${3 + index * 2 + (weight === "bold" ? 1 : 0)}`;
    this.fontName = `${f.name}-${weight === "bold" ? "Bold" : "Regular"}`;
    this.bytes = brotliDecompressSync(readFileSync(new URL(file, DIR)));
    const sum = createHash("sha256").update(this.bytes).digest("hex");
    if (sum !== f.sha256[weight]) throw new Error(`backend/fonts/${file} does not match fonts.json (SHA-256 ${sum}); run scripts/build-pdf-fonts.mjs again`);
    const face = new hb.Face(new hb.Blob(this.bytes));
    this.upem = face.upem;
    this.font = new hb.Font(face);
  }

  /** The glyph's own advance, in font units (what the PDF's width array says). */
  advance(gid: number): number {
    let a = this.advances.get(gid);
    if (a === undefined) {
      a = this.font.glyphHAdvance(gid);
      this.advances.set(gid, a);
    }
    return a;
  }

  nominal(cp: number): number | undefined {
    return this.font.nominalGlyph(cp);
  }

  shape(text: string, rtl: boolean): ShapedGlyph[] {
    const buf = shapingBuffer();
    buf.reset();
    buf.setClusterLevel(1); // MONOTONE_CHARACTERS: a mark keeps its own cluster, so it maps back to its own character
    buf.addText(text);
    buf.setDirection(rtl ? 5 : 4);
    buf.guessSegmentProperties();
    hb.shape(this.font, buf);
    const glyphs = buf.getGlyphInfosAndPositions();
    // Each glyph's text, for the ToUnicode map: a cluster of one glyph stands for all its characters. In a
    // cluster of several (Thai SARA AM splits in two, a merged mark), a glyph that is a character's own glyph
    // takes that character and the first other glyph takes what is left.
    const starts = [...new Set(glyphs.map((g) => g.cluster))].sort((a, b) => a - b);
    const end = (c: number) => starts[starts.indexOf(c) + 1] ?? text.length;
    const byCluster = new Map<number, number[]>();
    const reading = glyphs.map((_, i) => (rtl ? glyphs.length - 1 - i : i));
    for (const i of reading) {
      const c = glyphs[i]!.cluster;
      const list = byCluster.get(c);
      if (list) list.push(i);
      else byCluster.set(c, [i]);
    }
    const texts: string[] = glyphs.map(() => "");
    const exact: boolean[] = glyphs.map(() => true);
    for (const [c, idx] of byCluster) {
      const all = text.slice(c, end(c)).replace(INVISIBLE, "");
      // HarfBuzz draws Thai and Lao SARA AM as its two parts, NIKHAHIT and SARA AA: match the glyphs to those.
      const parts = all.replace(/\u0e33/g, "\u0e4d\u0e32").replace(/\u0eb3/g, "\u0ecd\u0eb2");
      const chars = [...parts];
      if (idx.length === 1) texts[idx[0]!] = all;
      else {
        const others: number[] = [];
        for (const i of idx) {
          const at = chars.findIndex((ch) => this.nominal(ch.codePointAt(0)!) === glyphs[i]!.codepoint);
          if (at >= 0) texts[i] = chars.splice(at, 1)[0]!;
          else others.push(i);
        }
        if (chars.length) texts[others[0] ?? idx[idx.length - 1]!] += chars.join("");
      }
      // A cluster whose glyphs are not each the glyph of one of its characters (an Arabic letter's joining form,
      // the dots Noto draws apart, a ligature) can't be read back exactly from the ToUnicode map.
      const ok = idx.every((i) => {
        const cps = [...texts[i]!];
        return cps.length === 1 && this.nominal(cps[0]!.codePointAt(0)!) === glyphs[i]!.codepoint;
      });
      if (!ok || parts !== all) for (const i of idx) exact[i] = false;
    }
    return glyphs.map((g, i) => ({ gid: g.codepoint, advance: g.xAdvance ?? 0, dx: g.xOffset ?? 0, dy: g.yOffset ?? 0, text: texts[i]!, exact: exact[i]! }));
  }

  /** The font program for a PDF: this font cut down to `gids`, glyph numbers kept, so a glyph's number is its CID. */
  subset(gids: Iterable<number>, unicodes: Iterable<number>): Buffer {
    this.subsetter ??= new SubsetFace(this.bytes);
    return this.subsetter.subset({
      glyphs: gids,
      unicodes,
      flags: SUBSET_FLAGS.RETAIN_GIDS | SUBSET_FLAGS.NO_HINTING,
      dropTables: ["GSUB", "GPOS", "GDEF", "BASE", "JSTF", "vhea", "vmtx", "VORG"],
      noLayout: true,
    });
  }

  table(tag: string): DataView | null {
    const t = this.font.face.referenceTable(tag);
    return t ? new DataView(t.buffer, t.byteOffset, t.byteLength) : null;
  }
}

export interface ShapedGlyph {
  gid: number;
  /** Font units. */
  advance: number;
  dx: number;
  dy: number;
  /** The characters this glyph stands for, for the ToUnicode map ("" for the second glyph of a cluster). */
  text: string;
  /** The ToUnicode map gives back exactly the characters of this glyph's cluster. */
  exact: boolean;
}

/** Joiners and variation selectors: they shape their neighbours and stand for no text of their own. */
const INVISIBLE = /[‌‍͏︀-️᠋-᠏\u{e0100}-\u{e01ef}]/gu;

let buffer: hb.Buffer | null = null;
function shapingBuffer(): hb.Buffer {
  buffer ??= new hb.Buffer();
  return buffer;
}

const faces = new Map<string, EmbeddedFace>();

/** The face to draw `weight` text in from font `index`, and whether it must be emboldened (no bold file). */
export function face(index: number, weight: Weight): { face: EmbeddedFace; fauxBold: boolean } {
  const real: Weight = weight === "bold" && FONTS[index]!.files.bold ? "bold" : "regular";
  const id = `${index}:${real}`;
  let f = faces.get(id);
  if (!f) {
    f = new EmbeddedFace(index, real);
    faces.set(id, f);
  }
  return { face: f, fauxBold: weight === "bold" && real === "regular" };
}

export function faceByKey(key: string): EmbeddedFace {
  for (const f of faces.values()) if (f.key === key) return f;
  throw new Error(`no loaded font ${key}`);
}

// ---------------------------------------------------------------- PDF objects

const n = (v: number) => (Math.round(v * 100) / 100).toString();

/** A glyph's width in the PDF's width array, in thousandths of an em. */
export function pdfWidth(f: EmbeddedFace, gid: number): number {
  return Math.round((f.advance(gid) * 1000 * 100) / f.upem) / 100;
}

function hex4(v: number): string {
  return v.toString(16).toUpperCase().padStart(4, "0");
}

function utf16Hex(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) out += hex4(text.charCodeAt(i));
  return out;
}

function toUnicode(map: Map<number, string>): string {
  const entries = [...map.entries()].filter(([, t]) => t).sort((a, b) => a[0] - b[0]);
  const blocks: string[] = [];
  for (let i = 0; i < entries.length; i += 100) {
    const chunk = entries.slice(i, i + 100);
    blocks.push(`${chunk.length} beginbfchar\n${chunk.map(([g, t]) => `<${hex4(g)}> <${utf16Hex(t)}>`).join("\n")}\nendbfchar`);
  }
  return [
    "/CIDInit /ProcSet findresource begin",
    "12 dict begin",
    "begincmap",
    "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
    "/CMapName /Adobe-Identity-UCS def",
    "/CMapType 2 def",
    "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange",
    ...blocks,
    "endcmap",
    "CMapName currentdict /CMap defineresource pop",
    "end",
    "end",
  ].join("\n");
}

function stream(dict: string, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from(`${dict}\nstream\n`, "latin1"), data, Buffer.from("\nendstream", "latin1")]);
}

/**
 * The five objects that embed one font, numbered from `base`: the Type 0
 * font, its CID font, the descriptor, the font program and the ToUnicode map.
 * `glyphs` maps each glyph the document draws to the characters it stands for.
 */
export function fontObjects(key: string, glyphs: Map<number, string>, base: number): Array<string | Buffer> {
  const f = faceByKey(key);
  const gids = [...glyphs.keys()].sort((a, b) => a - b);
  const unicodes = new Set<number>();
  for (const [gid, t] of glyphs) {
    const cps = [...t].map((c) => c.codePointAt(0)!);
    if (cps.length === 1 && f.nominal(cps[0]!) === gid) unicodes.add(cps[0]!);
  }
  const program = f.subset(gids, unicodes);
  // A subset font's name starts with a tag of six capital letters, here taken from the glyphs it holds.
  const digest = createHash("sha256").update(`${key}:${gids.join(",")}`).digest();
  const tag = Array.from(digest.subarray(0, 6), (b) => String.fromCharCode(65 + (b % 26))).join("");
  const name = `${tag}+${f.fontName}`;
  const scale = 1000 / f.upem;
  const head = f.table("head");
  const bbox = head ? [head.getInt16(36), head.getInt16(38), head.getInt16(40), head.getInt16(42)].map((v) => n(v * scale)) : ["0", "-300", "1000", "1000"];
  const hhea = f.table("hhea");
  const ascent = hhea ? hhea.getInt16(4) * scale : 900;
  const descent = hhea ? hhea.getInt16(6) * scale : -300;
  const os2 = f.table("OS/2");
  const capHeight = os2 && os2.getUint16(0) >= 2 && os2.byteLength >= 90 ? os2.getInt16(88) * scale : ascent * 0.75;
  // Widths: runs of consecutive glyph numbers share one array.
  const w: string[] = [];
  for (let i = 0; i < gids.length; ) {
    let j = i;
    while (j + 1 < gids.length && gids[j + 1] === gids[j]! + 1) j++;
    w.push(`${gids[i]} [${gids.slice(i, j + 1).map((g) => n(pdfWidth(f, g))).join(" ")}]`);
    i = j + 1;
  }
  const packed = deflateSync(program);
  const cmap = deflateSync(Buffer.from(toUnicode(glyphs), "latin1"));
  return [
    `<< /Type /Font /Subtype /Type0 /BaseFont /${name} /Encoding /Identity-H /DescendantFonts [${base + 1} 0 R] /ToUnicode ${base + 4} 0 R >>`,
    `<< /Type /Font /Subtype /CIDFontType2 /BaseFont /${name} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor ${base + 2} 0 R /DW 1000 /W [${w.join(" ")}] /CIDToGIDMap /Identity >>`,
    `<< /Type /FontDescriptor /FontName /${name} /Flags 4 /FontBBox [${bbox.join(" ")}] /ItalicAngle 0 /Ascent ${n(ascent)} /Descent ${n(descent)} /CapHeight ${n(capHeight)} /StemV 80 /FontFile2 ${base + 3} 0 R >>`,
    stream(`<< /Filter /FlateDecode /Length ${packed.length} /Length1 ${program.length} >>`, packed),
    stream(`<< /Filter /FlateDecode /Length ${cmap.length} >>`, cmap),
  ];
}
