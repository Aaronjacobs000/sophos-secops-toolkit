/**
 * Text for the PDF writer. Latin text uses the two standard Helvetica faces
 * every PDF reader carries (nothing embedded), their glyph widths, and the
 * WinAnsi encoding they use. A Latin word with a letter WinAnsi lacks (c with
 * a caron, l with a stroke, Vietnamese) or an accent no WinAnsi letter carries
 * is drawn whole from the bundled Noto Sans, so its letters match. Greek,
 * Cyrillic, Arabic, Hebrew, Thai, Korean, Chinese and Japanese text is drawn
 * from the bundled Noto fonts too (embedded.ts), shaped by HarfBuzz and put in
 * reading order (bidi.ts).
 * Anything no font covers prints as "?"; the CSV export keeps every character.
 * A line with nothing for the Noto fonts takes exactly the Helvetica path it
 * always did.
 *
 * Widths are Adobe's Helvetica and Helvetica-Bold metrics in 1/1000 em for
 * WinAnsi codes 32 to 255.
 */

import { MIRROR, hasRtl, resolveLevels, visualOrder } from "./bidi.js";
import { coveredBy, face as embeddedFace, fontFor, LATIN, type EmbeddedFace, type ShapedGlyph } from "./embedded.js";

// prettier-ignore
const HELVETICA = [278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584,0,556,0,222,556,333,1000,556,556,333,1000,667,333,1000,0,611,0,0,222,222,333,333,350,556,1000,333,1000,500,333,944,0,500,667,278,333,556,556,556,556,260,556,333,737,370,556,584,333,737,333,400,584,333,333,333,556,537,278,333,333,365,556,834,834,834,611,667,667,667,667,667,667,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,500,556,556,556,556,278,278,278,278,556,556,556,556,556,556,556,584,611,556,556,556,556,500,556,500];
// prettier-ignore
const HELVETICA_BOLD = [278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584,0,556,0,278,556,500,1000,556,556,333,1000,667,333,1000,0,611,0,0,278,278,500,500,350,556,1000,333,1000,556,333,944,0,500,667,278,333,556,556,556,556,280,556,333,737,370,556,584,333,737,333,400,584,333,333,333,611,556,278,333,333,365,556,834,834,834,611,722,722,722,722,722,722,1000,722,667,667,667,667,278,278,278,278,722,722,778,778,778,778,778,584,778,722,722,722,722,667,667,611,556,556,556,556,556,556,889,556,556,556,556,556,278,278,278,278,611,611,611,611,611,611,611,584,611,611,611,611,611,556,611,556];

export type FontFace = "regular" | "bold";

/** Unicode characters WinAnsi places at 0x80 to 0x9F. */
const WIN_ANSI_EXTRA: Record<number, number> = {
  0x20ac: 0x80, 0x201a: 0x82, 0x0192: 0x83, 0x201e: 0x84, 0x2026: 0x85, 0x2020: 0x86, 0x2021: 0x87, 0x02c6: 0x88, 0x2030: 0x89, 0x0160: 0x8a,
  0x2039: 0x8b, 0x0152: 0x8c, 0x017d: 0x8e, 0x2018: 0x91, 0x2019: 0x92, 0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97,
  0x02dc: 0x98, 0x2122: 0x99, 0x0161: 0x9a, 0x203a: 0x9b, 0x0153: 0x9c, 0x017e: 0x9e, 0x0178: 0x9f,
};

/** Dashes and spaces Helvetica draws as a near twin. */
const NEAR: Record<string, string> = { "\u2212": "-", "\u2010": "-", "\u2011": "-", "\u00A0": " ", "\u2009": " ", "\u202F": " " };

/** Letters with no WinAnsi form and no decomposition: the plain letter the Helvetica encoder prints, when no bundled font is used. */
const FOLD: Record<string, string> = { "\u0142": "l", "\u0141": "L", "\u0111": "d", "\u0110": "D", "\u0131": "i", "\u0127": "h", "\u0126": "H", "\u0140": "l", "\u013F": "L", "\u0167": "t", "\u0166": "T" };

/** The WinAnsi code for a character Helvetica draws as itself or as a near twin, or null. */
function direct(ch: string, cp: number): number | null {
  if ((cp >= 32 && cp <= 126) || (cp >= 0xa0 && cp <= 0xff)) return cp;
  const extra = WIN_ANSI_EXTRA[cp];
  if (extra !== undefined) return extra;
  const near = NEAR[ch];
  if (near) return near.charCodeAt(0);
  return null;
}

function code(ch: string): number {
  const cp = ch.codePointAt(0)!;
  const d = direct(ch, cp);
  if (d !== null) return d;
  const folded = FOLD[ch];
  if (folded) return folded.charCodeAt(0);
  const base = ch.normalize("NFKD").replace(/[\u0300-\u036F]/g, "");
  if (base.length === 1 && base !== ch) return code(base);
  return 63; // "?"
}

/** The WinAnsi codes for a string: zero-width and control characters dropped, tabs and line breaks as spaces. */
export function encode(text: string): number[] {
  const out: number[] = [];
  for (const ch of text.normalize("NFC").replace(/[\u200B-\u200F\u2028\u2029\u2060\uFEFF]/g, "").replace(/[\t\r\n]+/g, " ")) {
    const cp = ch.codePointAt(0)!;
    if (cp < 32 || (cp >= 0x7f && cp < 0xa0)) continue;
    out.push(code(ch));
  }
  return out;
}

export function widthOf(codes: number[], face: FontFace, size: number, tracking = 0): number {
  const table = face === "bold" ? HELVETICA_BOLD : HELVETICA;
  let w = 0;
  for (const c of codes) w += table[c - 32] ?? 556;
  return (w / 1000) * size + tracking * codes.length;
}

export function measure(text: string, face: FontFace, size: number, tracking = 0): number {
  return needsEmbedded(text) ? lineWidth(layoutLine(text, face), size, tracking) : widthOf(encode(text), face, size, tracking);
}

// ---------------------------------------------------------------- text for the Noto fonts

const PLAIN = /^[\x20-\x7e\u00a0-\u00ff]*$/;
const MARK = /^\p{M}$/u;
/** Characters that change how their neighbours are drawn and draw nothing themselves. */
const isJoiner = (cp: number) => cp === 0x200c || cp === 0x200d || cp === 0x034f || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef) || (cp >= 0x180b && cp <= 0x180f);
const attaches = (ch: string, cp: number) => isJoiner(cp) || MARK.test(ch);
const LATIN_LETTER = /^\p{Script=Latin}$/u;
/** A combining accent with no precomposed letter (g with a tilde), on a Latin letter Noto Sans has: Noto Sans draws the two. */
const latinAccent = (base: string | undefined, ch: string, cp: number) => !!base && MARK.test(ch) && LATIN_LETTER.test(base) && coveredBy(LATIN, base.codePointAt(0)!) && coveredBy(LATIN, cp);

/** True when Helvetica can't draw some of `text` but a bundled font can. */
export function needsEmbedded(text: string): boolean {
  if (PLAIN.test(text)) return false;
  let base: string | undefined;
  for (const ch of text.normalize("NFC")) {
    const cp = ch.codePointAt(0)!;
    if (direct(ch, cp) === null && (attaches(ch, cp) ? latinAccent(base, ch, cp) : fontFor(cp) >= 0)) return true;
    if (!attaches(ch, cp)) base = ch;
  }
  return false;
}

export interface StdRun {
  kind: "std";
  codes: number[];
}

export interface FontRun {
  kind: "font";
  face: EmbeddedFace;
  /** Bold asked for, and the font has no bold: drawn from the regular with an outline. */
  fauxBold: boolean;
  /** In drawing order, left to right. */
  glyphs: ShapedGlyph[];
  /** Font units. */
  advance: number;
}

/** A line of text as drawn: runs in left-to-right order, Helvetica and the Noto fonts in turn. */
export interface Line {
  face: FontFace;
  /** The characters drawn, in reading order. */
  text: string;
  /** Some of it reads right to left, or its glyphs can't all be mapped back to their characters. */
  needsActualText: boolean;
  runs: Array<StdRun | FontRun>;
}

const lines = new Map<string, Line>();

export function layoutLine(text: string, face: FontFace): Line {
  const key = `${face}\u0000${text}`;
  let line = lines.get(key);
  if (!line) {
    line = buildLine(text, face);
    if (lines.size >= 20_000) lines.clear();
    lines.set(key, line);
  }
  return line;
}

export function lineWidth(line: Line, size: number, tracking = 0): number {
  let w = 0;
  for (const r of line.runs) w += r.kind === "std" ? widthOf(r.codes, line.face, size, tracking) : (r.advance / r.face.upem) * size;
  return w;
}

interface Char {
  ch: string;
  cp: number;
  /** The bundled font that draws it, or -1 for Helvetica. */
  font: number;
}

function buildLine(text: string, face: FontFace): Line {
  const chars: Char[] = [];
  // As encode() does, plus directional formatting characters: the line's own bidi order replaces them.
  const clean = text.normalize("NFC").replace(/[\u200b\u200e\u200f\u061c\u202a-\u202e\u2028\u2029\u2060\u2066-\u2069\ufeff]/g, "").replace(/[\t\r\n]+/g, " ");
  let base: string | undefined;
  for (const ch of clean) {
    const cp = ch.codePointAt(0)!;
    if (cp < 32 || (cp >= 0x7f && cp < 0xa0)) continue;
    const prev = chars[chars.length - 1];
    if (attaches(ch, cp)) {
      // A mark or joiner stays with the letter before it when that letter's font has it. An accent on a
      // Helvetica letter that has no precomposed form goes to Noto Sans, which takes the word below.
      if (prev && prev.font >= 0 && (isJoiner(cp) || coveredBy(prev.font, cp))) chars.push({ ch, cp, font: prev.font });
      else if (!isJoiner(cp)) chars.push({ ch, cp, font: latinAccent(base, ch, cp) ? LATIN : -1 });
      continue;
    }
    base = ch;
    chars.push({ ch, cp, font: direct(ch, cp) !== null ? -1 : fontFor(cp) });
  }
  // A Latin word with a letter or accent only Noto Sans has is drawn from Noto Sans whole, so its letters match.
  const inLatinWord = (c: Char) => LATIN_LETTER.test(c.ch) || (MARK.test(c.ch) && (c.font < 0 || c.font === LATIN));
  for (let i = 0; i < chars.length; ) {
    let j = i;
    while (j < chars.length && inLatinWord(chars[j]!)) j++;
    if (j > i && chars.slice(i, j).some((c) => c.font === LATIN)) for (const c of chars.slice(i, j)) if (coveredBy(LATIN, c.cp)) c.font = LATIN;
    i = Math.max(j, i + 1);
  }
  const levels = hasRtl(clean) ? resolveLevels(chars.map((c) => c.cp)) : null;
  const runs: Array<{ font: number; level: number; chars: Char[] }> = [];
  for (let i = 0; i < chars.length; ) {
    const level = levels ? levels[i]! : 0;
    let j = i + 1;
    while (j < chars.length && chars[j]!.font === chars[i]!.font && (levels ? levels[j]! : 0) === level) j++;
    runs.push({ font: chars[i]!.font, level, chars: chars.slice(i, j) });
    i = j;
  }
  const drawn = (levels ? visualOrder(runs) : runs).map((r): StdRun | FontRun => {
    const rtl = r.level % 2 === 1;
    if (r.font < 0) {
      const cs = rtl ? r.chars.slice().reverse() : r.chars;
      return { kind: "std", codes: cs.map((c) => (rtl && MIRROR[c.cp] ? code(String.fromCodePoint(MIRROR[c.cp]!)) : code(c.ch))) };
    }
    const { face: f, fauxBold } = embeddedFace(r.font, face);
    const glyphs = f.shape(r.chars.map((c) => c.ch).join(""), rtl);
    return { kind: "font", face: f, fauxBold, glyphs, advance: glyphs.reduce((a, g) => a + g.advance, 0) };
  });
  return {
    face,
    text: chars.map((c) => c.ch).join(""),
    needsActualText: !!levels?.some((l) => l > 0) || drawn.some((r) => r.kind === "font" && r.glyphs.some((g) => !g.exact)),
    runs: drawn,
  };
}

let graphemeSegmenter: Intl.Segmenter | null = null;
let wordSegmenter: Intl.Segmenter | null = null;

/** Where each user-perceived character ends: the only places text that needs the Noto fonts may be cut. */
function graphemeEnds(text: string): number[] {
  graphemeSegmenter ??= new Intl.Segmenter(undefined, { granularity: "grapheme" });
  return [...graphemeSegmenter.segment(text)].map((s) => s.index + s.segment.length);
}

/** The last word boundary at or before `n` (Thai, Chinese and Japanese words have no spaces between them), or 0. */
function wordBreakBefore(text: string, n: number): number {
  wordSegmenter ??= new Intl.Segmenter(undefined, { granularity: "word" });
  let best = 0;
  for (const s of wordSegmenter.segment(text)) if (s.index > 0 && s.index <= n) best = s.index;
  return best;
}

/** The longest start of `text` that fits `width`, ending in an ellipsis when cut. */
export function fit(text: string, face: FontFace, size: number, width: number): string {
  if (measure(text, face, size) <= width) return text;
  const ell = "\u2026";
  if (needsEmbedded(text)) {
    const ends = graphemeEnds(text);
    let keep = 0;
    let top = ends.length;
    while (keep < top) {
      const mid = Math.ceil((keep + top) / 2);
      if (measure(text.slice(0, ends[mid - 1]).trimEnd() + ell, face, size) <= width) keep = mid;
      else top = mid - 1;
    }
    return keep ? text.slice(0, ends[keep - 1]).trimEnd() + ell : ell;
  }
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (measure(text.slice(0, mid).trimEnd() + ell, face, size) <= width) lo = mid;
    else hi = mid - 1;
  }
  return lo ? text.slice(0, lo).trimEnd() + ell : ell;
}

/**
 * Wraps text to `width`, breaking long words (addresses, IDs) where they
 * must. With maxLines, the last line ends in an ellipsis when text is left.
 */
export function wrap(text: string, face: FontFace, size: number, width: number, maxLines = Infinity): string[] {
  // A no-break space (U+00A0) stays inside its word.
  const words = text.replace(/[^\S\u00a0]+/g, " ").trim().split(" ");
  const lines: string[] = [];
  let cur = "";
  const push = (line: string) => lines.push(line);
  for (let i = 0; i < words.length; i++) {
    let word = words[i]!;
    const candidate = cur ? `${cur} ${word}` : word;
    if (measure(candidate, face, size) <= width) {
      cur = candidate;
      continue;
    }
    if (cur) {
      push(cur);
      cur = "";
    }
    while (measure(word, face, size) > width) {
      let n = word.length;
      // Text for the Noto fonts breaks only between whole characters, never between a letter and its marks.
      const ends = needsEmbedded(word) ? graphemeEnds(word) : null;
      if (ends) {
        let k = ends.length - 1;
        while (k > 0 && measure(word.slice(0, ends[k]), face, size) > width) k--;
        n = ends[k]!;
      } else while (n > 1 && measure(word.slice(0, n), face, size) > width) n--;
      // Prefer to break after a separator when one falls late enough in the line: a path or
      // address separator first (C:\dir\, user@), then a lesser one (host.name, a-b).
      let separated = false;
      for (const tier of [["\\", "/", "@"], [".", ":", "-", "_"]]) {
        const sep = Math.max(...tier.map((c) => word.lastIndexOf(c, n - 1)));
        if (sep + 1 >= Math.ceil(n * 0.4) && sep + 1 <= n) {
          n = sep + 1;
          separated = true;
          break;
        }
      }
      // Then at a word boundary, for scripts that write words without spaces.
      if (ends && !separated) {
        const at = wordBreakBefore(word, n);
        if (at >= Math.ceil(n * 0.4)) n = at;
      }
      push(word.slice(0, n));
      word = word.slice(n);
    }
    cur = word;
  }
  if (cur || !lines.length) push(cur);
  if (lines.length > maxLines) {
    const kept = lines.slice(0, maxLines);
    kept[maxLines - 1] = fit(`${kept[maxLines - 1]} ${lines.slice(maxLines).join(" ")}`, face, size, width);
    return kept;
  }
  return lines;
}
