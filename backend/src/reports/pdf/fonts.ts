/**
 * Text for the PDF writer: the two standard Helvetica faces every PDF reader
 * carries (nothing embedded, nothing downloaded), their glyph widths, and the
 * WinAnsi encoding they use. Characters outside WinAnsi fold to a plain
 * letter where one exists (c with a caron to c) and print as "?" otherwise; the CSV export
 * keeps every character.
 *
 * Widths are Adobe's Helvetica and Helvetica-Bold metrics in 1/1000 em for
 * WinAnsi codes 32 to 255.
 */

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

/** Letters with no WinAnsi form and no decomposition. */
const FOLD: Record<string, string> = { "\u0142": "l", "\u0141": "L", "\u0111": "d", "\u0110": "D", "\u0131": "i", "\u0127": "h", "\u0126": "H", "\u0140": "l", "\u013F": "L", "\u0167": "t", "\u0166": "T", "\u2212": "-", "\u2010": "-", "\u2011": "-", "\u00A0": " ", "\u2009": " ", "\u202F": " " };

function code(ch: string): number {
  const cp = ch.codePointAt(0)!;
  if ((cp >= 32 && cp <= 126) || (cp >= 0xa0 && cp <= 0xff)) return cp;
  const extra = WIN_ANSI_EXTRA[cp];
  if (extra !== undefined) return extra;
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
  return widthOf(encode(text), face, size, tracking);
}

/** The longest start of `text` that fits `width`, ending in an ellipsis when cut. */
export function fit(text: string, face: FontFace, size: number, width: number): string {
  if (measure(text, face, size) <= width) return text;
  const ell = "\u2026";
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
      while (n > 1 && measure(word.slice(0, n), face, size) > width) n--;
      // Prefer to break after a separator when one falls late enough in the line: a path or
      // address separator first (C:\dir\, user@), then a lesser one (host.name, a-b).
      for (const tier of [["\\", "/", "@"], [".", ":", "-", "_"]]) {
        const sep = Math.max(...tier.map((c) => word.lastIndexOf(c, n - 1)));
        if (sep + 1 >= Math.ceil(n * 0.4) && sep + 1 <= n) {
          n = sep + 1;
          break;
        }
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
