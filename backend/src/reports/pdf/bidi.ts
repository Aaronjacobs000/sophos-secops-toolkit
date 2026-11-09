/**
 * The Unicode Bidirectional Algorithm (UAX #9), cut down to what one line of a
 * report needs: a left-to-right paragraph (the reports are in English) with no
 * explicit embeddings, so an Arabic or Hebrew name keeps its place in an English
 * line and reads right to left, with its numbers left to right. Rules W1 to W7,
 * N0 to N2, I1 to I2, L1 and L2 apply. Bidi classes come from Unicode
 * properties the JavaScript regex engine knows, with the Arabic, Hebrew and
 * Latin-1 exceptions listed by hand.
 */

export type BidiClass = "L" | "R" | "AL" | "EN" | "ES" | "ET" | "AN" | "CS" | "NSM" | "BN" | "B" | "S" | "WS" | "ON";

// prettier-ignore
const LATIN1 = (
  "BN BN BN BN BN BN BN BN BN S B S WS B BN BN BN BN BN BN BN BN BN BN BN BN BN BN B B B S " + // 00-1F
  "WS ON ON ET ET ET ON ON ON ON ON ES CS ES CS CS EN EN EN EN EN EN EN EN EN EN CS ON ON ON ON ON " + // 20-3F
  "ON L L L L L L L L L L L L L L L L L L L L L L L L L L ON ON ON ON ON " + // 40-5F
  "ON L L L L L L L L L L L L L L L L L L L L L L L L L L ON ON ON ON BN " + // 60-7F
  "BN BN BN BN BN B BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN BN " + // 80-9F
  "CS ON ET ET ET ET ON ON ON ON L ON ON BN ON ON ET ET EN EN ON L ON ON ON EN L ON ON ON ON ON " + // A0-BF
  "L L L L L L L L L L L L L L L L L L L L L L L ON L L L L L L L L " + // C0-DF
  "L L L L L L L L L L L L L L L L L L L L L L L ON L L L L L L L L" // E0-FF
).split(" ") as BidiClass[];

const RE = {
  mark: /^[\p{Mn}\p{Me}]$/u,
  format: /^\p{Cf}$/u,
  space: /^\p{Zs}$/u,
  currency: /^\p{Sc}$/u,
  ltr: /^[\p{L}\p{Mc}\p{Nd}\p{Nl}]$/u,
};

const AN = new Set([0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x066b, 0x066c, 0x06dd, 0x0890, 0x0891, 0x08e2]);
const ES = new Set([0x207a, 0x207b, 0x208a, 0x208b, 0x2212, 0xfb29, 0xfe62, 0xfe63, 0xff0b, 0xff0d]);
const CS = new Set([0x060c, 0x202f, 0x2044, 0xfe50, 0xfe52, 0xfe55, 0xff0c, 0xff0e, 0xff0f, 0xff1a]);
const ET = new Set([0x066a, 0x2030, 0x2031, 0x2032, 0x2033, 0x2034, 0x2052, 0x2213, 0xfe5f, 0xfe69, 0xfe6a, 0xff03, 0xff04, 0xff05, 0xffe0, 0xffe1, 0xffe5, 0xffe6]);

export function bidiClass(cp: number): BidiClass {
  if (cp < 0x100) return LATIN1[cp]!;
  if (cp === 0x200e) return "L"; // left-to-right mark
  if (cp === 0x200f) return "R"; // right-to-left mark
  if (cp === 0x061c) return "AL"; // Arabic letter mark
  const ch = String.fromCodePoint(cp);
  if (RE.mark.test(ch)) return "NSM";
  if (cp === 0x2028) return "WS";
  if (cp === 0x2029) return "B";
  if (RE.format.test(ch)) return AN.has(cp) ? "AN" : "BN";
  if ((cp >= 0x0660 && cp <= 0x0669) || AN.has(cp) || (cp >= 0x10e60 && cp <= 0x10e7e)) return "AN";
  if ((cp >= 0x06f0 && cp <= 0x06f9) || (cp >= 0xff10 && cp <= 0xff19) || (cp >= 0x2070 && cp <= 0x2079 && cp !== 0x2071) || (cp >= 0x2080 && cp <= 0x2089)) return "EN";
  if (ES.has(cp)) return "ES";
  if (CS.has(cp)) return "CS";
  if (ET.has(cp) || RE.currency.test(ch)) return "ET";
  if (RE.space.test(ch)) return "WS";
  // The right-to-left blocks, by range: their punctuation (U+061F, the tatweel) is Common script but still Arabic letter class.
  if ((cp >= 0x0590 && cp <= 0x05ff) || (cp >= 0x07c0 && cp <= 0x085f) || (cp >= 0xfb1d && cp <= 0xfb4f)) return "R";
  if ((cp >= 0x0600 && cp <= 0x07bf) || (cp >= 0x0860 && cp <= 0x08ff) || (cp >= 0xfb50 && cp <= 0xfdff && cp !== 0xfd3e && cp !== 0xfd3f) || (cp >= 0xfe70 && cp <= 0xfefe)) return "AL";
  if ((cp >= 0x10800 && cp <= 0x10fff) || (cp >= 0x1e800 && cp <= 0x1ec6f)) return "R";
  if (cp >= 0x1ec70 && cp <= 0x1efff) return "AL";
  return RE.ltr.test(ch) ? "L" : "ON";
}

/** True when the text holds a character that reads right to left (or an Arabic number). */
export function hasRtl(text: string): boolean {
  return /[֐-ࣿ‏יִ-﷿ﹰ-ﻼ\u{10800}-\u{10fff}\u{1e800}-\u{1efff}]/u.test(text);
}

/** Bidi_Paired_Bracket: opening bracket to its closing pair. */
const BRACKETS: Record<number, number> = {
  0x28: 0x29, 0x5b: 0x5d, 0x7b: 0x7d, 0x2045: 0x2046, 0x207d: 0x207e, 0x208d: 0x208e, 0x2308: 0x2309, 0x230a: 0x230b, 0x2329: 0x232a,
  0x3008: 0x3009, 0x300a: 0x300b, 0x300c: 0x300d, 0x300e: 0x300f, 0x3010: 0x3011, 0x3014: 0x3015, 0x3016: 0x3017, 0x3018: 0x3019, 0x301a: 0x301b,
  0xfe59: 0xfe5a, 0xfe5b: 0xfe5c, 0xfe5d: 0xfe5e, 0xff08: 0xff09, 0xff3b: 0xff3d, 0xff5b: 0xff5d, 0xff5f: 0xff60, 0xff62: 0xff63,
};
const CLOSERS = new Map(Object.entries(BRACKETS).map(([o, c]) => [c, Number(o)]));
/** U+2329 and U+3008 are canonically the same bracket, and so are their pairs. */
const canonical = (cp: number) => (cp === 0x2329 ? 0x3008 : cp === 0x232a ? 0x3009 : cp);

/** Bidi_Mirroring_Glyph for the characters Helvetica draws. */
export const MIRROR: Record<number, number> = { 0x28: 0x29, 0x29: 0x28, 0x3c: 0x3e, 0x3e: 0x3c, 0x5b: 0x5d, 0x5d: 0x5b, 0x7b: 0x7d, 0x7d: 0x7b, 0xab: 0xbb, 0xbb: 0xab, 0x2039: 0x203a, 0x203a: 0x2039 };

const strong = (t: BidiClass): "L" | "R" | null => (t === "L" ? "L" : t === "R" || t === "AL" || t === "EN" || t === "AN" ? "R" : null);
const NEUTRAL = new Set<BidiClass>(["B", "S", "WS", "ON"]);

/** The embedding level of each code point (0 left to right, 1 right to left, 2 a number inside right-to-left text). */
export function resolveLevels(cps: readonly number[]): number[] {
  const n = cps.length;
  const original = cps.map(bidiClass);
  // X9 removes boundary neutrals; here each takes the class of the character before it, as a mark does.
  const t = original.map((c) => (c === "BN" ? "NSM" : c));

  // W1: a mark takes the class of the character it follows (the start of the line counts as L).
  for (let i = 0; i < n; i++) if (t[i] === "NSM") t[i] = i ? t[i - 1]! : "L";
  // W2 and W3: a European number after Arabic letters is an Arabic number; Arabic letters are R.
  let last: BidiClass = "L";
  for (let i = 0; i < n; i++) {
    if (t[i] === "L" || t[i] === "R" || t[i] === "AL") last = t[i]!;
    else if (t[i] === "EN" && last === "AL") t[i] = "AN";
  }
  for (let i = 0; i < n; i++) if (t[i] === "AL") t[i] = "R";
  // W4: one separator between two numbers of the same kind joins them.
  for (let i = 1; i < n - 1; i++) {
    if (t[i] === "ES" && t[i - 1] === "EN" && t[i + 1] === "EN") t[i] = "EN";
    else if (t[i] === "CS" && t[i - 1] === t[i + 1] && (t[i - 1] === "EN" || t[i - 1] === "AN")) t[i] = t[i - 1]!;
  }
  // W5: terminators (currency, percent) next to a European number belong to it.
  for (let i = 0; i < n; i++) {
    if (t[i] !== "ET") continue;
    let j = i;
    while (j < n && t[j] === "ET") j++;
    if ((i > 0 && t[i - 1] === "EN") || (j < n && t[j] === "EN")) for (let k = i; k < j; k++) t[k] = "EN";
    i = j - 1;
  }
  // W6: what separators remain are neutral.
  for (let i = 0; i < n; i++) if (t[i] === "ES" || t[i] === "ET" || t[i] === "CS") t[i] = "ON";
  // W7: a European number after left-to-right text is left to right.
  last = "L";
  for (let i = 0; i < n; i++) {
    if (t[i] === "L" || t[i] === "R") last = t[i]!;
    else if (t[i] === "EN" && last === "L") t[i] = "L";
  }

  // N0: a bracket pair takes the direction of what it encloses (BD16 pairs them, at most 63 deep).
  const pairs: Array<[number, number]> = [];
  const stack: Array<[number, number]> = [];
  for (let i = 0; i < n; i++) {
    if (t[i] !== "ON") continue;
    const cp = canonical(cps[i]!);
    if (BRACKETS[cp] !== undefined) {
      if (stack.length === 63) break;
      stack.push([canonical(BRACKETS[cp]!), i]);
    } else if (CLOSERS.has(cp)) {
      for (let k = stack.length - 1; k >= 0; k--) {
        if (stack[k]![0] !== cp) continue;
        pairs.push([stack[k]![1], i]);
        stack.length = k;
        break;
      }
    }
  }
  pairs.sort((a, b) => a[0] - b[0]);
  for (const [open, close] of pairs) {
    let inside: "L" | "R" | null = null;
    for (let k = open + 1; k < close; k++) {
      const s = strong(t[k]!);
      if (s === "L") {
        inside = "L";
        break;
      }
      if (s === "R") inside = "R";
    }
    if (!inside) continue;
    let dir: "L" | "R" = "L";
    if (inside === "R") {
      let before: "L" | "R" = "L";
      for (let k = open - 1; k >= 0; k--) {
        const s = strong(t[k]!);
        if (s) {
          before = s;
          break;
        }
      }
      dir = before;
    }
    t[open] = dir;
    t[close] = dir;
    // Marks on a bracket follow it.
    for (const at of [open, close]) for (let k = at + 1; k < n && original[k] === "NSM"; k++) t[k] = dir;
  }

  // N1 and N2: a run of neutrals between two runs of the same direction takes it; otherwise the line's (L).
  for (let i = 0; i < n; i++) {
    if (!NEUTRAL.has(t[i]!)) continue;
    let j = i;
    while (j < n && NEUTRAL.has(t[j]!)) j++;
    const before = i ? strong(t[i - 1]!) ?? "L" : "L";
    const after = j < n ? strong(t[j]!) ?? "L" : "L";
    const dir = before === after ? before : "L";
    for (let k = i; k < j; k++) t[k] = dir;
    i = j - 1;
  }

  // I1, with L1: spaces at the end of the line go back to the line's level.
  const levels = t.map((c) => (c === "R" ? 1 : c === "AN" || c === "EN" ? 2 : 0));
  for (let i = n - 1; i >= 0 && (original[i] === "WS" || original[i] === "S" || original[i] === "BN" || original[i] === "B"); i--) levels[i] = 0;
  for (let i = 0; i < n; i++) if (original[i] === "S" || original[i] === "B") levels[i] = 0;
  return levels;
}

/**
 * L2: the visual order of runs, each run all at one level. From the highest
 * level down to the lowest odd one, every stretch at that level or above is
 * reversed. A run's own contents read backwards when its level is odd.
 */
export function visualOrder<T extends { level: number }>(runs: readonly T[]): T[] {
  const out = runs.slice();
  const max = Math.max(0, ...out.map((r) => r.level));
  for (let k = max; k >= 1; k--) {
    for (let i = 0; i < out.length; i++) {
      if (out[i]!.level < k) continue;
      let j = i;
      while (j < out.length && out[j]!.level >= k) j++;
      out.splice(i, j - i, ...out.slice(i, j).reverse());
      i = j;
    }
  }
  return out;
}
