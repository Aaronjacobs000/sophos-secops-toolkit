#!/usr/bin/env node
// Builds the fonts PDF reports use for text Helvetica can't draw: Latin
// letters beyond Western European, Greek and Cyrillic, Arabic, Hebrew, Thai,
// Korean Hangul, and Chinese and Japanese (CJK ideographs, kana and full-width
// forms). Each is a Noto font (SIL Open Font License 1.1) from the
// google/fonts repository at a pinned commit, checked against its SHA-256,
// pinned to a static weight and cut down to the scripts it serves with
// HarfBuzz's subsetter, then Brotli-compressed.
//
//   npm run build
//   node scripts/build-pdf-fonts.mjs [--src <folder of downloaded sources>]
//
// Writes backend/fonts/*.ttf.br, the licences, and fonts.json (the coverage
// and checksums the PDF writer reads). The same inputs give the same files.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { brotliCompressSync, brotliDecompressSync, constants } from "node:zlib";
import * as hb from "harfbuzzjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "backend", "fonts");
const COMMIT = "5bb28733cec313b63fbd415b574b5ae35c8aa8b8"; // google/fonts main, 08/11/2026
const RAW = `https://raw.githubusercontent.com/google/fonts/${COMMIT}/`;

const { values } = parseArgs({ options: { src: { type: "string", default: path.join(tmpdir(), "secops-pdf-font-sources") } } });
const { subsetOnce, SUBSET_FLAGS } = await import(new URL("../backend/dist/reports/pdf/hb-subset.js", import.meta.url));

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const span = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
const DOTTED_CIRCLE = [0x25cc]; // HarfBuzz draws it under a mark with no letter to sit on

/** Tables a PDF never reads; the CJK fonts also drop layout, which they need only for vertical text and regional forms. */
const DROP = ["STAT", "gasp", "DSIG", "meta"];
const DROP_LAYOUT = [...DROP, "GSUB", "GPOS", "GDEF", "BASE", "JSTF", "vhea", "vmtx", "VORG"];

const LICENCES = {
  "OFL-NotoSans.txt": ["ofl/notosans/OFL.txt", "cee9892f9f0cc8fe882c9e9537ee6a89621d86ee7ceaf70b02e2b2b1c25c061a"],
  "OFL-NotoSansArabic.txt": ["ofl/notosansarabic/OFL.txt", "07fc70bfeb985cc1a87a8587d0a0c80bab11c86c9dc3fd95b6f0cb332f983e96"],
  "OFL-NotoSansHebrew.txt": ["ofl/notosanshebrew/OFL.txt", "9b9fe028b5ba74d231659a1bbaf0ed09b11e759d1ca6a070999e16d151616b47"],
  "OFL-NotoSansThai.txt": ["ofl/notosansthai/OFL.txt", "2e98fd23a52d253db8612cd5942c8f2ff4111b21d2367050fdca91d8ccc374a0"],
  // Noto Sans SC and KR carry the same licence file (Adobe's, as Source Han Sans).
  "OFL-NotoSansCJK.txt": ["ofl/notosanssc/OFL.txt", "1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9"],
};

/** In the order the PDF writer tries them. */
const FONTS = [
  {
    id: "latin-greek-cyrillic",
    name: "NotoSans",
    source: ["ofl/notosans/NotoSans[wdth,wght].ttf", "bfb7bb691513f12e734dc346c03a03f784912432d7e3fa8e56efcf906fe86b3d"],
    licence: "OFL-NotoSans.txt",
    axes: { wdth: 100 },
    weights: { regular: 400, bold: 700 },
    // Latin: a word with a letter Helvetica lacks (č, ł, ő, Vietnamese) is drawn whole from this font, so it needs the plain
    // letters too. Combining accents ride on its Latin, Greek and Cyrillic letters.
    unicodes: [...span(0x0020, 0x007e), ...span(0x00a0, 0x02ff), ...span(0x1e00, 0x1eff), ...span(0x2c60, 0x2c7f), ...span(0xa720, 0xa7ff), ...span(0xab30, 0xab6f),
      ...span(0x0300, 0x036f), ...span(0x0370, 0x03ff), ...span(0x0400, 0x052f), ...span(0x1c80, 0x1c8f), ...span(0x1f00, 0x1fff), ...span(0x2de0, 0x2dff), ...span(0xa640, 0xa69f), 0xfe2e, 0xfe2f, ...DOTTED_CIRCLE],
  },
  {
    id: "arabic",
    name: "NotoSansArabic",
    source: ["ofl/notosansarabic/NotoSansArabic[wdth,wght].ttf", "63111b5b2e074dd48cc67692e0a2726d86ee94c1c37fe8598257b7b4e87e869e"],
    licence: "OFL-NotoSansArabic.txt",
    axes: { wdth: 100 },
    weights: { regular: 400, bold: 700 },
    unicodes: [...span(0x0600, 0x06ff), ...span(0x0750, 0x077f), ...span(0x0870, 0x089f), ...span(0x08a0, 0x08ff), ...span(0xfb50, 0xfdff), ...span(0xfe70, 0xfefc), ...DOTTED_CIRCLE],
  },
  {
    id: "hebrew",
    name: "NotoSansHebrew",
    source: ["ofl/notosanshebrew/NotoSansHebrew[wdth,wght].ttf", "7ef36a2c3593758cdb622e1bdef4f84523e92fbc3ccc667438dd80ff54c2de88"],
    licence: "OFL-NotoSansHebrew.txt",
    axes: { wdth: 100 },
    weights: { regular: 400, bold: 700 },
    unicodes: [...span(0x0590, 0x05ff), ...span(0xfb1d, 0xfb4f), ...DOTTED_CIRCLE],
  },
  {
    id: "thai",
    name: "NotoSansThai",
    source: ["ofl/notosansthai/NotoSansThai[wdth,wght].ttf", "5a1c559bb539583c8a1fd99d1c5b9491e5e14478c9cd2bd0970d5c3096cc9ef8"],
    licence: "OFL-NotoSansThai.txt",
    axes: { wdth: 100 },
    weights: { regular: 400, bold: 700 },
    unicodes: [...span(0x0e00, 0x0e7f), ...DOTTED_CIRCLE],
  },
  {
    // Hangul only; the Han characters Korean names use come from the SC font.
    id: "korean",
    name: "NotoSansKR",
    source: ["ofl/notosanskr/NotoSansKR[wght].ttf", "194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252"],
    licence: "OFL-NotoSansCJK.txt",
    axes: {},
    weights: { regular: 400 },
    noLayout: true,
    unicodes: [...span(0x1100, 0x11ff), ...span(0x3131, 0x318e), ...span(0xa960, 0xa97f), ...span(0xac00, 0xd7a3), ...span(0xd7b0, 0xd7ff), ...span(0xffa0, 0xffdc)],
  },
  {
    // Every character in the CJK Unified Ideographs block, so one font serves Chinese, Japanese kanji and Korean hanja (in the
    // Simplified Chinese forms), plus kana, bopomofo, CJK punctuation and full-width forms.
    id: "cjk",
    name: "NotoSansSC",
    source: ["ofl/notosanssc/NotoSansSC[wght].ttf", "a3041811a78c361b1de50f953c805e0244951c21c5bd412f7232ef0d899af0da"],
    licence: "OFL-NotoSansCJK.txt",
    axes: {},
    weights: { regular: 400 },
    noLayout: true,
    unicodes: [...span(0x3000, 0x303f), ...span(0x3040, 0x30ff), ...span(0x3100, 0x312f), ...span(0x31a0, 0x31bf), ...span(0x31f0, 0x31ff), ...span(0x3200, 0x33ff), ...span(0x4e00, 0x9fff), ...span(0xfa0e, 0xfa29), ...span(0xff00, 0xffef)],
  },
];

async function source(rel, expected) {
  const file = path.join(values.src, rel.replace(/[\\/[\],]/g, "_"));
  let bytes = existsSync(file) ? readFileSync(file) : null;
  if (!bytes || sha256(bytes) !== expected) {
    const res = await fetch(RAW + rel.replace(/\[/g, "%5B").replace(/\]/g, "%5D").replace(/,/g, "%2C"), { redirect: "error" });
    if (!res.ok) throw new Error(`${rel}: HTTP ${res.status}`);
    bytes = Buffer.from(await res.arrayBuffer());
    mkdirSync(values.src, { recursive: true });
    writeFileSync(file, bytes);
  }
  const got = sha256(bytes);
  if (got !== expected) throw new Error(`${rel}: SHA-256 ${got}, expected ${expected}`);
  return bytes;
}

/** The code points a font maps, as [first, last] ranges. */
function coverage(bytes) {
  const cps = [...new hb.Face(new hb.Blob(bytes)).collectUnicodes()].sort((a, b) => a - b);
  const ranges = [];
  for (const cp of cps) {
    const last = ranges[ranges.length - 1];
    if (last && cp === last[1] + 1) last[1] = cp;
    else ranges.push([cp, cp]);
  }
  return { ranges, count: cps.length };
}

mkdirSync(OUT, { recursive: true });
for (const [name, [rel, hash]] of Object.entries(LICENCES)) writeFileSync(path.join(OUT, name), await source(rel, hash));

const manifest = { source: `https://github.com/google/fonts/tree/${COMMIT}`, fonts: [] };
let total = 0;
for (const f of FONTS) {
  const src = await source(f.source[0], f.source[1]);
  const entry = { id: f.id, name: f.name, licence: f.licence, source: f.source[0], sourceSha256: f.source[1], files: {}, sha256: {}, ranges: [] };
  for (const [weight, wght] of Object.entries(f.weights)) {
    const t = Date.now();
    const ttf = subsetOnce(src, {
      unicodes: f.unicodes,
      flags: SUBSET_FLAGS.NO_HINTING,
      pin: { ...f.axes, wght },
      dropTables: f.noLayout ? DROP_LAYOUT : DROP,
      noLayout: !!f.noLayout,
      nameIds: [13, 14], // the licence and its URL, besides the copyright and names
    });
    const br = brotliCompressSync(ttf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_LGWIN]: 24, [constants.BROTLI_PARAM_SIZE_HINT]: ttf.length } });
    if (!brotliDecompressSync(br).equals(ttf)) throw new Error(`${f.id} ${weight}: Brotli round trip failed`);
    const file = `noto-${f.id}-${weight}.ttf.br`;
    writeFileSync(path.join(OUT, file), br);
    const cov = coverage(ttf);
    if (weight === "regular") entry.ranges = cov.ranges;
    else if (JSON.stringify(cov.ranges) !== JSON.stringify(entry.ranges)) throw new Error(`${f.id}: the bold font covers different characters`);
    entry.files[weight] = file;
    entry.sha256[weight] = sha256(ttf);
    total += br.length;
    console.log(`${file.padEnd(36)} ${String(cov.count).padStart(6)} characters ${(ttf.length / 1024).toFixed(0).padStart(6)} KB, ${(br.length / 1024).toFixed(0).padStart(5)} KB compressed (${Date.now() - t} ms)`);
  }
  manifest.fonts.push(entry);
}
writeFileSync(path.join(OUT, "fonts.json"), `${JSON.stringify(manifest, null, 1).replace(/\[\s+(\d+),\s+(\d+)\s+\]/g, "[$1, $2]")}\n`);
console.log(`${(total / 1024 / 1024).toFixed(2)} MB of fonts in ${path.relative(ROOT, OUT)}`);
