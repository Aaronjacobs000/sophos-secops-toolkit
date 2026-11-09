import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import * as hb from "harfbuzzjs";
import { DEVICES, PEOPLE, SUBJECT, USER, withNonLatinNames } from "./helpers/non-latin.mjs";
import { pdfObjects, pdfPages } from "./helpers/pdf.mjs";

const root = mkdtempSync(path.join(tmpdir(), "secops-pdf-scripts-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { DemoProvider } = await import("../backend/dist/demo/demo-provider.js");
const { checkRequest, runReport } = await import("../backend/dist/reports/runner.js");
const { DemoReportSource } = await import("../backend/dist/reports/demo.js");
const { DEFAULT_SETTINGS } = await import("../backend/dist/store/settings.js");
const { renderPdf } = await import("../backend/dist/reports/pdf/render.js");
const { tableCsv, tableIds, findTable } = await import("../backend/dist/reports/csv.js");
const { measure, wrap, fit, layoutLine } = await import("../backend/dist/reports/pdf/fonts.js");
const { PdfPage, writePdf } = await import("../backend/dist/reports/pdf/writer.js");

async function demoRun(context, req) {
  const provider = new DemoProvider(context);
  try {
    return await runReport(checkRequest(provider, req), { source: new DemoReportSource(provider), settings: DEFAULT_SETTINGS });
  } finally {
    provider.stop();
  }
}

/** One line drawn on its own page, read back. */
function drawn(text, style = {}) {
  const page = new PdfPage(800, 100);
  page.text(10, 50, text, { size: 10, color: [0, 0, 0], ...style });
  return pdfPages(writePdf([page], { title: "t", createdAt: 0 }))[0];
}

const LATIN = "Kate Walsh, HL-LT-0007, Zoë Brontë, Łukasz, café";
const ALL = [...PEOPLE.map((p) => p.name), ...DEVICES, SUBJECT, USER.name];

test("a report with Chinese, Japanese, Korean, Thai, Cyrillic, Greek, Arabic and Hebrew names prints every name, never as ?", async () => {
  for (const req of [{ reportId: "detections", window: "7d" }, { reportId: "user", window: "7d", params: { user: "m.nguyen" } }]) {
    const doc = withNonLatinNames(await demoRun("tenant", { ...req, timeZone: "UTC" }));
    const pages = pdfPages(renderPdf(doc));
    const text = pages.flatMap((p) => p.texts).join("\n");
    const seen = ALL.filter((name) => text.includes(name));
    // The detections report names every person and device; the user report every person in its tables.
    for (const p of PEOPLE) assert.ok(text.includes(p.name), `${req.reportId}: ${p.script} name ${p.name} prints`);
    if (req.reportId === "detections") for (const d of DEVICES) assert.ok(text.includes(d), `${req.reportId}: device ${d} prints`);
    assert.ok(seen.length >= PEOPLE.length);
    assert.doesNotMatch(text, /\?|�/, `${req.reportId}: no question marks and nothing unreadable`);
    const fonts = new Set(pages.flatMap((p) => [...p.fonts.values()].map((f) => f.baseFont.replace(/^[A-Z]{6}\+/, ""))));
    for (const f of ["NotoSansSC-Regular", "NotoSansKR-Regular", "NotoSansThai-Regular", "NotoSans-Regular", "NotoSansArabic-Regular", "NotoSansHebrew-Regular"]) assert.ok(fonts.has(f), `${req.reportId} embeds ${f}`);
  }
});

test("each embedded font is a subset holding every glyph drawn, with the widths HarfBuzz gave", async () => {
  const doc = withNonLatinNames(await demoRun("tenant", { reportId: "detections", window: "7d", timeZone: "UTC" }));
  const buf = renderPdf(doc);
  assert.ok(buf.length < 150_000, `the PDF stays small (${buf.length} bytes)`);
  const pages = pdfPages(buf);
  // Each font is embedded once for the document, so it holds the glyphs every page draws from it.
  const drawnAnywhere = new Map();
  for (const page of pages) {
    for (const [, key, ops] of page.content.matchAll(/\/(F\d+) [\d.]+ Tf ([^/]*)/g)) {
      const set = drawnAnywhere.get(key) ?? new Set();
      for (const [, h] of ops.matchAll(/<([0-9A-F]+)>/g)) for (let i = 0; i < h.length; i += 4) set.add(parseInt(h.slice(i, i + 4), 16));
      drawnAnywhere.set(key, set);
    }
  }
  const embedded = new Set(pages.flatMap((p) => [...p.fonts.values()].filter((f) => f.type0).map((f) => f.baseFont)));
  assert.equal(embedded.size, 6, `one font per script family: ${[...embedded]}`);
  for (const page of pages) {
    for (const [key, f] of page.fonts) {
      if (!f.type0) continue;
      assert.match(f.baseFont, /^[A-Z]{6}\+Noto/, "a subset font is named as one");
      assert.match(f.cid, /\/CIDToGIDMap \/Identity/);
      assert.match(f.programDict, new RegExp(`/Length1 ${f.program.length}\\b`), "Length1 is the font program's size");
      const face = new hb.Face(new hb.Blob(f.program));
      const font = new hb.Font(face);
      const widths = new Map();
      for (const [, first, list] of f.cid.match(/\/W \[(.*)\] \/CIDToGIDMap/)[1].matchAll(/(\d+) \[([^\]]*)\]/g)) list.split(" ").forEach((w, i) => widths.set(Number(first) + i, Number(w)));
      const used = new Set();
      for (const [, hex] of page.content.matchAll(new RegExp(`/${key} [\\d.]+ Tf ([^/]*)`, "g"))) for (const [, h] of hex.matchAll(/<([0-9A-F]+)>/g)) for (let i = 0; i < h.length; i += 4) used.add(parseInt(h.slice(i, i + 4), 16));
      assert.ok(used.size, `${f.baseFont} is drawn on the page that lists it`);
      assert.ok(!used.has(0), `${f.baseFont} never draws the missing-glyph box`);
      for (const gid of used) {
        assert.ok(widths.has(gid), `${f.baseFont} glyph ${gid} has a width`);
        assert.equal(widths.get(gid), Math.round((font.glyphHAdvance(gid) * 100000) / face.upem) / 100, `${f.baseFont} glyph ${gid}'s width is its advance`);
        assert.ok(font.glyphToPath(gid).length > 0, `${f.baseFont} glyph ${gid} is in the font program`);
      }
      // Glyphs no page draws are left out (their numbers are kept, empty): the CJK font of 22,000 characters embeds a few
      // dozen. Others keep only the parts that accented letters are built from (й is и and a breve).
      const count = Buffer.from(face.referenceTable("maxp")).readUInt16BE(4);
      const extra = [];
      for (let g = 1; g < count; g++) if (!drawnAnywhere.get(key)?.has(g) && font.glyphToPath(g).length > 0) extra.push(g);
      if (/NotoSans(SC|KR)/.test(f.baseFont)) assert.deepEqual(extra, [], `${f.baseFont} holds no glyph the document doesn't draw`);
      else assert.ok(extra.length <= drawnAnywhere.get(key).size, `${f.baseFont} holds ${extra.length} glyphs beyond the ${drawnAnywhere.get(key).size} drawn`);
    }
  }
});

test("a Latin-only report embeds nothing and draws every string in Helvetica, as before", async () => {
  const doc = await demoRun("tenant", { reportId: "detections", window: "7d", timeZone: "UTC" });
  const buf = renderPdf(doc);
  assert.doesNotMatch(buf.toString("latin1"), /FontFile2|Type0|ActualText/);
  const objects = pdfObjects(buf);
  assert.deepEqual([...objects.values()].filter((o) => /\/Type \/Font\b/.test(o.dict)).map((o) => /\/BaseFont \/(\S+)/.exec(o.dict)[1]), ["Helvetica", "Helvetica-Bold"]);
  assert.match(drawn(LATIN).content, /^BT \/F1 10 Tf 0 0 0 rg 10 50 Td \(Kate Walsh, HL-LT-0007, Zo\\353 Bront\\353, Lukasz, caf\\351\) Tj ET$/);
});

test("Arabic letters join, Thai and Hebrew marks sit on their letters, and CJK is a full em wide", () => {
  const arabic = layoutLine("فاطمة", "regular").runs;
  assert.equal(arabic.length, 1);
  const glyphs = arabic[0].glyphs;
  // Joined, each letter takes its initial, medial or final form: not the glyph it has on its own.
  assert.ok(glyphs.filter((g) => g.advance > 0).some((g) => ![..."فاطمة"].some((ch) => arabic[0].face.nominal(ch.codePointAt(0)) === g.gid)), "joining forms are used");
  const thai = layoutLine("ที่", "regular").runs[0].glyphs;
  assert.equal(thai.length, 3);
  assert.deepEqual(thai.map((g) => g.advance > 0), [true, false, false], "the vowel and tone mark take no room of their own");
  const hebrew = layoutLine("שָׁלוֹם", "regular").runs[0].glyphs;
  assert.ok(hebrew.some((g) => g.advance === 0), "points sit on their letters");
  assert.equal(measure("王芳", "regular", 10), 20);
  assert.ok(Math.abs(measure("김민준", "regular", 10) - 27.6) < 1e-9, "Hangul is 0.92 em");
  assert.ok(measure("Дмитрий", "bold", 10) > measure("Дмитрий", "regular", 10), "Cyrillic has a real bold");
});

test("right-to-left names read right to left inside an English line, with numbers and brackets in place", () => {
  /** The characters a line draws, left to right, from its ActualText-free runs. */
  const visual = (text) =>
    layoutLine(text, "regular")
      .runs.map((r) => (r.kind === "std" ? String.fromCharCode(...r.codes) : r.glyphs.filter((g) => g.text).map((g) => g.text).join("")))
      .join("");
  assert.equal(visual("דוד כהן"), "ןהכ דוד");
  assert.equal(visual("Owner: דוד כהן 2024"), "Owner: 2024 ןהכ דוד");
  assert.equal(visual("then דוד כהן (מנהל) called"), "then (להנמ) ןהכ דוד called");
  assert.equal(visual("חיפה-LT-08"), "הפיח-LT-08");
  assert.equal(visual("abc"), "abc");
  // Copying the line gives the characters in reading order.
  const line = drawn("User investigation: فاطمة الزهراء (f.alzahra@harbourline.example)");
  assert.deepEqual(line.texts, ["User investigation: فاطمة الزهراء (f.alzahra@harbourline.example)"]);
  assert.match(line.content, /^\/Span << \/ActualText <feff[0-9a-f]+> >> BDC BT /);
  // A left-to-right line maps back through ToUnicode alone.
  assert.doesNotMatch(drawn("王芳 Дмитрий Γιώργος 김민준").content, /ActualText/);
  assert.deepEqual(drawn("王芳 Дмитрий Γιώργος 김민준").texts, ["王芳 Дмитрий Γιώργος 김민준"]);
});

test("Thai and CJK wrap between whole characters, at word boundaries, and a cut keeps marks with their letters", () => {
  const thai = "สมชายใจดีมากมายหลายอย่างที่นี่กรุงเทพมหานคร";
  const lines = wrap(thai, "regular", 10, 60);
  assert.ok(lines.length > 2);
  assert.equal(lines.join(""), thai, "nothing is lost");
  for (const l of lines) {
    assert.doesNotMatch(l, /^\p{M}/u, `no line starts with a mark: ${l}`);
    assert.ok(measure(l, "regular", 10) <= 60, `each line fits: ${l}`);
  }
  assert.deepEqual(wrap("中华人民共和国国务院总理李强", "regular", 10, 60), ["中华人民", "共和国国务院", "总理李强"]);
  const cut = fit("ที่นี่ที่นี่ที่นี่ที่นี่", "regular", 10, 30);
  assert.ok(cut.endsWith("…") && measure(cut, "regular", 10) <= 30, cut);
  const kept = [...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(cut.slice(0, -1))].map((x) => x.segment);
  assert.ok(kept.length > 0 && kept.every((g) => g === "ที่" || g === "นี่"), `every letter keeps both its marks: ${kept}`);
});

test("bold text in a font with no bold is outlined; Greek, Cyrillic, Arabic, Hebrew and Thai have a bold of their own", () => {
  const cjk = drawn("王芳", { face: "bold" });
  assert.match(cjk.content, /^q BT .* 2 Tr [\d.]+ w 0 0 0 RG \/F\d+ 10 Tf .* 0 Tr ET Q$/);
  assert.equal([...cjk.fonts.values()].find((f) => f.type0).baseFont.replace(/^[A-Z]{6}\+/, ""), "NotoSansSC-Regular");
  for (const [text, font] of [["Дмитрий", "NotoSans-Bold"], ["Γιώργος", "NotoSans-Bold"], ["فاطمة", "NotoSansArabic-Bold"], ["דוד", "NotoSansHebrew-Bold"], ["สมชาย", "NotoSansThai-Bold"]]) {
    const page = drawn(text, { face: "bold" });
    assert.doesNotMatch(page.content, /Tr/, `${font} is not outlined`);
    assert.equal([...page.fonts.values()].find((f) => f.type0).baseFont.replace(/^[A-Z]{6}\+/, ""), font);
  }
});

test("the CSV export keeps every name as UTF-8 with a byte order mark", async () => {
  const doc = withNonLatinNames(await demoRun("tenant", { reportId: "detections", window: "7d", timeZone: "UTC" }));
  const csv = tableIds(doc).map((id) => tableCsv(findTable(doc, id), doc.timeZone)).join("");
  const bytes = Buffer.from(csv, "utf8");
  assert.deepEqual([...bytes.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  for (const name of [...PEOPLE.map((p) => p.name), ...DEVICES]) assert.ok(csv.includes(name), name);
  assert.equal(bytes.toString("utf8"), csv, "round trips");
});
