// Reads back what the toolkit's PDF writer produces: objects through the xref
// table, fonts with their ToUnicode maps, and each page's text as a reader
// would copy it (ActualText where the writer gave one, else the ToUnicode or
// WinAnsi text of each string in drawing order).

import { inflateSync } from "node:zlib";

export function pdfObjects(buf) {
  const text = buf.toString("latin1");
  const startxref = Number(/startxref\n(\d+)/.exec(text)[1]);
  const rows = text.slice(startxref).split("\n").slice(3).filter((l) => / 00000 n $/.test(l));
  const objects = new Map();
  rows.forEach((row, i) => {
    const id = i + 1;
    const at = Number(row.slice(0, 10));
    const head = `${id} 0 obj\n`;
    if (text.slice(at, at + head.length) !== head) throw new Error(`object ${id} is not at its xref offset`);
    const start = at + head.length;
    const s = text.indexOf("\nstream\n", start);
    const e = text.indexOf("\nendobj", start);
    if (s >= 0 && s < e) {
      const dict = text.slice(start, s);
      const length = Number(/\/Length (\d+)/.exec(dict)[1]);
      const raw = buf.subarray(s + 8, s + 8 + length);
      objects.set(id, { dict, stream: /\/FlateDecode/.test(dict) ? inflateSync(raw) : raw });
    } else objects.set(id, { dict: text.slice(start, e), stream: null });
  });
  return objects;
}

const ref = (dict, key) => Number(new RegExp(`/${key} (\\d+) 0 R`).exec(dict)?.[1] ?? NaN);

function hexUtf16(hex) {
  const bytes = Buffer.from(hex, "hex");
  let out = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) out += String.fromCharCode(bytes.readUInt16BE(i));
  return out.replace(/^﻿/, "");
}

function toUnicode(cmap) {
  const map = new Map();
  for (const [, block] of cmap.matchAll(/beginbfchar\n([\s\S]*?)\nendbfchar/g)) {
    for (const [, gid, uni] of block.matchAll(/<([0-9A-F]{4})> <([0-9A-F]*)>/g)) map.set(parseInt(gid, 16), hexUtf16(uni));
  }
  return map;
}

/** Each font a page uses, by resource name: Helvetica or an embedded Type 0 font. */
export function pageFonts(objects, pageId) {
  const fonts = new Map();
  const res = /\/Font << (.*?) >>/.exec(objects.get(pageId).dict)[1];
  for (const [, key, id] of res.matchAll(/\/(F\d+) (\d+) 0 R/g)) {
    const font = objects.get(Number(id)).dict;
    const baseFont = /\/BaseFont \/(\S+)/.exec(font)[1];
    if (!/\/Type0/.test(font)) {
      fonts.set(key, { baseFont, type0: false });
      continue;
    }
    const cid = objects.get(Number(/\/DescendantFonts \[(\d+) 0 R\]/.exec(font)[1]));
    const descriptor = objects.get(ref(cid.dict, "FontDescriptor"));
    const program = objects.get(ref(descriptor.dict, "FontFile2"));
    fonts.set(key, {
      baseFont,
      type0: true,
      cid: cid.dict,
      descriptor: descriptor.dict,
      program: program.stream,
      programDict: program.dict,
      unicode: toUnicode(objects.get(ref(font, "ToUnicode")).stream.toString("latin1")),
    });
  }
  return fonts;
}

function literal(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") bytes.push(s.charCodeAt(i));
    else if (/[0-7]/.test(s[i + 1])) {
      bytes.push(parseInt(s.slice(i + 1, i + 4), 8));
      i += 3;
    } else bytes.push(s.charCodeAt(++i));
  }
  return new TextDecoder("windows-1252").decode(Uint8Array.from(bytes));
}

/** The pages: their ids, content and the text of each text object (or ActualText span), in drawing order. */
export function pdfPages(buf) {
  const objects = pdfObjects(buf);
  const kids = /\/Type \/Pages \/Kids \[([^\]]*)\]/.exec([...objects.values()].map((o) => o.dict).join("\n"))[1];
  return [...kids.matchAll(/(\d+) 0 R/g)].map(([, id]) => {
    const pageId = Number(id);
    const fonts = pageFonts(objects, pageId);
    const content = objects.get(ref(objects.get(pageId).dict, "Contents")).stream.toString("latin1");
    const texts = [];
    const tokens = /\/Span << \/ActualText <([0-9a-f]+)> >> BDC|EMC|BT|ET|\/(F\d+) [\d.]+ Tf|\((?:\\.|[^\\)])*\) Tj|\[[^\]]*\] TJ/g;
    let font = null;
    let actual = null;
    let cur = "";
    for (const [tok, at, key] of content.matchAll(tokens)) {
      if (at) actual = hexUtf16(at);
      else if (tok === "EMC") actual = null;
      else if (tok === "BT") cur = "";
      else if (tok === "ET") texts.push(actual ?? cur);
      else if (key) font = fonts.get(key);
      else if (tok.endsWith(" Tj")) cur += literal(tok.slice(1, -4));
      else for (const [, hex] of tok.matchAll(/<([0-9A-F]+)>/g)) for (let i = 0; i < hex.length; i += 4) cur += font.unicode.get(parseInt(hex.slice(i, i + 4), 16)) ?? "�";
    }
    return { id: pageId, fonts, content, texts };
  });
}
