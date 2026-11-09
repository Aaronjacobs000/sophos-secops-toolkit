/**
 * Font subsetting with HarfBuzz's hb-subset, from the standalone
 * harfbuzz-subset.wasm that harfbuzzjs ships (no imports, no JS glue, so it
 * loads synchronously the first time a PDF embeds a font). Used when a PDF is
 * written, to embed only the glyphs it draws, and by scripts/build-pdf-fonts.mjs
 * to cut the bundled Noto fonts down to the scripts they serve.
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

interface SubsetExports {
  memory: WebAssembly.Memory;
  _initialize?: () => void;
  malloc(size: number): number;
  free(ptr: number): void;
  hb_blob_create(data: number, length: number, mode: number, userData: number, destroy: number): number;
  hb_blob_destroy(blob: number): void;
  hb_blob_get_length(blob: number): number;
  hb_blob_get_data(blob: number, length: number): number;
  hb_face_create(blob: number, index: number): number;
  hb_face_destroy(face: number): void;
  hb_face_reference_blob(face: number): number;
  hb_set_add(set: number, value: number): void;
  hb_set_clear(set: number): void;
  hb_subset_input_create_or_fail(): number;
  hb_subset_input_destroy(input: number): void;
  hb_subset_input_unicode_set(input: number): number;
  hb_subset_input_glyph_set(input: number): number;
  hb_subset_input_set(input: number, which: number): number;
  hb_subset_input_set_flags(input: number, flags: number): void;
  hb_subset_input_pin_axis_location(input: number, face: number, axis: number, value: number): number;
  hb_subset_or_fail(face: number, input: number): number;
}

/** hb_subset_flags_t */
export const SUBSET_FLAGS = { NO_HINTING: 0x1, RETAIN_GIDS: 0x2 } as const;
/** hb_subset_sets_t */
const SETS = { DROP_TABLE_TAG: 3, NAME_ID: 4, LAYOUT_FEATURE_TAG: 6 } as const;
const MEMORY_MODE_READONLY = 1;

let wasm: SubsetExports | null = null;

function hb(): SubsetExports {
  if (wasm) return wasm;
  const file = createRequire(import.meta.url).resolve("harfbuzzjs/dist/harfbuzz-subset.wasm");
  const instance = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(file)), {});
  const x = instance.exports as unknown as SubsetExports;
  x._initialize?.();
  wasm = x;
  return x;
}

const tag = (s: string): number => ((s.charCodeAt(0) << 24) | (s.charCodeAt(1) << 16) | (s.charCodeAt(2) << 8) | s.charCodeAt(3)) >>> 0;

/** A font loaded into the subsetter once and kept, so each PDF copies only its own glyphs out. */
export class SubsetFace {
  private readonly face: number;

  constructor(bytes: Uint8Array) {
    const x = hb();
    const ptr = x.malloc(bytes.length);
    if (!ptr) throw new Error("hb-subset: out of memory loading a font");
    new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
    // The blob reads the copy in place and the face lives as long as the process: never freed.
    this.face = x.hb_face_create(x.hb_blob_create(ptr, bytes.length, MEMORY_MODE_READONLY, 0, 0), 0);
  }

  subset(opts: SubsetOptions): Buffer {
    return run(this.face, opts);
  }
}

export interface SubsetOptions {
  unicodes?: Iterable<number>;
  glyphs?: Iterable<number>;
  flags?: number;
  /** Variable font axes to pin, such as { wght: 400 }. */
  pin?: Record<string, number>;
  dropTables?: string[];
  /** Name IDs kept besides the default 0 to 6. */
  nameIds?: number[];
  /** Keep no OpenType layout features (the default keeps the ones shaping uses). */
  noLayout?: boolean;
}

function run(face: number, opts: SubsetOptions): Buffer {
  const x = hb();
  const input = x.hb_subset_input_create_or_fail();
  if (!input) throw new Error("hb-subset: could not create the subset input");
  try {
    if (opts.unicodes) {
      const set = x.hb_subset_input_unicode_set(input);
      for (const u of opts.unicodes) x.hb_set_add(set, u);
    }
    if (opts.glyphs) {
      const set = x.hb_subset_input_glyph_set(input);
      for (const g of opts.glyphs) x.hb_set_add(set, g);
    }
    if (opts.dropTables?.length) {
      const set = x.hb_subset_input_set(input, SETS.DROP_TABLE_TAG);
      for (const t of opts.dropTables) x.hb_set_add(set, tag(t));
    }
    if (opts.nameIds?.length) {
      const set = x.hb_subset_input_set(input, SETS.NAME_ID);
      for (const id of opts.nameIds) x.hb_set_add(set, id);
    }
    if (opts.noLayout) x.hb_set_clear(x.hb_subset_input_set(input, SETS.LAYOUT_FEATURE_TAG));
    x.hb_subset_input_set_flags(input, opts.flags ?? 0);
    for (const [axis, value] of Object.entries(opts.pin ?? {})) {
      if (!x.hb_subset_input_pin_axis_location(input, face, tag(axis), value)) throw new Error(`hb-subset: the font has no ${axis} axis`);
    }
    const out = x.hb_subset_or_fail(face, input);
    if (!out) throw new Error("hb-subset: subsetting failed");
    const blob = x.hb_face_reference_blob(out);
    const length = x.hb_blob_get_length(blob);
    const data = x.hb_blob_get_data(blob, 0);
    // Copy out before anything else runs: the wasm memory can grow and move.
    const bytes = Buffer.from(new Uint8Array(x.memory.buffer, data, length));
    x.hb_blob_destroy(blob);
    x.hb_face_destroy(out);
    if (!length) throw new Error("hb-subset: empty result");
    return bytes;
  } finally {
    x.hb_subset_input_destroy(input);
  }
}

/** Subsets a font held only for this call (the build script's use). */
export function subsetOnce(bytes: Uint8Array, opts: SubsetOptions): Buffer {
  const x = hb();
  const ptr = x.malloc(bytes.length);
  if (!ptr) throw new Error("hb-subset: out of memory loading a font");
  new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
  const blob = x.hb_blob_create(ptr, bytes.length, MEMORY_MODE_READONLY, 0, 0);
  const face = x.hb_face_create(blob, 0);
  try {
    return run(face, opts);
  } finally {
    x.hb_face_destroy(face);
    x.hb_blob_destroy(blob);
    x.free(ptr);
  }
}
