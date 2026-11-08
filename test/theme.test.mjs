import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = (name) => readFileSync(new URL(`../frontend/css/${name}`, import.meta.url), "utf8");

function block(source, selector) {
  const start = source.indexOf(`${selector} {`);
  assert.notEqual(start, -1, selector);
  return source.slice(start, source.indexOf("}", start));
}

function vars(text) {
  return Object.fromEntries([...text.matchAll(/(--[\w-]+):\s*(#[0-9a-f]{6})\s*;/gi)].map((m) => [m[1], m[2]]));
}

// WCAG 2 relative luminance and contrast ratio.
function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
const contrast = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

test("light mode --ink-3 text reads at 4.5:1 or better on every background", () => {
  const tokens = css("tokens.css");
  const light = { ...vars(block(tokens, ":root")), ...vars(block(tokens, ':root[data-theme="light"]')) };
  for (const bg of ["--bg", "--bg-2", "--panel", "--panel-2", "--panel-3"]) {
    const ratio = contrast(light["--ink-3"], light[bg]);
    assert.ok(ratio >= 4.5, `--ink-3 ${light["--ink-3"]} on ${bg} ${light[bg]} is ${ratio.toFixed(2)}:1`);
  }
});

test("the shared .num class turns tabular figures on", () => {
  const rule = block(css("app.css"), ".num");
  assert.match(rule, /font-variant-numeric:\s*tabular-nums/);
  assert.doesNotMatch(rule, /"tnum"\s*0/);
});
