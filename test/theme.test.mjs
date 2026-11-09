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

// sRGB hex to OKLab and back, for color-mix(in oklab, ...).
const toLinear = (c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const fromLinear = (c) => (c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055);
function oklab(hex) {
  const [r, g, b] = [1, 3, 5].map((i) => toLinear(parseInt(hex.slice(i, i + 2), 16) / 255));
  const [l, m, s] = [
    0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b,
    0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b,
    0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b,
  ].map(Math.cbrt);
  return [0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s, 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s, 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s];
}
function hexFromOklab([L, a, b]) {
  const [l, m, s] = [L + 0.3963377774 * a + 0.2158037573 * b, L - 0.1055613458 * a - 0.0638541728 * b, L - 0.0894841775 * a - 1.291485548 * b].map((v) => v ** 3);
  const rgb = [4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s, -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s, -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s];
  return `#${rgb.map((v) => Math.round(Math.min(1, Math.max(0, fromLinear(v))) * 255).toString(16).padStart(2, "0")).join("")}`;
}
/** color-mix(in oklab, a p%, b q%), the percentages scaled to add up to 100. */
const mixOklab = (a, p, b, q = 100 - p) => hexFromOklab(oklab(a).map((v, i) => (v * p + oklab(b)[i] * q) / (p + q)));
/** An rgba() token painted over an opaque hex colour. */
function over(rgba, hex) {
  const [r, g, b, alpha] = rgba.match(/[\d.]+/g).map(Number);
  return `#${[r, g, b].map((v, i) => Math.round(v * alpha + parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) * (1 - alpha)).toString(16).padStart(2, "0")).join("")}`;
}

function themeTokens(name) {
  const tokens = css("tokens.css");
  const read = (text) => ({ ...vars(text), ...Object.fromEntries([...text.matchAll(/(--[\w-]+):\s*(rgba\([^)]*\))\s*;/g)].map((m) => [m[1], m[2]])) });
  const base = read(block(tokens, ":root"));
  return name === "light" ? { ...base, ...read(block(tokens, ':root[data-theme="light"]')) } : base;
}

/** Every surface small --ink-3 text sits on, flat and tinted, as the stylesheets build them. */
function inkSurfaces(t) {
  const views = css("views.css");
  const tint = (selector, token) => {
    const m = block(views, selector).match(new RegExp(`color-mix\\(in oklab, var\\(${token}\\) (\\d+)%, var\\(--panel\\)\\)`));
    assert.ok(m, `${selector} tints --panel with ${token}`);
    return mixOklab(t[token], Number(m[1]), t["--panel"]);
  };
  const panel = block(css("app.css"), ".panel").match(/color-mix\(in oklab, var\(--panel\) (\d+)%, white (\d+)%\)/);
  assert.ok(panel, ".panel lightens its top edge");
  assert.match(block(css("reports.css"), ".rp-card.on"), /background: var\(--accent-soft\)/);
  return {
    "--bg": t["--bg"],
    "--bg-2": t["--bg-2"],
    "--panel": t["--panel"],
    "--panel-2": t["--panel-2"],
    "--panel-3": t["--panel-3"],
    // the top of a panel, where table headers sit; drawn opaque, a touch lighter than it renders
    "panel top": mixOklab(t["--panel"], Number(panel[1]), "#ffffff", Number(panel[2])),
    "red S/MIME tile": tint(".kpi-bad.kpi-alert", "--bad"),
    "amber S/MIME tile": tint(".kpi.kpi-alert:not(.kpi-bad)", "--warn"),
    "selected report card": over(t["--accent-soft"], t["--panel-2"]),
  };
}

/** The surfaces where --ink-3 falls under 4.5:1, with the ratio. */
const below = (t) =>
  Object.entries(inkSurfaces(t))
    .map(([name, bg]) => [name, bg, contrast(t["--ink-3"], bg)])
    .filter(([, , ratio]) => ratio < 4.5)
    .map(([name, bg, ratio]) => `${name} ${bg} ${ratio.toFixed(2)}:1`);

test("dark mode --ink-3 text reads at 4.5:1 or better on every surface, tinted tiles and selected cards included", () => {
  const dark = themeTokens("dark");
  assert.deepEqual(below(dark), [], `--ink-3 ${dark["--ink-3"]}`);
  // still a step below --ink-2, so secondary text stays secondary
  assert.ok(contrast(dark["--ink-2"], dark["--ink-3"]) >= 1.25, "--ink-3 stays distinct from --ink-2");
});

test("light mode --ink-3 also clears 4.5:1 on the tinted tiles and selected cards", () => {
  const light = themeTokens("light");
  assert.deepEqual(below(light), [], `--ink-3 ${light["--ink-3"]}`);
});

test("the shared .num class turns tabular figures on", () => {
  const rule = block(css("app.css"), ".num");
  assert.match(rule, /font-variant-numeric:\s*tabular-nums/);
  assert.doesNotMatch(rule, /"tnum"\s*0/);
});
