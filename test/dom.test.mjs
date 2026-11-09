import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

// A style declaration in miniature. Like the browser's, it only holds a custom
// property written through setProperty: style["--i"] = 0 is a plain JS property.
class FakeStyle {
  #custom = new Map();
  setProperty(name, value) {
    this.#custom.set(name, String(value));
  }
  getPropertyValue(name) {
    return name.startsWith("--") ? (this.#custom.get(name) ?? "") : String(this[name] ?? "");
  }
}

class FakeElement {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.style = new FakeStyle();
    this.dataset = {};
    this.attrs = new Map();
    this.childList = [];
  }
  setAttribute(name, value) {
    this.attrs.set(name, value);
  }
  addEventListener() {}
  append(...nodes) {
    this.childList.push(...nodes);
  }
}

globalThis.Element ??= FakeElement;
globalThis.Node ??= FakeElement;
globalThis.document ??= { createElement: (tag) => new FakeElement(tag), createTextNode: (text) => ({ text }) };

const { h } = await import("../frontend/js/dom.js");

test("h() writes custom properties in a style object, beside the plain ones", () => {
  const el = h("div", { style: { left: "12%", top: "40%", "--i": 3, "--c": "var(--bad)" } });
  assert.equal(el.style.getPropertyValue("--i"), "3");
  assert.equal(el.style.getPropertyValue("--c"), "var(--bad)");
  assert.equal(el.style.left, "12%");
  assert.equal(el.style.top, "40%");
});

test("h() still takes a style string as it is", () => {
  const el = h("span", { style: "--s: 22px" });
  assert.equal(el.attrs.get("style"), "--s: 22px");
});

test("every custom property a view sets inline is read by a stylesheet or script", () => {
  const files = (dir, ext) =>
    readdirSync(new URL(dir, import.meta.url), { recursive: true })
      .filter((f) => f.endsWith(ext))
      .map((f) => readFileSync(new URL(`${dir}${f}`, import.meta.url), "utf8"));
  const scripts = files("../frontend/js/", ".js");
  const all = [...files("../frontend/css/", ".css"), ...scripts].join("\n");
  const set = new Set();
  for (const source of scripts) {
    // a style object key ({ "--i": 3 }) or a declaration in a style string ("--c: var(--bad)")
    for (const [, name] of source.matchAll(/[{,]\s*"(--[\w-]+)"\s*:/g)) set.add(name);
    for (const [, name] of source.matchAll(/[`"']\s*(--[\w-]+):/g)) set.add(name);
  }
  assert.ok(set.size >= 5, `found the inline custom properties: ${[...set]}`);
  const unread = [...set].filter((name) => !new RegExp(`var\\(\\s*${name}\\s*[,)]`).test(all));
  assert.deepEqual(unread, [], "set but never read");
});
