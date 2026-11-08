// Small DOM helpers. Text always goes in through textContent, never innerHTML,
// because tenant names, hostnames and case titles come from the API.

// Views build children with `cond ? node : null`. The native append would
// print "null"; this app-wide wrapper drops empty children instead.
const nativeAppend = Element.prototype.append;
Element.prototype.append = function appendSkippingEmpty(...nodes) {
  return nativeAppend.apply(
    this,
    nodes.filter((n) => n !== null && n !== undefined && n !== false),
  );
};

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style" && typeof v === "object") setStyle(el, v);
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  return el;
}

// Custom properties (`--i`) only land through setProperty: assigning
// el.style["--i"] makes a plain JS property the browser never reads.
function setStyle(el, styles) {
  for (const [name, value] of Object.entries(styles)) {
    if (name.startsWith("--")) el.style.setProperty(name, String(value));
    else el.style[name] = value;
  }
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";

export function s(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.firstChild.remove();
  return el;
}

export function setText(el, text) {
  if (el && el.textContent !== String(text)) el.textContent = String(text);
}

/** Parses a small static SVG string that the toolkit itself wrote (icons). */
export function svgFromString(markup) {
  const doc = new DOMParser().parseFromString(markup, "image/svg+xml");
  return document.importNode(doc.documentElement, true);
}

export function qs(sel, root = document) {
  return root.querySelector(sel);
}

export function qsa(sel, root = document) {
  return [...root.querySelectorAll(sel)];
}
