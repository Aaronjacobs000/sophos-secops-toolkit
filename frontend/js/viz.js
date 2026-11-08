// Hand-built SVG and HTML charts: sparkline, hourly area, horizontal bars and
// a stacked bar. Thin marks, hairline grid, values on labels, a hover layer,
// and animated enter and update. Text uses ink tokens, never series colours.

import { h, s, clear, setText } from "./dom.js";
import { reducedMotion } from "./anim.js";
import { num } from "./format.js";

// ------------------------------------------------------------------ tooltip

const tip = () => document.getElementById("tip");

export function showTip(evt, title, rows = []) {
  const el = tip();
  if (!el) return;
  clear(el);
  el.append(h("div", { class: "tip-title", text: title }));
  for (const r of rows) {
    el.append(
      h("div", { class: "tip-row" }, r.color ? h("i", { class: "tip-key", style: { background: r.color } }) : null, h("b", { text: r.value }), h("span", { text: r.label })),
    );
  }
  el.hidden = false;
  const pad = 14;
  const { innerWidth: W, innerHeight: H } = window;
  const rect = el.getBoundingClientRect();
  let x = evt.clientX + pad;
  let y = evt.clientY + pad;
  if (x + rect.width > W - 8) x = evt.clientX - rect.width - pad;
  if (y + rect.height > H - 8) y = evt.clientY - rect.height - pad;
  el.style.transform = `translate(${Math.max(8, x)}px, ${Math.max(8, y)}px)`;
}

export function hideTip() {
  const el = tip();
  if (el) el.hidden = true;
}

/** Hover and keyboard focus show the same tooltip. */
export function tipOn(el, getContent) {
  el.addEventListener("pointermove", (e) => {
    const [title, rows] = getContent(e);
    showTip(e, title, rows);
  });
  el.addEventListener("pointerleave", hideTip);
  el.addEventListener("focus", () => {
    const r = el.getBoundingClientRect();
    const [title, rows] = getContent({ clientX: r.left + r.width / 2, clientY: r.top });
    showTip({ clientX: r.left + r.width / 2, clientY: r.bottom }, title, rows);
  });
  el.addEventListener("blur", hideTip);
}

// ------------------------------------------------------------------ paths

function linePath(points) {
  if (!points.length) return "";
  let d = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 1; i < points.length; i++) {
    const [x0, y0] = points[i - 1];
    const [x1, y1] = points[i];
    const cx = (x0 + x1) / 2;
    d += ` C${cx.toFixed(1)},${y0.toFixed(1)} ${cx.toFixed(1)},${y1.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}

function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}

// ------------------------------------------------------------------ sparkline

export function sparkline(values, opts = {}) {
  const w = opts.width ?? 240;
  const hgt = opts.height ?? 44;
  const svg = s("svg", { class: "spark", viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", "aria-hidden": "true" });
  const area = s("path", { class: "spark-area" });
  const line = s("path", { class: "spark-line" });
  const dot = s("circle", { class: "spark-dot", r: 3.5 });
  svg.append(area, line, dot);
  svg._opts = { w, hgt };
  updateSparkline(svg, values, true);
  return svg;
}

export function updateSparkline(svg, values, first = false) {
  const { w, hgt } = svg._opts;
  const [area, line, dot] = svg.children;
  const vals = values?.length ? values : [0, 0];
  const max = Math.max(1, ...vals);
  const pad = 4;
  const pts = vals.map((v, i) => [pad + (i / Math.max(1, vals.length - 1)) * (w - pad * 2), hgt - pad - (v / max) * (hgt - pad * 2)]);
  const d = linePath(pts);
  const last = pts[pts.length - 1];
  line.setAttribute("d", d);
  area.setAttribute("d", `${d} L${last[0]},${hgt} L${pts[0][0]},${hgt} Z`);
  dot.setAttribute("cx", last[0]);
  dot.setAttribute("cy", last[1]);
  if (first && !reducedMotion() && line.getTotalLength) {
    requestAnimationFrame(() => {
      const len = line.getTotalLength();
      line.animate([{ strokeDasharray: `${len}`, strokeDashoffset: len }, { strokeDasharray: `${len}`, strokeDashoffset: 0 }], { duration: 1300, easing: "cubic-bezier(.45,.05,.2,1)" });
      area.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 1300, easing: "ease-out" });
      dot.animate([{ opacity: 0, transform: "scale(0)" }, { opacity: 1, transform: "scale(1)" }], { duration: 400, delay: 1100, fill: "backwards", easing: "cubic-bezier(.34,1.4,.5,1)" });
    });
  }
}

// ------------------------------------------------------------------ hourly area chart

/**
 * Hourly counts over the last N hours. `values` oldest first. Crosshair and
 * tooltip snap to the hour under the pointer.
 */
export function hourlyChart(container, values, opts = {}) {
  clear(container);
  const w = 640;
  const hgt = opts.height ?? 200;
  const padL = 8;
  const padR = 44;
  const padT = 14;
  const padB = 26;
  const svg = s("svg", { class: "hourly", viewBox: `0 0 ${w} ${hgt}`, preserveAspectRatio: "none", role: "img", "aria-label": opts.label ?? "Hourly counts" });
  const g = s("g", { class: "grid" });
  const area = s("path", { class: "hourly-area" });
  const line = s("path", { class: "hourly-line" });
  const dot = s("circle", { class: "hourly-dot", r: 5 });
  const cross = s("line", { class: "crosshair", y1: padT, y2: hgt - padB, x1: -10, x2: -10 });
  const labels = h("div", { class: "hourly-labels" });
  const ticks = h("div", { class: "hourly-ticks" });
  svg.append(g, area, line, cross, dot);
  const wrap = h("div", { class: "hourly-wrap" }, svg, labels, ticks);
  container.append(wrap);
  const state = { values: [], svg, area, line, dot, cross, g, labels, ticks, w, hgt, padL, padR, padT, padB, opts };
  container._hourly = state;
  updateHourly(container, values, true);
  const hit = (e) => {
    const r = svg.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width) * w;
    const n = state.values.length;
    const i = Math.max(0, Math.min(n - 1, Math.round(((x - padL) / (w - padL - padR)) * (n - 1))));
    const cx = padL + (i / Math.max(1, n - 1)) * (w - padL - padR);
    cross.setAttribute("x1", cx);
    cross.setAttribute("x2", cx);
    const hoursAgo = n - 1 - i;
    const title = hoursAgo === 0 ? "This hour" : `${hoursAgo} h ago`;
    showTip(e, title, [{ value: num(state.values[i]), label: opts.unit ?? "per hour", color: "var(--accent)" }]);
  };
  svg.addEventListener("pointermove", hit);
  svg.addEventListener("pointerleave", () => {
    cross.setAttribute("x1", -10);
    cross.setAttribute("x2", -10);
    hideTip();
  });
}

export function updateHourly(container, values, first = false) {
  const st = container._hourly;
  if (!st) return;
  const { w, hgt, padL, padR, padT, padB } = st;
  const vals = values?.length ? values : new Array(24).fill(0);
  st.values = vals;
  const max = niceMax(Math.max(...vals, 1));
  const x = (i) => padL + (i / Math.max(1, vals.length - 1)) * (w - padL - padR);
  const y = (v) => hgt - padB - (v / max) * (hgt - padT - padB);
  clear(st.g);
  clear(st.labels);
  for (const f of [0, 0.5, 1]) {
    const yy = y(max * f);
    st.g.append(s("line", { x1: padL, x2: w - padR, y1: yy, y2: yy }));
    st.labels.append(h("span", { style: { top: `${(yy / hgt) * 100}%` }, text: num(max * f) }));
  }
  clear(st.ticks);
  const n = vals.length;
  const now = new Date();
  for (const back of [n - 1, Math.round((n - 1) * 0.75), Math.round((n - 1) * 0.5), Math.round((n - 1) * 0.25), 0]) {
    const t = new Date(now.getTime() - back * 3_600_000);
    st.ticks.append(h("span", { style: { left: `${(x(n - 1 - back) / w) * 100}%` }, text: back === 0 ? "now" : `${String(t.getHours()).padStart(2, "0")}:00` }));
  }
  const pts = vals.map((v, i) => [x(i), y(v)]);
  const d = linePath(pts);
  const last = pts[pts.length - 1];
  const prevD = st.line.getAttribute("d");
  st.line.setAttribute("d", d);
  st.area.setAttribute("d", `${d} L${last[0]},${hgt - padB} L${pts[0][0]},${hgt - padB} Z`);
  st.dot.setAttribute("cx", last[0]);
  st.dot.setAttribute("cy", last[1]);
  if (reducedMotion()) return;
  if (first) {
    requestAnimationFrame(() => {
      const len = st.line.getTotalLength();
      st.line.animate([{ strokeDasharray: `${len}`, strokeDashoffset: len }, { strokeDasharray: `${len}`, strokeDashoffset: 0 }], { duration: 1500, easing: "cubic-bezier(.45,.05,.2,1)" });
      st.area.animate([{ opacity: 0, transform: "scaleY(0.6)" }, { opacity: 1, transform: "none" }], { duration: 1400, easing: "cubic-bezier(.2,.75,.15,1)" });
    });
  } else if (prevD && prevD !== d) {
    try {
      st.line.animate([{ d: `path("${prevD}")` }, { d: `path("${d}")` }], { duration: 700, easing: "cubic-bezier(.2,.75,.15,1)" });
    } catch {
      // Browsers without animatable path data just jump.
    }
    st.dot.animate([{ r: 5 }, { r: 9 }, { r: 5 }], { duration: 700 });
  }
}

// ------------------------------------------------------------------ horizontal bars

/**
 * rows: [{ key, label, value, note?, color? }]. Values at the bar tips; bars
 * grow from zero on first render and glide on update.
 */
export function hbars(container, rows, opts = {}) {
  const max = opts.max ?? Math.max(1, ...rows.map((r) => r.value));
  let list = container.querySelector(".hbars");
  const first = !list;
  if (!list) {
    list = h("div", { class: "hbars", role: "list" });
    container.append(list);
  }
  const existing = new Map([...list.children].map((c) => [c.dataset.key, c]));
  const seen = new Set();
  rows.forEach((r, i) => {
    const key = String(r.key ?? r.label);
    seen.add(key);
    let row = existing.get(key);
    if (!row) {
      row = h(
        "div",
        { class: "hbar", role: "listitem", tabindex: "0", dataset: { key } },
        h("span", { class: "hbar-label" }, r.icon ?? null, h("span", { class: "hbar-text" })),
        h("span", { class: "hbar-track" }, h("i", { class: "hbar-fill" })),
        h("span", { class: "hbar-value" }),
      );
      tipOn(row, () => [r.label, [{ value: num(row._value), label: opts.unit ?? "", color: r.color ?? "var(--accent)" }, ...(row._note ? [{ value: "", label: row._note }] : [])]]);
      list.append(row);
    }
    const text = row.querySelector(".hbar-text");
    clear(text);
    text.append(h("b", { text: r.label }), r.note ? h("small", { text: ` ${r.note}` }) : null);
    row._value = r.value;
    row._note = r.note;
    const fill = row.querySelector(".hbar-fill");
    fill.style.background = r.color ?? "var(--accent)";
    const pct = `${Math.max(r.value > 0 ? 1.5 : 0, (r.value / max) * 100)}%`;
    if (first && !reducedMotion()) {
      fill.style.width = "0%";
      requestAnimationFrame(() => requestAnimationFrame(() => {
        fill.style.transitionDelay = `${i * 50}ms`;
        fill.style.width = pct;
      }));
    } else {
      fill.style.transitionDelay = "0ms";
      fill.style.width = pct;
    }
    setText(row.querySelector(".hbar-value"), num(r.value));
    if (list.children[i] !== row) list.insertBefore(row, list.children[i] ?? null);
  });
  for (const [k, row] of existing) if (!seen.has(k)) row.remove();
}

// ------------------------------------------------------------------ stacked bar

/** segments: [{ key, label, value, color }]. 2px gaps between segments. */
export function stackBar(container, segments, opts = {}) {
  let bar = container.querySelector(".stack");
  const first = !bar;
  if (!bar) {
    bar = h("div", { class: "stack", role: "img" });
    container.append(bar);
  }
  const total = segments.reduce((a, s2) => a + s2.value, 0);
  bar.setAttribute("aria-label", segments.map((x) => `${x.label} ${x.value}`).join(", "));
  const existing = new Map([...bar.children].map((c) => [c.dataset.key, c]));
  segments.forEach((sg, i) => {
    let seg = existing.get(sg.key);
    if (!seg) {
      seg = h("i", { class: "stack-seg", dataset: { key: sg.key }, tabindex: "0" });
      tipOn(seg, () => [opts.title ?? "", [{ value: num(seg._v), label: sg.label, color: sg.color }]]);
      bar.append(seg);
    }
    seg._v = sg.value;
    seg.style.background = sg.color;
    const grow = total ? sg.value / total : 0;
    if (first && !reducedMotion()) {
      seg.style.flexGrow = "0";
      requestAnimationFrame(() => requestAnimationFrame(() => {
        seg.style.transitionDelay = `${i * 70}ms`;
        seg.style.flexGrow = String(grow);
      }));
    } else seg.style.flexGrow = String(grow);
    seg.style.display = sg.value > 0 ? "" : "none";
  });
  if (!total) bar.classList.add("empty");
  else bar.classList.remove("empty");
}
