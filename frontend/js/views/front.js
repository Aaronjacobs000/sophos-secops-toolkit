// Overview: where the signals come from, how they become cases, who works
// them and how they end. Ribbons are sized by volume (a Sankey on each side of
// the triage lens), particles run along them, and every number counts.

import { h, s, clear, setText } from "../dom.js";
import { icon, sourceIcon, SEV_ICON } from "../icons.js";
import { tweenNumber, reducedMotion, pulse } from "../anim.js";
import { num, duration, greeting, plural, SEV_LABEL, ago, date } from "../format.js";
import { sparkline, updateSparkline, stackBar, tipOn } from "../viz.js";
import { store } from "../api.js";
import { freshChip } from "./common.js";

const W = 1600;
const H = 600;
const CY = 300;
const LEFT_X = 330;
const CONVERGE_X = 690;
const CORE_X = 860;
const CORE_R = 118;
const EXIT_X = 1000;
const COL1_X = 1170;
const COL2_X = 1400;
const BAR_W = 10;
const SEVS = ["critical", "high", "medium", "low", "info"];

function css(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function ribbon(x0, t0, b0, x1, t1, b1) {
  const mx = (x0 + x1) / 2;
  return `M${x0},${t0} C${mx},${t0} ${mx},${t1} ${x1},${t1} L${x1},${b1} C${mx},${b1} ${mx},${b0} ${x0},${b0} Z`;
}

function centreline(x0, y0, x1, y1, n = 60) {
  const pts = [];
  const mx = (x0 + x1) / 2;
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    const x = u * u * u * x0 + 3 * u * u * t * mx + 3 * u * t * t * mx + t * t * t * x1;
    const y = u * u * u * y0 + 3 * u * u * t * y0 + 3 * u * t * t * y1 + t * t * t * y1;
    pts.push([x, y]);
  }
  return pts;
}

function bandHeight(total, max, logBase) {
  if (!total) return 3;
  return Math.max(10, Math.min(max, 18 + (max - 18) * Math.min(1, Math.log10(total + 1) / logBase)));
}

/** Lays the flow model out in viewBox units. Pure, so a resize just re-runs it. */
function layout(model) {
  const sources = [...model.flow.sources];
  if (model.flow.moreSources) sources.push({ key: "more", label: `${num(model.flow.moreSources.count)} more`, count: model.flow.moreSources.total, kind: "more" });
  const total = sources.reduce((a, x) => a + x.count, 0);
  const leftBand = bandHeight(total, 170, 4);
  const n = Math.max(1, sources.length);
  const top = n > 1 ? 70 : CY;
  const bottom = n > 1 ? 530 : CY;
  let cursor = CY - leftBand / 2;
  const left = sources.map((src, i) => {
    const y = n > 1 ? top + ((bottom - top) * i) / (n - 1) : CY;
    const share = total ? src.count / total : 1 / n;
    const t = Math.max(total ? 1.6 : 1.2, share * leftBand);
    const arc = 26 * (1 - Math.pow((y - CY) / 260, 2));
    const ax = LEFT_X + arc;
    const seg = { src, y, ax, t, t0: y - t / 2, b0: y + t / 2, t1: cursor, b1: cursor + t };
    cursor += t;
    return seg;
  });
  // Re-centre the converged band after minimum widths.
  const used = cursor - (CY - leftBand / 2);
  const shift = (leftBand - used) / 2;
  for (const seg of left) {
    seg.t1 += shift;
    seg.b1 += shift;
  }

  const c = model.flow.cases;
  const groups = [
    { key: "mdr", label: "Sophos MDR", icon: "shield", color: "--mdr", open: c.mdr.open, resolved: c.mdr.resolved },
    { key: "self", label: "Your team", icon: "team", color: "--self", open: c.self.open, resolved: c.self.resolved },
    { key: "unclaimed", label: "Unclaimed", icon: "cases", color: "--unclaimed", open: c.unclaimed.open, resolved: c.unclaimed.resolved },
  ].filter((g) => g.open + g.resolved > 0 || g.key !== "unclaimed");
  const caseTotal = groups.reduce((a, g) => a + g.open + g.resolved, 0);
  const rightBand = bandHeight(caseTotal, 190, 2.3);
  const gap1 = 46;
  const col1Total = rightBand + gap1 * (groups.length - 1);
  let y1 = CY - col1Total / 2;
  let exitCursor = CY - rightBand / 2;
  const col1 = groups.map((g) => {
    const share = caseTotal ? (g.open + g.resolved) / caseTotal : 1 / groups.length;
    const hgt = Math.max(caseTotal ? 2 : 2, share * rightBand);
    const seg = { g, top: y1, bottom: y1 + hgt, exitTop: exitCursor, exitBottom: exitCursor + hgt };
    y1 += hgt + gap1;
    exitCursor += hgt;
    return seg;
  });
  const resolvedTotal = groups.reduce((a, g) => a + g.resolved, 0);
  const openTotal = groups.reduce((a, g) => a + g.open, 0);
  const gap2 = 96;
  const rH = caseTotal ? Math.max(3, (resolvedTotal / caseTotal) * rightBand) : 3;
  const oH = caseTotal ? Math.max(3, (openTotal / caseTotal) * rightBand) : 3;
  const col2Top = CY - (rH + oH + gap2) / 2;
  const resolvedBar = { top: col2Top, bottom: col2Top + rH };
  const openBar = { top: col2Top + rH + gap2, bottom: col2Top + rH + gap2 + oH };
  let rc = resolvedBar.top;
  let oc = openBar.top;
  const right = [];
  for (const seg of col1) {
    const segH = seg.bottom - seg.top;
    const sum = seg.g.open + seg.g.resolved;
    const rPart = sum ? (seg.g.resolved / sum) * segH : 0;
    const oPart = segH - rPart;
    const rTo = caseTotal ? (seg.g.resolved / caseTotal) * rightBand : 0;
    const oTo = caseTotal ? (seg.g.open / caseTotal) * rightBand : 0;
    right.push({ key: `${seg.g.key}-resolved`, color: seg.g.color, value: seg.g.resolved, path: [COL1_X + BAR_W, seg.top, seg.top + rPart, COL2_X, rc, rc + rTo] });
    right.push({ key: `${seg.g.key}-open`, color: seg.g.color, value: seg.g.open, path: [COL1_X + BAR_W, seg.top + rPart, seg.bottom, COL2_X, oc, oc + oTo] });
    rc += rTo;
    oc += oTo;
  }
  return { left, leftBand, col1, right, resolvedBar, openBar, rightBand, caseTotal, total, resolvedTotal, openTotal };
}

// ------------------------------------------------------------------ the triage lens (canvas)

class Lens {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.mix = { critical: 0, high: 0, medium: 0, low: 0, info: 1 };
    this.t0 = performance.now();
    this.born = performance.now();
    this.raf = 0;
    this.energy = 0;
  }
  setMix(mix) {
    const total = SEVS.reduce((a, k) => a + (mix[k] ?? 0), 0);
    this.mix = total ? Object.fromEntries(SEVS.map((k) => [k, (mix[k] ?? 0) / total])) : { critical: 0, high: 0, medium: 0, low: 0, info: 1 };
  }
  kick() {
    this.energy = 1;
  }
  colors() {
    return Object.fromEntries(SEVS.map((k) => [k, css(`--sev-${k}`)]));
  }
  start() {
    const loop = (t) => {
      this.draw(t);
      this.raf = requestAnimationFrame(loop);
    };
    if (reducedMotion()) this.draw(performance.now() + 4000);
    else this.raf = requestAnimationFrame(loop);
  }
  stop() {
    cancelAnimationFrame(this.raf);
  }
  draw(t) {
    const { canvas, ctx } = this;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const size = canvas.clientWidth;
    if (!size) return;
    if (canvas.width !== Math.round(size * dpr)) {
      canvas.width = Math.round(size * dpr);
      canvas.height = Math.round(size * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, size, size);
    const c = size / 2;
    const age = Math.min(1, (t - this.born) / 1400);
    const grow = 1 - Math.pow(1 - age, 3);
    const time = (t - this.t0) / 1000;
    this.energy *= 0.985;
    const colors = this.colors();
    const accent = css("--accent");
    // glow
    const glow = ctx.createRadialGradient(c, c, 0, c, c, c);
    glow.addColorStop(0, `${accent}33`);
    glow.addColorStop(0.55, `${accent}10`);
    glow.addColorStop(1, "transparent");
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(c, c, c * grow, 0, Math.PI * 2);
    ctx.fill();
    // severity-weighted dot rings
    const order = SEVS.flatMap((k) => new Array(Math.round((this.mix[k] ?? 0) * 60)).fill(k));
    const rings = [
      { r: 0.86, n: 72, speed: 0.07, size: 1.5, alpha: 0.5 },
      { r: 0.7, n: 56, speed: -0.12, size: 2.3, alpha: 0.95 },
      { r: 0.54, n: 40, speed: 0.2, size: 2.0, alpha: 0.85 },
      { r: 0.38, n: 26, speed: -0.32, size: 1.6, alpha: 0.7 },
    ];
    rings.forEach((ring, ri) => {
      const rr = c * ring.r * grow * (1 + 0.04 * this.energy * Math.sin(time * 8 + ri));
      for (let i = 0; i < ring.n; i++) {
        const a = (i / ring.n) * Math.PI * 2 + time * ring.speed * (1 + this.energy * 2);
        const sev = order.length ? order[(i * 7 + ri * 13) % order.length] : "info";
        const wobble = 1 + 0.06 * Math.sin(time * 1.7 + i * 0.9 + ri);
        const x = c + Math.cos(a) * rr * wobble;
        const y = c + Math.sin(a) * rr * wobble;
        ctx.globalAlpha = ring.alpha * (0.55 + 0.45 * Math.sin(time * 2.1 + i));
        ctx.fillStyle = ri === 0 ? accent : colors[sev];
        ctx.beginPath();
        ctx.arc(x, y, ring.size * (ri === 1 ? 1 + 0.6 * this.energy : 1), 0, Math.PI * 2);
        ctx.fill();
      }
    });
    ctx.globalAlpha = 1;
    // outer arcs
    ctx.lineWidth = 1.4;
    for (let k = 0; k < 2; k++) {
      ctx.strokeStyle = accent;
      ctx.globalAlpha = 0.65;
      const start = time * (k ? -0.25 : 0.18) + k * Math.PI;
      ctx.beginPath();
      ctx.arc(c, c, c * 0.97 * grow, start, start + Math.PI * 0.62);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
  }
}

// ------------------------------------------------------------------ particles (canvas)

class Particles {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.lanes = [];
    this.parts = [];
    this.raf = 0;
    this.last = performance.now();
  }
  setLanes(lanes) {
    this.lanes = lanes;
  }
  burst(n = 18) {
    const left = this.lanes.filter((l) => l.side === "left" && l.value > 0);
    for (let i = 0; i < n && left.length; i++) this.spawn(left[Math.floor(Math.random() * left.length)], Math.random() * 0.2);
  }
  spawn(lane, at = 0) {
    this.parts.push({ lane, t: at, speed: 0.18 + Math.random() * 0.12, size: 1.2 + Math.random() * 1.4, jitter: (Math.random() - 0.5) * lane.width * 0.7 });
  }
  start() {
    if (reducedMotion()) return;
    const loop = (t) => {
      this.step(t);
      this.raf = requestAnimationFrame(loop);
    };
    this.raf = requestAnimationFrame(loop);
  }
  stop() {
    cancelAnimationFrame(this.raf);
  }
  step(t) {
    const dt = Math.min(0.05, (t - this.last) / 1000);
    this.last = t;
    const { canvas, ctx } = this;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = canvas.clientWidth;
    const hgt = canvas.clientHeight;
    if (!w) return;
    if (canvas.width !== Math.round(w * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(hgt * dpr);
    }
    const k = w / W;
    ctx.setTransform(dpr * k, 0, 0, dpr * k, 0, 0);
    ctx.clearRect(0, 0, W, H);
    for (const lane of this.lanes) {
      const rate = lane.value > 0 ? Math.min(7, 0.5 + Math.sqrt(lane.value) * 0.5) : 0;
      if (Math.random() < rate * dt) this.spawn(lane);
    }
    if (this.parts.length > 900) this.parts.splice(0, this.parts.length - 900);
    const next = [];
    for (const p of this.parts) {
      p.t += p.speed * dt;
      if (p.t >= 1) continue;
      const pts = p.lane.points;
      const f = p.t * (pts.length - 1);
      const i = Math.floor(f);
      const a = pts[i];
      const b = pts[Math.min(pts.length - 1, i + 1)];
      const x = a[0] + (b[0] - a[0]) * (f - i);
      const y = a[1] + (b[1] - a[1]) * (f - i) + p.jitter * Math.sin(p.t * Math.PI);
      const fade = Math.sin(p.t * Math.PI);
      ctx.globalAlpha = 0.25 + 0.75 * fade;
      ctx.fillStyle = p.lane.color();
      ctx.beginPath();
      ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fill();
      next.push(p);
    }
    ctx.globalAlpha = 1;
    this.parts = next;
  }
}

// ------------------------------------------------------------------ the view

let st = null;

function pct(x, total) {
  return `${(x / total) * 100}%`;
}

function sevChips(bySeverity) {
  return h(
    "div",
    { class: "sev-chips" },
    SEVS.filter((k) => k !== "info" || bySeverity.info).map((k) =>
      h("span", { class: `sev-chip sev-${k}`, title: SEV_LABEL[k] }, icon(SEV_ICON[k], 12), h("b", { class: "num", dataset: { sev: k }, text: num(bySeverity[k] ?? 0) }), h("span", { class: "sr", text: SEV_LABEL[k] })),
    ),
  );
}

function buildStage(model) {
  const L = layout(model);
  const stage = h("div", { class: "flow-stage reveal", role: "img", "aria-label": stageLabel(model) });
  const svg = s("svg", { class: "flow-svg", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "xMidYMid meet" });
  const defs = s("defs");
  defs.append(
    s("clipPath", { id: "clip-left" }, s("rect", { class: "clip-rect clip-l", x: 0, y: 0, width: CORE_X, height: H })),
    s("clipPath", { id: "clip-right" }, s("rect", { class: "clip-rect clip-r", x: CORE_X, y: 0, width: W - CORE_X, height: H })),
    s(
      "linearGradient",
      { id: "grad-left", x1: "0", x2: "1", y1: "0", y2: "0" },
      s("stop", { offset: "0", "stop-color": "var(--accent)", "stop-opacity": "0.05" }),
      s("stop", { offset: "0.75", "stop-color": "var(--accent)", "stop-opacity": "0.32" }),
      s("stop", { offset: "1", "stop-color": "var(--accent)", "stop-opacity": "0.55" }),
    ),
  );
  svg.append(defs);
  const gl = s("g", { class: "ribbons ribbons-left", "clip-path": "url(#clip-left)" });
  for (const seg of L.left) {
    const p = s("path", { class: `rib rib-left${seg.src.count ? "" : " rib-zero"}`, d: ribbon(seg.ax + 8, seg.t0, seg.b0, CONVERGE_X, seg.t1, seg.b1), dataset: { key: seg.src.key } });
    gl.append(p);
  }
  // the converged band into the lens
  gl.append(s("path", { class: "rib rib-core", d: ribbon(CONVERGE_X, CY - L.leftBand / 2, CY + L.leftBand / 2, CORE_X - CORE_R * 0.55, CY - 14, CY + 14) }));
  svg.append(gl);
  const gr = s("g", { class: "ribbons ribbons-right", "clip-path": "url(#clip-right)" });
  for (const seg of L.col1) {
    gr.append(s("path", { class: "rib rib-cat", style: `--c: var(${seg.g.color})`, d: ribbon(EXIT_X, seg.exitTop, seg.exitBottom, COL1_X, seg.top, seg.bottom) }));
  }
  gr.append(s("path", { class: "rib rib-core-out", d: ribbon(CORE_X + CORE_R * 0.55, CY - 14, CY + 14, EXIT_X, CY - L.rightBand / 2, CY + L.rightBand / 2) }));
  for (const r of L.right) {
    gr.append(s("path", { class: `rib rib-cat rib-thin${r.value ? "" : " rib-zero"}`, style: `--c: var(${r.color})`, d: ribbon(...r.path) }));
  }
  // node bars
  for (const seg of L.col1) gr.append(s("rect", { class: "node-bar", style: `--c: var(${seg.g.color})`, x: COL1_X, y: seg.top, width: BAR_W, height: Math.max(2, seg.bottom - seg.top), rx: 3 }));
  gr.append(s("rect", { class: "node-bar node-good", x: COL2_X, y: L.resolvedBar.top, width: BAR_W, height: Math.max(2, L.resolvedBar.bottom - L.resolvedBar.top), rx: 3 }));
  // open bar split by severity
  const open = model.flow.cases.openBySeverity;
  const openTotal = SEVS.reduce((a, k) => a + (open[k] ?? 0), 0);
  let oy = L.openBar.top;
  const oh = L.openBar.bottom - L.openBar.top;
  for (const k of SEVS) {
    const v = open[k] ?? 0;
    if (!v) continue;
    const hh = (v / openTotal) * oh;
    gr.append(s("rect", { class: `node-bar node-sev`, style: `--c: var(--sev-${k})`, x: COL2_X, y: oy, width: BAR_W, height: Math.max(1.5, hh - 1.5), rx: 2 }));
    oy += hh;
  }
  if (!openTotal) gr.append(s("rect", { class: "node-bar", style: "--c: var(--ink-4)", x: COL2_X, y: L.openBar.top, width: BAR_W, height: 3, rx: 2 }));
  svg.append(gr);
  // source anchors
  const ga = s("g", { class: "anchors" });
  for (const seg of L.left) ga.append(s("circle", { class: "anchor", cx: seg.ax, cy: seg.y, r: 5.5 }));
  svg.append(ga);
  stage.append(svg);

  const particles = h("canvas", { class: "flow-particles", "aria-hidden": "true" });
  stage.append(particles);

  // labels: sources
  const labels = h("div", { class: "flow-labels" });
  L.left.forEach((seg) => {
    const src = seg.src;
    const el = h(
      "div",
      { class: "src-label", style: { left: pct(seg.ax - 16, W), top: pct(seg.y, H) }, tabindex: "0" },
      h("span", { class: "src-ic" }, icon(src.kind === "more" ? "grid" : sourceIcon(model.scope === "all" ? "tenant" : src.kind || src.label), 15)),
      h("span", { class: "src-name", text: src.label }),
      h("b", { class: "src-count num", text: num(src.count) }),
    );
    tipOn(el, () => [src.label, [{ value: num(src.count), label: `${model.flow.signals.label.toLowerCase()}, last ${windowLabel(model.windowHours)}`, color: "var(--accent)" }]]);
    labels.append(el);
  });
  if (!L.left.length) labels.append(h("div", { class: "src-empty", style: { left: pct(LEFT_X - 20, W), top: pct(CY, H) }, text: `No ${model.flow.signals.label.toLowerCase()} in the last ${windowLabel(model.windowHours)}` }));

  // the lens
  const lens = h("div", { class: "lens", style: { left: pct(CORE_X - CORE_R * 1.25, W), top: pct(CY - CORE_R * 1.25, H), width: pct(CORE_R * 2.5, W) } });
  const lensCanvas = h("canvas", { class: "lens-canvas", "aria-hidden": "true" });
  lens.append(lensCanvas);
  lens.append(
    h(
      "div",
      { class: "lens-text" },
      h("span", { class: "lens-kicker", text: model.flow.signals.label }),
      h("b", { class: "lens-num num", id: "lens-num", style: { viewTransitionName: "kpi-signals" }, text: "0" }),
      h("span", { class: "lens-sub" }, `last ${windowLabel(model.windowHours)}, `, h("b", { class: "num", id: "lens-opened", text: "0" }), ` ${model.flow.cases.opened === 1 ? "case" : "cases"} opened`),
    ),
  );
  labels.append(lens);
  if (model.flow.signals.sampled) labels.append(h("div", { class: "flow-note", style: { left: pct(CORE_X, W), top: pct(CY + CORE_R * 1.35, H) }, text: "Total from Sophos; the split by source is estimated from the newest 3,000 detections" }));

  // col1 labels
  L.col1.forEach((seg) => {
    const el = h(
      "div",
      { class: `cat-label cat-${seg.g.key}`, style: { left: pct(COL1_X + BAR_W + 12, W), top: pct((seg.top + seg.bottom) / 2, H) } },
      h("span", { class: "cat-ic", style: { color: `var(${seg.g.color})` } }, icon(seg.g.icon, 16)),
      h("span", { class: "cat-text" }, h("b", { class: "num", dataset: { k: seg.g.key }, text: num(seg.g.open + seg.g.resolved) }), h("span", { text: seg.g.label })),
    );
    tipOn(el, () => [seg.g.label, [{ value: num(seg.g.open), label: "open now", color: `var(${seg.g.color})` }, { value: num(seg.g.resolved), label: `resolved, last ${windowLabel(model.windowHours)}`, color: "var(--good)" }]]);
    labels.append(el);
  });
  // col2 labels
  labels.append(
    h(
      "div",
      { class: "out-label out-resolved", style: { left: pct(COL2_X + BAR_W + 16, W), top: pct((L.resolvedBar.top + L.resolvedBar.bottom) / 2, H) } },
      h("b", { class: "out-num num", id: "out-resolved", text: "0" }),
      h("span", { class: "out-name" }, icon("check", 15), `Resolved, last ${windowLabel(model.windowHours)}`),
    ),
  );
  labels.append(
    h(
      "a",
      { class: "out-label out-open", href: "#/cases", style: { left: pct(COL2_X + BAR_W + 16, W), top: pct((L.openBar.top + L.openBar.bottom) / 2, H) } },
      h("b", { class: "out-num num", id: "out-open", style: { viewTransitionName: "kpi-open" }, text: "0" }),
      h("span", { class: "out-name" }, icon("open", 15), "Open now"),
      sevChips(model.flow.cases.openBySeverity),
    ),
  );
  labels.append(h("div", { class: "col-head col-who", style: { left: pct(COL1_X, W), top: "3%" }, text: "Who works it" }));
  labels.append(h("div", { class: "col-head col-out", style: { left: pct(COL2_X, W), top: "3%" }, text: "Outcome" }));
  labels.append(
    h(
      "div",
      { class: "col-head col-head-left", style: { left: pct(40, W), top: "3%" } },
      model.scope === "all" ? "Tenants" : "Sources",
      h("small", { class: "col-sub", text: `${model.flow.signals.label} ${model.scope === "all" ? "per tenant" : "per source"}, last ${windowLabel(model.windowHours)}` }),
    ),
  );
  stage.append(labels);
  return { stage, L, particles, lensCanvas };
}

function windowLabel(hours) {
  return hours >= 168 ? `${hours / 24} d` : `${hours} h`;
}

function stageLabel(model) {
  const c = model.flow.cases;
  return `${num(model.flow.signals.total)} ${model.flow.signals.label.toLowerCase()} in the last ${windowLabel(model.windowHours)}, ${num(c.opened)} cases opened, ${num(c.open)} open now, ${num(c.resolved)} resolved.`;
}

function lanesFor(L) {
  const accent = () => css("--accent");
  const lanes = L.left.map((seg) => ({ side: "left", value: seg.src.count, width: seg.t, points: centreline(seg.ax + 8, seg.y, CONVERGE_X, (seg.t1 + seg.b1) / 2), color: accent }));
  const sev = () => css("--accent");
  for (const seg of L.col1) {
    const v = seg.g.open + seg.g.resolved;
    lanes.push({ side: "right", value: v, width: seg.bottom - seg.top, points: centreline(EXIT_X, (seg.exitTop + seg.exitBottom) / 2, COL1_X, (seg.top + seg.bottom) / 2), color: () => css(seg.g.color) });
  }
  for (const r of L.right) {
    const [x0, t0, b0, x1, t1, b1] = r.path;
    lanes.push({ side: "right", value: r.value, width: b0 - t0, points: centreline(x0, (t0 + b0) / 2, x1, (t1 + b1) / 2), color: () => css(r.key.endsWith("resolved") ? "--good" : r.color) });
  }
  void sev;
  return lanes;
}

function buildStrip(model) {
  const strip = h("div", { class: "strip" });
  const s1 = model.strip;
  const tiles = [];
  if (model.scope === "all") {
    tiles.push(
      h(
        "a",
        { class: "kpi reveal", href: "#/msp" },
        h("div", { class: "kpi-label" }, icon("grid", 14), "Tenants needing action"),
        h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-need", text: "0" }), h("span", { class: "kpi-unit", text: `of ${num(model.tenantCount)}` })),
        h("div", { class: "kpi-foot", text: "Critical on the MSP wall" }),
      ),
    );
  }
  tiles.push(
    h(
      "a",
      { class: "kpi reveal", href: "#/endpoints" },
      h("div", { class: "kpi-label" }, icon("endpoint", 14), "Endpoints"),
      h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-ep", text: "0" }), h("span", { class: "kpi-unit", id: "k-ep-unit", text: "" })),
      h("div", { class: "kpi-foot", id: "k-ep-foot" }),
      s1.endpoints.trend.length > 1 ? sparkline(s1.endpoints.trend, { width: 240, height: 34 }) : null,
    ),
  );
  const sig = sparkline(s1.signals.hourly, { width: 260, height: 40 });
  sig.id = "k-sig-spark";
  tiles.push(
    h(
      "a",
      { class: "kpi kpi-wide reveal", href: "#/now" },
      h("div", { class: "kpi-label" }, icon("pulse", 14), `${s1.signals.label}, last 24 h`),
      h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-sig", text: "0" }), h("span", { class: "kpi-unit", id: "k-sig-hour", text: "" })),
      sig,
    ),
  );
  tiles.push(
    h(
      "div",
      { class: "kpi reveal" },
      h("div", { class: "kpi-label" }, icon("shield", 14), model.scope === "all" ? "Average health score" : "Health score"),
      h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-health", text: "0" }), h("span", { class: "kpi-unit", text: "of 100" })),
      h("div", { class: "kpi-meter" }, h("i", { id: "k-health-bar" })),
      h("div", { class: "kpi-foot", text: model.scope === "all" ? `Across ${num(s1.health.tenants)} tenants with a score` : "Average of the Sophos health check sections" }),
    ),
  );
  tiles.push(
    h(
      "a",
      { class: "kpi reveal", href: "#/cases" },
      h("div", { class: "kpi-label" }, icon("cases", 14), "Open cases"),
      h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-cases", text: "0" }), h("span", { class: "kpi-unit", id: "k-oldest", text: "" })),
      h("div", { class: "kpi-sev", id: "k-sev" }),
    ),
  );
  if (s1.smime) tiles.push(smimeTile());
  strip.append(...tiles);
  return strip;
}

/** S/MIME certificates: amber when one expires within 30 days, red within 7 (the license rule). Hidden when no tenant uses S/MIME. */
function smimeTile() {
  return h(
    "div",
    { class: "kpi reveal", id: "k-smime" },
    h("div", { class: "kpi-label" }, icon("key", 14), "S/MIME certificates"),
    h("div", { class: "kpi-row" }, h("b", { class: "kpi-num num", id: "k-smime-n", text: "0" }), h("span", { class: "kpi-unit", text: "expire within 30 days" })),
    h("div", { class: "kpi-foot", id: "k-smime-foot" }),
  );
}

function fillSmime(model) {
  const sm = model.strip.smime;
  let tile = document.getElementById("k-smime");
  if (!sm) {
    tile?.remove();
    return;
  }
  if (!tile) {
    tile = smimeTile();
    document.querySelector(".front .strip")?.append(tile);
  }
  tweenNumber(document.getElementById("k-smime-n"), sm.expiring, num);
  tile.classList.toggle("kpi-alert", !!sm.level);
  tile.classList.toggle("kpi-bad", sm.level === "critical");
  const foot = document.getElementById("k-smime-foot");
  clear(foot);
  if (sm.soonest) {
    const what = sm.soonest.kind === "ca" ? "internal CA" : "a user certificate";
    foot.append(h("span", { class: sm.level === "critical" ? "t-bad" : "t-warn" }, icon(sm.level === "critical" ? "critical" : "warning", 13), ` Next: ${what} in ${plural(sm.soonest.days, "day")}${sm.soonest.tenantName ? `, ${sm.soonest.tenantName}` : ""}`));
  } else if (sm.caExpiresAt && model.scope !== "all") {
    foot.append(h("span", { class: "t-good" }, icon("check", 13), ` Internal CA valid until ${date(Date.parse(sm.caExpiresAt))}`));
  } else {
    foot.append(h("span", { class: "t-good" }, icon("check", 13), ` ${plural(sm.tenants, "tenant")} using S/MIME, none expiring`));
  }
  if (sm.expired) foot.append(h("span", { class: "dim", text: ` · ${num(sm.expired)} already expired` }));
}

function fillStrip(model) {
  const s1 = model.strip;
  tweenNumber(document.getElementById("k-need"), s1.needAction ?? 0, num);
  tweenNumber(document.getElementById("k-ep"), s1.endpoints.total, num);
  setText(document.getElementById("k-ep-unit"), "devices");
  const epFoot = document.getElementById("k-ep-foot");
  if (epFoot) {
    clear(epFoot);
    epFoot.append(
      s1.endpoints.unhealthy ? h("span", { class: "t-bad" }, icon("warning", 13), ` ${num(s1.endpoints.unhealthy)} unhealthy`) : h("span", { class: "t-good" }, icon("check", 13), " none unhealthy"),
      h("span", { class: "dim", text: ` · ${num(s1.endpoints.stale)} stale 7+ days` }),
    );
  }
  tweenNumber(document.getElementById("k-sig"), s1.signals.total, num);
  setText(document.getElementById("k-sig-hour"), `${num(s1.signals.lastHour)} in the last hour`);
  const spark = document.getElementById("k-sig-spark");
  if (spark) updateSparkline(spark, s1.signals.hourly);
  tweenNumber(document.getElementById("k-health"), s1.health.average ?? NaN, (n) => (Number.isFinite(n) ? num(n) : "-"));
  const bar = document.getElementById("k-health-bar");
  if (bar) {
    const v = s1.health.average ?? 0;
    bar.style.width = `${v}%`;
    bar.className = v < 50 ? "bad" : v < 80 ? "warn" : "good";
  }
  tweenNumber(document.getElementById("k-cases"), s1.cases.open, num);
  setText(document.getElementById("k-oldest"), s1.cases.oldestMs ? `oldest ${duration(s1.cases.oldestMs, 1)}` : "");
  const sev = document.getElementById("k-sev");
  if (sev) {
    if (!sev.querySelector(".k-sev-bar")) sev.append(h("div", { class: "k-sev-bar" }), h("div", { class: "k-sev-chips" }));
    stackBar(
      sev.querySelector(".k-sev-bar"),
      SEVS.map((k) => ({ key: k, label: SEV_LABEL[k], value: s1.cases.bySeverity[k] ?? 0, color: `var(--sev-${k})` })),
      { title: "Open cases by severity" },
    );
    const chips = sev.querySelector(".k-sev-chips");
    clear(chips);
    chips.append(sevChips(s1.cases.bySeverity));
  }
  fillSmime(model);
}

function fillNumbers(model, L) {
  tweenNumber(document.getElementById("lens-num"), model.flow.signals.total, num, 1400);
  tweenNumber(document.getElementById("lens-opened"), model.flow.cases.opened, num, 1400);
  tweenNumber(document.getElementById("out-resolved"), L.resolvedTotal, num, 1600);
  tweenNumber(document.getElementById("out-open"), L.openTotal, num, 1600);
  for (const el of document.querySelectorAll(".cat-label b[data-k]")) {
    const seg = L.col1.find((x) => x.g.key === el.dataset.k);
    if (seg) tweenNumber(el, seg.g.open + seg.g.resolved, num, 1600);
  }
}

function header(model, ctx) {
  const range = h(
    "div",
    { class: "seg", role: "group", "aria-label": "Time range" },
    [
      ["24", "24 h"],
      ["168", "7 d"],
    ].map(([v, label]) =>
      h("button", {
        type: "button",
        class: String(model.windowHours) === v ? "on" : "",
        "aria-pressed": String(model.windowHours) === v ? "true" : "false",
        text: label,
        onclick: () => {
          store.set("window", v);
          ctx.setQuery({ window: v });
        },
      }),
    ),
  );
  const gen = model.generation ? h("span", { class: `gen gen-${model.generation}`, text: model.generation === "fusion" ? "Fusion" : model.generation === "classic" ? "Classic" : "Unknown API" }) : null;
  return h(
    "div",
    { class: "front-head reveal" },
    h("div", {}, h("h1", { class: "greet", text: `${greeting()}` }), h("p", { class: "sub" }, h("span", { class: "sub-name", text: model.tenantName }), gen, h("span", { class: "dim", text: model.scope === "all" ? `${num(model.tenantCount)} tenants` : "" }))),
    h("div", { class: "front-tools" }, freshChip(model.freshness), range),
  );
}

export default {
  id: "front",
  mount(root, model, ctx) {
    const wrap = h("section", { class: "front" });
    wrap.append(header(model, ctx));
    const { stage, L, particles, lensCanvas } = buildStage(model);
    wrap.append(stage, buildStrip(model));
    root.append(wrap);
    const lens = new Lens(lensCanvas);
    lens.setMix(model.flow.signals.bySeverity);
    lens.start();
    const parts = new Particles(particles);
    parts.setLanes(lanesFor(L));
    setTimeout(() => {
      parts.start();
      parts.burst(30);
    }, reducedMotion() ? 0 : 1300);
    st = { lens, parts, model, L, root, ctx, total: model.flow.signals.total };
    if (!reducedMotion()) {
      for (const r of stage.querySelectorAll(".clip-rect")) r.animate([{ transform: "scaleX(0)" }, { transform: "scaleX(1)" }], { duration: 1500, delay: r.classList.contains("clip-r") ? 900 : 250, easing: "cubic-bezier(.45,.05,.2,1)", fill: "backwards" });
      stage.querySelectorAll(".src-label").forEach((el, i) => el.animate([{ opacity: 0, transform: "translate(-100%, -50%) translateX(-16px)" }, { opacity: 1, transform: "translate(-100%, -50%)" }], { duration: 600, delay: 150 + i * 60, easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" }));
      stage.querySelectorAll(".cat-label, .out-label").forEach((el, i) => el.animate([{ opacity: 0, transform: "translateY(-50%) translateX(-12px)" }, { opacity: 1, transform: "translateY(-50%)" }], { duration: 600, delay: 1300 + i * 110, easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" }));
      stage.querySelector(".lens").animate([{ opacity: 0, transform: "scale(.6) rotate(-30deg)" }, { opacity: 1, transform: "none" }], { duration: 1200, delay: 500, easing: "cubic-bezier(.34,1.3,.5,1)", fill: "backwards" });
    }
    setTimeout(() => fillNumbers(model, L), reducedMotion() ? 0 : 700);
    fillStrip(model);
  },
  update(model, ctx) {
    if (!st) return;
    const structural = JSON.stringify(model.flow.sources.map((x) => x.label)) !== JSON.stringify(st.model.flow.sources.map((x) => x.label)) || model.windowHours !== st.model.windowHours || model.tenantName !== st.model.tenantName;
    if (structural) {
      const root = st.root;
      this.unmount();
      clear(root);
      this.mount(root, model, ctx);
      return;
    }
    const stage = st.root.querySelector(".flow-stage");
    const fresh = buildStage(model);
    // Morph ribbons and bars to the new sizes rather than rebuilding them.
    const oldSvg = stage.querySelector(".flow-svg");
    const newSvg = fresh.stage.querySelector(".flow-svg");
    const oldPaths = oldSvg.querySelectorAll("path.rib");
    const newPaths = newSvg.querySelectorAll("path.rib");
    if (oldPaths.length === newPaths.length) {
      oldPaths.forEach((p, i) => {
        const d = newPaths[i].getAttribute("d");
        if (p.getAttribute("d") !== d) {
          p.style.d = `path("${d}")`;
          p.setAttribute("d", d);
        }
        p.setAttribute("class", newPaths[i].getAttribute("class"));
      });
      oldSvg.querySelectorAll(".node-bar").forEach((r) => r.remove());
      const gr = oldSvg.querySelector(".ribbons-right");
      for (const r of newSvg.querySelectorAll(".node-bar")) gr.append(r);
    } else {
      stage.replaceChild(newSvg, oldSvg);
    }
    stage.querySelector(".flow-labels").replaceWith(fresh.stage.querySelector(".flow-labels"));
    const newLensCanvas = stage.querySelector(".lens-canvas");
    st.lens.canvas = newLensCanvas;
    st.lens.ctx = newLensCanvas.getContext("2d");
    st.lens.born = performance.now() - 5000;
    st.lens.setMix(model.flow.signals.bySeverity);
    for (const el of stage.querySelectorAll(".lens-num, #lens-opened, #out-resolved, #out-open, .cat-label b[data-k]")) {
      const old = st.model;
      if (el.id === "lens-num") el.dataset.value = String(old.flow.signals.total);
      if (el.id === "lens-opened") el.dataset.value = String(old.flow.cases.opened);
      if (el.id === "out-resolved") el.dataset.value = String(st.L.resolvedTotal);
      if (el.id === "out-open") el.dataset.value = String(st.L.openTotal);
      if (el.dataset.k) {
        const seg = st.L.col1.find((x) => x.g.key === el.dataset.k);
        el.dataset.value = seg ? String(seg.g.open + seg.g.resolved) : "0";
      }
    }
    st.parts.setLanes(lanesFor(fresh.L));
    if (model.flow.signals.total > st.total) {
      st.parts.burst(Math.min(40, 6 + (model.flow.signals.total - st.total) * 4));
      st.lens.kick();
      pulse(stage.querySelector(".lens-text"));
    }
    st.total = model.flow.signals.total;
    fillNumbers(model, fresh.L);
    st.model = model;
    st.L = fresh.L;
    const fc = st.root.querySelector(".front-tools .fresh");
    if (fc) fc.replaceWith(freshChip(model.freshness));
    fillStrip(model);
    void ago;
  },
  unmount() {
    st?.lens.stop();
    st?.parts.stop();
    st = null;
  },
  onTheme() {
    // Canvas colours are read every frame; nothing to rebuild.
  },
};
