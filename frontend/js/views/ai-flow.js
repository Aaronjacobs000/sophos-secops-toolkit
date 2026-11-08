// The AI usage flow: AI apps on the left, users on the right, both meeting at
// what AI Defense did with their activity (blocked, warned or allowed). A
// Sankey on each side of the gate: bands are sized by activity and coloured by
// outcome, particles run into the gate, and every number counts up. Hover or
// focus shows the numbers; a click pins an app, a user or an outcome.

import { h, s, clear } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, reducedMotion, pulse } from "../anim.js";
import { num, plural } from "../format.js";
import { tipOn, hideTip } from "../viz.js";
import { AI_LOGOS, logoFor, monogram } from "../ai-logos.js";

const W = 1600;
const H = 620;
const TOP = 66;
const BOTTOM = 608;
const CY = (TOP + BOTTOM) / 2;
const LX = 322;
const GX0 = 700;
const GX1 = 900;
const RX = 1270;
const BAR = 8;
const MIN_SLOT = 40;
const SLOT_GAP = 6;
const MIN_GATE = 72;
const GATE_GAP = 20;
const MIN_VIEW = 400;

export const OUTCOMES = [
  { key: "blocked", label: "Blocked", icon: "critical", color: "--afl-blocked" },
  { key: "warned", label: "Warned", icon: "warning", color: "--afl-warned" },
  { key: "allowed", label: "Allowed", icon: "check", color: "--afl-allowed" },
];
const OUT = Object.fromEntries(OUTCOMES.map((o) => [o.key, o]));

function css(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function pct(x, total) {
  return `${(x / total) * 100}%`;
}

function share(v, total) {
  if (!total || !v) return "0%";
  const p = (v / total) * 100;
  return p < 1 ? "under 1%" : `${Math.round(p)}%`;
}

function ribbon(x0, t0, b0, x1, t1, b1) {
  const mx = (x0 + x1) / 2;
  return `M${x0},${t0} C${mx},${t0} ${mx},${t1} ${x1},${t1} L${x1},${b1} C${mx},${b1} ${mx},${b0} ${x0},${b0} Z`;
}

function centreline(x0, y0, x1, y1, n = 48) {
  const pts = [];
  const mx = (x0 + x1) / 2;
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    pts.push([u * u * u * x0 + 3 * u * u * t * mx + 3 * u * t * t * mx + t * t * t * x1, u * u * u * y0 + 3 * u * u * t * y0 + 3 * u * t * t * y1 + t * t * t * y1]);
  }
  return pts;
}

/** Thicker bands for more activity, on a log scale, so a quiet tenant reads as quiet. */
function bandHeight(total) {
  if (!total) return 0;
  return Math.max(40, Math.min(400, 60 + 340 * Math.min(1, Math.log10(total + 1) / 4.3)));
}

/** Lays the flow out in viewBox units. Pure, so an update just re-runs it. */
export function layoutFlow(flow) {
  const avail = BOTTOM - TOP;
  const need = (k) => {
    const side = (rows) => rows.reduce((a, r) => a + Math.max(MIN_SLOT, r.total * k + 6), 0) + Math.max(0, rows.length - 1) * SLOT_GAP;
    const gate = OUTCOMES.reduce((a, o) => a + Math.max(MIN_GATE, flow[o.key] * k), 0) + GATE_GAP * 2;
    return Math.max(side(flow.apps), side(flow.users), gate);
  };
  let k = flow.total ? bandHeight(flow.total) / flow.total : 0;
  for (let i = 0; i < 80 && k > 0 && need(k) > avail; i++) k *= 0.95;

  const heights = OUTCOMES.map((o) => Math.max(MIN_GATE, flow[o.key] * k));
  let gy = CY - (heights.reduce((a, b) => a + b, 0) + GATE_GAP * 2) / 2;
  const gate = OUTCOMES.map((o, i) => {
    const inner = flow[o.key] * k;
    const seg = { ...o, value: flow[o.key], top: gy, bottom: gy + heights[i], inner, start: gy + (heights[i] - inner) / 2 };
    gy += heights[i] + GATE_GAP;
    return seg;
  });
  const place = (rows) => {
    const slots = rows.map((r) => Math.max(MIN_SLOT, r.total * k + 6));
    let y = CY - (slots.reduce((a, b) => a + b, 0) + Math.max(0, rows.length - 1) * SLOT_GAP) / 2;
    return rows.map((r, i) => {
      const t = r.total * k;
      const cy = y + slots[i] / 2;
      y += slots[i] + SLOT_GAP;
      return { r, cy, top: cy - t / 2, bottom: cy + t / 2, t };
    });
  };
  const left = place(flow.apps);
  const right = place(flow.users);
  const ribbons = [];
  const attach = (nodes, side) => {
    if (!flow.split) {
      // No split: one neutral band per app or user, into the gate as a whole.
      let cursor = CY - (flow.total * k) / 2;
      for (const n of nodes) {
        const th = n.r.total * k;
        ribbons.push({ side, ent: n.r.key, out: "all", value: n.r.total, node: n, from: [n.top, n.bottom], to: [cursor, cursor + th] });
        cursor += th;
      }
      return;
    }
    const cursor = Object.fromEntries(gate.map((g) => [g.key, g.start]));
    for (const n of nodes) {
      let y = n.top;
      for (const g of gate) {
        const v = n.r[g.key] ?? 0;
        if (!v) continue;
        const th = v * k;
        ribbons.push({ side, ent: n.r.key, out: g.key, value: v, node: n, from: [y, y + th], to: [cursor[g.key], cursor[g.key] + th] });
        y += th;
        cursor[g.key] += th;
      }
    }
  };
  attach(left, "left");
  attach(right, "right");
  for (const rb of ribbons) {
    rb.d = rb.side === "left" ? ribbon(LX + BAR, rb.from[0], rb.from[1], GX0, rb.to[0], rb.to[1]) : ribbon(GX1, rb.to[0], rb.to[1], RX, rb.from[0], rb.from[1]);
    const fromMid = (rb.from[0] + rb.from[1]) / 2;
    const toMid = (rb.to[0] + rb.to[1]) / 2;
    // Particles always run into the gate.
    rb.points = rb.side === "left" ? centreline(LX + BAR, fromMid, GX0, toMid) : centreline(RX, fromMid, GX1, toMid);
  }
  // A sparse flow (a quiet tenant) gets a shorter stage instead of empty space above and below.
  const slotEdge = (nodes, end) => (nodes.length ? (end ? nodes.at(-1).cy + MIN_SLOT / 2 : nodes[0].cy - MIN_SLOT / 2) : CY);
  const contentTop = Math.min(gate[0].top, slotEdge(left, false), slotEdge(right, false), ...left.map((n) => n.top), ...right.map((n) => n.top));
  const contentBottom = Math.max(gate.at(-1).bottom, slotEdge(left, true), slotEdge(right, true), ...left.map((n) => n.bottom), ...right.map((n) => n.bottom));
  let y0 = Math.max(0, contentTop - TOP);
  let vh = Math.min(H - y0, contentBottom + (H - BOTTOM) - y0);
  if (vh < MIN_VIEW) {
    y0 = Math.max(0, y0 - (MIN_VIEW - vh) / 2);
    vh = Math.min(H - y0, MIN_VIEW);
  }
  return { k, gate, left, right, ribbons, view: { y0: Math.round(y0), vh: Math.round(vh) } };
}

// ------------------------------------------------------------------ marks

/** An app's logo chip, or its monogram when no licence-clean logo is cleared for it. */
export function appMark(app, size = 22) {
  if (app.kind === "other") return h("span", { class: "afl-mark afl-mark-other", style: { "--s": `${size}px` }, "aria-hidden": "true" }, icon("grid", Math.round(size * 0.62)));
  const key = logoFor({ id: app.appId ?? app.id, name: app.label ?? app.name, provider: app.provider });
  const chip = h("span", { class: `afl-mark${key ? " afl-mark-logo" : ""}`, style: { "--s": `${size}px` }, "aria-hidden": "true" });
  if (key) {
    chip.append(s("svg", { viewBox: "0 0 24 24", role: "presentation" }, s("path", { d: AI_LOGOS[key].path })));
    chip.title = `${AI_LOGOS[key].title} logo (Simple Icons, CC0)`;
  } else chip.append(h("b", { text: monogram(app.label ?? app.name) }));
  return chip;
}

/** A glyph only where it says something: an IP address AI Defense could not tie to a person, or a grouped band. */
function userMark(u, size = 22) {
  const style = { "--s": `${size}px` };
  if (u.kind === "other") return h("span", { class: "afl-mark afl-mark-other", style, title: u.count ? "Grouped" : "No user named" }, icon(u.count ? "team" : "identity", Math.round(size * 0.62)));
  if (u.network) return h("span", { class: "afl-mark afl-mark-other", style, title: "An IP address, not a named person" }, icon("network", Math.round(size * 0.62)));
  return h("span", { class: "afl-mark afl-mark-none", style, "aria-hidden": "true" });
}

function miniBar(r) {
  const bar = h("span", { class: "afl-mini", "aria-hidden": "true" });
  if (r.blocked === null || !r.total) return bar;
  for (const o of OUTCOMES) if (r[o.key]) bar.append(h("i", { style: { flex: String(r[o.key]), background: `var(${o.color})` } }));
  return bar;
}

// ------------------------------------------------------------------ tooltips

function entityTip(r, flow) {
  const rows = [{ value: num(r.total), label: `AI ${r.total === 1 ? "activity" : "activities"}, ${share(r.total, flow.total)} of all` }];
  if (r.blocked !== null) for (const o of OUTCOMES) rows.push({ value: num(r[o.key]), label: `${o.label.toLowerCase()}, ${share(r[o.key], r.total)}`, color: `var(${o.color})` });
  else rows.push({ value: "-", label: "split by outcome not read" });
  if (r.unsanctioned) rows.push({ value: num(r.unsanctioned), label: "allowed with no policy covering the app" });
  if (r.kind === "app") {
    if (r.users) rows.push({ value: num(r.users), label: r.tenants && r.tenants > 1 ? "users, counted per tenant" : r.users === 1 ? "user" : "users" });
    if (r.tenants && r.tenants > 1) rows.push({ value: num(r.tenants), label: "tenants" });
    if (r.elsewhere) rows.push({ value: num(r.elsewhere), label: "more where it is outside a tenant's top 10, under other apps" });
  } else if (r.kind === "user") {
    if (r.apps) rows.push({ value: num(r.apps), label: r.apps === 1 ? "AI app" : "AI apps" });
    if (r.topApp) rows.push({ value: r.topApp, label: "used most" });
    if (r.tenantName) rows.push({ value: r.tenantName, label: "" });
  }
  let title = r.label;
  if (r.kind === "app" && r.provider && r.provider !== r.label) title = `${r.label}, ${r.provider}`;
  if (r.kind === "other") title = `${r.label}: ${r.key === "other:apps" ? "every app outside the top 10" : r.count ? "everyone outside the top 10, and activity AI Defense could not tie to a person" : "activity AI Defense could not tie to a person"}`;
  return [title, rows];
}

function gateTip(g, flow) {
  const rows = [{ value: num(g.value), label: `of ${num(flow.total)} AI activities, ${share(g.value, flow.total)}`, color: `var(${g.color})` }];
  if (flow.split) {
    for (const [side, noun] of [[flow.apps, "app"], [flow.users, "user"]]) {
      const top = side.filter((r) => r.kind !== "other" && r[g.key]).sort((a, b) => b[g.key] - a[g.key]).slice(0, 3);
      if (top.length) rows.push({ value: "", label: `Top ${noun === "app" ? "apps" : "users"}` }, ...top.map((r) => ({ value: num(r[g.key]), label: r.label })));
    }
  }
  if (g.key === "allowed" && flow.unsanctioned) rows.push({ value: num(flow.unsanctioned), label: "with no policy covering the app" });
  return [`${g.label}, last 7 days`, rows];
}

function ribbonTip(rb, flow) {
  const r = rb.node.r;
  if (rb.out === "all") return entityTip(r, flow);
  const o = OUT[rb.out];
  return [`${r.label}, ${o.label.toLowerCase()}`, [{ value: num(rb.value), label: `${share(rb.value, r.total)} of ${r.kind === "other" ? "this group's" : "its"} activity`, color: `var(${o.color})` }]];
}

// ------------------------------------------------------------------ particles (canvas)

class Particles {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.lanes = [];
    this.parts = [];
    this.hits = [];
    this.raf = 0;
    this.last = performance.now();
    this.focus = null;
  }
  setLanes(lanes, view = { y0: 0, vh: H }) {
    this.lanes = lanes;
    this.view = view;
    const max = Math.max(1, ...lanes.map((l) => l.value));
    for (const l of lanes) l.rate = l.value > 0 ? Math.min(4.5, 0.25 + 4 * Math.sqrt(l.value / max)) : 0;
    this.parts = this.parts.filter((p) => lanes.includes(p.lane));
  }
  burst(n = 24) {
    const live = this.lanes.filter((l) => l.value > 0);
    for (let i = 0; i < n && live.length; i++) this.spawn(live[Math.floor(Math.random() * live.length)], Math.random() * 0.25);
  }
  spawn(lane, at = 0) {
    this.parts.push({ lane, t: at, speed: 0.22 + Math.random() * 0.12, size: 1.1 + Math.random() * 1.3, jitter: (Math.random() - 0.5) * Math.min(lane.width, 30) * 0.7 });
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
  lit(lane) {
    const f = this.focus;
    if (!f) return true;
    return f.kind === "ent" ? lane.ent === f.key : lane.out === f.key;
  }
  step(t) {
    const dt = Math.min(0.05, (t - this.last) / 1000);
    this.last = t;
    const { canvas, ctx } = this;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = canvas.clientWidth;
    const hgt = canvas.clientHeight;
    if (!w) return;
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(hgt * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(hgt * dpr);
    }
    const scale = w / W;
    const { y0, vh } = this.view ?? { y0: 0, vh: H };
    ctx.setTransform(dpr * scale, 0, 0, dpr * scale, 0, -y0 * dpr * scale);
    ctx.clearRect(0, y0, W, vh);
    const colors = { blocked: css("--afl-blocked"), warned: css("--afl-warned"), allowed: css("--afl-allowed"), all: css("--accent") };
    for (const lane of this.lanes) if (lane.rate && Math.random() < lane.rate * dt) this.spawn(lane);
    if (this.parts.length > 700) this.parts.splice(0, this.parts.length - 700);
    const next = [];
    for (const p of this.parts) {
      p.t += p.speed * dt;
      const pts = p.lane.points;
      if (p.t >= 1) {
        if (p.lane.out === "blocked" || p.lane.out === "warned") this.hits.push({ x: pts[pts.length - 1][0], y: pts[pts.length - 1][1] + p.jitter * 0.15, born: t, out: p.lane.out });
        continue;
      }
      const f = p.t * (pts.length - 1);
      const i = Math.floor(f);
      const a = pts[i];
      const b = pts[Math.min(pts.length - 1, i + 1)];
      const x = a[0] + (b[0] - a[0]) * (f - i);
      const y = a[1] + (b[1] - a[1]) * (f - i) + p.jitter * Math.sin(p.t * Math.PI);
      ctx.globalAlpha = (0.25 + 0.75 * Math.sin(p.t * Math.PI)) * (this.lit(p.lane) ? 1 : 0.12);
      ctx.fillStyle = colors[p.lane.out] ?? colors.all;
      ctx.beginPath();
      ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fill();
      next.push(p);
    }
    this.parts = next;
    // A blocked particle meets the gate with a small ring; a warned one with a short flash.
    if (this.hits.length > 80) this.hits.splice(0, this.hits.length - 80);
    this.hits = this.hits.filter((hit) => {
      const age = (t - hit.born) / 480;
      if (age >= 1) return false;
      ctx.globalAlpha = (1 - age) * 0.75 * (this.focus && this.focus.kind === "out" && this.focus.key !== hit.out ? 0.15 : 1);
      ctx.strokeStyle = colors[hit.out];
      ctx.lineWidth = hit.out === "blocked" ? 1.6 : 1.1;
      ctx.beginPath();
      ctx.arc(hit.x, hit.y, hit.out === "blocked" ? 2 + age * 9 : 1.5 + age * 5, 0, Math.PI * 2);
      ctx.stroke();
      return true;
    });
    ctx.globalAlpha = 1;
  }
}

// ------------------------------------------------------------------ the stage

function stageLabel(flow) {
  if (!flow.total) return "No AI activity in the last 7 days.";
  return `${num(flow.total)} AI activities in the last 7 days: ${num(flow.blocked)} blocked, ${num(flow.warned)} warned and ${num(flow.allowed)} allowed. The tables below list the apps and users.`;
}

const find = (flow, key) => flow.apps.find((x) => x.key === key) ?? flow.users.find((x) => x.key === key);

/** Bars on each side's nodes, split by outcome where the split is known. */
function nodeBars(flow, L) {
  const out = { left: [], right: [] };
  for (const [nodes, x, side] of [[L.left, LX, "left"], [L.right, RX, "right"]]) {
    for (const n of nodes) {
      if (flow.split && n.r.blocked !== null) {
        let y = n.top;
        for (const o of OUTCOMES) {
          const hh = (n.r[o.key] ?? 0) * L.k;
          if (hh <= 0) continue;
          out[side].push(s("rect", { class: "afl-node", x, y, width: BAR, height: Math.max(0.8, hh), style: `--c: var(${o.color})`, "data-ent": n.r.key, "data-out": o.key }));
          y += hh;
        }
      } else out[side].push(s("rect", { class: "afl-node", x, y: n.top, width: BAR, height: Math.max(1, n.t), style: "--c: var(--afl-neutral)", "data-ent": n.r.key }));
    }
  }
  return out;
}

function gateEdges(flow, L) {
  if (!flow.split) return [];
  return L.gate.flatMap((g) => (g.inner > 0 ? [GX0 - 2, GX1 - 2].map((x) => s("rect", { class: "afl-gate-edge", x, y: g.start, width: 4, height: g.inner, rx: 2, style: `--c: var(${g.color})`, "data-out": g.key })) : []));
}

function bindFocus(el, sel, opts, key = true) {
  el.addEventListener("pointerenter", () => opts.hover(sel));
  el.addEventListener("pointerleave", () => opts.hover(null));
  el.addEventListener("click", (e) => {
    e.stopPropagation();
    opts.pin(sel);
  });
  if (!key) return;
  el.addEventListener("focus", () => opts.hover(sel));
  el.addEventListener("blur", () => opts.hover(null));
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      opts.pin(sel);
    }
  });
}

/** Builds the stage. Tooltips read `ref`, so an update that only resizes keeps them current. */
function build(ref, opts) {
  const { flow, L } = ref;
  const { y0, vh } = L.view;
  const top = (y) => pct(y - y0, vh);
  const stage = h("div", { class: `afl-stage reveal${flow.split ? "" : " afl-unsplit"}`, role: "group", "aria-label": stageLabel(flow), style: { "--afl-ar": `${W} / ${vh}`, "--afl-wr": (W / vh).toFixed(4) } });
  const svg = s("svg", { class: "afl-svg", viewBox: `0 ${y0} ${W} ${vh}`, preserveAspectRatio: "xMidYMid meet", "aria-hidden": "true" });
  svg.append(
    s(
      "defs",
      {},
      s("clipPath", { id: "afl-clip-l" }, s("rect", { class: "afl-clip afl-clip-l", x: 0, y: y0, width: GX0 + 2, height: vh })),
      s("clipPath", { id: "afl-clip-r" }, s("rect", { class: "afl-clip afl-clip-r", x: GX1 - 2, y: y0, width: W - GX1 + 2, height: vh })),
    ),
  );
  const groups = { left: s("g", { class: "afl-ribbons afl-left", "clip-path": "url(#afl-clip-l)" }), right: s("g", { class: "afl-ribbons afl-right", "clip-path": "url(#afl-clip-r)" }) };
  L.ribbons.forEach((rb, i) => {
    const p = s("path", { class: `afl-rib afl-rib-${rb.out}`, d: rb.d, style: `--c: var(${OUT[rb.out]?.color ?? "--afl-neutral"})` });
    p.dataset.ent = rb.ent;
    p.dataset.out = rb.out;
    tipOn(p, () => ribbonTip(ref.L.ribbons[i], ref.flow));
    bindFocus(p, { kind: "ent", key: rb.ent }, opts, false);
    groups[rb.side].append(p);
  });
  const bars = nodeBars(flow, L);
  groups.left.append(s("g", { class: "afl-nodes" }, bars.left));
  groups.right.append(s("g", { class: "afl-nodes" }, bars.right));
  const gateG = s("g", { class: "afl-gate" });
  for (const g of L.gate) {
    const seg = s("rect", { class: "afl-gate-seg", x: GX0, y: g.top, width: GX1 - GX0, height: g.bottom - g.top, rx: 14, style: `--c: var(${g.color})`, "data-out": g.key });
    tipOn(seg, () => gateTip(ref.L.gate.find((x) => x.key === g.key), ref.flow));
    bindFocus(seg, { kind: "out", key: g.key }, opts, false);
    gateG.append(seg);
  }
  gateG.append(s("g", { class: "afl-edges" }, gateEdges(flow, L)));
  svg.append(groups.left, groups.right, gateG);
  stage.append(svg);
  const canvas = h("canvas", { class: "afl-particles", "aria-hidden": "true" });
  stage.append(canvas);

  const labels = h("div", { class: "afl-labels" });
  labels.append(
    h("div", { class: "afl-head afl-head-l", style: { left: pct(LX + BAR, W) } }, "AI apps", h("small", { text: `${plural(opts.appsTotal, "app")}${opts.multi ? ", counted per tenant" : ""}` })),
    h("div", { class: "afl-head afl-head-c", style: { left: pct((GX0 + GX1) / 2, W) } }, "What AI Defense did", h("small", { text: "last 7 days" })),
    h("div", { class: "afl-head afl-head-r", style: { left: pct(RX, W) } }, "Users", h("small", { text: plural(opts.usersTotal, "user") })),
  );
  const entLabel = (n, side) => {
    const r = n.r;
    const el = h(
      "div",
      { class: `afl-ent afl-ent-${side}${r.kind === "other" ? " afl-ent-other" : ""}`, tabindex: "0", style: { left: pct(side === "left" ? LX - 12 : RX + BAR + 12, W), top: top(n.cy) }, dataset: { ent: r.key } },
      side === "left" ? appMark(r) : userMark(r),
      h("span", { class: "afl-name", text: r.label }),
      h("b", { class: "afl-n num", dataset: { k: r.key }, text: "0" }),
      miniBar(r),
    );
    tipOn(el, () => entityTip(find(ref.flow, r.key) ?? r, ref.flow));
    bindFocus(el, { kind: "ent", key: r.key }, opts);
    return el;
  };
  const gateLabel = (g) => {
    const el = h(
      "div",
      { class: `afl-out afl-out-${g.key}`, tabindex: "0", style: { left: pct((GX0 + GX1) / 2, W), top: top((g.top + g.bottom) / 2), "--c": `var(${g.color})` }, dataset: { out: g.key } },
      h("span", { class: "afl-out-name" }, icon(g.icon, 14), g.label),
      h("b", { class: "afl-out-n num", id: `afl-out-${g.key}`, text: "0" }),
      h("span", { class: "afl-out-pct", text: share(g.value, flow.total) }),
    );
    tipOn(el, () => gateTip(ref.L.gate.find((x) => x.key === g.key), ref.flow));
    bindFocus(el, { kind: "out", key: g.key }, opts);
    return el;
  };
  labels.append(
    h("div", { class: "afl-col afl-col-apps" }, h("div", { class: "afl-col-head", text: "AI apps" }), L.left.map((n) => entLabel(n, "left"))),
    h("div", { class: "afl-col afl-col-gate" }, h("div", { class: "afl-col-head", text: "What AI Defense did" }), L.gate.map(gateLabel)),
    h("div", { class: "afl-col afl-col-users" }, h("div", { class: "afl-col-head", text: "Users" }), L.right.map((n) => entLabel(n, "right"))),
  );
  stage.append(labels);
  stage.addEventListener("click", () => opts.pin(null));
  return { stage, canvas };
}

function lanesFor(L) {
  return L.ribbons.map((rb) => ({ ent: rb.ent, out: rb.out, value: rb.value, width: rb.to[1] - rb.to[0], points: rb.points }));
}

const ribbonKey = (L) => L.ribbons.map((rb) => `${rb.side}|${rb.ent}|${rb.out}`).join(",");

/** The flow on the AI usage board: mount once, update in place, destroy on leaving the screen. */
export class AiFlowStage {
  constructor(container, flow, opts) {
    this.container = container;
    this.opts = { ...opts, hover: (sel) => this.setHover(sel), pin: (sel) => this.setPin(sel) };
    this.pinned = null;
    this.hovered = null;
    this.ref = { flow, L: null };
    this.onKey = (e) => {
      if (e.key === "Escape" && this.pinned) this.setPin(null);
    };
    document.addEventListener("keydown", this.onKey);
    this.mount(flow, true);
  }

  mount(flow, first) {
    this.parts?.stop();
    this.parts = null;
    this.stage = null;
    clear(this.container);
    this.ref = { flow, L: layoutFlow(flow) };
    if (!flow.total) {
      this.container.append(
        h(
          "div",
          { class: "afl-empty reveal" },
          h("span", { class: "afl-empty-gate", "aria-hidden": "true" }, OUTCOMES.map((o) => h("i", { style: { background: `var(${o.color})` } }))),
          h("div", {}, h("b", { text: "No AI activity in the last 7 days" }), h("p", { text: "AI Defense is set up. Once someone uses an AI app, this shows which apps and which people it blocked, warned on and allowed." })),
        ),
      );
      return;
    }
    const built = build(this.ref, this.opts);
    this.stage = built.stage;
    this.container.append(built.stage);
    this.parts = new Particles(built.canvas);
    this.parts.setLanes(lanesFor(this.ref.L), this.ref.L.view);
    this.applyFocus();
    const motion = !reducedMotion();
    if (motion && first) {
      for (const r of built.stage.querySelectorAll(".afl-clip")) r.animate([{ transform: "scaleX(0)" }, { transform: "scaleX(1)" }], { duration: 1400, delay: 250, easing: "cubic-bezier(.45,.05,.2,1)", fill: "backwards" });
      for (const r of built.stage.querySelectorAll(".afl-gate-seg")) r.animate([{ transform: "scaleY(0)", opacity: 0 }, { transform: "scaleY(1)", opacity: 1 }], { duration: 900, delay: 900, easing: "cubic-bezier(.34,1.3,.5,1)", fill: "backwards" });
      built.stage.querySelectorAll(".afl-ent-left").forEach((el, i) => el.animate([{ opacity: 0, transform: "translate(-100%, -50%) translateX(-14px)" }, { opacity: 1, transform: "translate(-100%, -50%)" }], { duration: 600, delay: 150 + i * 55, easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" }));
      built.stage.querySelectorAll(".afl-ent-right").forEach((el, i) => el.animate([{ opacity: 0, transform: "translateY(-50%) translateX(14px)" }, { opacity: 1, transform: "translateY(-50%)" }], { duration: 600, delay: 150 + i * 55, easing: "cubic-bezier(.2,.75,.15,1)", fill: "backwards" }));
      built.stage.querySelectorAll(".afl-out").forEach((el, i) => el.animate([{ opacity: 0, transform: "translate(-50%, -50%) scale(.85)" }, { opacity: 1, transform: "translate(-50%, -50%)" }], { duration: 700, delay: 1100 + i * 120, easing: "cubic-bezier(.34,1.3,.5,1)", fill: "backwards" }));
    }
    setTimeout(() => this.fillNumbers(flow), motion && first ? 650 : 0);
    setTimeout(
      () => {
        if (!this.parts) return;
        this.parts.start();
        this.parts.burst(30);
      },
      motion && first ? 1500 : 0,
    );
  }

  fillNumbers(flow, from = null) {
    if (!this.stage) return;
    for (const el of this.stage.querySelectorAll(".afl-n[data-k]")) {
      const before = from && find(from, el.dataset.k);
      if (before) el.dataset.value = String(before.total);
      tweenNumber(el, find(flow, el.dataset.k)?.total ?? 0, num, 1100);
    }
    for (const o of OUTCOMES) {
      const el = this.stage.querySelector(`#afl-out-${o.key}`);
      if (!el) continue;
      if (from) el.dataset.value = String(from[o.key]);
      tweenNumber(el, flow[o.key], num, 1300);
    }
  }

  update(flow, opts = {}) {
    const prev = this.ref.flow;
    if ((opts.appsTotal ?? this.opts.appsTotal) !== this.opts.appsTotal || (opts.usersTotal ?? this.opts.usersTotal) !== this.opts.usersTotal || (opts.multi ?? this.opts.multi) !== this.opts.multi) {
      Object.assign(this.opts, opts);
      this.mount(flow, false);
      return;
    }
    const L = layoutFlow(flow);
    const same = this.stage && flow.total > 0 && flow.split === prev.split && L.view.y0 === this.ref.L.view.y0 && L.view.vh === this.ref.L.view.vh && ribbonKey(L) === ribbonKey(this.ref.L) && flow.apps.map((x) => x.key).join() === prev.apps.map((x) => x.key).join() && flow.users.map((x) => x.key).join() === prev.users.map((x) => x.key).join();
    if (!same) {
      this.mount(flow, false);
      return;
    }
    // Same apps, users and bands: morph everything to the new sizes in place.
    this.ref.flow = flow;
    this.ref.L = L;
    const st = this.stage;
    st.querySelectorAll("path.afl-rib").forEach((p, i) => {
      const d = L.ribbons[i].d;
      if (p.getAttribute("d") !== d) {
        p.style.d = `path("${d}")`;
        p.setAttribute("d", d);
      }
    });
    const bars = nodeBars(flow, L);
    st.querySelector(".afl-left .afl-nodes").replaceChildren(...bars.left);
    st.querySelector(".afl-right .afl-nodes").replaceChildren(...bars.right);
    st.querySelector(".afl-edges").replaceChildren(...gateEdges(flow, L));
    st.querySelectorAll(".afl-gate-seg").forEach((r, i) => {
      r.setAttribute("y", L.gate[i].top);
      r.setAttribute("height", L.gate[i].bottom - L.gate[i].top);
    });
    for (const [nodes, side] of [[L.left, "left"], [L.right, "right"]]) {
      for (const n of nodes) {
        const el = st.querySelector(`.afl-ent-${side}[data-ent="${CSS.escape(n.r.key)}"]`);
        if (!el) continue;
        el.style.top = pct(n.cy - L.view.y0, L.view.vh);
        el.querySelector(".afl-mini").replaceWith(miniBar(n.r));
      }
    }
    for (const g of L.gate) {
      const el = st.querySelector(`.afl-out[data-out="${g.key}"]`);
      el.style.top = pct((g.top + g.bottom) / 2 - L.view.y0, L.view.vh);
      el.querySelector(".afl-out-pct").textContent = share(g.value, flow.total);
    }
    st.setAttribute("aria-label", stageLabel(flow));
    this.parts?.setLanes(lanesFor(L), L.view);
    this.applyFocus();
    this.fillNumbers(flow, prev);
    if (flow.blocked > prev.blocked) {
      this.parts?.burst(Math.min(30, 6 + (flow.blocked - prev.blocked)));
      pulse(st.querySelector(".afl-out-blocked"), "var(--afl-blocked)");
    }
  }

  setHover(sel) {
    this.hovered = sel;
    this.applyFocus();
  }

  setPin(sel) {
    const same = sel && this.pinned && sel.kind === this.pinned.kind && sel.key === this.pinned.key;
    this.pinned = same ? null : sel;
    if (!this.pinned) hideTip();
    this.applyFocus();
  }

  applyFocus() {
    const st = this.stage;
    if (!st) return;
    const f = this.hovered ?? this.pinned;
    st.classList.toggle("afl-focusing", !!f);
    if (this.parts) this.parts.focus = f;
    const flow = this.ref.flow;
    const has = (key, out) => {
      const r = find(flow, key);
      return !!r && (!flow.split || (r[out] ?? 0) > 0);
    };
    const pin = this.pinned;
    for (const p of st.querySelectorAll(".afl-rib")) p.classList.toggle("on", !!f && (f.kind === "ent" ? p.dataset.ent === f.key : p.dataset.out === f.key));
    for (const n of st.querySelectorAll(".afl-node")) n.classList.toggle("on", !!f && (f.kind === "ent" ? n.dataset.ent === f.key : n.dataset.out === f.key));
    for (const el of st.querySelectorAll(".afl-ent")) {
      el.classList.toggle("on", !!f && (f.kind === "ent" ? el.dataset.ent === f.key : has(el.dataset.ent, f.key)));
      el.classList.toggle("pin", !!pin && pin.kind === "ent" && el.dataset.ent === pin.key);
    }
    for (const el of st.querySelectorAll(".afl-out, .afl-gate-seg, .afl-gate-edge")) {
      el.classList.toggle("on", !!f && (f.kind === "out" ? el.dataset.out === f.key : has(f.key, el.dataset.out)));
      el.classList.toggle("pin", !!pin && pin.kind === "out" && el.dataset.out === pin.key);
    }
  }

  destroy() {
    this.parts?.stop();
    this.parts = null;
    document.removeEventListener("keydown", this.onKey);
    hideTip();
  }
}
