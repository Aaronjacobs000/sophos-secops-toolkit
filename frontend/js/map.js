// An offline world map from Natural Earth (public domain) through world-atlas
// TopoJSON, drawn as SVG with a Miller projection. No tiles, no network.

import { s, h, clear } from "./dom.js";
import { reducedMotion } from "./anim.js";
import { showTip, hideTip } from "./viz.js";
import { num } from "./format.js";

let worldPromise = null;

function decodeArcs(topo) {
  const [sx, sy] = topo.transform.scale;
  const [tx, ty] = topo.transform.translate;
  return topo.arcs.map((arc) => {
    let x = 0;
    let y = 0;
    return arc.map(([dx, dy]) => {
      x += dx;
      y += dy;
      return [x * sx + tx, y * sy + ty];
    });
  });
}

export function project([lon, lat]) {
  const phi = (Math.max(-80, Math.min(84, lat)) * Math.PI) / 180;
  return [lon, -(1.25 * Math.log(Math.tan(Math.PI / 4 + 0.4 * phi)) * 180) / Math.PI];
}

function ringPoints(arcs, indexes) {
  const pts = [];
  for (const i of indexes) {
    const arc = i < 0 ? [...arcs[~i]].reverse() : arcs[i];
    for (let k = pts.length ? 1 : 0; k < arc.length; k++) pts.push(arc[k]);
  }
  return pts;
}

async function loadWorld() {
  if (!worldPromise) {
    worldPromise = fetch("/vendor/countries-50m.json")
      .then((r) => r.json())
      .then((topo) => {
        const arcs = decodeArcs(topo);
        const shapes = [];
        for (const g of topo.objects.countries.geometries) {
          const polys = g.type === "Polygon" ? [g.arcs] : g.type === "MultiPolygon" ? g.arcs : [];
          for (const poly of polys) {
            const rings = poly.map((r) => ringPoints(arcs, r).map(project));
            const xs = rings[0].map((p) => p[0]);
            const ys = rings[0].map((p) => p[1]);
            shapes.push({ rings, bbox: [Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)] });
          }
        }
        return shapes;
      });
  }
  return worldPromise;
}

function ringPath(ring) {
  let d = "";
  let prevX = null;
  for (let i = 0; i < ring.length; i++) {
    const [x, y] = ring[i];
    // Break lines that wrap the antimeridian.
    if (prevX !== null && Math.abs(x - prevX) > 180) d += `M${x.toFixed(2)},${y.toFixed(2)}`;
    else d += `${i ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`;
    prevX = x;
  }
  return `${d}Z`;
}

/** The view box [x, y, width, height] fitted to projected points, or to opts.bbox when there are none. */
export function fitView(projected, opts = {}) {
  let [x0, y0, x1, y1] = opts.bbox ?? [110, -50, 180, -8];
  if (projected.length) {
    x0 = Math.min(...projected.map((p) => p.xy[0]));
    x1 = Math.max(...projected.map((p) => p.xy[0]));
    y0 = Math.min(...projected.map((p) => p.xy[1]));
    y1 = Math.max(...projected.map((p) => p.xy[1]));
  }
  const minSpanX = 46;
  const aspect = opts.aspect ?? 1.55;
  let cx = (x0 + x1) / 2;
  let cy = (y0 + y1) / 2;
  let spanX = Math.max(minSpanX, (x1 - x0) * 1.35);
  let spanY = Math.max(spanX / aspect, (y1 - y0) * 1.4);
  spanX = Math.max(spanX, spanY * aspect);
  spanY = spanX / aspect;
  return [cx - spanX / 2, cy - spanY / 2, spanX, spanY];
}

/** Bubble radius in view-box units: unit is a hundredth of the view width. */
export function radius(value, maxV, unit) {
  return unit * (0.9 + 2.6 * Math.sqrt(value / maxV));
}

function boxesOverlap(a, b) {
  return !(a[0] >= b[0] + b[2] || a[0] + a[2] <= b[0] || a[1] >= b[1] + b[3] || a[1] + a[3] <= b[1]);
}

function boxHitsCircle(box, [cx, cy], r) {
  const nx = Math.max(box[0], Math.min(cx, box[0] + box[2]));
  const ny = Math.max(box[1], Math.min(cy, box[1] + box[3]));
  return (nx - cx) ** 2 + (ny - cy) ** 2 < r * r;
}

/**
 * Labels for the largest points first. Each takes the first free spot: beside
 * its bubble (right, then left), above or below it, then up to four lines
 * further out on a leader line from the bubble's edge. A spot must stay on
 * the map and clear every label already placed, and first tries to clear every
 * other bubble too, so close bubbles (London and Dublin) both keep a label.
 * Returns [{ key, name, count, x, y, anchor, box, fs, leader: [x1, y1, x2, y2] | null }].
 */
export function placeLabels(projected, vb, unit, maxV) {
  const fs = unit * 2.4;
  const lineH = fs * 1.2;
  const gap = unit * 0.6;
  const bubbles = projected.map((p) => ({ key: p.key, xy: p.xy, r: radius(p.value, maxV, unit) }));
  const onMap = (b) => b[0] >= vb[0] && b[0] + b[2] <= vb[0] + vb[2] && b[1] >= vb[1] && b[1] + b[3] <= vb[1] + vb[3];
  const placed = [];
  const out = [];
  for (const p of [...projected].sort((a, b) => b.value - a.value)) {
    const r = radius(p.value, maxV, unit);
    const count = num(p.value);
    const w = `${p.label} ${count}`.length * fs * 0.55;
    const [px, py] = p.xy;
    // Each spot: the label box, where its text anchors, and the point a leader line would reach (null beside the bubble).
    const beside = (dir, dy) => {
      const x0 = dir > 0 ? px + r + gap : px - r - gap - w;
      const tip = Math.abs(dy) > r ? [dir > 0 ? x0 - unit * 0.3 : x0 + w + unit * 0.3, py + dy] : null;
      return { box: [x0, py + dy - lineH / 2, w, lineH], x: dir > 0 ? x0 : x0 + w, cy: py + dy, anchor: dir > 0 ? "start" : "end", tip };
    };
    const over = (dir, k) => {
      const cy = py + dir * (r + gap + lineH / 2 + k * lineH);
      const tip = k ? [px, cy - dir * (lineH / 2 + unit * 0.3)] : null;
      return { box: [px - w / 2, cy - lineH / 2, w, lineH], x: px, cy, anchor: "middle", tip };
    };
    const spots = [beside(1, 0), beside(-1, 0), over(-1, 0), over(1, 0)];
    for (let k = 1; k <= 4; k++) for (const dy of [-k * lineH, k * lineH]) spots.push(beside(1, dy), beside(-1, dy));
    for (let k = 1; k <= 3; k++) spots.push(over(-1, k), over(1, k));
    const free = (c, clearBubbles) => onMap(c.box) && !placed.some((b) => boxesOverlap(c.box, b)) && (!clearBubbles || !bubbles.some((b) => b.key !== p.key && boxHitsCircle(c.box, b.xy, b.r)));
    const spot = spots.find((c) => free(c, true)) ?? spots.find((c) => free(c, false));
    if (!spot) continue;
    placed.push(spot.box);
    let leader = null;
    if (spot.tip) {
      // From the bubble's edge toward the label's near end.
      const [tx, ty] = spot.tip;
      const d = Math.hypot(tx - px, ty - py) || 1;
      leader = [px + ((tx - px) / d) * r, py + ((ty - py) / d) * r, tx, ty];
    }
    out.push({ key: p.key, name: p.label, count, x: spot.x, y: spot.cy + fs * 0.35, anchor: spot.anchor, box: spot.box, fs, leader });
  }
  return out;
}

/**
 * Renders points on a map fitted to them. points: [{ key, label, lat, lon,
 * value, state: "bad"|"suspicious"|"good", detail }].
 */
export async function renderMap(container, points, opts = {}) {
  const shapes = await loadWorld();
  const projected = points.map((p) => ({ ...p, xy: project([p.lon, p.lat]) }));
  const vb = fitView(projected, opts);
  const spanX = vb[2];
  let svg = container.querySelector("svg.map");
  const first = !svg;
  if (!svg) {
    svg = s("svg", { class: "map", role: "img", "aria-label": opts.label ?? "Map" });
    svg.append(s("g", { class: "land" }), s("g", { class: "graticule" }), s("g", { class: "points" }));
    container.append(svg);
  }
  svg.setAttribute("viewBox", vb.map((v) => v.toFixed(2)).join(" "));
  const land = svg.querySelector(".land");
  if (first || land.dataset.vb !== vb.join()) {
    clear(land);
    land.dataset.vb = vb.join();
    const [vx0, vy0, vw, vh] = vb;
    for (const shape of shapes) {
      const [a, b, c, d] = shape.bbox;
      if (c < vx0 - 5 || a > vx0 + vw + 5 || d < vy0 - 5 || b > vy0 + vh + 5) continue;
      land.append(s("path", { d: shape.rings.map(ringPath).join(""), "vector-effect": "non-scaling-stroke" }));
    }
    const grat = svg.querySelector(".graticule");
    clear(grat);
    for (let lon = Math.ceil(vx0 / 10) * 10; lon < vx0 + vw; lon += 10) grat.append(s("line", { x1: lon, x2: lon, y1: vy0, y2: vy0 + vh, "vector-effect": "non-scaling-stroke" }));
    for (let lat = -80; lat <= 80; lat += 10) {
      const [, y] = project([0, lat]);
      if (y > vy0 && y < vy0 + vh) grat.append(s("line", { x1: vx0, x2: vx0 + vw, y1: y, y2: y, "vector-effect": "non-scaling-stroke" }));
    }
  }
  const g = svg.querySelector(".points");
  clear(g);
  const maxV = Math.max(1, ...projected.map((p) => p.value));
  const unit = spanX / 100;
  const sorted = [...projected].sort((a, b) => a.value - b.value);
  sorted.forEach((p, i) => {
    const r = radius(p.value, maxV, unit);
    const grp = s("g", { class: `pt pt-${p.state}`, tabindex: "0", transform: `translate(${p.xy[0]},${p.xy[1]})` });
    if (p.state === "bad") grp.append(s("circle", { class: "pt-ring", r }));
    grp.append(s("circle", { class: "pt-dot", r }));
    grp.addEventListener("pointermove", (e) => showTip(e, p.label, p.detail ?? [{ value: num(p.value), label: "devices" }]));
    grp.addEventListener("pointerleave", hideTip);
    g.append(grp);
    if (!reducedMotion() && first) {
      grp.firstChild.animate([{ transform: "scale(0)", opacity: 0 }, { transform: "scale(1)", opacity: 1 }], { duration: 650, delay: 300 + i * 70, easing: "cubic-bezier(.34,1.5,.5,1)", fill: "backwards" });
    }
  });
  for (const l of placeLabels(projected, vb, unit, maxV)) {
    const fs = l.fs;
    if (l.leader) {
      const [x1, y1, x2, y2] = l.leader;
      const line = s("line", { class: "pt-leader", x1, y1, x2, y2, "vector-effect": "non-scaling-stroke" });
      g.append(line);
      if (!reducedMotion() && first) line.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 500, delay: 900, fill: "backwards" });
    }
    const t = s("text", { class: "pt-label", x: l.x, "text-anchor": l.anchor, y: l.y, "font-size": fs.toFixed(2), "stroke-width": (fs * 0.22).toFixed(3) });
    t.append(s("tspan", { class: "pt-name", text: `${l.name} ` }), s("tspan", { class: "pt-count", text: l.count }));
    g.append(t);
    if (!reducedMotion() && first) t.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 500, delay: 900, fill: "backwards" });
  }
  if (!projected.length) {
    container.querySelector(".map-empty")?.remove();
    container.append(h("div", { class: "map-empty", text: opts.empty ?? "No locations to show." }));
  } else container.querySelector(".map-empty")?.remove();
}
