import test from "node:test";
import assert from "node:assert/strict";

// map.js loads the DOM and motion helpers; the placement functions need neither.
globalThis.Element ??= class {};
globalThis.window ??= { matchMedia: () => ({ matches: true, addEventListener() {} }) };
const { project, fitView, radius, placeLabels } = await import("../frontend/js/map.js");

function layout(points, opts) {
  const projected = points.map(([label, lat, lon, value]) => ({ key: label, label, value, xy: project([lon, lat]) }));
  const vb = fitView(projected, opts);
  const unit = vb[2] / 100;
  const maxV = Math.max(1, ...projected.map((p) => p.value));
  return { projected, vb, unit, maxV, labels: placeLabels(projected, vb, unit, maxV) };
}

const overlaps = (a, b) => !(a[0] >= b[0] + b[2] || a[0] + a[2] <= b[0] || a[1] >= b[1] + b[3] || a[1] + a[3] <= b[1]);
function hitsCircle(box, [cx, cy], r) {
  const nx = Math.max(box[0], Math.min(cx, box[0] + box[2]));
  const ny = Math.max(box[1], Math.min(cy, box[1] + box[3]));
  return (nx - cx) ** 2 + (ny - cy) ** 2 < r * r;
}

function assertReadable({ projected, vb, unit, maxV, labels }) {
  for (const [i, a] of labels.entries()) {
    assert.ok(a.box[0] >= vb[0] && a.box[0] + a.box[2] <= vb[0] + vb[2] && a.box[1] >= vb[1] && a.box[1] + a.box[3] <= vb[1] + vb[3], `${a.key} stays on the map`);
    for (const b of labels.slice(i + 1)) assert.ok(!overlaps(a.box, b.box), `${a.key} and ${b.key} labels overlap`);
    for (const p of projected) if (p.key !== a.key) assert.ok(!hitsCircle(a.box, p.xy, radius(p.value, maxV, unit)), `${a.key} label covers the ${p.key} bubble`);
  }
}

test("close bubbles keep readable labels: London and Dublin both labelled", () => {
  // The sign-in map that hid Dublin (29/10/2026): London and Dublin bubbles touch.
  const l = layout([
    ["London", 51.5072, -0.127586, 11952],
    ["Dublin", 53.3498, -6.26031, 7739],
    ["Toronto (North York)", 43.7289, -79.3293, 2367],
    ["Council Bluffs", 41.2619, -95.8608, 870],
    ["Cardiff", 51.4837, -3.1681, 273],
    ["San Jose", 37.3387, -121.885, 9],
  ]);
  const keys = l.labels.map((x) => x.key);
  for (const k of ["London", "Dublin", "Toronto (North York)", "Council Bluffs"]) assert.ok(keys.includes(k), `${k} is labelled`);
  assertReadable(l);
});

test("a tight cluster gets labels pulled out on leader lines rather than dropped", () => {
  const l = layout([
    ["Sydney", -33.87, 151.21, 900],
    ["Parramatta", -33.81, 151.0, 700],
    ["Chatswood", -33.8, 151.18, 500],
    ["Bondi", -33.89, 151.27, 300],
    ["Perth", -31.95, 115.86, 200],
  ]);
  assert.equal(l.labels.length, 5, "every point is labelled");
  assertReadable(l);
  const led = l.labels.filter((x) => x.leader);
  assert.ok(led.length >= 1, "at least one label sits away from its bubble on a leader line");
  for (const x of led) {
    const p = l.projected.find((q) => q.key === x.key);
    const [x1, y1] = x.leader;
    const d = Math.hypot(x1 - p.xy[0], y1 - p.xy[1]);
    assert.ok(Math.abs(d - radius(p.value, l.maxV, l.unit)) < 1e-6, `${x.key} leader starts on its bubble edge`);
  }
});
