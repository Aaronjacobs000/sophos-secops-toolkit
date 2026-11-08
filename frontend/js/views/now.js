// SOC "now": the wall a team glances at. Open cases by severity, who has no
// owner, what waits on the customer, signals in the last hour, the case most
// over its target, and how fresh each feed is.

import { h, clear, setText } from "../dom.js";
import { icon, SEV_ICON } from "../icons.js";
import { tweenNumber, pulse } from "../anim.js";
import { num, duration, SEV_LABEL, ago, hours } from "../format.js";
import { hourlyChart, updateHourly, stackBar } from "../viz.js";
import { freshChip, sevBadge, every, viewHead, genBadge } from "./common.js";

const SEVS = ["critical", "high", "medium", "low", "info"];
let st = null;

function tile(cls, title, ...body) {
  return h("section", { class: `tile reveal ${cls}` }, h("header", { class: "tile-head" }, h("h2", { text: title }), h("span", { class: "tile-fresh" })), ...body);
}

function build(root, d) {
  const wrap = h("section", { class: "now" });
  wrap.append(
    viewHead(d.tenantName, d.scope === "all" ? `Across ${num(d.tenantCount)} tenants` : "SOC now", h("div", { class: "head-row" }, genBadge(d.generation), freshChip(d.freshness))),
  );
  const grid = h("div", { class: "now-grid" });

  // 1. open by severity
  const sevRow = h(
    "div",
    { class: "sev-row" },
    SEVS.map((k) =>
      h("div", { class: `sev-col sev-${k}` }, h("span", { class: "sev-col-label" }, icon(SEV_ICON[k], 14), SEV_LABEL[k]), h("b", { class: "sev-col-num num", dataset: { sev: k }, text: "0" })),
    ),
  );
  const open = tile(
    "t-open",
    "Open cases by severity",
    h("div", { class: "open-main" }, h("div", { class: "hero" }, h("b", { class: "hero-num num", id: "n-open", style: { viewTransitionName: "kpi-open" }, text: "0" }), h("span", { class: "hero-unit", text: "open" })), sevRow),
    h("div", { class: "open-bar", id: "n-open-bar" }),
    h("p", { class: "tile-note", id: "n-open-note" }),
  );
  // 2. unassigned
  const unassigned = tile(
    "t-unassigned",
    "Unassigned",
    h("b", { class: "big-num num", id: "n-unassigned", text: "0" }),
    h("div", { class: "tile-lines", id: "n-unassigned-lines" }),
    h("p", { class: "tile-foot", id: "n-unassigned-foot" }),
  );
  // 3. waiting on customer
  const waiting = tile(
    "t-waiting",
    "Waiting on customer",
    h("b", { class: "big-num num", id: "n-waiting", text: "0" }),
    h("p", { class: "tile-line" }, icon("pause", 15), h("span", { text: "Case clock paused" })),
    h("p", { class: "tile-foot", id: "n-waiting-foot" }),
  );
  // 4. signals last hour
  const chart = h("div", { class: "now-chart" });
  const signals = tile(
    "t-signals",
    `New ${d.wall.signals.label.toLowerCase()}, last hour`,
    h("div", { class: "sig-head" }, h("b", { class: "big-num num", id: "n-sig", style: { viewTransitionName: "kpi-signals" }, text: "0" }), h("span", { class: "sig-vs", id: "n-sig-vs" })),
    chart,
  );
  // 5. oldest open case
  const oldest = tile("t-oldest", "Most over target", h("div", { id: "n-oldest" }));
  // 6. freshness
  const fresh = tile("t-fresh", "Data freshness", h("div", { class: "fresh-list", id: "n-fresh" }));

  grid.append(open, unassigned, waiting, signals, oldest, fresh);
  wrap.append(grid);
  root.append(wrap);
  hourlyChart(chart, d.wall.signals.hourly, { height: 210, label: "Signals per hour, last 24 hours" });
  return { root, wrap, chart };
}

function fill(d, first) {
  const w = d.wall;
  tweenNumber(document.getElementById("n-open"), w.open, num, 1100);
  for (const el of document.querySelectorAll(".sev-col-num")) tweenNumber(el, w.bySeverity[el.dataset.sev] ?? 0, num, 1100);
  const bar = document.getElementById("n-open-bar");
  stackBar(bar, SEVS.map((k) => ({ key: k, label: SEV_LABEL[k], value: w.bySeverity[k] ?? 0, color: `var(--sev-${k})` })), { title: "Open cases" });
  setText(document.getElementById("n-open-note"), `Targets: ${SEVS.slice(0, 4).map((k) => `${SEV_LABEL[k]} ${hours(d.targets[k])}`).join(", ")}. Set in Setup; the Sophos APIs carry no SLA field.`);

  const un = document.getElementById("n-unassigned");
  tweenNumber(un, w.unassigned.total, num, 1100);
  un.closest(".tile").classList.toggle("tile-alert", w.unassigned.total > 0 && (w.unassigned.bySeverity.critical > 0 || w.unassigned.bySeverity.high > 0));
  const lines = document.getElementById("n-unassigned-lines");
  clear(lines);
  const top = SEVS.filter((k) => (w.unassigned.bySeverity[k] ?? 0) > 0).slice(0, 3);
  if (w.unassigned.bySeverity.critical) lines.append(h("p", { class: "tile-line t-bad" }, icon("critical", 16), h("span", { text: `${num(w.unassigned.bySeverity.critical)} critical ${w.unassigned.bySeverity.critical === 1 ? "needs" : "need"} an owner` })));
  lines.append(h("p", { class: "tile-line" }, ...top.filter((k) => k !== "critical").map((k) => h("span", { class: `inline-sev sev-${k}` }, icon(SEV_ICON[k], 13), `${num(w.unassigned.bySeverity[k])} ${SEV_LABEL[k]}`))));
  setText(document.getElementById("n-unassigned-foot"), w.unassigned.oldestMs ? `Oldest unassigned ${duration(w.unassigned.oldestMs)}` : "Every open case has an owner");

  tweenNumber(document.getElementById("n-waiting"), w.waiting.total, num, 1100);
  setText(document.getElementById("n-waiting-foot"), w.waiting.autoCloseSoon ? `${num(w.waiting.autoCloseSoon)} MDR ${w.waiting.autoCloseSoon === 1 ? "case auto-closes" : "cases auto-close"} within 2 d` : w.waiting.mdr ? `${num(w.waiting.mdr)} with Sophos MDR` : "Nothing waiting on you");

  tweenNumber(document.getElementById("n-sig"), w.signals.lastHour, num, 1100);
  const avg = w.signals.avgPerHour;
  const delta = avg ? Math.round(((w.signals.lastHour - avg) / avg) * 100) : null;
  const vs = document.getElementById("n-sig-vs");
  clear(vs);
  if (delta !== null) vs.append(h("b", { class: delta > 25 ? "t-warn" : "", text: `${delta > 0 ? "+" : ""}${delta}%` }), ` vs 24 h average of ${num(avg)}`);
  else vs.append(`${num(w.signals.total)} in 24 h`);
  if (!first) updateHourly(st.chart, w.signals.hourly);

  const ob = document.getElementById("n-oldest");
  clear(ob);
  const c = w.oldest;
  if (!c) ob.append(h("p", { class: "calm" }, icon("check", 22), h("span", { text: "No open case being worked" })));
  else {
    const over = c.ageMs - c.targetMs;
    ob.closest(".tile").classList.toggle("tile-alert", c.over);
    ob.append(
      h("b", { class: "huge-dur", text: duration(c.ageMs) }),
      h("p", { class: `tile-line ${c.over ? "t-bad" : "t-warn"}` }, icon(c.over ? "critical" : "clock", 16), h("span", { text: c.over ? `Over target by ${duration(over)}` : `${duration(-over)} to target` })),
      h(
        "div",
        { class: "target-bar" },
        h("i", { class: c.over ? "over" : "", style: { width: `${Math.min(100, (c.ageMs / Math.max(c.ageMs, c.targetMs)) * 100)}%` } }),
        (() => {
          const at = Math.min(100, (c.targetMs / Math.max(c.ageMs, c.targetMs)) * 100);
          return h("span", { class: `target-mark${at < 12 ? " at-start" : at > 88 ? " at-end" : ""}`, style: { left: `${at}%` } }, h("small", { text: `Target ${duration(c.targetMs, 1)}` }));
        })(),
      ),
      h("p", { class: "case-line" }, h("b", { class: "mono", text: c.ref }), " ", sevBadge(c.severity), " ", h("span", { text: c.title }), c.tenantName ? h("small", { class: "dim", text: ` · ${c.tenantName}` }) : null),
    );
  }

  const fl = document.getElementById("n-fresh");
  clear(fl);
  for (const r of d.freshness) {
    fl.append(
      h(
        "div",
        { class: `fresh-row fresh-${r.state}` },
        icon(r.state === "failed" ? "offline" : r.state === "aging" ? "warning" : "check", 18),
        h("div", { class: "fresh-name" }, h("b", { text: r.label }), h("small", { text: `every ${every(r.intervalMs)}${r.coverage.of > 1 ? ` · ${num(r.coverage.have)} of ${num(r.coverage.of)} tenants` : ""}` })),
        h(
          "div",
          { class: "fresh-when" },
          r.state === "failed" ? h("b", { text: r.fetchedAt ? `Feed failed, showing cached ${ago(r.fetchedAt)}` : "Feed failed" }) : h("b", { class: "mono", dataset: { ago: r.fetchedAt ?? "" }, text: r.fetchedAt ? ago(r.fetchedAt) : "loading" }),
        ),
      ),
    );
  }
  for (const t of document.querySelectorAll(".now .tile-fresh")) {
    clear(t);
  }
}

export default {
  id: "now",
  mount(root, d) {
    st = build(root, d);
    st.data = d;
    fill(d, true);
  },
  update(d) {
    if (!st) return;
    const prev = st.data;
    fill(d, false);
    if (prev && d.wall.open !== prev.wall.open) pulse(document.querySelector(".t-open"));
    if (prev && d.wall.signals.lastHour !== prev.wall.signals.lastHour) pulse(document.querySelector(".t-signals"));
    const fc = st.wrap.querySelector(".view-head .fresh");
    if (fc) fc.replaceWith(freshChip(d.freshness));
    st.data = d;
  },
  unmount() {
    st = null;
  },
};
