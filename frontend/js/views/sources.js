// Data source health (view N3), read through Search GraphQL on Fusion
// tenants: every source (sensor type) that sent events in the last 7 days,
// how many, when the last one arrived, and how much landed unparsed in the
// generic schema. A source with nothing for 24 hours is quiet; one the last
// refresh saw that has gone missing is silent.

import { h, clear } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, pulse } from "../anim.js";
import { num, compact, ago, plural } from "../format.js";
import { sparkline, tipOn } from "../viz.js";
import { freshChip, panel, viewHead, gapNote, fitCount, isWall, searchChips, searchEmpty } from "./common.js";

let st = null;

const STATE = {
  live: { label: "Live", icon: "check", cls: "t-good" },
  quiet: { label: "Quiet 24 h+", icon: "warning", cls: "t-warn" },
  silent: { label: "Not seen this week", icon: "critical", cls: "t-bad" },
};

function kpi(id, label, cls = "") {
  return h(
    "section",
    { class: `kpi-tile reveal ${cls}`, id: `d-${id}` },
    h("div", { class: "kpi-tile-label", text: label }),
    h("b", { class: "kpi-tile-num num", text: "0" }),
    h("div", { class: "kpi-tile-foot" }),
  );
}

function setKpi(id, value, foot, alert, format = num) {
  const el = document.getElementById(`d-${id}`);
  if (!el) return;
  tweenNumber(el.querySelector(".kpi-tile-num"), value, format, 1000);
  const f = el.querySelector(".kpi-tile-foot");
  clear(f);
  if (foot) f.append(foot);
  el.classList.toggle("kpi-alert", !!alert);
}

function dayLabel(day) {
  const d = new Date(`${day}T00:00:00Z`);
  return d.toLocaleDateString("en-US", { weekday: "short", timeZone: "UTC" });
}

function build(root, d) {
  const wrap = h("section", { class: "sources" });
  wrap.append(viewHead("Data sources", `${d.tenantName}, last 7 days`, h("div", { class: "head-row" }, searchChips(d.model.search), d.freshness.length ? freshChip(d.freshness) : null)));
  if (!d.model.tenantsWithData) {
    wrap.append(searchEmpty(d));
    root.append(wrap);
    return { wrap, empty: true };
  }
  wrap.append(
    h(
      "div",
      { class: "kpi-row5" },
      kpi("sources", "Sources sending"),
      kpi("quiet", "Quiet 24 h or more"),
      kpi("silent", "Not seen this week", "kpi-bad"),
      kpi("events", "Events, 7 days"),
      kpi("unparsed", "Unparsed (generic)"),
    ),
  );
  const chart = panel("Events per day, all sources", { class: "p-days", icon: "pulse", right: h("span", { class: "dim", text: "UTC days" }) }, h("div", { class: "day-bars", id: "d-days" }));
  const table = h("table", { class: "dev-table src-table" });
  table.append(
    h("thead", {}, h("tr", {}, ["Source", d.scope === "all" ? "Tenant" : null, "State", "Last event", "Events, 7 days", "Per day", "Unparsed", "Schemas"].filter(Boolean).map((t) => h("th", { text: t })))),
    h("tbody", { id: "d-rows" }),
  );
  const list = panel("Sources", { class: "p-srcs", icon: "radar", right: h("span", { class: "dim", id: "d-count" }) }, h("div", { class: "table-wrap" }, table), h("div", { id: "d-note" }));
  wrap.append(h("div", { class: "src-grid" }, chart, list));
  root.append(wrap);
  return { wrap, empty: false };
}

function fill(d, first) {
  const m = d.model;
  const c = m.counts;
  setKpi("sources", c.live + c.quiet, h("span", { class: "dim", text: `${num(c.live)} live in the last 24 h` }));
  setKpi("quiet", c.quiet, h("span", { class: c.quiet ? "t-warn" : "t-good" }, icon(c.quiet ? "warning" : "check", 13), c.quiet ? " No events for a day" : " Every source sent today"), c.quiet > 0);
  setKpi("silent", c.silent, h("span", { class: c.silent ? "t-bad" : "dim", text: c.silent ? " Seen before, nothing in 7 days" : "None missing" }), c.silent > 0);
  setKpi("events", m.events7d, h("span", { class: "dim", text: `About ${compact(m.events7d / 7)} a day` }), false, compact);
  setKpi("unparsed", m.unparsed7d, h("span", { class: "dim", text: m.events7d ? `${((m.unparsed7d / m.events7d) * 100).toFixed(1)}% of events` : "" }), false, compact);

  // Events per day
  const box = document.getElementById("d-days");
  const max = Math.max(1, ...m.daily);
  const existing = [...box.children];
  m.daily.forEach((v, i) => {
    let col = existing[i];
    if (!col) {
      col = h("div", { class: "day-col", tabindex: "0" }, h("span", { class: "day-n num" }), h("span", { class: "day-track" }, h("i", { class: "day-fill" })), h("span", { class: "day-label" }));
      tipOn(col, () => [m.days[i] ?? "", [{ value: num(col._v), label: "events", color: "var(--accent)" }]]);
      box.append(col);
    }
    col._v = v;
    col.querySelector(".day-n").textContent = compact(v);
    col.querySelector(".day-label").textContent = i === m.daily.length - 1 ? "Today so far" : dayLabel(m.days[i] ?? "");
    const fillEl = col.querySelector(".day-fill");
    const target = `${Math.max(v ? 2 : 0, (v / max) * 100)}%`;
    if (first) {
      fillEl.style.height = "0%";
      requestAnimationFrame(() => requestAnimationFrame(() => {
        fillEl.style.transitionDelay = `${i * 60}ms`;
        fillEl.style.height = target;
      }));
    } else fillEl.style.height = target;
  });
  for (const extra of existing.slice(m.daily.length)) extra.remove();

  // Sources
  const rows = document.getElementById("d-rows");
  clear(rows);
  const room = isWall() ? fitCount(rows, 38, 20, 3) : m.rows.length;
  for (const r of m.rows.slice(0, room)) {
    const s = STATE[r.state];
    // Full days only: today has just begun and would read as a drop.
    const spark = sparkline(r.daily.length > 2 ? r.daily.slice(0, -1) : r.daily, { width: 110, height: 26 });
    spark.classList.add(`spark-${r.state}`);
    rows.append(
      h(
        "tr",
        { class: `src-${r.state}` },
        h("td", {}, h("b", { text: r.label }), h("small", { class: "mono dim", text: ` ${r.sensorType}` })),
        d.scope === "all" ? h("td", { class: "dim", text: r.tenantName ?? "" }) : null,
        h("td", {}, h("span", { class: s.cls }, icon(s.icon, 13), ` ${s.label}`)),
        h("td", { class: "mono", text: r.lastEventAt ? ago(r.lastEventAt) : "-" }),
        h("td", { class: "num", text: num(r.events7d) }),
        h("td", { class: "spark-cell" }, spark),
        h("td", { class: `num${r.unparsed7d ? " t-warn" : " dim"}`, text: r.unparsed7d ? num(r.unparsed7d) : "-" }),
        h("td", { class: "dim small schemas-cell", text: r.schemas.join(", ") }),
      ),
    );
  }
  if (!m.rows.length) rows.append(h("tr", {}, h("td", { colspan: "8", class: "calm-cell dim", text: "No source sent events in the window" })));
  const count = document.getElementById("d-count");
  count.textContent = m.rows.length > room ? `${num(room)} of ${plural(m.rows.length, "source")}` : plural(m.rows.length, "source");
  const note = document.getElementById("d-note");
  clear(note);
  note.append(gapNote("A source is a sensor type, such as Sophos endpoints or a firewall integration. Unparsed events land in the generic schema: stored and searchable, but no detection reads them."));

  const prev = st?.data?.model;
  if (!first && prev && (prev.counts.quiet !== c.quiet || prev.counts.silent !== c.silent)) pulse(document.getElementById(c.silent ? "d-silent" : "d-quiet"));
}

export default {
  id: "sources",
  mount(root, d, ctx) {
    st = build(root, d);
    st.data = d;
    st.root = root;
    if (!st.empty) fill(d, true);
    void ctx;
  },
  update(d, ctx) {
    if (!st) return;
    if (st.empty !== !d.model.tenantsWithData) {
      const root = st.root;
      clear(root);
      this.mount(root, d, ctx);
      return;
    }
    if (!st.empty) fill(d, false);
    const head = st.wrap.querySelector(".view-head .head-row");
    if (head) {
      clear(head);
      head.append(searchChips(d.model.search), d.freshness.length ? freshChip(d.freshness) : null);
    }
    st.data = d;
  },
  unmount() {
    st = null;
  },
};
