// The MSP wall: one tile per tenant, worst first. Tiles fill in as the
// scheduler reaches each tenant and glide to their new place when a tenant's
// state changes. Healthy tenants fold away on a wall screen.

import { h, clear, setText } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, reconcile } from "../anim.js";
import { num, ago, compact } from "../format.js";
import { stackBar } from "../viz.js";
import { freshChip, genBadge, viewHead, fitCount, isWall } from "./common.js";
import { store } from "../api.js";

let st = null;

const STATE_ICON = { critical: "critical", warning: "warning", healthy: "check", pending: "clock" };
const FILTERS = [
  ["all", "All"],
  ["critical", "Critical"],
  ["warning", "Warning"],
  ["classic", "Classic"],
  ["fusion", "Fusion"],
  ["mdr", "MDR"],
];

function tileEl(t) {
  const el = h("a", { class: "mtile", href: `#/now?tenant=${encodeURIComponent(t.id)}` });
  fillTile(el, t);
  return el;
}

function fillTile(el, t) {
  const sig = `${t.state}|${t.headline}|${t.metrics.map((m) => m.value).join(",")}|${t.generation}|${t.errors}|${t.name}|${t.ai ? `${t.ai.text}|${t.ai.blocked}|${t.ai.warned}` : ""}`;
  if (el.dataset.sig === sig) {
    const ageEl = el.querySelector(".mtile-age");
    if (ageEl && t.fetchedAt) setText(ageEl, ago(t.fetchedAt));
    return;
  }
  const changed = el.dataset.sig !== undefined && el.dataset.state !== t.state;
  el.dataset.sig = sig;
  el.dataset.state = t.state;
  el.href = `#/now?tenant=${encodeURIComponent(t.id)}`;
  clear(el);
  el.className = `mtile mtile-${t.state}${t.errors ? " mtile-err" : ""}`;
  el.append(
    h("div", { class: "mtile-name", text: t.name }),
    h("div", { class: "mtile-head" }, icon(STATE_ICON[t.state], 14), h("span", { text: t.headline })),
    h(
      "div",
      { class: "mtile-metrics" },
      t.metrics.map((m) => h("div", { class: `m m-${m.state}` }, h("small", { text: m.label }), h("b", { class: "num", text: m.value }))),
    ),
    aiLine(t.ai),
    h(
      "div",
      { class: "mtile-foot" },
      genBadge(t.generation),
      t.mdr ? h("span", { class: "who who-mdr", text: "MDR" }) : null,
      t.errors ? h("span", { class: "mtile-cached" }, icon("offline", 12), "showing cached") : null,
      h("span", { class: "mtile-age mono", text: t.fetchedAt ? ago(t.fetchedAt) : "queued" }),
    ),
  );
  if (changed && !document.documentElement.classList.contains("no-motion")) {
    el.animate([{ outline: "2px solid var(--accent)", outlineOffset: "4px" }, { outline: "2px solid transparent", outlineOffset: "10px" }], { duration: 1100, easing: "ease-out" });
  }
}

/** The AI Defense line: apps and users, then blocked and warned in the last 7 days; or why there is none. */
function aiLine(ai) {
  if (!ai) return null;
  if (ai.state !== "active") return h("div", { class: "mtile-ai mtile-ai-off", title: "AI Defense, last 7 days" }, icon("spark", 12), h("span", { text: ai.text }));
  return h(
    "div",
    { class: "mtile-ai", title: `AI Defense, last 7 days: ${num(ai.apps)} AI apps, ${num(ai.users)} users, ${num(ai.blocked)} blocked, ${num(ai.warned)} warned` },
    h("div", { class: "mtile-ai-row" }, icon("spark", 12), h("span", { text: ai.text })),
    h("div", { class: "mtile-ai-row mtile-ai-acts" }, h("span", { class: ai.blocked ? "t-bad" : "dim" }, h("b", { class: "num", text: compact(ai.blocked) }), " blocked"), h("span", { class: ai.warned ? "t-warn" : "dim" }, h("b", { class: "num", text: compact(ai.warned) }), " warned")),
  );
}

function matches(t, f) {
  if (f === "all") return true;
  if (f === "critical" || f === "warning") return t.state === f;
  if (f === "classic" || f === "fusion") return t.generation === f;
  if (f === "mdr") return t.mdr;
  return true;
}

function build(root, d) {
  const wrap = h("section", { class: "msp" });
  wrap.append(viewHead("MSP wall", "", h("div", { class: "head-row" }, h("span", { class: "dim", text: "Sorted worst first" }), freshChip(d.freshness))));
  const summary = h(
    "div",
    { class: "msp-summary reveal" },
    h("div", { class: "msp-bar", id: "m-bar" }),
    h(
      "div",
      { class: "msp-counts" },
      h("span", { class: "mc mc-critical" }, icon("critical", 15), h("b", { class: "num", id: "m-c", text: "0" }), "Critical"),
      h("span", { class: "mc mc-warning" }, icon("warning", 15), h("b", { class: "num", id: "m-w", text: "0" }), "Warning"),
      h("span", { class: "mc mc-healthy" }, icon("check", 15), h("b", { class: "num", id: "m-h", text: "0" }), "Healthy"),
    ),
  );
  const filters = h("div", { class: "msp-filters reveal", role: "group", "aria-label": "Filter tenants" });
  const grid = h("div", { class: "msp-grid", id: "m-grid" });
  const more = h("div", { class: "msp-more", id: "m-more" });
  const progress = h("div", { class: "msp-progress", id: "m-progress" });
  wrap.append(summary, filters, progress, grid, more, h("p", { class: "gap-line" }, icon("info", 13), h("span", { text: "Tenant list, licences and API generation daily; health every 6 h; endpoints every 2 h; cases and alerts hourly, and every 5 to 10 min for the worst 8 tenants and any tenant open on another screen; AI Defense hourly, daily for a tenant without it." })));
  root.append(wrap);
  return { wrap, grid, filters, more, progress };
}

function fill(d) {
  const c = d.counts;
  tweenNumber(document.getElementById("m-c"), c.critical, num);
  tweenNumber(document.getElementById("m-w"), c.warning, num);
  tweenNumber(document.getElementById("m-h"), c.healthy, num);
  stackBar(
    document.getElementById("m-bar"),
    [
      { key: "c", label: "Critical", value: c.critical, color: "var(--bad)" },
      { key: "w", label: "Warning", value: c.warning, color: "var(--warn)" },
      { key: "h", label: "Healthy", value: c.healthy, color: "var(--ink-4)" },
      { key: "p", label: "Loading", value: c.pending, color: "var(--panel-3)" },
    ],
    { title: "Tenants" },
  );
  const sub = st.wrap.querySelector(".view-head h1");
  if (sub && !st.wrap.querySelector(".view-head .sub")) st.wrap.querySelector(".view-head > div").append(h("p", { class: "sub", id: "m-sub" }));
  setText(document.getElementById("m-sub"), `${num(c.critical)} ${c.critical === 1 ? "tenant needs" : "tenants need"} action now, ${num(c.total)} in total${d.tenantsOverCap ? ` (${num(d.tenantsOverCap)} more over the per-install limit)` : ""}`);

  clear(st.filters);
  const counts = { all: c.total, critical: c.critical, warning: c.warning, classic: c.classic, fusion: c.fusion, mdr: c.mdr };
  for (const [k, label] of FILTERS) {
    st.filters.append(
      h(
        "button",
        {
          type: "button",
          class: `fchip${st.filter === k ? " on" : ""} fchip-${k}`,
          "aria-pressed": st.filter === k ? "true" : "false",
          onclick: () => {
            st.filter = k;
            store.set("msp-filter", k);
            fill(st.data);
          },
        },
        k === "critical" ? icon("critical", 13) : k === "warning" ? icon("warning", 13) : null,
        h("span", { text: label }),
        h("b", { class: "num", text: num(counts[k]) }),
      ),
    );
  }

  const p = d.progress;
  clear(st.progress);
  if (p.done < p.total) {
    st.progress.append(
      h("span", { class: "spin", "aria-hidden": "true" }),
      h("span", { text: `Reading tenants: ${num(p.done)} of ${num(p.total)} loaded. Tiles fill in as each tenant answers, within the API rate limit.` }),
      h("span", { class: "msp-progress-track" }, h("i", { style: { width: `${(p.done / Math.max(1, p.total)) * 100}%` } })),
    );
  }

  const wall = isWall();
  let tiles = d.tiles.filter((t) => matches(t, st.filter));
  let folded = 0;
  let pageNote = null;
  const limit = wall ? wallCapacity() : 64;
  if (st.filter === "all" || wall) {
    const notHealthy = tiles.filter((t) => t.state !== "healthy");
    const healthy = tiles.filter((t) => t.state === "healthy");
    if (wall && notHealthy.length > limit) {
      // Nobody scrolls a wall: page through the tenants that need attention.
      const pages = Math.ceil(notHealthy.length / limit);
      st.page %= pages;
      tiles = notHealthy.slice(st.page * limit, (st.page + 1) * limit);
      pageNote = `Page ${st.page + 1} of ${pages} · ${num(notHealthy.length)} tenants need attention`;
      folded = healthy.length;
    } else {
      const room = Math.max(0, limit - notHealthy.length);
      folded = healthy.length > room && !st.showAll ? healthy.length - room : 0;
      tiles = st.showAll && !wall ? tiles : [...notHealthy.slice(0, limit), ...healthy.slice(0, room)];
    }
  }
  reconcile(st.grid, tiles, (t) => t.id, tileEl, fillTile, { duration: 760 });
  clear(st.more);
  if (folded > 0 || pageNote) {
    st.more.append(
      icon("check", 15),
      pageNote ? h("span", { class: "msp-page", text: `${pageNote} · ` }) : null,
      h("span", {}, h("b", { text: `+${num(folded)} healthy` }), " tenants folded away "),
      wall ? null : h("button", { class: "btn btn-ghost btn-sm", type: "button", text: `Show all ${num(d.tiles.length)}`, onclick: () => { st.showAll = true; fill(st.data); } }),
    );
  }
}

function wallCapacity() {
  const gridW = st.grid.getBoundingClientRect().width || window.innerWidth - 44;
  const cols = Math.max(2, Math.floor((gridW + 12) / (220 + 12)));
  const tileH = (st.grid.firstElementChild?.offsetHeight || 150) + 12;
  const rows = fitCount(st.grid, tileH, 64, 2);
  return cols * rows;
}

export default {
  id: "msp",
  mount(root, d) {
    st = build(root, d);
    st.filter = store.get("msp-filter", "all");
    st.showAll = false;
    st.page = 0;
    st.data = d;
    fill(d);
    st.pager = setInterval(() => {
      if (!st || !isWall()) return;
      st.page++;
      fill(st.data);
    }, 12_000);
  },
  update(d) {
    if (!st) return;
    st.data = d;
    fill(d);
    const fc = st.wrap.querySelector(".view-head .fresh");
    if (fc) fc.replaceWith(freshChip(d.freshness));
  },
  unmount() {
    if (st?.pager) clearInterval(st.pager);
    st = null;
  },
  onResize() {
    if (st) fill(st.data);
  },
};
