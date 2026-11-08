// Case SLA and ageing board: lanes by status, a waiting-on-customer lane with
// the clock paused, age against the local target, the MDR auto-close
// countdown, and time to close split by who works the case. Cards glide
// between lanes when a case moves.

import { h, clear, setText } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, reconcile } from "../anim.js";
import { num, duration, hours, SEV_LABEL } from "../format.js";
import { api } from "../api.js";
import { freshChip, sevBadge, managedBadge, segmented, viewHead, gapNote, fitCount, isWall } from "./common.js";

const SEVS = ["critical", "high", "medium", "low", "info"];
let st = null;

function cardEl(c) {
  const el = h("article", { class: "card", tabindex: "0" });
  fillCard(el, c);
  return el;
}

function fillCard(el, c) {
  clear(el);
  el.className = `card card-${c.lane}${c.over ? " card-over" : ""}`;
  const progress = Math.min(100, (c.ageMs / Math.max(c.targetMs, 1)) * 100);
  let foot;
  if (c.lane === "resolved") {
    foot = h("p", { class: `card-foot ${c.metTarget ? "t-good" : "t-warn"}` }, icon(c.metTarget ? "check" : "warning", 13), h("span", { text: c.metTarget ? `Met ${duration(c.targetMs, 1)} target` : `Missed target by ${duration(c.timeToCloseMs - c.targetMs, 1)}` }));
  } else if (c.lane === "waiting") {
    foot = h(
      "p",
      { class: "card-foot" },
      icon("pause", 13),
      h("span", { text: `Paused at ${duration(c.pausedAtMs)} of ${duration(c.targetMs, 1)}` }),
      c.autoCloseInMs !== null ? h("span", { class: "autoclose", text: `auto-closes in ${duration(c.autoCloseInMs, 1)}` }) : null,
    );
  } else if (c.over) {
    foot = h("p", { class: "card-foot t-bad" }, icon("critical", 13), h("span", { text: `Over target by ${duration(c.ageMs - c.targetMs)}` }));
  } else if (progress > 75) {
    foot = h("p", { class: "card-foot t-warn" }, icon("clock", 13), h("span", { text: `${duration(c.targetMs - c.ageMs)} to target` }));
  }
  el.append(
    h("div", { class: "card-top" }, h("b", { class: "mono card-ref", text: c.ref }), sevBadge(c.severity), managedBadge(c.managedBy)),
    h("p", { class: "card-title", text: c.title }),
    h(
      "div",
      { class: "card-meta" },
      h("span", { class: `owner owner-${c.owner === "Unassigned" ? "none" : "set"}`, text: c.owner }),
      c.tenantName ? h("span", { class: "card-tenant", text: c.tenantName }) : null,
      h("span", { class: "card-age mono", text: c.lane === "resolved" ? duration(c.timeToCloseMs) : `${duration(c.ageMs)} of ${duration(c.targetMs, 1)}` }),
    ),
    c.lane === "resolved" ? null : h("div", { class: `age-bar${c.lane === "waiting" || c.lane === "hold" ? " paused" : ""}` }, h("i", { class: c.over ? "over" : progress > 75 ? "near" : "", style: { width: `${progress}%` } })),
    foot ?? null,
  );
  el.title = `${c.ref}: ${c.title} (${c.statusTitle})`;
}

function ttcBlock(label, who, v) {
  return h(
    "div",
    { class: "ttc reveal" },
    h("div", { class: "ttc-head" }, h("span", { text: label }), managedBadge(who)),
    h(
      "div",
      { class: "ttc-row" },
      h("div", {}, h("small", { text: "Median" }), h("b", { class: "num", text: v.median !== null ? duration(v.median) : "-" })),
      h("div", {}, h("small", { text: "90th pct" }), h("b", { class: "num", text: v.p90 !== null ? duration(v.p90) : "-" })),
      h("div", {}, h("small", { text: "Closed" }), h("b", { class: "num", text: num(v.n) })),
    ),
  );
}

function editTargets(d, ctx) {
  const dlg = h("dialog", { class: "dialog" });
  const inputs = {};
  const form = h(
    "form",
    { method: "dialog" },
    h("h2", { text: "Case targets" }),
    h("p", { class: "dim", text: "Hours from creation to close. The Sophos APIs have no SLA field, so the toolkit keeps these locally." }),
    h(
      "div",
      { class: "target-grid" },
      SEVS.map((k) => {
        inputs[k] = h("input", { type: "number", min: "1", max: "2160", step: "1", value: String(d.targets[k]), "aria-label": `${SEV_LABEL[k]} target in hours` });
        return h("label", {}, sevBadge(k), inputs[k], h("span", { class: "dim", text: "h" }));
      }),
    ),
    h(
      "div",
      { class: "dialog-actions" },
      h("button", { class: "btn btn-ghost", value: "cancel", text: "Cancel" }),
      h("button", {
        class: "btn btn-primary",
        value: "save",
        text: "Save targets",
        onclick: async (e) => {
          e.preventDefault();
          const targets = Object.fromEntries(SEVS.map((k) => [k, Number(inputs[k].value)]));
          await api.put("/api/settings", { targets });
          dlg.close();
          dlg.remove();
          ctx.toast("Targets saved");
          await ctx.refreshStatus();
          ctx.reload();
        },
      }),
    ),
  );
  dlg.append(form);
  document.body.append(dlg);
  dlg.showModal();
  dlg.addEventListener("close", () => dlg.remove());
}

function build(root, d, ctx) {
  const wrap = h("section", { class: "cases" });
  const managed = segmented(
    [
      ["all", "All"],
      ["mdr", "MDR"],
      ["self", "Self"],
    ],
    d.managed,
    (v) => ctx.setQuery({ managed: v }),
    "Who works the case",
  );
  const targets = h("span", { class: "targets dim", text: `Targets: ${SEVS.slice(0, 4).map((k) => `${SEV_LABEL[k]} ${hours(d.targets[k])}`).join(", ")}` });
  wrap.append(
    viewHead(
      "Case SLA and ageing",
      "",
      h("div", { class: "head-row" }, managed, targets, h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: () => editTargets(d, ctx) }, icon("clock", 14), "Edit targets"), freshChip(d.freshness)),
    ),
  );
  const sub = wrap.querySelector(".view-head .sub") ?? h("p", { class: "sub" });
  sub.id = "c-sub";
  const kpis = h("div", { class: "ttc-strip", id: "c-ttc" });
  wrap.append(kpis);
  wrap.append(h("p", { class: "gap-line reveal" }, icon("info", 13), h("span", { text: "Targets are set in the toolkit; no Sophos API carries an SLA. Sophos returns no status-change time either, so a waiting case's clock stops at its last update." })));
  const board = h("div", { class: "board reveal", id: "c-board" });
  for (const lane of d.board.lanes) {
    board.append(
      h(
        "section",
        { class: `lane lane-${lane.key}`, dataset: { lane: lane.key } },
        h("header", { class: "lane-head" }, h("h2", { text: lane.title }), h("b", { class: "lane-count num", text: "0" }), lane.note ? h("small", { class: "lane-note" }, icon(lane.key === "resolved" ? "clock" : "pause", 12), lane.note) : null),
        h("div", { class: "lane-cards" }),
        h("p", { class: "lane-more" }),
      ),
    );
  }
  wrap.append(board);
  root.append(wrap);
  return { wrap, board };
}

function fill(d) {
  const b = d.board;
  const sub = st.wrap.querySelector(".view-head .sub") ?? (() => {
    const p = h("p", { class: "sub" });
    st.wrap.querySelector(".view-head > div").append(p);
    return p;
  })();
  setText(sub, `${d.tenantName}, ${num(b.open)} open, ${num(b.overTarget)} over target, ${num(b.unassigned)} unassigned`);
  const ttc = document.getElementById("c-ttc");
  clear(ttc);
  ttc.append(ttcBlock("Time to close, last 30 d", "mdr", b.timeToClose.mdr), ttcBlock("Time to close, last 30 d", "self", b.timeToClose.self));
  ttc.append(
    h(
      "div",
      { class: "ttc reveal" },
      h("div", { class: "ttc-head" }, h("span", { text: "Open by severity" })),
      h("div", { class: "ttc-row" }, SEVS.slice(0, 4).map((k) => h("div", {}, h("small", { text: SEV_LABEL[k] }), h("b", { class: `num sevnum-${k}`, text: num(b.bySeverity[k]) })))),
    ),
  );
  for (const lane of b.lanes) {
    const sec = st.board.querySelector(`[data-lane="${lane.key}"]`);
    if (!sec) continue;
    tweenNumber(sec.querySelector(".lane-count"), lane.count, num, 800);
    const cards = sec.querySelector(".lane-cards");
    const shown = lane.cards.slice(0, st.perLane);
    reconcile(cards, shown, (c) => c.id, cardEl, fillCard, { fallbackRects: st.globalBefore, duration: 820 });
    const more = sec.querySelector(".lane-more");
    setText(more, lane.count > shown.length ? `+${num(lane.count - shown.length)} more` : lane.count === 0 ? "Nothing here" : "");
  }
  const notes = [...b.warnings];
  if (b.truncated) notes.push("More open cases exist than the toolkit reads per refresh; counts cover the first 1,000.");
  st.wrap.querySelector(".gap-extra")?.remove();
  if (notes.length) st.wrap.querySelector(".gap-line").after(h("div", { class: "gap-extra" }, notes.map((n) => gapNote(n))));
}

function perLaneFor() {
  if (!isWall() || !st) return 12;
  const firstCard = st.board.querySelector(".card");
  const cardH = (firstCard?.offsetHeight || 132) + 10;
  return fitCount(st.board.querySelector(".lane-cards"), cardH, 34, 2);
}

export default {
  id: "cases",
  mount(root, d, ctx) {
    st = build(root, d, ctx);
    st.perLane = 3;
    st.data = d;
    fill(d);
    // Measure real card heights, then fill a wall screen without scrolling.
    st.perLane = perLaneFor();
    if (st.perLane !== 3) fill(d);
  },
  update(d) {
    if (!st) return;
    // A card that changed lane glides from where it was on the board.
    st.globalBefore = new Map([...st.board.querySelectorAll(".card[data-key]")].map((el) => [el.dataset.key, el.getBoundingClientRect()]));
    fill(d);
    st.globalBefore = null;
    const fc = st.wrap.querySelector(".view-head .fresh");
    if (fc) fc.replaceWith(freshChip(d.freshness));
    st.data = d;
  },
  unmount() {
    st = null;
  },
  onResize() {
    if (!st) return;
    const n = perLaneFor();
    if (n !== st.perLane) {
      st.perLane = n;
      fill(st.data);
    }
  },
};
