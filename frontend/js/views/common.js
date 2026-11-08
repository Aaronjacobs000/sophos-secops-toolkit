// Pieces several screens share: freshness chips, severity and generation
// badges, panel frames.

import { h } from "../dom.js";
import { icon, SEV_ICON } from "../icons.js";
import { ago, clock, SEV_LABEL, num } from "../format.js";
import { showTip, hideTip } from "../viz.js";

/**
 * One chip for a set of datasets: the oldest "as of" age. Amber when older
 * than twice the refresh interval, hatched with "showing cached" when the
 * last refresh failed, "loading" before the first answer.
 */
export function freshChip(rows, opts = {}) {
  const list = (rows ?? []).filter((r) => !opts.only || opts.only.includes(r.dataset));
  const have = list.filter((r) => r.fetchedAt);
  const oldest = have.length ? Math.min(...have.map((r) => r.fetchedAt)) : null;
  const failed = list.some((r) => r.state === "failed");
  const aging = list.some((r) => r.state === "aging");
  const partial = list.filter((r) => r.state === "partial").reduce((a, r) => a + r.errors, 0);
  const pending = list.some((r) => r.state === "pending") && !have.length;
  const running = list.some((r) => r.running);
  const cls = failed ? "fresh fresh-failed" : aging || partial ? "fresh fresh-aging" : pending ? "fresh fresh-pending" : "fresh";
  const chip = h(
    "span",
    { class: cls, tabindex: "0" },
    icon(failed ? "offline" : "clock", 12),
    pending ? h("span", { text: "loading" }) : failed && oldest ? h("span", { text: `showing cached ${clock(oldest)}` }) : h("span", { dataset: { ago: oldest ?? "" }, text: ago(oldest) }),
    partial && !failed ? h("span", { text: `· ${partial} failed` }) : null,
    running ? h("i", { class: "fresh-spin", "aria-hidden": "true" }) : null,
  );
  chip.addEventListener("pointermove", (e) =>
    showTip(
      e,
      "Data as of",
      list.map((r) => ({
        value: r.fetchedAt ? ago(r.fetchedAt) : r.state === "failed" ? "failed" : "loading",
        label: `${r.label}${r.coverage.of > 1 ? ` (${num(r.coverage.have)} of ${num(r.coverage.of)} tenants)` : ""}, every ${every(r.intervalMs)}${r.lastError ? `: ${r.lastError.slice(0, 120)}` : ""}`,
      })),
    ),
  );
  chip.addEventListener("pointerleave", hideTip);
  return chip;
}

export function every(ms) {
  if (ms >= 86_400_000) return `${Math.round(ms / 86_400_000)} d`;
  if (ms >= 3_600_000) return `${Math.round(ms / 3_600_000)} h`;
  return `${Math.round(ms / 60_000)} min`;
}

export function sevBadge(sev, opts = {}) {
  const k = sev === "unset" ? "info" : sev;
  return h("span", { class: `sev sev-${k}${opts.big ? " sev-big" : ""}` }, icon(SEV_ICON[k], opts.big ? 18 : 13), h("span", { text: SEV_LABEL[sev] ?? sev }));
}

export function genBadge(gen) {
  if (!gen) return null;
  return h("span", { class: `gen gen-${gen}`, title: gen === "fusion" ? "Cases and detections on the Sophos Fusion APIs" : gen === "classic" ? "Cases on the Classic Sophos Central APIs" : "API generation not known" , text: gen === "fusion" ? "Fusion" : gen === "classic" ? "Classic" : "?" });
}

export function managedBadge(m) {
  if (m === "mdr") return h("span", { class: "who who-mdr", text: "MDR" });
  if (m === "self") return h("span", { class: "who who-self", text: "Self" });
  return h("span", { class: "who who-none", text: "Unclaimed" });
}

export function panel(title, opts = {}, ...body) {
  return h(
    "section",
    { class: `panel reveal ${opts.class ?? ""}`, style: opts.style ?? null, id: opts.id ?? null },
    h("header", { class: "panel-head" }, h("h2", {}, opts.icon ? icon(opts.icon, 15) : null, title), opts.right ?? null),
    h("div", { class: "panel-body" }, ...body),
  );
}

export function gapNote(text) {
  return h("p", { class: "gap-note" }, icon("warning", 13), h("span", { text }));
}

export function viewHead(title, sub, right = null) {
  return h("div", { class: "view-head reveal" }, h("div", {}, h("h1", { text: title }), sub ? h("p", { class: "sub", text: sub }) : null), right ? h("div", { class: "view-tools" }, right) : null);
}

/** On a wall: how many items of `itemHeight` px fit between `el`'s top and the footer. */
export function fitCount(el, itemHeight, reserve = 0, min = 1) {
  if (!el) return min;
  const top = el.getBoundingClientRect().top;
  const foot = document.getElementById("foot")?.offsetHeight ?? 0;
  return Math.max(min, Math.floor((window.innerHeight - top - foot - reserve) / itemHeight));
}

export function isWall() {
  return document.body.classList.contains("wall");
}

export function segmented(options, value, onPick, label) {
  return h(
    "div",
    { class: "seg", role: "group", "aria-label": label },
    options.map(([v, text]) => h("button", { type: "button", class: v === value ? "on" : "", "aria-pressed": v === value ? "true" : "false", text, onclick: () => onPick(v) })),
  );
}

/**
 * Chips for a Search GraphQL screen: where the data comes from, and a warning
 * when a search came back partial (some schemas failed) or over the row limit.
 */
export function searchChips(badge) {
  const out = h("span", { class: "search-chips" });
  out.append(h("span", { class: "chip dim", title: "Read through Search GraphQL (QL Data Lake search), Fusion tenants only" }, icon("search", 12), "Search GraphQL"));
  if (badge?.partial?.length) {
    out.append(h("span", { class: "chip chip-warn", title: `These schemas failed in the last search, so their events are missing: ${badge.partial.join(", ")}` }, icon("warning", 12), `Partial: ${badge.partial.slice(0, 3).join(", ")}${badge.partial.length > 3 ? ` +${badge.partial.length - 3}` : ""}`));
  }
  if (badge?.truncated) out.append(h("span", { class: "chip chip-warn", title: "The search returned more rows than the toolkit reads; the smallest groups are left out" }, icon("warning", 12), "Row limit reached"));
  return out;
}

/** A screen that only Fusion tenants can fill, explaining why it is empty. */
export function searchEmpty(d) {
  const t = d.tenants ?? { fusion: 0, classic: 0, unknown: 0 };
  let title = "Running the first search";
  let text = "Search GraphQL starts a search, waits for Sophos to finish it and reads the rows. The first answer takes a minute or so.";
  if (!t.fusion && t.classic && !t.unknown) {
    title = "Fusion tenants only";
    text = d.scope === "all" ? "None of these tenants is on Sophos Fusion yet. Search GraphQL reaches a tenant's data once it has moved to Fusion." : "This tenant's data is still on the Classic Sophos Central APIs. Search GraphQL reaches it once the tenant has moved to Sophos Fusion.";
  } else if (!t.fusion && t.unknown) {
    title = "Checking which tenants are on Fusion";
    text = "Search GraphQL serves Fusion tenants only. The toolkit is still asking Sophos which API each tenant is on.";
  } else if (d.scope === "all") {
    title = "No search results yet";
    text = "With all tenants selected these screens show what the daily refresh found. Pick one tenant to search it now and every 15 minutes while it is on screen.";
  }
  return h("section", { class: "empty reveal" }, h("div", { class: "empty-orb", "aria-hidden": "true" }), h("h1", { text: title }), h("p", { text }));
}
