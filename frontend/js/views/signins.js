// Sign-ins and MFA (views X10 and X11), read through Search GraphQL on Fusion
// tenants: where sign-ins come from, how many failed and why, and the
// successful sign-ins that used no MFA, by app, OS, location and user. Only
// interactive user sign-ins from identity sources that report MFA are counted
// for MFA; endpoint logons, service principal and non-interactive sign-ins are
// listed but never counted as "without MFA".

import { h, clear, setText } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, pulse } from "../anim.js";
import { num, plural, date } from "../format.js";
import { hbars, stackBar } from "../viz.js";
import { renderMap } from "../map.js";
import { freshChip, panel, viewHead, gapNote, fitCount, isWall, searchChips, searchEmpty } from "./common.js";

let st = null;

function kpi(id, label, cls = "") {
  return h(
    "section",
    { class: `kpi-tile reveal ${cls}`, id: `s-${id}` },
    h("div", { class: "kpi-tile-label", text: label }),
    h("b", { class: "kpi-tile-num num", text: "0" }),
    h("div", { class: "kpi-tile-foot" }),
  );
}

function setKpi(id, value, foot, alert) {
  const el = document.getElementById(`s-${id}`);
  if (!el) return;
  tweenNumber(el.querySelector(".kpi-tile-num"), value, num, 1000);
  const f = el.querySelector(".kpi-tile-foot");
  clear(f);
  if (foot) f.append(foot);
  el.classList.toggle("kpi-alert", !!alert);
}

function pct(part, whole) {
  return whole ? `${Math.round((part / whole) * 100)}%` : "0%";
}

function subtitle(d) {
  const m = d.model;
  const range = m.windowStart ? `${date(m.windowStart)} to ${date(m.windowEnd)}` : "last 7 days";
  return `${d.tenantName}, ${range}`;
}

function build(root, d, ctx) {
  const wrap = h("section", { class: "signins" });
  wrap.append(viewHead("Sign-ins and MFA", subtitle(d), h("div", { class: "head-row" }, searchChips(d.model.search), d.freshness.length ? freshChip(d.freshness) : null)));
  if (!d.model.tenantsWithData) {
    wrap.append(searchEmpty(d));
    root.append(wrap);
    return { wrap, empty: true };
  }
  wrap.append(
    h(
      "div",
      { class: "kpi-row4" },
      kpi("total", "Sign-ins, 7 days"),
      kpi("failed", "Failed", "kpi-bad"),
      kpi("nomfa", "Without MFA", "kpi-bad"),
      kpi("places", "Locations"),
    ),
  );
  const mapPanel = panel(
    "Where sign-ins come from",
    { class: "p-map", icon: "pin", right: h("span", { class: "map-legend" }, h("span", {}, h("i", { class: "dot dot-good" }), "Sign-ins"), h("span", {}, h("i", { class: "dot dot-warn" }), "Many failed"), h("span", {}, h("i", { class: "dot dot-bad" }), "Without MFA")) },
    h("div", { class: "map-grid" }, h("div", { class: "map-box", id: "s-map" }), h("div", { class: "loc-list", id: "s-locs" })),
    h("div", { class: "map-note", id: "s-map-note" }),
  );
  const results = panel("Results and failure reasons", { class: "p-results", icon: "shield" }, h("div", { id: "s-result-bar", class: "result-bar" }), h("div", { id: "s-result-legend", class: "drift-legend" }), h("div", { id: "s-failures" }));
  const byApp = panel("Without MFA, by app", { class: "p-app", icon: "layers", right: h("span", { class: "dim", id: "s-app-note" }) }, h("div", { id: "s-apps" }));
  const byOs = panel("Without MFA, by OS", { class: "p-os", icon: "endpoint" }, h("div", { id: "s-oses" }));
  const userTable = h("table", { class: "dev-table" });
  userTable.append(
    h("thead", {}, h("tr", {}, ["User", d.scope === "all" ? "Tenant" : null, "Without MFA", "Source"].filter(Boolean).map((t) => h("th", { text: t })))),
    h("tbody", { id: "s-users" }),
  );
  const users = panel("Top users without MFA", { class: "p-users", icon: "identity", right: h("span", { class: "dim", id: "s-users-note" }) }, h("div", { class: "table-wrap" }, userTable));
  const srcTable = h("table", { class: "dev-table" });
  srcTable.append(h("thead", {}, h("tr", {}, ["Source", "Sign-ins", "With MFA", "Without MFA", "Excluded"].map((t) => h("th", { text: t })))), h("tbody", { id: "s-sources" }));
  const sources = panel("Identity sources", { class: "p-idsrc", icon: "integration" }, h("div", { class: "table-wrap" }, srcTable), h("div", { id: "s-src-note" }));
  wrap.append(h("div", { class: "si-grid" }, mapPanel, h("div", { class: "si-side" }, byApp, byOs), h("div", { class: "si-bottom" }, h("div", { class: "si-col" }, results, sources), users)));
  root.append(wrap);
  void ctx;
  return { wrap, empty: false };
}

function locState(l) {
  if (l.noMfa > 0) return "bad";
  if (l.failed >= 5 && l.failed / Math.max(1, l.total) >= 0.2) return "suspicious";
  return "good";
}

/** "21,656 service principal and 1,508 non-interactive", for the sign-ins never counted for MFA. */
function notCounted(x) {
  return [x.service ? `${num(x.service)} service principal` : null, x.nonInteractive ? `${num(x.nonInteractive)} non-interactive` : null].filter(Boolean).join(" and ");
}

function fill(d, first) {
  const m = d.model;
  const mfa = m.mfa;
  // A source reports MFA, yet no sign-in in the window carries an MFA answer.
  const noAnswer = mfa.reportsMfa && !mfa.signins;
  const skipped = notCounted(mfa);
  setKpi("total", m.total, h("span", { class: "dim", text: `${num(m.success)} succeeded, ${plural(m.bySource.length, "source")}` }));
  setKpi("failed", m.failed, h("span", { class: m.failed ? "t-warn" : "dim", text: `${pct(m.failed, m.total)} of sign-ins` }), m.failed > 0 && m.failed / Math.max(1, m.total) >= 0.1);
  if (noAnswer) {
    setKpi("nomfa", NaN, h("span", { class: "dim", text: "No user sign-in with an MFA result" }));
  } else if (mfa.reportsMfa) {
    setKpi("nomfa", mfa.withoutMfa, h("span", { class: mfa.withoutMfa ? "t-bad" : "t-good" }, icon(mfa.withoutMfa ? "warning" : "check", 13), ` ${pct(mfa.withoutMfa, mfa.signins)} of ${plural(mfa.signins, "user sign-in")}`), mfa.withoutMfa > 0);
  } else {
    setKpi("nomfa", 0, h("span", { class: "dim", text: "No source here reports MFA" }));
  }
  const countries = new Set(m.locations.map((l) => l.country).filter(Boolean)).size;
  setKpi("places", m.locations.length, h("span", { class: "dim", text: m.locations.length ? `${plural(countries, "country", "countries")}` : "None placed" }));

  // Map
  const points = m.locations.map((l) => ({
    key: l.key,
    label: l.city ?? l.country ?? "Unknown",
    lat: l.lat,
    lon: l.lon,
    value: l.total,
    state: locState(l),
    detail: [
      { value: num(l.total), label: "sign-ins" },
      ...(l.failed ? [{ value: num(l.failed), label: "failed", color: "var(--warn)" }] : []),
      ...(l.noMfa ? [{ value: num(l.noMfa), label: "without MFA", color: "var(--bad)" }] : []),
      ...(l.country && l.city ? [{ value: l.country, label: "" }] : []),
    ],
  }));
  const p = m.placement;
  const empty = p.unplaced && !p.placed ? "Download DB-IP in Setup to place sign-ins by their source IP." : p.internal && !p.unplaced ? "Every sign-in came from a private or internal address." : "No sign-in has a public source IP yet.";
  renderMap(document.getElementById("s-map"), points, { label: "Sign-ins by source location", empty });
  const list = document.getElementById("s-locs");
  clear(list);
  const max = Math.max(1, ...m.locations.map((l) => l.total));
  const rows = isWall() ? 7 : 9;
  for (const l of m.locations.slice(0, rows)) {
    const state = locState(l);
    list.append(
      h(
        "div",
        { class: `loc loc-${state}` },
        icon(state === "bad" ? "critical" : state === "suspicious" ? "warning" : "low", 14),
        h("span", { class: "loc-name" }, h("b", { text: l.city ?? l.country ?? "Unknown" }), h("small", { text: l.noMfa ? ` ${num(l.noMfa)} no MFA` : l.failed ? ` ${num(l.failed)} failed` : "" })),
        h("span", { class: "loc-bar" }, h("i", { style: { width: `${(l.total / max) * 100}%` } })),
        h("b", { class: "loc-n num", text: num(l.total) }),
      ),
    );
  }
  if (p.internal || p.unplaced) {
    list.append(h("div", { class: "loc loc-none" }, icon("info", 14), h("span", { class: "loc-name" }, h("b", { text: "Not placed" }), h("small", { text: ` ${num(p.internal)} internal, ${num(p.unplaced)} not located` })), h("span"), h("b", { class: "loc-n num", text: num(p.internal + p.unplaced) })));
  }
  const note = document.getElementById("s-map-note");
  clear(note);
  note.append(gapNote(`Placed by source IP with DB-IP City Lite where installed. A VPN or proxy exit shows where traffic left, not where the person was. ${num(p.placed)} of ${num(m.total)} sign-ins placed.`));

  // Results
  stackBar(
    document.getElementById("s-result-bar"),
    [
      { key: "ok", label: "Succeeded", value: m.success, color: "var(--self)" },
      { key: "fail", label: "Failed", value: m.failed, color: "var(--warn)" },
      { key: "other", label: "Other", value: Math.max(0, m.total - m.success - m.failed), color: "var(--ink-4)" },
    ],
    { title: "Sign-ins" },
  );
  const legend = document.getElementById("s-result-legend");
  clear(legend);
  legend.append(
    h("span", {}, h("i", { class: "key key-cur" }), h("b", { text: num(m.success) }), " succeeded"),
    h("span", {}, h("i", { class: "key key-old" }), h("b", { text: num(m.failed) }), " failed"),
  );
  const fails = document.getElementById("s-failures");
  if (m.failures.length) {
    fails.querySelector(".calm-line")?.remove();
    hbars(fails, m.failures.slice(0, isWall() ? 4 : 6).map((f) => ({ key: f.reason, label: f.reason, value: f.count, color: "var(--warn)" })), { unit: "failed sign-ins" });
  } else {
    clear(fails);
    fails.append(h("p", { class: "calm-line" }, icon("check", 14), " No failed sign-ins"));
  }

  // MFA by app and OS
  const apps = document.getElementById("s-apps");
  const oses = document.getElementById("s-oses");
  if (!mfa.reportsMfa) {
    for (const el of [apps, oses]) {
      clear(el);
      el.append(h("p", { class: "dim small" }, "No identity source in this data reports MFA. Sophos endpoint logons carry no MFA fields, so they are not counted. Microsoft Entra ID sign-ins (Graph) do."));
    }
  } else if (noAnswer) {
    for (const el of [apps, oses]) {
      clear(el);
      el.append(h("p", { class: "dim small" }, `No interactive user sign-in in this window, so there is no MFA result to count. ${skipped ? `The ${skipped} sign-ins carry none: a service principal can't use MFA, and a non-interactive sign-in reuses a token without reporting MFA.` : ""}`.trim()));
    }
  } else {
    for (const el of [apps, oses]) el.querySelector("p.dim")?.remove();
    hbars(apps, mfa.byApp.slice(0, isWall() ? 5 : 8).map((a) => ({ key: a.name, label: a.name, value: a.withoutMfa, note: `of ${num(a.signins)}`, color: "var(--bad)" })), { unit: "sign-ins without MFA" });
    hbars(oses, mfa.byOs.slice(0, isWall() ? 5 : 7).map((o) => ({ key: o.name, label: o.name, value: o.withoutMfa, note: `of ${num(o.signins)}`, color: "var(--bad)" })), { unit: "sign-ins without MFA" });
  }
  setText(document.getElementById("s-app-note"), mfa.reportsMfa && !noAnswer ? `${pct(mfa.withoutMfa, mfa.signins)} without MFA` : "");

  // Users
  const ub = document.getElementById("s-users");
  clear(ub);
  const room = isWall() ? fitCount(ub, 34, 16, 3) : 15;
  for (const u of mfa.topUsers.slice(0, room)) {
    ub.append(h("tr", {}, h("td", { class: "mono strong", text: u.user }), d.scope === "all" ? h("td", { class: "dim", text: u.tenantName ?? "" }) : null, h("td", { class: "num t-bad", text: num(u.withoutMfa) }), h("td", { class: "dim", text: u.source })));
  }
  if (!mfa.topUsers.length) {
    ub.append(h("tr", {}, noAnswer ? h("td", { colspan: "4", class: "calm-cell", style: { color: "var(--ink-3)" }, text: "No user sign-in with an MFA result" }) : mfa.reportsMfa ? h("td", { colspan: "4", class: "calm-cell" }, icon("check", 16), " Every counted sign-in used MFA") : h("td", { colspan: "4", class: "calm-cell dim", text: "No source here reports MFA" })));
  }
  setText(document.getElementById("s-users-note"), mfa.topUsers.length ? `Top ${num(Math.min(room, mfa.topUsers.length))}` : "");

  // Sources
  const sb = document.getElementById("s-sources");
  clear(sb);
  for (const src of mfa.sources) {
    sb.append(
      h(
        "tr",
        {},
        h("td", {}, h("b", { text: src.label }), h("small", { class: "mono dim", text: ` ${src.sensorType}` })),
        h("td", { class: "num", text: num(src.signins) }),
        h("td", { class: "num", text: src.reportsMfa ? num(src.withMfa) : "-" }),
        h("td", { class: `num${src.reportsMfa && src.withoutMfa ? " t-bad" : ""}`, text: src.reportsMfa ? num(src.withoutMfa) : "-" }),
        src.reportsMfa ? h("td", { class: "num dim", title: notCounted(src) || null, text: num((src.service ?? 0) + (src.nonInteractive ?? 0)) }) : h("td", { class: "dim", text: "No MFA data" }),
      ),
    );
  }
  if (!mfa.sources.length) sb.append(h("tr", {}, h("td", { colspan: "5", class: "calm-cell dim", text: "No successful sign-ins in the window" })));
  const sn = document.getElementById("s-src-note");
  clear(sn);
  sn.append(gapNote(`${skipped ? `Excluded: ${skipped} sign-ins. ` : ""}Only interactive user sign-ins from sources that fill the MFA fields are counted. A service principal (an app with a secret or certificate) can't use MFA, and a non-interactive sign-in reuses a token and reports no MFA of its own. Sophos endpoint logons always report no MFA, so counting them would make every Windows logon a gap.`));

  const prev = st?.data?.model;
  if (!first && prev && prev.mfa.withoutMfa !== mfa.withoutMfa) pulse(document.getElementById("s-nomfa"));
}

export default {
  id: "signins",
  mount(root, d, ctx) {
    st = build(root, d, ctx);
    st.data = d;
    st.root = root;
    st.ctx = ctx;
    if (!st.empty) fill(d, true);
  },
  update(d, ctx) {
    if (!st) return;
    // The screen changes shape when data arrives for the first time or goes away.
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
    const sub = st.wrap.querySelector(".view-head .sub");
    if (sub) setText(sub, subtitle(d));
    st.data = d;
  },
  unmount() {
    st = null;
  },
};
