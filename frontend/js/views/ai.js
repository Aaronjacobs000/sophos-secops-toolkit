// AI usage (AI Defense Activity and Policy GraphQL, reads only): the AI
// activity Sophos AI Defense saw in the last 7 days, what it blocked and
// warned on by risk, the AI apps in use and who uses them, and the newest
// blocked and warned activity. A tenant without AI Defense gets a plain
// "not set up" (or "licence expired", or "not on Sophos Fusion") screen,
// never an error.

import { h, clear } from "../dom.js";
import { icon, SEV_ICON } from "../icons.js";
import { tweenNumber, pulse } from "../anim.js";
import { num, compact, ago, date, dateTime, plural } from "../format.js";
import { stackBar, tipOn } from "../viz.js";
import { freshChip, panel, viewHead, gapNote, fitCount, isWall } from "./common.js";
import { AiFlowStage, appMark } from "./ai-flow.js";

let st = null;

const RISK_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", unknown: "Unknown" };
const RISK_COLOR = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)", info: "var(--sev-info)", unknown: "var(--ink-4)" };
const STATE_LABEL = { active: "Set up", "not-set-up": "Not set up", "not-licensed": "Licence expired", unavailable: "Not on Sophos Fusion", "no-access": "No access", pending: "Not read yet" };

function riskBadge(risk) {
  const k = risk === "unknown" ? "info" : risk;
  return h("span", { class: `sev sev-${k}` }, icon(SEV_ICON[k] ?? "info", 13), h("span", { text: RISK_LABEL[risk] ?? risk }));
}

function actionBadge(action) {
  return action === "blocked"
    ? h("span", { class: "ai-act ai-act-blocked" }, icon("critical", 13), h("span", { text: "Blocked" }))
    : h("span", { class: "ai-act ai-act-warned" }, icon("warning", 13), h("span", { text: "Warned" }));
}

function kpi(id, label, cls = "") {
  return h(
    "section",
    { class: `kpi-tile reveal ${cls}`, id: `a-${id}` },
    h("div", { class: "kpi-tile-label", text: label }),
    h("b", { class: "kpi-tile-num num", text: "0" }),
    h("div", { class: "kpi-tile-foot" }),
  );
}

function setKpi(id, value, foot, alert, format = num) {
  const el = document.getElementById(`a-${id}`);
  if (!el) return;
  tweenNumber(el.querySelector(".kpi-tile-num"), value, format, 1000);
  const f = el.querySelector(".kpi-tile-foot");
  clear(f);
  if (foot) f.append(foot);
  el.classList.toggle("kpi-alert", !!alert);
}

function subtitle(d) {
  const m = d.model;
  const range = m.windowStart ? `${date(m.windowStart)} to ${date(m.windowEnd)}` : "last 7 days";
  return `${d.tenantName}, ${range}`;
}

function headRow(d) {
  return h("div", { class: "head-row" }, h("span", { class: "chip dim", title: "Read through the AI Defense Activity and Policy GraphQL APIs" }, icon("spark", 12), "AI Defense"), d.freshness.length ? freshChip(d.freshness) : null);
}

const EMPTY = {
  "not-set-up": ["AI Defense is not set up", "Once AI Defense is set up for this tenant in Sophos Fusion, this board shows its AI activity, the AI apps in use and who uses them. The toolkit checks once a day, and every hour while this screen shows the tenant."],
  "not-licensed": ["AI Defense licence expired", "There is no AI activity to show. The toolkit checks once a day, and every hour while this screen shows the tenant."],
  unavailable: ["AI Defense can't be read here", ""],
  "no-access": ["No access to AI Defense", ""],
  pending: ["Reading AI Defense", "The first read takes one call per tenant, and up to three for a tenant with AI Defense set up."],
  none: ["No tenant here has AI Defense set up", "Each tenant below says why. Tenants without AI Defense are checked once a day."],
};

function emptyState(d) {
  const m = d.model;
  const [title, text] = EMPTY[m.state] ?? EMPTY.pending;
  return h(
    "section",
    { class: "empty ai-empty reveal" },
    h("div", { class: "empty-orb", "aria-hidden": "true" }),
    h("h1", { text: title }),
    m.note ? h("p", { text: m.note }) : null,
    text ? h("p", { text }) : null,
  );
}

function table(id, heads) {
  const t = h("table", { class: "dev-table" });
  t.append(h("thead", {}, h("tr", {}, heads.filter(Boolean).map((x) => h("th", { text: x })))), h("tbody", { id }));
  return t;
}

function tenantsPanel(d) {
  return panel(
    "Tenants",
    { class: "p-ai-tenants", icon: "tenant", right: h("span", { class: "dim", id: "a-tenants-note" }) },
    h("div", { class: "table-wrap" }, table("a-tenants-rows", ["Tenant", "AI Defense", "AI activity", "Blocked", "Warned", "AI apps", "Users", "Policies"])),
  );
}

function build(root, d) {
  const wrap = h("section", { class: "aiboard" });
  wrap.append(viewHead("AI usage", subtitle(d), headRow(d)));
  if (d.model.state !== "active") {
    wrap.append(emptyState(d));
    if (d.scope === "all" && d.model.tenantRows.length) wrap.append(h("div", { class: "ai-stack" }, tenantsPanel(d)));
    root.append(wrap);
    return { wrap, empty: true };
  }
  wrap.append(
    h("div", { class: "afl-wrap", id: "a-flow" }),
    h("div", { class: "afl-caption", id: "a-flow-note" }),
    h(
      "div",
      { class: "kpi-row5" },
      kpi("total", "AI activity, 7 days"),
      kpi("blocked", "Blocked", "kpi-bad"),
      kpi("warned", "Warned"),
      kpi("apps", "AI apps in use"),
      kpi("users", "Users"),
    ),
  );
  const risks = panel("Blocked and warned by risk", { class: "p-ai-risk", icon: "shield", right: h("span", { class: "ai-legend" }, h("span", {}, h("i", { class: "dot dot-bad" }), "Blocked"), h("span", {}, h("i", { class: "dot dot-warn" }), "Warned")) }, h("div", { class: "ai-risks", id: "a-risks" }));
  const inventory = panel(
    "Inventory",
    { class: "p-ai-inv", icon: "layers" },
    h("div", { class: "ai-inv" }, h("div", { class: "ai-inv-head" }, h("b", { text: "AI apps by risk" }), h("span", { class: "dim", id: "a-apps-n" })), h("div", { id: "a-apps-bar", class: "ai-bar-wrap" }), h("div", { class: "drift-legend ai-legend-row", id: "a-apps-legend" })),
    h("div", { class: "ai-inv" }, h("div", { class: "ai-inv-head" }, h("b", { text: "Users by worst risk" }), h("span", { class: "dim", id: "a-users-n" })), h("div", { id: "a-users-bar", class: "ai-bar-wrap" }), h("div", { class: "drift-legend ai-legend-row", id: "a-users-legend" })),
    h("ul", { class: "ai-facts", id: "a-facts" }),
  );
  const apps = panel("Top AI apps", { class: "p-ai-apps", icon: "spark", right: h("span", { class: "dim", id: "a-apps-note" }) }, h("div", { class: "table-wrap" }, table("a-apps-rows", ["App", "Provider", "Risk", "Activity", "Users", "Unsanctioned", d.scope === "all" ? "Tenants" : "Last seen"])));
  const users = panel("Top users", { class: "p-ai-users", icon: "identity", right: h("span", { class: "dim", id: "a-users-note" }) }, h("div", { class: "table-wrap" }, table("a-users-rows", ["User", d.scope === "all" ? "Tenant" : null, "Worst risk", "Apps", "Activity", "Blocked or warned", "Top app", "Last seen"])));
  const recent = panel("Latest blocked and warned", { class: "p-ai-recent", icon: "clock", right: h("span", { class: "dim", id: "a-recent-note" }) }, h("div", { class: "table-wrap" }, table("a-recent-rows", ["Time", d.scope === "all" ? "Tenant" : null, "User", "App", "Action", "Risk", "Policy", "Device"])));
  wrap.append(
    h("div", { class: "ai-grid" }, risks, inventory),
    h("div", { class: "ai-stack" }, apps, users),
    h("div", { class: "ai-stack" }, recent, d.scope === "all" ? tenantsPanel(d) : null),
    h("div", { id: "a-note" }),
  );
  root.append(wrap);
  return { wrap, empty: false };
}

function fillRisks(m, first) {
  const box = document.getElementById("a-risks");
  const rows = m.risks.filter((r) => r.blocked || r.warned || !["info", "unknown"].includes(r.risk));
  const max = Math.max(1, ...rows.map((r) => Math.max(r.blocked, r.warned)));
  const keep = new Set(rows.map((r) => r.risk));
  for (const el of [...box.children]) if (!keep.has(el.dataset.risk)) el.remove();
  rows.forEach((r, i) => {
    let row = box.querySelector(`[data-risk="${r.risk}"]`);
    if (!row) {
      const bar = (kind) => h("div", { class: `ai-rbar ai-rbar-${kind}` }, h("span", { class: "ai-rbar-track" }, h("i", { class: "ai-rbar-fill" })), h("b", { class: "ai-rbar-n num" }));
      row = h("div", { class: "ai-risk", tabindex: "0", dataset: { risk: r.risk } }, h("span", { class: "ai-risk-label" }, riskBadge(r.risk)), h("div", { class: "ai-risk-bars" }, bar("blocked"), bar("warned")));
      tipOn(row, () => [`${RISK_LABEL[r.risk]} risk`, [{ value: num(row._b), label: "blocked", color: "var(--bad)" }, { value: num(row._w), label: "warned", color: "var(--warn)" }]]);
      box.append(row);
    }
    row._b = r.blocked;
    row._w = r.warned;
    row.classList.toggle("ai-risk-zero", !r.blocked && !r.warned);
    for (const [kind, v] of [["blocked", r.blocked], ["warned", r.warned]]) {
      const b = row.querySelector(`.ai-rbar-${kind}`);
      b.querySelector(".ai-rbar-n").textContent = num(v);
      const fill = b.querySelector(".ai-rbar-fill");
      const pct = `${Math.max(v > 0 ? 1.5 : 0, (v / max) * 100)}%`;
      if (first) {
        fill.style.width = "0%";
        requestAnimationFrame(() => requestAnimationFrame(() => {
          fill.style.transitionDelay = `${i * 70}ms`;
          fill.style.width = pct;
        }));
      } else fill.style.width = pct;
    }
    if (box.children[i] !== row) box.insertBefore(row, box.children[i] ?? null);
  });
}

function riskStack(barId, legendId, counts, title) {
  const keys = ["critical", "high", "medium", "low", "info", "unknown"];
  stackBar(document.getElementById(barId), keys.map((k) => ({ key: k, label: RISK_LABEL[k], value: counts[k] ?? 0, color: RISK_COLOR[k] })), { title });
  const legend = document.getElementById(legendId);
  clear(legend);
  for (const k of keys) {
    if (!counts[k] && (k === "info" || k === "unknown")) continue;
    legend.append(h("span", {}, h("i", { style: { background: RISK_COLOR[k] } }), `${RISK_LABEL[k]} `, h("b", { class: "num", text: num(counts[k] ?? 0) })));
  }
}

function flowOpts(d) {
  return { appsTotal: d.model.apps.total, usersTotal: d.model.users.total, multi: d.scope === "all" };
}

function fillFlowNote(m) {
  const box = document.getElementById("a-flow-note");
  if (!box) return;
  clear(box);
  if (!m.flow.total) return;
  const bucketed = m.flow.apps.some((x) => x.kind === "other") || m.flow.users.some((x) => x.kind === "other");
  box.append(h("p", { class: "dim", text: `Band width is activity.${bucketed ? " The top 10 apps and users are named; the rest share one band on each side." : ""} Hover or tap for the numbers; click to pin one.` }));
  if (m.flow.note) box.append(gapNote(m.flow.note));
}

function fill(d, first) {
  const m = d.model;
  const a = m.activity;
  if (first) st.flow = new AiFlowStage(document.getElementById("a-flow"), m.flow, flowOpts(d));
  else st.flow?.update(m.flow, flowOpts(d));
  fillFlowNote(m);
  const critHigh = (x) => x.critical + x.high;
  setKpi("total", a.total, h("span", { class: a.unsanctioned ? "t-warn" : "dim", text: a.unsanctioned ? `${num(a.unsanctioned)} unsanctioned` : "None unsanctioned" }), false, compact);
  setKpi("blocked", a.blocked, h("span", { class: critHigh(a.blockedByRisk) ? "t-bad" : "dim", text: `${num(critHigh(a.blockedByRisk))} critical or high risk` }), a.blocked > 0);
  setKpi("warned", a.warned, h("span", { class: "dim", text: `${num(critHigh(a.warnedByRisk))} critical or high risk` }), a.warned > 0);
  setKpi("apps", m.apps.total, h("span", { class: critHigh(m.apps.byRisk) ? "t-bad" : "dim", text: `${d.scope === "all" ? "Counted per tenant, " : ""}${num(critHigh(m.apps.byRisk))} critical or high risk` }), critHigh(m.apps.byRisk) > 0);
  setKpi("users", m.users.total, h("span", { class: "dim", text: `${num(m.users.withViolations)} blocked or warned` }));

  fillRisks(m, first);
  setTextById("a-apps-n", d.scope === "all" ? `${plural(m.apps.total, "app")}, counted per tenant` : plural(m.apps.total, "app"));
  setTextById("a-users-n", plural(m.users.total, "user"));
  riskStack("a-apps-bar", "a-apps-legend", m.apps.byRisk, "AI apps");
  riskStack("a-users-bar", "a-users-legend", m.users.byRisk, "Users");
  const facts = document.getElementById("a-facts");
  clear(facts);
  const fact = (ic, text, cls = "") => facts.append(h("li", { class: cls }, icon(ic, 14), h("span", { text })));
  if (m.policies) fact("shield", `${plural(m.policies.total, "policy", "policies")}, ${num(m.policies.enabled)} enabled${m.policies.failed ? `, ${num(m.policies.failed)} failed to apply` : ""}`, m.policies.failed ? "t-bad" : "");
  if (m.apps.trainsOnData !== null) fact("layers", `${plural(m.apps.trainsOnData, "app")} in use train on user data, opt-outs included`, m.apps.trainsOnData ? "t-warn" : "");
  if (m.apps.unsanctioned) fact("warning", `${plural(m.apps.unsanctioned, "app")} used with no policy covering ${m.apps.unsanctioned === 1 ? "it" : "them"}`, "t-warn");
  if (m.licence) {
    const grace = m.licence.state === "GRACE_PERIOD";
    const kind = m.licence.type ? ` (${m.licence.type.toLowerCase()})` : "";
    fact("key", `Licence${kind} ${grace ? `in its grace period to ${date(Date.parse(m.licence.graceEndsAt))}` : m.licence.expiresAt ? `ends ${date(Date.parse(m.licence.expiresAt))}` : m.licence.state === "ACTIVE" ? "active" : "state not known"}`, grace ? "t-warn" : "");
  }

  // Top apps
  const wall = isWall();
  const apps = document.getElementById("a-apps-rows");
  clear(apps);
  const appRoom = wall ? fitCount(apps, 36, 220, 4) : m.topApps.length;
  for (const x of m.topApps.slice(0, appRoom)) {
    apps.append(
      h(
        "tr",
        {},
        h("td", {}, h("span", { class: "ai-app-cell" }, appMark({ kind: "app", appId: x.id, label: x.name, provider: x.provider }, 22), h("b", { text: x.name }))),
        h("td", { class: "dim", text: x.provider || "-" }),
        h("td", {}, riskBadge(x.risk)),
        h("td", { class: "num", text: num(x.usage) }),
        h("td", { class: "num", text: num(x.users) }),
        h("td", { class: `num${x.unsanctioned ? " t-warn" : " dim"}`, text: x.unsanctioned ? num(x.unsanctioned) : "-" }),
        d.scope === "all" ? h("td", { class: "num", text: num(x.tenants) }) : h("td", { class: "mono dim", text: x.lastSeen ? ago(Date.parse(x.lastSeen)) : "-" }),
      ),
    );
  }
  if (!m.topApps.length) apps.append(h("tr", {}, h("td", { colspan: "7", class: "calm-cell dim", text: "No AI app was used in the window" })));
  setTextById("a-apps-note", d.scope === "all" ? `Each tenant's top apps, added up across ${plural(m.scope.active, "tenant")}` : m.topApps.length < m.apps.total ? `Top ${num(Math.min(appRoom, m.topApps.length))} of ${plural(m.apps.total, "app")}` : plural(m.topApps.length, "app"));

  // Top users
  const users = document.getElementById("a-users-rows");
  clear(users);
  const userRoom = wall ? fitCount(users, 36, 220, 4) : m.topUsers.length;
  for (const u of m.topUsers.slice(0, userRoom)) {
    users.append(
      h(
        "tr",
        {},
        h("td", {}, h("b", { text: u.name || "Unknown" })),
        d.scope === "all" ? h("td", { class: "dim", text: u.tenantName ?? "" }) : null,
        h("td", {}, riskBadge(u.risk)),
        h("td", { class: "num", text: num(u.apps) }),
        h("td", { class: "num", text: num(u.usage) }),
        h("td", { class: `num${u.violations ? " t-bad" : " dim"}`, text: u.violations ? num(u.violations) : "-" }),
        h("td", { class: "dim", text: u.topApp ?? "-" }),
        h("td", { class: "mono dim", text: u.lastSeen ? ago(Date.parse(u.lastSeen)) : "-" }),
      ),
    );
  }
  if (!m.topUsers.length) users.append(h("tr", {}, h("td", { colspan: "8", class: "calm-cell dim", text: "Nobody used an AI app in the window" })));
  setTextById("a-users-note", m.topUsers.length < m.users.total ? `Top ${num(Math.min(userRoom, m.topUsers.length))} of ${plural(m.users.total, "user")}` : plural(m.topUsers.length, "user"));

  // Latest blocked and warned
  const recent = document.getElementById("a-recent-rows");
  clear(recent);
  const recentRoom = wall ? fitCount(recent, 36, 40, 3) : Math.min(25, m.recent.length);
  for (const x of m.recent.slice(0, recentRoom)) {
    recent.append(
      h(
        "tr",
        { class: `ai-row-${x.action}` },
        h("td", { class: "mono", title: dateTime(x.at), text: ago(x.at) }),
        d.scope === "all" ? h("td", { class: "dim", text: x.tenantName ?? "" }) : null,
        h("td", { text: x.user || (x.userType === "NETWORK_ENTITY" ? "Network address" : "Unknown") }),
        h("td", {}, h("b", { text: x.app })),
        h("td", {}, actionBadge(x.action)),
        h("td", {}, riskBadge(x.risk)),
        h("td", { class: "dim", text: x.policy || "-" }),
        h("td", { class: "dim", text: x.device || "-" }),
      ),
    );
  }
  if (!m.recent.length) recent.append(h("tr", {}, h("td", { colspan: "8", class: "calm-cell", text: "Nothing blocked or warned in the window" })));
  setTextById("a-recent-note", m.recentOf > m.recent.length ? `Newest ${num(Math.min(recentRoom, m.recent.length))} of ${num(m.recentOf)}` : plural(m.recent.length, "activity", "activities"));

  if (d.scope === "all") fillTenants(d);
  const note = document.getElementById("a-note");
  clear(note);
  note.append(gapNote("Counts are AI Defense activities: one activity can gather several related events. Unsanctioned means allowed for an app no policy covers. A network address stands in for a user AI Defense could not name."));
  for (const w of m.warnings.slice(0, 3)) note.append(gapNote(w));

  const prev = st?.data?.model;
  if (!first && prev && prev.activity.blocked !== a.blocked) pulse(document.getElementById("a-blocked"));
}

function fillTenants(d) {
  const body = document.getElementById("a-tenants-rows");
  if (!body) return;
  clear(body);
  const m = d.model;
  const room = isWall() ? fitCount(body, 36, 40, 3) : m.tenantRows.length;
  for (const t of m.tenantRows.slice(0, room)) {
    const on = t.state === "active";
    body.append(
      h(
        "tr",
        { class: on ? "" : "ai-row-off" },
        h("td", {}, h("a", { href: `#/ai?tenant=${encodeURIComponent(t.tenantId)}`, text: t.name })),
        h("td", { class: on ? "t-good" : "dim", title: t.note ?? "" , text: STATE_LABEL[t.state] ?? t.state }),
        h("td", { class: "num", text: on ? num(t.total) : "-" }),
        h("td", { class: `num${t.blocked ? " t-bad" : ""}`, text: on ? num(t.blocked) : "-" }),
        h("td", { class: `num${t.warned ? " t-warn" : ""}`, text: on ? num(t.warned) : "-" }),
        h("td", { class: "num", text: on ? num(t.apps) : "-" }),
        h("td", { class: "num", text: on ? num(t.users) : "-" }),
        h("td", { class: "num", text: on && t.policies !== null ? num(t.policies) : "-" }),
      ),
    );
  }
  const s = m.scope;
  setTextById("a-tenants-note", `${num(s.active)} set up of ${plural(s.tenants, "tenant")}${m.tenantRows.length > room ? `, ${num(room)} shown` : ""}`);
}

function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

export default {
  id: "ai",
  mount(root, d) {
    st = build(root, d);
    st.data = d;
    st.root = root;
    if (!st.empty) fill(d, true);
    else if (d.scope === "all") fillTenants(d);
  },
  update(d, ctx) {
    if (!st) return;
    if (st.empty !== (d.model.state !== "active") || st.data.model.state !== d.model.state) {
      const root = st.root;
      st.flow?.destroy();
      clear(root);
      this.mount(root, d, ctx);
      return;
    }
    if (!st.empty) fill(d, false);
    else if (d.scope === "all") fillTenants(d);
    const head = st.wrap.querySelector(".view-head .head-row");
    if (head) head.replaceWith(headRow(d));
    st.data = d;
  },
  unmount() {
    st?.flow?.destroy();
    st = null;
  },
};
