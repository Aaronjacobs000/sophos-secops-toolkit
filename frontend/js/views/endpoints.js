// Endpoint health with the device map: stale buckets, unhealthy and tamper
// protection off, agent version drift, devices placed by their public egress
// IP (Sophos geolocation first, then DB-IP), and the worst devices.

import { h, clear, setText } from "../dom.js";
import { icon } from "../icons.js";
import { tweenNumber, reconcile, pulse } from "../anim.js";
import { num, plural, dateTime } from "../format.js";
import { hbars } from "../viz.js";
import { renderMap } from "../map.js";
import { freshChip, panel, segmented, viewHead, gapNote, fitCount, isWall } from "./common.js";

let st = null;

const PLATFORM_LABEL = { windows: "Windows", macos: "macOS", linux: "Linux" };

function kpi(id, label, cls = "") {
  return h(
    "section",
    { class: `kpi-tile reveal ${cls}`, id: `e-${id}` },
    h("div", { class: "kpi-tile-label", text: label }),
    h("b", { class: "kpi-tile-num num", text: "0" }),
    h("div", { class: "kpi-tile-foot" }),
  );
}

function setKpi(id, value, foot, alert) {
  const el = document.getElementById(`e-${id}`);
  if (!el) return;
  tweenNumber(el.querySelector(".kpi-tile-num"), value, num, 1000);
  const f = el.querySelector(".kpi-tile-foot");
  clear(f);
  if (foot) f.append(foot);
  el.classList.toggle("kpi-alert", !!alert);
}

function rowEl(w) {
  const el = h("tr", {});
  fillRow(el, w);
  return el;
}

function fillRow(el, w) {
  clear(el);
  const health =
    w.health === "bad" ? h("span", { class: "t-bad" }, icon("critical", 13), " Bad") : w.health === "suspicious" ? h("span", { class: "t-warn" }, icon("warning", 13), " Suspicious") : w.health === "unknown" ? h("span", { class: "dim" }, icon("offline", 13), " Unknown") : h("span", { class: "t-good" }, icon("check", 13), " Good");
  el.append(
    h("td", { class: "mono strong", text: w.hostname }),
    w.tenantName !== undefined ? h("td", { class: "dim", text: w.tenantName }) : null,
    h("td", { text: w.os }),
    h("td", { class: "mono" }, w.lastSeenAt ? dateTime(Date.parse(w.lastSeenAt)) : "never", w.silentDays >= 7 ? h("span", { class: "t-warn", text: `, ${w.silentDays} d` }) : null),
    h("td", {}, health),
    h("td", {}, w.tamper === false ? h("span", { class: "t-warn" }, icon("warning", 13), " Off") : w.tamper === true ? h("span", { class: "dim", text: "On" }) : h("span", { class: "dim", text: "-" })),
    h("td", { class: "mono" }, w.agentVersion ?? "-", w.outdated ? h("span", { class: "t-warn", text: " behind" }) : null),
    h("td", { text: w.isolation === "isolated" ? "Isolated" : (w.location ?? "-") }),
  );
}

function build(root, d, ctx) {
  const wrap = h("section", { class: "endpoints" });
  const osSeg = segmented(
    [["all", "All OS"], ...d.platforms.slice(0, 4).map((p) => [p.platform, PLATFORM_LABEL[p.platform] ?? p.platform])],
    d.platform ?? "all",
    (v) => ctx.setQuery({ os: v === "all" ? "" : v }),
    "Operating system",
  );
  wrap.append(viewHead("Endpoint health", "", h("div", { class: "head-row" }, osSeg, freshChip(d.freshness))));
  const kpis = h("div", { class: "kpi-row5" }, kpi("devices", "Devices"), kpi("stale", "Stale over 7 days"), kpi("unhealthy", "Unhealthy", "kpi-bad"), kpi("tamper", "Tamper protection off"), kpi("agent", "Agent behind newest"));
  wrap.append(kpis);

  const mapBox = h("div", { class: "map-box", id: "e-map" });
  const locList = h("div", { class: "loc-list", id: "e-locs" });
  const mapNote = h("div", { class: "map-note", id: "e-map-note" });
  const mapPanel = panel(
    "Device locations",
    { class: "p-map", icon: "pin", right: h("span", { class: "chip dim", text: "Public egress IP" }) },
    d.mapAvailable ? h("div", { class: "map-grid" }, mapBox, locList) : h("div", { class: "map-pick" }, icon("pin", 28), h("p", { text: "Pick one tenant to map its devices. Mapping runs a Data Lake query per tenant, so the all-tenants view skips it." })),
    mapNote,
  );
  const stale = panel("Stale devices by days silent", { class: "p-stale", icon: "clock" }, h("div", { id: "e-stale-bars" }));
  const drift = panel("Agent version drift", { class: "p-drift", icon: "layers" }, h("div", { id: "e-drift-head", class: "drift-head" }), h("div", { id: "e-drift" }));
  const table = h("table", { class: "dev-table" });
  table.append(
    h("thead", {}, h("tr", {}, ["Hostname", d.scope === "all" ? "Tenant" : null, "OS", "Last seen", "Health", "Tamper", "Agent", "Location"].filter(Boolean).map((t) => h("th", { text: t })))),
    h("tbody", { id: "e-rows" }),
  );
  const worst = panel("Worst devices", { class: "p-worst", icon: "warning", right: h("span", { class: "dim", id: "e-worst-count" }) }, h("div", { class: "table-wrap" }, table));
  const grid = h("div", { class: "ep-grid" }, mapPanel, h("div", { class: "ep-side" }, stale, drift), worst);
  wrap.append(grid);
  root.append(wrap);
  return { wrap };
}

function fill(d, first) {
  const s = d.summary;
  const winMac = s.byPlatform.map((p) => `${num(p.count)} ${PLATFORM_LABEL[p.platform] ?? p.platform}`).join(", ");
  setKpi("devices", s.total, h("span", { class: "dim", text: winMac || "No devices" }));
  setKpi("stale", s.staleOver7, s.stale.d90 ? h("span", { class: "t-warn" }, icon("warning", 13), ` ${num(s.stale.d90)} silent 90+ days`) : h("span", { class: "dim", text: `${num(s.stale.never)} never seen` }), s.staleOver7 > 0);
  setKpi("unhealthy", s.health.bad + s.health.suspicious, h("span", { class: s.health.bad ? "t-bad" : "dim" }, s.health.bad ? icon("critical", 13) : null, ` ${num(s.health.bad)} bad, ${num(s.health.suspicious)} suspicious`), s.health.bad > 0);
  setKpi("tamper", s.tamperOff, h("span", { class: "dim", text: s.total ? `${Math.round((s.tamperOff / s.total) * 100)}% of devices` : "" }), s.tamperOff > 0);
  setKpi("agent", s.versions.outdated, h("span", { class: "dim", text: s.versions.newest ? `Newest seen: ${s.versions.newest}` : "No version reported" }), s.versions.outdated > 0);

  hbars(document.getElementById("e-stale-bars"), [
    { key: "d7", label: "7 to 13 days", value: s.stale.d7, color: "var(--sev-medium)" },
    { key: "d14", label: "14 to 29 days", value: s.stale.d14, color: "var(--sev-high)" },
    { key: "d30", label: "30 to 89 days", value: s.stale.d30, color: "var(--sev-high)" },
    { key: "d90", label: "90 days or more", value: s.stale.d90, color: "var(--sev-critical)" },
  ], { unit: "devices" });

  const dh = document.getElementById("e-drift-head");
  clear(dh);
  const cur = s.versions.current;
  const tot = Math.max(1, cur + s.versions.outdated);
  dh.append(
    h("div", { class: "drift-bar" }, h("i", { class: "drift-cur", style: { flexGrow: String(cur / tot) } }), h("i", { class: "drift-old", style: { flexGrow: String(s.versions.outdated / tot) } })),
    h("p", { class: "drift-legend" }, h("span", {}, h("i", { class: "key key-cur" }), h("b", { text: num(cur) }), " on the newest agent for their platform"), h("span", {}, h("i", { class: "key key-old" }), h("b", { text: num(s.versions.outdated) }), " behind")),
  );
  hbars(document.getElementById("e-drift"), s.versions.list.map((v) => ({ key: `${v.platform}|${v.version}`, label: v.version, value: v.count, color: v.outdated ? "var(--sev-medium)" : "var(--self)", note: `${v.platformName}${v.outdated ? ", behind" : ", newest"}` })), { unit: "devices" });

  setText(document.getElementById("e-worst-count"), `${num(Math.min(s.worst.length, 40))} of ${plural(s.withIssues, "device")} with any issue`);
  const rows = document.getElementById("e-rows");
  const shown = s.worst.slice(0, isWall() ? fitCount(rows, 37, 24, 3) : 40);
  reconcile(rows, shown, (w) => w.id, rowEl, fillRow, { instantExit: true });
  if (!shown.length) rows.append(h("tr", {}, h("td", { colspan: "8", class: "calm-cell" }, icon("check", 16), " No device has an issue")));

  const note = document.getElementById("e-map-note");
  clear(note);
  if (d.mapAvailable) {
    const locs = s.locations ?? [];
    const p = s.placement;
    const points = locs.map((l) => ({
      key: l.key,
      label: l.city ?? l.country ?? "Unknown",
      lat: l.lat,
      lon: l.lon,
      value: l.devices,
      state: l.worst,
      detail: [
        { value: num(l.devices), label: "devices" },
        ...(l.bad ? [{ value: num(l.bad), label: "bad health", color: "var(--bad)" }] : []),
        ...(l.suspicious ? [{ value: num(l.suspicious), label: "suspicious", color: "var(--warn)" }] : []),
        ...(l.stale ? [{ value: num(l.stale), label: "stale 7+ days", color: "var(--sev-high)" }] : []),
        { value: l.source === "sophos" ? "Sophos" : "DB-IP", label: "located by" },
      ],
    }));
    renderMap(document.getElementById("e-map"), points, { label: "Devices by public egress location", empty: p ? "No device has a located egress IP yet." : "Reading egress IPs from the Data Lake…" });
    const list = document.getElementById("e-locs");
    clear(list);
    const max = Math.max(1, ...locs.map((l) => l.devices));
    for (const l of locs.slice(0, 9)) {
      list.append(
        h(
          "div",
          { class: `loc loc-${l.worst}` },
          icon(l.worst === "bad" ? "critical" : l.worst === "suspicious" ? "warning" : "low", 14),
          h("span", { class: "loc-name" }, h("b", { text: l.city ?? l.country ?? "Unknown" }), h("small", { text: l.bad ? ` ${num(l.bad)} bad` : l.suspicious ? ` ${num(l.suspicious)} suspicious` : l.stale ? ` ${num(l.stale)} stale` : "" })),
          h("span", { class: "loc-bar" }, h("i", { style: { width: `${(l.devices / max) * 100}%` } })),
          h("b", { class: "loc-n num", text: num(l.devices) }),
        ),
      );
    }
    if (p) {
      list.append(h("div", { class: "loc loc-none" }, icon("info", 14), h("span", { class: "loc-name" }, h("b", { text: "Not placed" }), h("small", { text: ` ${num(p.unplaced)} IP not located, ${num(p.noEgress)} no egress seen` })), h("span"), h("b", { class: "loc-n num", text: num(p.unplaced + p.noEgress) })));
      note.append(
        gapNote(
          `Placed ${num(p.placed)} of ${num(s.total)} devices: ${num(p.sources.sophos)} by Sophos geolocation, ${num(p.sources.dbip)} by DB-IP. Location is the device's public egress IP in the last 30 days (xdr_data.meta_public_ip, not in the published schema), not its physical location.`,
        ),
      );
    }
    for (const n of d.egressNotes ?? []) note.append(gapNote(n));
  }
  const prev = st?.data?.summary;
  if (!first && prev) {
    if (prev.health.bad + prev.health.suspicious !== s.health.bad + s.health.suspicious) pulse(document.getElementById("e-unhealthy"));
    if (prev.staleOver7 !== s.staleOver7) pulse(document.getElementById("e-stale"));
  }
}

export default {
  id: "endpoints",
  mount(root, d, ctx) {
    st = build(root, d, ctx);
    st.data = d;
    fill(d, true);
  },
  update(d) {
    if (!st) return;
    fill(d, false);
    const fc = st.wrap.querySelector(".view-head .fresh");
    if (fc) fc.replaceWith(freshChip(d.freshness));
    st.data = d;
  },
  unmount() {
    st = null;
  },
};
