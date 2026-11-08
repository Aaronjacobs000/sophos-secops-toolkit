// Reports: pick a report from the catalogue, set its parameters, run it, read
// the preview, then download the PDF or any table as CSV. A run happens on the
// server (it may run Search GraphQL searches for a minute or two); the page
// polls it and keeps the form as it was.

import { h, clear } from "../dom.js";
import { api, store, ApiError } from "../api.js";
import { icon } from "../icons.js";
import { num, duration, clock } from "../format.js";
import { hbars, stackBar, tipOn } from "../viz.js";
import { panel, viewHead, segmented } from "./common.js";

let st = null;

const TONE = {
  bad: "var(--bad)",
  warn: "var(--warn)",
  good: "var(--good)",
  neutral: "var(--ink-4)",
  accent: "var(--accent)",
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
  mdr: "var(--mdr)",
  self: "var(--self)",
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function browserZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** "6 Nov 2026 14:05" in the report's zone, as the PDF prints it. */
function when(ms, tz, withTime = true) {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "-";
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", hourCycle: "h23" }).formatToParts(ms).map((p) => [p.type, p.value]));
  const hh = String(Number(parts.hour) % 24).padStart(2, "0");
  return `${Number(parts.day)} ${MONTHS[Number(parts.month) - 1]} ${parts.year}${withTime ? ` ${hh}:${parts.minute}` : ""}`;
}

function cell(value, col, tz) {
  if (value === null || value === undefined || value === "") return "-";
  switch (col.format) {
    case "number":
      return typeof value === "number" ? num(value) : String(value);
    case "datetime":
      return typeof value === "number" ? when(value, tz) : String(value);
    case "date":
      return typeof value === "number" ? when(value, tz, false) : String(value);
    case "duration":
      return typeof value === "number" ? duration(value) : String(value);
    default:
      return String(value);
  }
}

// ------------------------------------------------------------------ the form

function windowsFor(def, tenant) {
  return (def.windows ?? []).map((w) => ({ ...w, allowed: tenant !== "all" || w.allTenants }));
}

function defaultTenant(data, def) {
  if (!data.multi) return data.tenants[0]?.id ?? "";
  const saved = store.get("tenant", "all");
  if (def.scope === "tenant") {
    const pick = data.tenants.find((t) => t.id === saved) ?? data.tenants.find((t) => t.generation === "fusion") ?? data.tenants[0];
    return pick?.id ?? "";
  }
  return data.tenants.some((t) => t.id === saved) ? saved : "all";
}

function formState(data, def, prev = {}) {
  const tenant = prev.tenant && (prev.tenant !== "all" || def.scope === "any") ? prev.tenant : defaultTenant(data, def);
  const wins = windowsFor(def, tenant);
  const win = wins.find((w) => w.key === prev.window && w.allowed)?.key ?? (wins.find((w) => w.key === def.defaultWindow && w.allowed) ?? wins.find((w) => w.allowed))?.key ?? null;
  return {
    tenant,
    window: win,
    user: prev.user ?? "",
    match: prev.match ?? "user",
    value: prev.value ?? "",
    schemas: prev.schemas ?? null,
    groupBy: prev.groupBy ?? "sensor_type",
    sensors: prev.sensors ?? [],
  };
}

function fieldRow(label, control, hint) {
  return h("div", { class: "field rp-field" }, h("span", { class: "field-label", text: label }), control, hint ? h("small", { class: "field-hint", text: hint }) : null);
}

function renderForm() {
  const { data, def, form } = st;
  const box = st.formBox;
  clear(box);
  const tenantGen = data.tenants.find((t) => t.id === form.tenant)?.generation;
  const rows = [];

  if (data.multi) {
    const select = h("select", { class: "rp-select", "aria-label": "Tenant" });
    if (def.scope === "any") select.append(h("option", { value: "all", text: `All tenants (${num(data.tenants.length)})` }));
    for (const t of data.tenants) select.append(h("option", { value: t.id, text: `${t.name}${t.generation === "classic" ? " (Classic)" : t.generation === "fusion" ? " (Fusion)" : ""}` }));
    select.value = form.tenant;
    select.addEventListener("change", () => {
      form.tenant = select.value;
      if (select.value !== "all") store.set("tenant", select.value);
      Object.assign(form, formState(data, def, form));
      renderForm();
    });
    rows.push(fieldRow("Tenant", select, def.scope === "tenant" ? "This report runs on one tenant." : null));
  } else {
    rows.push(fieldRow("Tenant", h("div", { class: "rp-static", text: data.tenants[0]?.name ?? "" })));
  }

  if (def.windows) {
    const wins = windowsFor(def, form.tenant);
    const seg = segmented(wins.map((w) => [w.key, w.label]), form.window, (v) => {
      if (!wins.find((w) => w.key === v)?.allowed) return;
      form.window = v;
      renderForm();
    }, "Time range");
    seg.querySelectorAll("button").forEach((b, i) => {
      if (!wins[i].allowed) {
        b.disabled = true;
        b.title = "Reads Sophos again for every tenant: pick one tenant for this window";
      }
    });
    rows.push(fieldRow("Time range", seg, wins.some((w) => !w.allowed) ? "Longer windows read Sophos again, so they run on one tenant." : null));
  } else {
    rows.push(fieldRow("Time range", h("div", { class: "rp-static", text: "Current state, plus the 30-day trend the toolkit keeps" })));
  }

  if (def.inputs.includes("user")) {
    const input = h("input", { type: "search", class: "rp-input", value: form.user, placeholder: "jsmith, j.smith@example.com or part of one", autocomplete: "off", spellcheck: "false", "aria-label": "User" });
    input.addEventListener("input", () => (form.user = input.value));
    input.addEventListener("keydown", (e) => e.key === "Enter" && run());
    rows.push(fieldRow("User", input, "Matches any account name that contains it, in every source."));
  }

  if (def.inputs.includes("match")) {
    const kinds = [["user", "User"], ["ip", "IP address"], ["host", "Device"]];
    rows.push(fieldRow("Search for", segmented(kinds, form.match, (v) => {
      form.match = v;
      form.schemas = null;
      renderForm();
    }, "Search for")));
    const input = h("input", { type: "search", class: "rp-input", value: form.value, placeholder: form.match === "ip" ? "203.0.113.10" : form.match === "host" ? "LT-0042 or part of a name" : "jsmith or part of a name", autocomplete: "off", spellcheck: "false", "aria-label": "Value" });
    input.addEventListener("input", () => (form.value = input.value));
    input.addEventListener("keydown", (e) => e.key === "Enter" && run());
    rows.push(fieldRow(form.match === "ip" ? "IP address" : form.match === "host" ? "Device" : "User", input, form.match === "ip" ? "An exact address." : "Matches any value that contains it."));
    const all = data.logSearch.schemas[form.match] ?? [];
    if (!form.schemas) form.schemas = all.filter((s) => !s.snapshot).map((s) => s.id);
    const boxes = h("div", { class: "rp-checks" });
    for (const s of all) {
      const cb = h("input", { type: "checkbox", value: s.id, checked: form.schemas.includes(s.id) });
      cb.addEventListener("change", () => {
        form.schemas = cb.checked ? [...form.schemas, s.id] : form.schemas.filter((x) => x !== s.id);
        renderGroupHint();
      });
      boxes.append(h("label", { class: "check" }, cb, s.label));
    }
    rows.push(fieldRow("Event types", boxes, `Only the ${num(all.length)} event types that carry ${form.match === "ip" ? "an IP address" : form.match === "host" ? "a device name" : "a user"} field can be searched this way. Inventory snapshots start unticked.`));
    const sel = h("select", { class: "rp-select", "aria-label": "Group by" });
    for (const g of data.logSearch.groupBy) sel.append(h("option", { value: g.id, text: g.label }));
    sel.value = form.groupBy;
    const hint = h("small", { class: "field-hint" });
    const renderGroupHint = () => {
      const g = data.logSearch.groupBy.find((x) => x.id === form.groupBy);
      const covered = g?.schemas === "all" ? form.schemas : form.schemas.filter((s) => g?.schemas.includes(s));
      hint.textContent = g?.schemas === "all" ? "Every chosen event type has this field." : covered.length ? `Counts ${num(covered.length)} of the ${num(form.schemas.length)} chosen event types; the others have no such field.` : "None of the chosen event types has this field.";
    };
    sel.addEventListener("change", () => {
      form.groupBy = sel.value;
      renderGroupHint();
    });
    renderGroupHint();
    rows.push(h("div", { class: "field rp-field" }, h("span", { class: "field-label", text: "Group by" }), sel, hint));
    if (data.logSearch.sensors.length) {
      const sensors = h("div", { class: "rp-checks" });
      for (const s of data.logSearch.sensors) {
        const cb = h("input", { type: "checkbox", value: s.id, checked: form.sensors.includes(s.id) });
        cb.addEventListener("change", () => (form.sensors = cb.checked ? [...form.sensors, s.id] : form.sensors.filter((x) => x !== s.id)));
        sensors.append(h("label", { class: "check", title: s.id }, cb, s.label));
      }
      rows.push(fieldRow("Data sources (optional)", sensors, "Tick none to search every source. These are the sources the Sources screen has seen."));
    }
  }

  const fusionNote = def.fusion === "required" && form.tenant !== "all" && tenantGen === "classic" ? "This tenant is on the Classic APIs. This report needs Sophos Fusion." : def.fusion === "partial" && tenantGen === "classic" ? "This tenant is on the Classic APIs: the sections that need Sophos Fusion will say so." : null;
  const runBtn = h("button", { class: "btn btn-primary", type: "button", onclick: run, disabled: !!st.running || (def.fusion === "required" && tenantGen === "classic") }, icon("play", 15), st.running ? "Running" : "Run report");
  rows.push(
    h(
      "div",
      { class: "rp-actions" },
      runBtn,
      h("span", { class: "dim small", text: `Times shown in ${browserZone()}.` }),
      fusionNote ? h("p", { class: "rp-warn" }, icon("warning", 13), h("span", { text: fusionNote })) : null,
    ),
  );
  box.append(h("div", { class: "rp-intro" }, h("h2", { text: def.title }), h("p", { class: "dim", text: def.summary }), h("p", { class: "dim small" }, h("b", { text: "Reads: " }), def.apis)), ...rows);
}

// ------------------------------------------------------------------ running

async function run() {
  if (st.running) return;
  const { def, form } = st;
  const params = {};
  if (def.inputs.includes("user")) params.user = form.user.trim();
  if (def.inputs.includes("match")) Object.assign(params, { match: form.match, value: form.value.trim(), schemas: form.schemas, groupBy: form.groupBy, sensors: form.sensors });
  st.status = null;
  try {
    const res = await api.post("/api/reports/run", { reportId: def.id, tenant: form.tenant, window: form.window, timeZone: browserZone(), params });
    st.running = res.run;
    st.status = res.run;
    renderForm();
    renderRun();
    poll();
  } catch (err) {
    st.ctx.toast(err instanceof ApiError ? err.message : String(err), "bad");
  }
}

function poll() {
  clearTimeout(st.timer);
  st.timer = setTimeout(async () => {
    if (!st?.running) return;
    try {
      const res = await api.get(`/api/reports/runs/${st.running.id}`);
      st.status = res.run;
      if (res.run.status === "running") {
        renderRun();
        poll();
        return;
      }
      st.running = null;
      st.doc = res.document;
      st.runId = res.run.id;
      store.set("report-run", res.run.id);
      renderForm();
      renderRun();
      renderPreview();
      refreshRuns();
    } catch (err) {
      st.running = null;
      st.status = { status: "failed", error: err instanceof ApiError ? err.message : String(err) };
      renderForm();
      renderRun();
    }
  }, 1500);
}

function renderRun() {
  const box = st.runBox;
  clear(box);
  const s = st.status;
  if (!s) return;
  if (s.status === "running") {
    box.append(h("div", { class: "rp-progress" }, h("i", { class: "spin", "aria-hidden": "true" }), h("b", { text: s.step }), h("span", { class: "dim", text: ` ${duration(Date.now() - s.startedAt)} so far` })));
  } else if (s.status === "failed") {
    box.append(h("div", { class: "rp-progress rp-failed", role: "alert" }, icon("warning", 15), h("span", { text: s.error ?? "The report failed." })));
  }
}

async function refreshRuns() {
  try {
    const d = await api.get("/api/reports");
    st.data.runs = d.runs;
    renderRuns();
  } catch {
    // The list just doesn't refresh.
  }
}

function renderRuns() {
  const box = st.runsBox;
  clear(box);
  const runs = st.data.runs.filter((r) => r.status !== "running");
  if (!runs.length) return;
  box.append(h("h3", { class: "rp-sub", text: "This session's runs" }));
  const list = h("div", { class: "rp-runs" });
  for (const r of runs.slice(0, 8)) {
    list.append(
      h(
        "button",
        {
          type: "button",
          class: `rp-run${r.id === st.runId ? " on" : ""}`,
          disabled: r.status !== "done",
          onclick: async () => {
            const res = await api.get(`/api/reports/runs/${r.id}`);
            st.doc = res.document;
            st.runId = r.id;
            store.set("report-run", r.id);
            renderRuns();
            renderPreview();
          },
        },
        h("b", { text: r.title }),
        h("span", { class: "dim", text: r.status === "done" ? `${r.subject ?? ""}, ${clock(r.finishedAt)}` : `Failed: ${r.error ?? ""}` }),
      ),
    );
  }
  box.append(list);
}

// ------------------------------------------------------------------ preview

function kpiGrid(items) {
  return h(
    "div",
    { class: "rp-kpis" },
    items.map((k) => h("div", { class: `rp-kpi${k.tone ? " toned" : ""}`, style: k.tone ? `--tone: ${TONE[k.tone]}` : null }, h("span", { class: "rp-kpi-label", text: k.label }), h("b", { class: "rp-kpi-num num", text: k.value }), k.note ? h("span", { class: "rp-kpi-note", text: k.note }) : null)),
  );
}

function seriesChart(b) {
  const totals = b.series.map((_, i) => b.buckets.reduce((a, x) => a + (x.values[i] ?? 0), 0));
  const all = totals.reduce((a, x) => a + x, 0);
  const wrap = h("div", { class: "rp-block" }, h("div", { class: "rp-block-head" }, h("h4", { text: b.title }), all && !b.levels ? h("span", { class: "dim small", text: `${num(all)} ${b.unit}` }) : null));
  if (!all || !b.buckets.length) {
    wrap.append(h("p", { class: "dim small", text: b.empty ?? "Nothing to show." }));
    return wrap;
  }
  const latest = b.buckets[b.buckets.length - 1].values;
  if (b.series.length > 1) {
    wrap.append(h("div", { class: "rp-legend" }, b.series.map((s, i) => h("span", {}, h("i", { style: { background: TONE[s.tone] } }), `${s.label} `, h("b", { text: b.levels ? `${num(latest[i] ?? 0)} now` : num(totals[i]) })))));
  }
  const W = 720;
  const H = 150;
  const max = Math.max(1, ...b.buckets.map((x) => x.values.reduce((a, v) => a + v, 0)));
  const colW = W / b.buckets.length;
  const bw = Math.max(1, Math.min(colW * 0.72, 30));
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "rp-series");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `${b.title}: ${num(all)} ${b.unit}`);
  for (const f of [0.5, 1]) {
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", "0");
    line.setAttribute("x2", String(W));
    line.setAttribute("y1", String(H - H * f));
    line.setAttribute("y2", String(H - H * f));
    line.setAttribute("class", "rp-gridline");
    svg.append(line);
  }
  b.buckets.forEach((bucket, i) => {
    let y = H;
    const g = document.createElementNS(ns, "g");
    g.setAttribute("tabindex", "0");
    bucket.values.forEach((v, j) => {
      if (v <= 0) return;
      const hgt = Math.max(1, (H * v) / max);
      const r = document.createElementNS(ns, "rect");
      r.setAttribute("x", String(i * colW + (colW - bw) / 2));
      r.setAttribute("y", String(y - hgt));
      r.setAttribute("width", String(bw));
      r.setAttribute("height", String(hgt));
      r.setAttribute("fill", TONE[b.series[j]?.tone] ?? "var(--accent)");
      g.append(r);
      y -= hgt;
    });
    const hit = document.createElementNS(ns, "rect");
    hit.setAttribute("x", String(i * colW));
    hit.setAttribute("y", "0");
    hit.setAttribute("width", String(colW));
    hit.setAttribute("height", String(H));
    hit.setAttribute("fill", "transparent");
    g.append(hit);
    tipOn(g, () => [bucket.label, b.series.map((s, j) => ({ value: num(bucket.values[j] ?? 0), label: s.label, color: TONE[s.tone] }))]);
    svg.append(g);
  });
  // About one label per 90 px of chart, so labels never run together on a phone.
  const every = Math.max(1, Math.ceil(b.buckets.length / Math.max(3, Math.floor(Math.min(window.innerWidth - 80, 1100) / 90))));
  const axis = h("div", { class: "rp-axis" }, b.buckets.map((x, i) => (i % every === 0 ? h("span", { style: { left: `${((i + 0.5) / b.buckets.length) * 100}%` }, text: x.label }) : null)));
  wrap.append(h("div", { class: "rp-chart" }, svg, h("span", { class: "rp-max num", text: num(max) })), axis);
  if (b.note) wrap.append(h("p", { class: "dim small", text: b.note }));
  return wrap;
}

function tableView(b, tz) {
  const shown = 100;
  const columns = b.columns.filter((c) => c.csv !== false);
  const head = h("div", { class: "rp-block-head" }, h("h4", { text: b.title }), h("span", { class: "rp-table-tools" }, h("span", { class: "dim small", text: b.rows.length > shown ? `${num(shown)} of ${num(b.rows.length)} rows` : `${num(b.rows.length)} ${b.rows.length === 1 ? "row" : "rows"}` }), b.rows.length ? h("a", { class: "btn btn-ghost btn-sm", href: `/api/reports/runs/${st.runId}/csv/${encodeURIComponent(b.id)}`, download: "" }, icon("download", 13), "CSV") : null));
  const table = h("table", { class: "dev-table rp-table" });
  table.append(h("thead", {}, h("tr", {}, columns.map((c) => h("th", { class: c.format === "number" || c.format === "duration" ? "num" : "", text: c.label })))));
  const body = h("tbody");
  for (const r of b.rows.slice(0, shown)) {
    body.append(h("tr", {}, columns.map((c) => h("td", { class: c.format === "number" || c.format === "duration" ? "num" : c.format === "mono" ? "mono" : "", text: cell(r[c.key], c, tz) }))));
  }
  if (!b.rows.length) body.append(h("tr", {}, h("td", { colspan: String(columns.length), class: "dim rp-empty", text: b.empty ?? "No rows." })));
  table.append(body);
  const notes = [];
  if (b.rows.length > shown) notes.push(`The preview shows the first ${num(shown)} rows; the CSV has all ${num(b.rows.length)}.`);
  if (b.total && b.total > b.rows.length) notes.push(`Sophos held ${num(b.total)}; the report read ${num(b.rows.length)}.`);
  if (b.note) notes.push(b.note);
  return h("div", { class: "rp-block" }, head, h("div", { class: "table-wrap" }, table), notes.length ? h("p", { class: "dim small", text: notes.join(" ") }) : null);
}

function blockView(b, tz) {
  switch (b.kind) {
    case "kpis":
      return kpiGrid(b.items);
    case "facts":
      return h("div", { class: "rp-block" }, b.title ? h("h4", { text: b.title }) : null, h("dl", { class: "rp-facts" }, b.items.map((it) => [h("dt", { text: it.label }), h("dd", { text: it.value })])));
    case "bars": {
      const box = h("div", { class: "rp-block" }, h("h4", { text: b.title }));
      if (!b.rows.length || b.rows.every((r) => !r.value)) box.append(h("p", { class: "dim small", text: b.empty ?? "Nothing to show." }));
      else hbars(box, b.rows.map((r, i) => ({ key: `${i}`, label: r.label, value: r.value, note: r.note, color: TONE[r.tone ?? "accent"] })), { unit: b.unit });
      if (b.note) box.append(h("p", { class: "dim small", text: b.note }));
      return box;
    }
    case "series":
      return seriesChart(b);
    case "stack": {
      const total = b.segments.reduce((a, s) => a + s.value, 0);
      const box = h("div", { class: "rp-block" }, h("h4", { text: b.title }));
      if (!total) {
        box.append(h("p", { class: "dim small", text: "None in the window." }));
        return box;
      }
      stackBar(box, b.segments.map((s, i) => ({ key: `${i}`, label: s.label, value: s.value, color: TONE[s.tone] })), { title: b.title });
      box.append(h("div", { class: "rp-legend" }, b.segments.map((s) => h("span", {}, h("i", { style: { background: TONE[s.tone] } }), `${s.label} `, h("b", { text: num(s.value) }), total ? h("span", { class: "dim", text: ` ${Math.round((s.value / total) * 100)}%` }) : null))));
      if (b.note) box.append(h("p", { class: "dim small", text: b.note }));
      return box;
    }
    case "table":
      return tableView(b, tz);
    case "note":
      return h("p", { class: `rp-note rp-note-${b.tone}` }, h("b", { text: b.tone === "gap" ? "Gap. " : b.tone === "warn" ? "Caution. " : "" }), b.text);
    case "text":
      return h("p", { class: "rp-text", text: b.text });
    default:
      return null;
  }
}

function renderPreview() {
  const box = st.previewBox;
  clear(box);
  const d = st.doc;
  if (!d) {
    box.append(h("div", { class: "rp-placeholder" }, icon("report", 28), h("p", { text: "Run a report to see it here. The PDF and the CSV files come from the same run." })));
    return;
  }
  const tz = d.timeZone;
  const pdf = (paper) => `/api/reports/runs/${st.runId}/pdf?paper=${paper}`;
  box.append(
    h(
      "header",
      { class: "rp-doc-head" },
      h(
        "div",
        { class: "rp-doc-title" },
        h("span", { class: "rp-eyebrow", text: d.demo ? "Report, demo data" : "Report" }),
        h("h2", { text: d.title }),
        h("p", { class: "rp-subject", text: d.subject }),
        h("p", { class: "dim small", text: [d.scope.label, d.window ? d.window.label : "Current state", `Times in ${tz}`, `Generated ${when(d.generatedAt, tz)}`].join("  ·  ") }),
      ),
      h(
        "div",
        { class: "rp-doc-tools" },
        h("a", { class: "btn btn-primary", href: pdf("a4"), download: "" }, icon("download", 15), "PDF, A4"),
        h("a", { class: "btn", href: pdf("letter"), download: "" }, "US Letter"),
      ),
    ),
  );
  if (d.summary.length) box.append(kpiGrid(d.summary));
  for (const s of d.sections) {
    box.append(h("section", { class: "rp-section" }, h("h3", { text: s.title }), s.lead ? h("p", { class: "dim rp-lead", text: s.lead }) : null, s.blocks.map((b) => blockView(b, tz))));
  }
  const calls = d.demo ? "None: demo data." : d.calls.total ? `${num(d.calls.total)}, all reads: ${Object.entries(d.calls.byKind).map(([k, v]) => `${k} ${num(v)}`).join(", ")}.` : "None: read from the toolkit's cache.";
  box.append(
    h(
      "section",
      { class: "rp-section" },
      h("h3", { text: "About this report" }),
      h("dl", { class: "rp-facts" }, [
        [h("dt", { text: "Credential" }), h("dd", { text: d.demo ? "Demo mode: every tenant, person, device and figure is fictional" : d.scope.credential })],
        [h("dt", { text: "Sophos calls" }), h("dd", { text: calls })],
        ...d.provenance.map((p) => [h("dt", { text: p.label }), h("dd", { text: `${p.detail}${p.asOf ? `, ${when(p.asOf, tz)}` : ""}` })]),
      ]),
      d.gaps.map((g) => h("p", { class: "rp-note rp-note-gap" }, h("b", { text: "Gap. " }), g)),
    ),
  );
}

// ------------------------------------------------------------------ catalogue

function renderCatalogue() {
  const box = st.catBox;
  clear(box);
  for (const def of st.data.reports) {
    const classicOnly = st.data.tenants.length > 0 && st.data.tenants.every((t) => t.generation === "classic");
    const blocked = def.fusion === "required" && classicOnly;
    box.append(
      h(
        "button",
        {
          type: "button",
          class: `rp-card${def.id === st.def.id ? " on" : ""}`,
          "aria-pressed": def.id === st.def.id ? "true" : "false",
          title: blocked ? "Needs a tenant on Sophos Fusion" : null,
          onclick: () => {
            st.def = def;
            st.form = formState(st.data, def, st.form);
            if (def.inputs.includes("match")) st.form.schemas = null;
            store.set("report", def.id);
            renderCatalogue();
            renderForm();
            history.replaceState(null, "", `#/reports?report=${def.id}`);
          },
        },
        h("span", { class: "rp-card-title" }, h("b", { text: def.title }), def.fusion === "required" ? h("span", { class: "gen gen-fusion", text: "Fusion" }) : null),
        h("span", { class: "rp-card-text", text: def.summary }),
        h("span", { class: "rp-card-meta", text: def.audience }),
      ),
    );
  }
  box.append(
    h(
      "details",
      { class: "rp-not" },
      h("summary", { text: `Not in this toolkit (${st.data.notBuilt.length})` }),
      h("ul", {}, st.data.notBuilt.map((n) => h("li", {}, h("b", { text: n.title }), h("span", { class: "dim", text: ` ${n.reason}` })))),
    ),
  );
}

function build(root, data, ctx) {
  const wanted = ctx.query.report ?? store.get("report", "user");
  const def = data.reports.find((r) => r.id === wanted) ?? data.reports[0];
  store.set("report", def.id);
  st = { data, def, ctx, form: formState(data, def, st?.form ?? {}), running: null, status: null, doc: null, runId: null, timer: null };
  st.catBox = h("div", { class: "rp-catalogue" });
  st.formBox = h("div", { class: "rp-form" });
  st.runBox = h("div", { class: "rp-runbox", "aria-live": "polite" });
  st.runsBox = h("div", { class: "rp-runs-box" });
  st.previewBox = h("div", { class: "rp-preview" });
  root.append(
    h(
      "section",
      { class: "reports" },
      viewHead("Reports", "Run a report, read it here, then download the PDF or any table as CSV."),
      h(
        "div",
        { class: "rp-grid" },
        panel("Reports", { class: "rp-left", icon: "report" }, st.catBox),
        h("div", { class: "rp-main" }, panel("Parameters", { class: "rp-params", icon: "gear" }, st.formBox, st.runBox), panel("Preview", { class: "rp-doc", icon: "layers" }, st.previewBox, st.runsBox)),
      ),
    ),
  );
  renderCatalogue();
  renderForm();
  renderRun();
  renderRuns();
  renderPreview();
  // A run from earlier in this session comes back after a reload.
  const last = ctx.query.run ?? store.get("report-run", null);
  const running = data.runs.find((r) => r.status === "running");
  if (running) {
    st.running = running;
    st.status = running;
    renderForm();
    renderRun();
    poll();
  } else if (last && data.runs.some((r) => r.id === last && r.status === "done")) {
    api.get(`/api/reports/runs/${last}`).then((res) => {
      if (!st || !res.document) return;
      st.doc = res.document;
      st.runId = last;
      renderRuns();
      renderPreview();
    }, () => undefined);
  }
}

export default {
  id: "reports",
  async load() {
    return api.get("/api/reports");
  },
  mount(root, data, ctx) {
    build(root, data, ctx);
  },
  update(data, ctx) {
    // A new report choice comes in through the address; anything else keeps the form as it is.
    if (!st) return;
    const wanted = ctx.query.report;
    st.data.runs = data.runs;
    if (wanted && wanted !== st.def.id) {
      const root = st.catBox.closest(".view");
      clearTimeout(st.timer);
      const keep = st.form;
      clear(root);
      st = { form: keep };
      build(root, data, ctx);
      return;
    }
    renderRuns();
  },
  unmount() {
    if (st) clearTimeout(st.timer);
    st = null;
  },
};
