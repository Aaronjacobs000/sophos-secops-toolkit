// Setup: add a Sophos API credential (first run), switch between saved
// credentials, demo mode, case targets, the wall playlist, privacy, the cache
// wipe and the optional DB-IP download.

import { h, clear } from "../dom.js";
import { icon } from "../icons.js";
import { api } from "../api.js";
import { num, date, hours, SEV_LABEL } from "../format.js";
import { sevBadge } from "./common.js";

const SEVS = ["critical", "high", "medium", "low", "info"];
const VIEW_NAMES = { front: "Overview", msp: "MSP wall", now: "Now", cases: "Cases", endpoints: "Endpoints", signins: "Sign-ins", sources: "Data sources", ai: "AI usage" };

function field(label, input, hint) {
  return h("label", { class: "field" }, h("span", { class: "field-label", text: label }), input, hint ? h("small", { class: "field-hint", text: hint }) : null);
}

function credentialForm(ctx, first) {
  const label = h("input", { type: "text", name: "label", placeholder: "e.g. Head office, or My MSP", autocomplete: "off", maxlength: "80" });
  const clientId = h("input", { type: "text", name: "clientId", placeholder: "Client ID", autocomplete: "off", spellcheck: "false", required: true });
  const secret = h("input", { type: "password", name: "clientSecret", placeholder: "Client secret", autocomplete: "off", spellcheck: "false", required: true });
  const status = h("p", { class: "form-status", role: "status" });
  const button = h("button", { class: "btn btn-primary", type: "submit" }, icon("key", 15), "Check and save");
  const form = h(
    "form",
    { class: "cred-form", autocomplete: "off" },
    field("Name shown on screens", label, "Sophos does not return a tenant's name to a tenant credential, so this is what the screens call it."),
    field("Client ID", clientId),
    field("Client secret", secret, "Stored encrypted (AES-256-GCM) in data/, with the key kept outside the repo."),
    h("div", { class: "form-actions" }, button, status),
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    button.disabled = true;
    clear(status).append(h("span", { class: "spin" }), " Checking with Sophos (token and whoami, both reads)…");
    try {
      const res = await api.post("/api/credentials", { label: label.value, clientId: clientId.value, clientSecret: secret.value });
      secret.value = "";
      clientId.value = "";
      clear(status).append(icon("check", 15), ` Saved. Detected a ${res.credential.kind} credential.`);
      ctx.toast(`${res.credential.label}: ${res.credential.kind} credential, screens adjusted`);
      await ctx.refreshStatus();
      setTimeout(() => ctx.navigate("front"), first ? 600 : 300);
    } catch (err) {
      clear(status).append(icon("warning", 15), ` ${err.message}`);
      status.classList.add("t-bad");
    } finally {
      button.disabled = false;
    }
  });
  return form;
}

function card(title, ic, ...body) {
  return h("section", { class: "panel setup-card reveal" }, h("header", { class: "panel-head" }, h("h2", {}, icon(ic, 15), title)), h("div", { class: "panel-body" }, ...body));
}

export default {
  id: "setup",
  async load() {
    return api.get("/api/status");
  },
  mount(root, d, ctx) {
    const wrap = h("section", { class: "setup" });
    const first = !d.configured;
    if (first) {
      wrap.append(
        h(
          "div",
          { class: "hero-setup reveal" },
          h("img", { src: "/img/mark.svg", alt: "", width: "56", height: "56", class: "hero-mark" }),
          h("h1", { text: "SecOps Toolkit" }),
          h("p", { class: "lede", text: "Wall boards and dashboards for Sophos tenants and partners, running on this computer. Add an API credential and the toolkit works out what it can see: one tenant, or every tenant a partner or organization manages." }),
          h("p", { class: "lede dim", text: "Unofficial. Uses the public Sophos APIs. It changes no setting, policy, case or device in Sophos." }),
        ),
      );
    }
    const grid = h("div", { class: "setup-grid" });
    const howTo = h(
      "ol",
      { class: "steps" },
      h("li", {}, "In Sophos Fusion (formerly Sophos Central), open Global Settings, then API Credentials Management. Partners use Settings, API Credentials in the Partner Dashboard."),
      h("li", {}, "Add a credential with the ", h("b", { text: "Service Principal Read-Only" }), " role. The toolkit only reads."),
      h("li", {}, "Paste the client ID and secret here. Sophos shows the secret once."),
    );
    grid.append(card(first ? "Add your first credential" : "Add a credential", "key", howTo, credentialForm(ctx, first)));

    const demo = card(
      "Demo mode",
      "eye",
      h("p", { class: "dim", text: "Explore every screen with fictional tenants, devices and cases. No Sophos calls." }),
      h(
        "div",
        { class: "btn-row" },
        h("button", { class: `btn ${d.demo && d.settings.demoContext === "partner" ? "btn-primary" : "btn-ghost"}`, type: "button", onclick: async () => { await api.post("/api/demo", { on: true, context: "partner" }); await ctx.refreshStatus(); ctx.navigate("front"); } }, icon("grid", 15), "Demo partner"),
        h("button", { class: `btn ${d.demo && d.settings.demoContext === "tenant" ? "btn-primary" : "btn-ghost"}`, type: "button", onclick: async () => { await api.post("/api/demo", { on: true, context: "tenant" }); await ctx.refreshStatus(); ctx.navigate("front"); } }, icon("tenant", 15), "Demo tenant"),
        d.demo && !d.forcedDemo ? h("button", { class: "btn btn-ghost", type: "button", onclick: async () => { await api.post("/api/demo", { on: false }); await ctx.refreshStatus(); ctx.navigate(d.credentials.length ? "front" : "setup"); } }, "Leave demo") : null,
      ),
    );
    grid.append(demo);

    if (d.credentials.length) {
      const list = h("div", { class: "cred-list" });
      for (const c of d.credentials) {
        const active = c.id === d.activeCredentialId && !d.demo;
        list.append(
          h(
            "div",
            { class: `cred${active ? " on" : ""}` },
            h("span", { class: "cred-ic" }, icon(c.kind === "tenant" ? "tenant" : "grid", 18)),
            h("span", { class: "cred-name" }, h("b", { text: c.label }), h("small", { text: `${c.kind} credential · ID ending ${c.hint} · added ${date(Date.parse(c.createdAt))}` })),
            active ? h("span", { class: "chip chip-on", text: d.status === "ready" ? "Active" : d.status }) : h("button", { class: "btn btn-ghost btn-sm", type: "button", text: "Use", onclick: async () => { await api.post(`/api/credentials/${c.id}/activate`, {}); await ctx.refreshStatus(); ctx.toast(`Switched to ${c.label}`); ctx.navigate("front"); } }),
            h("button", {
              class: "icon-btn",
              type: "button",
              title: "Remove from this computer",
              "aria-label": `Remove ${c.label}`,
              onclick: async () => {
                if (!confirm(`Remove ${c.label} from this computer? The credential itself stays in Sophos Fusion.`)) return;
                await api.del(`/api/credentials/${c.id}`);
                await ctx.refreshStatus();
                ctx.reload();
              },
            }, icon("trash", 16)),
          ),
        );
      }
      grid.append(card("Saved credentials", "lock", list, d.context ? h("p", { class: "dim small" }, `Active context: ${d.context.label}${d.context.multiTenant ? `, ${num(d.tenantCount)} tenants` : ""}. Screens shown: ${d.context.views.map((v) => VIEW_NAMES[v] ?? (v === "atlas" ? "Schema Atlas" : v === "reports" ? "Reports" : v)).join(", ")}.`) : null));
    }

    // Targets
    const inputs = {};
    const targets = h(
      "form",
      { class: "target-grid" },
      SEVS.map((k) => {
        inputs[k] = h("input", { type: "number", min: "1", max: "2160", value: String(d.settings.targets[k]), "aria-label": `${SEV_LABEL[k]} target in hours` });
        return h("label", {}, sevBadge(k), inputs[k], h("span", { class: "dim", text: "hours" }));
      }),
    );
    grid.append(
      card(
        "Case targets",
        "clock",
        h("p", { class: "dim", text: "Time from creation to close, per severity. No Sophos API carries an SLA, so these live here." }),
        targets,
        h("button", { class: "btn btn-ghost", type: "button", onclick: async () => { await api.put("/api/settings", { targets: Object.fromEntries(SEVS.map((k) => [k, Number(inputs[k].value)])) }); ctx.toast("Targets saved"); await ctx.refreshStatus(); } }, "Save targets"),
      ),
    );

    // Wall
    const secs = h("input", { type: "number", min: "10", max: "3600", value: String(d.settings.wall.seconds), "aria-label": "Seconds per board" });
    const checks = Object.entries(VIEW_NAMES).map(([v, label]) => {
      const cb = h("input", { type: "checkbox", value: v, checked: d.settings.wall.playlist.includes(v) });
      return h("label", { class: "check" }, cb, label);
    });
    const privacy = h("input", { type: "checkbox", checked: d.settings.privacy });
    grid.append(
      card(
        "Wall mode",
        "wall",
        h("p", { class: "dim" }, "Press ", h("kbd", { text: "W" }), " or the screen button for full screen boards that rotate. Arrow keys skip, Esc leaves. Open ", h("code", { text: "/?wall=1" }), " on a signage browser."),
        field("Seconds per board", secs),
        h("div", { class: "checks" }, checks),
        h("label", { class: "check" }, privacy, "Lobby privacy: hide tenant names, hostnames and case titles"),
        h(
          "button",
          {
            class: "btn btn-ghost",
            type: "button",
            onclick: async () => {
              const playlist = checks.map((c) => c.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
              await api.put("/api/settings", { wall: { seconds: Number(secs.value), playlist }, privacy: privacy.checked });
              ctx.toast("Wall settings saved");
              await ctx.refreshStatus();
            },
          },
          "Save wall settings",
        ),
      ),
    );

    // Cache and GeoIP
    const rows = d.cache.rows ? `${num(d.cache.rows.latest)} datasets and ${num(d.cache.rows.snapshots)} snapshots` : "unknown";
    grid.append(
      card(
        "Local data",
        "lock",
        h("p", { class: "dim", text: `Cached tenant data is encrypted on this computer and kept ${d.cache.retentionDays} days (${rows}). It sits outside the tenant's Sophos data region.` }),
        h(
          "button",
          {
            class: "btn btn-danger",
            type: "button",
            onclick: async () => {
              if (!confirm("Wipe the cache? Every cached dataset and snapshot is deleted and the cache key replaced. Credentials stay.")) return;
              const res = await api.post("/api/cache/wipe", { confirm: "wipe" });
              ctx.toast(`Cache wiped (${num(res.rows.latest)} rows left)`);
              await ctx.refreshStatus();
              ctx.reload();
            },
          },
          icon("trash", 15),
          "Wipe cache",
        ),
        h("hr"),
        h("p", { class: "dim", text: d.geoip.installed ? `DB-IP City Lite installed (${d.geoip.file}). ${d.geoip.attribution}.` : "Optional: DB-IP City Lite (CC BY 4.0, about 60 MB) places devices whose egress IP Sophos has not located. Downloaded from db-ip.com, the only non-Sophos host the toolkit ever calls, and only when you press this." }),
        h(
          "button",
          {
            class: "btn btn-ghost",
            type: "button",
            onclick: async (e) => {
              e.currentTarget.disabled = true;
              ctx.toast("Downloading DB-IP City Lite…");
              try {
                const res = await api.post("/api/geoip/download", { start: true });
                ctx.toast(`Installed ${res.file}`);
              } catch (err) {
                ctx.toast(err.message, "bad");
              }
              await ctx.refreshStatus();
              ctx.reload();
            },
          },
          icon("pin", 15),
          d.geoip.installed ? "Update DB-IP" : "Download DB-IP",
        ),
      ),
    );
    grid.append(
      card(
        "What the toolkit does and does not do",
        "shield",
        h(
          "ul",
          { class: "facts" },
          h("li", {}, "Changes no setting, policy, case or device. A guard in front of every Sophos call refuses anything but GETs, Data Lake SELECT runs, named GraphQL queries, and the two exact Search GraphQL requests that start a search job."),
          h("li", {}, `Stays inside the rate limit: at most ${d.budget?.perMinute ?? 80} calls a minute and ${d.budget?.perHour ?? 900} an hour per credential, screens on show first.`),
          h("li", {}, "Calls nothing but Sophos API hosts, plus db-ip.com if you download it. No telemetry, no update check."),
          h("li", {}, "Listens on 127.0.0.1 only, unless HOST and ALLOWED_IPS say otherwise."),
          h("li", {}, `Targets now: ${SEVS.slice(0, 4).map((k) => `${SEV_LABEL[k]} ${hours(d.settings.targets[k])}`).join(", ")}.`),
        ),
      ),
    );
    wrap.append(grid);
    root.append(wrap);
  },
};
