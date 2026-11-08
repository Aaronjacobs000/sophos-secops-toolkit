// The shell: routing, the context chip and tenant picker, live updates over
// server-sent events, screen transitions, and wall mode.

import { h, clear, setText, append } from "./dom.js";
import { api, stream, store, ApiError } from "./api.js";
import { icon } from "./icons.js";
import { transition, reducedMotion, setReducedMotion, revealChildren } from "./anim.js";
import { ago, clock, date, num, weekday } from "./format.js";
import { hideTip } from "./viz.js";
import front from "./views/front.js";
import now from "./views/now.js";
import cases from "./views/cases.js";
import endpoints from "./views/endpoints.js";
import msp from "./views/msp.js";
import signins from "./views/signins.js";
import sources from "./views/sources.js";
import ai from "./views/ai.js";
import reports from "./views/reports.js";
import atlas from "./views/atlas.js";
import setup from "./views/setup.js";

const VIEWS = { front, msp, now, cases, endpoints, signins, sources, ai, reports, atlas, setup };
const ORDER = ["front", "msp", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas", "setup"];
const NEEDS_DATA = new Set(["front", "msp", "now", "cases", "endpoints", "signins", "sources", "ai"]);

const params = new URLSearchParams(location.search);
if (params.get("motion") === "off") setReducedMotion(true);

const state = {
  status: null,
  route: "front",
  query: {},
  tenant: store.get("tenant", "all"),
  current: null,
  data: null,
  wall: params.get("wall") === "1" || params.get("tv") === "1",
  paused: false,
  rotateAt: 0,
  loadSeq: 0,
  lastUpdate: 0,
};

// ------------------------------------------------------------------ helpers

export function toast(message, kind = "info") {
  const box = document.getElementById("toasts");
  const el = h("div", { class: `toast toast-${kind}` }, icon(kind === "bad" ? "warning" : "check", 16), h("span", { text: message }));
  box.append(el);
  if (!reducedMotion()) el.animate([{ opacity: 0, transform: "translateY(10px)" }, { opacity: 1, transform: "none" }], { duration: 300, easing: "ease-out" });
  setTimeout(() => {
    el.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 300 }).finished.then(() => el.remove(), () => el.remove());
  }, 4200);
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, q] = raw.split("?");
  const route = ORDER.includes(path) ? path : "front";
  return { route, query: Object.fromEntries(new URLSearchParams(q ?? "")) };
}

export function navigate(route, query = {}) {
  const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString();
  location.hash = `#/${route}${qs ? `?${qs}` : ""}`;
}

function availableViews() {
  const ctx = state.status?.context;
  const views = ctx?.views ?? [];
  return ORDER.filter((v) => v === "setup" || v === "atlas" || views.includes(v));
}

function multi() {
  return !!state.status?.context?.multiTenant;
}

// ------------------------------------------------------------------ chrome

const NAV_META = {
  front: ["Overview", "flow"],
  msp: ["MSP wall", "grid"],
  now: ["Now", "pulse"],
  cases: ["Cases", "cases"],
  endpoints: ["Endpoints", "endpoint"],
  signins: ["Sign-ins", "identity"],
  sources: ["Sources", "radar"],
  ai: ["AI usage", "spark"],
  reports: ["Reports", "report"],
  atlas: ["Schema Atlas", "layers"],
  setup: ["Setup", "gear"],
};

function renderNav() {
  const nav = document.getElementById("nav");
  clear(nav);
  for (const id of availableViews()) {
    const [label, ic] = NAV_META[id];
    const a = h("a", { href: `#/${id}`, class: `nav-item${state.route === id ? " active" : ""}`, "aria-current": state.route === id ? "page" : null, title: label }, icon(ic, 16), h("span", { text: label }));
    if (state.route === id) a.append(h("i", { class: "nav-pill", "aria-hidden": "true" }));
    nav.append(a);
  }
  fitNav();
}

/** Tighter nav items, then icons only, then no brand name, until the screens fit beside the header controls. */
function fitNav() {
  const nav = document.getElementById("nav");
  const steps = ["nav-snug", "nav-tight", "nav-tighter"];
  document.body.classList.remove(...steps);
  for (const step of steps) {
    if (nav.scrollWidth <= nav.clientWidth) return;
    document.body.classList.add(step);
  }
}

function renderContext() {
  const box = document.getElementById("ctx");
  clear(box);
  const st = state.status;
  if (!st?.configured) {
    box.append(h("span", { class: "ctx-chip ctx-none" }, icon("key", 14), h("span", { text: "No credential" })));
    return;
  }
  const ctx = st.context;
  const kind = ctx ? ctx.label : st.status === "starting" ? "Connecting" : "Not connected";
  const chip = h(
    "button",
    { class: `ctx-chip${st.demo ? " ctx-demo" : ""}`, type: "button", "aria-haspopup": "listbox", title: multi() ? "Choose a tenant" : st.label },
    h("span", { class: "ctx-kind", text: st.demo ? `Demo ${kind}` : kind }),
    h("span", { class: "ctx-name", text: multi() ? tenantLabel() : (st.label ?? "") }),
    multi() ? h("span", { class: "ctx-count", text: num(st.tenantCount) }) : null,
    multi() ? icon("down", 14) : null,
  );
  box.append(chip);
  if (multi()) chip.addEventListener("click", () => openPicker(box));
}

function tenantLabel() {
  if (state.tenant === "all" || !state.tenants) return "All tenants";
  return state.tenants.find((t) => t.id === state.tenant)?.name ?? "All tenants";
}

async function openPicker(anchor) {
  if (anchor.querySelector(".picker")) {
    anchor.querySelector(".picker").remove();
    return;
  }
  if (!state.tenants) {
    try {
      state.tenants = (await api.get("/api/tenants")).tenants;
    } catch {
      state.tenants = [];
    }
  }
  const input = h("input", { type: "search", placeholder: `Search ${num(state.tenants.length)} tenants`, "aria-label": "Search tenants" });
  const list = h("div", { class: "picker-list", role: "listbox" });
  const picker = h("div", { class: "picker" }, h("div", { class: "picker-search" }, icon("search", 15), input), list);
  const fill = () => {
    clear(list);
    const q = input.value.trim().toLowerCase();
    const rows = [{ id: "all", name: `All tenants (${num(state.tenants.length)})`, generation: null }, ...state.tenants.filter((t) => !q || t.name.toLowerCase().includes(q))];
    for (const t of rows.slice(0, 200)) {
      list.append(
        h(
          "button",
          {
            type: "button",
            role: "option",
            class: `picker-row${state.tenant === t.id ? " on" : ""}`,
            "aria-selected": state.tenant === t.id ? "true" : "false",
            onclick: () => {
              setTenant(t.id);
              picker.remove();
            },
          },
          h("span", { text: t.name }),
          t.generation ? h("span", { class: `gen gen-${t.generation}`, text: t.generation === "fusion" ? "Fusion" : t.generation === "classic" ? "Classic" : "?" }) : null,
        ),
      );
    }
  };
  input.addEventListener("input", fill);
  fill();
  anchor.append(picker);
  input.focus();
  const close = (e) => {
    if (!picker.contains(e.target) && !anchor.contains(e.target)) {
      picker.remove();
      document.removeEventListener("pointerdown", close);
    }
  };
  setTimeout(() => document.addEventListener("pointerdown", close), 0);
  picker.addEventListener("keydown", (e) => {
    if (e.key === "Escape") picker.remove();
  });
}

function setTenant(id) {
  state.tenant = id;
  store.set("tenant", id);
  renderContext();
  if (state.route === "msp" && id !== "all") {
    navigate("now", { tenant: id });
    return;
  }
  load(true);
}

function renderBudget() {
  const box = document.getElementById("budget");
  const b = state.status?.budget;
  clear(box);
  if (!b || state.status?.demo) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const pct = Math.min(100, (b.lastMinute / b.perMinute) * 100);
  box.append(
    h("span", { class: "budget-label", text: "API" }),
    h("span", { class: "budget-track" }, h("i", { class: `budget-fill${pct > 85 ? " hot" : ""}`, style: { width: `${pct}%` } })),
    h("span", { class: "budget-num" }, h("b", { text: num(b.lastMinute) }), ` of ${b.perMinute}/min`),
  );
  box.title = `Sophos API calls by this credential: ${b.lastMinute} in the last minute, ${b.lastHour} in the last hour (limits used: ${b.perMinute} a minute, ${b.perHour} an hour).${b.queued ? ` ${b.queued} waiting.` : ""}`;
}

function renderBanner() {
  const el = document.getElementById("banner");
  const st = state.status;
  clear(el);
  let msg = null;
  let kind = "warn";
  if (st?.status === "auth-failed") {
    msg = "Sophos refused the active credential. Check the credential in Setup.";
    kind = "bad";
  } else if (st?.status === "error") msg = `Could not reach Sophos: ${st.statusMessage}. The toolkit keeps trying.`;
  else if (st?.budget?.pausedFor > 0) msg = `Sophos asked the toolkit to slow down (HTTP 429). Refreshes resume in ${Math.ceil(st.budget.pausedFor / 1000)} s; screens show cached data meanwhile.`;
  else if (st?.tenantsOverCap > 0) msg = `This credential reaches ${num(st.tenantCount + st.tenantsOverCap)} tenants. The toolkit reads the first ${num(st.tenantCount)} (the per-install limit).`;
  el.hidden = !msg;
  if (msg) {
    el.className = `banner banner-${kind}`;
    el.append(icon("warning", 16), h("span", { text: msg }));
  }
}

function renderFooter() {
  const el = document.getElementById("foot");
  clear(el);
  const st = state.status;
  append(el, [
    h("span", { class: "foot-strong", text: "Unofficial. Uses the public Sophos APIs." }),
    h("span", { text: " Not a Sophos product." }),
    st?.demo ? h("span", { class: "foot-demo", text: " Demo mode: every tenant, device, person and case shown is fictional." }) : null,
    st?.geoip?.installed ? h("a", { href: "https://db-ip.com", rel: "noreferrer", target: "_blank", text: " IP geolocation by DB-IP." }) : null,
    h("span", { class: "foot-right", text: `SecOps Toolkit ${st?.version ?? ""}` }),
  ]);
}

function renderChrome() {
  renderWallbar();
  renderNav();
  renderContext();
  renderBudget();
  renderBanner();
  renderFooter();
  const wallBtn = document.getElementById("wall-btn");
  clear(wallBtn).append(icon(state.wall ? "close" : "wall", 18));
  wallBtn.title = state.wall ? "Leave wall mode" : "Wall mode: full screen, rotating boards";
  const theme = document.documentElement.dataset.theme;
  clear(document.getElementById("theme-btn")).append(icon(theme === "dark" ? "sun" : "moon", 18));
  clear(document.getElementById("menu-btn")).append(icon("menu", 18));
}

// ------------------------------------------------------------------ loading views

async function refreshStatus() {
  try {
    state.status = await api.get("/api/status");
    if (multi() && !state.tenants && state.status.status === "ready") {
      state.tenants = (await api.get("/api/tenants")).tenants;
    }
  } catch {
    // Keep the last status; the banner covers a server that went away.
  }
  return state.status;
}

function viewQuery(route) {
  const q = { ...state.query };
  if (multi() && route !== "msp") q.tenant = q.tenant ?? state.tenant ?? "all";
  if (route === "front") q.window = q.window ?? store.get("window", "24");
  return q;
}

async function fetchView(route) {
  const view = VIEWS[route];
  if (view.load) return view.load(ctxFor(route));
  if (!NEEDS_DATA.has(route)) return null;
  const q = new URLSearchParams(viewQuery(route)).toString();
  return api.get(`/api/view/${route}${q ? `?${q}` : ""}`);
}

function ctxFor(route) {
  return {
    state,
    route,
    multi: multi(),
    wall: state.wall,
    query: viewQuery(route),
    navigate,
    toast,
    setQuery(patch) {
      state.query = { ...state.query, ...patch };
      navigate(route, { ...state.query });
    },
    reload: () => load(true),
    refreshStatus: async () => {
      await refreshStatus();
      state.tenants = null;
      renderChrome();
    },
  };
}

function emptyState(root, err) {
  const title = err?.status === 503 && err.body?.error === "not_configured" ? "Add a credential to begin" : err?.body?.error === "starting" ? "Connecting to Sophos" : "This screen has nothing to show yet";
  const msg = err?.body?.message ?? err?.message ?? "";
  root.append(
    h(
      "section",
      { class: "empty reveal" },
      h("div", { class: "empty-orb", "aria-hidden": "true" }),
      h("h1", { text: title }),
      h("p", { text: msg }),
      err?.body?.error === "not_configured" ? h("a", { class: "btn btn-primary", href: "#/setup", text: "Open setup" }) : null,
    ),
  );
}

async function load(sameView = false) {
  const seq = ++state.loadSeq;
  const { route, query } = parseHash();
  const allowed = availableViews();
  const target = state.status?.configured || route === "setup" || route === "atlas" ? route : "setup";
  // While a new credential is still connecting, Sophos hasn't said what it can see yet: keep the route.
  const connecting = !!state.status?.configured && !state.status?.context;
  const routeOk = allowed.includes(target) || target === "setup" || target === "atlas" || connecting ? target : allowed[0] ?? "setup";
  if (route !== routeOk && !sameView) {
    navigate(routeOk, query);
    return;
  }
  if (query.tenant && multi()) {
    state.tenant = query.tenant;
    store.set("tenant", query.tenant);
  }
  const changedView = state.route !== routeOk || !state.current;
  const prevIndex = ORDER.indexOf(state.route);
  state.route = routeOk;
  state.query = query;
  let data = null;
  let error = null;
  const root = document.getElementById("view");
  if (!changedView) root.classList.add("refetching");
  try {
    data = await fetchView(routeOk);
  } catch (err) {
    error = err instanceof ApiError ? err : new ApiError(0, { message: String(err?.message ?? err) });
  }
  root.classList.remove("refetching");
  // A screen still sliding in must finish before this load decides whether to
  // update it in place or mount again; otherwise both would mount it.
  while (state.transitioning) await state.transitioning;
  if (seq !== state.loadSeq) return;
  const view = VIEWS[routeOk];
  if (!changedView && state.current === view && !error && view.update && root.dataset.mounted === routeOk) {
    state.data = data;
    view.update(data, ctxFor(routeOk));
    renderChrome();
    return;
  }
  const dir = ORDER.indexOf(routeOk) >= prevIndex ? "forward" : "back";
  let done;
  state.transitioning = new Promise((r) => (done = r));
  await transition(() => {
    hideTip();
    state.current?.unmount?.();
    clear(root);
    root.dataset.view = routeOk;
    document.body.dataset.view = routeOk;
    state.current = view;
    state.data = data;
    if (error) {
      emptyState(root, error);
      root.dataset.mounted = "";
    } else {
      view.mount(root, data, ctxFor(routeOk));
      root.dataset.mounted = routeOk;
    }
    renderChrome();
    // The new screen's panels cascade in live while the old screen's snapshot leaves.
    revealChildren(root);
  }, dir);
  state.transitioning = null;
  done();
  if (!state.wall) root.focus({ preventScroll: true });
  document.title = `${NAV_META[routeOk][0]} · SecOps Toolkit`;
}

// ------------------------------------------------------------------ live updates

// Updates arrive in bursts while a partner estate loads. Redraw at most every
// few seconds so animations finish and a wall never flickers.
let pending = null;
let lastRefresh = 0;
const MIN_REFRESH_MS = 4000;
function scheduleRefresh(delay = 600) {
  if (pending) return;
  const wait = Math.max(delay, lastRefresh + MIN_REFRESH_MS - Date.now());
  pending = setTimeout(async () => {
    pending = null;
    if (document.hidden) return;
    lastRefresh = Date.now();
    await refreshStatus();
    if (NEEDS_DATA.has(state.route)) await load(true);
    else renderChrome();
  }, wait);
}

stream({
  update: () => scheduleRefresh(),
  status: async () => {
    await refreshStatus();
    state.tenants = null;
    renderChrome();
    scheduleRefresh(200);
  },
  budget: (b) => {
    if (state.status && b) {
      state.status.budget = b;
      renderBudget();
      renderBanner();
    }
  },
  lost: () => document.body.classList.add("offline"),
  open: () => document.body.classList.remove("offline"),
});

// Freshness chips tick every 20 s even when nothing new arrives.
setInterval(() => {
  for (const el of document.querySelectorAll("[data-ago]")) setText(el, ago(Number(el.dataset.ago)));
}, 20_000);

// ------------------------------------------------------------------ wall mode

let wakeLock = null;
let cursorTimer = null;

function wallPlaylist() {
  const views = availableViews().filter((v) => v !== "setup" && v !== "atlas" && v !== "reports");
  const list = (state.status?.settings?.wall?.playlist ?? views).filter((v) => views.includes(v));
  return list.length ? list : views;
}

function renderWallbar() {
  const bar = document.getElementById("wallbar");
  bar.hidden = !state.wall;
  if (!state.wall) return;
  clear(bar);
  const list = wallPlaylist();
  const i = list.indexOf(state.route);
  const next = list[(i + 1) % list.length] ?? list[0];
  const seconds = state.status?.settings?.wall?.seconds ?? 120;
  bar.append(
    h("div", { class: "wall-title" }, h("b", { text: NAV_META[state.route]?.[0] ?? "" }), h("span", { text: state.status?.label ?? "" })),
    h(
      "div",
      { class: "wall-next" },
      h("span", { text: "Next " }),
      h("b", { text: NAV_META[next]?.[0] ?? "" }),
      h("span", { class: "wall-track" }, h("i", { class: "wall-progress", id: "wall-progress" })),
      h("span", { class: "wall-count mono", id: "wall-count", text: "" }),
      h(
        "button",
        {
          class: "btn btn-ghost btn-sm",
          type: "button",
          onclick: () => {
            state.paused = !state.paused;
            if (!state.paused) state.rotateAt = Date.now() + seconds * 1000;
            renderWallbar();
          },
        },
        icon(state.paused ? "play" : "pause", 14),
        state.paused ? "Resume" : "Pause",
      ),
    ),
    h("div", { class: "wall-clock" }, h("b", { class: "mono", id: "wall-time", text: clock(Date.now(), true) }), h("span", { id: "wall-date", text: `${weekday()} ${date(Date.now())}` })),
  );
}

async function setWall(on) {
  state.wall = on;
  document.body.classList.toggle("wall", on);
  const url = new URL(location.href);
  if (on) url.searchParams.set("wall", "1");
  else {
    url.searchParams.delete("wall");
    url.searchParams.delete("tv");
  }
  history.replaceState(null, "", url);
  if (on) {
    state.paused = false;
    state.rotateAt = Date.now() + (state.status?.settings?.wall?.seconds ?? 120) * 1000;
    try {
      if (!document.fullscreenElement && document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
    } catch {
      // Full screen needs a click; a signage browser in kiosk mode is already full screen.
    }
    try {
      wakeLock = await navigator.wakeLock?.request("screen");
    } catch {
      wakeLock = null;
    }
    if (!wallPlaylist().includes(state.route)) navigate(wallPlaylist()[0] ?? "front");
  } else {
    wakeLock?.release?.();
    wakeLock = null;
    if (document.fullscreenElement) document.exitFullscreen?.().catch(() => undefined);
  }
  renderWallbar();
  renderChrome();
  scheduleRefresh(50);
}

setInterval(() => {
  if (!state.wall) return;
  const t = document.getElementById("wall-time");
  if (t) setText(t, clock(Date.now(), true));
  const seconds = state.status?.settings?.wall?.seconds ?? 120;
  const p = document.getElementById("wall-progress");
  const left = Math.max(0, state.rotateAt - Date.now());
  if (p) p.style.transform = `scaleX(${state.paused ? 0 : 1 - left / (seconds * 1000)})`;
  const c = document.getElementById("wall-count");
  if (c) setText(c, state.paused ? "paused" : `${Math.ceil(left / 1000)} s`);
  if (!state.paused && left <= 0) {
    const list = wallPlaylist();
    const next = list[(list.indexOf(state.route) + 1) % list.length] ?? list[0];
    state.rotateAt = Date.now() + seconds * 1000;
    navigate(next, multi() && next !== "msp" ? { tenant: state.tenant } : {});
  }
}, 250);

document.addEventListener("pointermove", () => {
  document.body.classList.remove("cursor-hidden");
  clearTimeout(cursorTimer);
  if (state.wall) cursorTimer = setTimeout(() => document.body.classList.add("cursor-hidden"), 3000);
});

document.addEventListener("visibilitychange", async () => {
  if (!document.hidden && state.wall && !wakeLock) {
    try {
      wakeLock = await navigator.wakeLock?.request("screen");
    } catch {
      wakeLock = null;
    }
  }
  if (!document.hidden) scheduleRefresh(100);
});

// ------------------------------------------------------------------ boot

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  store.set("theme", theme);
}

document.getElementById("theme-btn").addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  renderChrome();
  if (state.current?.onTheme) state.current.onTheme();
});
document.getElementById("wall-btn").addEventListener("click", () => setWall(!state.wall));
document.getElementById("menu-btn").addEventListener("click", (e) => {
  const open = document.body.classList.toggle("menu-open");
  e.currentTarget.setAttribute("aria-expanded", String(open));
});
document.getElementById("nav").addEventListener("click", () => document.body.classList.remove("menu-open"));
document.addEventListener("keydown", (e) => {
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
  if (e.key === "w" && !e.metaKey && !e.ctrlKey) setWall(!state.wall);
  if (e.key === "Escape" && state.wall) setWall(false);
  if (state.wall && (e.key === "ArrowRight" || e.key === "ArrowLeft")) {
    const list = wallPlaylist();
    const i = list.indexOf(state.route);
    const next = list[(i + (e.key === "ArrowRight" ? 1 : list.length - 1)) % list.length];
    state.rotateAt = Date.now() + (state.status?.settings?.wall?.seconds ?? 120) * 1000;
    navigate(next);
  }
});
window.addEventListener("hashchange", () => load());
document.fonts?.ready.then(fitNav);
window.addEventListener("resize", () => {
  fitNav();
  state.current?.onResize?.();
});

applyTheme(params.get("theme") === "light" ? "light" : params.get("theme") === "dark" ? "dark" : store.get("theme", "dark"));
document.body.classList.toggle("wall", state.wall);

(async () => {
  await refreshStatus();
  renderChrome();
  if (state.wall) renderWallbar();
  if (state.wall) state.rotateAt = Date.now() + (state.status?.settings?.wall?.seconds ?? 120) * 1000;
  if (!location.hash) navigate(state.status?.configured ? "front" : "setup");
  else load();
})();
