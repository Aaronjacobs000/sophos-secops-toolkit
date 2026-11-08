/**
 * The local API the pages call. Reads come from the cache through the view
 * builders. The only writes are local ones (credentials, settings, the cache
 * wipe), they take JSON only and, through localHostOnly, only from the
 * toolkit's own pages. Nothing here writes to Sophos.
 */

import { Router, type NextFunction, type Request, type Response } from "express";
import { jsonBody, jsonOnly } from "../middleware/json-body.js";
import { addCredential, listCredentials, removeCredential, renameCredential } from "../store/credentials.js";
import { getSettings, saveSettings, VIEWS, type Settings } from "../store/settings.js";
import { activateCredential, CredentialUnreadableError, deactivate, events, getCache, getProvider, isForcedDemo, setDemo, wipeCache } from "../state.js";
import { buildAi, buildCases, buildEndpoints, buildFront, buildMsp, buildNow, buildSignins, buildSources, scopeFor, screensFor, tenantList } from "../services/views.js";
import { createSophosCore } from "../vendor/sophos-core/index.js";
import { callPriority, createGuardedFetch } from "../sophos/guard.js";
import { PRIORITY, RateLimiter } from "../sophos/rate-limiter.js";
import { ContextError, detectContext } from "../sophos/context.js";
import { getRingBuffer, log, maskSecrets, registerSecret } from "../log.js";
import { downloadDbIp, geoIpStatus } from "../services/geoip.js";
import type { Engine } from "../services/engine.js";
import { reportsRouter } from "./reports.js";

export const apiRouter = Router();

/**
 * Express 4 does not catch a rejected async handler, and Node exits on an
 * unhandled rejection: one bad request would stop the server. This hands the
 * error to the error handler instead.
 */
function safe(handler: (req: Request, res: Response) => Promise<unknown>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    handler(req, res).catch(next);
  };
}

/**
 * Another website can't read these answers, but a GET it fires (an image tag)
 * would still make the toolkit focus a tenant and spend Sophos calls on it.
 * A request the browser marks as coming from another site is refused; the
 * toolkit's own pages and an address typed into the browser still work.
 */
apiRouter.use((req, res, next) => {
  const site = req.headers["sec-fetch-site"];
  if (site === "cross-site" || site === "same-site") {
    res.status(403).json({ error: "forbidden_site", message: "The API answers only the toolkit's own pages." });
    return;
  }
  next();
});

apiRouter.use("/reports", reportsRouter);

const VERSION = "0.1.0";

function providerOr503(res: Response) {
  const p = getProvider();
  if (!p) {
    res.status(503).json({ error: "not_configured", message: "Add a Sophos API credential, or turn on demo mode." });
    return null;
  }
  if (p.status !== "ready") {
    res.status(503).json({ error: p.status, message: p.statusMessage || "Starting up." });
    return null;
  }
  return p;
}

apiRouter.get("/status", safe(async (_req, res) => {
  const p = getProvider();
  const settings = getSettings();
  const creds = await listCredentials();
  let counts: { latest: number; snapshots: number } | null = null;
  try {
    counts = getCache().counts();
  } catch {
    counts = null;
  }
  res.json({
    version: VERSION,
    configured: !!p,
    demo: p?.kind === "demo",
    forcedDemo: isForcedDemo(),
    status: p?.status ?? "unconfigured",
    statusMessage: p?.statusMessage ?? "",
    label: p?.label ?? null,
    context: p?.context ? { kind: p.context.kind, label: p.context.label, multiTenant: p.context.multiTenant, views: screensFor(p) } : null,
    tenantCount: p?.tenants.length ?? 0,
    tenantsOverCap: p?.tenantsOverCap ?? 0,
    progress: p?.progress() ?? null,
    budget: p?.budget() ?? null,
    activeCredentialId: settings.activeCredentialId,
    credentials: creds,
    settings: { targets: settings.targets, wall: settings.wall, privacy: settings.privacy, demoContext: settings.demoContext },
    cache: { retentionDays: getCache().retention, rows: counts },
    geoip: geoIpStatus(),
  });
}));

apiRouter.get("/credentials", safe(async (_req, res) => {
  res.json({ credentials: await listCredentials(), activeCredentialId: getSettings().activeCredentialId });
}));

/**
 * Adds a credential after proving it: an OAuth token and GET /whoami/v1, both
 * reads. The whoami answer decides the context (tenant, partner or
 * organization) and so which screens appear.
 */
apiRouter.post("/credentials", jsonBody, safe(async (req, res) => {
  const { label, clientId, clientSecret } = req.body as { label?: unknown; clientId?: unknown; clientSecret?: unknown };
  if (typeof clientId !== "string" || typeof clientSecret !== "string" || clientId.trim().length < 8 || clientSecret.trim().length < 8) {
    res.status(400).json({ error: "bad_request", message: "Paste the client ID and the client secret from Sophos Fusion (Global Settings, API Credentials Management)." });
    return;
  }
  // Masked from the first call on, so an error that echoes either never reaches the log or the response.
  registerSecret(clientId.trim());
  registerSecret(clientSecret.trim());
  const limiter = new RateLimiter({ perMinute: 10 });
  const core = createSophosCore({ clientId: clientId.trim(), clientSecret: clientSecret.trim(), fetch: createGuardedFetch({ limiter }) });
  let kind;
  try {
    const identity = await callPriority.run(PRIORITY.interactive, () => core.tenants.init());
    kind = detectContext(identity).kind;
  } catch (err) {
    const message = maskSecrets(err instanceof Error ? err.message : String(err));
    const auth = /auth failed|401|invalid_client|unauthor/i.test(message);
    res.status(auth ? 401 : 502).json({
      error: auth ? "auth_failed" : err instanceof ContextError ? "unsupported" : "sophos_error",
      message: auth ? "Sophos refused this client ID and secret. Check both, and that the credential has not been deleted." : message,
    });
    return;
  }
  const saved = await addCredential({ label: typeof label === "string" ? label : "", kind, clientId, clientSecret });
  log.emit("info", "credentials", `Added ${saved.label} (${kind})`);
  await activateCredential(saved.id);
  res.status(201).json({ credential: saved });
}));

apiRouter.post("/credentials/:id/activate", jsonOnly, safe(async (req, res) => {
  const id = String(req.params.id);
  // An unknown ID changes nothing: the active credential keeps running.
  if (!(await listCredentials()).some((c) => c.id === id)) {
    res.status(404).json({ error: "not_found", message: "No such credential." });
    return;
  }
  try {
    await activateCredential(id);
  } catch (err) {
    if (!(err instanceof CredentialUnreadableError)) throw err;
    res.status(409).json({ error: "unreadable", message: err.message });
    return;
  }
  res.json({ ok: true });
}));

apiRouter.patch("/credentials/:id", jsonBody, safe(async (req, res) => {
  const ok = await renameCredential(String(req.params.id), String((req.body as { label?: unknown }).label ?? ""));
  res.status(ok ? 200 : 404).json({ ok });
}));

apiRouter.delete("/credentials/:id", safe(async (req, res) => {
  const id = String(req.params.id);
  const ok = await removeCredential(id);
  if (ok && getSettings().activeCredentialId === id) {
    await saveSettings({ activeCredentialId: null });
    const rest = await listCredentials();
    if (rest[0]) await activateCredential(rest[0].id).catch(async (err) => {
      if (!(err instanceof CredentialUnreadableError)) throw err;
      await deactivate();
    });
    else await deactivate();
  }
  res.status(ok ? 200 : 404).json({ ok });
}));

apiRouter.put("/settings", jsonBody, safe(async (req, res) => {
  const body = req.body as Partial<Settings>;
  const patch: Partial<Settings> = {};
  if (body.targets) patch.targets = body.targets;
  if (body.wall) {
    const playlist = Array.isArray(body.wall.playlist) ? body.wall.playlist : getSettings().wall.playlist;
    patch.wall = { ...getSettings().wall, ...body.wall, playlist: playlist.filter((v) => (VIEWS as readonly string[]).includes(v)) };
  }
  if (typeof body.privacy === "boolean") patch.privacy = body.privacy;
  const saved = await saveSettings(patch);
  events.emit("update", { dataset: "settings" });
  res.json({ settings: saved });
}));

apiRouter.post("/demo", jsonBody, safe(async (req, res) => {
  const { on, context } = req.body as { on?: unknown; context?: unknown };
  await setDemo(on === true, context === "tenant" ? "tenant" : "partner");
  res.json({ ok: true });
}));

apiRouter.post("/cache/wipe", jsonBody, safe(async (req, res) => {
  if ((req.body as { confirm?: unknown }).confirm !== "wipe") {
    res.status(400).json({ error: "bad_request", message: "Send {\"confirm\":\"wipe\"}." });
    return;
  }
  await wipeCache();
  log.emit("info", "cache", "Cache wiped and its key replaced");
  res.json({ ok: true, rows: getCache().counts() });
}));

apiRouter.get("/tenants", (_req, res) => {
  const p = providerOr503(res);
  if (!p) return;
  res.json({ tenants: tenantList(p, getSettings()) });
});

function windowParam(req: Request): number {
  const w = Number(req.query.window);
  return [24, 168, 720].includes(w) ? w : 24;
}

apiRouter.get("/view/:name", (req, res) => {
  const p = providerOr503(res);
  if (!p) return;
  const settings = getSettings();
  const scope = scopeFor(p, req.query.tenant);
  switch (req.params.name) {
    case "front":
      res.json(buildFront(p, scope, settings, windowParam(req)));
      return;
    case "now":
      res.json(buildNow(p, scope, settings));
      return;
    case "cases": {
      const m = req.query.managed;
      res.json(buildCases(p, scope, settings, m === "mdr" || m === "self" ? m : "all"));
      return;
    }
    case "endpoints": {
      const platform = typeof req.query.os === "string" && /^[a-z]{2,12}$/i.test(req.query.os) ? req.query.os.toLowerCase() : null;
      res.json(buildEndpoints(p, scope, settings, platform));
      return;
    }
    case "signins":
      res.json(buildSignins(p, scope, settings));
      return;
    case "sources":
      res.json(buildSources(p, scope, settings));
      return;
    case "ai":
      res.json(buildAi(p, scope, settings));
      return;
    case "msp":
      if (!p.context?.multiTenant) {
        res.status(404).json({ error: "single_tenant", message: "The MSP wall needs a partner or organization credential. This one reaches one tenant." });
        return;
      }
      res.json(buildMsp(p, settings));
      return;
    default:
      res.status(404).json({ error: "not_found" });
  }
});

/** Server-sent events: a nudge whenever a dataset lands, plus the budget every 5 seconds. */
apiRouter.get("/stream", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  let pending: Set<string> = new Set();
  let flush: NodeJS.Timeout | null = null;
  const onUpdate = (detail: { dataset?: string }) => {
    pending.add(detail?.dataset ?? "any");
    if (flush) return;
    flush = setTimeout(() => {
      send("update", { datasets: [...pending] });
      pending = new Set();
      flush = null;
    }, 400);
  };
  const onStatus = () => send("status", { at: Date.now() });
  events.on("update", onUpdate);
  events.on("status", onStatus);
  const beat = setInterval(() => send("budget", getProvider()?.budget() ?? null), 5000);
  send("hello", { at: Date.now() });
  req.on("close", () => {
    events.off("update", onUpdate);
    events.off("status", onStatus);
    clearInterval(beat);
    if (flush) clearTimeout(flush);
  });
});

apiRouter.get("/logs", (_req, res) => {
  res.json({ entries: getRingBuffer().slice(-200) });
});

/** Calls per minute over the last hour, so the budget claim can be checked. */
apiRouter.get("/budget/history", (_req, res) => {
  const p = getProvider();
  if (!p || p.kind !== "live") {
    res.json({ minutes: [], peakPerMinute: 0, lastHour: 0 });
    return;
  }
  const engine = p as unknown as Engine;
  const calls = engine.callLog();
  const now = Date.now();
  const minutes = new Map<number, number>();
  for (const c of calls) {
    if (c.at < now - 3_600_000) continue;
    const m = Math.floor(c.at / 60_000) * 60_000;
    minutes.set(m, (minutes.get(m) ?? 0) + 1);
  }
  const statuses: Record<string, number> = {};
  const methods: Record<string, number> = {};
  for (const c of calls) {
    statuses[c.status] = (statuses[c.status] ?? 0) + 1;
    const key = c.method === "GET" ? "GET" : `${c.method} ${c.host === "api.taegis.sophos.com" ? `GraphQL ${c.operation ?? "query"}` : c.path.replace(/[0-9a-f-]{36}/g, ":id")}`;
    methods[key] = (methods[key] ?? 0) + 1;
  }
  res.json({
    minutes: [...minutes.entries()].sort((a, b) => a[0] - b[0]).map(([at, n]) => ({ at, n })),
    peakPerMinute: engine.limiter.peakPerMinute(),
    lastHour: calls.filter((c) => c.at >= now - 3_600_000).length,
    total: calls.length,
    statuses,
    methods,
  });
});

apiRouter.get("/geoip", (_req, res) => {
  res.json(geoIpStatus());
});

apiRouter.post("/geoip/download", jsonBody, safe(async (_req, res) => {
  const p = getProvider();
  const limiter = new RateLimiter({ perMinute: 5 });
  let allowed = false;
  const fetchImpl = p && p.kind === "live" ? (p as unknown as Engine).guardedFetch : createGuardedFetch({ limiter, allowDownloads: () => allowed });
  try {
    allowed = true;
    const file = p && p.kind === "live" ? await (p as unknown as Engine).withDownloads(() => downloadDbIp(fetchImpl)) : await downloadDbIp(fetchImpl);
    res.json({ ok: true, ...geoIpStatus(), downloaded: file });
  } catch (err) {
    res.status(502).json({ error: "download_failed", message: maskSecrets(err instanceof Error ? err.message : String(err)) });
  } finally {
    allowed = false;
  }
}));
