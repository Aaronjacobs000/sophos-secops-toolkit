/**
 * SecOps Toolkit. Unofficial. Uses the public Sophos APIs.
 *
 * A local web server: listens on 127.0.0.1 by default, serves the pages from
 * frontend/ and a JSON API under /api that reads the encrypted cache.
 */

import path from "node:path";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";

import { log } from "./log.js";
import { setRepoRoot } from "./store/paths.js";
import { initState, shutdown } from "./state.js";
import { errorHandler } from "./middleware/error-handler.js";
import { localHostOnly } from "./middleware/local-host.js";
import { allowedClientsOnly } from "./middleware/client-ip.js";
import { noStore, securityHeaders } from "./middleware/security-headers.js";
import { addressUrl, listenErrorMessage, networkSettings, type NetworkSettings } from "./config/network.js";
import { apiRouter } from "./routes/api.js";
import { loadGeoIp } from "./services/geoip.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");

const envFile = path.join(REPO_ROOT, ".env");
if (existsSync(envFile)) process.loadEnvFile(envFile);

function readNetworkSettings(): NetworkSettings {
  try {
    return networkSettings();
  } catch (err) {
    log.error(`Not starting: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

export function createApp(network: NetworkSettings): express.Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(allowedClientsOnly(network.allowList));
  app.use(localHostOnly);
  app.use(securityHeaders);
  app.use(express.json({ limit: "256kb" }));
  app.use("/api", noStore, apiRouter);
  const FRONTEND_DIR = path.join(REPO_ROOT, "frontend");
  app.use(express.static(FRONTEND_DIR, { index: "index.html", maxAge: 0 }));
  app.use((req, res, next) => {
    if (req.method !== "GET" || req.path.startsWith("/api/")) return next();
    res.sendFile(path.join(FRONTEND_DIR, "index.html"));
  });
  app.use(errorHandler);
  return app;
}

async function main() {
  setRepoRoot(REPO_ROOT);
  const network = readNetworkSettings();
  await initState({ demo: process.argv.includes("--demo") });
  void loadGeoIp();
  const PORT = Number(process.env.PORT) || 3200;
  const HOST = network.host;
  const app = createApp(network);
  const stop = (err: unknown): never => {
    log.error(`Not starting: ${listenErrorMessage(err, HOST, PORT)}`);
    process.exit(1);
  };
  const server = app.listen(PORT, HOST, () => {
    log.info(`SecOps Toolkit on ${addressUrl(HOST, PORT)}. Unofficial. Uses the public Sophos APIs.`);
    if (network.beyondLoopback && !network.allowList) {
      log.warn(`WARNING: listening beyond this computer with no ALLOWED_IPS. Anyone who can reach port ${PORT} can see the cached tenant data. Set ALLOWED_IPS.`);
    }
  });
  server.on("error", stop);
  const close = () => {
    shutdown();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on("SIGINT", close);
  process.on("SIGTERM", close);
}

/** True when node was asked to run this file, through a symlink or not (a service manager often uses one). */
function isEntryPoint(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  main().catch((err) => {
    log.error("fatal startup error", err);
    process.exit(1);
  });
}
