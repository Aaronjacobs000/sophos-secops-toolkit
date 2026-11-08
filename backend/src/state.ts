/**
 * Process-wide state: the encrypted cache, the settings, and the one provider
 * the screens read from (the live engine for the active credential, or demo).
 */

import { EventEmitter } from "node:events";
import { EncryptedCache } from "./store/cache.js";
import { getSettings, loadSettings, saveSettings } from "./store/settings.js";
import { listCredentials, readSecret } from "./store/credentials.js";
import { Engine } from "./services/engine.js";
import { DemoProvider } from "./demo/demo-provider.js";
import type { Provider } from "./services/provider.js";
import { log } from "./log.js";

/** A stored credential the key in SECOPS_KEY_DIR can't decrypt. */
export class CredentialUnreadableError extends Error {}

export const events = new EventEmitter();
events.setMaxListeners(200);

let cache: EncryptedCache | null = null;
let provider: Provider | null = null;
let forceDemo = false;
let pruneTimer: NodeJS.Timeout | null = null;

export function getCache(): EncryptedCache {
  if (!cache) throw new Error("State not initialised.");
  return cache;
}

export function getProvider(): Provider | null {
  return provider;
}

export function isForcedDemo(): boolean {
  return forceDemo;
}

function wire(p: Provider): void {
  p.on("update", (detail) => events.emit("update", detail));
  p.on("status", () => events.emit("status"));
}

async function swap(next: Provider | null): Promise<void> {
  provider?.stop();
  provider = next;
  if (next) wire(next);
  events.emit("status");
}

export async function initState(options: { demo?: boolean } = {}): Promise<void> {
  forceDemo = options.demo === true || process.env.SECOPS_DEMO === "1";
  cache = new EncryptedCache();
  await cache.open();
  cache.prune();
  pruneTimer = setInterval(() => {
    try {
      cache?.prune();
    } catch {
      // The cache may be mid-wipe.
    }
  }, 6 * 3_600_000);
  pruneTimer.unref?.();
  const settings = await loadSettings();
  if (forceDemo || settings.demo) {
    await swap(new DemoProvider(settings.demoContext));
    return;
  }
  try {
    if (settings.activeCredentialId) await activateCredential(settings.activeCredentialId);
    else {
      const creds = await listCredentials();
      if (creds[0]) await activateCredential(creds[0].id);
    }
  } catch (err) {
    // Start anyway, so Setup can show the credentials and the person can delete the one that can't be read.
    if (!(err instanceof CredentialUnreadableError)) throw err;
    await swap(null);
  }
}

export async function activateCredential(id: string): Promise<Engine | null> {
  let found: Awaited<ReturnType<typeof readSecret>>;
  try {
    found = await readSecret(id);
  } catch (err) {
    const message =
      "This credential can't be decrypted with the key in the key folder (SECOPS_KEY_DIR, by default ~/.secops-toolkit). " +
      "The key may have been replaced, or the data folder copied from another computer. Delete the credential in Setup and add it again.";
    log.emit("error", "credentials", `${message} (${err instanceof Error ? err.message : String(err)})`);
    throw new CredentialUnreadableError(message);
  }
  if (!found) {
    await saveSettings({ activeCredentialId: null });
    await swap(null);
    return null;
  }
  const engine = new Engine({
    credentialId: found.summary.id,
    label: found.summary.label,
    clientId: found.secret.clientId,
    clientSecret: found.secret.clientSecret,
    cache: getCache(),
  });
  await saveSettings({ activeCredentialId: id, demo: false });
  await swap(engine);
  void engine.start().then(() => log.emit("info", "engine", `Active: ${found.summary.label} (${engine.context?.kind ?? engine.status})`));
  return engine;
}

export async function setDemo(on: boolean, context: "partner" | "tenant" = getSettings().demoContext): Promise<void> {
  await saveSettings({ demo: on, demoContext: context });
  if (on) {
    await swap(new DemoProvider(context));
    return;
  }
  if (forceDemo) {
    await swap(new DemoProvider(context));
    return;
  }
  const active = getSettings().activeCredentialId;
  if (active) await activateCredential(active);
  else await swap(null);
}

export async function deactivate(): Promise<void> {
  await swap(null);
}

export async function wipeCache(): Promise<void> {
  const c = getCache();
  await c.wipe();
  // The live engine reads the cache through its memo; restart it so nothing stale lingers.
  const active = getSettings().activeCredentialId;
  if (provider?.kind === "live" && active) await activateCredential(active);
  events.emit("status");
}

export function shutdown(): void {
  provider?.stop();
  if (pruneTimer) clearInterval(pruneTimer);
  cache?.close();
}
