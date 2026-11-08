// A vault entry the key folder can't decrypt (the key replaced, or data/
// copied from another computer) must not stop the server from starting.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = mkdtempSync(path.join(tmpdir(), "secops-recover-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");
delete process.env.SECOPS_DEMO;

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const { addCredential, listCredentials } = await import("../backend/dist/store/credentials.js");
const { saveSettings, loadSettings } = await import("../backend/dist/store/settings.js");
const { initState, activateCredential, getProvider, shutdown, CredentialUnreadableError } = await import("../backend/dist/state.js");

test("the server starts with an unreadable credential, and activating it says why", async () => {
  await loadSettings();
  const saved = await addCredential({ label: "Old laptop", kind: "tenant", clientId: "client-id-12345678", clientSecret: "client-secret-12345678" });
  await saveSettings({ activeCredentialId: saved.id, demo: false });
  rmSync(path.join(root, "keys"), { recursive: true, force: true }); // the key folder is gone
  await initState();
  assert.equal(getProvider(), null, "started, with nothing active");
  assert.equal((await listCredentials()).length, 1, "the credential is still listed, so Setup can delete it");
  await assert.rejects(activateCredential(saved.id), (err) => err instanceof CredentialUnreadableError && /Delete the credential in Setup/.test(err.message));
  shutdown();
});
