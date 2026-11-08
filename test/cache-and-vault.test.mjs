import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = mkdtempSync(path.join(tmpdir(), "secops-test-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { EncryptedCache } = await import("../backend/dist/store/cache.js");
const { addCredential, listCredentials, readSecret, removeCredential } = await import("../backend/dist/store/credentials.js");
const { keyFile, seal, open, UnreadableError } = await import("../backend/dist/store/crypto.js");
const { setQuiet, maskSecrets } = await import("../backend/dist/log.js");
setQuiet(true);

const SECRET_TEXT = "Harbourline-confidential-case-title-7731";

test("cached values round-trip and are encrypted on disk", async () => {
  const cache = new EncryptedCache(path.join(root, "data", "cache-a.db"));
  await cache.open();
  cache.put("cases:tenant-1", { title: SECRET_TEXT, n: 3 });
  const fresh = new EncryptedCache(path.join(root, "data", "cache-a.db"));
  await fresh.open();
  assert.deepEqual(fresh.get("cases:tenant-1").value, { title: SECRET_TEXT, n: 3 });
  cache.close();
  fresh.close();
  const bytes = readFileSync(path.join(root, "data", "cache-a.db"));
  assert.equal(bytes.includes(Buffer.from(SECRET_TEXT)), false, "the plaintext is not in the file");
  assert.equal(bytes.includes(Buffer.from("tenant-1")), false, "nor is the tenant ID in the row key");
  // Windows has no POSIX modes; the key folder is private through the user profile's permissions there.
  if (process.platform !== "win32") assert.equal(statSync(keyFile("cache")).mode & 0o777, 0o600, "the key file is private");
});

test("the key lives outside the data folder", () => {
  assert.ok(existsSync(keyFile("cache")));
  assert.ok(!keyFile("cache").startsWith(process.env.SECOPS_DATA_DIR));
});

test("wipe deletes every row and replaces the key", async () => {
  const file = path.join(root, "data", "cache-b.db");
  const cache = new EncryptedCache(file);
  await cache.open();
  cache.put("endpoints:t", [{ hostname: SECRET_TEXT }]);
  cache.snapshot("snap-endpoints:t", { total: 4 });
  assert.deepEqual(cache.counts(), { latest: 1, snapshots: 1 });
  const keyBefore = readFileSync(keyFile("cache"), "utf8");
  await cache.wipe();
  assert.deepEqual(cache.counts(), { latest: 0, snapshots: 0 });
  assert.equal(cache.get("endpoints:t"), null);
  assert.notEqual(readFileSync(keyFile("cache"), "utf8"), keyBefore, "a new key, so old copies can't be read");
  cache.put("after:wipe", 1);
  assert.equal(cache.get("after:wipe").value, 1, "the cache keeps working after a wipe");
  cache.close();
});

test("rows older than the retention period are pruned", async () => {
  const cache = new EncryptedCache(path.join(root, "data", "cache-c.db"), 30);
  await cache.open();
  const now = Date.now();
  cache.put("old", 1, now - 31 * 86_400_000);
  cache.put("new", 2, now - 86_400_000);
  cache.snapshot("s", 1, now - 40 * 86_400_000);
  cache.snapshot("s", 2, now - 1000);
  assert.equal(cache.prune(now), 2);
  assert.equal(cache.get("old"), null);
  assert.equal(cache.get("new").value, 2);
  assert.deepEqual(cache.snapshots("s").map((x) => x.value), [2]);
  cache.close();
});

test("the credential vault never stores a secret in the clear", async () => {
  const saved = await addCredential({ label: "Acme", kind: "tenant", clientId: "client-id-abcdef123456", clientSecret: "client-secret-zyxwvu987654" });
  const raw = readFileSync(path.join(process.env.SECOPS_DATA_DIR, "credentials.json"), "utf8");
  assert.equal(raw.includes("client-secret-zyxwvu987654"), false);
  assert.equal(raw.includes("client-id-abcdef123456"), false);
  assert.equal(saved.hint, "3456");
  const listed = await listCredentials();
  assert.equal(JSON.stringify(listed).includes("zyxwvu"), false, "the list never carries the secret");
  const back = await readSecret(saved.id);
  assert.equal(back.secret.clientSecret, "client-secret-zyxwvu987654");
  assert.equal(maskSecrets("oops client-secret-zyxwvu987654 leaked").includes("zyxwvu"), false, "a read secret is masked in logs from then on");
  assert.equal(await removeCredential(saved.id), true);
  assert.equal(await readSecret(saved.id), null);
});

test("a sealed box with its tag cut short is refused", async () => {
  const { randomBytes } = await import("node:crypto");
  const key = randomBytes(32);
  const box = seal(key, "secret value", "aad");
  assert.equal(open(key, box, "aad").toString("utf8"), "secret value");
  const short = { ...box, tag: Buffer.from(box.tag, "base64").subarray(0, 4).toString("base64") };
  assert.throws(() => open(key, short, "aad"), UnreadableError);
});
