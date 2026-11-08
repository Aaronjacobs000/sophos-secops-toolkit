// The DB-IP GeoIP download carries no credential, but the guard's path check
// sees only the address a request starts at, so a followed redirect would
// fetch the file from an address the guard never approved. A redirect on the
// download is refused, never followed. These tests run Node's real fetch,
// through the guard, against two local servers: a stand-in download host that
// answers with a redirect, and the host it points at, which must never see a
// request.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createGuardedFetch, ReadOnlyViolationError } from "../backend/dist/sophos/guard.js";
import { RateLimiter } from "../backend/dist/sophos/rate-limiter.js";
import { downloadDbIp, dbipFileNames } from "../backend/dist/services/geoip.js";

/** Requests the redirect target received. Must stay empty. */
const elsewhere = [];
/** Paths the stand-in download host received. */
const seen = [];
/** What the stand-in download host answers. */
let status = 200;

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let sink;
let dbip;
let dataDir;
const savedDataDir = process.env.SECOPS_DATA_DIR;

/** Sends https://download.db-ip.com/<path> to the stand-in download host, with the caller's options untouched. */
const toStandIn = (input, init) => {
  const url = new URL(String(input));
  return fetch(`http://127.0.0.1:${dbip.address().port}${url.pathname}`, init);
};

const guarded = () => createGuardedFetch({ limiter: new RateLimiter(), baseFetch: toStandIn, allowDownloads: () => true });

before(async () => {
  dataDir = mkdtempSync(path.join(tmpdir(), "secops-geoip-"));
  process.env.SECOPS_DATA_DIR = dataDir;
  sink = await listen((req, res) => {
    elsewhere.push(`${req.method} ${req.url}`);
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end("not-the-db-ip-file");
  });
  dbip = await listen((req, res) => {
    seen.push(req.url);
    if (status >= 300 && status < 400) {
      res.writeHead(status, { Location: `http://127.0.0.1:${sink.address().port}${req.url}` });
      res.end();
      return;
    }
    res.writeHead(status, { "Content-Type": "application/octet-stream" });
    res.end("db-ip-bytes");
  });
});

after(() => {
  if (savedDataDir === undefined) delete process.env.SECOPS_DATA_DIR;
  else process.env.SECOPS_DATA_DIR = savedDataDir;
  rmSync(dataDir, { recursive: true, force: true });
  sink.close();
  dbip.close();
});

function reset(next) {
  status = next;
  seen.length = 0;
  elsewhere.length = 0;
}

test("a plain answer from the download host still comes through the guard (control)", async () => {
  reset(200);
  const [name] = dbipFileNames();
  const response = await guarded()(`https://download.db-ip.com/free/${name}`, { method: "GET" });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "db-ip-bytes");
  assert.deepEqual(seen, [`/free/${name}`]);
});

for (const code of [301, 302, 307, 308]) {
  test(`a ${code} on the DB-IP download is refused, not followed, and nothing is saved`, async () => {
    reset(code);
    await assert.rejects(
      () => downloadDbIp(guarded()),
      (error) =>
        error instanceof ReadOnlyViolationError &&
        error.message.includes(`with a ${code} redirect to 127.0.0.1:${sink.address().port}`) &&
        /never followed/.test(error.message)
    );
    assert.deepEqual(seen, [`/free/${dbipFileNames()[0]}`], "one request, no fallback to last month");
    assert.deepEqual(elsewhere, [], "nothing was fetched from the redirect target");
    let saved = [];
    try {
      saved = readdirSync(path.join(dataDir, "geoip"));
    } catch {
      // no geoip directory: nothing saved
    }
    assert.deepEqual(saved, []);
  });
}
