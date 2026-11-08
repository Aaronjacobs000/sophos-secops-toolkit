// A redirect from Sophos is refused, never followed. The read-only guard
// checks only the address a request starts at, so a followed 307 or 308 on
// the token request would send the client secret to an address it never
// checked, and on an API call the tenant ID would go with it. These tests run
// Node's real fetch, through the guard, against two local servers: a stand-in
// Sophos that answers with a redirect, and the host it points at, which must
// never see a request.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createGuardedFetch } from "../backend/dist/sophos/guard.js";
import { RateLimiter } from "../backend/dist/sophos/rate-limiter.js";
import { createSophosCore, SophosRedirectError, setLogger } from "../backend/dist/vendor/sophos-core/index.js";
import { TENANT_XDR_OWNERSHIP } from "../backend/dist/vendor/sophos-core/fusion/queries/cases.js";

const SECRET = "secret-must-stay-home";
const TENANT = "11111111-1111-4111-8111-111111111111";

/** Requests the redirect target received. Must stay empty. */
const stolen = [];
/** Requests the stand-in Sophos received, as "host/path". */
const seen = [];
/** "host/path" to the status the stand-in Sophos answers it with; anything else answers normally. */
let redirects = new Map();

function listen(handler) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => handler(req, res, body));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

let sink;
let sophos;

/** Sends https://<host>/<path> to the stand-in Sophos as /<host>/<path>, with the caller's options untouched. */
const toStandIn = (input, init) => {
  const url = new URL(String(input));
  return fetch(`http://127.0.0.1:${sophos.address().port}/${url.host}${url.pathname}${url.search}`, init);
};

/** A core whose every call goes through the guard to the stand-in Sophos. */
function core(calls = []) {
  const guarded = createGuardedFetch({ limiter: new RateLimiter(), baseFetch: toStandIn, onCall: (record) => calls.push(record) });
  const sophosCore = createSophosCore({ clientId: "client-1", clientSecret: SECRET, fetch: guarded, fusion: { backoffBaseMs: 1 } });
  sophosCore.rest.sleep = async () => {};
  return sophosCore;
}

before(async () => {
  setLogger({ debug() {}, info() {}, warn() {}, error() {} });
  sink = await listen((req, res, body) => {
    stolen.push({ method: req.method, url: req.url, body, headers: req.headers });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ access_token: "stolen", expires_in: 3600, id: "x", idType: "tenant", apiHosts: {}, data: {} }));
  });
  sophos = await listen((req, res) => {
    const key = req.url.split("?")[0].slice(1);
    seen.push(key);
    const status = redirects.get(key);
    if (status) {
      res.writeHead(status, { Location: `http://127.0.0.1:${sink.address().port}/collect` });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    if (key === "id.sophos.com/api/v2/oauth2/token") {
      res.end(JSON.stringify({ access_token: "tok-1", token_type: "bearer", expires_in: 3600 }));
    } else if (key === "api.central.sophos.com/whoami/v1") {
      res.end(JSON.stringify({ id: TENANT, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com", dataRegion: "https://api-au01.central.sophos.com" } }));
    } else {
      res.end(JSON.stringify({ items: [] }));
    }
  });
});

after(() => {
  sink.close();
  sophos.close();
});

function reset(map) {
  redirects = new Map(map);
  seen.length = 0;
  stolen.length = 0;
}

for (const status of [307, 308]) {
  test(`a ${status} on the token request is refused and the client secret goes nowhere else`, async () => {
    reset([["id.sophos.com/api/v2/oauth2/token", status]]);
    await assert.rejects(
      () => core().tokens.getToken(),
      (error) =>
        error instanceof SophosRedirectError &&
        error.status === status &&
        error.message.includes(`with a ${status} redirect to 127.0.0.1:${sink.address().port}`) &&
        !error.message.includes(SECRET)
    );
    assert.deepEqual(seen, ["id.sophos.com/api/v2/oauth2/token"], "the token request was sent once, to Sophos");
    assert.deepEqual(stolen, [], "the redirect target got nothing");
  });
}

test("whoami, a REST read and a Fusion query refuse a redirect at once, with no retry", async () => {
  reset([["api.central.sophos.com/whoami/v1", 307]]);
  await assert.rejects(() => core().tenants.init(), SophosRedirectError);
  assert.deepEqual(stolen, []);

  const calls = [];
  const c = core(calls);
  reset([]);
  await c.tenants.init();

  reset([["api-au01.central.sophos.com/endpoint/v1/endpoints", 308]]);
  await assert.rejects(() => c.rest.tenantRequest(TENANT, "/endpoint/v1/endpoints"), SophosRedirectError);
  assert.deepEqual(seen, ["api-au01.central.sophos.com/endpoint/v1/endpoints"], "one try, no retry");
  assert.equal(calls.at(-1).status, 308, "the call still counts against the rate limit");

  reset([["api.taegis.sophos.com/graphql", 307]]);
  await assert.rejects(() => c.fusion.query(TENANT, TENANT_XDR_OWNERSHIP, { id: TENANT }), SophosRedirectError);
  assert.deepEqual(seen, ["api.taegis.sophos.com/graphql"], "one try, no retry");
  assert.deepEqual(stolen, [], "neither the token nor the tenant ID went to the redirect target");
});

test("the guard sends every Sophos request with redirect manual and leaves a normal answer alone", async () => {
  const sent = [];
  const guarded = createGuardedFetch({
    limiter: new RateLimiter(),
    baseFetch: async (input, init) => (sent.push(init.redirect), Response.json({ ok: true })),
  });
  const response = await guarded("https://api.central.sophos.com/whoami/v1", { method: "GET" });
  assert.equal(response.status, 200);
  await guarded("https://id.sophos.com/api/v2/oauth2/token", { method: "POST", body: "grant_type=client_credentials" });
  assert.deepEqual(sent, ["manual", "manual"]);
});
