// Retry-After in the vendored sophos-core clients. It comes as seconds or as an
// HTTP date (RFC 9110, 10.2.3); only seconds were read, so a date became NaN
// and the retry went at once. fetch is scripted and sleep recorded; no network.
import test from "node:test";
import assert from "node:assert/strict";
import { SophosClient, FusionClient, retryAfterMs } from "../backend/dist/vendor/sophos-core/index.js";

const TENANT = "00000000-0000-4000-a000-000000000011";

const limited = (retryAfter) => () => new Response("", { status: 429, headers: { "Retry-After": retryAfter } });
const ok = (body) => () => Response.json(body);

/** answers[n] answers the nth call, the last repeats; sleeps are recorded, not waited. */
function scripted(make, answers) {
  let n = 0;
  const fetch = async () => answers[Math.min(n++, answers.length - 1)]();
  const client = make(fetch);
  const waits = [];
  client.sleep = async (ms) => {
    waits.push(ms);
  };
  return { client, waits };
}

const rest = (fetch) => new SophosClient({ getToken: async () => "token" }, { resolveApiHost: async () => "https://api-eu01.central.sophos.com" }, fetch);
const fusion = (fetch) => new FusionClient({ getToken: async () => "token" }, { fetch, backoffBaseMs: 1 });

/** An HTTP date `seconds` from now, in whole seconds, as a server sends it. */
function httpDateIn(seconds, now = Date.now()) {
  return new Date(Math.ceil(now / 1000) * 1000 + seconds * 1000).toUTCString();
}

test("retryAfterMs reads seconds and HTTP dates", () => {
  const now = Date.UTC(2026, 9, 15, 8, 0, 0);
  assert.equal(retryAfterMs("120", now), 120_000);
  assert.equal(retryAfterMs("0", now), 0);
  assert.equal(retryAfterMs("Thu, 15 Oct 2026 08:01:30 GMT", now), 90_000);
  // A date already gone means no wait, not a negative one.
  assert.equal(retryAfterMs("Thu, 15 Oct 2026 07:59:00 GMT", now), 0);
  assert.equal(retryAfterMs("soon", now), null);
  assert.equal(retryAfterMs("", now), null);
  assert.equal(retryAfterMs(null, now), null);
});

test("the REST client waits until a Retry-After date", async () => {
  const { client, waits } = scripted(rest, [limited(httpDateIn(3)), ok({ items: [] })]);
  assert.deepEqual(await client.tenantRequest(TENANT, "/common/v1/alerts"), { items: [] });
  assert.equal(waits.length, 1);
  assert.ok(waits[0] > 2000 && waits[0] <= 4000, `waited ${waits[0]} ms`);
});

test("the Fusion client waits until a Retry-After date", async () => {
  const { client, waits } = scripted(fusion, [limited(httpDateIn(2)), ok({ data: { tenant: { id: TENANT } } })]);
  const { data } = await client.query(TENANT, "query { tenant { id } }");
  assert.equal(data.tenant.id, TENANT);
  assert.equal(waits.length, 1);
  assert.ok(waits[0] > 1000 && waits[0] <= 3000, `waited ${waits[0]} ms`);
});

test("seconds still work, and an unreadable header falls back to the default wait", async () => {
  const { client, waits } = scripted(rest, [limited("1"), limited("later"), ok({ items: [] })]);
  await client.tenantRequest(TENANT, "/common/v1/alerts");
  assert.deepEqual(waits, [1000, 5000]);

  const graph = scripted(fusion, [limited("2"), limited("later"), ok({ data: { tenant: { id: TENANT } } })]);
  await graph.client.query(TENANT, "query { tenant { id } }");
  assert.deepEqual(graph.waits, [2000, 5]);
});
