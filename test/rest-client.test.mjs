// Retries in the vendored sophos-core REST client. fetch is scripted; no network.
import test from "node:test";
import assert from "node:assert/strict";
import { SophosClient, SophosApiRequestError } from "../backend/dist/vendor/sophos-core/index.js";

const TENANT = "00000000-0000-4000-a000-000000000011";

/** A SophosClient on a scripted transport: handler(n) answers the nth call. No backoff waits. */
function scripted(handler) {
  const calls = [];
  const fetch = async (url) => {
    calls.push(String(url));
    return handler(calls.length);
  };
  const resolver = { resolveApiHost: async () => "https://api-eu01.central.sophos.com" };
  const rest = new SophosClient({ getToken: async () => "token" }, resolver, fetch);
  rest.sleep = async () => {};
  return { rest, calls };
}

test("a 4xx whose body is not JSON is sent once, not retried", async () => {
  const { rest, calls } = scripted(() => new Response("<html>Not Found</html>", { status: 404 }));
  await assert.rejects(rest.tenantRequest(TENANT, "/endpoint/v1/endpoints"), (err) => {
    assert.ok(err instanceof SophosApiRequestError);
    assert.equal(err.status, 404);
    assert.equal(err.message, "Sophos API error (404): <html>Not Found</html>");
    return true;
  });
  assert.equal(calls.length, 1, "one attempt, not three");
});

test("a 4xx with a JSON body is still sent once, and a 5xx is still retried", async () => {
  const json = scripted(() => Response.json({ error: "BadRequest", message: "no" }, { status: 400 }));
  await assert.rejects(json.rest.tenantRequest(TENANT, "/common/v1/alerts"), /Sophos API error 400: BadRequest - no/);
  assert.equal(json.calls.length, 1);

  const flaky = scripted((n) => (n === 1 ? new Response("upstream", { status: 502 }) : Response.json({ items: [] })));
  assert.deepEqual(await flaky.rest.tenantRequest(TENANT, "/common/v1/alerts"), { items: [] });
  assert.equal(flaky.calls.length, 2);
});
