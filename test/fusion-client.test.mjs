import test from "node:test";
import assert from "node:assert/strict";
import { FusionClient, createSophosCore, isTenantNotOnFusion } from "../backend/dist/vendor/sophos-core/index.js";
import { fetchGeneration } from "../backend/dist/data/fetchers.js";

const TENANT = "00000000-0000-4000-a000-000000000011";

// The body Sophos sent on 29/10/2026 for two partner tenants Fusion does not
// hold, 3 of 3 times each, with only the tenant id replaced. It carries no
// error code, so the text is what marks it.
const NOT_ON_FUSION = { message: `error invoking downstream api\ntenantsv4.APIClient.GetTenant: input:1:30: tenant ${TENANT} not found or not accessible` };

const reply = ({ status, body }) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** A FusionClient on a scripted transport: the nth call gets answers[n], the last answer repeats. */
function scripted(answers) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return reply(answers[Math.min(calls.length - 1, answers.length - 1)]);
  };
  const fusion = new FusionClient({ getToken: async () => "token" }, { fetch, backoffBaseMs: 0 });
  return { fusion, calls };
}

const QUERY = "query FusionTenantXdrOwnership($id: ID!) { tenant(id: $id) { id } }";

test("the 503 for a tenant Fusion does not hold is an answer: one call, no retry", async () => {
  const { fusion, calls } = scripted([{ status: 503, body: NOT_ON_FUSION }]);
  await assert.rejects(fusion.query(TENANT, QUERY, { id: TENANT }), (err) => {
    assert.ok(isTenantNotOnFusion(err), err.message);
    return true;
  });
  assert.equal(calls.length, 1);
});

test("any other 503 and other 5xx answers are still retried", async () => {
  const outage = scripted([{ status: 503, body: { message: "upstream connect error or disconnect/reset before headers" } }]);
  await assert.rejects(outage.fusion.query(TENANT, QUERY), (err) => !isTenantNotOnFusion(err) && /error 503/.test(err.message));
  assert.equal(outage.calls.length, 3, "first try plus the two retries");

  const blip = scripted([{ status: 502, body: { message: "bad gateway" } }, { status: 200, body: { data: { tenant: { id: TENANT } } } }]);
  const { data } = await blip.fusion.query(TENANT, QUERY);
  assert.equal(data.tenant.id, TENANT);
  assert.equal(blip.calls.length, 2);
});

test("a per-call timeout overrides the client's own for that call only", async () => {
  // Answers after 120 ms unless the caller gives up first.
  const fetch = (url, init) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(reply({ status: 200, body: { data: { tenant: { id: TENANT } } } })), 120);
    init.signal.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
    });
  });
  const fusion = new FusionClient({ getToken: async () => "token" }, { fetch, timeoutMs: 40, retries: 0 });
  const { data } = await fusion.query(TENANT, QUERY, { id: TENANT }, { timeoutMs: 1_000 });
  assert.equal(data.tenant.id, TENANT);
  await assert.rejects(fusion.query(TENANT, QUERY, { id: TENANT }), /timed out after 40ms/);
});

test("the daily generation check reads a Classic partner tenant in one Fusion call", async () => {
  const fusionCalls = [];
  const fetch = async (url, init) => {
    if (new URL(url).hostname === "id.sophos.com") return reply({ status: 200, body: { access_token: "fake-access-token-value", token_type: "bearer", expires_in: 3600, errorCode: "success" } });
    fusionCalls.push(init);
    return reply({ status: 503, body: NOT_ON_FUSION });
  };
  const core = createSophosCore({ clientId: "id", clientSecret: "secret", fetch, fusion: { backoffBaseMs: 0 } });
  assert.deepEqual(await fetchGeneration(core, TENANT), { generation: "classic", xdrOwnership: null });
  assert.equal(fusionCalls.length, 1);
});
