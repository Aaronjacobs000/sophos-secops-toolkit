import test from "node:test";
import assert from "node:assert/strict";
import { SearchService, SearchError, FusionGraphQLError, SEARCH_POLL_MS, MAX_SEARCH_PAGE } from "../backend/dist/vendor/sophos-core/index.js";
import { CREATE_SEARCH, GET_OR_CREATE_SEARCH, SEARCH_RESULTS, SEARCH_STATUS } from "../backend/dist/vendor/sophos-core/fusion/queries/search.js";

const T0 = Date.parse("2026-10-29T00:00:00Z");

function search(over = {}) {
  return {
    urn: "urn:search:t:1",
    status: "COMPLETE",
    errors: [],
    outcome: { success: "ALL", errors: [] },
    searchPartitions: [{ urn: "urn:p:1", schemaType: "auth", status: "SUCCEEDED", errors: [] }],
    createTime: new Date(T0).toISOString(),
    expireTime: new Date(T0 + 30 * 86_400_000).toISOString(),
    ...over,
  };
}

/**
 * A scripted FusionClient: `script` answers each call by document. Records
 * every call, and drives a fake clock so deadlines run without waiting.
 */
function harness(script) {
  const calls = [];
  let clock = T0 + 10_000;
  const fusion = {
    async query(tenantId, document, variables, options) {
      calls.push({ tenantId, document, variables, options });
      const answer = await script(document, variables, calls.length);
      if (answer instanceof Error) throw answer;
      return { data: answer, warnings: [] };
    },
  };
  const service = new SearchService(fusion);
  const sleeps = [];
  const opts = { now: () => clock, sleep: async (ms) => { sleeps.push(ms); clock += ms; } };
  return { service, calls, sleeps, opts, advance: (ms) => (clock += ms) };
}

const kind = (doc) => (doc === GET_OR_CREATE_SEARCH ? "goc" : doc === CREATE_SEARCH ? "create" : doc === SEARCH_STATUS ? "status" : doc === SEARCH_RESULTS ? "results" : "other");

test("a search is reused, polled every 5 s until complete, then read page by page", async () => {
  let polls = 0;
  const h = harness((doc, vars) => {
    if (kind(doc) === "goc") return { getOrCreateSearch: search({ status: "QUEUED", createTime: new Date(T0 + 10_000).toISOString() }) };
    if (kind(doc) === "status") return { search: search({ status: ++polls < 3 ? "IN_PROGRESS" : "COMPLETE" }) };
    if (kind(doc) === "results") {
      const page = vars.cursor ? Number(vars.cursor) : 0;
      return { searchResults: { values: [{ n: page * 2 }, { n: page * 2 + 1 }], totals: { total: { value: "6" } }, nextCursor: page < 2 ? String(page + 1) : null } };
    }
  });
  const run = await h.service.run("t1", "from auth earliest=-1h", h.opts);
  assert.deepEqual(h.calls.map((c) => kind(c.document)), ["goc", "status", "status", "status", "results", "results", "results"]);
  assert.deepEqual(h.sleeps, [SEARCH_POLL_MS, SEARCH_POLL_MS, SEARCH_POLL_MS]);
  assert.deepEqual(run.rows.map((r) => r.n), [0, 1, 2, 3, 4, 5]);
  assert.equal(run.total, 6, "an Int64 total that arrives as a string is read as a number");
  assert.equal(run.calls, 7);
  assert.equal(run.outcome, "ALL");
  assert.equal(run.reused, false, "a search created by this call is not a reuse");
  assert.deepEqual(h.calls[0].variables, { input: { text: "from auth earliest=-1h" } });
  assert.equal(h.calls[4].variables.limit, MAX_SEARCH_PAGE);
  assert.equal(h.calls[5].variables.cursor, "1", "the cursor goes back unchanged");
});

test("results pages carry the page timeout; starting and polling keep the client's", async () => {
  const h = harness((doc, vars) => {
    if (kind(doc) === "goc") return { getOrCreateSearch: search({ status: "QUEUED", createTime: new Date(T0 + 10_000).toISOString() }) };
    if (kind(doc) === "status") return { search: search() };
    if (kind(doc) === "results") return { searchResults: { values: [{ n: 1 }], totals: { total: { value: 2 } }, nextCursor: vars.cursor ? null : "1" } };
  });
  await h.service.run("t1", "from auth earliest=-1h", { ...h.opts, pageTimeoutMs: 90_000 });
  assert.deepEqual(h.calls.map((c) => [kind(c.document), c.options?.timeoutMs]), [["goc", undefined], ["status", undefined], ["results", 90_000], ["results", 90_000]]);
});

test("createSearch is used when reuse is off, and is never retried after a 5xx", async () => {
  const h = harness((doc) => (kind(doc) === "create" ? { createSearch: search() } : { searchResults: { values: [], totals: null, nextCursor: null } }));
  await h.service.run("t1", "from auth earliest=-1h", { ...h.opts, reuse: false });
  assert.equal(kind(h.calls[0].document), "create");
  assert.equal(h.calls[0].options.idempotent, false);
});

test("a search still running at the deadline throws a timeout that names the search", async () => {
  const h = harness((doc) => (kind(doc) === "goc" ? { getOrCreateSearch: search({ status: "IN_PROGRESS" }) } : { search: search({ status: "IN_PROGRESS" }) }));
  await assert.rejects(h.service.run("t1", "from auth", { ...h.opts, deadlineMs: 20_000 }), (err) => {
    assert.ok(err instanceof SearchError);
    assert.equal(err.kind, "timeout");
    assert.equal(err.urn, "urn:search:t:1");
    return true;
  });
  assert.equal(h.sleeps.length, 4, "polls stop at the deadline");
});

test("PARTIAL: accepted by default with the failed schemas named, or refused on request", async () => {
  const partial = search({
    outcome: { success: "PARTIAL", errors: [{ urn: "urn:p:2", errors: ["netflow timed out"] }] },
    searchPartitions: [
      { urn: "urn:p:1", schemaType: "auth", status: "SUCCEEDED", errors: [] },
      { urn: "urn:p:2", schemaType: "netflow", status: "FAILED", errors: [] },
    ],
  });
  const answer = (doc) => (kind(doc) === "goc" ? { getOrCreateSearch: partial } : { searchResults: { values: [{ a: 1 }], totals: null, nextCursor: null } });
  const h = harness(answer);
  const run = await h.service.run("t1", "from auth, netflow", h.opts);
  assert.equal(run.outcome, "PARTIAL");
  assert.deepEqual(run.failedPartitions, [{ schemaType: "netflow", errors: ["netflow timed out"] }]);
  assert.equal(run.rows.length, 1);
  const r = harness(answer);
  await assert.rejects(r.service.run("t1", "from auth, netflow", { ...r.opts, partial: "reject" }), /partial: netflow failed/);
});

test("a reused search that failed is run once more as a new search; a new failure throws", async () => {
  const failed = search({ outcome: { success: "NONE", errors: [{ urn: "urn:p:1", errors: ["boom"] }] } });
  const h = harness((doc) => (kind(doc) === "goc" ? { getOrCreateSearch: failed } : kind(doc) === "create" ? { createSearch: failed } : null));
  await assert.rejects(h.service.run("t1", "from auth", h.opts), (err) => err.kind === "failed" && /boom/.test(err.message));
  assert.deepEqual(h.calls.map((c) => kind(c.document)), ["goc", "create"]);
});

test("a reused search close to expiry is replaced by a new one", async () => {
  const old = search({ createTime: new Date(T0 - 29 * 86_400_000).toISOString(), expireTime: new Date(T0 + 10_000 + 60_000).toISOString() });
  const h = harness((doc) => (kind(doc) === "goc" ? { getOrCreateSearch: old } : kind(doc) === "create" ? { createSearch: search({ urn: "urn:search:t:2" }) } : { searchResults: { values: [], totals: null, nextCursor: null } }));
  const run = await h.service.run("t1", "from auth", h.opts);
  assert.equal(run.urn, "urn:search:t:2");
  assert.equal(run.reused, false);
});

test("results that expire while being read are fetched again from a new search, once", async () => {
  let reads = 0;
  const h = harness((doc) => {
    if (kind(doc) === "goc") return { getOrCreateSearch: search({ createTime: new Date(T0 - 86_400_000).toISOString() }) };
    if (kind(doc) === "create") return { createSearch: search({ urn: "urn:search:t:9" }) };
    if (++reads === 1) return new FusionGraphQLError("gone", [{ message: "search results expired" }]);
    return { searchResults: { values: [{ ok: true }], totals: null, nextCursor: null } };
  });
  const run = await h.service.run("t1", "from auth", h.opts);
  assert.equal(run.urn, "urn:search:t:9");
  assert.deepEqual(run.rows, [{ ok: true }]);
});

test("a refusal (HTTP 403 or a permission error) is a 'denied' error the scheduler treats as no access", async () => {
  for (const refusal of [new Error("Sophos Fusion API error 403: Forbidden"), new FusionGraphQLError("x", [{ message: "Unauthorized: missing permission", extensions: { code: "FORBIDDEN" } }])]) {
    const h = harness(() => refusal);
    await assert.rejects(h.service.run("t1", "from auth", h.opts), (err) => err instanceof SearchError && err.kind === "denied" && err.noAccess === true);
  }
  const other = harness(() => new Error("Sophos Fusion API error 500: boom"));
  await assert.rejects(other.service.run("t1", "from auth", other.opts), (err) => !(err instanceof SearchError));
});

test("reading stops at maxRows and the run says it was truncated", async () => {
  const h = harness((doc, vars) =>
    kind(doc) === "goc" ? { getOrCreateSearch: search() } : { searchResults: { values: [{ i: 1 }, { i: 2 }, { i: 3 }], totals: { total: { value: 9 } }, nextCursor: vars.cursor ? null : "c" } },
  );
  const run = await h.service.run("t1", "from auth", { ...h.opts, maxRows: 4 });
  assert.equal(run.rows.length, 4);
  assert.equal(run.truncated, true);
  assert.equal(run.total, 9);
});

test("a COMPLETE search with an UNKNOWN outcome failed as a whole and says why", async () => {
  const h = harness(() => ({ createSearch: search({ outcome: { success: "UNKNOWN", errors: [] }, errors: ["query validation failed"] }) }));
  await assert.rejects(h.service.run("t1", "from auth", { ...h.opts, reuse: false }), /query validation failed/);
});
