import test from "node:test";
import assert from "node:assert/strict";
import { assertReadOnly, createGuardedFetch, graphqlOperation, ReadOnlyViolationError, ALLOWED_GRAPHQL_OPERATIONS, ALLOWED_GRAPHQL_MUTATIONS, allowedSearchMutation } from "../backend/dist/sophos/guard.js";
import { CREATE_SEARCH, GET_OR_CREATE_SEARCH, SEARCH_STATUS, SEARCH_RESULTS } from "../backend/dist/vendor/sophos-core/fusion/queries/search.js";
import { RateLimiter } from "../backend/dist/sophos/rate-limiter.js";
import { LIST_CASES, TENANT_XDR_OWNERSHIP, CREATE_CASE, UPDATE_CASE, ADD_CASE_COMMENT } from "../backend/dist/vendor/sophos-core/fusion/queries/cases.js";
import { DETECTION_SEARCH_DOC, DETECTION_COUNT_DOC, EGRESS_SQL, EGRESS_GEO_SQL } from "../backend/dist/data/fetchers.js";

const REGION = "https://api-au01.central.sophos.com";
const GQL = "https://api.taegis.sophos.com/graphql";
const gql = (query) => ({ method: "POST", body: JSON.stringify({ query, variables: {} }) });

test("reads are allowed", () => {
  assertReadOnly(`${REGION}/endpoint/v1/endpoints?pageSize=500`);
  assertReadOnly("https://api.central.sophos.com/whoami/v1", { method: "GET" });
  assertReadOnly("https://id.sophos.com/api/v2/oauth2/token", { method: "POST", body: "grant_type=client_credentials" });
  assertReadOnly(`${REGION}/xdr-query/v1/queries/runs`, { method: "POST", body: JSON.stringify({ adHocQuery: { template: EGRESS_SQL } }) });
  assertReadOnly(`${REGION}/xdr-query/v1/queries/runs`, { method: "POST", body: JSON.stringify({ adHocQuery: { template: EGRESS_GEO_SQL } }) });
});

test("every GraphQL document the toolkit sends is an allowlisted query", () => {
  for (const doc of [LIST_CASES, TENANT_XDR_OWNERSHIP, DETECTION_SEARCH_DOC, DETECTION_COUNT_DOC]) {
    assertReadOnly(GQL, gql(doc));
    assert.ok(ALLOWED_GRAPHQL_OPERATIONS.has(graphqlOperation(doc)));
  }
});

test("writes to Central are refused before anything is sent", () => {
  for (const [method, path] of [
    ["PATCH", "/endpoint/v1/endpoints/x/isolation"],
    ["POST", "/endpoint/v1/endpoints/x/scans"],
    ["DELETE", "/endpoint/v1/endpoints/x"],
    ["PUT", "/endpoint/v1/settings/exclusions/scanning/x"],
    ["POST", "/common/v1/alerts/x/actions"],
    ["POST", "/cases/v1/cases"],
    ["PATCH", "/cases/v1/cases/1-2"],
    ["POST", "/endpoint/v1/policies"],
  ]) {
    assert.throws(() => assertReadOnly(`${REGION}${path}`, { method, body: "{}" }), ReadOnlyViolationError, `${method} ${path}`);
  }
});

test("a Data Lake run must be a SELECT", () => {
  assert.throws(() => assertReadOnly(`${REGION}/xdr-query/v1/queries/runs`, { method: "POST", body: JSON.stringify({ adHocQuery: { template: "DROP TABLE xdr_data" } }) }), /SELECT/);
  assert.throws(() => assertReadOnly(`${REGION}/xdr-query/v1/queries/runs`, { method: "POST", body: "not json" }), /JSON/);
});

test("GraphQL mutations are refused whatever they are called", () => {
  for (const doc of [CREATE_CASE, UPDATE_CASE, ADD_CASE_COMMENT, "mutation FusionListCases { updateCase(input: {}) { id } }", "query ToolkitDetectionCount { a } mutation X { b }", "  mutation\n{ x }"]) {
    assert.throws(() => assertReadOnly(GQL, gql(doc)), ReadOnlyViolationError, doc.slice(0, 40));
  }
  assert.throws(() => assertReadOnly(GQL, gql("query SomethingElse { tenants { id } }")), /allowlist/);
  assert.throws(() => assertReadOnly(GQL, gql("{ tenants { id } }")), /named queries/);
  assert.throws(() => assertReadOnly(GQL, { method: "GET" }), /POST/);
  // A keyword inside a string literal does not count against a real query.
  assert.equal(graphqlOperation('query ToolkitDetectionCount { a(q: "mutation") }'), "ToolkitDetectionCount");
});

test("only Sophos API hosts are reachable, over https", () => {
  assert.throws(() => assertReadOnly("https://example.com/"), /not a Sophos API host/);
  assert.throws(() => assertReadOnly("https://api.central.sophos.com.evil.example/whoami/v1"), /not a Sophos API host/);
  assert.throws(() => assertReadOnly("http://api.central.sophos.com/whoami/v1"), /https/);
  assert.throws(() => assertReadOnly("https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz"), /only when you start a download/);
  assertReadOnly("https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", {}, { allowDownloads: true });
  assert.throws(() => assertReadOnly("https://download.db-ip.com/free/other.exe", {}, { allowDownloads: true }), /DB-IP City Lite/);
});

test("the guarded fetch never calls the network for a refused request", async () => {
  let called = 0;
  const f = createGuardedFetch({ limiter: new RateLimiter(), baseFetch: async () => (called++, new Response("{}")) });
  await assert.rejects(f(`${REGION}/endpoint/v1/endpoints/x/isolation`, { method: "PATCH", body: "{}" }), ReadOnlyViolationError);
  await assert.rejects(f(GQL, gql(CREATE_CASE)), ReadOnlyViolationError);
  assert.equal(called, 0);
  await f(`${REGION}/endpoint/v1/endpoints`);
  assert.equal(called, 1);
});

test("a 429 from Sophos pauses the credential's limiter", async () => {
  const limiter = new RateLimiter();
  const f = createGuardedFetch({ limiter, baseFetch: async () => new Response("{}", { status: 429, headers: { "Retry-After": "12" } }) });
  await f(`${REGION}/endpoint/v1/endpoints`);
  assert.ok(limiter.stats().pausedFor >= 11_000);
});

// ------------------------------------------------------------------ Search GraphQL mutations

const searchBody = (query, variables = { input: { text: "from auth earliest=-1h | aggregate count" } }, extra = {}) => ({ method: "POST", body: JSON.stringify({ query, variables, ...extra }) });

test("exactly two mutations are allowed, and they are the client's own documents", () => {
  assert.deepEqual([...ALLOWED_GRAPHQL_MUTATIONS.keys()], ["CreateSearch", "GetOrCreateSearch"]);
  assert.equal(ALLOWED_GRAPHQL_MUTATIONS.get("CreateSearch"), CREATE_SEARCH, "guard and client copies must match character for character");
  assert.equal(ALLOWED_GRAPHQL_MUTATIONS.get("GetOrCreateSearch"), GET_OR_CREATE_SEARCH);
  assertReadOnly(GQL, searchBody(CREATE_SEARCH));
  assertReadOnly(GQL, searchBody(GET_OR_CREATE_SEARCH));
  assertReadOnly(GQL, searchBody(CREATE_SEARCH, undefined, { operationName: "CreateSearch" }));
  assert.equal(allowedSearchMutation(JSON.parse(searchBody(GET_OR_CREATE_SEARCH).body)), "GetOrCreateSearch");
  // Polling and reading results are ordinary allowlisted queries.
  assertReadOnly(GQL, { method: "POST", body: JSON.stringify({ query: SEARCH_STATUS, variables: { urn: "urn:x" } }) });
  assertReadOnly(GQL, { method: "POST", body: JSON.stringify({ query: SEARCH_RESULTS, variables: { urn: "urn:x", limit: 1000 } }) });
});

test("near misses of the search documents are refused", () => {
  const nearMisses = [
    CREATE_SEARCH + "\n",
    " " + CREATE_SEARCH,
    CREATE_SEARCH.replace("urn\n", "urn\n    metadata\n"),
    CREATE_SEARCH.replace("    expireTime\n", ""),
    CREATE_SEARCH.replace("CreateSearch(", "createSearch("),
    CREATE_SEARCH.replace(/\n\s*/g, " "),
    CREATE_SEARCH + "\nmutation X { deleteCase(id: 1) { id } }",
    CREATE_SEARCH.replace("createSearch(input: $input)", "updateCase(input: $input)"),
    GET_OR_CREATE_SEARCH.replace("mutation GetOrCreateSearch", "mutation CreateSearch"),
    "mutation CreateSearch($input: CreateSearchInput) { createSearch(input: $input) { urn } }",
    "mutation CreateSearch { deleteCase(id: 1) { id } }",
    "mutation GetOrCreateSearch($input: CreateSearchInput) { getOrCreateSearch(input: $input) { urn status } }",
  ];
  for (const doc of nearMisses) {
    assert.throws(() => assertReadOnly(GQL, searchBody(doc)), ReadOnlyViolationError, JSON.stringify(doc.slice(0, 60)));
  }
});

test("an allowed search document with anything else in the request is refused", () => {
  const bad = [
    searchBody(CREATE_SEARCH, { input: { text: "from auth", metadata: { a: 1 } } }),
    searchBody(CREATE_SEARCH, { input: { text: "from auth", spec: {} } }),
    searchBody(CREATE_SEARCH, { input: { text: "" } }),
    searchBody(CREATE_SEARCH, { input: { text: 42 } }),
    searchBody(CREATE_SEARCH, { input: { text: "x".repeat(8001) } }),
    searchBody(CREATE_SEARCH, { input: { text: "from auth" }, other: 1 }),
    searchBody(CREATE_SEARCH, {}),
    searchBody(CREATE_SEARCH, undefined, { operationName: "UpdateCase" }),
    searchBody(GET_OR_CREATE_SEARCH, undefined, { operationName: "CreateSearch" }),
    searchBody(CREATE_SEARCH, undefined, { extensions: { persistedQuery: { sha256Hash: "x" } } }),
    { method: "POST", body: JSON.stringify([{ query: CREATE_SEARCH, variables: { input: { text: "from auth" } } }]) },
    { method: "GET", body: JSON.stringify({ query: CREATE_SEARCH, variables: { input: { text: "from auth" } } }) },
  ];
  for (const init of bad) assert.throws(() => assertReadOnly(GQL, init), ReadOnlyViolationError, String(init.body).slice(0, 80));
  assert.throws(() => assertReadOnly("https://api.taegis.sophos.com/other", searchBody(CREATE_SEARCH)), /POST \/graphql only/);
});

test("other mutations stay refused, including the ones Search GraphQL's neighbours define", () => {
  for (const doc of [
    "mutation runLiveDiscoverQuery { runLiveDiscoverQuery(input: {}) { id } }",
    "mutation CancelSearch($urn: URN!) { cancelSearch(urn: $urn) { urn } }",
    "mutation GetOrCreateSearch($input: CreateSearchInput) { getOrCreateSearch(input: $input) { urn } } ",
  ]) {
    assert.throws(() => assertReadOnly(GQL, searchBody(doc)), ReadOnlyViolationError);
  }
});

test("the guarded fetch sends an allowed search and records its operation name", async () => {
  let called = 0;
  const records = [];
  const f = createGuardedFetch({ limiter: new RateLimiter(), baseFetch: async () => (called++, new Response("{}")), onCall: (r) => records.push(r) });
  await f(GQL, searchBody(GET_OR_CREATE_SEARCH));
  await assert.rejects(f(GQL, searchBody(GET_OR_CREATE_SEARCH + " ")), ReadOnlyViolationError);
  assert.equal(called, 1);
  assert.equal(records[0].operation, "GetOrCreateSearch");
});

test("a quote inside a comment can't hide a mutation from the guard", () => {
  const post = (body) => ({ method: "POST", body: JSON.stringify(body) });
  const hidden = [
    // A quote in a comment opened a "string" that swallowed the mutation on the next line.
    { query: 'query FusionListCases { a } # "\nmutation M { deleteThing(id: "x") { id } }\n# "', operationName: "M" },
    { query: 'query FusionListCases { a } # """\nmutation M { deleteThing(id: "x") { id } }\n# """', operationName: "M" },
    // A string left open, or escaping its own line end, refuses rather than hiding what follows.
    { query: 'query FusionListCases { a(b: "x\n) }\nmutation M { deleteThing { id } }' },
    { query: 'query FusionListCases { a(b: "x\\\nmutation M { deleteThing { id } }\n") }' },
    { query: 'query FusionListCases { a(b: """open) }\nmutation M { deleteThing { id } }' },
  ];
  for (const body of hidden) assert.throws(() => assertReadOnly(GQL, post(body)), ReadOnlyViolationError, body.query.slice(0, 50));
  // Strings and comments that hold keywords are still fine.
  assert.equal(graphqlOperation('query FusionListCases { a(b: "mutation # not a comment", c: """block\n\\""" mutation""") } # mutation'), "FusionListCases");
});

test("a GraphQL read carries only query, variables and a matching operationName", () => {
  const post = (body) => ({ method: "POST", body: JSON.stringify(body) });
  assertReadOnly(GQL, post({ query: LIST_CASES, variables: {}, operationName: "FusionListCases" }));
  assert.throws(() => assertReadOnly(GQL, post({ query: LIST_CASES, variables: {}, operationName: "M" })), /operationName must be FusionListCases/);
  assert.throws(() => assertReadOnly(GQL, post({ query: LIST_CASES, variables: {}, extensions: { persistedQuery: {} } })), /only query, variables and operationName/);
});
