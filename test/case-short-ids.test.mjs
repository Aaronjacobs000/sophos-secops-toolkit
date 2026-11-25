// Case short IDs in the vendored sophos-core: Sophos Fusion issues E-01167
// beside CSE00001 since 18/11/2026, and only digits-dash-digits (1-598868) is
// a Classic case ID. No network.
import test from "node:test";
import assert from "node:assert/strict";
import { isCaseShortId, isLegacyCaseId, isOtherDashedCaseId } from "../backend/dist/vendor/sophos-core/fusion/format.js";
import { CasesService, CaseNotFoundError } from "../backend/dist/vendor/sophos-core/services/cases.js";
import { LegacyCasesService } from "../backend/dist/vendor/sophos-core/services/legacy-cases.js";

const TENANT = "00000000-0000-4000-a000-000000000011";
const UUID = "00000000-0000-4000-a000-000000000099";

test("E-##### is a Fusion short ID, not a Classic ID; only digits-dash-digits is Classic", () => {
  for (const id of ["E-01167", "e-01167", "CSE00001", "cse00001"]) {
    assert.equal(isCaseShortId(id), true, id);
    assert.equal(isLegacyCaseId(id), false, id);
    assert.equal(isOtherDashedCaseId(id), false, id);
  }
  for (const id of ["1-598868", "3-201650"]) {
    assert.equal(isCaseShortId(id), false, id);
    assert.equal(isLegacyCaseId(id), true, id);
    assert.equal(isOtherDashedCaseId(id), false, id);
  }
  for (const id of ["X-00042", "AB-12"]) {
    assert.equal(isCaseShortId(id), false, id);
    assert.equal(isLegacyCaseId(id), false, id);
    assert.equal(isOtherDashedCaseId(id), true, id);
  }
  for (const id of [UUID, "E-", "E01167", ""]) {
    assert.equal(isCaseShortId(id), false, id);
    assert.equal(isLegacyCaseId(id), false, id);
    assert.equal(isOtherDashedCaseId(id), false, id);
  }
});

// Sophos Fusion issues F-08717 beside CSE00001 and E-01167 since 26/11/2026.
test("F-##### is a Fusion short ID, not a Classic ID or another two part ID", () => {
  for (const id of ["F-08717", "f-08717"]) {
    assert.equal(isCaseShortId(id), true, id);
    assert.equal(isLegacyCaseId(id), false, id);
    assert.equal(isOtherDashedCaseId(id), false, id);
  }
  for (const id of ["F-", "F08717", "F-0A"]) assert.equal(isCaseShortId(id), false, id);
});

test("resolveCaseId sends E-##### and other two part IDs to a Fusion shortId search, and Classic IDs to cases v1", async () => {
  const fusionQl = [];
  const fusion = {
    query: async (_tenantId, document, variables) => {
      if (!document.startsWith("query FusionListCases(")) throw new Error(`unexpected document ${document.slice(0, 40)}`);
      const ql = variables.arguments.query;
      fusionQl.push(ql);
      const cases = ql === "shortId = 'E-01167'" ? [{ id: UUID, shortId: "E-01167" }] : [];
      const pageInfo = { startCursor: null, endCursor: null, hasNextPage: false, hasPreviousPage: false };
      return { data: { cases: { totalCount: cases.length, pageInfo, cases } }, warnings: [] };
    },
  };
  const restPaths = [];
  const rest = {
    tenantRequest: async (_tenantId, path) => {
      restPaths.push(path);
      throw new Error("cases v1 is not used here");
    },
    tenantRequestWithMeta: async () => {
      throw new Error("cases v1 is not used here");
    },
  };
  const service = new CasesService(fusion, {}, new LegacyCasesService(rest));

  assert.deepEqual(await service.resolveCaseId(TENANT, "E-01167"), { id: UUID, warnings: [] });
  assert.deepEqual(await service.resolveCaseId(TENANT, " e-01167 "), { id: UUID, warnings: [] });
  await assert.rejects(() => service.resolveCaseId(TENANT, "CSE00001"), CaseNotFoundError);
  await assert.rejects(() => service.resolveCaseId(TENANT, "X-00042"), CaseNotFoundError);
  assert.deepEqual(fusionQl, ["shortId = 'E-01167'", "shortId = 'E-01167'", "shortId = 'CSE00001'", "shortId = 'X-00042'"]);

  // With the v1 service wired in, a Classic ID is passed through for cases v1, unsearched.
  assert.deepEqual(await service.resolveCaseId(TENANT, "1-598868"), { id: "1-598868", warnings: [] });
  assert.equal(fusionQl.length, 4);
  assert.deepEqual(restPaths, []);

  // Without it, a Classic ID is refused and an unrecognized one names both formats.
  const fusionOnly = new CasesService(fusion, {});
  await assert.rejects(() => fusionOnly.resolveCaseId(TENANT, "1-598868"), /Classic Sophos Central case ID/);
  await assert.rejects(() => fusionOnly.resolveCaseId(TENANT, "not a case"), /a short ID like CSE00001 or E-01167/);
  assert.equal(fusionQl.length, 4);
});
