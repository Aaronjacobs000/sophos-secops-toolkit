import test from "node:test";
import assert from "node:assert/strict";
import { detectContext, ContextError, tenantListPath } from "../backend/dist/sophos/context.js";

const ID = "11111111-2222-4333-8444-555555555555";

test("a tenant credential gets the single-tenant screens and its regional host", () => {
  const ctx = detectContext({ id: ID, idType: "tenant", apiHosts: { global: "https://api.central.sophos.com", dataRegion: "https://api-au01.central.sophos.com" } });
  assert.equal(ctx.kind, "tenant");
  assert.equal(ctx.multiTenant, false);
  assert.equal(ctx.apiHost, "https://api-au01.central.sophos.com");
  assert.equal(ctx.idHeader, "X-Tenant-ID");
  assert.ok(!ctx.views.includes("msp"), "no MSP wall for one tenant");
  assert.deepEqual(ctx.views, ["front", "now", "cases", "endpoints", "signins", "sources", "ai", "reports", "atlas"]);
});

test("a partner credential gets the MSP wall and the tenant picker", () => {
  const ctx = detectContext({ id: ID, idType: "partner", apiHosts: { global: "https://api.central.sophos.com" } });
  assert.equal(ctx.kind, "partner");
  assert.equal(ctx.multiTenant, true);
  assert.equal(ctx.idHeader, "X-Partner-ID");
  assert.equal(ctx.apiHost, null);
  assert.ok(ctx.views.includes("msp"));
  assert.equal(tenantListPath("partner"), "/partner/v1/tenants");
});

test("an organization credential is multi-tenant like a partner", () => {
  const ctx = detectContext({ id: ID, idType: "organization", apiHosts: { global: "https://api.central.sophos.com" } });
  assert.equal(ctx.kind, "organization");
  assert.equal(ctx.multiTenant, true);
  assert.equal(ctx.idHeader, "X-Organization-ID");
  assert.ok(ctx.views.includes("msp"));
  assert.equal(tenantListPath("organization"), "/organization/v1/tenants");
  assert.equal(tenantListPath("tenant"), null);
});

test("unknown or broken whoami answers are refused with a clear message", () => {
  assert.throws(() => detectContext(null), ContextError);
  assert.throws(() => detectContext({ id: ID, idType: "distributor", apiHosts: {} }), /Unknown credential type/);
  assert.throws(() => detectContext({ id: "not-a-uuid", idType: "tenant", apiHosts: { dataRegion: "https://api-au01.central.sophos.com" } }), /no usable ID/);
  assert.throws(() => detectContext({ id: ID, idType: "tenant", apiHosts: {} }), /data region host/);
});

test("a data region host that is not a Sophos host is not trusted", () => {
  assert.throws(() => detectContext({ id: ID, idType: "tenant", apiHosts: { dataRegion: "https://evil.example.com" } }), /data region host/);
  assert.throws(() => detectContext({ id: ID, idType: "tenant", apiHosts: { dataRegion: "http://api-au01.central.sophos.com" } }), /data region host/);
  const ctx = detectContext({ id: ID, idType: "partner", apiHosts: { global: "https://evil.example.com" } });
  assert.equal(ctx.globalHost, "https://api.central.sophos.com", "falls back to the known global host");
});
