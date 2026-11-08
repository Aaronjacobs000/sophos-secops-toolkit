import test from "node:test";
import assert from "node:assert/strict";
import { sensorLabel } from "../backend/dist/mappers/views.js";

// icons.js loads the DOM helpers, which patch Element.prototype; sourceIcon itself needs no DOM.
globalThis.Element ??= class {};
const { sourceIcon } = await import("../frontend/js/icons.js");

test("only real cloud sources get the cloud icon", () => {
  for (const kind of ["cloud", "google cloud", "aws", "azure"]) assert.equal(sourceIcon(kind), "cloud", kind);
  assert.notEqual(sourceIcon("cloudflare"), "cloud");
  assert.notEqual(sourceIcon("cloudflare http"), "cloud");
});

test("Cloudflare takes the firewall icon on the overview", () => {
  // The overview passes the label, lower-cased, as the source kind.
  for (const raw of ["CLOUDFLARE_HTTP", "Cloudflare"]) assert.equal(sourceIcon(sensorLabel(raw).toLowerCase()), "firewall", raw);
  assert.equal(sourceIcon("sophos firewall"), "firewall");
});

test("a vendor name decides the icon before a generic word such as server", () => {
  // Sensor types as Fusion stores them and as the Taegis Sensor Types page lists them, through the label the overview shows.
  const cases = {
    "Amazon S3 server access log": "cloud",
    "Amazon GuardDuty": "cloud",
    "AWS CloudTrail": "cloud",
    "Google Cloud Platform": "cloud",
    Salesforce: "cloud",
    "Delinea Secret Server": "identity",
    CyberArk: "identity",
    "Google Workspace": "identity",
    GOOGLE_WORKSPACE: "identity",
    "Cisco Duo": "identity",
    OKTA: "identity",
    MICROSOFT_GRAPH_SIGN_IN: "identity",
    AbnormalSecurity: "email",
    "Check Point Harmony Email": "email",
    BARRACUDA_WAF: "firewall",
    FORTIGATE_FW: "firewall",
    PALOALTO_FIREWALL: "firewall",
    CISCO_FIREWALL_ASA: "firewall",
    ENDPOINT_CROWD_STRIKE: "endpoint",
    ENDPOINT_SENTINELONE: "endpoint",
    ENDPOINT_CARBON_BLACK_PSC: "endpoint",
    ENDPOINT_HARFANG_LAB: "endpoint",
    "AWS VPC Flow": "cloud",
    ORACLE_OCI_AUDIT: "cloud",
    SERVER: "server",
    ENDPOINT_SOPHOS: "endpoint",
  };
  for (const [raw, want] of Object.entries(cases)) assert.equal(sourceIcon(sensorLabel(raw).toLowerCase()), want, raw);
  assert.notEqual(sourceIcon("sophos central"), "identity", "entra counts as a whole word only");
});

test("only the Microsoft identity sources take the identity icon on the overview", () => {
  // The Microsoft sensor types on the Taegis Sensor Types page, through the label the overview shows.
  const cases = {
    MICROSOFT_WINDOWS_SNARE: "server",
    MICROSOFT_WINDOWS_SPLUNK: "server",
    "Microsoft IIS": "server",
    MSDHCP: "network",
    MSDNS: "network",
    ENDPOINT_MICROSOFT_ATP: "endpoint",
    "Azure Application Gateway": "cloud",
    "Azure Firewall": "firewall",
    "Azure Flow Logs": "cloud",
    "Azure Front Door": "cloud",
    MICROSOFT_AZURE_ACTIVITY: "cloud",
    MICROSOFT_GRAPH_ALERTS: "radar",
    "Azure Risk Detection": "identity",
    MICROSOFT_GRAPH_SIGN_IN: "identity",
    MICROSOFT_GRAPH_DIRECTORY_AUDIT: "identity",
    MICROSOFT_OFFICE_MANAGEMENT: "identity",
  };
  for (const [raw, want] of Object.entries(cases)) assert.equal(sourceIcon(sensorLabel(raw).toLowerCase()), want, raw);
});

test("Sophos product labels keep their icons", () => {
  const cases = { endpoint: "endpoint", server: "server", firewall: "firewall", email: "email", emailgateway: "email", encryption: "lock", mobile: "mobile", wireless: "network", ndr: "network", integrations: "integration", tenant: "tenant", other: "radar" };
  for (const [kind, want] of Object.entries(cases)) assert.equal(sourceIcon(kind), want, kind);
});
