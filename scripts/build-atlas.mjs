#!/usr/bin/env node
// Builds the Schema Atlas snapshot the app ships with.
//
//   node scripts/build-atlas.mjs <qlSchemaMapV1.json> [legacy-schemas-dir]
//
// 1. Fusion: the answer to the undocumented Fusion GraphQL query
//    `query { qlSchemaMapV1 }` saved as JSON (schema metadata only, the same
//    for every tenant). It is normalised, relabelled where descriptions use
//    pre-Fusion product names, and dated. The app never calls it live.
// 2. Data Lake (Classic): the public schema JSON on docs.sophos.com. Read from
//    a folder of saved files when given, otherwise fetched (no credential).
//
// Writes frontend/data/atlas-fusion.json, atlas-datalake.json and atlas-meta.json.

import { readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "frontend", "data");
const DOCS = "https://docs.sophos.com/central/References/schemas/schemas";

const FRIENDLY = {
  auth: "Sign-ins",
  process: "Processes",
  netflow: "Network connections",
  dnsquery: "DNS lookups",
  filemod: "Files changed",
  alert: "Detections",
  investigations: "Cases",
  email: "Email",
  http: "Web requests",
  generic: "Third-party logs (unparsed)",
  cloudaudit: "Cloud audit",
  agentdetection: "Agent detections",
  antivirus: "Antivirus",
  apicall: "API calls",
  dhcp: "DHCP",
  encrypt: "Encrypted sessions",
  detectionfinding: "Detection findings",
  identityfinding: "Identity findings",
  managementevent: "Management events",
  nids: "Network intrusion",
  persistence: "Persistence",
  processmodule: "Loaded modules",
  registry: "Registry changes",
  scriptblock: "Script blocks",
  thread: "Remote threads",
  filecontent: "File content",
  fileshare: "File shares",
  patchstate: "Patch state",
  softwareinfo: "Installed software",
  systeminfo: "System info",
  scheduledtask: "Scheduled tasks",
};

const ENTITY_FIELDS = new Set(["host_id", "sensor_id", "tenant_id", "resource_id", "event_time_usec", "process_correlation_id", "parent_process_correlation_id", "username", "user_name", "source_address", "destination_address", "hostname", "sensor_type"]);
const OLD_NAMES = /\b(taegis|redcloak|red cloak|isensor)\b/i;

function cleanTitle(title, name) {
  const t = String(title ?? name).replace(/\bTaegis\s+/gi, "").trim();
  return t || name;
}

function flatten(fields, prefix = "", depth = 0, out = []) {
  for (const f of fields ?? []) {
    const p = prefix ? `${prefix}.${f.name}` : f.name;
    const entry = {
      n: p,
      d: (f.description ?? "").trim(),
      t: f.type ?? "",
      s: !!f.searchable,
      a: !!f.aggregatable,
      r: !!f.repeated,
      k: depth,
    };
    if (Array.isArray(f.values) && f.values.length) entry.v = f.values.slice(0, 40).map((v) => (typeof v === "string" ? v : (v?.name ?? v?.value ?? JSON.stringify(v))));
    if (OLD_NAMES.test(entry.d)) entry.o = 1;
    out.push(entry);
    if (f.child?.fields && depth < 1) flatten(f.child.fields, p, depth + 1, out);
  }
  return out;
}

function buildFusion(file) {
  const raw = JSON.parse(readFileSync(file, "utf8"));
  const map = raw.data?.qlSchemaMapV1 ?? raw.qlSchemaMapV1 ?? raw;
  const types = map.types ?? {};
  const schemas = [];
  let version = null;
  let top = 0;
  let all = 0;
  let described = 0;
  let oldNames = 0;
  for (const [name, t] of Object.entries(types).sort((a, b) => a[0].localeCompare(b[0]))) {
    version = version ?? t.version ?? null;
    const fields = flatten(t.fields);
    top += (t.fields ?? []).length;
    all += fields.length;
    described += fields.filter((f) => f.d).length;
    oldNames += fields.filter((f) => f.o).length;
    schemas.push({
      name,
      title: cleanTitle(t.title, name),
      friendly: FRIENDLY[name] ?? cleanTitle(t.title, name),
      category: t.category ?? "EVENTS",
      description: (t.description ?? "").replace(/\bTaegis\s+/gi, "").trim(),
      fields,
    });
  }
  // Which schemas share a field name: the joins a person can make.
  const shared = {};
  for (const s of schemas) for (const f of s.fields) if (f.k === 0) (shared[f.n] ??= []).push(s.name);
  const joins = Object.fromEntries(Object.entries(shared).filter(([n, list]) => list.length >= 3 || ENTITY_FIELDS.has(n)).map(([n, list]) => [n, list]));
  const logical = (map.logical_fields ?? []).map((l) => ({ name: l.name, description: (l.description ?? "").trim(), type: l.type ?? "" }));
  return { schemas, joins, logical, version, stats: { schemas: schemas.length, topLevelFields: top, fields: all, described, oldNames } };
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { "User-Agent": "secops-toolkit-atlas-build" } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

function strip(html) {
  return String(html ?? "")
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

async function buildDataLake(dir) {
  const read = async (name) => {
    if (dir && existsSync(path.join(dir, `${name}.json`))) return JSON.parse(readFileSync(path.join(dir, `${name}.json`), "utf8"));
    return fetchJson(`${DOCS}/${name}.json`);
  };
  const index = await read("schemas");
  const groups = [];
  let tables = 0;
  let columns = 0;
  let described = 0;
  for (const group of index) {
    if (group.type !== "Data Lake") continue;
    for (const entry of group.schemas ?? []) {
      if (!entry.schemaName || /^https?:/.test(entry.schemaName)) continue;
      let data;
      try {
        data = await read(entry.schemaName);
      } catch (err) {
        console.warn(`skip ${entry.schemaName}: ${err.message}`);
        continue;
      }
      const list = (Array.isArray(data) ? data : []).map((t) => ({
        name: t.name,
        description: strip(t.description),
        platforms: t.platforms ?? [],
        columns: (t.columns ?? []).map((c) => ({ n: c.name, t: c.type ?? "", d: strip(c.description) })),
      }));
      tables += list.length;
      for (const t of list) {
        columns += t.columns.length;
        described += t.columns.filter((c) => c.d).length;
      }
      groups.push({ name: entry.name, schema: entry.schemaName, tables: list });
    }
  }
  return { groups, stats: { groups: groups.length, tables, columns, described } };
}

const [fusionFile, legacyDir] = process.argv.slice(2);
if (!fusionFile) {
  console.error("Usage: node scripts/build-atlas.mjs <qlSchemaMapV1.json> [legacy-schemas-dir]");
  process.exit(2);
}
const snapshotDate = new Date(statSync(fusionFile).mtime).toISOString().slice(0, 10);
const fusion = buildFusion(fusionFile);
const lake = await buildDataLake(legacyDir);
writeFileSync(path.join(OUT, "atlas-fusion.json"), JSON.stringify({ source: "Sophos Fusion GraphQL qlSchemaMapV1 (undocumented; schema metadata only)", snapshot: snapshotDate, version: fusion.version, logical: fusion.logical, joins: fusion.joins, schemas: fusion.schemas }));
writeFileSync(path.join(OUT, "atlas-datalake.json"), JSON.stringify({ source: `${DOCS}/schemas.json (public)`, snapshot: new Date().toISOString().slice(0, 10), groups: lake.groups }));
writeFileSync(path.join(OUT, "atlas-meta.json"), JSON.stringify({ fusion: { snapshot: snapshotDate, version: fusion.version, ...fusion.stats }, datalake: { snapshot: new Date().toISOString().slice(0, 10), ...lake.stats } }, null, 2) + "\n");
console.log("fusion", JSON.stringify(fusion.stats), "datalake", JSON.stringify(lake.stats));
