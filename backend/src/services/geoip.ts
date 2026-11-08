/**
 * Optional local IP geolocation from DB-IP City Lite (CC BY 4.0,
 * https://db-ip.com). Not bundled in git: the person downloads it from the
 * setup screen, or drops a dbip-city-lite-*.mmdb file in data/geoip/. Sophos's
 * own geolocation (xdr_ioc_view) is always tried first. MaxMind GeoLite is not
 * used: its licence needs an account and restricts redistribution.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { Reader, type CityResponse } from "mmdb-lib";
import { dataDir, ensurePrivateDir } from "../store/paths.js";
import type { GeoPoint } from "../data/types.js";
import type { FetchLike } from "../vendor/sophos-core/index.js";
import { log } from "../log.js";

type CityRecord = CityResponse;

let reader: Reader<CityRecord> | null = null;
let loadedFrom: string | null = null;
let loading: Promise<void> | null = null;

function geoDir(): string {
  return path.join(dataDir(), "geoip");
}

async function findFile(): Promise<string | null> {
  try {
    const files = (await fs.readdir(geoDir())).filter((f) => /^dbip-city-lite.*\.mmdb$/i.test(f)).sort();
    return files.length ? path.join(geoDir(), files[files.length - 1]!) : null;
  } catch {
    return null;
  }
}

export async function loadGeoIp(): Promise<void> {
  if (loading) return loading;
  loading = (async () => {
    const file = await findFile();
    if (!file || file === loadedFrom) return;
    try {
      reader = new Reader<CityRecord>(await fs.readFile(file));
      loadedFrom = file;
      log.emit("info", "geoip", `DB-IP City Lite loaded (${path.basename(file)})`);
    } catch (err) {
      reader = null;
      log.emit("warn", "geoip", `DB-IP file could not be read: ${err instanceof Error ? err.message : String(err)}`);
    }
  })().finally(() => {
    loading = null;
  });
  return loading;
}

export function geoIpStatus(): { installed: boolean; file: string | null; attribution: string } {
  return { installed: !!reader, file: loadedFrom ? path.basename(loadedFrom) : null, attribution: "IP geolocation by DB-IP (db-ip.com), CC BY 4.0" };
}

/** True for an address that can be placed: not private, loopback, link-local or shared. */
export function isPublicIp(ip: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return ip.includes(":") && !/^(fe80|fc|fd|::1)/i.test(ip);
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10 || a === 127 || a === 0 || a >= 224) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

export async function lookupIp(ip: string): Promise<GeoPoint | null> {
  if (!reader || !isPublicIp(ip)) return null;
  try {
    const hit = reader.get(ip);
    const lat = hit?.location?.latitude;
    const lon = hit?.location?.longitude;
    if (typeof lat !== "number" || typeof lon !== "number") return null;
    return { city: (hit?.city?.names as Record<string, string> | undefined)?.en ?? null, country: (hit?.country?.names as Record<string, string> | undefined)?.en ?? hit?.country?.iso_code ?? null, lat, lon, source: "dbip" };
  } catch {
    return null;
  }
}

/** The current month's file name, falling back to last month's when the new one isn't out yet. */
export function dbipFileNames(now = new Date()): string[] {
  const fmt = (d: Date) => `dbip-city-lite-${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}.mmdb.gz`;
  const prev = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
  return [fmt(now), fmt(prev)];
}

/** Downloads DB-IP City Lite (about 60 MB compressed) through the guarded transport. */
export async function downloadDbIp(fetchImpl: FetchLike): Promise<string> {
  let lastStatus = 0;
  for (const name of dbipFileNames()) {
    const response = await fetchImpl(`https://download.db-ip.com/free/${name}`, { method: "GET" });
    lastStatus = response.status;
    if (!response.ok) continue;
    const gz = Buffer.from(await response.arrayBuffer());
    const mmdb = gunzipSync(gz);
    new Reader<CityRecord>(mmdb);
    await ensurePrivateDir(geoDir());
    const file = path.join(geoDir(), name.replace(/\.gz$/, ""));
    await fs.writeFile(file, mmdb);
    for (const f of await fs.readdir(geoDir())) {
      if (f !== path.basename(file) && /^dbip-city-lite.*\.mmdb$/i.test(f)) await fs.rm(path.join(geoDir(), f), { force: true });
    }
    loadedFrom = null;
    await loadGeoIp();
    return path.basename(file);
  }
  throw new Error(`DB-IP download failed (HTTP ${lastStatus}).`);
}
