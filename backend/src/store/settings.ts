/**
 * Settings that hold nothing secret: which credential is active, the local
 * case targets (the Sophos APIs carry no SLA field), the wall playlist, and
 * display options. data/settings.json.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { dataDir, writeFileAtomic } from "./paths.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Settings {
  activeCredentialId: string | null;
  /** Demo mode: fictional data, no Sophos calls. */
  demo: boolean;
  demoContext: "partner" | "tenant";
  /** Case targets in hours, per severity. Set here because no Sophos API has them. */
  targets: Record<Severity, number>;
  wall: { seconds: number; playlist: string[] };
  /** Hide tenant names, hostnames, user names and case titles (lobby screens). */
  privacy: boolean;
}

export const VIEWS = ["front", "now", "cases", "endpoints", "msp", "signins", "sources", "ai", "atlas"] as const;

export const DEFAULT_SETTINGS: Settings = {
  activeCredentialId: null,
  demo: false,
  demoContext: "partner",
  targets: { critical: 8, high: 48, medium: 120, low: 240, info: 336 },
  wall: { seconds: 120, playlist: ["front", "msp", "now", "cases", "endpoints", "signins", "sources", "ai"] },
  privacy: false,
};

let current: Settings | null = null;

function settingsPath(): string {
  return path.join(dataDir(), "settings.json");
}

function clampHours(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n <= 24 * 90 ? Math.round(n * 10) / 10 : fallback;
}

export function normaliseSettings(raw: Partial<Settings> | null | undefined): Settings {
  const base = structuredClone(DEFAULT_SETTINGS);
  if (!raw || typeof raw !== "object") return base;
  const targets = { ...base.targets };
  for (const sev of Object.keys(targets) as Severity[]) targets[sev] = clampHours(raw.targets?.[sev], targets[sev]);
  const playlist = Array.isArray(raw.wall?.playlist)
    ? raw.wall!.playlist.filter((v): v is string => typeof v === "string" && (VIEWS as readonly string[]).includes(v))
    : base.wall.playlist;
  const seconds = Number(raw.wall?.seconds);
  return {
    activeCredentialId: typeof raw.activeCredentialId === "string" ? raw.activeCredentialId : null,
    demo: raw.demo === true,
    demoContext: raw.demoContext === "tenant" ? "tenant" : "partner",
    targets,
    wall: { seconds: Number.isFinite(seconds) && seconds >= 10 && seconds <= 3600 ? Math.round(seconds) : base.wall.seconds, playlist: playlist.length ? playlist : base.wall.playlist },
    privacy: raw.privacy === true,
  };
}

export async function loadSettings(): Promise<Settings> {
  try {
    current = normaliseSettings(JSON.parse(await fs.readFile(settingsPath(), "utf8")) as Partial<Settings>);
  } catch {
    current = structuredClone(DEFAULT_SETTINGS);
  }
  return current;
}

export function getSettings(): Settings {
  return current ?? structuredClone(DEFAULT_SETTINGS);
}

export async function saveSettings(patch: Partial<Settings>): Promise<Settings> {
  const merged = normaliseSettings({ ...getSettings(), ...patch, targets: { ...getSettings().targets, ...(patch.targets ?? {}) }, wall: { ...getSettings().wall, ...(patch.wall ?? {}) } });
  current = merged;
  await writeFileAtomic(settingsPath(), JSON.stringify(merged, null, 2) + "\n");
  return merged;
}
