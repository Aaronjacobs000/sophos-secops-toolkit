/**
 * The encrypted credential vault. data/credentials.json holds one entry per
 * Sophos API credential. The client ID and secret of each are sealed with
 * AES-256-GCM under the vault key (keys/credentials.key, outside data/), with
 * the entry ID as associated data so an entry can't be swapped for another.
 * Labels and the detected context (tenant, partner or organization) stay
 * readable: they hold nothing secret and the setup screen lists them.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { dataDir, writeFileAtomic } from "./paths.js";
import { loadOrCreateKey, open, seal, type SealedBox } from "./crypto.js";
import { registerSecret } from "../log.js";

export type CredentialKind = "tenant" | "partner" | "organization";

export interface StoredCredential {
  id: string;
  label: string;
  kind: CredentialKind;
  /** Last four characters of the client ID, so a person can tell two apart. */
  hint: string;
  createdAt: string;
  box: SealedBox;
}

export interface CredentialSummary {
  id: string;
  label: string;
  kind: CredentialKind;
  hint: string;
  createdAt: string;
}

export interface Secret {
  clientId: string;
  clientSecret: string;
}

interface VaultFile {
  version: 1;
  entries: StoredCredential[];
}

const KEY_NAME = "credentials";

function vaultPath(): string {
  return path.join(dataDir(), "credentials.json");
}

async function readVault(): Promise<VaultFile> {
  try {
    const parsed = JSON.parse(await fs.readFile(vaultPath(), "utf8")) as VaultFile;
    return { version: 1, entries: Array.isArray(parsed.entries) ? parsed.entries : [] };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, entries: [] };
    throw new Error("The credential vault (data/credentials.json) can't be read.");
  }
}

async function writeVault(vault: VaultFile): Promise<void> {
  await writeFileAtomic(vaultPath(), JSON.stringify(vault, null, 2) + "\n");
}

function summary(entry: StoredCredential): CredentialSummary {
  const { box: _box, ...rest } = entry;
  return rest;
}

export async function listCredentials(): Promise<CredentialSummary[]> {
  return (await readVault()).entries.map(summary);
}

export async function addCredential(input: { label: string; kind: CredentialKind } & Secret): Promise<CredentialSummary> {
  const key = await loadOrCreateKey(KEY_NAME);
  const vault = await readVault();
  const id = randomUUID();
  const entry: StoredCredential = {
    id,
    label: input.label.trim().slice(0, 80) || "Sophos credential",
    kind: input.kind,
    hint: input.clientId.trim().slice(-4),
    createdAt: new Date().toISOString(),
    box: seal(key, JSON.stringify({ clientId: input.clientId.trim(), clientSecret: input.clientSecret.trim() }), id),
  };
  vault.entries.push(entry);
  await writeVault(vault);
  return summary(entry);
}

export async function removeCredential(id: string): Promise<boolean> {
  const vault = await readVault();
  const before = vault.entries.length;
  vault.entries = vault.entries.filter((e) => e.id !== id);
  if (vault.entries.length === before) return false;
  await writeVault(vault);
  return true;
}

export async function renameCredential(id: string, label: string): Promise<boolean> {
  const vault = await readVault();
  const entry = vault.entries.find((e) => e.id === id);
  if (!entry) return false;
  entry.label = label.trim().slice(0, 80) || entry.label;
  await writeVault(vault);
  return true;
}

/** The secret for one entry. Registered with the logger so neither half can ever reach a log line. */
export async function readSecret(id: string): Promise<{ summary: CredentialSummary; secret: Secret } | null> {
  const vault = await readVault();
  const entry = vault.entries.find((e) => e.id === id);
  if (!entry) return null;
  const key = await loadOrCreateKey(KEY_NAME);
  const secret = JSON.parse(open(key, entry.box, entry.id).toString("utf8")) as Secret;
  registerSecret(secret.clientId);
  registerSecret(secret.clientSecret);
  return { summary: summary(entry), secret };
}
