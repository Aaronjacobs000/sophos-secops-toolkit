/**
 * Where the toolkit keeps its files. Data (the encrypted credential vault, the
 * encrypted cache and settings) sits in SECOPS_DATA_DIR, by default data/ in
 * the repo. The encryption keys sit apart from it, in SECOPS_KEY_DIR, by
 * default ~/.secops-toolkit, so copying or syncing data/ exposes nothing.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";

let repoRoot = process.cwd();

export function setRepoRoot(root: string): void {
  repoRoot = root;
}

export function getRepoRoot(): string {
  return repoRoot;
}

export function dataDir(): string {
  const override = process.env.SECOPS_DATA_DIR?.trim();
  return override ? path.resolve(override) : path.join(repoRoot, "data");
}

export function keyDir(): string {
  const override = process.env.SECOPS_KEY_DIR?.trim();
  return override ? path.resolve(override) : path.join(os.homedir(), ".secops-toolkit");
}

export async function ensurePrivateDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
}

/** Write a whole file through a temp file and a rename, so a crash never leaves half a file. */
export async function writeFileAtomic(file: string, contents: string | Buffer, mode = 0o600): Promise<void> {
  await ensurePrivateDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, contents, { mode });
  await fs.rename(tmp, file);
}
