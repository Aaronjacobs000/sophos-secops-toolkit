/**
 * AES-256-GCM with keys kept in files outside the data folder (see paths.ts).
 * A key file is created on first use with mode 0600 in a 0700 folder, and
 * never overwritten by a second writer ("wx").
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import { ensurePrivateDir, keyDir } from "./paths.js";

export const KEY_BYTES = 32;

export interface SealedBox {
  iv: string;
  tag: string;
  data: string;
}

/** The key file is not a 256-bit key, or a box was tampered with or sealed under another key. */
export class UnreadableError extends Error {}

export function keyFile(name: string): string {
  return path.join(keyDir(), `${name}.key`);
}

function decodeKey(text: string): Buffer {
  const key = Buffer.from(text.trim(), "base64");
  if (key.length !== KEY_BYTES) throw new UnreadableError(`The key file is not a 256-bit key.`);
  return key;
}

/** Reads the named key, creating it the first time. */
export async function loadOrCreateKey(name: string): Promise<Buffer> {
  const file = keyFile(name);
  try {
    return decodeKey(await fs.readFile(file, "utf8"));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  await ensurePrivateDir(path.dirname(file));
  try {
    await fs.writeFile(file, randomBytes(KEY_BYTES).toString("base64") + "\n", { mode: 0o600, flag: "wx" });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
  return decodeKey(await fs.readFile(file, "utf8"));
}

/** Deletes the named key, so everything sealed under it can never be read again. */
export async function destroyKey(name: string): Promise<void> {
  await fs.rm(keyFile(name), { force: true });
}

export function seal(key: Buffer, plaintext: Buffer | string, aad?: string): SealedBox {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, "utf8"));
  const data = Buffer.concat([cipher.update(typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext), cipher.final()]);
  return { iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
}

export function open(key: Buffer, box: SealedBox, aad?: string): Buffer {
  try {
    // A full 16-byte tag only: without authTagLength, GCM accepts a tag cut to 4 bytes.
    const tag = Buffer.from(box.tag, "base64");
    if (tag.length !== 16) throw new Error("short tag");
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "base64"), { authTagLength: 16 });
    if (aad) decipher.setAAD(Buffer.from(aad, "utf8"));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(box.data, "base64")), decipher.final()]);
  } catch {
    throw new UnreadableError("The encrypted data can't be read with this key.");
  }
}

/** A stable ID for a value that does not reveal the value. */
export function keyedId(key: Buffer, text: string, length = 32): string {
  return createHmac("sha256", key).update(text).digest("hex").slice(0, length);
}
