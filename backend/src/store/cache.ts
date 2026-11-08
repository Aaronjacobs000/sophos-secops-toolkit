/**
 * The encrypted on-disk cache: data/cache.db, SQLite through node:sqlite.
 *
 * Every row is gzipped and sealed with AES-256-GCM under the cache key
 * (keys/cache.key, outside data/). Row keys are an HMAC of the logical key
 * ("endpoints:<tenant id>"), so the file reveals neither tenant IDs nor what
 * is cached; the logical key is also the associated data, so a row can't be
 * moved under another key. Only the fetch time is stored in the clear, which
 * retention needs.
 *
 * Two tables: `latest` holds the newest value per key; `snapshots` holds a
 * dated series (daily endpoint summaries, case status per refresh) for the
 * trends and time-in-status the Sophos APIs don't provide. Rows older than the
 * retention period (30 days by default) are pruned. wipe() deletes every row,
 * compacts the file and destroys the key, so even a backup of the old file
 * can't be read.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { DatabaseSync } from "node:sqlite";
import { dataDir, ensurePrivateDir } from "./paths.js";
import { destroyKey, keyedId, loadOrCreateKey, open, seal } from "./crypto.js";

const KEY_NAME = "cache";
const DAY_MS = 86_400_000;

export interface CacheHit<T> {
  value: T;
  fetchedAt: number;
}

export interface Snapshot<T> {
  takenAt: number;
  value: T;
}

export class EncryptedCache {
  private db: DatabaseSync | null = null;
  private key: Buffer | null = null;
  private memo = new Map<string, CacheHit<unknown>>();

  constructor(
    private file: string = path.join(dataDir(), "cache.db"),
    private retentionDays: number = Number(process.env.SECOPS_CACHE_DAYS ?? 30) || 30,
  ) {}

  get path(): string {
    return this.file;
  }

  async open(): Promise<void> {
    if (this.db) return;
    await ensurePrivateDir(path.dirname(this.file));
    this.key = await loadOrCreateKey(KEY_NAME);
    this.db = new DatabaseSync(this.file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS latest (k TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, box TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT NOT NULL, taken_at INTEGER NOT NULL, box TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS snapshots_k_taken ON snapshots (k, taken_at);
    `);
    await fs.chmod(this.file, 0o600).catch(() => undefined);
  }

  close(): void {
    this.db?.close();
    this.db = null;
    this.memo.clear();
  }

  private ready(): { db: DatabaseSync; key: Buffer } {
    if (!this.db || !this.key) throw new Error("The cache is not open.");
    return { db: this.db, key: this.key };
  }

  private rowKey(key: Buffer, logical: string): string {
    return keyedId(key, logical, 40);
  }

  private sealValue(key: Buffer, logical: string, value: unknown): string {
    return JSON.stringify(seal(key, gzipSync(Buffer.from(JSON.stringify(value), "utf8")), logical));
  }

  private openValue<T>(key: Buffer, logical: string, box: string): T {
    return JSON.parse(gunzipSync(open(key, JSON.parse(box), logical)).toString("utf8")) as T;
  }

  put<T>(logical: string, value: T, fetchedAt = Date.now()): void {
    const { db, key } = this.ready();
    db.prepare("INSERT INTO latest (k, fetched_at, box) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET fetched_at = excluded.fetched_at, box = excluded.box").run(
      this.rowKey(key, logical),
      fetchedAt,
      this.sealValue(key, logical, value),
    );
    this.memo.set(logical, { value, fetchedAt });
  }

  get<T>(logical: string): CacheHit<T> | null {
    const hit = this.memo.get(logical);
    if (hit) return hit as CacheHit<T>;
    const { db, key } = this.ready();
    const row = db.prepare("SELECT fetched_at, box FROM latest WHERE k = ?").get(this.rowKey(key, logical)) as
      | { fetched_at: number; box: string }
      | undefined;
    if (!row) return null;
    try {
      const value = this.openValue<T>(key, logical, row.box);
      const result = { value, fetchedAt: Number(row.fetched_at) };
      this.memo.set(logical, result);
      return result;
    } catch {
      return null;
    }
  }

  snapshot<T>(logical: string, value: T, takenAt = Date.now()): void {
    const { db, key } = this.ready();
    db.prepare("INSERT INTO snapshots (k, taken_at, box) VALUES (?, ?, ?)").run(this.rowKey(key, logical), takenAt, this.sealValue(key, logical, value));
  }

  snapshots<T>(logical: string, sinceMs = 0): Snapshot<T>[] {
    const { db, key } = this.ready();
    const rows = db
      .prepare("SELECT taken_at, box FROM snapshots WHERE k = ? AND taken_at >= ? ORDER BY taken_at ASC")
      .all(this.rowKey(key, logical), sinceMs) as Array<{ taken_at: number; box: string }>;
    const out: Snapshot<T>[] = [];
    for (const row of rows) {
      try {
        out.push({ takenAt: Number(row.taken_at), value: this.openValue<T>(key, logical, row.box) });
      } catch {
        // A row sealed under an older key is skipped.
      }
    }
    return out;
  }

  /** Deletes rows older than the retention period. Returns how many went. */
  prune(now = Date.now()): number {
    const { db } = this.ready();
    const cutoff = now - this.retentionDays * DAY_MS;
    const a = db.prepare("DELETE FROM latest WHERE fetched_at < ?").run(cutoff);
    const b = db.prepare("DELETE FROM snapshots WHERE taken_at < ?").run(cutoff);
    for (const [k, v] of this.memo) if (v.fetchedAt < cutoff) this.memo.delete(k);
    return Number(a.changes) + Number(b.changes);
  }

  counts(): { latest: number; snapshots: number } {
    const { db } = this.ready();
    const a = db.prepare("SELECT COUNT(*) AS n FROM latest").get() as { n: number };
    const b = db.prepare("SELECT COUNT(*) AS n FROM snapshots").get() as { n: number };
    return { latest: Number(a.n), snapshots: Number(b.n) };
  }

  /**
   * Deletes everything: every row, then the file is compacted so the deleted
   * pages are overwritten, then the key is destroyed and a new one made.
   */
  async wipe(): Promise<void> {
    const { db } = this.ready();
    db.exec("DELETE FROM latest; DELETE FROM snapshots;");
    db.exec("VACUUM;");
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    this.memo.clear();
    await destroyKey(KEY_NAME);
    this.key = await loadOrCreateKey(KEY_NAME);
  }

  get retention(): number {
    return this.retentionDays;
  }
}
