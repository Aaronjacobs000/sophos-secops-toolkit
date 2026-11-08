/**
 * One rate limiter per credential, shared by every call that credential makes.
 *
 * Sophos enforces 100 calls a minute per credential (bursts to 300) and
 * recommends no more than 1,000 an hour. The toolkit aims under both: 80 a
 * minute and 900 an hour by default, counted over sliding windows, so no
 * minute ever reaches 100 however the calls bunch up. Waiting calls are served
 * by priority (what is on screen first), then in arrival order. A 429 pauses
 * the whole credential for Retry-After seconds, with jitter, rather than
 * letting every caller retry on its own.
 */

export const PRIORITY = { interactive: 0, onScreen: 1, background: 2 } as const;
export type Priority = (typeof PRIORITY)[keyof typeof PRIORITY];

export interface RateLimiterOptions {
  perMinute?: number;
  perHour?: number;
  now?: () => number;
  /** Timer hooks, replaced by tests to drive a fake clock. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
  random?: () => number;
}

interface Waiter {
  priority: number;
  seq: number;
  resolve: () => void;
}

const MINUTE = 60_000;
const HOUR = 3_600_000;

/** A budget from the environment, or the default when the value is missing, empty or not a positive number ("80/min" would turn limiting off). */
function envBudget(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export class RateLimiter {
  readonly perMinute: number;
  readonly perHour: number;
  private stamps: number[] = [];
  private queue: Waiter[] = [];
  private seq = 0;
  private timer: unknown = null;
  private pausedUntil = 0;
  private now: () => number;
  private setTimer: (fn: () => void, ms: number) => unknown;
  private clearTimer: (handle: unknown) => void;
  private random: () => number;
  /** Calls let through, for the budget meter and the tests. */
  total = 0;
  throttled = 0;

  constructor(options: RateLimiterOptions = {}) {
    this.perMinute = Math.max(1, Math.min(100, options.perMinute ?? envBudget("SECOPS_RATE_PER_MIN", 80)));
    this.perHour = Math.max(1, options.perHour ?? envBudget("SECOPS_RATE_PER_HOUR", 900));
    this.now = options.now ?? Date.now;
    this.setTimer = options.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
    this.clearTimer = options.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>));
    this.random = options.random ?? Math.random;
  }

  /** How long until a call may go, or 0 now. Pure apart from trimming old stamps. */
  waitMs(at = this.now()): number {
    while (this.stamps.length && this.stamps[0]! <= at - HOUR) this.stamps.shift();
    let wait = Math.max(0, this.pausedUntil - at);
    if (this.stamps.length >= this.perHour) {
      wait = Math.max(wait, this.stamps[this.stamps.length - this.perHour]! + HOUR - at);
    }
    const minuteStart = at - MINUTE;
    let inMinute = 0;
    for (let i = this.stamps.length - 1; i >= 0 && this.stamps[i]! > minuteStart; i--) inMinute++;
    if (inMinute >= this.perMinute) {
      const oldest = this.stamps[this.stamps.length - this.perMinute]!;
      wait = Math.max(wait, oldest + MINUTE - at);
    }
    return wait;
  }

  /** Resolves when this call may go. Lower priority numbers go first. */
  acquire(priority: number = PRIORITY.background): Promise<void> {
    return new Promise<void>((resolve) => {
      this.queue.push({ priority, seq: this.seq++, resolve });
      this.queue.sort((a, b) => a.priority - b.priority || a.seq - b.seq);
      this.pump();
    });
  }

  private pump(): void {
    if (this.timer !== null) return;
    while (this.queue.length) {
      const at = this.now();
      const wait = this.waitMs(at);
      if (wait > 0) {
        this.throttled++;
        this.timer = this.setTimer(() => {
          this.timer = null;
          this.pump();
        }, wait + 5);
        return;
      }
      const next = this.queue.shift()!;
      this.stamps.push(at);
      this.total++;
      next.resolve();
    }
  }

  /** Sophos said 429: hold every call on this credential for Retry-After (default 30 s), plus jitter. */
  backoff(retryAfterSeconds?: number | null): void {
    const base = retryAfterSeconds && retryAfterSeconds > 0 ? retryAfterSeconds * 1000 : 30_000;
    const until = this.now() + base + Math.round(this.random() * 2000);
    this.pausedUntil = Math.max(this.pausedUntil, until);
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
    this.pump();
  }

  stats(at = this.now()): { lastMinute: number; lastHour: number; queued: number; pausedFor: number; perMinute: number; perHour: number } {
    this.waitMs(at);
    let lastMinute = 0;
    for (let i = this.stamps.length - 1; i >= 0 && this.stamps[i]! > at - MINUTE; i--) lastMinute++;
    return {
      lastMinute,
      lastHour: this.stamps.length,
      queued: this.queue.length,
      pausedFor: Math.max(0, this.pausedUntil - at),
      perMinute: this.perMinute,
      perHour: this.perHour,
    };
  }

  /** The call times of the last hour, so a restart can carry the hourly budget over. */
  exportStamps(at = this.now()): number[] {
    this.waitMs(at);
    return [...this.stamps];
  }

  /** Seeds the window with calls made before a restart (only the last hour counts). */
  seedStamps(stamps: number[], at = this.now()): void {
    const recent = stamps.filter((t) => Number.isFinite(t) && t > at - HOUR && t <= at).sort((a, b) => a - b);
    this.stamps = [...recent, ...this.stamps].sort((a, b) => a - b);
  }

  /** The most calls in any 60-second window so far, for the tests. */
  peakPerMinute(): number {
    let peak = 0;
    let start = 0;
    for (let end = 0; end < this.stamps.length; end++) {
      while (this.stamps[end]! - this.stamps[start]! >= MINUTE) start++;
      peak = Math.max(peak, end - start + 1);
    }
    return peak;
  }
}
