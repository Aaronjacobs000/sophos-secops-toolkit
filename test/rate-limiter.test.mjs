import test from "node:test";
import assert from "node:assert/strict";
import { RateLimiter, PRIORITY } from "../backend/dist/sophos/rate-limiter.js";

/** A fake clock with timers the test advances by hand. */
function clock(start = 1_000_000) {
  let now = start;
  let timers = [];
  return {
    now: () => now,
    setTimer(fn, ms) {
      const t = { at: now + ms, fn };
      timers.push(t);
      return t;
    },
    clearTimer(t) {
      timers = timers.filter((x) => x !== t);
    },
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        timers.sort((a, b) => a.at - b.at);
        const next = timers[0];
        if (!next || next.at > end) break;
        timers.shift();
        now = next.at;
        next.fn();
        await Promise.resolve();
      }
      now = end;
      await new Promise((r) => setImmediate(r));
    },
  };
}

function limiter(c, opts = {}) {
  return new RateLimiter({ perMinute: 80, perHour: 900, now: c.now, setTimer: c.setTimer, clearTimer: c.clearTimer, random: () => 0, ...opts });
}

test("never lets more than the per-minute cap through in any 60 s window", async () => {
  const c = clock();
  const rl = limiter(c);
  let done = 0;
  for (let i = 0; i < 250; i++) rl.acquire().then(() => done++);
  await c.advance(0);
  assert.equal(done, 80, "the first 80 go at once");
  await c.advance(59_000);
  assert.equal(done, 80, "nothing more inside the first minute");
  await c.advance(1_100);
  assert.equal(done, 160);
  await c.advance(240_000);
  assert.equal(done, 250);
  assert.ok(rl.peakPerMinute() <= 80, `peak ${rl.peakPerMinute()} per minute`);
  assert.ok(rl.peakPerMinute() < 100, "always under Sophos's enforced 100 a minute");
});

test("the per-hour cap holds as well", async () => {
  const c = clock();
  const rl = limiter(c, { perMinute: 100, perHour: 150 });
  let done = 0;
  for (let i = 0; i < 200; i++) rl.acquire().then(() => done++);
  await c.advance(30 * 60_000);
  assert.equal(done, 150, "stops at 150 within the hour");
  await c.advance(31 * 60_000);
  assert.equal(done, 200, "resumes once the oldest calls leave the hour");
});

test("waiting calls are served by priority, then in arrival order", async () => {
  const c = clock();
  const rl = limiter(c, { perMinute: 1, perHour: 1000 });
  const order = [];
  await rl.acquire();
  rl.acquire(PRIORITY.background).then(() => order.push("background-1"));
  rl.acquire(PRIORITY.background).then(() => order.push("background-2"));
  rl.acquire(PRIORITY.onScreen).then(() => order.push("on-screen"));
  rl.acquire(PRIORITY.interactive).then(() => order.push("interactive"));
  await c.advance(5 * 60_000);
  assert.deepEqual(order, ["interactive", "on-screen", "background-1", "background-2"]);
});

test("a 429 pauses the whole credential for Retry-After", async () => {
  const c = clock();
  const rl = limiter(c);
  rl.backoff(20);
  let done = false;
  rl.acquire().then(() => (done = true));
  await c.advance(19_000);
  assert.equal(done, false);
  assert.ok(rl.stats().pausedFor > 0);
  await c.advance(2_000);
  assert.equal(done, true);
});

test("without Retry-After it backs off 30 s", async () => {
  const c = clock();
  const rl = limiter(c);
  rl.backoff(null);
  assert.ok(rl.stats().pausedFor >= 30_000);
});

test("stats report the last minute and hour", async () => {
  const c = clock();
  const rl = limiter(c);
  for (let i = 0; i < 10; i++) await rl.acquire();
  await c.advance(61_000);
  for (let i = 0; i < 5; i++) await rl.acquire();
  const s = rl.stats();
  assert.equal(s.lastMinute, 5);
  assert.equal(s.lastHour, 15);
  assert.equal(s.perMinute, 80);
});

test("calls from before a restart still count against the hour", async () => {
  const c = clock();
  const first = limiter(c, { perMinute: 100, perHour: 120 });
  for (let i = 0; i < 100; i++) await first.acquire();
  const saved = first.exportStamps();
  await c.advance(2 * 60_000);
  const second = limiter(c, { perMinute: 100, perHour: 120 });
  second.seedStamps(saved);
  let done = 0;
  for (let i = 0; i < 40; i++) second.acquire().then(() => done++);
  await c.advance(0);
  assert.equal(done, 20, "only the 20 left in the hour go");
  second.seedStamps([c.now() - 2 * 3_600_000]);
  assert.equal(second.stats().lastHour, 120, "stamps older than an hour are ignored");
});

test("the per-minute setting can never exceed Sophos's 100", () => {
  const rl = new RateLimiter({ perMinute: 500 });
  assert.equal(rl.perMinute, 100);
});

test("a budget setting that is not a positive number keeps the default instead of turning limiting off", () => {
  const saved = { m: process.env.SECOPS_RATE_PER_MIN, h: process.env.SECOPS_RATE_PER_HOUR };
  try {
    for (const [m, h] of [["80/min", "900/h"], ["", ""], ["-5", "0"]]) {
      process.env.SECOPS_RATE_PER_MIN = m;
      process.env.SECOPS_RATE_PER_HOUR = h;
      const l = new RateLimiter();
      assert.equal(l.perMinute, 80, JSON.stringify(m));
      assert.equal(l.perHour, 900, JSON.stringify(h));
    }
    process.env.SECOPS_RATE_PER_MIN = "40";
    process.env.SECOPS_RATE_PER_HOUR = "500";
    const set = new RateLimiter();
    assert.deepEqual([set.perMinute, set.perHour], [40, 500]);
  } finally {
    for (const [k, v] of [["SECOPS_RATE_PER_MIN", saved.m], ["SECOPS_RATE_PER_HOUR", saved.h]]) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
});
