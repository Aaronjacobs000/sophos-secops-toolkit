// Times follow the viewer, not the computer the toolkit was written on. The
// screens use the browser's zone; a report uses the zone the browser sent,
// or the computer's when none comes (a headless run). Node applies a change
// to process.env.TZ at once, so each test sets the zone it needs.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const root = mkdtempSync(path.join(tmpdir(), "secops-tz-"));
process.env.SECOPS_DATA_DIR = path.join(root, "data");
process.env.SECOPS_KEY_DIR = path.join(root, "keys");

const { setQuiet } = await import("../backend/dist/log.js");
setQuiet(true);
const ui = await import("../frontend/js/format.js");
const { formatCalendarDate, formatDate, hourLabel, serverTimeZone } = await import("../backend/dist/reports/format.js");
const { buckets } = await import("../backend/dist/reports/builders/series.js");
const { checkRequest, runReport } = await import("../backend/dist/reports/runner.js");
const { DemoReportSource } = await import("../backend/dist/reports/demo.js");
const { DemoProvider } = await import("../backend/dist/demo/demo-provider.js");
const { DEFAULT_SETTINGS } = await import("../backend/dist/store/settings.js");

const ORIGINAL_TZ = process.env.TZ;
function inZone(tz, fn) {
  process.env.TZ = tz;
  try {
    return fn();
  } finally {
    if (ORIGINAL_TZ === undefined) delete process.env.TZ;
    else process.env.TZ = ORIGINAL_TZ;
  }
}

// 03:05 UTC on 9 Nov 2026: still 8 Nov in the Americas, already afternoon in Sydney.
const AT = Date.parse("2026-11-09T03:05:00Z");

test("the screens show the viewer's own time and date, wherever they are", () => {
  const seen = {};
  for (const tz of ["America/Los_Angeles", "Europe/London", "Asia/Kolkata", "Australia/Sydney"]) {
    seen[tz] = inZone(tz, () => ({ date: ui.date(AT), clock: ui.clock(AT), when: ui.dateTime(AT), day: ui.weekday(AT), greet: ui.greeting(AT) }));
  }
  assert.deepEqual(seen["America/Los_Angeles"], { date: "8 Nov 2026", clock: "19:05", when: "8 Nov 2026 19:05", day: "Sun", greet: "Good evening" });
  assert.deepEqual(seen["Europe/London"], { date: "9 Nov 2026", clock: "03:05", when: "9 Nov 2026 03:05", day: "Mon", greet: "Good morning" });
  assert.deepEqual(seen["Asia/Kolkata"], { date: "9 Nov 2026", clock: "08:35", when: "9 Nov 2026 08:35", day: "Mon", greet: "Good morning" });
  assert.deepEqual(seen["Australia/Sydney"], { date: "9 Nov 2026", clock: "14:05", when: "9 Nov 2026 14:05", day: "Mon", greet: "Good afternoon" });
});

test("screen dates name the month, so a day and a month can't swap", () => {
  inZone("Europe/London", () => {
    assert.equal(ui.date(Date.parse("2026-03-11T12:00:00Z")), "11 Mar 2026");
    assert.equal(ui.date(Date.parse("2026-11-03T12:00:00Z")), "3 Nov 2026");
    assert.equal(ui.date("2026-11-03T12:00:00Z"), "3 Nov 2026", "an ISO timestamp string works too");
    assert.equal(ui.date(null), "-");
    assert.equal(ui.date("not a date"), "-");
    assert.equal(ui.clock(Date.parse("2026-11-09T00:05:09Z"), true), "00:05:09", "midnight is 00, not 24");
  });
});

test("a calendar day from the API is the same day on screen in every zone", () => {
  for (const tz of ["America/Los_Angeles", "Pacific/Honolulu", "UTC", "Pacific/Kiritimati"]) {
    inZone(tz, () => {
      assert.equal(ui.date("2031-03-27"), "27 Mar 2031", `${tz}: a licence end or snapshot day`);
      assert.equal(ui.date("2026-01-01"), "1 Jan 2026", tz);
    });
  }
});

test("a report's calendar days stay put west of UTC, and its timestamps move with the zone", () => {
  assert.equal(formatCalendarDate("2027-01-01", "America/Los_Angeles"), "1 Jan 2027");
  assert.equal(formatCalendarDate("2027-01-01", "Pacific/Kiritimati"), "1 Jan 2027");
  assert.equal(formatCalendarDate(null, "UTC"), "-");
  assert.equal(formatCalendarDate("2026-11-09T03:05:00Z", "America/Los_Angeles"), "8 Nov 2026", "a full timestamp is still formatted in the zone");
  assert.equal(formatDate(Date.parse("2027-01-01"), "America/Los_Angeles"), "31 Dec 2026", "which is why a calendar day must not go through Date.parse");
});

test("hour labels show the real local start of each hour in half-hour zones", () => {
  const hour = Date.parse("2026-11-09T03:00:00Z");
  assert.equal(hourLabel(hour, "UTC"), "03:00");
  assert.equal(hourLabel(hour, "Australia/Sydney"), "14:00");
  assert.equal(hourLabel(hour, "Asia/Kolkata"), "08:30");
  assert.equal(hourLabel(hour, "Australia/Adelaide"), "13:30");
  assert.equal(hourLabel(hour, "Asia/Kathmandu"), "08:45");
  const b = buckets({ start: hour, end: hour + 3 * 3_600_000, hours: 3 }, "Asia/Kolkata");
  assert.deepEqual(b.labels, ["08:30", "09:30", "10:30"]);
});

test("the endpoint report prints each licence's end day as the API sends it, in a zone west of UTC", async () => {
  const provider = new DemoProvider("tenant");
  try {
    const checked = checkRequest(provider, { reportId: "endpoints", timeZone: "America/Los_Angeles" });
    const doc = await runReport(checked, { source: new DemoReportSource(provider), settings: DEFAULT_SETTINGS });
    assert.equal(doc.timeZone, "America/Los_Angeles");
    const raw = (provider.get("licences", checked.tenant) ?? []).map((l) => l.endDate).filter(Boolean);
    assert.ok(raw.length, "the demo tenant has licences with end days");
    const table = doc.sections.flatMap((s) => s.blocks).find((b) => b.kind === "table" && b.id === "licences");
    const printed = table.rows.map((r) => r.ends).sort();
    const expected = raw.map((d) => {
      const [y, m, day] = d.split("-").map(Number);
      return `${day} ${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][m - 1]} ${y}`;
    }).sort();
    assert.deepEqual(printed, expected);
  } finally {
    provider.stop();
  }
});

test("a report run with no zone, or a zone it doesn't know, uses the computer's zone", () => {
  inZone("America/New_York", () => {
    assert.equal(serverTimeZone(), "America/New_York");
    const provider = new DemoProvider("tenant");
    try {
      assert.equal(checkRequest(provider, { reportId: "endpoints" }).timeZone, "America/New_York");
      assert.equal(checkRequest(provider, { reportId: "endpoints", timeZone: "Not/AZone" }).timeZone, "America/New_York");
      assert.equal(checkRequest(provider, { reportId: "endpoints", timeZone: "Europe/Berlin" }).timeZone, "Europe/Berlin", "the browser's zone wins when it sends one");
    } finally {
      provider.stop();
    }
  });
});
