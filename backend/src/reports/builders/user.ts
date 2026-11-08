/**
 * User investigation: the Sophos version of a SIEM's user page. Who the
 * person is in the Sophos directory, every sign-in the tenant's sources saw
 * (Microsoft 365, VPN and firewall, endpoint logons), where from, on which
 * devices, the detections and cases that name them, and their activity by
 * event type.
 */

import type { CaseRecord, GeoPoint } from "../../data/types.js";
import { failureName, mfaSources, signinKind } from "../../mappers/search.js";
import { sensorLabel } from "../../mappers/views.js";
import { cleanUser } from "../queries.js";
import { schemaLabel } from "../queries.js";
import type { DetectionDetailSet, DirectoryUser, UserActivity, UserSigninRow } from "../data.js";
import { SEVERITIES, SEV_LABEL, cachedAsOf, hostNames, kpi, list, section, table, type BuildContext, type BuiltReport } from "../context.js";
import { dayKey, dayLabel, formatDate, formatNumber, formatPercent, hourLabel, plural } from "../format.js";
import type { Block, ReportSection, Tone } from "../types.js";

/** Sources that are a firewall or VPN gateway, by sensor type or application. */
const VPN_SENSOR = /VPN|SFOS|FORTI|PALOALTO|GLOBALPROTECT|CISCO_FIREWALL|ASA\b|PULSE|NETSCALER|SONICWALL|WATCHGUARD|JUNIPER|CHECKPOINT|ZTNA|ZSCALER|BARRACUDA_FW|PFSENSE/i;
const VPN_APP = /vpn|remote access|anyconnect|globalprotect/i;
const MICROSOFT = /^(MICROSOFT|AZURE|O365|ENTRA)/i;

const LOGON_LABELS: Record<string, string> = {
  INTERACTIVE: "Interactive",
  NONINTERACTIVE: "Non-interactive",
  REMOTEINTERACTIVE: "Remote interactive",
  CACHEDINTERACTIVE: "Cached interactive",
  CACHEDREMOTEINTERACTIVE: "Cached remote interactive",
  CACHEDUNLOCKED: "Cached unlock",
  NETWORK: "Network",
  NETWORKCLEARTEXT: "Network (clear text)",
  NEWCREDENTIALS: "New credentials",
  UNLOCK: "Unlock",
  SERVICE: "Service",
  BATCH: "Batch",
  PROXY: "Proxy",
  SYSTEMONLY: "System",
  UNKNOWN: "Not given",
};

export function logonLabel(t: string): string {
  return LOGON_LABELS[t.toUpperCase()] ?? t.toLowerCase().replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase());
}

export function isVpnRow(r: Pick<UserSigninRow, "sensorType" | "app">): boolean {
  return VPN_SENSOR.test(r.sensorType) || VPN_APP.test(r.app);
}

function errText(err: unknown): string {
  const m = err instanceof Error ? err.message : String(err);
  if (/403|forbidden|denied|not allowed/i.test(m)) return "Sophos refused this read (HTTP 403): the credential's role or the tenant's licence does not cover it.";
  return `Sophos did not answer this read: ${m.slice(0, 200)}`;
}

/** What a source writes when it has no address, such as a Windows logon that failed before one was known. */
const NO_ADDRESS = new Set(["0.0.0.0", "::"]);

function placeOf(ip: string | null, geo: Record<string, GeoPoint>, isPrivate: (ip: string) => boolean): string {
  if (!ip || NO_ADDRESS.has(ip)) return "No address";
  const g = geo[ip];
  if (g) return [g.city, g.country].filter(Boolean).join(", ") || "Placed";
  return isPrivate(ip) ? "Internal address" : "Not placed";
}

function privateIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd|::1$)/i.test(ip);
}

export async function buildUser(ctx: BuildContext): Promise<BuiltReport> {
  const user = cleanUser(ctx.params.user);
  const tenant = ctx.scope.tenants[0]!;
  const tid = tenant.id;
  const window = ctx.window!;
  const tz = ctx.tz;
  const gaps: string[] = [];
  const provenance: BuiltReport["provenance"] = [];
  const fusion = ctx.provider.get("generation", tid)?.generation === "fusion";
  const q = user.toLowerCase();

  ctx.progress("Looking up the Sophos directory");
  let directory: { users: DirectoryUser[]; total: number } | null = null;
  let directoryError: string | null = null;
  try {
    directory = await ctx.source.directory(tid, user);
    provenance.push({ label: "Sophos directory", detail: "Directory API, read for this report", asOf: ctx.now });
  } catch (err) {
    directoryError = errText(err);
  }

  let activity: UserActivity | null = null;
  let activityError: string | null = null;
  if (fusion) {
    ctx.progress("Searching sign-ins and activity (5 searches)");
    try {
      activity = await ctx.source.userActivity(tid, user, window);
      provenance.push({ label: "Sign-ins and activity", detail: `Search GraphQL, ${plural(activity.search.calls, "call")}${activity.search.reused ? ", reusing searches from the last quarter hour" : ""}`, asOf: activity.search.ranAt });
    } catch (err) {
      activityError = errText(err);
    }
  } else {
    gaps.push("Sign-ins, VPN, Microsoft 365 and activity by event type need the tenant on Sophos Fusion (Search GraphQL). This tenant's data is still on the Classic APIs.");
  }

  let detections: DetectionDetailSet | null = null;
  let detectionError: string | null = null;
  if (fusion) {
    ctx.progress("Reading detections that name the user");
    try {
      detections = await ctx.source.detections(tid, window.hours, { kind: "user", value: user });
      provenance.push({ label: "Detections", detail: "Detections v2, read for this report", asOf: ctx.now });
    } catch (err) {
      detectionError = errText(err);
    }
  }

  ctx.progress("Matching cases and devices");
  const caseSet = ctx.provider.get("cases", tid);
  const cases = new Map<string, CaseRecord>();
  for (const c of [...(caseSet?.open ?? []), ...(caseSet?.recentClosed ?? [])]) if (c.title.toLowerCase().includes(q)) cases.set(c.id, c);
  let casesMore = false;
  try {
    const older = await ctx.source.casesByTitle(tid, user);
    if (older) {
      for (const c of older.cases) cases.set(c.id, c);
      casesMore = older.more;
    }
  } catch (err) {
    gaps.push(`Cases older than 30 days: ${errText(err)}`);
  }
  provenance.push({ label: "Cases", detail: fusion ? "Cached cases plus a Cases v2 title search read for this report" : "Cached cases (open, and closed in the last 30 days)", asOf: cachedAsOf(ctx.provider, "cases", [tenant]) });

  const devices = hostNames(ctx.provider, [tid]);
  provenance.push({ label: "Devices", detail: "Endpoint API (cached)", asOf: cachedAsOf(ctx.provider, "endpoints", [tenant]) });

  const signins = activity?.signins ?? [];
  const geo = activity?.geo ?? {};
  // A source reports MFA when this user's sign-ins show it, or when the tenant's own MFA search (the Sign-ins screen's) saw it do so.
  const aware = mfaSources(signins.map((s) => ({ sensorType: s.sensorType, mfaUsed: s.mfa })));
  for (const src of ctx.provider.get("mfa", tid)?.sources ?? []) if (src.reportsMfa) aware.add(src.sensorType);
  const sum = (rows: UserSigninRow[]) => rows.reduce((a, r) => a + r.count, 0);
  const total = sum(signins);
  const failed = sum(signins.filter((s) => s.result === "failed"));
  const counted = signins.filter((s) => s.result === "success" && aware.has(s.sensorType) && signinKind(s.logonType) === "user");
  const withoutMfa = sum(counted.filter((s) => s.mfa === false));
  const places = new Set(signins.filter((s) => s.ip && geo[s.ip]).map((s) => `${geo[s.ip!]!.city}|${geo[s.ip!]!.country}`));

  // Devices: assigned in Sophos, or signed in to in the window.
  const deviceRows = new Map<string, { id: string; how: string[]; count: number; last: number | null }>();
  for (const e of devices.values()) if (e.person && e.person.toLowerCase().includes(q)) deviceRows.set(e.id, { id: e.id, how: ["Assigned to the user in Sophos"], count: 0, last: null });
  for (const s of signins) {
    if (!s.hostId || !devices.has(s.hostId)) continue;
    const d = deviceRows.get(s.hostId) ?? { id: s.hostId, how: [], count: 0, last: null };
    d.count += s.count;
    d.last = Math.max(d.last ?? 0, s.last ?? 0) || null;
    deviceRows.set(s.hostId, d);
  }

  const detItems = detections?.items ?? [];
  const sections: ReportSection[] = [];

  // ------------------------------------------------------------ who
  const who: Block[] = [];
  // The person searched for: a directory user whose email, Exchange login or name is the text, or whose email starts with it.
  const exact = directory?.users.find((u) => [u.email, u.exchangeLogin, u.name].some((v) => v?.toLowerCase() === q) || u.email?.toLowerCase().split("@")[0] === q) ?? null;
  const best = exact ?? directory?.users[0] ?? null;
  if (best) {
    who.push({
      kind: "facts",
      title: exact ? "Sophos directory record" : directory!.total === 1 ? `The Sophos directory user matching "${user}"` : `First of ${formatNumber(directory!.total)} Sophos directory users matching "${user}"`,
      items: [
        { label: "Name", value: best.name },
        { label: "Email", value: best.email ?? "-" },
        { label: "Exchange login", value: best.exchangeLogin ?? "-" },
        { label: "Directory source", value: best.domain ? `${best.source} (${best.domain})` : best.source },
        { label: "Groups", value: best.groups === null ? "-" : formatNumber(best.groups) },
        { label: "Added to Sophos", value: best.createdAt ? formatDate(Date.parse(best.createdAt), tz) : "-" },
        { label: "Last changed", value: best.updatedAt ? formatDate(Date.parse(best.updatedAt), tz) : "-" },
      ],
    });
  } else if (directoryError) {
    who.push({ kind: "note", tone: "gap", text: `Sophos directory: ${directoryError}` });
  } else {
    who.push({ kind: "note", tone: "info", text: `No Sophos directory user matches "${user}". The report searched the events for it anyway.` });
  }
  if ((directory?.users.length ?? 0) > 1) {
    who.push(table("directory-matches", "Other directory users that match", [
      { key: "name", label: "Name", width: 2 },
      { key: "email", label: "Email", width: 3 },
      { key: "source", label: "Source", width: 2 },
    ], directory!.users.filter((u) => u !== best).map((u) => ({ name: u.name, email: u.email, source: u.source })), { total: directory!.total }));
  }
  if (activity) {
    const accounts = new Map<string, { account: string; sources: Set<string>; signins: number; failed: number; first: number | null; last: number | null }>();
    for (const s of signins) {
      const name = s.user || "(no account name)";
      const a = accounts.get(name) ?? { account: name, sources: new Set<string>(), signins: 0, failed: 0, first: null, last: null };
      a.sources.add(sensorLabel(s.sensorType));
      a.signins += s.count;
      if (s.result === "failed") a.failed += s.count;
      if (s.first !== null) a.first = a.first === null ? s.first : Math.min(a.first, s.first);
      if (s.last !== null) a.last = Math.max(a.last ?? 0, s.last);
      accounts.set(name, a);
    }
    who.push(table("accounts", "Accounts seen signing in", [
      { key: "account", label: "Account", format: "mono", width: 3 },
      { key: "sources", label: "Seen by", width: 3 },
      { key: "signins", label: "Sign-ins", format: "number", width: 1 },
      { key: "failed", label: "Failed", format: "number", width: 1 },
      { key: "first", label: "First", format: "datetime", width: 1.6 },
      { key: "last", label: "Last", format: "datetime", width: 1.6 },
    ], [...accounts.values()].sort((a, b) => b.signins - a.signins).map((a) => ({ account: a.account, sources: [...a.sources].join(", "), signins: a.signins, failed: a.failed, first: a.first, last: a.last })), { empty: "No account matching the user signed in during the window." }));
  }
  who.push({ kind: "note", tone: "gap", text: "Job title, department, manager, Active Directory distinguished name and password last set are not in any Sophos API. The Sophos directory holds name, email, Exchange login and groups." });
  sections.push(section("identity", "Who this is", who, activity ? `The accounts below are those whose sign-ins in the window matched "${user}".` : undefined));

  // ------------------------------------------------------------ sign-ins
  if (activity) {
    const sb: Block[] = [];
    sb.push({
      kind: "kpis",
      items: [
        kpi("Sign-ins", formatNumber(total), `${formatNumber(total - failed)} succeeded`),
        kpi("Failed", formatNumber(failed), total ? `${formatPercent(failed, total)} of sign-ins` : undefined, failed ? "bad" : undefined),
        kpi("Without MFA", aware.size ? formatNumber(withoutMfa) : "-", aware.size ? `of ${plural(sum(counted), "interactive user sign-in")}` : "No source here reports MFA", withoutMfa ? "bad" : undefined),
        kpi("Places", formatNumber(places.size), `${plural(new Set(signins.map((s) => s.ip).filter(Boolean)).size, "source address", "source addresses")}`),
      ],
    });
    const hourly = activity.bucket === "1h";
    const buckets = new Map<string, { label: string; values: number[] }>();
    const keys: string[] = [];
    if (hourly) {
      for (let t = Math.floor(window.start / 3_600_000) * 3_600_000; t < window.end; t += 3_600_000) {
        const k = String(t);
        keys.push(k);
        buckets.set(k, { label: window.end - window.start > 86_400_000 ? `${dayLabel(dayKey(t, tz))} ${hourLabel(t, tz)}` : hourLabel(t, tz), values: [0, 0, 0] });
      }
    } else {
      for (let t = Date.parse(`${new Date(window.start).toISOString().slice(0, 10)}T00:00:00Z`); t < window.end; t += 86_400_000) {
        const k = String(t);
        keys.push(k);
        buckets.set(k, { label: dayLabel(new Date(t).toISOString().slice(0, 10)), values: [0, 0, 0] });
      }
    }
    for (const r of activity.timeline) {
      const b = buckets.get(String(r.at));
      if (b) b.values[r.result === "success" ? 0 : r.result === "failed" ? 1 : 2]! += r.count;
    }
    sb.push({
      kind: "series",
      title: hourly ? "Sign-ins per hour" : "Sign-ins per day (UTC days)",
      unit: "sign-ins",
      series: [
        { key: "success", label: "Succeeded", tone: "good" },
        { key: "failed", label: "Failed", tone: "bad" },
        { key: "other", label: "Other", tone: "neutral" },
      ],
      buckets: keys.map((k) => buckets.get(k)!),
      empty: "No sign-ins in the window.",
    });
    const bySource = new Map<string, { label: string; value: number; failed: number }>();
    for (const s of signins) {
      const b = bySource.get(s.sensorType) ?? { label: sensorLabel(s.sensorType), value: 0, failed: 0 };
      b.value += s.count;
      if (s.result === "failed") b.failed += s.count;
      bySource.set(s.sensorType, b);
    }
    sb.push({ kind: "bars", title: "Sign-ins by source", unit: "sign-ins", rows: [...bySource.values()].sort((a, b) => b.value - a.value).map((b) => ({ label: b.label, value: b.value, note: b.failed ? `${formatNumber(b.failed)} failed` : undefined, tone: "accent" as Tone })), empty: "No sign-ins in the window." });
    const failures = new Map<string, { reason: string; source: string; count: number; ips: Set<string>; last: number | null }>();
    for (const s of signins.filter((x) => x.result === "failed")) {
      const k = `${failureName(s.failure)}|${s.sensorType}`;
      const f = failures.get(k) ?? { reason: failureName(s.failure), source: sensorLabel(s.sensorType), count: 0, ips: new Set<string>(), last: null };
      f.count += s.count;
      if (s.ip) f.ips.add(s.ip);
      f.last = Math.max(f.last ?? 0, s.last ?? 0) || null;
      failures.set(k, f);
    }
    sb.push(table("failures", "Failed sign-ins", [
      { key: "reason", label: "Reason", width: 2.4 },
      { key: "source", label: "Source", width: 2 },
      { key: "count", label: "Failed", format: "number", width: 1 },
      { key: "from", label: "From", width: 2.6 },
      { key: "last", label: "Last", format: "datetime", width: 1.6 },
    ], [...failures.values()].sort((a, b) => b.count - a.count).map((f) => ({ reason: f.reason, source: f.source, count: f.count, from: list([...f.ips].map((ip) => `${ip} (${placeOf(ip, geo, privateIp)})`), 2), last: f.last })), { empty: "No failed sign-ins in the window." }));
    const how = new Map<string, { source: string; type: string; app: string; signins: number; failed: number; mfa: string; last: number | null }>();
    for (const s of signins) {
      const k = `${s.sensorType}|${s.logonType}|${s.app}`;
      const kind = signinKind(s.logonType);
      const h = how.get(k) ?? { source: sensorLabel(s.sensorType), type: logonLabel(s.logonType), app: s.app || "-", signins: 0, failed: 0, mfa: "", last: null };
      h.signins += s.count;
      if (s.result === "failed") h.failed += s.count;
      h.last = Math.max(h.last ?? 0, s.last ?? 0) || null;
      const yes = s.mfa === true;
      h.mfa = !aware.has(s.sensorType) ? "Not reported" : kind !== "user" ? (kind === "service" ? "Service sign-in" : "Token refresh") : h.mfa === "Mixed" || (h.mfa && h.mfa !== (yes ? "Yes" : "No")) ? "Mixed" : yes ? "Yes" : "No";
      how.set(k, h);
    }
    sb.push(table("signin-types", "How they signed in", [
      { key: "source", label: "Source", width: 2 },
      { key: "type", label: "Type", width: 1.4 },
      { key: "app", label: "Application", width: 2.2 },
      { key: "signins", label: "Sign-ins", format: "number", width: 1 },
      { key: "failed", label: "Failed", format: "number", width: 0.9 },
      { key: "mfa", label: "MFA", width: 1.2 },
      { key: "last", label: "Last", format: "datetime", width: 1.6 },
    ], [...how.values()].sort((a, b) => b.signins - a.signins), { empty: "No sign-ins in the window." }));
    sb.push({ kind: "note", tone: "info", text: "MFA is counted only for interactive user sign-ins from sources that fill the MFA fields, such as Microsoft Entra ID. Token refreshes and service sign-ins report no MFA of their own, and Sophos endpoint logons never carry MFA, so they are listed but not counted." });
    if (activity.signinsTruncated) sb.push({ kind: "note", tone: "warn", text: "The sign-in search returned more groups than the report reads (5,000); the smallest groups are missing from these tables." });
    sections.push(section("signins", "Sign-ins", sb));
  } else if (activityError) {
    sections.push(section("signins", "Sign-ins", [{ kind: "note", tone: "gap", text: `Sign-ins and activity: ${activityError}` }]));
  }

  // ------------------------------------------------------------ Microsoft 365
  if (activity) {
    const ms = signins.filter((s) => MICROSOFT.test(s.sensorType));
    const mb: Block[] = [];
    if (ms.length || activity.cloud.length) {
      const interactive = ms.filter((s) => s.result === "success" && signinKind(s.logonType) === "user");
      // MFA counts only from sources that report it, as in the sign-ins section: the Microsoft 365 audit log's logins don't.
      const msAware = interactive.filter((s) => aware.has(s.sensorType));
      const noMfa = sum(msAware.filter((s) => s.mfa === false));
      mb.push({
        kind: "kpis",
        items: [
          kpi("Interactive sign-ins", formatNumber(sum(interactive))),
          kpi("With MFA", msAware.length ? formatNumber(sum(msAware.filter((s) => s.mfa === true))) : "-", msAware.length ? undefined : "Not reported by these sources"),
          kpi("Without MFA", msAware.length ? formatNumber(noMfa) : "-", msAware.length ? undefined : "Not reported by these sources", noMfa ? "bad" : undefined),
          kpi("Token refreshes", formatNumber(sum(ms.filter((s) => signinKind(s.logonType) === "nonInteractive"))), "Non-interactive, no MFA of their own"),
        ],
      });
      const apps = new Map<string, { app: string; signins: number; noMfa: number; failed: number; last: number | null }>();
      for (const s of ms) {
        const a = apps.get(s.app || "Not named") ?? { app: s.app || "Not named", signins: 0, noMfa: 0, failed: 0, last: null };
        a.signins += s.count;
        if (s.result === "failed") a.failed += s.count;
        if (s.result === "success" && s.mfa === false && signinKind(s.logonType) === "user" && aware.has(s.sensorType)) a.noMfa += s.count;
        a.last = Math.max(a.last ?? 0, s.last ?? 0) || null;
        apps.set(a.app, a);
      }
      mb.push(table("m365-apps", "Microsoft 365 sign-ins by application", [
        { key: "app", label: "Application", width: 3 },
        { key: "signins", label: "Sign-ins", format: "number", width: 1 },
        { key: "noMfa", label: "Without MFA", format: "number", width: 1.2 },
        { key: "failed", label: "Failed", format: "number", width: 1 },
        { key: "last", label: "Last", format: "datetime", width: 1.6 },
      ], [...apps.values()].sort((a, b) => b.signins - a.signins).map((a) => (msAware.length ? a : { ...a, noMfa: null })), { empty: "No Microsoft 365 or Entra ID sign-ins in the window." }));
      mb.push(table("cloud-operations", "Cloud operations (Microsoft 365 audit)", [
        { key: "operation", label: "Operation", width: 3 },
        { key: "source", label: "Source", width: 2 },
        { key: "from", label: "From", width: 2.4 },
        { key: "count", label: "Times", format: "number", width: 0.9 },
        { key: "last", label: "Last", format: "datetime", width: 1.6 },
      ], activity.cloud.map((c) => ({ operation: c.operation, source: sensorLabel(c.sensorType), from: c.ip ? `${c.ip} (${placeOf(c.ip, geo, privateIp)})` : "-", count: c.count, last: c.last })), { empty: "No cloud audit events for this user in the window." }));
    } else {
      mb.push({ kind: "note", tone: "gap", text: "No Microsoft 365 or Entra ID events name this user in the window. They appear once the Microsoft 365 integration sends its sign-in and audit logs to Sophos Fusion." });
    }
    sections.push(section("m365", "Microsoft 365 and Entra ID", mb));

    // ------------------------------------------------------------ VPN
    const vpn = signins.filter(isVpnRow);
    const vb: Block[] = [];
    if (vpn.length) {
      const byIp = new Map<string, { ip: string; place: string; source: string; ok: number; failed: number; first: number | null; last: number | null }>();
      for (const s of vpn) {
        const k = `${s.ip ?? "-"}|${s.sensorType}`;
        const v = byIp.get(k) ?? { ip: s.ip ?? "-", place: placeOf(s.ip, geo, privateIp), source: `${sensorLabel(s.sensorType)}${s.app ? `, ${s.app}` : ""}`, ok: 0, failed: 0, first: null, last: null };
        if (s.result === "failed") v.failed += s.count;
        else v.ok += s.count;
        if (s.first !== null) v.first = v.first === null ? s.first : Math.min(v.first, s.first);
        v.last = Math.max(v.last ?? 0, s.last ?? 0) || null;
        byIp.set(k, v);
      }
      vb.push(table("vpn", "VPN and firewall sign-ins by source address", [
        { key: "ip", label: "Source IP", format: "mono", width: 1.6 },
        { key: "place", label: "Place", width: 1.8 },
        { key: "source", label: "Gateway", width: 2.2 },
        { key: "ok", label: "Succeeded", format: "number", width: 1 },
        { key: "failed", label: "Failed", format: "number", width: 0.9 },
        { key: "first", label: "First", format: "datetime", width: 1.6 },
        { key: "last", label: "Last", format: "datetime", width: 1.6 },
      ], [...byIp.values()].sort((a, b) => (b.last ?? 0) - (a.last ?? 0))));
      vb.push({ kind: "note", tone: "gap", text: "VPN session end times and the address a VPN gave the user are not in any Sophos API; the report shows when each source address signed in." });
    } else {
      vb.push({ kind: "note", tone: "gap", text: "No VPN or firewall sign-ins for this user in the window. They appear when the firewall or VPN gateway sends its authentication logs to Sophos Fusion (Sophos Firewall, Fortinet, Palo Alto GlobalProtect, Cisco and others). Even then, VPN session end times and the address a VPN gave the user are not in any Sophos API." });
    }
    sections.push(section("vpn", "VPN and remote access", vb));

    // ------------------------------------------------------------ places
    const pl = new Map<string, { place: string; ips: Set<string>; signins: number; failed: number; first: number | null; last: number | null }>();
    let internal = 0;
    let unplaced = 0;
    for (const s of [...signins]) {
      if (!s.ip || !geo[s.ip]) {
        if (s.ip && !NO_ADDRESS.has(s.ip) && !privateIp(s.ip)) unplaced += s.count;
        else internal += s.count;
        continue;
      }
      const g = geo[s.ip]!;
      const k = `${g.city ?? ""}|${g.country ?? ""}`;
      const p = pl.get(k) ?? { place: [g.city, g.country].filter(Boolean).join(", ") || "Unknown", ips: new Set<string>(), signins: 0, failed: 0, first: null, last: null };
      p.ips.add(s.ip);
      p.signins += s.count;
      if (s.result === "failed") p.failed += s.count;
      if (s.first !== null) p.first = p.first === null ? s.first : Math.min(p.first, s.first);
      p.last = Math.max(p.last ?? 0, s.last ?? 0) || null;
      pl.set(k, p);
    }
    sections.push(section("places", "Where they signed in from", [
      table("places", "Places", [
        { key: "place", label: "Place", width: 2.2 },
        { key: "ips", label: "Source addresses", format: "mono", width: 2.6 },
        { key: "signins", label: "Sign-ins", format: "number", width: 1 },
        { key: "failed", label: "Failed", format: "number", width: 0.9 },
        { key: "first", label: "First", format: "datetime", width: 1.6 },
        { key: "last", label: "Last", format: "datetime", width: 1.6 },
      ], [...pl.values()].sort((a, b) => b.signins - a.signins).map((p) => ({ place: p.place, ips: list([...p.ips], 3), signins: p.signins, failed: p.failed, first: p.first, last: p.last })), { empty: "No sign-in came from a public address the report could place." }),
      { kind: "note", tone: "info", text: `Places come from the source IP, located with DB-IP City Lite where installed (Setup). A VPN or proxy shows where traffic left, not where the person was. Not placed: ${formatNumber(internal)} sign-ins from internal or no address, ${formatNumber(unplaced)} from public addresses with no location.` },
    ]));
  }

  // ------------------------------------------------------------ devices
  const devRows = [...deviceRows.values()].map((d) => {
    const e = devices.get(d.id)!;
    return { device: e.hostname, how: [...d.how, ...(d.count ? [`Signed in ${plural(d.count, "time")}`] : [])].join("; "), os: e.osName, health: e.health.charAt(0).toUpperCase() + e.health.slice(1), lastSeen: e.lastSeenAt ? Date.parse(e.lastSeenAt) : null, tamper: e.tamper === false ? "Off" : e.tamper === true ? "On" : "-", last: d.last };
  }).sort((a, b) => (b.last ?? 0) - (a.last ?? 0));
  sections.push(section("devices", "Devices", [
    table("devices", "Devices the user is assigned to or signed in to", [
      { key: "device", label: "Device", format: "mono", width: 2 },
      { key: "how", label: "Link", width: 2.6 },
      { key: "os", label: "OS", width: 1.8 },
      { key: "health", label: "Health", width: 1 },
      { key: "tamper", label: "Tamper protection", width: 1.2 },
      { key: "lastSeen", label: "Device last seen", format: "datetime", width: 1.6 },
    ], devRows, { empty: "No Sophos-managed device is assigned to this user or was signed in to by them in the window." }),
  ]));

  // ------------------------------------------------------------ accounts used
  if (activity) {
    // Same account on both sides is an ordinary sign-in; a different one is a switch of account (runas, an admin account).
    const differs = (s: UserSigninRow) => !!s.user && !!s.sourceUser && s.user.toLowerCase() !== s.sourceUser.toLowerCase();
    const asOther = signins.filter((s) => differs(s) && s.sourceUser.toLowerCase().includes(q));
    const others = signins.filter((s) => differs(s) && s.user.toLowerCase().includes(q) && !s.sourceUser.toLowerCase().includes(q));
    if (asOther.length || others.length) {
      const rowsOf = (rows: UserSigninRow[]) => {
        const m = new Map<string, { from: string; to: string; device: string; count: number; last: number | null }>();
        for (const s of rows) {
          const k = `${s.sourceUser}|${s.user}|${s.hostId}`;
          const r = m.get(k) ?? { from: s.sourceUser, to: s.user, device: s.hostId ? (devices.get(s.hostId)?.hostname ?? s.hostId) : "-", count: 0, last: null };
          r.count += s.count;
          r.last = Math.max(r.last ?? 0, s.last ?? 0) || null;
          m.set(k, r);
        }
        return [...m.values()].sort((a, b) => b.count - a.count);
      };
      const cols = [
        { key: "from", label: "From account", format: "mono" as const, width: 2 },
        { key: "to", label: "To account", format: "mono" as const, width: 2 },
        { key: "device", label: "Device", format: "mono" as const, width: 1.8 },
        { key: "count", label: "Times", format: "number" as const, width: 0.9 },
        { key: "last", label: "Last", format: "datetime" as const, width: 1.6 },
      ];
      sections.push(section("accounts-used", "Other accounts", [
        table("as-other-accounts", "This user signing in as other accounts", cols, rowsOf(asOther), { empty: "None in the window." }),
        table("other-accounts-as-user", "Other accounts signing in as this user", cols, rowsOf(others), { empty: "None in the window." }),
      ], "A sign-in names both the account that started it and the account it used when the source reports both, as Windows does for runas and remote logons."));
    }
  }

  // ------------------------------------------------------------ detections
  const db: Block[] = [];
  if (detections) {
    const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, detItems.filter((d) => d.severity === s).length]));
    const critHigh = (bySev.critical ?? 0) + (bySev.high ?? 0);
    db.push({ kind: "kpis", items: [kpi("Detections", formatNumber(detections.total)), kpi("Critical or high", formatNumber(critHigh), undefined, critHigh ? "high" : undefined), kpi("Medium", formatNumber(bySev.medium ?? 0), undefined, bySev.medium ? "medium" : undefined), kpi("Low or info", formatNumber((bySev.low ?? 0) + (bySev.info ?? 0)))] });
    db.push(table("detections", "Detections that name the user", [
      { key: "at", label: "Time", format: "datetime", width: 1.6 },
      { key: "severity", label: "Severity", width: 0.9 },
      { key: "title", label: "Detection", width: 3.2 },
      { key: "hosts", label: "Devices", format: "mono", width: 1.6 },
      { key: "ips", label: "Addresses", format: "mono", width: 1.6 },
      { key: "status", label: "Status", width: 0.9 },
    ], detItems.slice(0, 500).map((d) => ({ at: d.createdAt, severity: SEV_LABEL[d.severity], title: d.title, hosts: list(d.hosts, 2), ips: list(d.ips, 2), status: d.status ? d.status.toLowerCase().replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase()) : "-" })), { total: detections.total, empty: "No detection names this user in the window.", pdfRows: 60 }));
    if (detections.sampled) db.push({ kind: "note", tone: "warn", text: `Sophos counted ${formatNumber(detections.total)} detections; the report reads the newest ${formatNumber(detItems.length)}.` });
  } else if (detectionError) {
    db.push({ kind: "note", tone: "gap", text: `Detections: ${detectionError}` });
  } else {
    db.push({ kind: "note", tone: "gap", text: "Detections v2 serves Sophos Fusion tenants only. This tenant is still on the Classic APIs, where its signals are product alerts, which carry no user field to search." });
  }
  sections.push(section("detections", "Detections", db));

  // ------------------------------------------------------------ cases
  const caseRows = [...cases.values()].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  sections.push(section("cases", "Cases", [
    table("cases", "Cases whose title names the user", [
      { key: "ref", label: "Case", format: "mono", width: 1.2 },
      { key: "title", label: "Title", width: 3.6 },
      { key: "severity", label: "Severity", width: 0.9 },
      { key: "status", label: "Status", width: 1.4 },
      { key: "owner", label: "Worked by", width: 1.1 },
      { key: "created", label: "Created", format: "datetime", width: 1.6 },
      { key: "closed", label: "Closed", format: "datetime", width: 1.6 },
    ], caseRows.map((c) => ({ ref: c.ref, title: c.title, severity: SEV_LABEL[c.severity], status: c.statusTitle, owner: c.managedBy === "mdr" ? "Sophos MDR" : c.managedBy === "self" ? "Your team" : "-", created: Date.parse(c.createdAt), closed: c.closedAt ? Date.parse(c.closedAt) : null })), { empty: "No case title names this user." }),
    { kind: "note", tone: "gap", text: `Cases are matched on their title: the Cases API cannot search by the users in a case's evidence. ${fusion ? "Fusion cases of any age are searched" : "Classic cases cover those open now and those closed in the last 30 days"}.${casesMore ? " More than 100 older cases matched; the newest 100 are shown." : ""}` },
  ]));

  // ------------------------------------------------------------ activity by event type
  if (activity) {
    const bySchema = new Map<string, number>();
    for (const a of activity.activity) bySchema.set(a.schema, (bySchema.get(a.schema) ?? 0) + a.count);
    sections.push(section("activity", "Activity by event type", [
      { kind: "bars", title: "Events that name the user", unit: "events", rows: [...bySchema.entries()].sort((a, b) => b[1] - a[1]).map(([s, n]) => ({ label: schemaLabel(s), value: n, tone: "accent" as Tone })), empty: "No events name the user in the window." },
      table("activity", "Events by type and source", [
        { key: "type", label: "Event type", width: 2 },
        { key: "source", label: "Source", width: 2.4 },
        { key: "events", label: "Events", format: "number", width: 1 },
      ], activity.activity.map((a) => ({ type: schemaLabel(a.schema), source: sensorLabel(a.sensorType), events: a.count }))),
      { kind: "note", tone: "info", text: "Counted across the 19 event types that carry a user field. DNS, DHCP, encryption and unparsed (generic) events carry none, so they are not searched by user; the log search export can search them by IP address or device." },
    ]));

    // ------------------------------------------------------------ recent
    sections.push(section("recent", "Recent sign-ins", [
      table("recent-signins", "Newest sign-in events", [
        { key: "at", label: "Time", format: "datetime", width: 1.6 },
        { key: "account", label: "Account", format: "mono", width: 2.2 },
        { key: "source", label: "Source", width: 1.8 },
        { key: "type", label: "Type", width: 1.2, pdf: false },
        { key: "app", label: "Application", width: 1.6 },
        { key: "result", label: "Result", width: 1.6 },
        { key: "mfa", label: "MFA", width: 0.7 },
        { key: "ip", label: "Source IP", format: "mono", width: 1.5 },
        { key: "device", label: "Device", format: "mono", width: 1.4 },
      ], activity.recent.map((r) => ({
        at: r.at,
        account: r.sourceUser && r.sourceUser !== r.user ? `${r.sourceUser} as ${r.user}` : r.user,
        source: sensorLabel(r.sensorType),
        type: logonLabel(r.logonType),
        app: r.app || "-",
        result: r.result === "failed" ? `Failed: ${failureName(r.failure)}` : r.result === "success" ? "Succeeded" : "Other",
        mfa: r.mfa === true ? "Yes" : r.mfa === false ? (aware.has(r.sensorType) ? "No" : "-") : "-",
        ip: r.ip ?? "-",
        device: r.hostId ? (devices.get(r.hostId)?.hostname ?? r.hostId.slice(0, 8)) : "-",
      })), { empty: "No sign-in events in the window.", pdfRows: 40 }),
    ]));
  }

  const summary = [
    kpi("Sign-ins", activity ? formatNumber(total) : "-", activity ? `${formatNumber(failed)} failed` : "Needs Sophos Fusion"),
    kpi("Without MFA", activity && aware.size ? formatNumber(withoutMfa) : "-", activity && aware.size ? "interactive user sign-ins" : undefined, withoutMfa ? "bad" : undefined),
    kpi("Detections", detections ? formatNumber(detections.total) : "-", detections ? `${formatNumber(detItems.filter((d) => d.severity === "critical" || d.severity === "high").length)} critical or high` : undefined, detItems.some((d) => d.severity === "critical" || d.severity === "high") ? "bad" : undefined),
    kpi("Cases", formatNumber(cases.size), `${formatNumber(caseRows.filter((c) => !c.closed).length)} open`),
    kpi("Devices", formatNumber(deviceRows.size)),
    kpi("Places", activity ? formatNumber(places.size) : "-"),
  ];
  return { subject: exact ? `${exact.name}${exact.email && exact.email.toLowerCase() !== exact.name.toLowerCase() ? ` (${exact.email})` : ""}` : user, summary, sections, gaps, provenance, params: { user } };
}
