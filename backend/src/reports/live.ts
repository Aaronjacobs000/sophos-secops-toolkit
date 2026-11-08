/**
 * The Sophos reads a report makes beyond the dashboard cache. Every one goes
 * through the active credential's read-only guard and rate limiter: GETs, the
 * two allowed search mutations (each starts a Search GraphQL search and
 * changes nothing), and GraphQL queries the guard allows, one of them
 * (ToolkitDetectionDetail) only as the exact document below.
 */

import { LIST_CASES } from "../vendor/sophos-core/fusion/queries/cases.js";
import type { FusionCasesResponse, SophosCore, SearchRun, SearchRunOptions } from "../vendor/sophos-core/index.js";
import { mapCase } from "../mappers/api.js";
import { searchMeta } from "../mappers/search.js";
import type { CaseRecord, GeoPoint } from "../data/types.js";
import {
  mapDetectionDetail,
  mapDirectoryUser,
  parseLogRow,
  parseUserActivity,
  parseUserCloud,
  parseUserRecent,
  parseUserSignins,
  parseUserTimeline,
  bucketTime,
  count,
  str,
  type DetectionDetailSet,
  type DirectoryUser,
  type LogSearchResult,
  type UserActivity,
} from "./data.js";
import {
  bucketFor,
  detectionQl,
  groupSchemas,
  logGroupQl,
  logRowsQl,
  logTimelineQl,
  rowGroups,
  userActivityQl,
  userCloudQl,
  userRecentQl,
  userSigninsQl,
  userTimelineQl,
  type LogSearchSpec,
  type MatchKind,
} from "./queries.js";

/**
 * Detections with their titles and entities, for the reports. The guard lets
 * this name through only as this exact text; a test checks the guard's copy.
 */
export const DETECTION_DETAIL_DOC = `query ToolkitDetectionDetail($in: SearchRequestInput!) {
  detectionSearch(in: $in) {
    status
    reason
    alerts {
      total_results
      next_offset
      list {
        id
        status
        sensor_types
        attack_technique_ids
        metadata {
          title
          severity
          created_at { seconds }
          creator { detector { detector_name } }
        }
        enrichment_details { mitre_attack_info { technique_id technique tactics } }
        source_entities { display_name subtype }
        target_entities { display_name subtype }
      }
    }
  }
}`;

/**
 * Search settings for a report: reuse a matching search, 5 s polls, a 3-minute deadline,
 * and 90 s for each results page. On a live tenant (06/11/2026) the first page of a new log
 * search took 35 s at 100 rows and 40 to 56 s at 500, past the client's 30 s.
 */
export const REPORT_SEARCH: SearchRunOptions = { reuse: true, pollMs: 5_000, deadlineMs: 180_000, maxRows: 5_000, partial: "accept", pageTimeoutMs: 90_000 };

type Window = { start: number; end: number };

/** Runs tasks with at most `limit` at once; a search polls for a while, and two at once keep the rest of the toolkit moving. */
export async function limited<T>(tasks: Array<() => Promise<T>>, limit = 2): Promise<T[]> {
  const out: T[] = new Array(tasks.length);
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const i = next++;
      out[i] = await tasks[i]!();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return out;
}

export interface GeoDeps {
  isPublic: (ip: string) => boolean;
  lookup: (ip: string) => Promise<GeoPoint | null>;
}

export async function placeIps(ips: Iterable<string | null>, geo: GeoDeps): Promise<Record<string, GeoPoint>> {
  const out: Record<string, GeoPoint> = {};
  for (const ip of new Set([...ips].filter((x): x is string => !!x && geo.isPublic(x)))) {
    const found = await geo.lookup(ip);
    if (found) out[ip] = found;
  }
  return out;
}

/** The user investigation searches: sign-ins, their timeline, activity by event type, the newest sign-ins and cloud operations. */
export async function fetchUserActivity(core: SophosCore, tenantId: string, user: string, window: Window, geo: GeoDeps, options: SearchRunOptions = REPORT_SEARCH): Promise<UserActivity> {
  const bucket = bucketFor(window);
  const [signins, timeline, activity, recent, cloud] = await limited<SearchRun>([
    () => core.search.run(tenantId, userSigninsQl(user, window), options),
    () => core.search.run(tenantId, userTimelineQl(user, window), { ...options, maxRows: 3_000 }),
    () => core.search.run(tenantId, userActivityQl(user, window), { ...options, maxRows: 500 }),
    () => core.search.run(tenantId, userRecentQl(user, window), { ...options, maxRows: 100, pageSize: 100 }),
    () => core.search.run(tenantId, userCloudQl(user, window), { ...options, maxRows: 1_000 }),
  ]);
  const rows = parseUserSignins(signins!.rows);
  return {
    window,
    bucket,
    signins: rows,
    signinsTruncated: signins!.truncated,
    timeline: parseUserTimeline(timeline!.rows, bucket),
    activity: parseUserActivity(activity!.rows),
    recent: parseUserRecent(recent!.rows),
    cloud: parseUserCloud(cloud!.rows),
    geo: await placeIps([...rows.map((r) => r.ip), ...parseUserCloud(cloud!.rows).map((r) => r.ip)], geo),
    search: searchMeta([signins!, timeline!, activity!, recent!, cloud!], Date.now()),
  };
}

export async function fetchLogSearch(core: SophosCore, tenantId: string, spec: LogSearchSpec, window: Window, options: SearchRunOptions = REPORT_SEARCH): Promise<LogSearchResult> {
  const bucket = bucketFor(window);
  const groupQl = logGroupQl(spec, window);
  const [timelineRun, groupRun] = await limited<SearchRun | null>([
    () => core.search.run(tenantId, logTimelineQl(spec, window), { ...options, maxRows: 5_000 }),
    () => (groupQl ? core.search.run(tenantId, groupQl, { ...options, maxRows: 2_000 }) : Promise.resolve(null)),
  ]);
  const timeline: LogSearchResult["timeline"] = [];
  for (const v of timelineRun!.rows) {
    const at = bucketTime(v[`event_time_usec_${bucket}`]);
    const n = count(v.row_count);
    if (at !== null && n) timeline.push({ at, schema: str(v.schema_type) ?? "unknown", count: n });
  }
  const field = spec.groupBy === "schema" ? "sensor_type" : spec.groupBy;
  const groups = groupRun
    ? {
        field: spec.groupBy,
        schemas: groupSchemas(spec),
        rows: groupRun.rows
          .map((v) => ({ value: v[field] === undefined || v[field] === null || v[field] === "" ? "" : String(v[field]), schema: str(v.schema_type) ?? "unknown", sensorType: str(v.sensor_type), count: count(v.row_count) }))
          .filter((r) => r.count > 0),
      }
    : null;
  // The newest events, read a few event types at a time (only types with events) and merged.
  const rowRuns = await limited<SearchRun>(rowGroups(timeline).map((schemas) => () => core.search.run(tenantId, logRowsQl(spec, window, schemas), { ...options, maxRows: spec.rows, pageSize: Math.min(1_000, spec.rows) })));
  const all = rowRuns.flatMap((r) => r.rows).map(parseLogRow).filter((r): r is NonNullable<typeof r> => !!r).sort((a, b) => b.at - a.at);
  const rows = all.slice(0, spec.rows);
  return {
    window,
    bucket,
    timeline: timeline.sort((a, b) => a.at - b.at),
    groups,
    rows,
    rowsTruncated: all.length > spec.rows || rowRuns.some((r) => r.rows.length >= spec.rows),
    search: searchMeta([timelineRun!, ...(groupRun ? [groupRun] : []), ...rowRuns], Date.now()),
  };
}

interface DetectionSearchAnswer {
  detectionSearch: { status?: string; reason?: string; alerts?: { total_results?: number; list?: unknown[] } | null } | null;
}

/** Detections for the window (one tenant), newest first, with titles and entities. One call, up to `cap`. */
export async function fetchDetectionDetail(core: SophosCore, tenantId: string, hours: number, match: { kind: MatchKind; value: string } | null = null, cap = 3_000): Promise<DetectionDetailSet> {
  const { data } = await core.fusion.query<DetectionSearchAnswer>(tenantId, DETECTION_DETAIL_DOC, {
    in: { cql_query: detectionQl(match?.kind ?? null, match?.value ?? null, hours), limit: cap, offset: 0 },
  });
  const alerts = data.detectionSearch?.alerts;
  const items = (alerts?.list ?? []).map(mapDetectionDetail).filter((d): d is NonNullable<typeof d> => !!d).sort((a, b) => b.createdAt - a.createdAt);
  const total = Math.max(alerts?.total_results ?? 0, items.length);
  return { hours, total, items, sampled: total > items.length };
}

/** Sophos directory users whose name or email holds the text (GET, one page). */
export async function fetchDirectoryUsers(core: SophosCore, tenantId: string, text: string): Promise<{ users: DirectoryUser[]; total: number }> {
  const data = await core.rest.tenantRequest<{ items?: unknown[]; pages?: { items?: number } }>(tenantId, "/common/v1/directory/users", { params: { search: text, pageSize: "25", pageTotal: "true" } });
  const users = (data.items ?? []).map(mapDirectoryUser).filter((u): u is DirectoryUser => !!u);
  return { users, total: data.pages?.items ?? users.length };
}

/** Fusion cases of any age whose title holds the text (Cases v2 search, one page of 100). */
export async function fetchCasesByTitle(core: SophosCore, tenantId: string, text: string): Promise<{ cases: CaseRecord[]; more: boolean }> {
  const { data } = await core.fusion.query<FusionCasesResponse>(tenantId, LIST_CASES, { arguments: { query: `title contains '${text}'`, pagination: { offset: { page: 1, perPage: 100 } } } });
  const cases = data.cases.cases.map((c) => mapCase(c, "v2")).filter((c): c is CaseRecord => !!c);
  return { cases, more: data.cases.pageInfo.hasNextPage };
}
