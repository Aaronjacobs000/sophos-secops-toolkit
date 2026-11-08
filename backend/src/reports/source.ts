/**
 * Where a report run reads from. Cached datasets come from the provider the
 * screens use (the live engine or demo). Reads beyond the cache (searches,
 * detections with titles, the directory, cases by title) come from the live
 * source, which sends them through the active credential's guard and rate
 * limiter at interactive priority, or from the demo source, which invents them.
 */

import type { Provider } from "../services/provider.js";
import type { Engine } from "../services/engine.js";
import type { AlertSet, CaseRecord } from "../data/types.js";
import { callPriority } from "../sophos/guard.js";
import { PRIORITY } from "../sophos/rate-limiter.js";
import { fetchAlerts } from "../data/fetchers.js";
import { isPublicIp, lookupIp } from "../services/geoip.js";
import type { DetectionDetailSet, DirectoryUser, LogSearchResult, UserActivity } from "./data.js";
import { fetchCasesByTitle, fetchDetectionDetail, fetchDirectoryUsers, fetchLogSearch, fetchUserActivity } from "./live.js";
import type { LogSearchSpec, MatchKind } from "./queries.js";

type Window = { start: number; end: number };

export interface ReportSource {
  readonly kind: "live" | "demo";
  readonly provider: Provider;
  userActivity(tenantId: string, user: string, window: Window): Promise<UserActivity>;
  logSearch(tenantId: string, spec: LogSearchSpec, window: Window): Promise<LogSearchResult>;
  detections(tenantId: string, hours: number, match?: { kind: MatchKind; value: string } | null): Promise<DetectionDetailSet>;
  alerts(tenantId: string, hours: number): Promise<AlertSet>;
  directory(tenantId: string, text: string): Promise<{ users: DirectoryUser[]; total: number }>;
  /** Cases of any age whose title holds the text; null where the tenant's cases are not on Fusion. */
  casesByTitle(tenantId: string, text: string): Promise<{ cases: CaseRecord[]; more: boolean } | null>;
}

export class LiveReportSource implements ReportSource {
  readonly kind = "live" as const;
  readonly provider: Provider;

  constructor(private readonly engine: Engine) {
    this.provider = engine;
  }

  private interactive<T>(fn: () => Promise<T>): Promise<T> {
    return callPriority.run(PRIORITY.interactive, fn);
  }

  userActivity(tenantId: string, user: string, window: Window): Promise<UserActivity> {
    return this.interactive(() => fetchUserActivity(this.engine.core, tenantId, user, window, { isPublic: isPublicIp, lookup: lookupIp }));
  }

  logSearch(tenantId: string, spec: LogSearchSpec, window: Window): Promise<LogSearchResult> {
    return this.interactive(() => fetchLogSearch(this.engine.core, tenantId, spec, window));
  }

  detections(tenantId: string, hours: number, match: { kind: MatchKind; value: string } | null = null): Promise<DetectionDetailSet> {
    return this.interactive(() => fetchDetectionDetail(this.engine.core, tenantId, hours, match));
  }

  alerts(tenantId: string, hours: number): Promise<AlertSet> {
    return this.interactive(() => fetchAlerts(this.engine.core, tenantId, hours));
  }

  directory(tenantId: string, text: string): Promise<{ users: DirectoryUser[]; total: number }> {
    return this.interactive(() => fetchDirectoryUsers(this.engine.core, tenantId, text));
  }

  async casesByTitle(tenantId: string, text: string): Promise<{ cases: CaseRecord[]; more: boolean } | null> {
    if (this.engine.get("generation", tenantId)?.generation !== "fusion") return null;
    return this.interactive(() => fetchCasesByTitle(this.engine.core, tenantId, text));
  }
}
