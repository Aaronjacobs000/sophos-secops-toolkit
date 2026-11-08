// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/fusion/ai-defense.ts and src/tools/fusion-ai-defense-activity.ts at release 0.13.0. MIT License,
// Copyright (c) 2026; the full notice is in LICENSE-MIT at the root of this package.
// (SecOps Toolkit local modification, 08/11/2026.)

/**
 * The AI Defense reads SecOps Toolkit makes, on the Sophos Fusion GraphQL
 * endpoint with the tenant's credential: an overview (settings, inventory
 * summary, blocked and warned counts by risk), the policy counts, the
 * details (top apps and users, the newest blocked or warned activity) and the
 * flow (blocked and warned for each of the top apps and users). Reads only:
 * the settings mutation and the policy writes are not here.
 *
 * Every read sends a time window. The Activity API's default window sits on
 * filter.timeRange (since 00:00 UTC today), and a relative preset with
 * absolute bounds is refused by the API with only "input: failed to retrieve
 * activities", so the pair is refused here first.
 */

import type { FusionClient, FusionQueryResult } from "../client/fusion-client.js";
import { AI_DEFENSE_DETAIL, AI_DEFENSE_FLOW, AI_DEFENSE_FLOW_SLOTS, AI_DEFENSE_FLOW_UNUSED, AI_DEFENSE_OVERVIEW, AI_DEFENSE_POLICIES, AI_DEFENSE_TIMEOUT_MS } from "../fusion/queries/ai-defense.js";

export const AI_DEFENSE_RELATIVE_RANGES = [
  "SINCE_BEGINNING_OF_DAY",
  "SINCE_BEGINNING_OF_WEEK_SUNDAY",
  "SINCE_BEGINNING_OF_WEEK_MONDAY",
  "SINCE_BEGINNING_OF_MONTH",
  "SINCE_BEGINNING_OF_QUARTER",
  "SINCE_BEGINNING_OF_YEAR",
  "LAST_MONTH",
  "LAST_QUARTER",
  "LAST_YEAR",
] as const;

export interface AiDefenseTimeRangeArgs {
  relative?: (typeof AI_DEFENSE_RELATIVE_RANGES)[number];
  startTime?: string;
  endTime?: string;
}

/** The SecureAITimeRange to send, or undefined when neither form is given. */
export function buildTimeRange(args: AiDefenseTimeRangeArgs): Record<string, string> | undefined {
  const absolute = args.startTime !== undefined || args.endTime !== undefined;
  if (args.relative !== undefined && absolute) {
    throw new Error("Pass a relative AI Defense window or startTime and endTime, not both. The API refuses the pair with only 'input: failed to retrieve activities'.");
  }
  if (args.relative !== undefined) return { relative: args.relative };
  if (!absolute) return undefined;
  const range: Record<string, string> = {};
  if (args.startTime !== undefined) range.startTime = args.startTime;
  if (args.endTime !== undefined) range.endTime = args.endTime;
  return range;
}

export type AiDefenseRiskLevel = "UNKNOWN" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "ERROR";

interface Count {
  totalCount: number;
}

export interface AiDefenseOverviewResponse {
  secureAITenantSettings: {
    onboarding: { status: "NOT_STARTED" | "IN_PROGRESS" | "COMPLETED" } | null;
    licenseState: "ACTIVE" | "GRACE_PERIOD" | "EXPIRED" | null;
    licenseType: string | null;
    licenseExpiryDate: string | null;
    gracePeriodEndsAt: string | null;
  } | null;
  inventorySummary: {
    apps: { totalApps: number; criticalRisk: number; highRisk: number; mediumRisk: number; lowRisk: number; infoRisk: number; unknownRisk: number; errorRisk: number; trainsOnData: number | null; unsanctionedCount: number };
    users: { totalUsers: number; criticalRisk: number; highRisk: number; mediumRisk: number; lowRisk: number; infoRisk: number; unknownRisk: number; withViolations: number; unsanctionedCount: number };
  } | null;
  all: Count | null;
  unsanctioned: Count | null;
  blocked: Count | null;
  blockedCritical: Count | null;
  blockedHigh: Count | null;
  blockedMedium: Count | null;
  blockedLow: Count | null;
  blockedInfo: Count | null;
  warned: Count | null;
  warnedCritical: Count | null;
  warnedHigh: Count | null;
  warnedMedium: Count | null;
  warnedLow: Count | null;
  warnedInfo: Count | null;
}

export interface AiDefenseDetailResponse {
  appInventory: {
    totalCount: number;
    entries: Array<{ id: string; name: string; provider: string; risk: AiDefenseRiskLevel; usage: number; uniqueUsers: number; lastSeen: string | null; unsanctionedCount: number }>;
  } | null;
  userInventory: {
    totalCount: number;
    entries: Array<{ id: string; name: string; risk: AiDefenseRiskLevel; appsUsed: number; usage: number; policyViolations: number; topApp: string | null; lastSeen: string | null; unsanctionedCount: number }>;
  } | null;
  activities: {
    totalCount: number;
    activities: Array<{
      timestamp: { startTime: string | null } | null;
      actor: { name: string; type: string } | null;
      application: { id: string; name: string } | null;
      action: "UNKNOWN" | "ALLOWED" | "BLOCKED" | "WARNED" | "MODIFIED" | null;
      policy: string;
      device: { name: string; platform: string } | null;
      risk: AiDefenseRiskLevel;
      aggregationCount: number;
    }>;
  } | null;
}

/** `app0Blocked` to `app9Warned` and `user0Blocked` to `user9Warned`, each a total. */
export type AiDefenseFlowResponse = Record<string, Count | null>;

export interface AiDefensePoliciesResponse {
  policies: { totalCount: number; enabledCount: number; failedCount: number } | null;
}

export class AiDefenseService {
  constructor(private readonly fusion: FusionClient) {}

  private variables(range: AiDefenseTimeRangeArgs): Record<string, unknown> {
    const timeRange = buildTimeRange(range);
    if (!timeRange) throw new Error("AI Defense reads need a time window: with none, Sophos reads only since 00:00 UTC today.");
    return { timeRange };
  }

  /** Settings, the inventory summary and blocked and warned counts by risk, in one call. */
  overview(tenantId: string, range: AiDefenseTimeRangeArgs): Promise<FusionQueryResult<AiDefenseOverviewResponse>> {
    return this.fusion.query<AiDefenseOverviewResponse>(tenantId, AI_DEFENSE_OVERVIEW, this.variables(range), { timeoutMs: AI_DEFENSE_TIMEOUT_MS });
  }

  /** The top 20 apps and users by activity, and the newest 50 blocked or warned activities. */
  detail(tenantId: string, range: AiDefenseTimeRangeArgs): Promise<FusionQueryResult<AiDefenseDetailResponse>> {
    return this.fusion.query<AiDefenseDetailResponse>(tenantId, AI_DEFENSE_DETAIL, this.variables(range), { timeoutMs: AI_DEFENSE_TIMEOUT_MS });
  }

  /**
   * Blocked and warned counts for up to 10 app ids and 10 actor ids. Every
   * slot is sent: one with no id gets the unused id, which matches nothing.
   */
  flow(tenantId: string, range: AiDefenseTimeRangeArgs, appIds: readonly string[], userIds: readonly string[]): Promise<FusionQueryResult<AiDefenseFlowResponse>> {
    if (appIds.length > AI_DEFENSE_FLOW_SLOTS || userIds.length > AI_DEFENSE_FLOW_SLOTS) throw new Error(`The AI Defense flow read takes at most ${AI_DEFENSE_FLOW_SLOTS} apps and ${AI_DEFENSE_FLOW_SLOTS} users.`);
    const slot = (ids: readonly string[], i: number) => (ids[i] ? ids[i]! : AI_DEFENSE_FLOW_UNUSED);
    const variables: Record<string, unknown> = this.variables(range);
    for (let i = 0; i < AI_DEFENSE_FLOW_SLOTS; i++) variables[`app${i}`] = slot(appIds, i);
    for (let i = 0; i < AI_DEFENSE_FLOW_SLOTS; i++) variables[`user${i}`] = slot(userIds, i);
    return this.fusion.query<AiDefenseFlowResponse>(tenantId, AI_DEFENSE_FLOW, variables, { timeoutMs: AI_DEFENSE_TIMEOUT_MS });
  }

  /** Policy counts (a separate permission from the activity reads). */
  policies(tenantId: string): Promise<FusionQueryResult<AiDefensePoliciesResponse>> {
    return this.fusion.query<AiDefensePoliciesResponse>(tenantId, AI_DEFENSE_POLICIES, {}, { timeoutMs: AI_DEFENSE_TIMEOUT_MS });
  }
}
