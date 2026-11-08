// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// src/fusion/queries/ai-defense-activity.ts and ai-defense-policy.ts at release 0.13.0. MIT License,
// Copyright (c) 2026; the full notice is in LICENSE-MIT at the root of this package.
// (SecOps Toolkit local modification, 08/11/2026.)

/**
 * AI Defense Activity and Policy GraphQL API v1 documents (released
 * 15/10/2026), trimmed to the reads SecOps Toolkit shows. All four are
 * queries. SecOps Toolkit's read-only guard allows exactly these documents,
 * compared character for character, so an edit here has to be made in
 * backend/src/sophos/guard.ts as well (a test checks they match). The
 * settings mutation (updateSecureAITenantSettings) and every policy write
 * are never sent.
 *
 * Measured on live tenants 07/11/2026 (sophos-central-mcp-server) and
 * 08/11/2026:
 * - The activities list must not select additionalData: it is null on every
 *   row, which nulls the whole response.
 * - The live app inventory entry has none of the reference's training,
 *   compliance and category fields (selecting one is an HTTP 400), so only
 *   fields both carry are selected.
 * - The default window, since 00:00 UTC today, sits on filter.timeRange, so
 *   every read here passes $timeRange.
 * - The risks filter refuses ERROR ("invalid RiskLevel"), and that one error
 *   nulls the whole response. The counts filter CRITICAL to INFO only; the
 *   rest of a blocked or warned total (UNKNOWN and ERROR) is the remainder.
 * - Aliased counts run in one call: 15 activity counts, the settings and the
 *   inventory summary took 1.3 s on a tenant with 9,067 activities in 7 days.
 * - policies is a separate permission (SecureAIPolicy read) and a non-null
 *   root field, so a refusal there would null every other field beside it.
 *   It gets a document of its own.
 * - A year of activity or inventory took 13 to 22 s on a busy tenant, so these
 *   reads get a longer per-attempt timeout than the client's 30 s.
 */

export const AI_DEFENSE_TIMEOUT_MS = 90_000;

/** Settings, inventory summary and blocked and warned counts by risk for the window. */
export const AI_DEFENSE_OVERVIEW = `query ToolkitAiDefenseOverview($timeRange: SecureAITimeRange) {
  secureAITenantSettings {
    onboarding { status }
    licenseState
    licenseType
    licenseExpiryDate
    gracePeriodEndsAt
  }
  inventorySummary(filter: { timeRange: $timeRange }) {
    apps { totalApps criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk errorRisk trainsOnData unsanctionedCount }
    users { totalUsers criticalRisk highRisk mediumRisk lowRisk infoRisk unknownRisk withViolations unsanctionedCount }
  }
  all: activities(filter: { timeRange: $timeRange }, first: 1) { totalCount }
  unsanctioned: activities(filter: { timeRange: $timeRange, isUnsanctioned: true }, first: 1) { totalCount }
  blocked: activities(filter: { timeRange: $timeRange, actions: [BLOCKED] }, first: 1) { totalCount }
  blockedCritical: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [CRITICAL] }, first: 1) { totalCount }
  blockedHigh: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [HIGH] }, first: 1) { totalCount }
  blockedMedium: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [MEDIUM] }, first: 1) { totalCount }
  blockedLow: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [LOW] }, first: 1) { totalCount }
  blockedInfo: activities(filter: { timeRange: $timeRange, actions: [BLOCKED], risks: [INFO] }, first: 1) { totalCount }
  warned: activities(filter: { timeRange: $timeRange, actions: [WARNED] }, first: 1) { totalCount }
  warnedCritical: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [CRITICAL] }, first: 1) { totalCount }
  warnedHigh: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [HIGH] }, first: 1) { totalCount }
  warnedMedium: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [MEDIUM] }, first: 1) { totalCount }
  warnedLow: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [LOW] }, first: 1) { totalCount }
  warnedInfo: activities(filter: { timeRange: $timeRange, actions: [WARNED], risks: [INFO] }, first: 1) { totalCount }
}`;

/** The top 20 apps and users by activity (with each user's actor id, for the flow read), and the newest 50 blocked or warned activities, for the window. */
export const AI_DEFENSE_DETAIL = `query ToolkitAiDefenseDetail($timeRange: SecureAITimeRange) {
  appInventory(filter: { timeRange: $timeRange }, sort: { field: USAGE, order: DESC }, limit: 20, offset: 0) {
    totalCount
    entries { id name provider risk usage uniqueUsers lastSeen unsanctionedCount }
  }
  userInventory(filter: { timeRange: $timeRange }, sort: { field: USAGE, order: DESC }, limit: 20, offset: 0) {
    totalCount
    entries { id name risk appsUsed usage policyViolations topApp lastSeen unsanctionedCount }
  }
  activities(filter: { timeRange: $timeRange, actions: [BLOCKED, WARNED] }, sort: { field: TIMESTAMP, order: DESC }, first: 50) {
    totalCount
    activities {
      timestamp { startTime }
      actor { name type }
      application { id name }
      action
      policy
      device { name platform }
      risk
      aggregationCount
    }
  }
}`;

/** Slots in the flow read: the top 10 apps and the top 10 users, each counted blocked and warned. */
export const AI_DEFENSE_FLOW_SLOTS = 10;

/** A slot with no app or user takes this id, which matches nothing, so its counts are 0. */
export const AI_DEFENSE_FLOW_UNUSED = "toolkit-unused-slot";

/**
 * Blocked and warned counts for each of the top 10 apps (by app id) and the
 * top 10 users (by actor id) for the window, so the AI usage flow can say
 * which apps and which people AI Defense stopped. The Activity API has no
 * group by, so each count is its own aliased activities total, all in one
 * call. Every slot is a required variable: an empty or missing id list would
 * apply no filter and count everything, so unused slots get
 * AI_DEFENSE_FLOW_UNUSED instead. Allowed is each app's or user's usage less
 * these two.
 */
export const AI_DEFENSE_FLOW = `query ToolkitAiDefenseFlow(
  $timeRange: SecureAITimeRange
  $app0: ID! $app1: ID! $app2: ID! $app3: ID! $app4: ID! $app5: ID! $app6: ID! $app7: ID! $app8: ID! $app9: ID!
  $user0: String! $user1: String! $user2: String! $user3: String! $user4: String! $user5: String! $user6: String! $user7: String! $user8: String! $user9: String!
) {
  app0Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app0], actions: [BLOCKED] }, first: 1) { totalCount }
  app0Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app0], actions: [WARNED] }, first: 1) { totalCount }
  app1Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app1], actions: [BLOCKED] }, first: 1) { totalCount }
  app1Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app1], actions: [WARNED] }, first: 1) { totalCount }
  app2Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app2], actions: [BLOCKED] }, first: 1) { totalCount }
  app2Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app2], actions: [WARNED] }, first: 1) { totalCount }
  app3Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app3], actions: [BLOCKED] }, first: 1) { totalCount }
  app3Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app3], actions: [WARNED] }, first: 1) { totalCount }
  app4Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app4], actions: [BLOCKED] }, first: 1) { totalCount }
  app4Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app4], actions: [WARNED] }, first: 1) { totalCount }
  app5Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app5], actions: [BLOCKED] }, first: 1) { totalCount }
  app5Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app5], actions: [WARNED] }, first: 1) { totalCount }
  app6Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app6], actions: [BLOCKED] }, first: 1) { totalCount }
  app6Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app6], actions: [WARNED] }, first: 1) { totalCount }
  app7Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app7], actions: [BLOCKED] }, first: 1) { totalCount }
  app7Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app7], actions: [WARNED] }, first: 1) { totalCount }
  app8Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app8], actions: [BLOCKED] }, first: 1) { totalCount }
  app8Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app8], actions: [WARNED] }, first: 1) { totalCount }
  app9Blocked: activities(filter: { timeRange: $timeRange, applicationIds: [$app9], actions: [BLOCKED] }, first: 1) { totalCount }
  app9Warned: activities(filter: { timeRange: $timeRange, applicationIds: [$app9], actions: [WARNED] }, first: 1) { totalCount }
  user0Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user0], actions: [BLOCKED] }, first: 1) { totalCount }
  user0Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user0], actions: [WARNED] }, first: 1) { totalCount }
  user1Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user1], actions: [BLOCKED] }, first: 1) { totalCount }
  user1Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user1], actions: [WARNED] }, first: 1) { totalCount }
  user2Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user2], actions: [BLOCKED] }, first: 1) { totalCount }
  user2Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user2], actions: [WARNED] }, first: 1) { totalCount }
  user3Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user3], actions: [BLOCKED] }, first: 1) { totalCount }
  user3Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user3], actions: [WARNED] }, first: 1) { totalCount }
  user4Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user4], actions: [BLOCKED] }, first: 1) { totalCount }
  user4Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user4], actions: [WARNED] }, first: 1) { totalCount }
  user5Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user5], actions: [BLOCKED] }, first: 1) { totalCount }
  user5Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user5], actions: [WARNED] }, first: 1) { totalCount }
  user6Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user6], actions: [BLOCKED] }, first: 1) { totalCount }
  user6Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user6], actions: [WARNED] }, first: 1) { totalCount }
  user7Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user7], actions: [BLOCKED] }, first: 1) { totalCount }
  user7Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user7], actions: [WARNED] }, first: 1) { totalCount }
  user8Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user8], actions: [BLOCKED] }, first: 1) { totalCount }
  user8Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user8], actions: [WARNED] }, first: 1) { totalCount }
  user9Blocked: activities(filter: { timeRange: $timeRange, actorIds: [$user9], actions: [BLOCKED] }, first: 1) { totalCount }
  user9Warned: activities(filter: { timeRange: $timeRange, actorIds: [$user9], actions: [WARNED] }, first: 1) { totalCount }
}`;

/** How many AI Defense policies the tenant has, how many are enabled, how many failed to enforce. */
export const AI_DEFENSE_POLICIES = `query ToolkitAiDefensePolicies {
  policies(first: 1) { totalCount enabledCount failedCount }
}`;
