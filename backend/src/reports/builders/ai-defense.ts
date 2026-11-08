/**
 * The executive summary's AI Defense section: blocked and warned AI activity
 * by risk, the AI apps and the people using them, policies and licence, and
 * a row per tenant for partners. Built from the dashboard cache, which keeps
 * one 7-day AI Defense read per tenant. A tenant without AI Defense gets one
 * plain line saying why.
 */

import { AI_RISK_LABEL, aiDefenseView, type AiViewState } from "../../mappers/ai-defense.js";
import { asOfText, cachedAsOf, kpi, section, table, type BuildContext } from "../context.js";
import { formatDate, formatNumber, plural } from "../format.js";
import type { Block, ReportDocument, ReportSection } from "../types.js";

const STATE: Record<AiViewState, string> = { active: "Set up", "not-set-up": "Not set up", "not-licensed": "Licence expired", unavailable: "Not on Sophos Fusion", "no-access": "No access", pending: "Not read yet", none: "Not set up" };

export function aiDefenseSection(ctx: BuildContext): { section: ReportSection; provenance: ReportDocument["provenance"][number] } {
  const tz = ctx.tz;
  const tenants = ctx.scope.tenants;
  const all = ctx.scope.all;
  const m = aiDefenseView(tenants.map((t) => ({ tenantId: t.id, tenantName: all ? t.name : undefined, record: ctx.provider.get("aidefense", t.id) })));
  const asOf = cachedAsOf(ctx.provider, "aidefense", tenants);
  const provenance = { label: "AI Defense", detail: `Cached ${asOfText(asOf, tz)}, last 7 days`, asOf };

  const tenantTable = () =>
    table(
      "ai-tenants",
      "AI Defense by tenant",
      [
        { key: "tenant", label: "Tenant", width: 2.6 },
        { key: "state", label: "AI Defense", width: 1.4 },
        { key: "total", label: "AI activity", format: "number", width: 1 },
        { key: "blocked", label: "Blocked", format: "number", width: 0.9 },
        { key: "warned", label: "Warned", format: "number", width: 0.9 },
        { key: "apps", label: "AI apps", format: "number", width: 0.8 },
        { key: "users", label: "Users", format: "number", width: 0.8 },
        { key: "policies", label: "Policies", format: "number", width: 0.8 },
      ],
      m.tenantRows.map((t) => ({ tenant: t.name, state: STATE[t.state], total: t.total, blocked: t.blocked, warned: t.warned, apps: t.apps, users: t.users, policies: t.policies })),
      { pdfRows: 60 },
    );

  if (m.state !== "active") {
    const text = m.note ?? (all ? "AI Defense has not been read for these tenants yet." : "AI Defense has not been read for this tenant yet.");
    const blocks: Block[] = [{ kind: "note", tone: "gap", text }];
    if (all) blocks.push(tenantTable());
    return { section: section("ai", "AI Defense", blocks), provenance };
  }

  const a = m.activity;
  const critHigh = (x: { critical: number; high: number }) => x.critical + x.high;
  const risks = m.risks.filter((r) => r.blocked || r.warned || (r.risk !== "info" && r.risk !== "unknown"));
  const blocks: Block[] = [
    {
      kind: "kpis",
      items: [
        kpi("AI activity", formatNumber(a.total)),
        kpi("Blocked", formatNumber(a.blocked), `${formatNumber(critHigh(a.blockedByRisk))} critical or high risk`, a.blocked ? "bad" : undefined),
        kpi("Warned", formatNumber(a.warned), `${formatNumber(critHigh(a.warnedByRisk))} critical or high risk`, a.warned ? "warn" : undefined),
        kpi("Unsanctioned", formatNumber(a.unsanctioned), "Allowed for an app no policy covers", a.unsanctioned ? "warn" : undefined),
        kpi("AI apps", formatNumber(m.apps.total), all ? "Counted per tenant" : `${formatNumber(critHigh(m.apps.byRisk))} critical or high risk`),
        kpi("Users", formatNumber(m.users.total), `${formatNumber(m.users.withViolations)} blocked or warned`),
      ],
    },
    {
      kind: "series",
      title: "Blocked and warned AI activity by risk",
      unit: "activities",
      series: [
        { key: "blocked", label: "Blocked", tone: "bad" },
        { key: "warned", label: "Warned", tone: "warn" },
      ],
      buckets: risks.map((r) => ({ label: AI_RISK_LABEL[r.risk], values: [r.blocked, r.warned] })),
      empty: "Nothing was blocked or warned in the last 7 days.",
    },
  ];
  const facts: Array<{ label: string; value: string }> = [];
  if (m.policies) facts.push({ label: "Policies", value: `${formatNumber(m.policies.total)}, ${formatNumber(m.policies.enabled)} enabled${m.policies.failed ? `, ${formatNumber(m.policies.failed)} failed to apply` : ""}` });
  if (m.licence) {
    const grace = m.licence.state === "GRACE_PERIOD" && m.licence.graceEndsAt;
    const end = m.licence.expiresAt ? `ends ${formatDate(Date.parse(m.licence.expiresAt), tz)}` : m.licence.state === "ACTIVE" ? "active" : "state not known";
    facts.push({ label: "Licence", value: `${m.licence.type ? `${m.licence.type.charAt(0)}${m.licence.type.slice(1).toLowerCase()}, ` : ""}${grace ? `in its grace period to ${formatDate(Date.parse(m.licence.graceEndsAt!), tz)}` : end}` });
  }
  if (m.apps.trainsOnData !== null) facts.push({ label: "Train on user data", value: `${plural(m.apps.trainsOnData, "app")} in use, opt-outs included` });
  if (facts.length) blocks.push({ kind: "facts", title: "Policies and licence", items: facts });
  blocks.push(
    table(
      "ai-apps",
      "Top AI apps",
      [
        { key: "app", label: "App", width: 2.2 },
        { key: "provider", label: "Provider", width: 1.6 },
        { key: "risk", label: "Risk", width: 0.9 },
        { key: "usage", label: "Activity", format: "number", width: 1 },
        { key: "users", label: "Users", format: "number", width: 0.8 },
        { key: "unsanctioned", label: "Unsanctioned", format: "number", width: 1.1 },
        ...(all ? [{ key: "tenants", label: "Tenants", format: "number" as const, width: 0.8 }] : []),
      ],
      m.topApps.map((x) => ({ app: x.name, provider: x.provider, risk: AI_RISK_LABEL[x.risk], usage: x.usage, users: x.users, unsanctioned: x.unsanctioned, ...(all ? { tenants: x.tenants } : {}) })),
      { pdfRows: 10, empty: "No AI app was used in the last 7 days.", ...(all ? { note: "Each tenant's top apps added up; the AI apps figure above counts an app once per tenant." } : {}) },
    ),
    table(
      "ai-users",
      "Top AI users",
      [
        { key: "user", label: "User", width: 2.6 },
        ...(all ? [{ key: "tenant", label: "Tenant", width: 1.8 }] : []),
        { key: "risk", label: "Worst risk", width: 0.9 },
        { key: "apps", label: "Apps", format: "number", width: 0.6 },
        { key: "usage", label: "Activity", format: "number", width: 0.9 },
        { key: "violations", label: "Policy violations", format: "number", width: 1.2 },
        { key: "topApp", label: "Top app", width: 1.6 },
      ],
      m.topUsers.map((u) => ({ user: u.name, ...(all ? { tenant: u.tenantName ?? "" } : {}), risk: AI_RISK_LABEL[u.risk], apps: u.apps, usage: u.usage, violations: u.violations, topApp: u.topApp })),
      { pdfRows: 10, empty: "Nobody used an AI app in the last 7 days." },
    ),
  );
  if (all) blocks.push(tenantTable());
  blocks.push({ kind: "note", tone: "info", text: "AI Defense figures cover the last 7 days whatever window the report uses: the toolkit keeps one 7-day read per tenant. Counts are AI Defense activities, and one activity can gather several related events. A network address stands in for a user AI Defense could not name." });
  const lead = all ? `${plural(m.scope.active, "tenant")} of ${formatNumber(m.scope.tenants)} ${m.scope.active === 1 ? "has" : "have"} AI Defense set up.` : "AI activity Sophos AI Defense saw in the last 7 days.";
  return { section: section("ai", "AI Defense", blocks, lead), provenance };
}
