// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// the handler bodies in src/tools/fusion-cases.ts at commit 9471c18. MIT License,
// Copyright (c) 2026; the full notice is in LICENSE-MIT at the root of this package.

/**
 * Fusion Cases GraphQL v2 for the app: list, detail, summary, comments,
 * reference data, create, update, comment, link and evidence. The rules each
 * method enforces before it writes were measured on a live tenant on
 * 22/09/2026 and are the MCP server's rules, minus its tool plumbing:
 *
 * - A closed case is frozen apart from status, verdicts, secondary status,
 *   secondary reasons and archive.
 * - Closing needs a verdict when the case type supports verdicts.
 * - Leaving a closed status needs the verdict cleared in the same update, and
 *   only an empty string clears it.
 * - A case never returns to new once it has left it.
 * - Tags replace on write, so an addition is merged with the current list.
 * - An archived case refuses every update until it is unarchived.
 * - managedBy is fixed at creation and has no default.
 * - Unrecognised @mentions are dropped by the API without an error.
 *
 * A tenant still on the legacy cases v1 API is served through
 * LegacyCasesService instead, with its cases in the same shapes: list and
 * create go by the reference data's `api`, and every call on one case by the
 * case ID's shape, since only v1 hands out IDs like 1-598868. What v1 can't
 * do is refused with LegacyCasesError before anything is sent; see the v1
 * section at the end of the class.
 */

import { FusionGraphQLError, type FusionClient } from "../client/fusion-client.js";
import { SophosApiRequestError } from "../client/sophos-client.js";
import type { CaseReferenceData, CaseReferenceDataCache, CasesApi } from "../fusion/case-reference-data.js";
import { buildCasesQl } from "../fusion/cases-ql.js";
import {
  RESOURCE_NAME_EXAMPLE,
  isCaseShortId,
  isLegacyCaseId,
  isResourceName,
  isUuid,
  looksLikeEmail,
  mergeTags,
  normaliseCaseSeverity,
  parseMentionTokens,
  qlString,
} from "../fusion/format.js";
import { buildMitreSummary, type MitreSummary } from "../fusion/mitre.js";
import {
  LEGACY_CASE_TYPES,
  LEGACY_CREATE_STATUSES,
  LEGACY_OPEN_STATUSES,
  LEGACY_OVERVIEW_MAX,
  LEGACY_SEVERITY_VALUE,
  LEGACY_UNCREATABLE_TYPES,
  isLegacyDetectionId,
  legacyCaseToFusion,
  legacyMitreSummary,
  legacyNameProblem,
  legacySeverityName,
  legacyStatus,
  legacyType,
  legacyVerdict,
  type LegacyCaseCreate,
  type LegacyCasePatch,
  type LegacyCaseSeverity,
  type LegacyCaseStatus,
  type LegacyDetection,
} from "../legacy/cases-v1.js";
import { LEGACY_PAGE_MAX, type LegacyCasesService, type RecentDetectionsOptions } from "./legacy-cases.js";
import {
  ADD_CASE_COMMENT,
  ADD_EVIDENCE_TO_CASE,
  CASE_PRIMARY_VERDICTS_FOR,
  CREATE_CASE,
  CREATE_CASE_LINK,
  GET_CASE,
  GET_CASE_EVIDENCE,
  LIST_CASES,
  LIST_CASE_COMMENTS,
  REMOVE_EVIDENCE_FROM_CASE,
  UPDATE_CASE,
} from "../fusion/queries/cases.js";
import { DETECTIONS_BY_ID } from "../fusion/queries/detections.js";
import type {
  FusionAddCaseCommentResponse,
  FusionAddEvidenceResponse,
  FusionCasePrimaryStatus,
  FusionCaseComment,
  FusionCaseCommentsResponse,
  FusionCaseDetail,
  FusionCaseEvidence,
  FusionCaseEvidenceResponse,
  FusionCaseLink,
  FusionCasePrimaryVerdictsResponse,
  FusionCaseResponse,
  FusionCaseSummary,
  FusionCasesResponse,
  FusionCreateCaseLinkResponse,
  FusionCreateCaseResponse,
  FusionDetectionRecord,
  FusionDetectionsByIdResponse,
  FusionEvidenceMutationResult,
  FusionReferenceItem,
  FusionRemoveEvidenceResponse,
  FusionUpdateCaseResponse,
} from "../fusion/types.js";

/** Group mention tokens that resolved on a live tenant (22/09/2026). */
export const KNOWN_MENTION_GROUPS = ["@authorized_contacts", "@customer", "@sophos"] as const;

export type ManagedBy = "PROVIDER" | "CUSTOMER";

/** 2, 4, 6, 8, 10 or informational, low, medium, high, critical. */
export type CaseSeverityInput = number | string;

export interface CaseListOptions {
  /** Case type name or UUID. */
  type?: string;
  /** Primary status names or UUIDs (any of). */
  status?: string[];
  /** Primary verdict name or UUID. */
  verdict?: string;
  severity?: CaseSeverityInput;
  severityMin?: CaseSeverityInput;
  openOnly?: boolean;
  /** Subject ID, never an email. */
  assigneeId?: string;
  unassigned?: boolean;
  titleContains?: string;
  tag?: string;
  /** ISO 8601. */
  createdAfter?: string;
  createdBefore?: string;
  updatedAfter?: string;
  /** Raw QL, combined with the filters above using "and". */
  query?: string;
  /** "<field> asc|desc". */
  sort?: string;
  /** Offset paging (default 1). Ignored when `after` is given. */
  page?: number;
  /** 1 to 100, default 50. */
  perPage?: number;
  /** endCursor from a previous page, for cursor paging. */
  after?: string;
}

export interface CaseListResult {
  total: number;
  hasNextPage: boolean;
  endCursor: string | null;
  /** The QL string sent, or null when nothing filtered. */
  ql: string | null;
  cases: FusionCaseSummary[];
  warnings: string[];
}

export interface CaseSummaryResult {
  case: FusionCaseDetail;
  evidence: FusionCaseEvidence | null;
  /** Detections attached to the case. */
  detectionsTotal: number;
  /** Up to maxDetections of them, resolved in one call. Severity here is the 0 to 1 scale. */
  detections: FusionDetectionRecord[];
  mitre: MitreSummary | null;
  /**
   * A cases v1 case's detections, up to maxDetections, in v1's own shape:
   * their 0 to 10 severity is neither the case scale nor the Fusion 0 to 1
   * score. `detections` is empty for a v1 case.
   */
  legacyDetections?: LegacyDetection[];
  warnings: string[];
}

export interface CaseCommentsResult {
  caseId: string;
  total: number;
  totalUnread: number;
  comments: FusionCaseComment[];
  warnings: string[];
}

export interface NewCaseInput {
  /** 1 to 256 characters. */
  title: string;
  /** Case type name or UUID. */
  type: string;
  severity: CaseSeverityInput;
  /** PROVIDER hands the case to Sophos MDR, CUSTOMER keeps it self managed. Cannot change later. */
  managedBy: ManagedBy;
  /** Initial primary status name or UUID. Defaults by managedBy. */
  status?: string;
  /** Subject ID or @mention. */
  assigneeId?: string;
  /** Markdown. */
  keyFindings?: string;
  tags?: string[];
  /** Six section resource names. */
  detectionIds?: string[];
  detectionsSearchQuery?: string;
  /** Six section resource names. */
  eventIds?: string[];
  searchQueries?: string[];
  hostIds?: string[];
}

export interface CaseUpdate {
  title?: string;
  severity?: CaseSeverityInput;
  /** Primary status name or UUID. */
  status?: string;
  /** Primary verdict name or UUID; "" clears the recorded verdict. */
  verdict?: string;
  closeReason?: string;
  /** Subject ID or @mention; "" clears. */
  assigneeId?: string;
  /** Markdown; replaces the key findings document. */
  keyFindings?: string;
  /** Tags to add, merged with the current list unless replaceTags is true. */
  tags?: string[];
  replaceTags?: boolean;
  /** true archives a closed case, false unarchives. */
  archived?: boolean;
}

export interface CaseUpdateResult {
  case: FusionCaseDetail;
  /** What the service did on the caller's behalf, in words. */
  notes: string[];
  warnings: string[];
  /** x-request-id of the last updateCase call. */
  requestId: string | null;
  /** x-correlation-id of a cases v1 write. */
  correlationId?: string | null;
}

export interface CaseCommentResult {
  comment: FusionCaseComment;
  /** Mentions the API stored, so the ones that notified someone. */
  mentionsResolved: string[];
  /** Tokens in the text the API dropped; they notified nobody. */
  mentionsUnresolved: string[];
  warnings: string[];
  requestId: string | null;
}

export interface CaseCreateResult {
  case: FusionCaseDetail;
  warnings: string[];
  /** createCase calls made, counting retries of the partnerPreferences fault. */
  attempts: number;
  requestId: string | null;
  /** x-correlation-id of a cases v1 create. */
  correlationId?: string | null;
}

export interface CaseCreateOptions {
  /** Called before each retry of the partnerPreferences fault, with the attempt about to run and the bound. */
  onAttempt?: (attempt: number, limit: number) => void;
}

export interface NewCaseLink {
  url: string;
  title?: string;
  /** Linked system, for example ServiceNow. */
  type?: string;
  /** ID in the linked system. */
  reference?: string;
  /** Needs a partner or MDR provider credential. */
  internal?: boolean;
}

export interface EvidenceToAdd {
  detectionIds?: string[];
  detectionsSearchQuery?: string;
  eventIds?: string[];
  hostIds?: string[];
  searchQueries?: string[];
}

export interface EvidenceToRemove {
  detectionIds?: string[];
  eventIds?: string[];
  /** Asset source IDs from the case evidence, not host IDs. */
  assetIds?: string[];
  searchQueries?: string[];
  /** Remove every piece of evidence. Cannot be combined with the lists. */
  all?: boolean;
}

/** The Fusion case does not exist in the tenant, or the short ID matched nothing. */
export class CaseNotFoundError extends Error {
  constructor(caseRef: string, tenantId: string) {
    super(`Fusion case ${caseRef} not found in tenant ${tenantId}.`);
    this.name = "CaseNotFoundError";
  }
}

/**
 * Something the legacy cases v1 API can't do, for a tenant still on it.
 * Thrown before anything is sent. `action` completes "The old Sophos cases
 * can't ...", and `userMessage` is that sentence for a person.
 */
export class LegacyCasesError extends Error {
  readonly userMessage: string;
  constructor(
    readonly tenantId: string,
    readonly action: string
  ) {
    super(`The old Sophos cases (cases v1), which tenant ${tenantId} is still on, can't ${action}. Nothing was sent.`);
    this.name = "LegacyCasesError";
    this.userMessage = `The old Sophos cases can't ${action}. Nothing was sent.`;
  }
}

const TITLE_MAX = 256;

export class CasesService {
  /** Without `legacy` every tenant is served by Cases v2, as the unit tests of the v2 rules expect. */
  constructor(
    private client: FusionClient,
    private referenceData: CaseReferenceDataCache,
    private legacy?: LegacyCasesService
  ) {}

  /** Which API holds the tenant's cases. See CaseReferenceData.api for how it is decided. */
  async casesApi(tenantId: string, options: { refresh?: boolean } = {}): Promise<CasesApi> {
    return (await this.referenceData.get(tenantId, options)).api;
  }

  /**
   * Whether the tenant's cases are on Sophos Fusion (Cases v2). A tenant that
   * isn't returns HTTP 200 with no case types and no error (Phase 0,
   * 22/09/2026), so emptiness is the Fusion signal.
   */
  async fusionAvailable(tenantId: string, options: { refresh?: boolean } = {}): Promise<boolean> {
    const { api, types } = await this.referenceData.get(tenantId, options);
    return api === "v2" && types.length > 0;
  }

  /** Case types, primary statuses and primary verdicts, cached per tenant for 15 minutes. */
  async getReferenceData(tenantId: string, options: { refresh?: boolean } = {}): Promise<CaseReferenceData> {
    return this.referenceData.get(tenantId, options);
  }

  /** Verdicts valid for closing a case of this type into this closed status. */
  async verdictsFor(tenantId: string, typeId: string, primaryStatusId: string): Promise<FusionReferenceItem[]> {
    if (this.legacy && (LEGACY_CASE_TYPES as readonly string[]).includes(typeId)) {
      throw new LegacyCasesError(tenantId, "record a verdict");
    }
    const { data } = await this.client.query<FusionCasePrimaryVerdictsResponse>(
      tenantId,
      CASE_PRIMARY_VERDICTS_FOR,
      { arguments: { typeId, primaryStatusId } }
    );
    return data.casePrimaryVerdicts?.primaryVerdicts ?? [];
  }

  async list(tenantId: string, options: CaseListOptions = {}): Promise<CaseListResult> {
    const legacy = await this.legacyFor(tenantId);
    if (legacy) return this.listLegacy(legacy, tenantId, options);
    const typeId = options.type ? await this.referenceData.resolveTypeId(tenantId, options.type) : undefined;
    const statusIds = options.status
      ? await Promise.all(options.status.map((s) => this.referenceData.resolveStatusId(tenantId, s)))
      : undefined;
    const verdictId = options.verdict
      ? await this.referenceData.resolveVerdictId(tenantId, options.verdict)
      : undefined;

    const ql = buildCasesQl({
      query: options.query,
      typeId,
      statusIds,
      verdictId,
      severity: options.severity !== undefined ? normaliseCaseSeverity(options.severity) : undefined,
      severityMin: options.severityMin !== undefined ? normaliseCaseSeverity(options.severityMin) : undefined,
      openOnly: options.openOnly,
      assigneeId: options.assigneeId,
      unassigned: options.unassigned,
      titleContains: options.titleContains,
      tag: options.tag,
      createdAfter: options.createdAfter,
      createdBefore: options.createdBefore,
      updatedAfter: options.updatedAfter,
      sort: options.sort,
    });

    const perPage = clampPerPage(options.perPage);
    const pagination = options.after
      ? { cursor: { first: perPage, after: options.after } }
      : { offset: { page: Math.max(1, options.page ?? 1), perPage } };

    const { data, warnings } = await this.client.query<FusionCasesResponse>(tenantId, LIST_CASES, {
      arguments: { ...(ql ? { query: ql } : {}), pagination },
    });

    return {
      total: data.cases.totalCount,
      hasNextPage: data.cases.pageInfo.hasNextPage,
      endCursor: data.cases.pageInfo.endCursor,
      ql: ql ?? null,
      cases: data.cases.cases,
      warnings,
    };
  }

  /** Turns a UUID or short ID (CSE00001) into the case UUID. A short ID costs one search. */
  async resolveCaseId(tenantId: string, caseRef: string): Promise<{ id: string; warnings: string[] }> {
    const value = caseRef.trim();
    if (this.legacy && isLegacyCaseId(value)) return { id: value, warnings: [] };
    if (isUuid(value)) return { id: value, warnings: [] };

    if (isCaseShortId(value)) {
      const shortId = value.toUpperCase();
      const { data, warnings } = await this.client.query<FusionCasesResponse>(tenantId, LIST_CASES, {
        arguments: {
          query: `shortId = ${qlString(shortId)}`,
          pagination: { offset: { page: 1, perPage: 1 } },
        },
      });
      const found = data.cases.cases[0];
      if (!found) throw new CaseNotFoundError(shortId, tenantId);
      return { id: found.id, warnings };
    }

    if (isLegacyCaseId(value)) {
      throw new Error(
        `${value} looks like a Classic Sophos Central case ID. Fusion holds a separate case set and Classic IDs do not resolve here.`
      );
    }

    throw new Error(
      `Unrecognised case ID ${JSON.stringify(value)}. Expected a Fusion case UUID or a short ID like CSE00001.`
    );
  }

  async get(tenantId: string, caseRef: string): Promise<{ case: FusionCaseDetail; warnings: string[] }> {
    const legacy = this.legacyForCase(caseRef);
    if (legacy) return { case: await this.readLegacy(legacy, tenantId, caseRef), warnings: [] };
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const read = await this.readCase(tenantId, resolved.id, caseRef);
    return { case: read.case, warnings: [...resolved.warnings, ...read.warnings] };
  }

  async getEvidence(tenantId: string, caseRef: string): Promise<{ evidence: FusionCaseEvidence; warnings: string[] }> {
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "list evidence by ID; read the case summary instead");
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const { data, warnings } = await this.client
      .query<FusionCaseEvidenceResponse>(tenantId, GET_CASE_EVIDENCE, { arguments: { id: resolved.id } })
      .catch((error: unknown) => rethrowNotFound(error, caseRef, tenantId));
    if (!data.caseEvidence) throw new CaseNotFoundError(caseRef, tenantId);
    return { evidence: data.caseEvidence, warnings: [...resolved.warnings, ...warnings] };
  }

  /**
   * The case, its evidence, up to maxDetections attached detections resolved
   * in one batched call, and the MITRE roll-up built from them. The case and
   * its evidence are two calls on purpose: two case-scoped root fields in one
   * document fail with "conn busy" (live tenant, 21/09/2026).
   */
  async getSummary(
    tenantId: string,
    caseRef: string,
    options: { includeDetections?: boolean; maxDetections?: number } = {}
  ): Promise<CaseSummaryResult> {
    const includeDetections = options.includeDetections ?? true;
    const maxDetections = Math.min(100, Math.max(1, options.maxDetections ?? 50));
    const legacy = this.legacyForCase(caseRef);
    if (legacy) return this.summaryLegacy(legacy, tenantId, caseRef, includeDetections, maxDetections);
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const warnings = [...resolved.warnings];

    const read = await this.readCase(tenantId, resolved.id, caseRef);
    warnings.push(...read.warnings);

    const evidenceResult = await this.client.query<FusionCaseEvidenceResponse>(tenantId, GET_CASE_EVIDENCE, {
      arguments: { id: resolved.id },
    });
    warnings.push(...evidenceResult.warnings);
    const evidence = evidenceResult.data.caseEvidence;
    const attached = evidence?.detectionsEvidence ?? [];
    const toResolve = attached.map((e) => e.detectionId).slice(0, maxDetections);

    let detections: FusionDetectionRecord[] = [];
    let mitre: MitreSummary | null = null;
    if (includeDetections && toResolve.length > 0) {
      const result = await this.client.query<FusionDetectionsByIdResponse>(tenantId, DETECTIONS_BY_ID, {
        in: { iDs: toResolve },
      });
      warnings.push(...result.warnings);
      detections = result.data.detectionRetrieveById?.alerts?.list ?? [];
      mitre = buildMitreSummary(detections);
    }

    return {
      case: read.case,
      evidence,
      detectionsTotal: attached.length,
      detections,
      mitre,
      warnings,
    };
  }

  async listComments(
    tenantId: string,
    caseRef: string,
    options: {
      visibility?: "ALL" | "INTERNAL" | "NOT_INTERNAL";
      order?: "asc" | "desc";
      authorIds?: string[];
      page?: number;
      perPage?: number;
    } = {}
  ): Promise<CaseCommentsResult> {
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "hold comments");
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const page = Math.max(1, options.page ?? 1);
    const perPage = clampPerPage(options.perPage ?? 25);
    const { data, warnings } = await this.client.query<FusionCaseCommentsResponse>(tenantId, LIST_CASE_COMMENTS, {
      arguments: {
        caseId: resolved.id,
        visibility: options.visibility ?? "ALL",
        page,
        perPage,
        // PaginationOrder is ASCENDING or DESCENDING; "ASC" is not accepted.
        ...(options.order ? { orderBy: options.order === "asc" ? "ASCENDING" : "DESCENDING" } : {}),
        ...(options.authorIds?.length ? { authorIds: options.authorIds } : {}),
      },
    });
    return {
      caseId: resolved.id,
      total: data.caseComments.totalCount,
      totalUnread: data.caseComments.totalUnreadCount,
      comments: data.caseComments.comments,
      warnings: [...resolved.warnings, ...warnings],
    };
  }

  /**
   * Creates a case. managedBy is required and always sent: omitting it
   * creates an unclaimed case, and it cannot be changed afterwards. The client
   * retries the intermittent partnerPreferences fault on this call (74% of
   * first attempts on 22/09/2026) up to its bound, so a create can take tens
   * of seconds. A timeout or 5xx is not retried: that attempt may have
   * created the case. A tenant still on the legacy cases v1 API gets a v1
   * create instead, sent once (see createLegacy).
   */
  async create(tenantId: string, input: NewCaseInput, options: CaseCreateOptions = {}): Promise<CaseCreateResult> {
    const legacy = await this.legacyFor(tenantId);
    if (legacy) return this.createLegacy(legacy, tenantId, input);
    const createInput = await this.buildCreateCaseInput(tenantId, input);
    const result = await this.client
      .query<FusionCreateCaseResponse>(
        tenantId,
        CREATE_CASE,
        { input: createInput },
        { idempotent: false, onTransientRetry: options.onAttempt }
      )
      .catch(rethrowWithHint);
    if (!result.data.createCase) throw new Error("createCase returned no case.");
    return {
      case: result.data.createCase,
      warnings: result.warnings,
      attempts: result.attempts ?? 1,
      requestId: result.requestId ?? null,
    };
  }

  /**
   * PATCH-style update: only the supplied fields change. Every check runs
   * before the first write, so a refused call changes nothing.
   */
  async update(tenantId: string, caseRef: string, changes: CaseUpdate): Promise<CaseUpdateResult> {
    const legacy = this.legacyForCase(caseRef);
    if (legacy) return this.updateLegacy(legacy, tenantId, caseRef, changes);
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const warnings = [...resolved.warnings];
    const notes: string[] = [];
    if (changes.assigneeId) assertAssignee(changes.assigneeId);
    if (changes.title !== undefined) assertTitle(changes.title);

    const fields: Record<string, unknown> = {};
    if (changes.title !== undefined) fields.title = changes.title;
    if (changes.severity !== undefined) fields.severity = normaliseCaseSeverity(changes.severity);
    if (changes.closeReason !== undefined) fields.closeReason = changes.closeReason;
    if (changes.assigneeId !== undefined) fields.assigneeId = changes.assigneeId;
    if (changes.keyFindings !== undefined) fields.keyFindings = keyFindingsInput(changes.keyFindings);

    const status = changes.status ? await this.referenceData.resolveStatus(tenantId, changes.status) : undefined;
    if (status) fields.primaryStatusId = status.id;
    if (changes.verdict !== undefined) {
      fields.primaryVerdictId =
        changes.verdict === "" ? "" : await this.referenceData.resolveVerdictId(tenantId, changes.verdict);
    }

    if (Object.keys(fields).length === 0 && changes.tags === undefined && changes.archived === undefined) {
      throw new Error("Nothing to update: supply at least one field to change.");
    }

    // One read serves the archived and closed checks, the tag merge, the one
    // way door on new and the reopen rule.
    const read = await this.readCase(tenantId, resolved.id, caseRef);
    warnings.push(...read.warnings);
    const current = read.case;

    if (changes.tags !== undefined) {
      if (changes.replaceTags) {
        fields.tags = changes.tags;
      } else {
        fields.tags = mergeTags(current.tags, changes.tags);
        notes.push(
          `Tags merged with the existing list (${(current.tags ?? []).length} existing); set replaceTags to replace it.`
        );
      }
    }

    if (current.archivedAt && changes.archived !== false) {
      throw new Error(
        "This case is archived and refuses every update. Unarchive it first (archived false, which can be combined with the other changes; the unarchive is applied before them). Nothing was changed."
      );
    }

    // A closed case is frozen apart from status, verdicts, secondary status,
    // secondary reasons and archive. A reopen is refused here rather than done
    // on the caller's behalf, because it is a visible state change.
    const reopening = status !== undefined && !status.isClosed;
    if (current.primaryStatus.isClosed && !reopening) {
      const frozen = (["title", "severity", "assigneeId", "keyFindings", "tags"] as const).filter(
        (key) => key in fields
      );
      if (frozen.length > 0) {
        throw new Error(
          `This case is closed (${current.primaryStatus.name}) and Fusion only allows status, verdict, secondary status, secondary reasons and archive to change while closed; ${frozen.join(", ")} cannot. Reopen it first in its own update, or drop those fields. Nothing was changed.`
        );
      }
    }

    if (status) {
      const currentName = current.primaryStatus.name.toLowerCase();
      if (status.name.toLowerCase() === "new" && currentName !== "new") {
        throw new Error(
          `Fusion cannot move a case back to new once it has left it (current status ${current.primaryStatus.name}). Choose another open status.`
        );
      }
      if (status.isClosed && changes.verdict === undefined) {
        const options = await this.verdictsFor(tenantId, current.type.id, status.id);
        if (options.length > 0) {
          throw new Error(
            `Closing this case requires a verdict. Valid verdicts for its type: ${options
              .map((v) => `${v.name}${v.title ? ` (${v.title})` : ""}`)
              .join(", ")}.`
          );
        }
      }
      if (!status.isClosed && current.primaryStatus.isClosed && current.primaryVerdict && changes.verdict === undefined) {
        // A null verdict satisfies the rule but leaves the stored verdict in
        // place; an empty string clears it (live tenant, 22/09/2026).
        fields.primaryVerdictId = "";
        notes.push(
          `Cleared the recorded verdict ${current.primaryVerdict.name}: Fusion refuses to leave a closed status while a verdict is set. Set a verdict when closing again.`
        );
      }
    }

    let requestId: string | null = null;
    const send = async (input: Record<string, unknown>): Promise<FusionCaseDetail> => {
      const result = await this.client
        .query<FusionUpdateCaseResponse>(tenantId, UPDATE_CASE, { input: { id: resolved.id, ...input } })
        .catch(rethrowWithHint);
      warnings.push(...result.warnings);
      requestId = result.requestId ?? requestId;
      if (!result.data.updateCase) throw new Error("updateCase returned no case.");
      return result.data.updateCase;
    };

    // Unarchive first (an archived case refuses everything), then the field
    // changes, then archive last (an archived case is frozen).
    let updated: FusionCaseDetail | null = null;
    const hasFields = Object.keys(fields).length > 0;
    if (changes.archived === false) {
      updated = await send({ isArchived: false });
      if (hasFields) notes.push("Unarchived first, then applied the other changes.");
    }
    if (hasFields) {
      updated = await send(fields);
    }
    if (changes.archived === true) {
      updated = await send({ isArchived: true });
      if (hasFields) notes.push("Applied the other changes first, then archived.");
    }
    if (!updated) throw new Error("Nothing to update: supply at least one field to change.");

    return { case: updated, notes, warnings, requestId };
  }

  /**
   * Adds a comment. Every recognised @mention in the text notifies its group,
   * even one that only appears in prose; an unrecognised one is dropped by the
   * API without an error, so the stored mentions are compared with the text.
   * A timeout or 5xx is not retried: that attempt may have posted it.
   */
  async addComment(
    tenantId: string,
    caseRef: string,
    text: string,
    options: { internal?: boolean } = {}
  ): Promise<CaseCommentResult> {
    if (!text.trim()) throw new Error("A comment cannot be empty.");
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "hold comments");
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const { data, warnings, requestId } = await this.client
      .query<FusionAddCaseCommentResponse>(
        tenantId,
        ADD_CASE_COMMENT,
        {
          input: {
            caseId: resolved.id,
            comment: text,
            ...(options.internal !== undefined ? { isInternal: options.internal } : {}),
          },
        },
        { idempotent: false }
      )
      .catch(rethrowWithHint);
    if (!data.addCaseComment) throw new Error("addCaseComment returned no comment.");
    const mentions = compareMentions(text, data.addCaseComment);
    return {
      comment: data.addCaseComment,
      mentionsResolved: mentions.resolved,
      mentionsUnresolved: mentions.unresolved,
      warnings: [...resolved.warnings, ...warnings, ...mentions.warnings],
      requestId: requestId ?? null,
    };
  }

  /** Adds a link. A timeout or 5xx is not retried: that attempt may have added it. */
  async createLink(
    tenantId: string,
    caseRef: string,
    link: NewCaseLink
  ): Promise<{ link: FusionCaseLink; caseId: string; warnings: string[]; requestId: string | null }> {
    if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(link.url)) {
      throw new Error(`A case link needs an absolute URL, got ${JSON.stringify(link.url)}.`);
    }
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "hold links");
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const input: Record<string, unknown> = { caseId: resolved.id, url: link.url };
    if (link.title !== undefined) input.title = link.title;
    if (link.type !== undefined) input.type = link.type;
    if (link.reference !== undefined) input.reference = link.reference;
    if (link.internal !== undefined) input.isInternal = link.internal;
    const { data, warnings, requestId } = await this.client
      .query<FusionCreateCaseLinkResponse>(tenantId, CREATE_CASE_LINK, { input }, { idempotent: false })
      .catch(rethrowWithHint);
    if (!data.createCaseLink) throw new Error("createCaseLink returned no link.");
    return {
      link: data.createCaseLink,
      caseId: resolved.id,
      warnings: [...resolved.warnings, ...warnings],
      requestId: requestId ?? null,
    };
  }

  /**
   * Attaches evidence. Asynchronous on the Sophos side: a count read straight
   * after still shows the old number, and a detection brings its linked asset
   * and events with it. The client retries the partnerPreferences fault here
   * too.
   */
  async addEvidence(
    tenantId: string,
    caseRef: string,
    evidence: EvidenceToAdd
  ): Promise<{ result: FusionEvidenceMutationResult; warnings: string[] }> {
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "add evidence to a case");
    assertResourceNames("detectionIds", evidence.detectionIds);
    assertResourceNames("eventIds", evidence.eventIds);
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const input: Record<string, unknown> = { caseId: resolved.id };
    if (evidence.detectionIds?.length) input.detectionIds = evidence.detectionIds;
    if (evidence.detectionsSearchQuery) input.detectionsSearchQuery = evidence.detectionsSearchQuery;
    if (evidence.eventIds?.length) input.eventIds = evidence.eventIds;
    if (evidence.hostIds?.length) input.hostIds = evidence.hostIds;
    if (evidence.searchQueries?.length) input.searchQueries = evidence.searchQueries;
    if (Object.keys(input).length === 1) {
      throw new Error("Supply at least one of detectionIds, detectionsSearchQuery, eventIds, hostIds or searchQueries.");
    }
    const { data, warnings } = await this.client
      .query<FusionAddEvidenceResponse>(tenantId, ADD_EVIDENCE_TO_CASE, { input })
      .catch(rethrowWithHint);
    if (!data.addEvidenceToCase) throw new Error("addEvidenceToCase returned no result.");
    return { result: data.addEvidenceToCase, warnings: [...resolved.warnings, ...warnings] };
  }

  /**
   * Detaches evidence by source ID (the IDs on the case evidence). Any other
   * ID is accepted by the API and removes nothing. Removing a detection leaves
   * the asset and events it brought; `all` removes every category explicitly.
   */
  async removeEvidence(
    tenantId: string,
    caseRef: string,
    evidence: EvidenceToRemove
  ): Promise<{ result: FusionEvidenceMutationResult | null; warnings: string[] }> {
    if (this.legacyForCase(caseRef)) throw new LegacyCasesError(tenantId, "remove evidence from a case");
    const resolved = await this.resolveCaseId(tenantId, caseRef);
    const warnings = [...resolved.warnings];
    const input: Record<string, unknown> = { caseId: resolved.id };
    const explicit = [evidence.detectionIds, evidence.eventIds, evidence.assetIds, evidence.searchQueries].some(
      (list) => list && list.length > 0
    );

    if (evidence.all) {
      if (explicit) throw new Error("all cannot be combined with detectionIds, eventIds, assetIds or searchQueries.");
      const read = await this.client
        .query<FusionCaseEvidenceResponse>(tenantId, GET_CASE_EVIDENCE, { arguments: { id: resolved.id } })
        .catch((error: unknown) => rethrowNotFound(error, caseRef, tenantId));
      warnings.push(...read.warnings);
      const current = read.data.caseEvidence;
      if (!current) throw new CaseNotFoundError(caseRef, tenantId);
      const detectionIds = (current.detectionsEvidence ?? []).map((d) => d.detectionId);
      const eventIds = (current.eventsEvidence ?? []).map((e) => e.eventId);
      const assetIds = (current.assetsEvidence ?? []).map((a) => a.assetId);
      const searchQueries = (current.searchQueriesEvidence ?? []).map((s) => s.searchQueryId);
      if (detectionIds.length) input.detectionIds = detectionIds;
      if (eventIds.length) input.eventIds = eventIds;
      if (assetIds.length) input.assetIds = assetIds;
      if (searchQueries.length) input.searchQueries = searchQueries;
      if (Object.keys(input).length === 1) return { result: null, warnings };
    } else {
      assertResourceNames("detectionIds", evidence.detectionIds);
      assertResourceNames("eventIds", evidence.eventIds);
      if (evidence.detectionIds?.length) input.detectionIds = evidence.detectionIds;
      if (evidence.eventIds?.length) input.eventIds = evidence.eventIds;
      if (evidence.assetIds?.length) input.assetIds = evidence.assetIds;
      if (evidence.searchQueries?.length) input.searchQueries = evidence.searchQueries;
      if (Object.keys(input).length === 1) {
        throw new Error("Supply at least one of detectionIds, eventIds, assetIds or searchQueries, or all.");
      }
    }

    const { data, warnings: removeWarnings } = await this.client
      .query<FusionRemoveEvidenceResponse>(tenantId, REMOVE_EVIDENCE_FROM_CASE, { input })
      .catch(rethrowWithHint);
    warnings.push(...removeWarnings);
    if (!data.removeEvidenceFromCase) throw new Error("removeEvidenceFromCase returned no result.");
    return { result: data.removeEvidenceFromCase, warnings };
  }

  // --- the legacy cases v1 API ---

  /**
   * The tenant's detections from the last 30 days, newest first, for opening
   * a case on the old Sophos cases: v1 creates a case only from one of them.
   */
  async recentDetectionsForNewCase(tenantId: string, options: RecentDetectionsOptions = {}): Promise<LegacyDetection[]> {
    const legacy = await this.legacyFor(tenantId);
    if (!legacy) throw new Error("Only a tenant on the old Sophos cases (cases v1) opens a case from a detection.");
    return legacy.recentDetections(tenantId, options);
  }

  /** The v1 service when the tenant's cases are on cases v1, otherwise null. For list and create. */
  private async legacyFor(tenantId: string): Promise<LegacyCasesService | null> {
    if (!this.legacy) return null;
    return (await this.referenceData.get(tenantId)).api === "v1" ? this.legacy : null;
  }

  /**
   * The v1 service when the case ID is a v1 one (1-598868), otherwise null.
   * Only cases v1 hands out that shape, so a case path needs no reference
   * read to know where to go, and a Fusion case path is exactly as before.
   */
  private legacyForCase(caseRef: string): LegacyCasesService | null {
    return this.legacy && isLegacyCaseId(caseRef.trim()) ? this.legacy : null;
  }

  /** Newest first by default. `after` is the next page number, as the list hands it out in endCursor. */
  private async listLegacy(legacy: LegacyCasesService, tenantId: string, options: CaseListOptions): Promise<CaseListResult> {
    const params = legacyListParams(tenantId, options);
    if (!params) return { total: 0, hasNextPage: false, endCursor: null, ql: null, cases: [], warnings: [] };
    const page = options.after !== undefined ? Number(options.after) : Math.max(1, options.page ?? 1);
    if (!Number.isInteger(page) || page < 1) throw new Error(`Unrecognised page cursor ${JSON.stringify(options.after)}.`);
    const perPage = Math.min(LEGACY_PAGE_MAX, clampPerPage(options.perPage));
    const data = await legacy.list(tenantId, { ...params, page: String(page), pageSize: String(perPage) });
    const items = data.items ?? [];
    const current = data.pages?.current ?? page;
    const hasNextPage = data.pages?.total !== undefined ? current < data.pages.total : items.length === perPage;
    return {
      total: data.pages?.items ?? items.length,
      hasNextPage,
      endCursor: hasNextPage ? String(current + 1) : null,
      ql: null,
      cases: items.map(legacyCaseToFusion),
      warnings: [],
    };
  }

  private async readLegacy(legacy: LegacyCasesService, tenantId: string, caseRef: string): Promise<FusionCaseDetail> {
    const { id } = await this.resolveCaseId(tenantId, caseRef);
    try {
      return legacyCaseToFusion(await legacy.get(tenantId, id));
    } catch (error) {
      if (error instanceof SophosApiRequestError && error.status === 404) throw new CaseNotFoundError(caseRef, tenantId);
      throw error;
    }
  }

  /**
   * The case and up to maxDetections of its detections, with the MITRE
   * roll-up built from them the way the Fusion summary builds it.
   */
  private async summaryLegacy(
    legacy: LegacyCasesService,
    tenantId: string,
    caseRef: string,
    includeDetections: boolean,
    maxDetections: number
  ): Promise<CaseSummaryResult> {
    const item = await this.readLegacy(legacy, tenantId, caseRef);
    let detectionsTotal = item.detectionsCount;
    let detections: LegacyDetection[] = [];
    if (includeDetections) {
      const pageSize = Math.min(LEGACY_PAGE_MAX, maxDetections);
      for (let page = 1; detections.length < maxDetections; page += 1) {
        const result = await legacy.detections(tenantId, item.id, page, pageSize);
        const items = result.items ?? [];
        detections.push(...items);
        detectionsTotal = result.pages?.items ?? detectionsTotal;
        if (items.length === 0 || page >= (result.pages?.total ?? page)) break;
      }
      detections = detections.slice(0, maxDetections);
    }
    return {
      case: item,
      evidence: null,
      detectionsTotal,
      detections: [],
      mitre: detections.length > 0 ? legacyMitreSummary(detections) : null,
      legacyDetections: detections,
      warnings: [],
    };
  }

  /**
   * A v1 create, sent once (v1 has no known fault to retry). v1 opens only
   * self-managed cases, only from a detection of the last 30 days, and
   * needs an assignee, which is "Unassigned" unless an email is given.
   */
  private async createLegacy(legacy: LegacyCasesService, tenantId: string, input: NewCaseInput): Promise<CaseCreateResult> {
    const body = legacyCreateBody(tenantId, input);
    const { data, meta } = await legacy.create(tenantId, body);
    return {
      case: legacyCaseToFusion(data),
      warnings: [],
      attempts: 1,
      requestId: meta.requestId,
      correlationId: meta.correlationId,
    };
  }

  /**
   * A v1 PATCH, sent once. v1 writes name, severity, status, assignee and
   * overview only, and only on a self-managed case, so everything else is
   * refused before the case is read.
   */
  private async updateLegacy(
    legacy: LegacyCasesService,
    tenantId: string,
    caseRef: string,
    changes: CaseUpdate
  ): Promise<CaseUpdateResult> {
    if (changes.verdict !== undefined) throw new LegacyCasesError(tenantId, "record a verdict");
    if (changes.closeReason !== undefined) throw new LegacyCasesError(tenantId, "record a close reason");
    if (changes.tags !== undefined || changes.replaceTags) throw new LegacyCasesError(tenantId, "hold tags");
    if (changes.archived !== undefined) throw new LegacyCasesError(tenantId, "archive a case");

    const patch: LegacyCasePatch = {};
    if (changes.title !== undefined) {
      const problem = legacyNameProblem(changes.title);
      if (problem) throw new Error(problem);
      patch.name = changes.title;
    }
    if (changes.severity !== undefined) patch.severity = legacySeverityName(normaliseCaseSeverity(changes.severity));
    if (changes.status !== undefined) patch.status = requireLegacyStatus(changes.status);
    if (changes.assigneeId !== undefined) patch.assignee = legacyAssigneeInput(changes.assigneeId);
    if (changes.keyFindings !== undefined) patch.overview = legacyOverviewInput(changes.keyFindings);
    if (Object.keys(patch).length === 0) throw new Error("Nothing to update: supply at least one field to change.");
    if (patch.status === "actionRequired") throw new LegacyCasesError(tenantId, "set Action required, which only Sophos MDR uses");

    const current = await this.readLegacy(legacy, tenantId, caseRef);
    if (current.managedBy === "PROVIDER") {
      throw new LegacyCasesError(tenantId, "change a case Sophos MDR works; the API only changes self-managed cases");
    }
    const { data, meta } = await legacy.update(tenantId, current.id, patch);
    return { case: legacyCaseToFusion(data), notes: [], warnings: [], requestId: meta.requestId, correlationId: meta.correlationId };
  }

  private async readCase(
    tenantId: string,
    id: string,
    caseRef: string
  ): Promise<{ case: FusionCaseDetail; warnings: string[] }> {
    const { data, warnings } = await this.client
      .query<FusionCaseResponse>(tenantId, GET_CASE, { arguments: { id } })
      .catch((error: unknown) => rethrowNotFound(error, caseRef, tenantId));
    if (!data.case) throw new CaseNotFoundError(caseRef, tenantId);
    return { case: data.case, warnings };
  }

  /** CreateCaseInput. managedBy is always sent. */
  private async buildCreateCaseInput(tenantId: string, input: NewCaseInput): Promise<Record<string, unknown>> {
    assertTitle(input.title);
    if (input.managedBy !== "PROVIDER" && input.managedBy !== "CUSTOMER") {
      throw new Error(
        "managedBy must be PROVIDER (hand the case to Sophos MDR) or CUSTOMER (self managed). It has no default and cannot be changed after creation."
      );
    }
    assertAssignee(input.assigneeId);
    assertResourceNames("detectionIds", input.detectionIds);
    assertResourceNames("eventIds", input.eventIds);

    const typeId = await this.referenceData.resolveTypeId(tenantId, input.type);
    const { types } = await this.referenceData.get(tenantId);
    const type = types.find((t) => t.id === typeId);
    if (type?.managedBy && type.managedBy !== input.managedBy) {
      throw new Error(
        `Case type ${type.name} is always managed by ${type.managedBy}; managedBy ${input.managedBy} contradicts it and the API would refuse. Use ${type.managedBy}, or a type that leaves it free.`
      );
    }

    const primaryStatusId = input.status
      ? await this.referenceData.resolveStatusId(tenantId, input.status)
      : await this.defaultOpenStatusId(tenantId, input.managedBy);

    const createInput: Record<string, unknown> = {
      title: input.title,
      typeId,
      severity: normaliseCaseSeverity(input.severity),
      primaryStatusId,
      managedBy: input.managedBy,
    };
    if (input.assigneeId) createInput.assigneeId = input.assigneeId;
    if (input.keyFindings !== undefined) createInput.keyFindings = keyFindingsInput(input.keyFindings);
    if (input.tags) createInput.tags = input.tags;
    if (input.detectionIds?.length) createInput.detectionIds = input.detectionIds;
    if (input.detectionsSearchQuery) createInput.detectionsSearchQuery = input.detectionsSearchQuery;
    if (input.eventIds?.length) createInput.eventIds = input.eventIds;
    if (input.searchQueries?.length) createInput.searchQueries = input.searchQueries;
    if (input.hostIds?.length) createInput.hostIds = input.hostIds;
    return createInput;
  }

  /**
   * Initial status when none is given. A PROVIDER case enters the Sophos MDR
   * queue at awaiting_sophos_assignment where the tenant exposes it;
   * otherwise, and for CUSTOMER cases, new (or open, or the first open status).
   */
  private async defaultOpenStatusId(tenantId: string, managedBy: ManagedBy): Promise<string> {
    const { primaryStatuses } = await this.referenceData.get(tenantId);
    const preferred = defaultOpenStatus(primaryStatuses, managedBy);
    if (!preferred) {
      throw new Error("This tenant exposes no open case status; choose a status explicitly.");
    }
    return preferred;
  }
}

/**
 * The starting status a new case gets from who works it: awaiting Sophos
 * assignment for Sophos MDR where the tenant has it, otherwise new, open, or
 * the first open status. Null when there is no open status.
 */
export function defaultOpenStatus(
  statuses: readonly FusionCasePrimaryStatus[],
  managedBy: ManagedBy
): string | null {
  const open = statuses.filter((s) => !s.isClosed);
  const byName = (name: string) => open.find((s) => s.name.toUpperCase() === name);
  const preferred =
    (managedBy === "PROVIDER" ? byName("AWAITING_SOPHOS_ASSIGNMENT") : undefined) ??
    byName("NEW") ??
    byName("OPEN") ??
    open[0];
  return preferred?.id ?? null;
}

/**
 * CaseListOptions as cases v1 query parameters, or null when the filters
 * can match nothing (open only and a closed status). QL, tag, part-of-title
 * and last-update filters have no v1 equivalent and are refused.
 */
function legacyListParams(tenantId: string, options: CaseListOptions): Record<string, string> | null {
  if (options.query) throw new LegacyCasesError(tenantId, "filter with a QL query");
  if (options.tag) throw new LegacyCasesError(tenantId, "filter by tag");
  if (options.titleContains) throw new LegacyCasesError(tenantId, "filter by part of a title");
  if (options.updatedAfter) throw new LegacyCasesError(tenantId, "filter by last update");

  const params: Record<string, string> = { sort: legacySort(options.sort) };

  let statuses: LegacyCaseStatus[] | null = options.status?.length ? options.status.map(requireLegacyStatus) : null;
  if (options.openOnly) statuses = (statuses ?? [...LEGACY_OPEN_STATUSES]).filter((s) => LEGACY_OPEN_STATUSES.includes(s));
  if (statuses) {
    if (statuses.length === 0) return null;
    params.status = statuses.join(",");
  }

  const names = Object.keys(LEGACY_SEVERITY_VALUE) as LegacyCaseSeverity[];
  let severities: LegacyCaseSeverity[] | null = null;
  if (options.severity !== undefined) {
    const value = normaliseCaseSeverity(options.severity);
    severities = names.filter((name) => LEGACY_SEVERITY_VALUE[name] === value);
  }
  if (options.severityMin !== undefined) {
    const min = normaliseCaseSeverity(options.severityMin);
    const atLeast = names.filter((name) => LEGACY_SEVERITY_VALUE[name] >= min);
    severities = severities ? severities.filter((name) => atLeast.includes(name)) : atLeast;
  }
  if (severities) {
    if (severities.length === 0) return null;
    params.severity = severities.join(",");
  }

  if (options.type) {
    const type = legacyType(options.type);
    if (!type) throw new Error(`Unknown case type "${options.type}" for the old Sophos cases.`);
    params.type = type;
  }
  if (options.verdict) {
    const verdict = legacyVerdict(options.verdict);
    if (!verdict) throw new Error(`Unknown verdict "${options.verdict}" for the old Sophos cases.`);
    params.verdict = verdict;
  }
  if (options.unassigned) params.assignee = "Unassigned";
  else if (options.assigneeId) params.assignee = options.assigneeId;
  if (options.createdAfter) params.createdAfter = options.createdAfter;
  if (options.createdBefore) params.createdBefore = options.createdBefore;
  return params;
}

/** "<field> asc|desc" as v1's "<field>:asc|desc"; newest first when no sort is given. */
function legacySort(sort: string | undefined): string {
  if (!sort?.trim()) return "createdAt:desc";
  const match = /^\s*([A-Za-z]+)\s*(?:[\s:]\s*(asc|desc))?\s*$/i.exec(sort);
  if (!match) throw new Error(`Sort must look like "createdAt desc", got ${JSON.stringify(sort)}.`);
  return match[2] ? `${match[1]}:${match[2].toLowerCase()}` : match[1];
}

function requireLegacyStatus(value: string): LegacyCaseStatus {
  const status = legacyStatus(value);
  if (!status) {
    throw new Error(`Unknown case status "${value}" for the old Sophos cases. Available: new, investigating, onHold, resolved.`);
  }
  return status;
}

/** v1 takes an email address or "Unassigned"; "" unassigns. */
function legacyAssigneeInput(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed.toLowerCase() === "unassigned") return "Unassigned";
  if (!looksLikeEmail(trimmed)) {
    throw new Error(`The old Sophos cases take an assignee's email address, or none (got ${JSON.stringify(value)}).`);
  }
  return trimmed;
}

function legacyOverviewInput(value: string): string {
  if (value.length > LEGACY_OVERVIEW_MAX) throw new Error(`A case overview can be at most ${LEGACY_OVERVIEW_MAX} characters.`);
  return value;
}

/** The POST body for a v1 create, with every check made before anything is sent. */
function legacyCreateBody(tenantId: string, input: NewCaseInput): LegacyCaseCreate {
  if (input.managedBy === "PROVIDER") {
    throw new LegacyCasesError(tenantId, "hand a new case to Sophos MDR; the API only creates self-managed cases");
  }
  if (input.managedBy !== "CUSTOMER") {
    throw new Error(
      "managedBy must be PROVIDER (hand the case to Sophos MDR) or CUSTOMER (self managed). It has no default and cannot be changed after creation."
    );
  }
  const problem = legacyNameProblem(input.title);
  if (problem) throw new Error(problem);
  const type = legacyType(input.type);
  if (!type) throw new Error(`Unknown case type "${input.type}" for the old Sophos cases.`);
  if (LEGACY_UNCREATABLE_TYPES.includes(type)) throw new LegacyCasesError(tenantId, `open a ${type} case through the API`);
  const status = input.status ? requireLegacyStatus(input.status) : "new";
  if (!LEGACY_CREATE_STATUSES.includes(status)) {
    throw new Error(`A new case on the old Sophos cases starts as new or investigating, not ${status}.`);
  }
  if (input.tags?.length) throw new LegacyCasesError(tenantId, "hold tags");
  if (input.eventIds?.length || input.hostIds?.length || input.searchQueries?.length || input.detectionsSearchQuery) {
    throw new LegacyCasesError(tenantId, "attach events, hosts or searches to a case");
  }
  const detections = input.detectionIds ?? [];
  if (detections.length === 0) {
    throw new Error("The old Sophos cases open a case from a detection of the last 30 days. Choose one.");
  }
  const bad = detections.filter((id) => !isLegacyDetectionId(id));
  if (bad.length > 0) throw new Error(`Not a detection ID the old Sophos cases take: ${bad.join(", ")}.`);
  if (detections.length > 101) throw new Error("A new case takes at most 101 detections: one to open it and 100 more.");

  const body: LegacyCaseCreate = {
    name: input.title,
    type,
    severity: legacySeverityName(normaliseCaseSeverity(input.severity)),
    status,
    managedBy: "self",
    // The API refuses a create without an assignee (400 "Assignee cannot be null or blank", 21/09/2026).
    assignee: legacyAssigneeInput(input.assigneeId ?? ""),
    initialDetectionId: detections[0],
  };
  if (detections.length > 1) body.otherDetectionIds = detections.slice(1);
  if (input.keyFindings?.trim()) body.overview = legacyOverviewInput(input.keyFindings);
  return body;
}

function clampPerPage(value: number | undefined): number {
  return Math.min(100, Math.max(1, value ?? 50));
}

/**
 * Fusion reports an unknown case as "record not found" beside a null root
 * field, so the client throws before a null check can run.
 */
function rethrowNotFound(error: unknown, caseRef: string, tenantId: string): never {
  if (error instanceof FusionGraphQLError && error.notFound) {
    throw new CaseNotFoundError(caseRef, tenantId);
  }
  throw error;
}

/** Server-side lifecycle refusals, each with what to do about it. The API's wording is kept. */
const CASE_WRITE_HINTS: Array<[RegExp, string]> = [
  [
    /closed primary status/i,
    "The case is closed: only status, verdicts, secondary status, secondary reasons and archive can change, and evidence writes are refused. Reopen it first, then retry.",
  ],
  [
    /archived investigations cannot be updated/i,
    "The case is archived and refuses every update. Unarchive it first, then retry.",
  ],
  [
    /primary verdict is not valid for provided case primary status/i,
    "A verdict cannot be carried into an open status. Leave the verdict out when reopening and it is cleared automatically.",
  ],
  [
    /invalid rn format/i,
    `Detection and event IDs are six section resource names like ${RESOURCE_NAME_EXAMPLE}, not bare UUIDs.`,
  ],
  [
    /only partner or MDR provider users can set isInternal/i,
    "Internal needs a partner or MDR provider credential; leave it off.",
  ],
];

function rethrowWithHint(error: unknown): never {
  if (error instanceof Error) {
    const hint = CASE_WRITE_HINTS.find(([pattern]) => pattern.test(error.message))?.[1];
    if (hint) {
      const wrapped = new Error(`${error.message}. ${hint}`);
      wrapped.name = error.name;
      throw wrapped;
    }
  }
  throw error;
}

function assertTitle(title: string): void {
  if (!title.trim() || title.length > TITLE_MAX) {
    throw new Error(`A case title must be 1 to ${TITLE_MAX} characters.`);
  }
}

function assertAssignee(assigneeId: string | undefined): void {
  if (assigneeId && looksLikeEmail(assigneeId)) {
    throw new Error(
      `The assignee must be a Subject ID or an @mention (@customer, @sophos), not an email address (got ${assigneeId}).`
    );
  }
}

function assertResourceNames(field: string, values: string[] | undefined): void {
  const rejected = (values ?? []).filter((value) => !isResourceName(value));
  if (rejected.length > 0) {
    throw new Error(
      `${field} must be six section resource names (for example ${RESOURCE_NAME_EXAMPLE}), not bare UUIDs or evidence entry IDs. Rejected: ${rejected.join(", ")}.`
    );
  }
}

/** documentVersion must be exactly "1.0"; "1.0.0" is rejected. */
function keyFindingsInput(content: string) {
  return { documentType: "MARKDOWN", documentVersion: "1.0", content };
}

function compareMentions(text: string, stored: FusionCaseComment) {
  const requested = parseMentionTokens(text);
  const resolved = (stored.mentionsIds ?? []).map((id) => id.toLowerCase());
  const unresolved = requested.filter((token) => !resolved.includes(token));
  const warnings =
    unresolved.length > 0
      ? [
          `These @mentions did not resolve and notified nobody: ${unresolved.join(", ")}. Known group tokens: ${KNOWN_MENTION_GROUPS.join(", ")}.`,
        ]
      : [];
  return { resolved: stored.mentionsIds ?? [], unresolved, warnings };
}
