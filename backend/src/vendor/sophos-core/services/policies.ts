// SPDX-License-Identifier: Apache-2.0
/**
 * Endpoint policies (/endpoint/v1/policies): list by type, detail, and the
 * v1 writes: enable, disable, priority, rename and leaf setting edits.
 *
 * Two write rules come from live testing. `appliesTo` is never sent: every
 * write carrying it returned 500 (02/07/2026), so assignment cannot change
 * from here. And a setting's `unit` is returned by GET but rejected on write,
 * so a settings patch carries `value` and nothing else.
 */

import type { MetaResult, SophosClient } from "../client/sophos-client.js";

/** A setting's value as GET returns it. v1 edits the scalar kinds only. */
export type PolicySettingValue = boolean | number | string | unknown[] | Record<string, unknown> | null;
export type PolicyLeafValue = boolean | number | string;

export interface PolicySetting {
  value: PolicySettingValue;
  recommendedValue?: PolicySettingValue;
  unit?: string;
}

export interface EndpointPolicy {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  /** 0 is the base policy. */
  priority: number;
  /** Set by a partner or enterprise that manages the tenant; the tenant cannot edit it. */
  lockedByManagingAccount?: boolean;
  tenant?: { id: string };
  settings: Record<string, PolicySetting>;
  appliesTo?: {
    users?: Array<{ id: string; name?: string }>;
    userGroups?: Array<{ id: string; name?: string }>;
    endpoints?: Array<{ id: string; hostname?: string }>;
    endpointGroups?: Array<{ id: string; name?: string }>;
  };
  createdAt?: string;
  updatedAt?: string;
}

export interface PolicyPage {
  items: EndpointPolicy[];
  page: number;
  totalPages: number | null;
  total: number | null;
}

/** Everything a v1 policy write can change. There is deliberately no appliesTo. */
export interface PolicyPatch {
  name?: string;
  enabled?: boolean;
  priority?: number;
  /** Changed keys only, as settingsPatch builds them. */
  settings?: Record<string, { value: PolicyLeafValue }>;
}

export interface SettingChange {
  key: string;
  before: PolicyLeafValue;
  after: PolicyLeafValue;
}

interface PolicyListResponse {
  items: EndpointPolicy[];
  pages: { current?: number; total?: number; items?: number };
}

export class PoliciesService {
  constructor(private client: SophosClient) {}

  async list(
    tenantId: string,
    options: { policyType?: string; page?: number; pageSize?: number } = {}
  ): Promise<PolicyPage> {
    const page = Math.max(1, options.page ?? 1);
    const pageSize = Math.min(200, Math.max(1, options.pageSize ?? 50));
    const data = await this.client.tenantRequest<PolicyListResponse>(tenantId, "/endpoint/v1/policies", {
      params: {
        page: String(page),
        pageSize: String(pageSize),
        pageTotal: "true",
        ...(options.policyType ? { policyType: options.policyType } : {}),
      },
    });
    return {
      items: data.items,
      page: data.pages?.current ?? page,
      totalPages: data.pages?.total ?? null,
      total: data.pages?.items ?? null,
    };
  }

  async get(tenantId: string, policyId: string): Promise<EndpointPolicy> {
    return this.client.tenantRequest<EndpointPolicy>(tenantId, `/endpoint/v1/policies/${encodeURIComponent(policyId)}`);
  }

  /**
   * PATCHes only the fields given. The body is rebuilt from the allowed
   * fields, so an appliesTo or unit smuggled in by a caller never reaches
   * the API. Returns the PATCH response: list reads lag writes by minutes.
   * The PATCH is idempotent, so a retry after a timeout is safe.
   */
  async update(tenantId: string, policyId: string, patch: PolicyPatch): Promise<MetaResult<EndpointPolicy>> {
    const body: Record<string, unknown> = {};
    if (patch.name !== undefined) {
      if (!patch.name.trim()) throw new Error("A policy name cannot be empty.");
      body.name = patch.name;
    }
    if (patch.enabled !== undefined) body.enabled = patch.enabled;
    if (patch.priority !== undefined) {
      if (!Number.isInteger(patch.priority) || patch.priority < 0) {
        throw new Error(`Policy priority must be a whole number of 0 or more, got ${patch.priority}.`);
      }
      body.priority = patch.priority;
    }
    if (patch.settings !== undefined) {
      const settings: Record<string, { value: PolicyLeafValue }> = {};
      for (const [key, setting] of Object.entries(patch.settings)) {
        if (!isLeaf(setting?.value)) {
          throw new Error(`Setting ${key}: only boolean, number and text values can be edited.`);
        }
        settings[key] = { value: setting.value };
      }
      if (Object.keys(settings).length > 0) body.settings = settings;
    }
    if (Object.keys(body).length === 0) {
      throw new Error("Nothing to update: supply a name, enabled, priority or at least one changed setting.");
    }
    return this.client.tenantRequestWithMeta<EndpointPolicy>(
      tenantId,
      `/endpoint/v1/policies/${encodeURIComponent(policyId)}`,
      { method: "PATCH", body }
    );
  }
}

/**
 * The before-and-after of each edited leaf setting that actually changed, in
 * key order. Refuses a key the policy does not have, a setting whose current
 * value is not a boolean, number or text, and a change of kind (true to "true").
 */
export function diffPolicySettings(
  current: Record<string, PolicySetting>,
  edits: Record<string, PolicyLeafValue>
): SettingChange[] {
  const changes: SettingChange[] = [];
  for (const key of Object.keys(edits).sort()) {
    const setting = current[key];
    if (!setting) throw new Error(`The policy has no setting ${key}.`);
    const before = setting.value;
    const after = edits[key];
    if (!isLeaf(before)) {
      throw new Error(`Setting ${key} is not a boolean, number or text value and cannot be edited here.`);
    }
    if (typeof after !== typeof before) {
      throw new Error(`Setting ${key} holds a ${typeof before}; got a ${typeof after}.`);
    }
    if (typeof after === "number" && !Number.isFinite(after)) {
      throw new Error(`Setting ${key} needs a finite number.`);
    }
    if (after !== before) changes.push({ key, before, after });
  }
  return changes;
}

/** The settings part of a PATCH for these changes: `value` only, never `unit`. */
export function settingsPatch(changes: SettingChange[]): Record<string, { value: PolicyLeafValue }> {
  return Object.fromEntries(changes.map((change) => [change.key, { value: change.after }]));
}

function isLeaf(value: unknown): value is PolicyLeafValue {
  return typeof value === "boolean" || typeof value === "number" || typeof value === "string";
}
