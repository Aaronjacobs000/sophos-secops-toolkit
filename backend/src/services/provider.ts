/**
 * What the screens read from: the live engine for the active credential, or
 * the demo provider. Both answer the same questions from cached records.
 */

import type { EventEmitter } from "node:events";
import type { AppContext } from "../sophos/context.js";
import type { TenantRecord } from "../data/types.js";
import type { DatasetName, DatasetValueMap, EngineStatus, Freshness } from "./engine.js";

export interface Provider extends EventEmitter {
  readonly kind: "live" | "demo";
  readonly label: string;
  context: AppContext | null;
  tenants: TenantRecord[];
  tenantsOverCap: number;
  status: EngineStatus;
  statusMessage: string;
  get<K extends DatasetName>(dataset: K, tenantId: string): DatasetValueMap[K] | null;
  fetchedAt(dataset: DatasetName, tenantId: string): number | null;
  snapshots<T>(name: string, tenantId: string, sinceMs: number): Array<{ takenAt: number; value: T }>;
  freshness(tenantIds: string[], datasets: DatasetName[]): Freshness[];
  focus(datasets: DatasetName[], tenantIds: string[]): void;
  setFastTenants(ids: string[]): void;
  budget(): { lastMinute: number; lastHour: number; queued: number; pausedFor: number; perMinute: number; perHour: number; total: number };
  progress(): { done: number; total: number };
  tenant(id: string): TenantRecord | null;
  stop(): void;
}
