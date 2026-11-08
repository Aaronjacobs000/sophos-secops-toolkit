// SPDX-License-Identifier: MIT
// Adapted from sophos-central-mcp-server (https://github.com/Aaronjacobs000/sophos-mcp),
// buildMitreSummary in src/tools/fusion-cases.ts at commit 9471c18. MIT License,
// Copyright (c) 2026; the full notice is in LICENSE-MIT at the root of this package.

/**
 * Client-side MITRE ATT&CK roll-up for a Fusion case: tactics and techniques
 * across the case's resolved detections, with detection counts. Fusion has no
 * server-side equivalent of the Classic mitre-attack-summary endpoint.
 */

import type { FusionDetectionRecord } from "./types.js";

export interface MitreTechniqueCount {
  techniqueId: string;
  technique: string | null;
  detectionCount: number;
}

export interface MitreSummary {
  detectionCount: number;
  techniqueCount: number;
  /** Sorted by tactic name; techniques within a tactic by detection count, highest first. */
  tactics: Array<{ tactic: string; techniques: MitreTechniqueCount[] }>;
  /** Techniques a detection names without any enrichment that gives their tactic. */
  techniquesWithoutTactic: MitreTechniqueCount[];
}

export function buildMitreSummary(records: FusionDetectionRecord[]): MitreSummary {
  const techniques = new Map<
    string,
    { techniqueId: string; technique: string | null; tactics: Set<string>; detections: Set<string> }
  >();

  const touch = (id: string, name: string | null, tactics: string[] | null, detectionId: string) => {
    const entry = techniques.get(id) ?? {
      techniqueId: id,
      technique: null,
      tactics: new Set<string>(),
      detections: new Set<string>(),
    };
    if (name && !entry.technique) entry.technique = name;
    for (const t of tactics ?? []) entry.tactics.add(t);
    entry.detections.add(detectionId);
    techniques.set(id, entry);
  };

  for (const r of records) {
    for (const d of r.enrichment_details ?? []) {
      const info = d.mitre_attack_info;
      if (info?.technique_id) touch(info.technique_id, info.technique, info.tactics, r.id);
    }
    for (const id of r.attack_technique_ids ?? []) touch(id, null, null, r.id);
  }

  const byTactic = new Map<string, MitreTechniqueCount[]>();
  const withoutTactic: MitreTechniqueCount[] = [];
  for (const entry of techniques.values()) {
    const row = {
      techniqueId: entry.techniqueId,
      technique: entry.technique,
      detectionCount: entry.detections.size,
    };
    if (entry.tactics.size === 0) {
      withoutTactic.push(row);
      continue;
    }
    for (const tactic of entry.tactics) {
      const list = byTactic.get(tactic) ?? [];
      list.push(row);
      byTactic.set(tactic, list);
    }
  }

  return {
    detectionCount: records.length,
    techniqueCount: techniques.size,
    tactics: [...byTactic.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([tactic, list]) => ({
        tactic,
        techniques: list.sort((a, b) => b.detectionCount - a.detectionCount),
      })),
    techniquesWithoutTactic: withoutTactic,
  };
}
