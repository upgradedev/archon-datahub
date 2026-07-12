// ClassifierAgent — deterministic, no LLM. Partitions the harvested catalog into the
// buckets the downstream agents need, and produces a compact classification the
// narrator summarizes. Mirrors the extraction pipeline's rule-based classifier: fast,
// explainable, no model call.

import type { CatalogSnapshot } from "../datahub/models.js";
import { looksSensitive } from "../datahub/models.js";

export interface Classification {
  totalEntities: number;
  withLineage: number; // entities declaring at least one upstream
  sensitiveEntities: number; // entities with at least one sensitive field
  domains: Record<string, number>; // entity count per domain (or "(none)")
  platforms: Record<string, number>; // entity count per data platform
}

export class ClassifierAgent {
  classify(snapshot: CatalogSnapshot): Classification {
    const domains: Record<string, number> = {};
    const platforms: Record<string, number> = {};
    let withLineage = 0;
    let sensitiveEntities = 0;

    for (const e of snapshot.entities) {
      const dom = e.domain ?? "(none)";
      domains[dom] = (domains[dom] ?? 0) + 1;
      platforms[e.platform] = (platforms[e.platform] ?? 0) + 1;
      if ((e.upstreams ?? []).length > 0) withLineage++;
      if ((e.fields ?? []).some((f) => looksSensitive(f.path))) sensitiveEntities++;
    }

    return {
      totalEntities: snapshot.entities.length,
      withLineage,
      sensitiveEntities,
      domains,
      platforms,
    };
  }
}
