import type { CatalogSnapshot, Urn } from "./models.js";

export interface ImpactedAsset {
  urn: Urn;
  minHops: number;
}

export interface BlastRadiusResult {
  rootUrn: Urn;
  downstream: ImpactedAsset[];
  maxHops: number;
  truncated: boolean;
  impact: "none" | "low" | "medium" | "high" | "critical";
}

export interface BlastRadiusOptions {
  maxHops?: number;
  maxAssets?: number;
}

function impactOf(count: number): BlastRadiusResult["impact"] {
  if (count === 0) return "none";
  if (count <= 2) return "low";
  if (count <= 5) return "medium";
  if (count <= 20) return "high";
  return "critical";
}

// Compute downstream impact from the snapshot's upstream edges. The traversal is bounded,
// cycle-safe, deterministic, and reports truncation instead of silently dropping assets.
export function computeBlastRadius(
  snapshot: CatalogSnapshot,
  subject: string,
  options: BlastRadiusOptions = {}
): BlastRadiusResult {
  const rootUrn = subject.split("#", 1)[0] as Urn;
  const maxHops = Math.max(1, Math.min(10, Math.floor(options.maxHops ?? 3)));
  const maxAssets = Math.max(1, Math.min(10_000, Math.floor(options.maxAssets ?? 500)));
  const consumers = new Map<Urn, Urn[]>();

  for (const entity of snapshot.entities) {
    for (const edge of entity.upstreams ?? []) {
      const current = consumers.get(edge.upstream) ?? [];
      current.push(entity.urn);
      consumers.set(edge.upstream, current);
    }
  }
  for (const values of consumers.values()) values.sort();

  const distances = new Map<Urn, number>();
  const queue: Array<{ urn: Urn; hops: number }> = [{ urn: rootUrn, hops: 0 }];
  let truncated = false;
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const current = queue[cursor]!;
    if (current.hops >= maxHops) {
      if ((consumers.get(current.urn)?.length ?? 0) > 0) truncated = true;
      continue;
    }
    for (const downstream of consumers.get(current.urn) ?? []) {
      if (downstream === rootUrn || distances.has(downstream)) continue;
      if (distances.size >= maxAssets) {
        truncated = true;
        break;
      }
      const hops = current.hops + 1;
      distances.set(downstream, hops);
      queue.push({ urn: downstream, hops });
    }
  }

  const downstream = [...distances]
    .map(([urn, minHops]) => ({ urn, minHops }))
    .sort((a, b) => a.minHops - b.minHops || a.urn.localeCompare(b.urn));
  return {
    rootUrn,
    downstream,
    maxHops,
    truncated,
    impact: impactOf(downstream.length),
  };
}
