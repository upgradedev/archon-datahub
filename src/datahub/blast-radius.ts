import type {
  CatalogSnapshot,
  LineageTopologyNode,
  Urn,
} from "./models.js";
import { DataHubHarvestError } from "./harvest-policy.js";

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

function compareImpacted(a: ImpactedAsset, b: ImpactedAsset): number {
  return (
    a.minHops - b.minHops ||
    (a.urn < b.urn ? -1 : a.urn > b.urn ? 1 : 0)
  );
}

function fromProvenTopology(
  rootUrn: Urn,
  nodes: readonly LineageTopologyNode[],
  maxHops: number,
  maxAssets: number
): BlastRadiusResult {
  const withinHopBound = nodes
    .filter((node) => node.minHops <= maxHops)
    .map(({ urn, minHops }) => ({ urn, minHops }))
    .sort(compareImpacted);
  const downstream = withinHopBound.slice(0, maxAssets);
  const truncated =
    nodes.some((node) => node.minHops > maxHops) ||
    withinHopBound.length > maxAssets;
  return {
    rootUrn,
    downstream,
    maxHops,
    truncated,
    impact: impactOf(downstream.length),
  };
}

// Prefer provider-proven downstream reachability for audited roots. For a non-root
// subject such as a genuinely dangling upstream, first locate its in-scope consumers and
// then compose each consumer's proven topology. That preserves the exact one-root audit
// scope without hiding the consumer's out-of-scope downstream impact.
export function computeBlastRadius(
  snapshot: CatalogSnapshot,
  subject: string,
  options: BlastRadiusOptions = {}
): BlastRadiusResult {
  const rootUrn = subject.split("#", 1)[0] as Urn;
  const maxHops = Math.max(1, Math.min(10, Math.floor(options.maxHops ?? 3)));
  const maxAssets = Math.max(1, Math.min(10_000, Math.floor(options.maxAssets ?? 500)));
  const provenTopology = snapshot.downstreamByRoot.get(rootUrn);
  if (provenTopology !== undefined) {
    return fromProvenTopology(
      rootUrn,
      provenTopology,
      maxHops,
      maxAssets
    );
  }
  if (snapshot.entities.some((entity) => entity.urn === rootUrn)) {
    throw new DataHubHarvestError(
      "LINEAGE_RESPONSE_INCOMPLETE",
      "Complete downstream lineage is unavailable for the audited asset."
    );
  }

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
      const hops = current.hops + 1;
      distances.set(downstream, hops);
      queue.push({ urn: downstream, hops });
    }
  }

  for (const [consumerUrn, consumerHops] of [...distances]) {
    const consumerTopology = snapshot.downstreamByRoot.get(consumerUrn);
    if (consumerTopology === undefined) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "Complete downstream lineage is unavailable for an audited consumer."
      );
    }
    for (const node of consumerTopology) {
      const minHops = consumerHops + node.minHops;
      if (minHops > maxHops) {
        truncated = true;
        continue;
      }
      const current = distances.get(node.urn);
      if (
        node.urn !== rootUrn &&
        (current === undefined || minHops < current)
      ) {
        distances.set(node.urn, minHops);
      }
    }
  }

  const withinAssetBound = [...distances]
    .map(([urn, minHops]) => ({ urn, minHops }))
    .sort(compareImpacted);
  const downstream = withinAssetBound.slice(0, maxAssets);
  if (withinAssetBound.length > maxAssets) truncated = true;
  return {
    rootUrn,
    downstream,
    maxHops,
    truncated,
    impact: impactOf(downstream.length),
  };
}
