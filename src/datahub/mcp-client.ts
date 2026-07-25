// DataHub MCP client — the seam through which the agent CONSUMES DataHub metadata.
//
// Current entity discovery and resolved topology use the OFFICIAL DataHub MCP server
// (`acryldata/mcp-server-datahub`). Completeness-bound live audits complement those tools
// with narrow direct-GMS reads for current declared lineage and retained aspect history.
// This module defines OUR interface over that evidence (not acryldata's wire shapes), so
// the rest of the agent is decoupled from the transports and runs identically against:
//   • FakeDataHubMcpClient — deterministic fixtures, zero network (tests + CI + demo),
//   • the live client (src/datahub/mcp-client-live.ts) — a thin adapter that maps the
//     real MCP tool responses onto this same interface.
//
// Everything here is READ-ONLY. The DataHub MCP server's mutation tools (add_tags,
// set_domains, …) are OFF by default and this agent never enables them — Archon
// recommends, a human disposes.

import type { AuditFact } from "../types.js";
import type {
  CatalogEntity,
  CatalogSnapshot,
  LineageEdge,
  LineageTopologyNode,
  Urn,
} from "./models.js";
import { reportsToFacts, type SourceReport } from "../audit/harvest.js";
import { FIXTURE_REPORTS, FIXTURE_VERSION_HISTORY } from "./fixtures.js";
import type { AspectVersionHistory } from "./version-history.js";
import type { AuditExecutionProfile } from "./harvest-policy.js";

export interface AuditHarvest {
  snapshot: CatalogSnapshot;
  facts: AuditFact[];
  versionHistories: AspectVersionHistory[];
}

export interface AuditHarvestOptions {
  profile: AuditExecutionProfile;
  signal?: AbortSignal;
}

// A live adapter proves topology independently from the audited search roots. The Fake
// instead supplies its full current graph through `topologyEntities`, allowing a filtered
// one-root audit to retain complete downstream context without auditing neighboring assets.
export interface SnapshotTopologyContext {
  topologyEntities?: readonly CatalogEntity[];
  downstreamByRoot?: ReadonlyMap<Urn, readonly LineageTopologyNode[]>;
  knownLineageUrns?: ReadonlySet<Urn>;
}

// The read surface the agent needs. Mirrors the DataHub MCP server's read tools, but
// in OUR provider-neutral vocabulary so the agent never depends on acryldata shapes.
export interface DataHubClient {
  // `search` — dataset URNs matching a query (all catalogued datasets when omitted).
  search(query?: string): Promise<Urn[]>;
  // `get_entities` — full metadata (aspects) for the given URNs (current view).
  getEntities(urns: Urn[]): Promise<CatalogEntity[]>;
  // `get_lineage` — provider-resolved upstream nodes for one entity.
  getLineage(urn: Urn): Promise<LineageEdge[]>;
  // Convenience harvest assembled into the completeness-bound current snapshot the
  // governance validator audits.
  harvestSnapshot(query?: string): Promise<CatalogSnapshot>;
  // Provenance-aware harvest: the FULL fact stream across every source/scan, which the
  // self-audit consistency engine needs to see cross-source disagreements.
  harvestFacts(query?: string): Promise<AuditFact[]>;
  // One logical audit harvest. Snapshot and fact views MUST derive from the same
  // report stream; live implementations also reuse the exact discovered URN set for
  // bounded aspect-history work. This prevents time-of-check/time-of-use drift and
  // duplicate network harvests inside one pipeline run.
  harvestAudit(
    query: string | undefined,
    options: AuditHarvestOptions
  ): Promise<AuditHarvest>;
  // OPTIONAL — aspect VERSION HISTORY for the catalog's mutable governance aspects, from a
  // DIRECT GMS read (OpenAPI v3 / Timeline), NOT the MCP read tools. This is what recovers
  // cross-source CONTRADICTIONS on a LIVE catalog, where latest-write-wins collapses the
  // conflict on the current view (see src/datahub/version-history.ts). Optional so a client
  // that only has the MCP read surface can omit it; the pipeline degrades gracefully.
  harvestVersionHistories?(query?: string): Promise<AspectVersionHistory[]>;
}

// Reduce a provenance-aware report stream to the CURRENT view — the latest report per
// URN (newest `createdAt` wins; ties broken deterministically by scanId). This is what
// `get_entities` conceptually returns: one current entity per URN.
export function mergeLatest(reports: readonly SourceReport[]): CatalogEntity[] {
  const latest = new Map<Urn, SourceReport>();
  for (const r of reports) {
    const cur = latest.get(r.entity.urn);
    if (
      !cur ||
      r.createdAt > cur.createdAt ||
      (r.createdAt === cur.createdAt && r.scanId > cur.scanId)
    ) {
      latest.set(r.entity.urn, r);
    }
  }
  return [...latest.values()]
    .sort((a, b) => (a.entity.urn < b.entity.urn ? -1 : a.entity.urn > b.entity.urn ? 1 : 0))
    .map((r) => r.entity);
}

function deriveDownstreamByRoot(
  roots: readonly CatalogEntity[],
  topologyEntities: readonly CatalogEntity[]
): Map<Urn, LineageTopologyNode[]> {
  // Audited entities win for their own URNs so every projection is bound to the exact
  // report stream. The remaining entities provide topology context only.
  const byUrn = new Map<Urn, CatalogEntity>();
  for (const entity of topologyEntities) byUrn.set(entity.urn, entity);
  for (const root of roots) byUrn.set(root.urn, root);

  const directConsumers = new Map<Urn, Set<Urn>>();
  for (const entity of byUrn.values()) {
    for (const edge of entity.upstreams ?? []) {
      if (!edge.upstreamResolved || !byUrn.has(edge.upstream)) continue;
      let consumers = directConsumers.get(edge.upstream);
      if (!consumers) {
        consumers = new Set<Urn>();
        directConsumers.set(edge.upstream, consumers);
      }
      consumers.add(entity.urn);
    }
  }

  const downstreamByRoot = new Map<Urn, LineageTopologyNode[]>();
  for (const root of roots) {
    const distances = new Map<Urn, number>();
    const queue: Array<{ urn: Urn; hops: number }> = [
      { urn: root.urn, hops: 0 },
    ];
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const current = queue[cursor]!;
      const consumers = [...(directConsumers.get(current.urn) ?? [])].sort();
      for (const downstream of consumers) {
        if (downstream === root.urn || distances.has(downstream)) continue;
        const minHops = current.hops + 1;
        distances.set(downstream, minHops);
        queue.push({ urn: downstream, hops: minHops });
      }
    }
    const nodes = [...distances]
      .map(([urn, minHops]): LineageTopologyNode => {
        const entity = byUrn.get(urn)!;
        return {
          urn,
          minHops,
          entityType: "DATASET",
          deprecated: entity.deprecated === true,
        };
      })
      .sort(
        (a, b) =>
          a.minHops - b.minHops ||
          (a.urn < b.urn ? -1 : a.urn > b.urn ? 1 : 0)
      );
    downstreamByRoot.set(root.urn, nodes);
  }
  return downstreamByRoot;
}

function copyProvenDownstream(
  roots: readonly CatalogEntity[],
  proven: ReadonlyMap<Urn, readonly LineageTopologyNode[]>
): Map<Urn, LineageTopologyNode[]> {
  const downstreamByRoot = new Map<Urn, LineageTopologyNode[]>();
  for (const root of roots) {
    const raw = proven.get(root.urn);
    if (raw === undefined) {
      throw new TypeError(
        `Complete downstream topology is missing for audited root ${root.urn}.`
      );
    }
    const seen = new Set<Urn>();
    const nodes = raw.map((node): LineageTopologyNode => {
      if (
        !node ||
        typeof node.urn !== "string" ||
        node.urn.length === 0 ||
        node.urn === root.urn ||
        !Number.isInteger(node.minHops) ||
        node.minHops < 1 ||
        typeof node.entityType !== "string" ||
        node.entityType.trim().length === 0 ||
        typeof node.deprecated !== "boolean" ||
        seen.has(node.urn)
      ) {
        throw new TypeError(
          `Downstream topology for ${root.urn} contains an invalid or duplicate node.`
        );
      }
      seen.add(node.urn);
      return {
        urn: node.urn,
        minHops: node.minHops,
        entityType: node.entityType,
        deprecated: node.deprecated,
      };
    });
    nodes.sort(
      (a, b) =>
        a.minHops - b.minHops ||
        (a.urn < b.urn ? -1 : a.urn > b.urn ? 1 : 0)
    );
    downstreamByRoot.set(root.urn, nodes);
  }
  return downstreamByRoot;
}

// Assemble a CatalogSnapshot from the exact audited report stream plus independently
// proven topology context. `entities` never expands beyond the reports; downstream nodes
// and known lineage URNs are context, not additional governance/history audit targets.
export function snapshotFromReports(
  reports: readonly SourceReport[],
  context: SnapshotTopologyContext = {}
): CatalogSnapshot {
  const entities = mergeLatest(reports);
  if (context.topologyEntities && context.downstreamByRoot) {
    throw new TypeError(
      "Provide either topologyEntities or downstreamByRoot, not both."
    );
  }
  const downstreamByRoot = context.downstreamByRoot
    ? copyProvenDownstream(entities, context.downstreamByRoot)
    : deriveDownstreamByRoot(
        entities,
        context.topologyEntities ?? entities
      );
  const knownUrns = new Set<Urn>(entities.map((e) => e.urn));
  for (const entity of entities) {
    for (const edge of entity.upstreams ?? []) {
      if (edge.upstreamResolved) knownUrns.add(edge.upstream);
    }
  }
  for (const nodes of downstreamByRoot.values()) {
    for (const node of nodes) knownUrns.add(node.urn);
  }
  for (const urn of context.knownLineageUrns ?? []) {
    if (typeof urn !== "string" || urn.length === 0) {
      throw new TypeError("Known lineage context contains an invalid URN.");
    }
    knownUrns.add(urn);
  }
  const scanId = reports.reduce((acc, r) => (r.scanId > acc ? r.scanId : acc), "");
  return { scanId, entities, knownUrns, downstreamByRoot };
}

// The offline DataHub client: serves a fixed report stream through the same interface
// the live client implements. Injectable — tests pass their own reports; the default
// is the shipped fixture catalog.
export class FakeDataHubMcpClient implements DataHubClient {
  private histories: AspectVersionHistory[];

  // `histories` defaults to the shipped version-history fixtures ONLY for the default
  // catalog; a caller that injects its own reports (e.g. a clean single-source catalog)
  // gets no version history unless it passes one explicitly — so a "clean" Fake stays clean.
  constructor(private reports: SourceReport[] = FIXTURE_REPORTS, histories?: AspectVersionHistory[]) {
    this.histories = histories ?? (reports === FIXTURE_REPORTS ? FIXTURE_VERSION_HISTORY : []);
  }

  private filter(query?: string): SourceReport[] {
    if (!query || query === "*" || query.trim().length === 0) return this.reports;
    const q = query.toLowerCase();
    return this.reports.filter(
      (r) => r.entity.name.toLowerCase().includes(q) || r.entity.urn.toLowerCase().includes(q)
    );
  }

  async search(query?: string): Promise<Urn[]> {
    return [...new Set(this.filter(query).map((r) => r.entity.urn))].sort();
  }

  async getEntities(urns: Urn[]): Promise<CatalogEntity[]> {
    const want = new Set(urns);
    return mergeLatest(this.reports).filter((e) => want.has(e.urn));
  }

  async getLineage(urn: Urn): Promise<LineageEdge[]> {
    const e = mergeLatest(this.reports).find((x) => x.urn === urn);
    return e?.upstreams ?? [];
  }

  async harvestSnapshot(query?: string): Promise<CatalogSnapshot> {
    return snapshotFromReports(this.filter(query), {
      topologyEntities: mergeLatest(this.reports),
    });
  }

  async harvestFacts(query?: string): Promise<AuditFact[]> {
    return reportsToFacts(this.filter(query));
  }

  async harvestAudit(
    query: string | undefined,
    _options: AuditHarvestOptions
  ): Promise<AuditHarvest> {
    // The deterministic fixtures are trusted test data, so hosted network ceilings do
    // not change Fake semantics. The filter is evaluated once and both projections are
    // derived from that exact in-memory report bundle.
    const reports = this.filter(query);
    return {
      snapshot: snapshotFromReports(reports, {
        topologyEntities: mergeLatest(this.reports),
      }),
      facts: reportsToFacts(reports),
      versionHistories: this.filterHistories(query),
    };
  }

  // Offline aspect version history: the deterministic fixture histories, filtered by the
  // same query rule. Mirrors what a live direct-GMS read would assemble (the conflicting
  // versioned values + stable pipeline identities the current view collapsed), so the
  // contradiction-recovery path fires
  // identically offline and online.
  async harvestVersionHistories(query?: string): Promise<AspectVersionHistory[]> {
    return this.filterHistories(query);
  }

  private filterHistories(query?: string): AspectVersionHistory[] {
    if (!query || query === "*" || query.trim().length === 0) return this.histories;
    const q = query.toLowerCase();
    return this.histories.filter((h) => h.urn.toLowerCase().includes(q));
  }
}

// True when a live DataHub MCP endpoint is configured. Absent → offline Fake, so the
// whole agent (tests, CI, demo) runs with zero credentials and zero network.
export function hasDataHubCreds(): boolean {
  return Boolean(process.env.DATAHUB_MCP_URL || process.env.DATAHUB_GMS_URL);
}

// Auto-select the client by environment. The live adapter is loaded lazily (dynamic
// import) so its MCP-transport dependencies never load in the offline path.
export async function createDataHubClient(): Promise<DataHubClient> {
  if (!hasDataHubCreds()) return new FakeDataHubMcpClient();
  const { LiveDataHubMcpClient } = await import("./mcp-client-live.js");
  return new LiveDataHubMcpClient();
}
