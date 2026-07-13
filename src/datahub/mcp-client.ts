// DataHub MCP client — the seam through which the agent CONSUMES DataHub metadata.
//
// The agent never talks to DataHub's GMS directly. It speaks the Model Context
// Protocol to the OFFICIAL DataHub MCP server (`acryldata/mcp-server-datahub`), whose
// read tools — `search`, `get_entities`, `get_lineage` (docs/DATAHUB_RESEARCH.md §3) —
// are the exact surface a governance/lineage agent needs. This module defines OUR
// interface over those tools (not acryldata's wire shapes), so the rest of the agent
// is decoupled from the transport and runs identically against:
//   • FakeDataHubMcpClient — deterministic fixtures, zero network (tests + CI + demo),
//   • the live client (src/datahub/mcp-client-live.ts) — a thin adapter that maps the
//     real MCP tool responses onto this same interface.
//
// Everything here is READ-ONLY. The DataHub MCP server's mutation tools (add_tags,
// set_domains, …) are OFF by default and this agent never enables them — Archon
// recommends, a human disposes.

import type { AuditFact } from "../types.js";
import type { CatalogEntity, CatalogSnapshot, LineageEdge, Urn } from "./models.js";
import { reportsToFacts, type SourceReport } from "../audit/harvest.js";
import { FIXTURE_REPORTS, FIXTURE_VERSION_HISTORY } from "./fixtures.js";
import type { AspectVersionHistory } from "./version-history.js";

// The read surface the agent needs. Mirrors the DataHub MCP server's read tools, but
// in OUR provider-neutral vocabulary so the agent never depends on acryldata shapes.
export interface DataHubClient {
  // `search` — dataset URNs matching a query (all catalogued datasets when omitted).
  search(query?: string): Promise<Urn[]>;
  // `get_entities` — full metadata (aspects) for the given URNs (current view).
  getEntities(urns: Urn[]): Promise<CatalogEntity[]>;
  // `get_lineage` — upstream lineage edges declared for one entity.
  getLineage(urn: Urn): Promise<LineageEdge[]>;
  // Convenience harvest: search → get_entities → get_lineage, assembled into the
  // current-view snapshot the governance validator audits.
  harvestSnapshot(query?: string): Promise<CatalogSnapshot>;
  // Provenance-aware harvest: the FULL fact stream across every source/scan, which the
  // self-audit consistency engine needs to see cross-source disagreements.
  harvestFacts(query?: string): Promise<AuditFact[]>;
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
export function mergeLatest(reports: SourceReport[]): CatalogEntity[] {
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

// Assemble a CatalogSnapshot (current view + the set of URNs DataHub knows about) from
// a report stream. Shared by the Fake and the live adapter.
export function snapshotFromReports(reports: SourceReport[]): CatalogSnapshot {
  const entities = mergeLatest(reports);
  const knownUrns = new Set<Urn>(entities.map((e) => e.urn));
  const scanId = reports.reduce((acc, r) => (r.scanId > acc ? r.scanId : acc), "");
  return { scanId, entities, knownUrns };
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
    return snapshotFromReports(this.filter(query));
  }

  async harvestFacts(query?: string): Promise<AuditFact[]> {
    return reportsToFacts(this.filter(query));
  }

  // Offline aspect version history: the deterministic fixture histories, filtered by the
  // same query rule. Mirrors what a live direct-GMS read would assemble (the conflicting
  // per-run values the current view collapsed), so the contradiction-recovery path fires
  // identically offline and online.
  async harvestVersionHistories(query?: string): Promise<AspectVersionHistory[]> {
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
