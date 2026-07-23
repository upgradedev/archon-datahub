// Live DataHub MCP client — the thin transport adapter that maps the OFFICIAL DataHub MCP
// server (`acryldata/mcp-server-datahub`) onto our DataHubClient interface.
//
// PINNED FROM SOURCE. The tool names, argument schemas, and response shapes below are taken
// from the acryldata/mcp-server-datahub source (tools/search.py, tools/entities.py,
// tools/lineage.py, graphql_helpers.py) — see src/datahub/live-mappers.ts for the exact
// cleaned-response types and the pure mappers. This file is the NETWORK SHELL only; all
// shape logic lives in live-mappers.ts (which the offline suite covers). This transport
// path is network-bound and therefore excluded from the coverage gate, exactly as a real
// transport client should be.
//
// TWO TRANSPORTS, one mapping:
//   • stdio (default, the reliable OSS path): spawns the pinned `mcp-server-datahub@0.6.0`
//     DATAHUB_GMS_URL + DATAHUB_GMS_TOKEN in its env. This is the transport DataHub itself
//     documents for Claude Desktop / Cursor / Claude Code.
//   • HTTP (Streamable): when DATAHUB_MCP_URL is set, connect to a hosted MCP endpoint
//     (a DataHub Cloud tenant integrations URL, or a GMS that exposes /mcp).
// The tool CALLS and response MAPPING are identical across both.
//
// The intended home for a live DataHub instance is a CLOUD VM (the quickstart is a
// ~14-container stack — see README "Running against a real DataHub"), never the dev desktop.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { AuditFact } from "../types.js";
import type { CatalogEntity, CatalogSnapshot, LineageEdge, Urn } from "./models.js";
import { reportsToFacts, type SourceReport } from "../audit/harvest.js";
import type {
  AuditHarvest,
  AuditHarvestOptions,
  DataHubClient,
} from "./mcp-client.js";
import { snapshotFromReports } from "./mcp-client.js";
import {
  mapEntitiesStrict,
  mapSearchPageStrict,
  mapUpstreamEdgesStrict,
  parseMcpReadToolResult,
  type DhCleanedEntity,
  type DhLineageResponse,
  type DhSearchResponse,
} from "./live-mappers.js";
import type {
  AspectVersionHistory,
  MutableAspectName,
} from "./version-history.js";
import { readAspectVersionHistory } from "./version-history-reader.js";
import {
  DataHubHarvestError,
  deadlineSignal,
  harvestPolicy,
  mapWithConcurrency,
  requireDirectHistoryCapability,
  waitWithinDeadline,
  type LiveHarvestPolicy,
} from "./harvest-policy.js";

// The DataHub MCP server tags every catalogued asset with its dataPlatform, but its READ
// tools return a single current view per URN (aspects are single-valued). So a live harvest
// is one logical source at one scan; we label it with a stable id and let TIME (scanId) be
// the provenance axis. See DESIGN.md §Phase-2 and the README limits note.
const LIVE_SOURCE = "datahub";
const SEARCH_PAGE_SIZE = 50;
const MAX_LINEAGE_RESULTS = 50;
const MUTABLE_ASPECTS: readonly MutableAspectName[] = [
  "ownership",
  "schemaMetadata",
  "domains",
  "deprecation",
];

function httpMcpUrl(): string | null {
  const explicit = process.env.DATAHUB_MCP_URL;
  return explicit && explicit.trim().length > 0 ? explicit : null;
}

export class LiveDataHubMcpClient implements DataHubClient {
  private client: Client;
  private connected = false;

  constructor() {
    this.client = new Client({ name: "archon-datahub", version: "0.2.0" }, { capabilities: {} });
  }

  private async connect(): Promise<void> {
    if (this.connected) return;
    const httpUrl = httpMcpUrl();
    if (httpUrl) {
      // Hosted MCP endpoint (DataHub Cloud / GMS /mcp). Bearer PAT via Authorization header.
      const headers: Record<string, string> = {};
      const token = process.env.DATAHUB_GMS_TOKEN;
      if (token) headers["Authorization"] = `Bearer ${token}`;
      const transport = new StreamableHTTPClientTransport(new URL(httpUrl), {
        requestInit: { headers },
      });
      await this.client.connect(transport);
    } else {
      // stdio: the standard OSS path — run the published server against the local/remote GMS.
      const transport = new StdioClientTransport({
        command: process.env.DATAHUB_MCP_COMMAND ?? "uvx",
        args: (process.env.DATAHUB_MCP_ARGS ?? "mcp-server-datahub@0.6.0").split(/\s+/),
        env: {
          ...process.env,
          DATAHUB_GMS_URL: process.env.DATAHUB_GMS_URL ?? "http://localhost:8080",
          ...(process.env.DATAHUB_GMS_TOKEN ? { DATAHUB_GMS_TOKEN: process.env.DATAHUB_GMS_TOKEN } : {}),
        } as Record<string, string>,
      });
      await this.client.connect(transport);
    }
    this.connected = true;
  }

  private async call(
    name: string,
    args: Record<string, unknown>,
    signal: AbortSignal,
    timeoutMs: number
  ): Promise<unknown> {
    await waitWithinDeadline(
      this.connect(),
      signal,
      "HARVEST_DEADLINE_EXCEEDED"
    );
    const res = await this.client.callTool(
      { name, arguments: args },
      undefined,
      { signal, timeout: timeoutMs }
    );
    return parseMcpReadToolResult(res);
  }

  // Standalone read methods use the strict synchronous budget. Full pipeline callers use
  // harvestAudit so snapshot + facts + history share one exact live harvest.
  async search(query?: string): Promise<Urn[]> {
    const policy = harvestPolicy("synchronous-preview");
    const signal = deadlineSignal(policy.harvestDeadlineMs);
    return this.searchWithinPolicy(query, policy, signal);
  }

  async getEntities(urns: Urn[]): Promise<CatalogEntity[]> {
    const policy = harvestPolicy("synchronous-preview");
    const signal = deadlineSignal(policy.harvestDeadlineMs);
    return this.getEntitiesWithinPolicy(urns, policy, signal);
  }

  async getLineage(urn: Urn): Promise<LineageEdge[]> {
    const policy = harvestPolicy("synchronous-preview");
    const signal = deadlineSignal(policy.harvestDeadlineMs);
    return this.getLineageWithinPolicy(urn, () => true, policy, signal);
  }

  async harvestSnapshot(query?: string): Promise<CatalogSnapshot> {
    return (
      await this.harvestAudit(query, { profile: "async-worker" })
    ).snapshot;
  }

  async harvestFacts(query?: string): Promise<AuditFact[]> {
    return (
      await this.harvestAudit(query, { profile: "async-worker" })
    ).facts;
  }

  async harvestAudit(
    query: string | undefined,
    options: AuditHarvestOptions
  ): Promise<AuditHarvest> {
    // Hosted audit completeness depends on direct versioned-aspect reads. MCP-only
    // connectivity remains useful for standalone search/get tools, but cannot produce
    // an audit or governed plan that silently omits temporal contradictions.
    requireDirectHistoryCapability(process.env.DATAHUB_GMS_URL);
    const policy = harvestPolicy(options.profile);
    const signal = deadlineSignal(policy.harvestDeadlineMs, options.signal);
    return waitWithinDeadline(
      this.harvestWithinPolicy(query, policy, signal),
      signal,
      "HARVEST_DEADLINE_EXCEEDED"
    );
  }

  // Aspect VERSION HISTORY — the contradiction-recovery read. This is a DIRECT GMS read
  // over the OpenAPI v3 versioned-aspect endpoints (systemMetadata=true), NOT one of the
  // DataHub MCP read tools: the MCP tools return only the current view, so the cross-source
  // conflict that latest-write-wins collapsed is invisible to them. GMS still retains every
  // prior write with the execution `runId` and, when configured by the ingestion source,
  // stable `pipelineName`. `version-history.ts` fails closed unless a stable source
  // identity is available; distinct run ids alone are never treated as distinct sources.
  //
  // Requires DATAHUB_GMS_URL (+ a PAT). Bounded per aspect. Exercised against a live GMS on
  // a cloud VM (user-gated) — version-enumeration semantics are instance/version-dependent,
  // so this transport is deliberately outside the coverage gate; the PURE mapping + audit it
  // feeds (version-history.ts) is fully unit-tested.
  async harvestVersionHistories(query?: string): Promise<AspectVersionHistory[]> {
    return (
      await this.harvestAudit(query, { profile: "async-worker" })
    ).versionHistories;
  }

  // Assemble provenance reports from the live catalog: search → get_entities → get_lineage.
  // A single harvest = one source at one scan (scanId = today), because DataHub's MCP read
  // surface returns only the current value per aspect. Cross-source CONTRADICTION detection
  // therefore needs aspect version history (systemMetadata / OpenAPI v3) which the MCP tools
  // do not expose — it lights up across scans once a findings store diffs harvests
  // (Phase 3). Lineage-gap + governance findings work fully on this surface today.
  private async harvestWithinPolicy(
    query: string | undefined,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<AuditHarvest> {
    const { reports, urns } = await this.reports(query, policy, signal);
    return {
      snapshot: snapshotFromReports(reports),
      facts: reportsToFacts(reports),
      versionHistories: await this.histories(urns, policy, signal),
    };
  }

  private async reports(
    query: string | undefined,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<{ reports: SourceReport[]; urns: Urn[] }> {
    const urns = await this.searchWithinPolicy(query, policy, signal);
    const entities = await this.getEntitiesWithinPolicy(urns, policy, signal);
    const known = new Set<Urn>(entities.map((e) => e.urn));
    const withLineage = await mapWithConcurrency(
      entities,
      policy.lineageConcurrency,
      signal,
      async (e) => ({
        ...e,
        upstreams: await this.getLineageWithinPolicy(
          e.urn,
          (u) => known.has(u),
          policy,
          signal
        ),
      })
    );
    const now = new Date().toISOString();
    const scanId = now.slice(0, 10);
    return {
      urns,
      reports: withLineage.map((e) => ({
        source: e.source || LIVE_SOURCE,
        scanId,
        createdAt: now,
        entity: e,
      })),
    };
  }

  private async searchWithinPolicy(
    query: string | undefined,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<Urn[]> {
    const q = query && query.trim().length > 0 ? query : "*";
    const urns: Urn[] = [];
    const seen = new Set<Urn>();
    let offset = 0;
    let declaredTotal: number | undefined;
    while (declaredTotal === undefined || offset < declaredTotal) {
      const response = (await this.call(
        "search",
        {
          query: q,
          filter: "entity_type = dataset",
          num_results: SEARCH_PAGE_SIZE,
          offset,
        },
        signal,
        policy.operationTimeoutMs
      )) as DhSearchResponse | null;
      const page = mapSearchPageStrict(
        response,
        offset,
        policy.maxEntities
      );
      if (
        declaredTotal !== undefined &&
        page.total !== declaredTotal
      ) {
        throw new DataHubHarvestError(
          "SEARCH_RESPONSE_INCOMPLETE",
          "DataHub search total changed during the bounded harvest."
        );
      }
      declaredTotal ??= page.total;
      if (page.urns.length === 0 && offset < declaredTotal) {
        throw new DataHubHarvestError(
          "SEARCH_RESPONSE_INCOMPLETE",
          "DataHub search ended before its declared total was returned."
        );
      }
      for (const urn of page.urns) {
        if (seen.has(urn)) {
          throw new DataHubHarvestError(
            "SEARCH_RESPONSE_INCOMPLETE",
            "DataHub search returned a duplicate URN across pages."
          );
        }
        seen.add(urn);
        urns.push(urn);
      }
      offset += page.urns.length;
    }
    if (declaredTotal === undefined || urns.length !== declaredTotal) {
      throw new DataHubHarvestError(
        "SEARCH_RESPONSE_INCOMPLETE",
        "DataHub search did not return its complete declared result set."
      );
    }
    return urns;
  }

  private async getEntitiesWithinPolicy(
    urns: Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<CatalogEntity[]> {
    if (urns.length === 0) return [];
    if (urns.length > policy.maxEntities) {
      throw new DataHubHarvestError(
        "SEARCH_LIMIT_EXCEEDED",
        `The entity request exceeds the ${policy.maxEntities}-entity hosted safety limit.`
      );
    }
    const response = (await this.call(
      "get_entities",
      { urns },
      signal,
      policy.operationTimeoutMs
    )) as DhCleanedEntity[] | { entities?: DhCleanedEntity[] } | null;
    return mapEntitiesStrict(response, urns, LIVE_SOURCE);
  }

  private async getLineageWithinPolicy(
    urn: Urn,
    isKnown: (urn: Urn) => boolean,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<LineageEdge[]> {
    const response = (await this.call(
      "get_lineage",
      {
        urn,
        upstream: true,
        max_hops: 1,
        max_results: MAX_LINEAGE_RESULTS,
        offset: 0,
      },
      signal,
      policy.operationTimeoutMs
    )) as DhLineageResponse | null;
    return mapUpstreamEdgesStrict(
      response,
      isKnown,
      MAX_LINEAGE_RESULTS
    );
  }

  private async histories(
    urns: readonly Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<AspectVersionHistory[]> {
    const gms = requireDirectHistoryCapability(
      process.env.DATAHUB_GMS_URL
    );
    if (urns.length === 0) return [];
    if (urns.length > policy.maxEntities) {
      throw new DataHubHarvestError(
        "SEARCH_LIMIT_EXCEEDED",
        `Version-history scope exceeds the ${policy.maxEntities}-URN hosted safety limit.`
      );
    }
    const token = process.env.DATAHUB_GMS_TOKEN;
    const work = urns.flatMap((urn) =>
      MUTABLE_ASPECTS.map((aspect) => ({ urn, aspect }))
    );
    const results = await mapWithConcurrency(
      work,
      policy.historyConcurrency,
      signal,
      async ({ urn, aspect }): Promise<AspectVersionHistory | null> => {
        const versions = await readAspectVersionHistory(
          gms,
          token,
          urn,
          aspect,
          {
            maxHistoricalVersions: policy.maxHistoricalVersions,
            requestTimeoutMs: policy.operationTimeoutMs,
            signal,
          }
        );
        return versions.length > 0 ? { urn, aspect, versions } : null;
      }
    );
    return results.filter(
      (history): history is AspectVersionHistory => history !== null
    );
  }
}
