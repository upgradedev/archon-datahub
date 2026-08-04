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
import type {
  CatalogEntity,
  CatalogSnapshot,
  LineageEdge,
  LineageTopologyNode,
  Urn,
} from "./models.js";
import { reportsToFacts, type SourceReport } from "../audit/harvest.js";
import type {
  AuditHarvest,
  AuditHarvestOptions,
  DataHubClient,
} from "./mcp-client.js";
import { snapshotFromReports } from "./mcp-client.js";
import {
  assertLineageRelationLimit,
  completeEntitySchema,
  mapDownstreamTopologyStrict,
  mapEntity,
  mapSchemaFieldPageStrict,
  mapSearchPageStrict,
  mapUpstreamEdgesStrict,
  orderedEntitiesStrict,
  parseMcpReadToolResult,
  reconcileUpstreamEdgesStrict,
  schemaCompletionRequirement,
  type DhCleanedEntity,
  type DhCleanedSchemaField,
  type DhLineageResponse,
  type DhSchemaFieldPageResponse,
  type DhSearchResponse,
} from "./live-mappers.js";
import type {
  AspectVersionHistory,
  MutableAspectName,
} from "./version-history.js";
import {
  readAspectVersionHistory,
  readCurrentUpstreamLineage,
  type DeclaredUpstreamLineage,
} from "./version-history-reader.js";
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
const MUTABLE_ASPECTS: readonly MutableAspectName[] = [
  "ownership",
  "schemaMetadata",
  "domains",
  "deprecation",
];

interface LiveLineageTopology {
  upstreamByRoot: Map<Urn, LineageEdge[]>;
  downstreamByRoot: Map<Urn, LineageTopologyNode[]>;
  knownLineageUrns: Set<Urn>;
}

interface DirectAspectHarvest {
  declaredUpstreamsByRoot: Map<Urn, DeclaredUpstreamLineage[]>;
  versionHistories: AspectVersionHistory[];
}

type DirectAspectTask =
  | {
      kind: "current-upstreams";
      urn: Urn;
    }
  | {
      kind: "history";
      urn: Urn;
      aspect: MutableAspectName;
    };

type DirectAspectResult =
  | {
      kind: "current-upstreams";
      urn: Urn;
      declared: DeclaredUpstreamLineage[];
    }
  | {
      kind: "history";
      history: AspectVersionHistory | null;
    };

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
    return this.getUpstreamLineageWithinPolicy(urn, policy, signal);
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
  // Resolve runId -> stable ingestion source from DataHub's own registry.
  //
  // `systemMetadata.pipelineName` is sticky per aspect: two independent ingestion
  // runs leave the FIRST pipeline name on every retained version, which merges two
  // real sources into one. The registry does not have that defect -- each run is a
  // `dataHubExecutionRequest` whose id equals the aspect's runId, under the
  // `dataHubIngestionSource` that produced it. Failure is non-fatal: an empty map
  // simply falls back to pipelineName and then to `unknown-source`.
  private async resolveSourceIdentities(): Promise<Record<string, string>> {
    const override = process.env.ARCHON_SOURCE_MAP;
    if (override) {
      try {
        const parsed = JSON.parse(override) as Record<string, string>;
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          return parsed;
        }
      } catch {
        // An unparseable override is ignored rather than trusted.
      }
    }

    const base = process.env.DATAHUB_GMS_URL;
    if (!base) return {};
    const query =
      "{ listIngestionSources(input:{start:0,count:100}) { ingestionSources " +
      "{ name executions(start:0,count:100){ executionRequests { id } } } } }";
    try {
      const response = await fetch(`${base.replace(/\/+$/, "")}/api/graphql`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(process.env.DATAHUB_GMS_TOKEN
            ? { Authorization: `Bearer ${process.env.DATAHUB_GMS_TOKEN}` }
            : {}),
        },
        body: JSON.stringify({ query }),
      });
      if (!response.ok) return {};
      const payload = (await response.json()) as {
        data?: {
          listIngestionSources?: {
            ingestionSources?: Array<{
              name?: string;
              executions?: { executionRequests?: Array<{ id?: string }> };
            }>;
          };
        };
      };
      const sources =
        payload.data?.listIngestionSources?.ingestionSources ?? [];
      const map: Record<string, string> = {};
      for (const source of sources) {
        const name = typeof source?.name === "string" ? source.name.trim() : "";
        if (!name) continue;
        for (const execution of source.executions?.executionRequests ?? []) {
          const id = typeof execution?.id === "string" ? execution.id.trim() : "";
          if (id) map[id] = name;
        }
      }
      return map;
    } catch {
      return {};
    }
  }

  async harvestVersionHistories(query?: string): Promise<AspectVersionHistory[]> {
    return (
      await this.harvestAudit(query, { profile: "async-worker" })
    ).versionHistories;
  }

  // Assemble one completeness-bound live harvest. After the bounded search fixes the audited
  // roots, entity/schema completion, bidirectional topology, current raw upstreamLineage,
  // and retained history can run concurrently. The direct current aspect declares every
  // edge (including dangling references); the MCP search independently proves which direct
  // dataset URNs resolve. Topology neighbors augment identity/reachability only; they never
  // become audited entities and never enter version-history work.
  // A single harvest = one source at one scan (scanId = today), because DataHub's MCP read
  // surface returns only the current value per aspect. Cross-source CONTRADICTION detection
  // therefore consumes retained aspect history (systemMetadata / OpenAPI v3) in this same
  // harvest bundle; the MCP tools alone do not expose that evidence. Lineage-gap and
  // governance findings likewise use the completeness-bound evidence assembled here.
  private async harvestWithinPolicy(
    query: string | undefined,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<AuditHarvest> {
    const urns = await this.searchWithinPolicy(query, policy, signal);
    const [entities, topology, directAspects] = await Promise.all([
      this.getEntitiesWithinPolicy(urns, policy, signal),
      this.getLineageTopologyWithinPolicy(urns, policy, signal),
      this.directAspects(urns, policy, signal),
    ]);
    const reconciledUpstreamByRoot = new Map<Urn, LineageEdge[]>();
    const withLineage = entities.map((entity) => {
      const resolvedUpstreams = topology.upstreamByRoot.get(entity.urn);
      const declaredUpstreams =
        directAspects.declaredUpstreamsByRoot.get(entity.urn);
      if (!resolvedUpstreams || !declaredUpstreams) {
        throw new DataHubHarvestError(
          "LINEAGE_RESPONSE_INCOMPLETE",
          "DataHub lineage omitted an audited root from the completed current-view evidence."
        );
      }
      const upstreams = reconcileUpstreamEdgesStrict(
        declaredUpstreams,
        resolvedUpstreams,
        policy.maxLineageResultsPerDirection
      );
      reconciledUpstreamByRoot.set(entity.urn, upstreams);
      return {
        ...entity,
        upstreams,
      };
    });
    assertLineageRelationLimit(
      reconciledUpstreamByRoot,
      topology.downstreamByRoot,
      policy.maxLineageRelations
    );
    const now = new Date().toISOString();
    const scanId = now.slice(0, 10);
    const reports: SourceReport[] = withLineage.map((entity) => ({
      source: entity.source || LIVE_SOURCE,
      scanId,
      createdAt: now,
      entity,
    }));
    return {
      snapshot: snapshotFromReports(reports, {
        downstreamByRoot: topology.downstreamByRoot,
        knownLineageUrns: topology.knownLineageUrns,
      }),
      facts: reportsToFacts(reports),
      versionHistories: directAspects.versionHistories,
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
    // A normal loop exit proves the first page established declaredTotal;
    // all pre-assignment failure paths throw instead of reaching this point.
    if (urns.length !== declaredTotal) {
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
    const ordered = orderedEntitiesStrict(response, urns);
    const completed = await mapWithConcurrency(
      ordered,
      policy.schemaCompletionConcurrency,
      signal,
      (entity) => this.completeSchemaWithinPolicy(entity, policy, signal)
    );
    return completed.map((entity) => mapEntity(entity, LIVE_SOURCE));
  }

  private async completeSchemaWithinPolicy(
    entity: DhCleanedEntity,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<DhCleanedEntity> {
    const requirement = schemaCompletionRequirement(
      entity,
      policy.maxSchemaFieldsPerEntity
    );
    if (!requirement.required) return entity;
    const urn = entity.urn;
    if (typeof urn !== "string" || urn.length === 0) {
      throw new DataHubHarvestError(
        "ENTITY_RESPONSE_INCOMPLETE",
        "A schema completion request requires its validated entity URN."
      );
    }

    const fields: DhCleanedSchemaField[] = [];
    const seen = new Set<string>();
    let offset = 0;
    let pages = 0;
    while (offset < requirement.totalFields) {
      if (pages >= policy.maxSchemaFieldPages) {
        throw new DataHubHarvestError(
          "SCHEMA_LIMIT_EXCEEDED",
          `DataHub schema completion exceeded the ${policy.maxSchemaFieldPages}-page hosted safety limit.`
        );
      }
      const response = (await this.call(
        "list_schema_fields",
        {
          urn,
          limit: policy.schemaFieldPageSize,
          offset,
        },
        signal,
        policy.operationTimeoutMs
      )) as DhSchemaFieldPageResponse | null;
      const page = mapSchemaFieldPageStrict(
        response,
        urn,
        offset,
        policy.schemaFieldPageSize,
        policy.maxSchemaFieldsPerEntity
      );
      if (page.total !== requirement.totalFields) {
        throw new DataHubHarvestError(
          "SCHEMA_RESPONSE_INCOMPLETE",
          "DataHub schema total changed between get_entities and list_schema_fields."
        );
      }
      for (const field of page.fields) {
        if (seen.has(field.fieldPath)) {
          throw new DataHubHarvestError(
            "SCHEMA_RESPONSE_INCOMPLETE",
            "DataHub list_schema_fields returned a duplicate field across pages."
          );
        }
        seen.add(field.fieldPath);
        fields.push(field);
      }
      offset += page.fields.length;
      pages += 1;
    }
    return completeEntitySchema(
      entity,
      fields,
      requirement.totalFields
    );
  }

  private async getUpstreamLineageWithinPolicy(
    urn: Urn,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<LineageEdge[]> {
    const response = (await this.call(
      "get_lineage",
      {
        urn,
        upstream: true,
        filter: "entity_type = dataset",
        max_hops: 1,
        max_results: policy.maxLineageResultsPerDirection,
        offset: 0,
      },
      signal,
      policy.operationTimeoutMs
    )) as DhLineageResponse | null;
    return mapUpstreamEdgesStrict(
      response,
      policy.maxLineageResultsPerDirection
    );
  }

  private async getDownstreamTopologyWithinPolicy(
    urn: Urn,
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<LineageTopologyNode[]> {
    const response = (await this.call(
      "get_lineage",
      {
        urn,
        upstream: false,
        // Pinned MCP v0.6.0 defines max_hops=3 as unlimited-hop reachability.
        max_hops: 3,
        max_results: policy.maxLineageResultsPerDirection,
        offset: 0,
      },
      signal,
      policy.operationTimeoutMs
    )) as DhLineageResponse | null;
    return mapDownstreamTopologyStrict(
      response,
      policy.maxLineageResultsPerDirection
    );
  }

  private async getLineageTopologyWithinPolicy(
    urns: readonly Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<LiveLineageTopology> {
    const upstreamByRoot = new Map<Urn, LineageEdge[]>();
    const downstreamByRoot = new Map<Urn, LineageTopologyNode[]>();
    for (const urn of urns) {
      upstreamByRoot.set(urn, []);
      downstreamByRoot.set(urn, []);
    }
    const work = urns.flatMap((root) => [
      { root, direction: "upstream" as const },
      { root, direction: "downstream" as const },
    ]);
    const results = await mapWithConcurrency(
      work,
      policy.lineageConcurrency,
      signal,
      async (task) => {
        if (task.direction === "upstream") {
          return {
            ...task,
            edges: await this.getUpstreamLineageWithinPolicy(
              task.root,
              policy,
              signal
            ),
          };
        }
        return {
          ...task,
          nodes: await this.getDownstreamTopologyWithinPolicy(
            task.root,
            policy,
            signal
          ),
        };
      }
    );

    const knownLineageUrns = new Set<Urn>();
    let relationCount = 0;
    for (const result of results) {
      if (result.direction === "upstream") {
        upstreamByRoot.set(result.root, result.edges);
        relationCount += result.edges.length;
        for (const edge of result.edges) {
          knownLineageUrns.add(edge.upstream);
        }
      } else {
        downstreamByRoot.set(result.root, result.nodes);
        relationCount += result.nodes.length;
        for (const node of result.nodes) {
          knownLineageUrns.add(node.urn);
        }
      }
    }
    if (relationCount > policy.maxLineageRelations) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        `DataHub lineage exceeds the ${policy.maxLineageRelations}-relation hosted safety limit.`
      );
    }
    return {
      upstreamByRoot,
      downstreamByRoot,
      knownLineageUrns,
    };
  }

  private async directAspects(
    urns: readonly Urn[],
    policy: Readonly<LiveHarvestPolicy>,
    signal: AbortSignal
  ): Promise<DirectAspectHarvest> {
    const gms = requireDirectHistoryCapability(
      process.env.DATAHUB_GMS_URL
    );
    if (urns.length === 0) {
      return {
        declaredUpstreamsByRoot: new Map(),
        versionHistories: [],
      };
    }
    if (urns.length > policy.maxEntities) {
      throw new DataHubHarvestError(
        "SEARCH_LIMIT_EXCEEDED",
        `Direct-aspect scope exceeds the ${policy.maxEntities}-URN hosted safety limit.`
      );
    }
    const token = process.env.DATAHUB_GMS_TOKEN;
    const work: DirectAspectTask[] = [];
    for (const urn of urns) {
      work.push({ kind: "current-upstreams", urn });
      for (const aspect of MUTABLE_ASPECTS) {
        work.push({ kind: "history", urn, aspect });
      }
    }
    const results = await mapWithConcurrency(
      work,
      policy.historyConcurrency,
      signal,
      async (task): Promise<DirectAspectResult> => {
        if (task.kind === "current-upstreams") {
          const declared = await readCurrentUpstreamLineage(
            gms,
            token,
            task.urn,
            {
              requestTimeoutMs: policy.operationTimeoutMs,
              signal,
            }
          );
          return {
            kind: "current-upstreams",
            urn: task.urn,
            declared,
          };
        }
        const versions = await readAspectVersionHistory(
          gms,
          token,
          task.urn,
          task.aspect,
          {
            maxHistoricalVersions: policy.maxHistoricalVersions,
            requestTimeoutMs: policy.operationTimeoutMs,
            signal,
          }
        );
        return {
          kind: "history",
          history:
            versions.length > 0
              ? {
                  urn: task.urn,
                  aspect: task.aspect,
                  versions,
                }
              : null,
        };
      }
    );
    const declaredUpstreamsByRoot = new Map<
      Urn,
      DeclaredUpstreamLineage[]
    >();
    const versionHistories: AspectVersionHistory[] = [];
    for (const result of results) {
      if (result.kind === "current-upstreams") {
        if (declaredUpstreamsByRoot.has(result.urn)) {
          throw new DataHubHarvestError(
            "LINEAGE_RESPONSE_INCOMPLETE",
            "DataHub direct-aspect harvest duplicated an audited root."
          );
        }
        declaredUpstreamsByRoot.set(result.urn, result.declared);
      } else if (result.history) {
        versionHistories.push(result.history);
      }
    }
    if (declaredUpstreamsByRoot.size !== urns.length) {
      throw new DataHubHarvestError(
        "LINEAGE_RESPONSE_INCOMPLETE",
        "DataHub direct-aspect harvest omitted an audited root."
      );
    }
    const sourceIdentityByRunId = await this.resolveSourceIdentities();
    const resolvedHistories = versionHistories.map((history) => ({
      ...history,
      sourceIdentityByRunId,
    }));
    return { declaredUpstreamsByRoot, versionHistories: resolvedHistories };
  }
}
