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
//   • stdio (default, the reliable OSS path): spawns `uvx mcp-server-datahub@latest` with
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
import type { DataHubClient } from "./mcp-client.js";
import { snapshotFromReports } from "./mcp-client.js";
import {
  mapEntities,
  mapSearchUrns,
  mapUpstreamEdges,
  type DhCleanedEntity,
  type DhLineageResponse,
  type DhSearchResponse,
} from "./live-mappers.js";
import type {
  AspectVersionHistory,
  DhVersionedAspect,
  MutableAspectName,
} from "./version-history.js";

// The DataHub MCP server tags every catalogued asset with its dataPlatform, but its READ
// tools return a single current view per URN (aspects are single-valued). So a live harvest
// is one logical source at one scan; we label it with a stable id and let TIME (scanId) be
// the provenance axis. See DESIGN.md §Phase-2 and the README limits note.
const LIVE_SOURCE = "datahub";

function httpMcpUrl(): string | null {
  const explicit = process.env.DATAHUB_MCP_URL;
  return explicit && explicit.trim().length > 0 ? explicit : null;
}

// Parse the MCP text-content contract into a JS value (tools return their JSON as a text
// block, per the MCP content spec: result.content = [{ type: "text", text: "<json>" }]).
function parseToolResult(result: unknown): unknown {
  const content = (result as { content?: Array<{ type: string; text?: string }> })?.content ?? [];
  const text = content.find((c) => c.type === "text")?.text;
  if (text === undefined) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
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
        args: (process.env.DATAHUB_MCP_ARGS ?? "mcp-server-datahub@latest").split(/\s+/),
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

  private async call(name: string, args: Record<string, unknown>): Promise<unknown> {
    await this.connect();
    const res = await this.client.callTool({ name, arguments: args });
    return parseToolResult(res);
  }

  // `search` — DataHub /q keyword search. Datasets only, via the documented filter DSL
  // (`entity_type = dataset`). num_results is capped at 50 by the server; we page by offset.
  async search(query?: string): Promise<Urn[]> {
    const q = query && query.trim().length > 0 ? query : "*";
    const urns: Urn[] = [];
    const seen = new Set<Urn>();
    let offset = 0;
    const page = 50; // the server's hard cap
    // Bounded paging: stop at total, at an empty page, or a safety ceiling.
    for (let i = 0; i < 40; i++) {
      const res = (await this.call("search", {
        query: q,
        filter: "entity_type = dataset",
        num_results: page,
        offset,
      })) as DhSearchResponse | null;
      const pageUrns = mapSearchUrns(res);
      for (const u of pageUrns) {
        if (!seen.has(u)) {
          seen.add(u);
          urns.push(u);
        }
      }
      const total = res?.total ?? pageUrns.length;
      offset += page;
      if (pageUrns.length === 0 || offset >= total) break;
    }
    return urns;
  }

  // `get_entities` — batch metadata by URN. Passing an ARRAY returns a list of cleaned
  // entities (per-URN { error, urn } objects for any that fail, which the mapper skips).
  async getEntities(urns: Urn[]): Promise<CatalogEntity[]> {
    if (urns.length === 0) return [];
    const res = (await this.call("get_entities", { urns })) as
      | DhCleanedEntity[]
      | { entities?: DhCleanedEntity[] }
      | null;
    return mapEntities(res, LIVE_SOURCE);
  }

  // `get_lineage` — upstream lineage for one entity. `upstream: true` (bool) → the response's
  // `upstreams.searchResults[].entity`. Resolution against the harvested URN set is decided
  // by the caller via `harvestSnapshot`/`reports`; standalone calls resolve optimistically.
  async getLineage(urn: Urn, isKnown: (u: Urn) => boolean = () => true): Promise<LineageEdge[]> {
    const res = (await this.call("get_lineage", {
      urn,
      upstream: true,
      max_hops: 1,
    })) as DhLineageResponse | null;
    return mapUpstreamEdges(res, isKnown);
  }

  async harvestSnapshot(query?: string): Promise<CatalogSnapshot> {
    return snapshotFromReports(await this.reports(query));
  }

  async harvestFacts(query?: string): Promise<AuditFact[]> {
    return reportsToFacts(await this.reports(query));
  }

  // Aspect VERSION HISTORY — the contradiction-recovery read. This is a DIRECT GMS read
  // over the OpenAPI v3 versioned-aspect endpoints (systemMetadata=true), NOT one of the
  // DataHub MCP read tools: the MCP tools return only the current view, so the cross-source
  // conflict that latest-write-wins collapsed is invisible to them. GMS still retains every
  // prior write with the `runId` that produced it, so reading an aspect's version list
  // resurfaces the conflicting per-run values that `version-history.ts` audits.
  //
  // Requires DATAHUB_GMS_URL (+ a PAT). Bounded per aspect. Exercised against a live GMS on
  // a cloud VM (user-gated) — version-enumeration semantics are instance/version-dependent,
  // so this transport is deliberately outside the coverage gate; the PURE mapping + audit it
  // feeds (version-history.ts) is fully unit-tested.
  async harvestVersionHistories(query?: string): Promise<AspectVersionHistory[]> {
    const gms = process.env.DATAHUB_GMS_URL;
    if (!gms) return [];
    const token = process.env.DATAHUB_GMS_TOKEN;
    const urns = await this.search(query);
    const aspects: MutableAspectName[] = ["ownership", "schemaMetadata", "domains", "deprecation"];
    const histories: AspectVersionHistory[] = [];
    for (const urn of urns) {
      for (const aspect of aspects) {
        const versions = await this.readAspectVersions(gms, token, urn, aspect);
        if (versions.length > 0) histories.push({ urn, aspect, versions });
      }
    }
    return histories;
  }

  // Read the stored versions of ONE aspect on ONE entity from GMS OpenAPI v3.
  //
  // DataHub's aspect version numbering is deliberately NOT trusted here. `?version=0` is the
  // latest, and historical rows are 1..N — but how `systemMetadata.version` reports its own
  // ordinal is deployment-dependent, so deriving the count from it risks fetching too few
  // versions and SILENTLY missing the middle write that carries the conflict. Instead we
  // enumerate v = 1, 2, 3… until a read returns nothing, collecting every non-null version
  // (bounded by MAX_VERSIONS). This captures the full history regardless of how `version`
  // is reported. Falls back to the current view (version 0) if no historical rows exist.
  private async readAspectVersions(
    gms: string,
    token: string | undefined,
    urn: string,
    aspect: MutableAspectName
  ): Promise<DhVersionedAspect[]> {
    const MAX_VERSIONS = 50;
    const base = gms.replace(/\/+$/, "");
    const headers: Record<string, string> = { Accept: "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const readOne = async (version: number): Promise<DhVersionedAspect | null> => {
      const url =
        `${base}/openapi/v3/entity/dataset/${encodeURIComponent(urn)}/${aspect}` +
        `?systemMetadata=true&version=${version}`;
      const res = await fetch(url, { headers });
      if (!res.ok) return null;
      const body = (await res.json()) as Record<string, unknown> | null;
      const wrapped = body?.[aspect] as DhVersionedAspect | undefined;
      return wrapped && typeof wrapped === "object" ? wrapped : null;
    };

    const versions: DhVersionedAspect[] = [];
    for (let v = 1; v <= MAX_VERSIONS; v++) {
      const entry = await readOne(v);
      if (!entry) break; // no more historical rows
      versions.push(entry);
    }
    if (versions.length > 0) return versions;
    // No historical rows enumerable → fall back to the current view (version 0).
    const latest = await readOne(0);
    return latest ? [latest] : [];
  }

  // Assemble provenance reports from the live catalog: search → get_entities → get_lineage.
  // A single harvest = one source at one scan (scanId = today), because DataHub's MCP read
  // surface returns only the current value per aspect. Cross-source CONTRADICTION detection
  // therefore needs aspect version history (systemMetadata / OpenAPI v3) which the MCP tools
  // do not expose — it lights up across scans once a findings store diffs harvests
  // (Phase 3). Lineage-gap + governance findings work fully on this surface today.
  private async reports(query?: string): Promise<SourceReport[]> {
    const urns = await this.search(query);
    const entities = await this.getEntities(urns);
    const known = new Set<Urn>(entities.map((e) => e.urn));
    const withLineage = await Promise.all(
      entities.map(async (e) => ({
        ...e,
        upstreams: await this.getLineage(e.urn, (u) => known.has(u)),
      }))
    );
    const now = new Date().toISOString();
    const scanId = now.slice(0, 10);
    return withLineage.map((e) => ({
      source: e.source || LIVE_SOURCE,
      scanId,
      createdAt: now,
      entity: e,
    }));
  }
}
