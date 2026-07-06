// Live DataHub MCP client — the thin adapter that maps the OFFICIAL DataHub MCP
// server (`acryldata/mcp-server-datahub`) onto our DataHubClient interface.
//
// PROVISIONAL. This path is network-bound and therefore NOT exercised by the offline
// test suite (it is excluded from coverage, exactly as a real transport client should
// be — the Fake carries the shared logic and the tests). It is wired to the documented
// tool names + HTTP transport (docs/DATAHUB_RESEARCH.md §3): the self-hosted GMS
// exposes an MCP endpoint at `${DATAHUB_GMS_URL}/mcp`; DataHub Cloud exposes one at the
// tenant integrations URL. The exact JSON payload of each tool response is version-
// dependent, so the aspect mapping below is best-effort and defensive — when the live
// slice runs against a real instance we pin it against captured responses.
//
// The intended home for a live DataHub instance is a CLOUD VM (the quickstart is a
// ~14-container stack — see README "Running against a real DataHub"), never the dev
// desktop.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { AuditFact } from "../types.js";
import type { CatalogEntity, CatalogSnapshot, LineageEdge, Urn } from "./models.js";
import { reportsToFacts, type SourceReport } from "../audit/harvest.js";
import type { DataHubClient } from "./mcp-client.js";
import { snapshotFromReports } from "./mcp-client.js";

function mcpUrl(): string {
  const explicit = process.env.DATAHUB_MCP_URL;
  if (explicit) return explicit;
  const gms = process.env.DATAHUB_GMS_URL ?? "http://localhost:8080";
  return `${gms.replace(/\/$/, "")}/mcp`;
}

// Parse the MCP text-content contract into a JS value (tools return their JSON as a
// text block, per the MCP content spec).
function parseToolResult(result: unknown): unknown {
  const content = (result as { content?: Array<{ type: string; text?: string }> })?.content ?? [];
  const text = content.find((c) => c.type === "text")?.text;
  if (!text) return null;
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
    this.client = new Client({ name: "archon-datahub", version: "0.1.0" }, { capabilities: {} });
  }

  private async connect(): Promise<void> {
    if (this.connected) return;
    const headers: Record<string, string> = {};
    const token = process.env.DATAHUB_GMS_TOKEN;
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl()), {
      requestInit: { headers },
    });
    await this.client.connect(transport);
    this.connected = true;
  }

  private async call(name: string, args: Record<string, unknown>): Promise<unknown> {
    await this.connect();
    const res = await this.client.callTool({ name, arguments: args });
    return parseToolResult(res);
  }

  async search(query?: string): Promise<Urn[]> {
    const res = (await this.call("search", { query: query ?? "*", entity_types: ["dataset"] })) as
      | { urns?: Urn[]; entities?: Array<{ urn: Urn }> }
      | null;
    if (!res) return [];
    if (Array.isArray(res.urns)) return res.urns;
    if (Array.isArray(res.entities)) return res.entities.map((e) => e.urn);
    return [];
  }

  async getEntities(urns: Urn[]): Promise<CatalogEntity[]> {
    if (urns.length === 0) return [];
    const res = (await this.call("get_entities", { urns })) as
      | { entities?: unknown[] }
      | unknown[]
      | null;
    const raw = Array.isArray(res) ? res : (res?.entities ?? []);
    return (raw as unknown[]).map((e) => mapEntity(e));
  }

  async getLineage(urn: Urn): Promise<LineageEdge[]> {
    const res = (await this.call("get_lineage", { urn, direction: "upstream" })) as
      | { upstreams?: Array<{ urn: Urn; type?: string }> }
      | null;
    return (res?.upstreams ?? []).map((u) => ({
      upstream: u.urn,
      upstreamResolved: true, // a returned lineage node is a resolved node
      type: u.type,
    }));
  }

  async harvestSnapshot(query?: string): Promise<CatalogSnapshot> {
    return snapshotFromReports(await this.reports(query));
  }

  async harvestFacts(query?: string): Promise<AuditFact[]> {
    return reportsToFacts(await this.reports(query));
  }

  // Assemble provenance reports from the live catalog. Live systemMetadata provenance
  // per aspect is version-dependent; until pinned we report the current view as a
  // single source, so lineage-gap + governance findings work and cross-source
  // contradiction detection lights up once per-aspect provenance is mapped.
  private async reports(query?: string): Promise<SourceReport[]> {
    const urns = await this.search(query);
    const entities = await this.getEntities(urns);
    const withLineage = await Promise.all(
      entities.map(async (e) => ({ ...e, upstreams: await this.getLineage(e.urn) }))
    );
    const now = new Date().toISOString();
    return withLineage.map((e) => ({
      source: e.source || "datahub",
      scanId: now.slice(0, 10),
      createdAt: now,
      entity: e,
    }));
  }
}

// Best-effort map of a live entity payload onto our neutral CatalogEntity.
function mapEntity(e: unknown): CatalogEntity {
  const o = (e ?? {}) as Record<string, unknown>;
  const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
  const urn = asStr(o["urn"]) ?? "";
  return {
    urn,
    name: asStr(o["name"]) ?? urn,
    platform: asStr(o["platform"]) ?? "unknown",
    source: asStr(o["source"]) ?? "datahub",
    description: asStr(o["description"]) ?? null,
    owners: Array.isArray(o["owners"]) ? (o["owners"] as Urn[]) : [],
    domain: asStr(o["domain"]) ?? null,
    tags: Array.isArray(o["tags"]) ? (o["tags"] as string[]) : [],
    glossaryTerms: Array.isArray(o["glossaryTerms"]) ? (o["glossaryTerms"] as string[]) : [],
    deprecated: typeof o["deprecated"] === "boolean" ? (o["deprecated"] as boolean) : false,
    fields: Array.isArray(o["fields"])
      ? (o["fields"] as Array<Record<string, unknown>>).map((f) => ({
          path: asStr(f["path"]) ?? "",
          type: asStr(f["type"]) ?? null,
          tags: Array.isArray(f["tags"]) ? (f["tags"] as string[]) : [],
          glossaryTerms: Array.isArray(f["glossaryTerms"]) ? (f["glossaryTerms"] as string[]) : [],
        }))
      : [],
    upstreams: [],
  };
}
