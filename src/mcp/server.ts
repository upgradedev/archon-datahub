// MCP server — the Model Context Protocol surface over the Archon-DataHub agent.
//
// This exposes the read-only governance agent to any standard MCP client (an IDE, an
// orchestrator, another agent) as MCP TOOLS. It is a thin WRAPPER over the SAME
// injectable pipeline + loop the rest of the agent uses — one agent, two faces (this
// server CONSUMES the DataHub MCP server for metadata, and RE-EXPOSES its audit as
// tools). Every tool is READ-ONLY: audit_catalog / run_audit_loop recommend findings;
// search_datasets / get_entity read metadata. Nothing here mutates DataHub.
//
// Transport: stdio (main()). Built by buildMcpServer(deps) so tests drive it offline
// over an in-memory transport with the Fakes — no network, no key. stdout is owned by
// the JSON-RPC transport; this module logs only to stderr.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { pathToFileURL } from "node:url";
import { createDataHubClient, type DataHubClient } from "../datahub/mcp-client.js";
import type { CatalogEntity } from "../datahub/models.js";
import { AuditPipeline } from "../pipeline/pipeline.js";
import { defaultAuditLoop, type AuditLoop } from "../ap/loop.js";
import {
  projectPublicAuditReport,
  projectPublicAuditRunResult,
} from "../reporting/public-audit-report.js";

export const MCP_TOOLS: Tool[] = [
  {
    name: "audit_catalog",
    description:
      "Run the full read-only audit pipeline (classifier → lineage-analyzer → governance-auditor → " +
      "narrator) over one narrowly scoped DataHub dataset and return the findings + an executive " +
      "summary. The query must exactly match the server-configured public demo scope. The audit phase " +
      "is read-only; any later governed action remains separately human-gated.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        query: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          pattern:
            "^(?!\\s*$)(?!\\s*\\{\\}\\s*$)(?!.*[*?])[^\\u0000-\\u001f\\u007f]+$",
          description:
            "Must exactly equal the server-configured public demo query.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "run_audit_loop",
    description:
      "Run the bounded multi-step ReAct audit loop (harvest → self-audit → governance → emit) and return " +
      "the PENDING findings + the full step trace for the server-configured public demo dataset. " +
      "This loop is read-only.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        query: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          pattern:
            "^(?!\\s*$)(?!\\s*\\{\\}\\s*$)(?!.*[*?])[^\\u0000-\\u001f\\u007f]+$",
          description:
            "Must exactly equal the server-configured public demo query.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "search_datasets",
    description:
      "Resolve the exact server-configured public demo query. Execution fails closed unless exactly one dataset matches.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        query: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          pattern:
            "^(?!\\s*$)(?!\\s*\\{\\}\\s*$)(?!.*[*?])[^\\u0000-\\u001f\\u007f]+$",
          description: "Must exactly equal the server-configured public demo query.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "get_entity",
    description:
      "Return a minimal public projection of the single dataset resolved by the server-configured demo query. Read-only.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { urn: { type: "string", description: "The dataset URN." } },
      required: ["urn"],
    },
  },
];

export interface McpDeps {
  datahub: DataHubClient;
  pipeline: AuditPipeline;
  loop?: Pick<AuditLoop, "run">;
  demoQuery?: string;
}

function ok(payload: unknown): CallToolResult {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}
function fail(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function narrowQuery(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 256) return null;
  const query = value.trim();
  if (
    query !== value ||
    query.length === 0 ||
    /[*?]/u.test(query) ||
    query === "{}" ||
    /[\u0000-\u001f\u007f]/u.test(query)
  ) {
    return null;
  }
  return query;
}

const CREDENTIAL_PATTERNS = [
  /(?:AKIA|ASIA)[A-Z0-9]{16}/u,
  /gh[pousr]_[A-Za-z0-9_]{20,}/u,
  /github_pat_[A-Za-z0-9_]{20,}/u,
  /xox[baprs]-[A-Za-z0-9-]{10,}/u,
  /AIza[0-9A-Za-z_-]{35}/u,
  /(?:Bearer\s+|sk-(?:ant-)?)[A-Za-z0-9._~+/=-]{12,}/iu,
  /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/u,
  /(?:api[_ -]?key|password|passwd|pwd|secret|token)\s*[:=]\s*["']?[^\s"',;]{8,}/iu,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
] as const;

function publicText(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    CREDENTIAL_PATTERNS.some((pattern) => pattern.test(value))
  ) {
    throw new Error("unsafe public entity value");
  }
  return value;
}

function configuredDemoQuery(deps: McpDeps): string {
  const configured = deps.demoQuery;
  const query = narrowQuery(configured);
  if (!query || query !== configured) {
    throw new Error("public demo scope is unavailable");
  }
  return query;
}

function exactPublicQuery(
  deps: McpDeps,
  value: unknown,
  toolName: string
): string | CallToolResult {
  const query = narrowQuery(value);
  if (!query) {
    return fail(`${toolName} requires the exact configured demo query.`);
  }
  if (query !== configuredDemoQuery(deps)) {
    return fail("error: query_outside_public_demo_scope");
  }
  return query;
}

async function resolveDemoUrn(deps: McpDeps, query: string): Promise<string> {
  const urns = await deps.datahub.search(query);
  if (!Array.isArray(urns) || urns.length !== 1) {
    throw new Error("public demo scope did not resolve exactly once");
  }
  const urn = publicText(urns[0], 2_048);
  if (!urn.startsWith("urn:li:dataset:")) {
    throw new Error("public demo scope returned a non-dataset");
  }
  return urn;
}

function projectPublicEntity(
  entity: CatalogEntity,
  expectedUrn: string
): Record<string, unknown> {
  if (!entity || typeof entity !== "object" || entity.urn !== expectedUrn) {
    throw new Error("entity did not bind to the public demo scope");
  }
  if (
    entity.fabric !== undefined &&
    typeof entity.fabric !== "string"
  ) {
    throw new Error("invalid public entity fabric");
  }
  if (
    entity.deprecated !== undefined &&
    typeof entity.deprecated !== "boolean"
  ) {
    throw new Error("invalid public entity deprecation state");
  }
  return {
    schemaVersion: "archon.public-catalog-entity/v1",
    urn: publicText(entity.urn, 2_048),
    name: publicText(entity.name, 512),
    platform: publicText(entity.platform, 128),
    fabric:
      entity.fabric === undefined ? null : publicText(entity.fabric, 128),
    deprecated: entity.deprecated ?? null,
  };
}

// Dispatch one tool call against the agent. Extracted so it is unit-testable in
// isolation and shared by the stdio + in-memory transports.
export async function callAuditTool(
  deps: McpDeps,
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  try {
    switch (name) {
      case "audit_catalog": {
        const query = exactPublicQuery(
          deps,
          args.query,
          "audit_catalog"
        );
        if (typeof query !== "string") return query;
        await resolveDemoUrn(deps, query);
        return ok(
          projectPublicAuditReport(
            await deps.pipeline.run(deps.datahub, query, {
              executionProfile: "synchronous-preview",
            })
          )
        );
      }
      case "run_audit_loop": {
        const query = exactPublicQuery(
          deps,
          args.query,
          "run_audit_loop"
        );
        if (typeof query !== "string") return query;
        await resolveDemoUrn(deps, query);
        return ok(
          projectPublicAuditRunResult(
            await (deps.loop ?? defaultAuditLoop()).run(deps.datahub, query)
          )
        );
      }
      case "search_datasets": {
        const query = exactPublicQuery(
          deps,
          args.query,
          "search_datasets"
        );
        if (typeof query !== "string") return query;
        return ok({ urns: [await resolveDemoUrn(deps, query)] });
      }
      case "get_entity": {
        const urn =
          typeof args.urn === "string" &&
          args.urn === args.urn.trim() &&
          args.urn.length <= 2_048 &&
          !/[\u0000-\u001f\u007f]/u.test(args.urn)
            ? args.urn
            : "";
        if (!urn) return fail("get_entity requires an exact dataset urn.");
        const scopedUrn = await resolveDemoUrn(
          deps,
          configuredDemoQuery(deps)
        );
        if (urn !== scopedUrn) {
          return fail("error: entity_outside_public_demo_scope");
        }
        const entities = await deps.datahub.getEntities([scopedUrn]);
        if (!Array.isArray(entities) || entities.length !== 1) {
          throw new Error("public entity hydration was incomplete");
        }
        const entity = entities[0];
        if (!entity || entity.urn !== scopedUrn) {
          throw new Error("public entity hydration did not match scope");
        }
        return ok(projectPublicEntity(entity, scopedUrn));
      }
      default:
        return fail("error: unknown_tool");
    }
  } catch {
    // Upstream/provider errors are untrusted and can contain endpoints, request
    // identifiers, echoed payloads, or credentials. Keep the public MCP failure
    // stable and opaque; operational details belong only in access-controlled telemetry.
    return fail("error: tool_execution_failed");
  }
}

export async function buildMcpServer(deps?: Partial<McpDeps>): Promise<{ server: Server; deps: McpDeps }> {
  const demoQuery = deps?.demoQuery ?? process.env.ARCHON_DEMO_QUERY;
  const resolved: McpDeps = {
    datahub: deps?.datahub ?? (await createDataHubClient()),
    pipeline: deps?.pipeline ?? new AuditPipeline(),
    ...(deps?.loop ? { loop: deps.loop } : {}),
    ...(demoQuery !== undefined ? { demoQuery } : {}),
  };
  const server = new Server({ name: "archon-datahub", version: "0.1.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MCP_TOOLS }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    return callAuditTool(resolved, name, (args ?? {}) as Record<string, unknown>);
  });
  return { server, deps: resolved };
}

async function main(): Promise<void> {
  const { server } = await buildMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("archon-datahub MCP server ready on stdio\n");
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]!).href;
if (isMain) {
  main().catch(() => {
    process.stderr.write("MCP server failed during startup.\n");
    process.exit(1);
  });
}
