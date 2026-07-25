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
import { AuditPipeline } from "../pipeline/pipeline.js";
import { defaultAuditLoop } from "../ap/loop.js";

export const MCP_TOOLS: Tool[] = [
  {
    name: "audit_catalog",
    description:
      "Run the full read-only audit pipeline (classifier → lineage-analyzer → governance-auditor → " +
      "narrator) over one narrowly scoped DataHub dataset and return the findings + an executive " +
      "summary. The audit phase is read-only; any later governed action remains separately human-gated.",
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
            "Required narrow query that resolves to exactly one hosted demo dataset.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "run_audit_loop",
    description:
      "Run the bounded multi-step ReAct audit loop (harvest → self-audit → governance → emit) and return " +
      "the PENDING findings + the full step trace for one narrowly scoped dataset. This loop is read-only.",
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
            "Required narrow query that resolves to exactly one hosted demo dataset.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "search_datasets",
    description:
      "Resolve a narrow DataHub dataset query. Hosted execution fails closed unless at most one dataset matches.",
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
          description: "Required non-wildcard dataset query.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "get_entity",
    description: "Fetch the current metadata (aspects) for one dataset URN. Read-only.",
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
    query.length === 0 ||
    /[*?]/u.test(query) ||
    query === "{}" ||
    /[\u0000-\u001f\u007f]/u.test(query)
  ) {
    return null;
  }
  return query;
}

// Dispatch one tool call against the agent. Extracted so it is unit-testable in
// isolation and shared by the stdio + in-memory transports.
export async function callAuditTool(
  deps: McpDeps,
  name: string,
  args: Record<string, unknown>
): Promise<CallToolResult> {
  try {
    const query = narrowQuery(args.query);
    switch (name) {
      case "audit_catalog": {
        if (!query) return fail("audit_catalog requires a narrow, non-wildcard query.");
        return ok(
          await deps.pipeline.run(deps.datahub, query, {
            executionProfile: "synchronous-preview",
          })
        );
      }
      case "run_audit_loop": {
        if (!query) return fail("run_audit_loop requires a narrow, non-wildcard query.");
        return ok(await defaultAuditLoop().run(deps.datahub, query));
      }
      case "search_datasets": {
        if (!query) return fail("search_datasets requires a narrow, non-wildcard query.");
        return ok({ urns: await deps.datahub.search(query) });
      }
      case "get_entity": {
        const urn = String(args.urn ?? "");
        if (!urn) return fail("get_entity requires a urn.");
        const [entity] = await deps.datahub.getEntities([urn]);
        return entity ? ok(entity) : fail(`not found: ${urn}`);
      }
      default:
        return fail(`unknown tool: ${name}`);
    }
  } catch (err) {
    return fail(`error: ${(err as Error).message}`);
  }
}

export async function buildMcpServer(deps?: Partial<McpDeps>): Promise<{ server: Server; deps: McpDeps }> {
  const resolved: McpDeps = {
    datahub: deps?.datahub ?? (await createDataHubClient()),
    pipeline: deps?.pipeline ?? new AuditPipeline(),
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
  main().catch((err) => {
    process.stderr.write(`MCP server failed: ${(err as Error).message}\n`);
    process.exit(1);
  });
}
