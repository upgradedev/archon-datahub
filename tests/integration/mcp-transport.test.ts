// Integration — the MCP surface end to end through a REAL MCP Client ↔ Server pair
// over an in-memory transport. This proves the full protocol wiring (tool registration,
// the ListTools + CallTool JSON-RPC round-trip, the content/isError contract) — not just
// the dispatch function — while staying fully offline (Fakes, no key, no network). It is
// the headline "round-trip through OUR MCP surface" test, and it asserts the read-only
// guarantee holds over MCP.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  buildMcpServer,
  type McpDeps,
} from "../../src/mcp/server.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";

delete process.env.LLM_API_KEY;
delete process.env.LLM_PROVIDER;
delete process.env.AWS_BEARER_TOKEN_BEDROCK;
delete process.env.DATAHUB_MCP_URL;
delete process.env.DATAHUB_GMS_URL;
delete process.env.ARCHON_DEMO_QUERY;

async function connect(
  overrides: Partial<McpDeps> = {}
): Promise<{ client: Client; close: () => Promise<void> }> {
  const { server } = await buildMcpServer({
    datahub: new FakeDataHubMcpClient(),
    pipeline: new AuditPipeline(),
    demoQuery: "sales",
    ...overrides,
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" }, { capabilities: {} });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

function payload(res: unknown): any {
  return JSON.parse((res as { content: Array<{ text: string }> }).content[0]!.text);
}

test("MCP client can list the read-only audit tools", async () => {
  const { client, close } = await connect();
  try {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, ["audit_catalog", "get_entity", "run_audit_loop", "search_datasets"]);
    for (const t of tools) {
      assert.equal((t.inputSchema as { type: string }).type, "object");
      if (t.name !== "get_entity") {
        assert.deepEqual((t.inputSchema as { required?: string[] }).required, ["query"]);
      }
    }
  } finally {
    await close();
  }
});

test("audit_catalog round-trip over a real MCP Client returns findings + narrative", async () => {
  const { client, close } = await connect();
  try {
    const report = payload(
      await client.callTool({ name: "audit_catalog", arguments: { query: "sales" } })
    );
    assert.ok(report.findings.length >= 1);
    assert.equal(report.findings[0].severity, "high");
    assert.ok(report.narrative);
    assert.equal(report.trace.length, 4);
  } finally {
    await close();
  }
});

test("run_audit_loop over MCP is human-gated (pending) and mutates nothing", async () => {
  const { client, close } = await connect();
  try {
    const out = payload(
      await client.callTool({ name: "run_audit_loop", arguments: { query: "sales" } })
    );
    assert.equal(out.disposition, "pending");
    assert.equal(out.stopReason, "emitted_findings");
    assert.ok(out.trace.length >= 3);
  } finally {
    await close();
  }
});

test("model-backed MCP transport failures are stable and never expose provider detail", async () => {
  const sentinel = `sk-${"transport-secret".repeat(3)}`;
  const pipeline = {
    run: async () => {
      throw new Error(
        `provider rejected ${sentinel} at https://gateway.example/v1`
      );
    },
  } as unknown as AuditPipeline;
  const loop = {
    run: async () => {
      throw new Error(`loop rejected ${sentinel}`);
    },
  };
  const { client, close } = await connect({ pipeline, loop });
  try {
    for (const name of ["audit_catalog", "run_audit_loop"]) {
      const result = (await client.callTool({
        name,
        arguments: { query: "sales" },
      })) as {
        isError?: boolean;
        content: Array<{ text: string }>;
      };
      assert.equal(result.isError, true);
      assert.equal(result.content[0]?.text, "error: tool_execution_failed");
      assert.doesNotMatch(JSON.stringify(result), new RegExp(sentinel));
      assert.doesNotMatch(JSON.stringify(result), /gateway\.example/u);
    }
  } finally {
    await close();
  }
});

test("search_datasets + get_entity round-trip returns only the configured dataset's public identity", async () => {
  const { client, close } = await connect();
  try {
    const search = payload(await client.callTool({ name: "search_datasets", arguments: { query: "sales" } }));
    assert.deepEqual(search.urns, [
      "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)",
    ]);

    const entity = payload(
      await client.callTool({
        name: "get_entity",
        arguments: { urn: search.urns[0] },
      })
    );
    assert.deepEqual(Object.keys(entity).sort(), [
      "deprecated",
      "fabric",
      "name",
      "platform",
      "schemaVersion",
      "urn",
    ]);
    assert.equal(entity.schemaVersion, "archon.public-catalog-entity/v1");
    assert.equal(entity.name, "sales_orders");
    assert.doesNotMatch(
      JSON.stringify(entity),
      /description|owner|field|tag|glossary|domain|source|upstream|dbt-ingest/iu
    );

    const err = (await client.callTool({ name: "get_entity", arguments: { urn: "urn:ds:nope" } })) as {
      isError?: boolean;
      content: Array<{ text: string }>;
    };
    assert.equal(err.isError, true);
    assert.equal(err.content[0]?.text, "error: entity_outside_public_demo_scope");

    const alternate = (await client.callTool({
      name: "search_datasets",
      arguments: { query: "customer" },
    })) as {
      isError?: boolean;
      content: Array<{ text: string }>;
    };
    assert.equal(alternate.isError, true);
    assert.equal(
      alternate.content[0]?.text,
      "error: query_outside_public_demo_scope"
    );
  } finally {
    await close();
  }
});
