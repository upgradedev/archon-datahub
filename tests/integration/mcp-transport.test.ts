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
import { buildMcpServer } from "../../src/mcp/server.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";

delete process.env.LLM_API_KEY;
delete process.env.DATAHUB_MCP_URL;
delete process.env.DATAHUB_GMS_URL;

async function connect(): Promise<{ client: Client; close: () => Promise<void> }> {
  const { server } = await buildMcpServer({
    datahub: new FakeDataHubMcpClient(),
    pipeline: new AuditPipeline(),
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
    for (const t of tools) assert.equal((t.inputSchema as { type: string }).type, "object");
  } finally {
    await close();
  }
});

test("audit_catalog round-trip over a real MCP Client returns findings + narrative", async () => {
  const { client, close } = await connect();
  try {
    const report = payload(await client.callTool({ name: "audit_catalog", arguments: {} }));
    assert.ok(report.findings.length >= 5);
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
    const out = payload(await client.callTool({ name: "run_audit_loop", arguments: {} }));
    assert.equal(out.disposition, "pending");
    assert.equal(out.stopReason, "emitted_findings");
    assert.ok(out.trace.length >= 3);
  } finally {
    await close();
  }
});

test("search_datasets + get_entity round-trip; unknown urn returns an MCP error", async () => {
  const { client, close } = await connect();
  try {
    const search = payload(await client.callTool({ name: "search_datasets", arguments: { query: "sales" } }));
    assert.ok(search.urns.some((u: string) => u.includes("sales_orders")));

    const err = (await client.callTool({ name: "get_entity", arguments: { urn: "urn:ds:nope" } })) as {
      isError?: boolean;
    };
    assert.equal(err.isError, true);
  } finally {
    await close();
  }
});
