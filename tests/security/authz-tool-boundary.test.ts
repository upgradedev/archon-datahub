// PEN-TEST — AuthZ / tool-boundary.
//
// Threat: the agent is "dual-face" — it CONSUMES the official DataHub MCP server and
// RE-EXPOSES its audit as MCP tools of its own. A tool-boundary bug (a mutation tool
// leaking onto either face, or a "read" tool that actually writes) would break the
// headline read-only guarantee. These tests prove, over the REAL MCP protocol wiring and
// the dispatch layer, that:
//   • our re-exposed MCP surface exposes ONLY read tools (no mutation tool name reachable);
//   • the DataHubClient seam has no write method at all (no capability to mutate exists);
//   • the read tools are idempotent — calling them changes no observable state;
//   • a mutation-named call is refused (unknown tool → MCP error), so there is no write
//     path even by string-guessing a DataHub mutation tool name.
// Fully offline (Fakes, no network, no key).

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildMcpServer, callAuditTool, MCP_TOOLS } from "../../src/mcp/server.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";

delete process.env.LLM_API_KEY;
delete process.env.DATAHUB_MCP_URL;
delete process.env.DATAHUB_GMS_URL;

// The DataHub MCP server's mutation tools — the exact write surface this agent must NEVER
// expose or invoke. (Mirrors the readiness gate's MUTATION_TOOLS list.)
const MUTATION_TOOLS = [
  "add_tags",
  "remove_tags",
  "add_terms",
  "remove_terms",
  "add_owners",
  "remove_owners",
  "set_domains",
  "remove_domains",
  "update_description",
  "add_structured_properties",
];

const READ_ONLY_TOOLS = ["audit_catalog", "get_entity", "run_audit_loop", "search_datasets"];

async function connect() {
  const { server } = await buildMcpServer({
    datahub: new FakeDataHubMcpClient(),
    pipeline: new AuditPipeline(),
  });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "pentest-client", version: "0.0.0" }, { capabilities: {} });
  await Promise.all([server.connect(st), client.connect(ct)]);
  return { client, close: async () => { await client.close(); await server.close(); } };
}

test("authz: our MCP surface exposes ONLY the four read-only tools — no mutation tool", () => {
  const names = MCP_TOOLS.map((t) => t.name).sort();
  assert.deepEqual(names, READ_ONLY_TOOLS);
  for (const m of MUTATION_TOOLS) {
    assert.ok(!names.includes(m), `mutation tool '${m}' must not be exposed`);
  }
});

test("authz: the DataHubClient seam has NO write method (no mutate capability exists)", () => {
  const client = new FakeDataHubMcpClient();
  const proto = Object.getPrototypeOf(client);
  const methods = Object.getOwnPropertyNames(proto).filter((n) => typeof (client as never)[n] === "function");
  // Every public method is a read/harvest verb; none is a mutation verb.
  for (const m of methods) {
    assert.ok(
      !MUTATION_TOOLS.includes(m) && !/^(set|add|remove|update|delete|write|put|patch)/i.test(m) || m === "constructor",
      `client method '${m}' looks like a mutation — the read-only seam must not carry one`
    );
  }
  // And none of the DataHub mutation tool names is callable on the client.
  for (const m of MUTATION_TOOLS) {
    assert.equal(typeof (client as never)[m], "undefined", `client must not implement '${m}'`);
  }
});

test("authz: a mutation-named tool call is refused over the dispatch layer (no write path)", async () => {
  const { deps } = await buildMcpServer({ datahub: new FakeDataHubMcpClient() });
  for (const m of MUTATION_TOOLS) {
    const res = await callAuditTool(deps, m, { urn: "urn:li:dataset:(x)", tag: "PII" });
    assert.equal(res.isError, true, `mutation tool '${m}' must be rejected`);
    const text = (res.content as Array<{ type: string; text?: string }>)[0]?.text ?? "";
    assert.match(text, /unknown tool/i);
  }
});

test("authz: a mutation-named tool call is refused over the REAL MCP protocol too", async () => {
  const { client, close } = await connect();
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), READ_ONLY_TOOLS);
    const res = (await client.callTool({ name: "add_tags", arguments: { urn: "x", tag: "y" } })) as {
      isError?: boolean;
    };
    assert.equal(res.isError, true, "add_tags must not be callable over MCP");
  } finally {
    await close();
  }
});

test("authz: read tools are idempotent — repeated calls mutate no observable state", async () => {
  const client = new FakeDataHubMcpClient();
  const s1 = await client.search("sales");
  const s2 = await client.search("sales");
  assert.deepEqual(s1, s2);

  const snap1 = await client.harvestSnapshot();
  const snap2 = await client.harvestSnapshot();
  assert.deepEqual(
    snap1.entities.map((e) => ({ urn: e.urn, owners: e.owners })),
    snap2.entities.map((e) => ({ urn: e.urn, owners: e.owners }))
  );

  // Running the full audit twice yields the identical finding set — nothing was written.
  const pipe = new AuditPipeline();
  const r1 = await pipe.run(new FakeDataHubMcpClient());
  const r2 = await pipe.run(new FakeDataHubMcpClient());
  assert.deepEqual(r1.findings, r2.findings);
});
