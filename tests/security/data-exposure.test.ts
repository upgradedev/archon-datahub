// PEN-TEST — sensitive-data-exposure (OWASP LLM06 / secrets in output & logs).
//
// Threat: the agent holds a DataHub Personal Access Token (DATAHUB_GMS_TOKEN) and connects
// to GMS. A regression that echoed that token — or any credential — into a finding, the
// executive narrative, or a log line would leak it to anyone who can read the audit output.
//
// These tests plant a sentinel token in the environment, run the FULL agent (pipeline +
// ReAct loop + MCP round-trip) AND deliberately force the loop's console-logging fallback
// path, then assert the sentinel appears in NONE of: the serialized findings/narrative, the
// MCP tool output, or any captured console.{log,warn,error} line. Offline throughout — only
// the TOKEN sentinel is set (not the URL vars), so `hasDataHubCreds()` stays false and the
// agent never leaves the Fakes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { buildMcpServer } from "../../src/mcp/server.js";
import { AuditLoop } from "../../src/ap/loop.js";
import type { LlmClient } from "../../src/llm/client.js";

const SENTINEL = "SENTINEL_PAT_a1b2c3d4e5f6_do_not_leak";

delete process.env.LLM_API_KEY;
delete process.env.DATAHUB_MCP_URL; // keep offline — token-only sentinel does NOT flip the client
delete process.env.DATAHUB_GMS_URL;
process.env.DATAHUB_GMS_TOKEN = SENTINEL;

// A stub LLM that never returns a usable tool call — forces the loop's no-progress fallback,
// which logs via console.warn. This exercises the realistic offline leak surface (logging).
class NoOpLlm implements LlmClient {
  chat = { completions: { create: async () => ({ choices: [{ message: { content: null, tool_calls: undefined } }] }) } };
}

function captureConsole(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const orig = { log: console.log, warn: console.warn, error: console.error };
  const cap = (...args: unknown[]) => { lines.push(args.map(String).join(" ")); };
  console.log = cap as never;
  console.warn = cap as never;
  console.error = cap as never;
  return { lines, restore: () => { console.log = orig.log; console.warn = orig.warn; console.error = orig.error; } };
}

test("data-exposure: the token never appears in the pipeline report (findings + narrative)", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const serialized = JSON.stringify(report);
  assert.ok(!serialized.includes(SENTINEL), "DATAHUB_GMS_TOKEN leaked into the audit report");
});

test("data-exposure: the token never appears in the MCP tool output", async () => {
  const { server } = await buildMcpServer({ datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "pentest", version: "0.0.0" }, { capabilities: {} });
  await Promise.all([server.connect(st), client.connect(ct)]);
  try {
    const res = (await client.callTool({ name: "audit_catalog", arguments: {} })) as { content: Array<{ text: string }> };
    assert.ok(!JSON.stringify(res).includes(SENTINEL), "token leaked over the MCP surface");
  } finally {
    await client.close();
    await server.close();
  }
});

test("data-exposure: the token never appears in any log line — even on the loop fallback path", async () => {
  const cap = captureConsole();
  let out;
  try {
    // maxSteps forces termination; the NoOp LLM drives the no-progress fallback (console.warn).
    out = await new AuditLoop(new NoOpLlm(), "test-model", { maxSteps: 3 }).run(new FakeDataHubMcpClient());
  } finally {
    cap.restore();
  }
  assert.equal(out!.disposition, "pending");
  assert.ok(cap.lines.length > 0, "the fallback path should have logged (proving the capture is live)");
  for (const line of cap.lines) {
    assert.ok(!line.includes(SENTINEL), `token leaked to a log line: ${line}`);
  }
  assert.ok(!JSON.stringify(out).includes(SENTINEL), "token leaked into the loop result");
});
