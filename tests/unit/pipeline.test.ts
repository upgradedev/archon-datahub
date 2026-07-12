// Unit tests for the multi-agent pipeline, the ReAct audit loop, the narrator (Fake
// LLM), and the MCP tool dispatch — all offline against the Fakes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { FIXTURE_CLEAN_REPORTS, UNCATALOGUED_UPSTREAM } from "../../src/datahub/fixtures.js";
import { ClassifierAgent } from "../../src/agents/classifier.js";
import { LineageAnalyzerAgent } from "../../src/agents/lineage-analyzer.js";
import { GovernanceAuditorAgent } from "../../src/agents/governance-auditor.js";
import { NarratorAgent } from "../../src/agents/narrator.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { AuditLoop, defaultAuditLoop, ALL_LOOP_TOOLS } from "../../src/ap/loop.js";
import { FakeLlmClient } from "../../src/llm/fake.js";
import { callAuditTool, MCP_TOOLS } from "../../src/mcp/server.js";

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

test("ClassifierAgent buckets the catalog by domain/platform, lineage, sensitivity", async () => {
  const snap = await new FakeDataHubMcpClient().harvestSnapshot();
  const c = new ClassifierAgent().classify(snap);
  assert.equal(c.totalEntities, 3);
  assert.ok(c.withLineage >= 2); // sales_orders + raw_orders declare upstreams
  assert.ok(c.sensitiveEntities >= 1); // customer_pii has email
  assert.ok(c.platforms["snowflake"]! >= 3);
});

test("LineageAnalyzerAgent turns the self-audit into contradiction + lineage_gap findings", async () => {
  const facts = await new FakeDataHubMcpClient().harvestFacts();
  const findings = new LineageAnalyzerAgent().analyze(facts);
  assert.ok(findings.some((f) => f.type === "contradiction" && f.subject === SALES));
  assert.ok(findings.some((f) => f.type === "lineage_gap" && f.subject === UNCATALOGUED_UPSTREAM));
  // a field-type contradiction is high severity (schema-break risk)
  assert.ok(findings.some((f) => f.type === "contradiction" && f.severity === "high"));
});

test("GovernanceAuditorAgent emits only the failed rules as governance_violation findings", async () => {
  const snap = await new FakeDataHubMcpClient().harvestSnapshot();
  const findings = new GovernanceAuditorAgent().audit(snap);
  assert.ok(findings.length > 0);
  assert.ok(findings.every((f) => f.type === "governance_violation"));
  const rules = new Set(findings.map((f) => (f.detail as { ruleId: string }).ruleId));
  assert.ok(rules.has("G1")); // customer_pii has no owner
});

test("NarratorAgent (Fake LLM) writes a summary grounded in the finding counts", async () => {
  const narrator = new NarratorAgent(new FakeLlmClient());
  const withFindings = await narrator.summarize(
    [{ type: "contradiction", severity: "high", subject: "x", summary: "s", detail: {} }],
    { totalEntities: 3, withLineage: 2, sensitiveEntities: 1, domains: {}, platforms: {} }
  );
  assert.match(withFindings, /1 finding/);
  const clean = await narrator.summarize([], { totalEntities: 3, withLineage: 0, sensitiveEntities: 0, domains: {}, platforms: {} });
  assert.match(clean, /consistent|no .*violations/i);
});

test("AuditPipeline runs all four agents end-to-end and returns findings + narrative + trace", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  assert.ok(report.findings.length >= 5);
  // sorted highest severity first
  assert.equal(report.findings[0]!.severity, "high");
  assert.match(report.narrative, /governance|finding/i);
  assert.equal(report.trace.length, 4);
  assert.equal(report.trace[0]!.agent, "classifier");
});

test("AuditPipeline on a clean single-source catalog yields no contradictions", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient(FIXTURE_CLEAN_REPORTS));
  assert.equal(report.findings.filter((f) => f.type === "contradiction").length, 0);
});

test("AuditLoop drives harvest → self-audit → governance → emit, human-gated (pending)", async () => {
  const result = await new AuditLoop(new FakeLlmClient()).run(new FakeDataHubMcpClient());
  assert.equal(result.disposition, "pending");
  assert.equal(result.stopReason, "emitted_findings");
  assert.ok(result.findings.length >= 5);
  const tools = result.trace.map((s) => s.tool);
  assert.deepEqual(tools, ["harvest_catalog", "run_consistency_audit", "run_governance_audit"]);
});

test("AuditLoop falls back to flag_for_review when the step budget is too small", async () => {
  let stopReason = "";
  const loop = new AuditLoop(new FakeLlmClient(), "m", {
    maxSteps: 3,
    onStop: (r) => (stopReason = r),
  });
  // 3 steps only reach governance; emit_findings needs a 4th → max_steps fallback.
  const result = await loop.run(new FakeDataHubMcpClient());
  assert.equal(result.disposition, "pending"); // still nothing mutated
  assert.equal(result.stopReason, "max_steps_fallback");
  assert.equal(stopReason, "max_steps_fallback");
});

test("defaultAuditLoop + ALL_LOOP_TOOLS expose the read-only tool set", () => {
  assert.ok(defaultAuditLoop() instanceof AuditLoop);
  assert.ok(ALL_LOOP_TOOLS.includes("emit_findings"));
  assert.ok(ALL_LOOP_TOOLS.includes("harvest_catalog"));
});

test("MCP audit_catalog tool returns the pipeline report", async () => {
  const deps = { datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() };
  const res = await callAuditTool(deps, "audit_catalog", {});
  assert.ok(!res.isError);
  const report = JSON.parse((res.content[0] as { text: string }).text);
  assert.ok(report.findings.length >= 5);
  assert.ok(report.narrative);
});

test("MCP search_datasets + get_entity are read-only passthroughs", async () => {
  const deps = { datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() };
  const search = await callAuditTool(deps, "search_datasets", { query: "sales" });
  assert.match((search.content[0] as { text: string }).text, /sales_orders/);
  const get = await callAuditTool(deps, "get_entity", { urn: SALES });
  assert.match((get.content[0] as { text: string }).text, /dbt-ingest/);
});

test("MCP get_entity errors on a missing urn, and unknown tools error", async () => {
  const deps = { datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() };
  assert.equal((await callAuditTool(deps, "get_entity", { urn: "urn:ds:nope" })).isError, true);
  assert.equal((await callAuditTool(deps, "get_entity", {})).isError, true);
  assert.equal((await callAuditTool(deps, "bogus", {})).isError, true);
  assert.ok(MCP_TOOLS.length === 4);
});

test("MCP run_audit_loop returns pending findings + trace", async () => {
  const deps = { datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() };
  const res = await callAuditTool(deps, "run_audit_loop", {});
  const out = JSON.parse((res.content[0] as { text: string }).text);
  assert.equal(out.disposition, "pending");
  assert.ok(out.trace.length >= 3);
});
