// Unit tests for the multi-agent pipeline, the ReAct audit loop, the narrator (Fake
// LLM), and the MCP tool dispatch — all offline against the Fakes.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FakeDataHubMcpClient,
  type AuditHarvest,
  type AuditHarvestOptions,
} from "../../src/datahub/mcp-client.js";
import { FIXTURE_CLEAN_REPORTS, UNCATALOGUED_UPSTREAM } from "../../src/datahub/fixtures.js";
import { ClassifierAgent } from "../../src/agents/classifier.js";
import { LineageAnalyzerAgent } from "../../src/agents/lineage-analyzer.js";
import { GovernanceAuditorAgent } from "../../src/agents/governance-auditor.js";
import { NarratorAgent } from "../../src/agents/narrator.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { AuditLoop, defaultAuditLoop, ALL_LOOP_TOOLS } from "../../src/ap/loop.js";
import {
  DETERMINISTIC_FIXTURE_MODEL,
  FakeLlmClient,
} from "../../src/llm/fake.js";
import { callAuditTool, MCP_TOOLS } from "../../src/mcp/server.js";
import {
  PublicAuditProjectionError,
  projectPublicAuditReport,
} from "../../src/reporting/public-audit-report.js";

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

// Always inject the Fake LLM into the pipeline's narrator so these tests are hermetic:
// a real provider key in the ambient environment (ANTHROPIC_API_KEY, OPENAI_API_KEY, …)
// must not flip an offline test into a live, billable model call.
const fakePipeline = () => new AuditPipeline({ narrator: new NarratorAgent(new FakeLlmClient()) });

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
  assert.match(withFindings.narrative, /1 finding/);
  assert.deepEqual(withFindings.modelProvenance, {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "deterministic-fixture",
    modelCall: false,
    provider: "fixture",
    requestedModel: "archon-deterministic-fixture-narrator-v1",
    returnedModel: null,
    providerResponseId: null,
    tokenUsage: null,
    latencyMs: null,
  });
  const clean = await narrator.summarize([], { totalEntities: 3, withLineage: 0, sensitiveEntities: 0, domains: {}, platforms: {} });
  assert.match(clean.narrative, /consistent|no .*violations/i);
});

test("AuditPipeline runs all four agents end-to-end and returns findings + narrative + trace", async () => {
  const report = await fakePipeline().run(new FakeDataHubMcpClient());
  assert.ok(report.findings.length >= 5);
  // sorted highest severity first
  assert.equal(report.findings[0]!.severity, "high");
  assert.match(report.narrative, /governance|finding/i);
  assert.equal(report.schemaVersion, "archon.audit-report/v1");
  assert.equal(report.modelProvenance.source, "deterministic-fixture");
  assert.equal(report.modelProvenance.modelCall, false);
  assert.equal(report.trace.length, 4);
  assert.equal(report.trace[0]!.agent, "classifier");
});

test("public audit projection retains UI evidence but excludes arbitrary rich detail", async () => {
  const internal = await fakePipeline().run(new FakeDataHubMcpClient());
  assert.ok(
    internal.findings.some(
      (finding) =>
        Object.hasOwn(finding.detail, "values") ||
        Object.hasOwn(finding.detail, "resolution") ||
        Object.hasOwn(finding.detail, "sensitiveFields")
    )
  );

  const projected = projectPublicAuditReport(internal);
  const allowed = new Set([
    "ruleId",
    "rule",
    "attribute",
    "unclassifiedFields",
    "blastRadius",
    "provenance",
    "dossier",
    "approval",
  ]);
  for (const finding of projected.findings) {
    assert.ok(
      Object.keys(finding.detail).every((key) => allowed.has(key)),
      "public detail must be rebuilt from the exact allowlist"
    );
    assert.equal(Object.hasOwn(finding.detail, "values"), false);
    assert.equal(Object.hasOwn(finding.detail, "resolution"), false);
    assert.equal(Object.hasOwn(finding.detail, "sensitiveFields"), false);
  }
  const contradiction = projected.findings.find(
    (finding) => finding.type === "contradiction"
  );
  assert.ok(Array.isArray(contradiction?.detail["provenance"]));
  assert.ok(
    (
      contradiction!.detail["provenance"] as Array<
        Record<string, unknown>
      >
    ).every(
      (event) =>
        !Object.hasOwn(event, "actor") &&
        !Object.hasOwn(event, "value")
    )
  );
  assert.notEqual(projected, internal);
  assert.notEqual(projected.findings, internal.findings);
});

test("public audit projection fails closed on credential-shaped narrative content", async () => {
  const internal = await fakePipeline().run(new FakeDataHubMcpClient());
  const unsafe = {
    ...internal,
    narrative: `provider accidentally returned sk-${"public-boundary-secret".repeat(2)}`,
  };
  assert.throws(
    () => projectPublicAuditReport(unsafe),
    PublicAuditProjectionError
  );
});

test("public audit projection preserves every bounded UI evidence summary", async () => {
  const internal = structuredClone(
    await fakePipeline().run(new FakeDataHubMcpClient())
  );
  internal.modelProvenance = {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "live-provider",
    modelCall: true,
    provider: "qwen",
    requestedModel: "qwen-plus",
    returnedModel: "qwen-plus-2026-07",
    providerResponseId: "chatcmpl_public_123",
    tokenUsage: {
      inputTokens: 20,
      outputTokens: 5,
      totalTokens: 25,
    },
    latencyMs: 120,
  };
  const finding = internal.findings[0]!;
  finding.detail = {
    ruleId: "G6",
    rule: "Sensitive fields require an exact classification.",
    attribute: "classification",
    unclassifiedFields: ["email"],
    blastRadius: finding.detail["blastRadius"],
    provenance: [
      {
        source: "pipeline:snowflake",
        runId: "run-20260725",
        observedAt: "2026-07-25T10:00:00.000Z",
        actor: "private-actor",
        value: "private-raw-value",
        status: "trusted",
      },
    ],
    dossier: {
      dossierId: "dossier-public-001",
      digest: `sha256:${"1".repeat(64)}`,
      policyDigest: `sha256:${"2".repeat(64)}`,
      generatedAt: "2026-07-25T10:00:01.000Z",
      evidenceCount: 7,
    },
    approval: {
      approvalId: "approval-public-001",
      expiresAt: "2026-07-26T10:00:00.000Z",
      targetField: "email",
      proposedTag: "urn:li:tag:PII",
      before: [],
      after: ["urn:li:tag:PII"],
      planDigest: `sha256:${"3".repeat(64)}`,
      risk: "low",
    },
  };

  const projected = projectPublicAuditReport(internal);
  const detail = projected.findings[0]!.detail;
  assert.equal(projected.modelProvenance.source, "live-provider");
  assert.deepEqual(detail["unclassifiedFields"], ["email"]);
  assert.equal(
    (detail["dossier"] as Record<string, unknown>)["evidenceCount"],
    7
  );
  assert.equal(
    (detail["approval"] as Record<string, unknown>)["risk"],
    "low"
  );
  assert.deepEqual(detail["provenance"], [
    {
      source: "pipeline:snowflake",
      runId: "run-20260725",
      observedAt: "2026-07-25T10:00:00.000Z",
      status: "trusted",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(projected), /private-actor|private-raw-value/u);
});

test("AuditPipeline derives snapshot, facts, and history from one fresh harvest bundle", async () => {
  class BundleOnlyClient extends FakeDataHubMcpClient {
    bundleCalls = 0;

    override async harvestAudit(
      query: string | undefined,
      options: AuditHarvestOptions
    ): Promise<AuditHarvest> {
      this.bundleCalls += 1;
      return super.harvestAudit(query, options);
    }

    override async harvestSnapshot(): Promise<never> {
      throw new Error("pipeline must not run a second snapshot harvest");
    }

    override async harvestFacts(): Promise<never> {
      throw new Error("pipeline must not run a second fact harvest");
    }

    override async harvestVersionHistories(): Promise<never> {
      throw new Error("pipeline must not run a second history harvest");
    }
  }

  const client = new BundleOnlyClient();
  const report = await fakePipeline().run(client, "sales");
  assert.equal(client.bundleCalls, 1);
  assert.equal(report.classification.totalEntities, 1);
  assert.match(
    report.trace[1]!.produced,
    /recovered from aspect version history/
  );
});

test("AuditPipeline on a clean single-source catalog yields no contradictions", async () => {
  const report = await fakePipeline().run(new FakeDataHubMcpClient(FIXTURE_CLEAN_REPORTS));
  assert.equal(report.findings.filter((f) => f.type === "contradiction").length, 0);
});

test("AuditLoop drives harvest → self-audit → governance → emit, human-gated (pending)", async () => {
  const result = await new AuditLoop(new FakeLlmClient()).run(new FakeDataHubMcpClient());
  assert.equal(result.disposition, "pending");
  assert.equal(result.stopReason, "emitted_findings");
  assert.ok(result.findings.length >= 5);
  const tools = result.trace.map((s) => s.tool);
  assert.deepEqual(tools, ["harvest_catalog", "run_consistency_audit", "run_governance_audit"]);
  assert.equal(result.modelProvenance.length, 4);
  assert.ok(
    result.modelProvenance.every(
      (receipt) =>
        receipt.source === "deterministic-fixture" &&
        receipt.modelCall === false &&
        receipt.requestedModel === DETERMINISTIC_FIXTURE_MODEL
    )
  );
  assert.doesNotMatch(JSON.stringify(result), /reasoning/iu);
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
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
    demoQuery: "sales",
  };
  const res = await callAuditTool(deps, "audit_catalog", { query: "sales" });
  assert.ok(!res.isError);
  const report = JSON.parse((res.content[0] as { text: string }).text);
  assert.ok(report.findings.length >= 1);
  assert.ok(report.narrative);
  assert.ok(
    report.findings.every((finding: { detail: Record<string, unknown> }) =>
      !Object.hasOwn(finding.detail, "values")
    )
  );
});

test("MCP search_datasets + get_entity stay inside one exact public scope and expose only allowlisted identity", async () => {
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
    demoQuery: "sales",
  };
  const search = await callAuditTool(deps, "search_datasets", { query: "sales" });
  assert.deepEqual(
    JSON.parse((search.content[0] as { text: string }).text),
    { urns: [SALES] }
  );
  const get = await callAuditTool(deps, "get_entity", { urn: SALES });
  assert.deepEqual(
    JSON.parse((get.content[0] as { text: string }).text),
    {
      schemaVersion: "archon.public-catalog-entity/v1",
      urn: SALES,
      name: "sales_orders",
      platform: "snowflake",
      fabric: "PROD",
      deprecated: false,
    }
  );
  assert.doesNotMatch(
    (get.content[0] as { text: string }).text,
    /description|owner|field|tag|glossary|domain|source|upstream|dbt-ingest/iu
  );
});

test("MCP get_entity rejects every URN outside the resolved public scope", async () => {
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
    demoQuery: "sales",
  };
  assert.equal((await callAuditTool(deps, "get_entity", { urn: "urn:ds:nope" })).isError, true);
  assert.equal((await callAuditTool(deps, "get_entity", {})).isError, true);
  assert.equal((await callAuditTool(deps, "bogus", {})).isError, true);
  assert.ok(MCP_TOOLS.length === 4);
});

test("MCP run_audit_loop returns pending findings + trace", async () => {
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
    demoQuery: "sales",
  };
  const res = await callAuditTool(deps, "run_audit_loop", { query: "sales" });
  const out = JSON.parse((res.content[0] as { text: string }).text);
  assert.equal(out.disposition, "pending");
  assert.ok(out.trace.length >= 3);
  assert.equal(out.modelProvenance.length, 4);
  assert.ok(
    out.modelProvenance.every(
      (receipt: { requestedModel: string }) =>
        receipt.requestedModel === DETERMINISTIC_FIXTURE_MODEL
    )
  );
  assert.doesNotMatch(JSON.stringify(out), /reasoning/iu);
});

test("MCP model-backed tools never expose raw provider failures", async () => {
  const sentinel = `sk-${"provider-secret".repeat(3)}`;
  const pipeline = {
    run: async () => {
      throw new Error(`provider rejected ${sentinel} at https://gateway.example/v1`);
    },
  } as unknown as AuditPipeline;
  const loop = {
    run: async () => {
      throw new Error(`provider loop failed with ${sentinel}`);
    },
  };
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline,
    loop,
    demoQuery: "sales",
  };

  for (const name of ["audit_catalog", "run_audit_loop"]) {
    const result = await callAuditTool(deps, name, { query: "sales" });
    const text = (result.content[0] as { text: string }).text;
    assert.equal(result.isError, true);
    assert.equal(text, "error: tool_execution_failed");
    assert.doesNotMatch(text, new RegExp(sentinel));
    assert.doesNotMatch(text, /gateway\.example/u);
  }
});

test("MCP public catalog tools reject omitted, padded, wildcard, blank, or alternate scope", async () => {
  const deps = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
    demoQuery: "sales",
  };
  for (const name of ["audit_catalog", "run_audit_loop", "search_datasets"]) {
    for (const query of [
      undefined,
      "",
      "   ",
      "*",
      "?",
      "**",
      "{}",
      " sales",
      "sales ",
      "customer",
    ]) {
      const res = await callAuditTool(
        deps,
        name,
        query === undefined ? {} : { query }
      );
      assert.equal(res.isError, true);
      assert.doesNotMatch(
        (res.content[0] as { text: string }).text,
        /sales_orders|customer_pii|urn:li/iu
      );
    }
  }
});

test("MCP public catalog tools fail closed without config or one exact dataset", async () => {
  const unconfigured = {
    datahub: new FakeDataHubMcpClient(),
    pipeline: fakePipeline(),
  };
  const missingScope = await callAuditTool(
    unconfigured,
    "search_datasets",
    { query: "sales" }
  );
  assert.equal(missingScope.isError, true);
  assert.equal(
    (missingScope.content[0] as { text: string }).text,
    "error: tool_execution_failed"
  );

  class AmbiguousSearchClient extends FakeDataHubMcpClient {
    override async search(_query?: string): Promise<string[]> {
      return [SALES, "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_archive,PROD)"];
    }
  }
  const ambiguous = await callAuditTool(
    {
      datahub: new AmbiguousSearchClient(),
      pipeline: fakePipeline(),
      demoQuery: "sales",
    },
    "get_entity",
    { urn: SALES }
  );
  assert.equal(ambiguous.isError, true);
  assert.equal(
    (ambiguous.content[0] as { text: string }).text,
    "error: tool_execution_failed"
  );
});
