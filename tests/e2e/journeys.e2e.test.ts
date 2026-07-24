// EXTENSIVE E2E — end-to-end user journeys through the whole agent, offline.
//
// Where readiness.e2e.test.ts asserts the GATE, this suite walks the actual user-facing
// JOURNEYS a data steward drives, each end to end and each asserting real behavior of the
// shipped code (pipeline, ReAct loop, self-audit, version-history recovery, dual-face MCP),
// driven entirely by the Fakes + the replay cassette — no live DataHub, no credentials.
//
// Journeys:
//   J1  metadata scan → 4-agent audit → quantified, multi-class findings report
//   J2  ReAct governance audit — G1–G6 evaluated, human-gated (pending)
//   J3  live-shaped contradiction recovery via aspect version history — FIRES
//   J4  drift-candidate (negative) — same-pipeline edit does NOT become a contradiction
//   J5  dual-face MCP round-trip — audit_catalog + run_audit_loop over the real protocol
//   J6  quantified findings report — exact class counts + severity ordering + grounded narrative
//   J7  edge: clean single-source catalog — no contradictions, governance still audits
//   J8  edge: same-pipeline drift is benign (drift candidate, not a confirmed conflict)
//   J9  replay-cassette journey — real-shape GMS history recovers the conflict through the pipeline

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { buildMcpServer } from "../../src/mcp/server.js";
import { defaultAuditLoop } from "../../src/ap/loop.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { FIXTURE_CLEAN_REPORTS, FIXTURE_VERSION_HISTORY } from "../../src/datahub/fixtures.js";
import { validateSnapshot } from "../../src/governance/validator.js";
import {
  auditVersionHistory,
  detectDrift,
  versionHistoryToFacts,
  type AspectVersionHistory,
  type DhVersionedAspect,
} from "../../src/datahub/version-history.js";
import type { Finding } from "../../src/types.js";

delete process.env.LLM_API_KEY;
delete process.env.DATAHUB_MCP_URL;
delete process.env.DATAHUB_GMS_URL;

const SALES = "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";

function countByType(findings: Finding[]): Record<Finding["type"], number> {
  const c = { contradiction: 0, lineage_gap: 0, governance_violation: 0 };
  for (const f of findings) c[f.type]++;
  return c;
}

// ── J1 — the headline journey: scan → 4-agent audit → multi-class findings report ──
test("J1: metadata scan → 4-agent audit → quantified, multi-class findings report", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  assert.deepEqual(report.trace.map((t) => t.agent), [
    "classifier",
    "lineage-analyzer",
    "governance-auditor",
    "narrator",
  ]);
  const c = countByType(report.findings);
  assert.ok(c.contradiction > 0 && c.governance_violation > 0 && c.lineage_gap > 0,
    `expected all three classes; got ${JSON.stringify(c)}`);
  assert.ok(report.narrative.length > 0);
});

// ── J2 — ReAct governance audit: G1–G6 evaluated, human-gated ───────────────────
test("J2: ReAct governance audit evaluates G1–G6 and ends human-gated (pending)", async () => {
  const out = await defaultAuditLoop().run(new FakeDataHubMcpClient());
  assert.equal(out.disposition, "pending");
  assert.equal(out.stopReason, "emitted_findings");
  const tools = out.trace.map((t) => t.tool);
  assert.ok(tools.includes("harvest_catalog"));
  assert.ok(tools.includes("run_consistency_audit"));
  assert.ok(tools.includes("run_governance_audit"));

  // The governance gate genuinely evaluated every rule G1–G6.
  const snapshot = await new FakeDataHubMcpClient().harvestSnapshot();
  const ruleIds = new Set(validateSnapshot(snapshot).map((r) => r.ruleId));
  assert.deepEqual([...ruleIds].sort(), ["G1", "G2", "G3", "G4", "G5", "G6"]);
});

// ── J3 — live-shaped contradiction recovery via version history FIRES ───────────
test("J3: version-history recovery fires on a single-source catalog (the live-shaped path)", async () => {
  // Single ingestion source on the current view (no fact-based cross-source conflict), so
  // the contradiction can ONLY surface through aspect version-history recovery.
  const client = new FakeDataHubMcpClient(FIXTURE_CLEAN_REPORTS, FIXTURE_VERSION_HISTORY);
  const report = await new AuditPipeline().run(client);

  const contradictions = report.findings.filter((f) => f.type === "contradiction");
  const attrs = contradictions.map((f) => (f.detail as { attribute: string }).attribute).sort();
  assert.deepEqual(attrs, ["fieldType", "owner"], `recovered attrs: ${attrs.join(",")}`);
  // The pipeline trace attributes the recovery to version history.
  const lineageStep = report.trace.find((t) => t.agent === "lineage-analyzer")!;
  assert.match(lineageStep.produced, /2 recovered from aspect version history/);
});

// ── J4 — drift-candidate negative: same-pipeline edit is NOT a contradiction ─────────
test("J4: raw_orders' same-pipeline edit does NOT surface as a contradiction", async () => {
  const client = new FakeDataHubMcpClient(FIXTURE_CLEAN_REPORTS, FIXTURE_VERSION_HISTORY);
  const report = await new AuditPipeline().run(client);
  const rawOrdersContradictions = report.findings.filter(
    (f) => f.type === "contradiction" && f.subject.includes("raw_orders")
  );
  assert.equal(rawOrdersContradictions.length, 0, "same-pipeline drift must not become a contradiction");
});

// ── J5 — dual-face MCP round-trip over the real protocol ────────────────────────
test("J5: dual-face MCP round-trip — audit_catalog + run_audit_loop over a real Client↔Server", async () => {
  const { server } = await buildMcpServer({ datahub: new FakeDataHubMcpClient(), pipeline: new AuditPipeline() });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "journey", version: "0.0.0" }, { capabilities: {} });
  await Promise.all([server.connect(st), client.connect(ct)]);
  try {
    const audit = JSON.parse(((await client.callTool({ name: "audit_catalog", arguments: {} })) as {
      content: Array<{ text: string }>;
    }).content[0]!.text);
    assert.ok(audit.findings.length >= 5);
    assert.ok(audit.narrative);

    const loop = JSON.parse(((await client.callTool({ name: "run_audit_loop", arguments: {} })) as {
      content: Array<{ text: string }>;
    }).content[0]!.text);
    assert.equal(loop.disposition, "pending");
  } finally {
    await client.close();
    await server.close();
  }
});

// ── J6 — quantified findings report: exact counts, severity ordering, grounded narrative ─
test("J6: quantified report — exact class counts, severity-ordered, narrative grounded in counts", async () => {
  const report = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const c = countByType(report.findings);
  // The shipped fixture catalog carries exactly this finding profile.
  assert.deepEqual(c, { contradiction: 2, governance_violation: 4, lineage_gap: 1 });

  // Findings are ordered highest-severity first.
  const rank = (s: Finding["severity"]) => (s === "high" ? 3 : s === "medium" ? 2 : 1);
  for (let i = 1; i < report.findings.length; i++) {
    assert.ok(rank(report.findings[i - 1]!.severity) >= rank(report.findings[i]!.severity),
      "findings must be sorted by descending severity");
  }
  // The narrator's total is grounded in the real counts (2+4+1 = 7).
  assert.match(report.narrative, /7 finding/);
});

// ── J7 — edge: clean single-source catalog — no contradictions, governance still audits ─
test("J7: edge — a clean single-source catalog yields no contradictions but still audits governance", async () => {
  // Clean reports with NO version history → no recovery input, one source per URN.
  const client = new FakeDataHubMcpClient(FIXTURE_CLEAN_REPORTS, []);
  const report = await new AuditPipeline().run(client);
  const c = countByType(report.findings);
  assert.equal(c.contradiction, 0, "single-source catalog must have zero contradictions");
  // customer_pii is still ungoverned → governance findings persist.
  assert.ok(c.governance_violation > 0, "governance audit still runs on a clean catalog");
});

// ── J8 — edge: two runs of one pipeline are drift, never a cross-source conflict ─────
test("J8: edge — same-pipeline drift is a candidate, never a confirmed contradiction", async () => {
  const samePipeline: AspectVersionHistory = {
    urn: SALES,
    aspect: "ownership",
    versions: [
      { value: { owners: [{ owner: "urn:li:corpGroup:a" }] }, systemMetadata: { version: "1", lastObserved: 1, runId: "r1", pipelineName: "snowflake-prod" } },
      { value: { owners: [{ owner: "urn:li:corpGroup:b" }] }, systemMetadata: { version: "2", lastObserved: 2, runId: "r2", pipelineName: "snowflake-prod" } },
    ],
  };
  // Recovery correctly reports ZERO contradictions for a same-pipeline edit …
  assert.equal(auditVersionHistory([samePipeline]).contradictions.length, 0);
  // … yet the on-MCP-surface drift detector still surfaces it as a CANDIDATE (the value did
  // change between two harvests) — proving the two are honestly separated.
  const prior = versionHistoryToFacts({ ...samePipeline, versions: [samePipeline.versions[0]!] });
  const current = versionHistoryToFacts({ ...samePipeline, versions: [samePipeline.versions[1]!] });
  const drift = detectDrift(prior, current);
  assert.equal(drift.length, 1);
  assert.equal(drift[0]!.attribute, "owner");
  assert.deepEqual([drift[0]!.from, drift[0]!.to], ["urn:li:corpGroup:a", "urn:li:corpGroup:b"]);
});

// ── J9 — replay-cassette journey: real-shape GMS history → recovery → pipeline report ─
test("J9: replay-cassette journey — real-shape GMS history recovers the conflict through the pipeline", async () => {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const cassette = JSON.parse(
    readFileSync(resolve(HERE, "../cassettes/openapi-v3-versioned-aspects.json"), "utf8")
  ) as { entries: Array<{ response: Record<string, unknown> }> };

  // Reconstruct the ownership history exactly as the live client's readAspectVersions() does.
  const versions = cassette.entries
    .filter((e) => e.response["urn"] === SALES && e.response["ownership"])
    .map((e) => e.response["ownership"] as DhVersionedAspect);
  const history: AspectVersionHistory = { urn: SALES, aspect: "ownership", versions };
  assert.equal(history.versions.length, 2);

  // Drive it through the FULL pipeline via a client that serves ONLY this recovered history
  // (empty current-view reports → the finding can come only from the cassette history).
  const client = new FakeDataHubMcpClient([], [history]);
  const report = await new AuditPipeline().run(client);
  const owner = report.findings.find(
    (f) => f.type === "contradiction" && (f.detail as { attribute?: string }).attribute === "owner"
  );
  assert.ok(owner, "the cassette's cross-source ownership conflict must surface as a finding");
  assert.match(owner!.recommendation ?? "", /team-ops/);
});
