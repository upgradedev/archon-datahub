import assert from "node:assert/strict";
import { test } from "node:test";
import type { AuditReport } from "../../src/pipeline/pipeline.js";
import type {
  ApprovalDecisionV1,
  ApprovalRequestV1,
  EvidenceDossierV1,
  ExecutionReceiptV1,
  RemediationPlanV1,
  RollbackProposalV1,
} from "../../src/remediation/contracts.js";
import {
  verifyApprovalDecision,
  verifyApprovalRequest,
} from "../../src/remediation/control-loop.js";
import {
  canonicalize,
  digest,
  verifyDigest,
} from "../../src/remediation/integrity.js";
import {
  verifyEvidenceDossier,
  verifyRemediationPlan,
} from "../../src/remediation/planner.js";
import {
  createRollbackProposal,
  verifyExecutionReceipt,
} from "../../src/remediation/receipt.js";
import {
  buildJudgeEvidencePack,
  JUDGE_EVIDENCE_ALL_PATHS,
} from "../../scripts/generate-judge-evidence.js";
import { assertPublicJudgeEvidenceIdentifiers } from "../../scripts/verify-judge-evidence.js";

const RELEASE_SHA = "a".repeat(40);

function parsed<T>(
  files: ReadonlyMap<string, string>,
  path: string
): T {
  const content = files.get(path);
  assert.ok(content, `missing ${path}`);
  return JSON.parse(content) as T;
}

test("judge evidence is reproducible and binds the real audit/remediation functions", async () => {
  const first = await buildJudgeEvidencePack({ releaseSha: RELEASE_SHA });
  const second = await buildJudgeEvidencePack({ releaseSha: RELEASE_SHA });

  assert.deepEqual([...first.files.entries()], [...second.files.entries()]);
  assert.deepEqual(
    [...first.files.keys()].sort(),
    [...JUDGE_EVIDENCE_ALL_PATHS].sort()
  );

  const report = parsed<AuditReport>(first.files, "audit/report.json");
  const dossier = parsed<EvidenceDossierV1>(
    first.files,
    "control/evidence-dossier.json"
  );
  const plan = parsed<RemediationPlanV1>(
    first.files,
    "control/remediation-plan.json"
  );
  const request = parsed<ApprovalRequestV1>(
    first.files,
    "control/approval-request.json"
  );
  const decision = parsed<ApprovalDecisionV1>(
    first.files,
    "control/approval-decision.json"
  );
  const receipt = parsed<ExecutionReceiptV1>(
    first.files,
    "control/execution-receipt.json"
  );
  const rollback = parsed<RollbackProposalV1>(
    first.files,
    "control/rollback-proposal.json"
  );

  const counts = {
    contradiction: 0,
    lineage_gap: 0,
    governance_violation: 0,
  };
  for (const finding of report.findings) counts[finding.type] += 1;
  assert.equal(report.classification.totalEntities, 3);
  assert.equal(report.findings.length, 7);
  assert.deepEqual(report.modelProvenance, {
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
  assert.deepEqual(counts, {
    contradiction: 2,
    lineage_gap: 1,
    governance_violation: 4,
  });

  assert.equal(verifyEvidenceDossier(dossier), true);
  assert.equal(verifyRemediationPlan(plan), true);
  assert.equal(verifyApprovalRequest(request), true);
  assert.equal(verifyApprovalDecision(decision), true);
  assert.deepEqual(verifyExecutionReceipt(receipt), {
    valid: true,
    issues: [],
  });
  assert.equal(receipt.outcome, "VERIFIED");
  assert.equal(receipt.checks.length, 5);
  assert.ok(receipt.checks.every((check) => check.passed));
  assert.equal(receipt.rollback.availability, "ELIGIBLE");

  assert.equal(plan.dossierDigest, dossier.digest);
  assert.equal(request.dossierDigest, dossier.digest);
  assert.equal(request.planDigest, plan.digest);
  assert.equal(decision.requestDigest, request.digest);
  assert.equal(decision.planDigest, plan.digest);
  assert.equal(receipt.dossierDigest, dossier.digest);
  assert.equal(receipt.planDigest, plan.digest);
  assert.equal(receipt.approvalDecisionDigest, decision.digest);
  assert.equal(rollback.originalReceiptDigest, receipt.digest);
  assert.equal(rollback.requiresFreshApproval, true);

  const after = receipt.after;
  assert.ok(after);
  const recreatedRollback = createRollbackProposal(receipt, after);
  assert.ok(recreatedRollback);
  assert.equal(canonicalize(recreatedRollback), canonicalize(rollback));

  const { digest: manifestDigest, ...manifestUnsigned } = first.manifest;
  assert.equal(verifyDigest(manifestUnsigned, manifestDigest), true);
  assert.equal(first.manifest.source.releaseSha, RELEASE_SHA);
  assert.equal(first.manifest.bindings.reportDigest, digest(report));
  assert.equal(first.manifest.bindings.dossierDigest, dossier.digest);
  assert.equal(first.manifest.bindings.planDigest, plan.digest);
  assert.equal(first.manifest.bindings.approvalRequestDigest, request.digest);
  assert.equal(first.manifest.bindings.approvalDecisionDigest, decision.digest);
  assert.equal(first.manifest.bindings.receiptDigest, receipt.digest);
  assert.equal(first.manifest.bindings.rollbackProposalDigest, rollback.digest);

  const sarif = parsed<{
    version: string;
    runs: Array<{ results: unknown[] }>;
  }>(first.files, "audit/report.sarif");
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0]!.results.length, report.findings.length);

  const publicBytes = [...first.files.values()].join("\n");
  for (const [path, content] of first.files) {
    assert.doesNotThrow(() =>
      assertPublicJudgeEvidenceIdentifiers(content, path)
    );
  }
  assert.doesNotMatch(publicBytes, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u);
  assert.doesNotMatch(publicBytes, /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/u);
  assert.doesNotMatch(publicBytes, /-----BEGIN .*PRIVATE KEY-----/u);
  assert.doesNotMatch(publicBytes, /"taskToken"\s*:/u);
  assert.match(first.files.get("README.md")!, /Synthetic offline fixture evidence/u);
  assert.match(first.files.get("SHA256SUMS")!, /manifest\.json/u);
});

test("judge evidence identifier boundaries reject unknown URN extensions", () => {
  const dataset =
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,sales_orders,PROD)";
  assert.doesNotThrow(() =>
    assertPublicJudgeEvidenceIdentifiers(
      `scan-2026-07-01:${dataset}:ownership`,
      "known-fact-id"
    )
  );
  assert.throws(
    () =>
      assertPublicJudgeEvidenceIdentifiers(
        `scan-2026-07-01:${dataset}:ownership-shadow`,
        "extended-fact-id"
      ),
    /unapproved DataHub URN/u
  );
  assert.doesNotThrow(() =>
    assertPublicJudgeEvidenceIdentifiers(
      `scan-2026-07-01:${dataset}#amount:schema`,
      "known-field-fact-id"
    )
  );
  assert.doesNotThrow(() =>
    assertPublicJudgeEvidenceIdentifiers(
      '"urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)#email"',
      "known-verification-evidence"
    )
  );
  assert.throws(
    () =>
      assertPublicJudgeEvidenceIdentifiers(
        "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)#email.shadow",
        "ambiguous-field-extension"
      ),
    /unapproved DataHub URN/u
  );
  assert.throws(
    () =>
      assertPublicJudgeEvidenceIdentifiers(
        `${dataset}#arbitrary`,
        "unknown-field-extension"
      ),
    /unapproved DataHub URN/u
  );
  assert.throws(
    () =>
      assertPublicJudgeEvidenceIdentifiers(
        "urn:li:corpGroup:unapproved",
        "unknown-urn"
      ),
    /unapproved DataHub URN/u
  );
});

test("judge evidence rejects a non-exact release revision", async () => {
  await assert.rejects(
    buildJudgeEvidencePack({ releaseSha: "not-a-git-sha" }),
    /exact lowercase 40-character Git SHA/u
  );
});
