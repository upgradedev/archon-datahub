import { test } from "node:test";
import assert from "node:assert/strict";
import { AuditPipeline } from "../../src/pipeline/pipeline.js";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import type {
  DataHubTagMutationPort,
  G6FindingEvidence,
  MutationAck,
  TagProjection,
  TagProjectionReader,
} from "../../src/remediation/contracts.js";
import {
  createApprovalDecision,
  createApprovalRequest,
  executeApprovedRemediation,
  InMemoryExecutionJournal,
} from "../../src/remediation/control-loop.js";
import { digest } from "../../src/remediation/integrity.js";
import {
  createTagProjection,
  createTrustedRemediationPolicy,
  planG6Remediation,
} from "../../src/remediation/planner.js";
import { createRollbackProposal, verifyExecutionReceipt } from "../../src/remediation/receipt.js";

class MutableFieldTagPort implements TagProjectionReader, DataHubTagMutationPort {
  writes = 0;
  constructor(public projection: TagProjection) {}

  async readTagProjection(): Promise<TagProjection> {
    return this.projection;
  }

  async addTags(input: {
    tagUrns: readonly string[];
    entityUrns: readonly string[];
    columnPaths?: readonly (string | null)[];
  }): Promise<MutationAck> {
    this.writes += 1;
    this.projection = createTagProjection({
      entityUrn: input.entityUrns[0]!,
      columnPath: input.columnPaths?.[0] ?? "",
      tags: [...this.projection.tags, input.tagUrns[0]!],
    });
    return {
      requestDigest: digest({
        tagUrns: [...input.tagUrns],
        entityUrns: [...input.entityUrns],
        columnPaths: [...(input.columnPaths ?? [])],
      }),
      responseDigest: digest({ success: true }),
    };
  }
}

test("E2E: audit → G6 dossier → exact approval → add tag → verify → receipt/rollback anchor", async () => {
  const client = new FakeDataHubMcpClient();
  const audit = await new AuditPipeline().run(client);
  const finding = audit.findings.find(
    (item) =>
      item.type === "governance_violation" &&
      item.detail["ruleId"] === "G6"
  );
  assert.ok(finding, "fixture audit must emit a structured G6 finding");
  const unclassifiedFields = finding.detail["unclassifiedFields"];
  assert.ok(Array.isArray(unclassifiedFields));
  const columnPath = String(unclassifiedFields[0]);

  const before = createTagProjection({
    entityUrn: finding.subject,
    columnPath,
    tags: [],
  });
  const findingEvidence: G6FindingEvidence = {
    type: "governance_violation",
    severity: finding.severity,
    subject: finding.subject,
    ruleId: "G6",
    unclassifiedFields: unclassifiedFields.map(String),
  };
  const blast = finding.detail["blastRadius"] as {
    downstream?: Array<{ urn?: string }>;
    truncated?: boolean;
  };
  const planned = planG6Remediation({
    scanId: audit.scanId,
    finding: findingEvidence,
    columnPath,
    before,
    policy: createTrustedRemediationPolicy({
      policyId: "classification-safe-writeback-v1",
      enabled: true,
      classificationTagUrn: "urn:li:tag:PII",
      allowedEntityUrnPrefixes: ["urn:li:dataset:"],
    }),
    observedAt: "2026-07-23T10:00:00.000Z",
    blastRadius: {
      downstreamUrns: (blast?.downstream ?? []).map((item) => String(item.urn)),
      truncated: blast?.truncated === true,
    },
  });
  assert.equal(planned.disposition, "ACTIONABLE");

  const request = createApprovalRequest({
    dossier: planned.dossier,
    plan: planned.plan,
    requestedAt: "2026-07-23T10:01:00.000Z",
    expiresAt: "2026-07-23T10:11:00.000Z",
    nonce: "e2e-nonce-0001",
  });
  const decision = createApprovalDecision({
    request,
    plan: planned.plan,
    decision: "APPROVE",
    approver: {
      subject: "steward@example.test",
      issuer: "https://oidc.example.test",
      roles: ["DataSteward"],
      authenticated: true,
    },
    decidedAt: "2026-07-23T10:02:00.000Z",
  });
  const port = new MutableFieldTagPort(before);
  const times = ["2026-07-23T10:03:00.000Z", "2026-07-23T10:03:01.000Z"];
  const receipt = await executeApprovedRemediation({
    dossier: planned.dossier,
    plan: planned.plan,
    request,
    decision,
    reader: port,
    mutation: port,
    journal: new InMemoryExecutionJournal(),
    idempotencyKey: "e2e-g6-1",
    clock: () => times.shift() ?? "2026-07-23T10:03:01.000Z",
  });

  assert.equal(port.writes, 1);
  assert.equal(receipt.outcome, "VERIFIED");
  assert.equal(verifyExecutionReceipt(receipt).valid, true);
  const rollback = createRollbackProposal(receipt, port.projection);
  assert.ok(rollback);
  assert.equal(rollback.requiresFreshApproval, true);
});

test("E2E: contradictions remain manual-only and cannot become a tag plan", async () => {
  const audit = await new AuditPipeline().run(new FakeDataHubMcpClient());
  const contradiction = audit.findings.find((item) => item.type === "contradiction");
  assert.ok(contradiction);
  const result = planG6Remediation({
    scanId: audit.scanId,
    finding: contradiction,
    columnPath: "email",
    before: createTagProjection({
      entityUrn: contradiction.subject,
      columnPath: "email",
      tags: [],
    }),
    policy: createTrustedRemediationPolicy({
      policyId: "classification-safe-writeback-v1",
      enabled: true,
      classificationTagUrn: "urn:li:tag:PII",
    }),
    observedAt: "2026-07-23T10:00:00.000Z",
  });
  assert.deepEqual(result, {
    disposition: "MANUAL_ONLY",
    reason: "UNSUPPORTED_FINDING",
  });
});
