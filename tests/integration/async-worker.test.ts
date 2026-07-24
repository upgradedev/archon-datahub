import assert from "node:assert/strict";
import { test } from "node:test";
import { FakeDataHubMcpClient } from "../../src/datahub/mcp-client.js";
import { LiveDataHubMcpClient } from "../../src/datahub/mcp-client-live.js";
import {
  DataHubHarvestError,
} from "../../src/datahub/harvest-policy.js";
import type {
  DataHubMutationClient,
  TagMutationRequest,
} from "../../src/datahub/mutation-client.js";
import type {
  ApprovalRequestV1,
  ExecutionJournal,
  ExecutionReceiptV1,
  MutationAck,
  TagProjection,
  TagProjectionReader,
} from "../../src/remediation/contracts.js";
import { InMemoryExecutionJournal } from "../../src/remediation/control-loop.js";
import { digest, type Sha256Digest } from "../../src/remediation/integrity.js";
import { createTagProjection } from "../../src/remediation/planner.js";
import type {
  ApprovalQueueMessageV1,
  AuditEvidenceV1,
  ExecutionEvidenceV1,
  RemediationQueueMessageV1,
} from "../../src/worker/contracts.js";
import type {
  ApprovalHandoff,
  AuditResultCheckpoint,
  ImmutableEvidenceStore,
} from "../../src/worker/service.js";
import {
  ApprovalHandoffService,
  AuditWorkerService,
  RemediationWorkerService,
  verifyAuditEvidence,
} from "../../src/worker/service.js";

const EXECUTION =
  "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0001";

class MemoryEvidence implements ImmutableEvidenceStore {
  readonly documents: Array<AuditEvidenceV1 | ExecutionEvidenceV1> = [];

  async put(document: AuditEvidenceV1 | ExecutionEvidenceV1): Promise<void> {
    this.documents.push(document);
  }

  async getAuditEvidence(expected: Sha256Digest): Promise<AuditEvidenceV1> {
    const document = this.documents.find(
      (candidate): candidate is AuditEvidenceV1 =>
        candidate.schemaVersion === "archon.audit-evidence/v1" &&
        candidate.digest === expected
    );
    assert.ok(document);
    assert.equal(verifyAuditEvidence(document, expected), true);
    return document;
  }
}

class MutableProjection
  implements TagProjectionReader, DataHubMutationClient
{
  projection?: TagProjection;
  writes = 0;

  async readTagProjection(target: {
    entityUrn: string;
    columnPath: string;
  }): Promise<TagProjection> {
    this.projection ??= createTagProjection({ ...target, tags: [] });
    return this.projection;
  }

  async addTags(input: TagMutationRequest): Promise<MutationAck> {
    this.writes += 1;
    this.projection = createTagProjection({
      entityUrn: input.entityUrns[0]!,
      columnPath: input.columnPaths?.[0] ?? "",
      tags: [...(this.projection?.tags ?? []), input.tagUrns[0]!],
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

  async removeTags(): Promise<MutationAck> {
    throw new Error("rollback requires a separately approved worker request");
  }
}

class MemoryApprovalHandoff implements ApprovalHandoff {
  calls: Array<{
    message: ApprovalQueueMessageV1;
    request: ApprovalRequestV1;
  }> = [];

  async put(input: {
    message: ApprovalQueueMessageV1;
    request: ApprovalRequestV1;
  }): Promise<"CREATED"> {
    this.calls.push(input);
    return "CREATED";
  }
}

class MemoryAuditCheckpoint implements AuditResultCheckpoint {
  value?: {
    executionId: string;
    requestDigest: Sha256Digest;
    output: Awaited<ReturnType<AuditWorkerService["audit"]>>;
  };

  async get(executionId: string, requestDigest: Sha256Digest) {
    return this.value?.executionId === executionId &&
      this.value.requestDigest === requestDigest
      ? this.value.output
      : null;
  }

  async put(
    executionId: string,
    requestDigest: Sha256Digest,
    output: Awaited<ReturnType<AuditWorkerService["audit"]>>
  ) {
    this.value = { executionId, requestDigest, output };
    return output;
  }
}

class RecoveringJournal implements ExecutionJournal {
  completed?: ExecutionReceiptV1;

  async claim() {
    return { disposition: "RECONCILE" as const, fencingToken: 7 };
  }

  async resume(lease: {
    idempotencyKey: string;
    fencingToken: number;
  }): Promise<boolean> {
    assert.equal(lease.fencingToken, 7);
    return true;
  }

  async complete(
    lease: { idempotencyKey: string; fencingToken: number },
    receipt: ExecutionReceiptV1
  ): Promise<void> {
    assert.equal(lease.fencingToken, 7);
    assert.equal(lease.idempotencyKey, receipt.idempotencyKey);
    this.completed = receipt;
  }
}

test("governed hosted audit fails closed when only the MCP read surface is configured", async () => {
  const saved = {
    gms: process.env.DATAHUB_GMS_URL,
    mcp: process.env.DATAHUB_MCP_URL,
  };
  delete process.env.DATAHUB_GMS_URL;
  process.env.DATAHUB_MCP_URL = "https://read-only.example.test/mcp";
  try {
    const evidence = new MemoryEvidence();
    const projection = new MutableProjection();
    const service = new AuditWorkerService({
      dataHub: new LiveDataHubMcpClient(),
      tagReader: projection,
      evidence,
      releaseSha: "a".repeat(40),
    });
    await assert.rejects(
      service.audit({
        type: "AUDIT_REQUESTED",
        taskToken: "opaque-audit-task-token-history-required",
        executionId: EXECUTION,
        request: {
          schemaVersion: "archon.audit-request/v1",
          requestId: "request-history-required",
          requestedAt: "2026-07-23T10:00:00.000Z",
          query: "archon_demo",
          mode: "GOVERNED",
        },
      }),
      (error: unknown) =>
        error instanceof DataHubHarvestError &&
        error.code === "HISTORY_CAPABILITY_REQUIRED"
    );
    assert.equal(evidence.documents.length, 0);
    assert.equal(projection.writes, 0);
  } finally {
    if (saved.gms === undefined) delete process.env.DATAHUB_GMS_URL;
    else process.env.DATAHUB_GMS_URL = saved.gms;
    if (saved.mcp === undefined) delete process.env.DATAHUB_MCP_URL;
    else process.env.DATAHUB_MCP_URL = saved.mcp;
  }
});

test("hosted async path binds audit evidence, durable approval handoff, write, verification, and receipt", async () => {
  const evidence = new MemoryEvidence();
  const catalog = new MutableProjection();
  const approvalHandoff = new MemoryApprovalHandoff();
  const auditCheckpoint = new MemoryAuditCheckpoint();
  const times = [
    "2026-07-23T10:02:00.000Z",
    "2026-07-23T10:04:00.000Z",
    "2026-07-23T10:04:01.000Z",
    "2026-07-23T10:04:02.000Z",
  ];
  const auditService = new AuditWorkerService({
    dataHub: new FakeDataHubMcpClient(),
    tagReader: catalog,
    evidence,
    auditCheckpoint,
    releaseSha: "a".repeat(40),
    clock: () => times.shift() ?? "2026-07-23T10:04:02.000Z",
    nonce: () => "deterministic-worker-nonce-0001",
  });

  const audit = await auditService.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "opaque-audit-task-token-0001",
    executionId: EXECUTION,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: "request-0001",
      requestedAt: "2026-07-23T10:00:00.000Z",
    },
  });
  assert.equal(audit.requiresApproval, true);
  assert.ok(audit.approvalId);
  assert.ok(audit.planDigest);
  assert.equal(evidence.documents.length, 1);
  assert.equal(catalog.writes, 0);
  const replayedAudit = await auditService.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "different-redelivery-token-0001",
    executionId: EXECUTION,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: "request-0001",
      requestedAt: "2026-07-23T10:00:00.000Z",
    },
  });
  assert.deepEqual(replayedAudit, audit);
  assert.equal(evidence.documents.length, 1);

  const approvalMessage: ApprovalQueueMessageV1 = {
    type: "APPROVAL_REQUESTED",
    taskToken: "opaque-approval-task-token-0001",
    executionId: EXECUTION,
    approvalId: audit.approvalId,
    planDigest: audit.planDigest,
    evidenceDigest: audit.evidenceDigest,
    approvalRequestDigest: audit.approvalRequestDigest!,
    requestedAt: audit.approvalRequestedAt!,
    expiresAt: audit.approvalExpiresAt!,
  };
  const approvalService = new ApprovalHandoffService({
    evidence,
    approvalHandoff,
  });
  assert.equal(await approvalService.handoffApproval(approvalMessage), "CREATED");
  assert.equal(approvalHandoff.calls.length, 1);
  assert.equal(
    approvalHandoff.calls[0]!.message.taskToken,
    "opaque-approval-task-token-0001"
  );
  assert.equal(catalog.writes, 0);

  const remediationMessage: RemediationQueueMessageV1 = {
    type: "REMEDIATION_REQUESTED",
    taskToken: "opaque-remediation-task-token-0001",
    executionId: EXECUTION,
    approvalId: audit.approvalId,
    planDigest: audit.planDigest,
    evidenceDigest: audit.evidenceDigest,
    approvalResult: {
      approvalId: audit.approvalId,
      decision: {
        decision: "APPROVE",
        approver: {
          subject: "cognito-user-0001",
          issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
          roles: ["DataSteward"],
          authenticated: true,
        },
        decidedAt: "2026-07-23T10:03:00.000Z",
      },
    },
  };
  const remediationService = new RemediationWorkerService({
    tagReader: catalog,
    mutation: catalog,
    journal: new InMemoryExecutionJournal(),
    evidence,
    clock: () => times.shift() ?? "2026-07-23T10:04:02.000Z",
  });
  const result = await remediationService.remediate(remediationMessage);
  assert.equal(result.outcome, "VERIFIED");
  assert.equal(catalog.writes, 1);
  assert.equal(evidence.documents.length, 2);
  assert.equal(
    evidence.documents[1]!.schemaVersion,
    "archon.execution-evidence/v1"
  );
  const firstExecutionEvidence = evidence.documents[1] as ExecutionEvidenceV1;
  const replayedResult = await remediationService.remediate({
    ...remediationMessage,
    taskToken: "different-remediation-redelivery-token-0001",
  });
  assert.deepEqual(replayedResult, result);
  assert.equal(catalog.writes, 1);
  assert.equal(evidence.documents.length, 3);
  assert.deepEqual(evidence.documents[2], firstExecutionEvidence);
});

test("async audit remains read-only when the fresh field projection invalidates its G6 proposal", async () => {
  const evidence = new MemoryEvidence();
  const mutation = new MutableProjection();
  const service = new AuditWorkerService({
    dataHub: new FakeDataHubMcpClient(),
    tagReader: {
      async readTagProjection(target) {
        return createTagProjection({ ...target, tags: ["urn:li:tag:PII"] });
      },
    },
    evidence,
    releaseSha: "b".repeat(40),
    clock: () => "2026-07-23T11:00:00.000Z",
    nonce: () => "unused-policy-rejected-nonce",
  });
  const result = await service.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "opaque-audit-task-token-0002",
    executionId:
      "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0002",
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: "request-0002",
      requestedAt: "2026-07-23T10:59:00.000Z",
    },
  });
  assert.equal(result.requiresApproval, false);
  assert.equal(result.manualOnlyReason, "POLICY_REJECTED_PROPOSAL");
  assert.equal(mutation.writes, 0);
  assert.equal(evidence.documents.length, 1);
});

test("a human rejection produces immutable execution evidence without a mutation", async () => {
  const evidence = new MemoryEvidence();
  const catalog = new MutableProjection();
  const auditService = new AuditWorkerService({
    dataHub: new FakeDataHubMcpClient(),
    tagReader: catalog,
    evidence,
    releaseSha: "c".repeat(40),
    clock: () => "2026-07-23T12:00:00.000Z",
    nonce: () => "deterministic-rejection-nonce-0001",
  });
  const audit = await auditService.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "opaque-audit-task-token-0003",
    executionId:
      "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0003",
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: "request-0003",
      requestedAt: "2026-07-23T11:59:00.000Z",
    },
  });
  assert.equal(audit.requiresApproval, true);
  const remediation = new RemediationWorkerService({
    tagReader: catalog,
    mutation: catalog,
    journal: new InMemoryExecutionJournal(),
    evidence,
    clock: () => "2026-07-23T12:02:00.000Z",
  });

  const result = await remediation.remediate({
    type: "REMEDIATION_REQUESTED",
    taskToken: "opaque-remediation-task-token-0003",
    executionId:
      "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0003",
    approvalId: audit.approvalId!,
    planDigest: audit.planDigest!,
    evidenceDigest: audit.evidenceDigest,
    approvalResult: {
      approvalId: audit.approvalId!,
      decision: {
        decision: "REJECT",
        approver: {
          subject: "cognito-user-0002",
          issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
          roles: ["DataSteward"],
          authenticated: true,
        },
        decidedAt: "2026-07-23T12:01:00.000Z",
      },
    },
  });

  assert.equal(result.outcome, "REJECTED");
  assert.equal(catalog.writes, 0);
  assert.equal(evidence.documents.length, 2);
  assert.equal(
    (evidence.documents[1] as ExecutionEvidenceV1).receipt.outcome,
    "REJECTED"
  );
});

test("stale execution reconciliation never replays a mutation after state changed", async () => {
  const evidence = new MemoryEvidence();
  const catalog = new MutableProjection();
  const auditService = new AuditWorkerService({
    dataHub: new FakeDataHubMcpClient(),
    tagReader: catalog,
    evidence,
    releaseSha: "d".repeat(40),
    clock: () => "2026-07-23T13:00:00.000Z",
    nonce: () => "deterministic-recovery-nonce-0001",
  });
  const executionId =
    "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0004";
  const audit = await auditService.audit({
    type: "AUDIT_REQUESTED",
    taskToken: "opaque-audit-task-token-0004",
    executionId,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: "request-0004",
      requestedAt: "2026-07-23T12:59:00.000Z",
    },
  });
  const auditEvidence = evidence.documents[0] as AuditEvidenceV1;
  assert.equal(auditEvidence.remediation.disposition, "ACTIONABLE");
  if (auditEvidence.remediation.disposition !== "ACTIONABLE") return;
  catalog.projection = auditEvidence.remediation.plan.expectedAfter;
  const journal = new RecoveringJournal();
  const remediation = new RemediationWorkerService({
    tagReader: catalog,
    mutation: catalog,
    journal,
    evidence,
    clock: () => "2026-07-23T13:02:00.000Z",
  });

  const result = await remediation.remediate({
    type: "REMEDIATION_REQUESTED",
    taskToken: "opaque-remediation-task-token-0004",
    executionId,
    approvalId: audit.approvalId!,
    planDigest: audit.planDigest!,
    evidenceDigest: audit.evidenceDigest,
    approvalResult: {
      approvalId: audit.approvalId!,
      decision: {
        decision: "APPROVE",
        approver: {
          subject: "cognito-user-0003",
          issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
          roles: ["DataSteward"],
          authenticated: true,
        },
        decidedAt: "2026-07-23T13:01:00.000Z",
      },
    },
  });

  assert.equal(result.outcome, "INDETERMINATE");
  assert.equal(catalog.writes, 0);
  assert.equal(journal.completed?.outcome, "INDETERMINATE");
});
