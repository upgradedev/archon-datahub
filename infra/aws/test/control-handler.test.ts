const mockDdbSend = jest.fn();
const mockS3Send = jest.fn();
const mockSfnSend = jest.fn();
const { createHash } = require("node:crypto") as typeof import("node:crypto");

jest.mock(
  "@aws-sdk/client-dynamodb",
  () => ({
    DynamoDBClient: class {
      send = mockDdbSend;
    },
    GetItemCommand: class {
      readonly kind = "GetItemCommand";
      constructor(readonly input: Record<string, unknown>) {}
    }
  }),
  { virtual: true }
);
jest.mock(
  "@aws-sdk/client-s3",
  () => ({
    S3Client: class {
      send = mockS3Send;
    },
    GetObjectCommand: class {
      readonly kind = "GetObjectCommand";
      constructor(readonly input: Record<string, unknown>) {}
    }
  }),
  { virtual: true }
);
jest.mock(
  "@aws-sdk/client-sfn",
  () => ({
    SFNClient: class {
      send = mockSfnSend;
    },
    DescribeExecutionCommand: class {
      readonly kind = "DescribeExecutionCommand";
      constructor(readonly input: Record<string, unknown>) {}
    },
    StartExecutionCommand: class {
      readonly kind = "StartExecutionCommand";
      constructor(readonly input: Record<string, unknown>) {}
    }
  }),
  { virtual: true }
);

process.env.STATE_MACHINE_ARN =
  "arn:aws:states:eu-west-1:111111111111:stateMachine:archon-staging-control-loop";
process.env.CHECKPOINT_TABLE = "checkpoint-table";
process.env.APPROVAL_TABLE = "approval-table";
process.env.EVIDENCE_BUCKET = "evidence-bucket";

const { handler } = require("../lambda/control/index.js") as {
  handler: (event: Record<string, any>) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    body: string;
  }>;
};

function startEvent(body: unknown): Record<string, unknown> {
  return {
    httpMethod: "POST",
    resource: "/api/control-loops",
    requestContext: { requestId: "request-123" },
    body: JSON.stringify(body)
  };
}

function statusEvent(auditId: string): Record<string, unknown> {
  return {
    httpMethod: "GET",
    resource: "/api/control-loops/{auditId}",
    pathParameters: { auditId },
    requestContext: { requestId: "request-456" }
  };
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`)
    .join(",")}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value), "utf8")
    .digest("hex")}`;
}

function rawDigest(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function without(
  value: Record<string, unknown>,
  keys: string[]
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !keys.includes(key))
  );
}

function signed<T extends Record<string, unknown>>(value: T): T & { digest: string } {
  return { ...value, digest: digest(value) };
}

function terminalFixture(
  auditId: string,
  decisionValue: "APPROVE" | "REJECT" = "APPROVE"
) {
  const executionArn =
    `arn:aws:states:eu-west-1:111111111111:execution:` +
    `archon-staging-control-loop:${auditId}`;
  const approver = {
    subject: "private-steward-subject",
    issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
    roles: ["DataSteward"],
    authenticated: true
  };
  const before = signed({
    entityUrn: "urn:li:dataset:private-customer",
    columnPath: "email",
    tags: [] as string[]
  });
  const after = signed({
    entityUrn: "urn:li:dataset:private-customer",
    columnPath: "email",
    tags: ["urn:li:tag:PII"]
  });
  const argumentsValue = {
    tag_urns: ["urn:li:tag:PII"],
    entity_urns: ["urn:li:dataset:private-customer"],
    column_paths: ["email"]
  };
  const action = signed({
    actionId: "datahub.add-classification-tag.v1",
    tool: "add_tags",
    arguments: argumentsValue,
    inverse: {
      tool: "remove_tags",
      arguments: argumentsValue
    }
  });
  const findingEvidence = {
    type: "governance_violation",
    severity: "high",
    subject: "urn:li:dataset:private-customer",
    ruleId: "G6",
    unclassifiedFields: ["email"]
  };
  const dossierUnsigned = {
    schemaVersion: "archon.evidence-dossier/v1",
    scanId: "scan-live-terminal",
    findingDigest: digest(findingEvidence),
    finding: findingEvidence,
    target: {
      entityUrn: "urn:li:dataset:private-customer",
      columnPath: "email"
    },
    provenance: [],
    blastRadius: {
      downstreamUrns: [],
      maxHops: 3,
      truncated: false
    },
    before,
    policyDigest: `sha256:${"7".repeat(64)}`,
    createdAt: "2026-07-23T12:00:05.000Z"
  };
  const dossierDigest = digest(dossierUnsigned);
  const dossier = {
    ...dossierUnsigned,
    dossierId: `dossier-${dossierDigest.slice(7, 31)}`,
    digest: dossierDigest
  };
  const planUnsigned = {
    schemaVersion: "archon.remediation-plan/v1",
    dossierDigest: dossier.digest,
    policyDigest: dossier.policyDigest,
    actionCatalogDigest: `sha256:${"8".repeat(64)}`,
    action,
    expectedBefore: before,
    expectedAfter: after,
    risk: "low",
    requiresHumanApproval: true
  };
  const planDigest = digest(planUnsigned);
  const plan = {
    ...planUnsigned,
    planId: `plan-${planDigest.slice(7, 31)}`,
    digest: planDigest
  };
  const approvalRequestUnsigned = {
    schemaVersion: "archon.approval-request/v1",
    dossierDigest: dossier.digest,
    planDigest: plan.digest,
    actionCatalogDigest: plan.actionCatalogDigest,
    expectedBeforeDigest: before.digest,
    requestedAt: "2026-07-23T12:00:05.000Z",
    expiresAt: "2026-07-29T12:00:05.000Z",
    nonce: "terminal-nonce"
  };
  const approvalRequestDigest = digest(approvalRequestUnsigned);
  const approvalId = `approval-${approvalRequestDigest.slice(7, 31)}`;
  const approvalRequest = {
    ...approvalRequestUnsigned,
    approvalId,
    digest: approvalRequestDigest
  };
  const report = {
    scanId: "scan-live-terminal",
    classification: {
      totalEntities: 1,
      withLineage: 1,
      sensitiveEntities: 1,
      domains: { Customer: 1 },
      platforms: { snowflake: 1 }
    },
    findings: [
      {
        type: "governance_violation",
        severity: "high",
        subject: "urn:li:dataset:private-customer",
        summary: "Missing PII classification",
        detail: { ruleId: "G6", unclassifiedFields: ["email"] }
      }
    ],
    narrative: "One exact G6 finding.",
    trace: [{ agent: "governance-auditor", produced: "one finding" }]
  };
  const reportDigest = digest(report);
  const unsignedAuditEvidence = {
    schemaVersion: "archon.audit-evidence/v1",
    executionId: executionArn,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: auditId,
      requestedAt: "2026-07-23T12:00:00.000Z",
      mode: "GOVERNED"
    },
    releaseSha: "release-live-terminal",
    report,
    reportDigest,
    remediation: {
      disposition: "ACTIONABLE",
      dossier,
      plan,
      approvalRequest
    },
    createdAt: "2026-07-23T12:00:05.000Z"
  };
  const auditEvidence = signed(unsignedAuditEvidence);
  const decidedAt = "2026-07-23T12:01:00.000Z";
  const decision = signed({
    schemaVersion: "archon.approval-decision/v1",
    approvalId,
    requestDigest: approvalRequest.digest,
    planDigest: plan.digest,
    decision: decisionValue,
    approver,
    decidedAt
  });
  const outcome = decisionValue === "APPROVE" ? "VERIFIED" : "REJECTED";
  const idempotencyKey = digest({
    schemaVersion: "archon.worker-execution-key/v1",
    executionId: executionArn,
    approvalId,
    decisionDigest: decision.digest
  });
  const receiptExecutionDigest = digest({
    decisionDigest: decision.digest,
    idempotencyKey
  });
  const mutation = {
    requestDigest: digest({
      tagUrns: [...argumentsValue.tag_urns],
      entityUrns: [...argumentsValue.entity_urns],
      columnPaths: [...argumentsValue.column_paths]
    }),
    responseDigest: `sha256:${"9".repeat(64)}`
  };
  const checks =
    outcome === "VERIFIED"
      ? [
          "TARGET_UNCHANGED",
          "PREEXISTING_TAGS_PRESERVED",
          "POLICY_TAG_PRESENT",
          "NO_UNEXPECTED_TAGS",
          "APPROVAL_BINDING_VALID"
        ].map((checkId) => ({
          checkId,
          passed: true,
          evidence: `${checkId} passed without exposing provider data.`
        }))
      : [];
  const rollback =
    outcome === "VERIFIED"
      ? {
          availability: "ELIGIBLE",
          inverseActionDigest: digest(action.inverse),
          restoreStateDigest: before.digest
        }
      : { availability: "NOT_APPLICABLE" };
  const startedAt = "2026-07-23T12:01:01.000Z";
  const completedAt = "2026-07-23T12:01:02.000Z";
  const eventPayloads = [
    {
      kind: "DOSSIER_BOUND",
      payload: { dossierDigest: dossier.digest },
      occurredAt: startedAt
    },
    {
      kind: "PLAN_BOUND",
      payload: { planDigest: plan.digest },
      occurredAt: startedAt
    },
    {
      kind: "APPROVAL_BOUND",
      payload: { approvalDecisionDigest: decision.digest },
      occurredAt: startedAt
    },
    {
      kind: "PRECONDITION_CHECKED",
      payload: { beforeDigest: outcome === "VERIFIED" ? before.digest : null },
      occurredAt: startedAt
    },
    ...(outcome === "VERIFIED"
      ? [
          {
            kind: "MUTATION_INVOKED",
            payload: mutation,
            occurredAt: completedAt
          },
          {
            kind: "POSTCONDITION_CHECKED",
            payload: { afterDigest: after.digest, checks },
            occurredAt: completedAt
          }
        ]
      : []),
    {
      kind: "ROLLBACK_ANCHORED",
      payload: rollback,
      occurredAt: completedAt
    }
  ];
  let previousHash = digest("archon-execution-receipt-chain-genesis-v1");
  const events = eventPayloads.map((event, sequence) => {
    const unsigned = {
      sequence,
      kind: event.kind,
      occurredAt: event.occurredAt,
      payloadDigest: digest(event.payload),
      previousHash
    };
    const value = { ...unsigned, eventHash: digest(unsigned) };
    previousHash = value.eventHash;
    return value;
  });
  const unsignedReceipt = {
    schemaVersion: "archon.execution-receipt/v1",
    executionId:
      `execution-${receiptExecutionDigest.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}`,
    outcome,
    dossierDigest: dossier.digest,
    planDigest: plan.digest,
    approvalDecisionDigest: decision.digest,
    action,
    idempotencyKey,
    ...(outcome === "VERIFIED" ? { before, after, mutation } : {}),
    checks,
    rollback,
    events,
    startedAt,
    completedAt
  };
  const receiptDigest = digest(unsignedReceipt);
  const receipt = {
    ...unsignedReceipt,
    receiptId:
      `receipt-${receiptDigest.slice(
        "sha256:".length,
        "sha256:".length + 24
      )}`,
    digest: receiptDigest
  };
  const executionEvidence = signed({
    schemaVersion: "archon.execution-evidence/v1",
    executionId: executionArn,
    approvalId,
    auditEvidenceDigest: auditEvidence.digest,
    decision,
    receipt,
    createdAt: "2026-07-23T12:01:03.000Z"
  });
  const remediationResult = {
    schemaVersion: "archon.remediation-result/v1",
    approvalId,
    planDigest: plan.digest,
    evidenceDigest: auditEvidence.digest,
    receiptDigest: receipt.digest,
    executionEvidenceDigest: executionEvidence.digest,
    outcome
  };
  const decisionEvidence = {
    schemaVersion: "archon.approval-decision/v1",
    approvalId,
    executionId: executionArn,
    evidenceDigest: auditEvidence.digest,
    planDigest: plan.digest,
    requestDigest: approvalRequest.digest,
    decision: decisionValue,
    approver,
    commentDigest: `sha256:${"a".repeat(64)}`
  };
  const decisionEvidenceText = JSON.stringify(decisionEvidence);
  return {
    approvalId,
    approvalExpiresAt: approvalRequest.expiresAt,
    auditEvidence,
    decisionEvidenceText,
    decisionEvidenceDigest: rawDigest(decisionEvidenceText),
    decidedAt,
    executionArn,
    executionEvidence,
    outcome,
    planDigest: plan.digest,
    remediationResult,
    reportDigest,
    receipt
  };
}

describe("async audit control Lambda", () => {
  beforeEach(() => {
    mockDdbSend.mockReset();
    mockS3Send.mockReset();
    mockSfnSend.mockReset();
  });

  test("starts a strict Standard execution and returns only an opaque polling capability", async () => {
    mockSfnSend.mockResolvedValue({
      executionArn:
        "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:ignored"
    });

    const result = await handler(startEvent({ query: "domain:Commerce" }));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(202);
    expect(body).toEqual(
      expect.objectContaining({
        schemaVersion: "archon.control-loop-start/v1",
        status: "RUNNING",
        submittedAt: expect.any(String)
      })
    );
    expect(body.auditId).toMatch(/^[a-f0-9]{64}$/);
    expect(body.pollUrl).toBe(`/api/control-loops/${body.auditId}`);
    expect(body).not.toHaveProperty("executionArn");
    const command = mockSfnSend.mock.calls[0]![0] as {
      kind: string;
      input: Record<string, any>;
    };
    expect(command.kind).toBe("StartExecutionCommand");
    expect(command.input.name).toBe(body.auditId);
    expect(JSON.parse(command.input.input)).toEqual({
      schemaVersion: "archon.audit-request/v1",
      requestId: body.auditId,
      requestedAt: body.submittedAt,
      mode: "GOVERNED",
      query: "domain:Commerce"
    });
  });

  test("rejects unbounded or mutation-bearing start input before AWS", async () => {
    const unexpected = await handler(
      startEvent({
        query: "domain:Commerce",
        tool: "add_tags",
        arguments: { entityUrns: ["urn:li:dataset:forbidden"] }
      })
    );
    const tooLong = await handler(startEvent({ query: "x".repeat(257) }));
    const missing = await handler(startEvent({}));
    const wildcard = await handler(startEvent({ query: "*" }));

    expect(unexpected.statusCode).toBe(400);
    expect(JSON.parse(unexpected.body)).toEqual({ error: "unexpected_field" });
    expect(tooLong.statusCode).toBe(400);
    expect(JSON.parse(missing.body)).toEqual({ error: "query_required" });
    expect(JSON.parse(wildcard.body)).toEqual({
      error: "query_must_be_narrow"
    });
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("reports running without exposing the execution ARN or raw Step Functions data", async () => {
    const auditId = "a".repeat(64);
    mockSfnSend.mockResolvedValue({
      status: "RUNNING",
      startDate: new Date("2026-07-23T12:00:00.000Z"),
      input: JSON.stringify({ secret: "must-not-leak" })
    });
    mockDdbSend.mockResolvedValue({});

    const result = await handler(statusEvent(auditId));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body).toEqual(
      expect.objectContaining({
        schemaVersion: "archon.control-loop-status/v1",
        auditId,
        status: "RUNNING",
        submittedAt: "2026-07-23T12:00:00.000Z"
      })
    );
    expect(JSON.stringify(body)).not.toContain("must-not-leak");
    expect(JSON.stringify(body)).not.toContain("arn:aws:states");
    expect(mockS3Send).not.toHaveBeenCalled();
  });

  test("verifies immutable evidence and projects a pending approval without its task token", async () => {
    const auditId = "d".repeat(64);
    const executionArn =
      `arn:aws:states:eu-west-1:111111111111:execution:` +
      `archon-staging-control-loop:${auditId}`;
    const report = {
      scanId: "scan-live-1234",
      classification: {
        totalEntities: 1,
        withLineage: 1,
        sensitiveEntities: 1,
        domains: { Customer: 1 },
        platforms: { snowflake: 1 }
      },
      findings: [
        {
          type: "governance_violation",
          severity: "high",
          subject: "urn:li:dataset:customer",
          summary: "Missing PII classification",
          detail: { ruleId: "G6", unclassifiedFields: ["email"] }
        }
      ],
      narrative: "One exact G6 finding.",
      trace: [{ agent: "governance-auditor", produced: "one finding" }]
    };
    const reportDigest = digest(report);
    const planDigest = `sha256:${"5".repeat(64)}`;
    const unsignedEvidence = {
      schemaVersion: "archon.audit-evidence/v1",
      executionId: executionArn,
      request: {
        schemaVersion: "archon.audit-request/v1",
        requestId: auditId,
        requestedAt: "2026-07-23T12:00:00.000Z"
      },
      releaseSha: "release-live-123",
      report,
      reportDigest,
      remediation: {
        disposition: "ACTIONABLE",
        dossier: {
          dossierId: "dossier-live-1234",
          digest: `sha256:${"6".repeat(64)}`,
          policyDigest: `sha256:${"7".repeat(64)}`,
          createdAt: "2026-07-23T12:00:05.000Z",
          finding: {
            subject: "urn:li:dataset:customer"
          },
          target: { columnPath: "email" },
          provenance: [],
          blastRadius: { downstreamUrns: [] }
        },
        plan: {
          digest: planDigest,
          risk: "low",
          action: {
            arguments: { tag_urns: ["urn:li:tag:PII"] }
          },
          expectedBefore: { tags: [] },
          expectedAfter: { tags: ["urn:li:tag:PII"] }
        },
        approvalRequest: {
          approvalId: "approval-live-1234",
          expiresAt: "2026-07-30T12:00:00.000Z"
        }
      },
      createdAt: "2026-07-23T12:00:05.000Z"
    };
    const evidenceDigest = digest(unsignedEvidence);
    const evidence = { ...unsignedEvidence, digest: evidenceDigest };
    mockSfnSend.mockResolvedValue({
      status: "RUNNING",
      startDate: new Date("2026-07-23T12:00:00.000Z")
    });
    mockDdbSend.mockImplementation(async (command: any) => {
      const pk = command.input.Key.pk.S;
      if (pk.startsWith("AUDIT#")) {
        return {
          Item: {
            output: {
              S: JSON.stringify({
                schemaVersion: "archon.audit-result/v1",
                requiresApproval: true,
                reportDigest,
                evidenceDigest,
                approvalId: "approval-live-1234",
                planDigest
              })
            }
          }
        };
      }
      return {
        Item: {
          status: { S: "PENDING" },
          evidenceDigest: { S: evidenceDigest },
          planDigest: { S: planDigest },
          taskToken: { S: "opaque-task-token-must-never-leak" },
          approvalExpiresAt: { S: "2026-07-30T12:00:00.000Z" },
          expiresAt: { N: "1785412800" }
        }
      };
    });
    mockS3Send.mockResolvedValue({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(JSON.stringify(evidence), "utf8")
      }
    });

    const result = await handler(statusEvent(auditId));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body.status).toBe("AWAITING_APPROVAL");
    expect(body.releaseSha).toBe("release-live-123");
    expect(body.report.findings[0].detail.approval).toEqual(
      expect.objectContaining({
        approvalId: "approval-live-1234",
        targetField: "email",
        proposedTag: "urn:li:tag:PII",
        planDigest
      })
    );
    expect(JSON.stringify(body)).not.toContain("opaque-task-token");
    expect(JSON.stringify(body)).not.toContain(executionArn);
  });

  test("verifies and sanitizes terminal governed execution evidence", async () => {
    const auditId = "e".repeat(64);
    const fixture = terminalFixture(auditId);
    mockSfnSend.mockResolvedValue({
      status: "SUCCEEDED",
      startDate: new Date("2026-07-23T12:00:00.000Z"),
      stopDate: new Date("2026-07-23T12:01:04.000Z"),
      output: JSON.stringify({
        auditResult: { providerError: "raw-provider-error-must-not-leak" },
        taskToken: "raw-output-token-must-not-leak",
        remediationResult: fixture.remediationResult
      })
    });
    mockDdbSend.mockImplementation(async (command: any) => {
      const pk = command.input.Key.pk.S;
      if (pk.startsWith("AUDIT#")) {
        return {
          Item: {
            output: {
              S: JSON.stringify({
                schemaVersion: "archon.audit-result/v1",
                requiresApproval: true,
                reportDigest: fixture.reportDigest,
                evidenceDigest: fixture.auditEvidence.digest,
                approvalId: fixture.approvalId,
                planDigest: fixture.planDigest
              })
            }
          }
        };
      }
      return {
        Item: {
          status: { S: "DECIDED" },
          evidenceDigest: { S: fixture.auditEvidence.digest },
          planDigest: { S: fixture.planDigest },
          decision: { S: "APPROVE" },
          decisionEvidence: { S: fixture.decisionEvidenceText },
          decisionEvidenceDigest: { S: fixture.decisionEvidenceDigest },
          decidedAt: { S: fixture.decidedAt },
          approvalExpiresAt: { S: fixture.approvalExpiresAt },
          expiresAt: {
            N: String(
              Math.floor(Date.parse(fixture.decidedAt) / 1000) +
                90 * 24 * 60 * 60
            )
          },
          taskToken: { S: "server-held-token-must-not-leak" }
        }
      };
    });
    mockS3Send.mockImplementation(async (command: any) => {
      const key = command.input.Key;
      const value = key.startsWith("v1/audit/")
        ? fixture.auditEvidence
        : fixture.executionEvidence;
      return {
        Body: {
          transformToByteArray: async () =>
            Buffer.from(JSON.stringify(value), "utf8")
        }
      };
    });

    const result = await handler(statusEvent(auditId));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body.result).toEqual({
      outcome: "VERIFIED",
      receiptDigest: fixture.receipt.digest,
      completedAt: fixture.receipt.completedAt,
      verification: {
        checks: [
          { checkId: "TARGET_UNCHANGED", passed: true },
          { checkId: "PREEXISTING_TAGS_PRESERVED", passed: true },
          { checkId: "POLICY_TAG_PRESENT", passed: true },
          { checkId: "NO_UNEXPECTED_TAGS", passed: true },
          { checkId: "APPROVAL_BINDING_VALID", passed: true }
        ],
        eventCount: 7,
        rollbackAvailability: "ELIGIBLE"
      },
      executionEvidenceDigest: fixture.executionEvidence.digest
    });
    expect(body.approval.expiresAt).toBe(fixture.approvalExpiresAt);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("private-steward-subject");
    expect(serialized).not.toContain("server-held-token");
    expect(serialized).not.toContain("raw-output-token");
    expect(serialized).not.toContain("raw-provider-error");
    expect(serialized).not.toContain(`sha256:${"9".repeat(64)}`);
    expect(serialized).not.toContain(fixture.executionArn);
    expect(
      mockS3Send.mock.calls.map(([command]) => command.input.Key)
    ).toEqual([
      `v1/audit/sha256/${fixture.auditEvidence.digest.slice(7)}.json`,
      `v1/execution/sha256/${fixture.executionEvidence.digest.slice(7)}.json`
    ]);
  });

  test("fails closed when content-addressed terminal evidence has a broken receipt chain", async () => {
    const auditId = "f".repeat(64);
    const fixture = terminalFixture(auditId);
    const executionEvidence = JSON.parse(
      JSON.stringify(fixture.executionEvidence)
    );
    executionEvidence.receipt.events[4].eventHash = `sha256:${"b".repeat(64)}`;
    executionEvidence.receipt.digest = digest(
      without(executionEvidence.receipt, ["receiptId", "digest"])
    );
    executionEvidence.receipt.receiptId =
      `receipt-${executionEvidence.receipt.digest.slice(7, 31)}`;
    executionEvidence.digest = digest(
      without(executionEvidence, ["digest"])
    );
    const remediationResult = {
      ...fixture.remediationResult,
      receiptDigest: executionEvidence.receipt.digest,
      executionEvidenceDigest: executionEvidence.digest
    };
    mockSfnSend.mockResolvedValue({
      status: "SUCCEEDED",
      output: JSON.stringify({ remediationResult })
    });
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.input.Key.pk.S.startsWith("AUDIT#")) {
        return {
          Item: {
            output: {
              S: JSON.stringify({
                schemaVersion: "archon.audit-result/v1",
                requiresApproval: true,
                reportDigest: fixture.reportDigest,
                evidenceDigest: fixture.auditEvidence.digest,
                approvalId: fixture.approvalId,
                planDigest: fixture.planDigest
              })
            }
          }
        };
      }
      return {
        Item: {
          status: { S: "DECIDED" },
          evidenceDigest: { S: fixture.auditEvidence.digest },
          planDigest: { S: fixture.planDigest },
          decision: { S: "APPROVE" },
          decisionEvidence: { S: fixture.decisionEvidenceText },
          decisionEvidenceDigest: { S: fixture.decisionEvidenceDigest },
          decidedAt: { S: fixture.decidedAt },
          approvalExpiresAt: { S: fixture.approvalExpiresAt },
          expiresAt: {
            N: String(
              Math.floor(Date.parse(fixture.decidedAt) / 1000) +
                90 * 24 * 60 * 60
            )
          }
        }
      };
    });
    mockS3Send.mockImplementation(async (command: any) => ({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(
            JSON.stringify(
              command.input.Key.startsWith("v1/audit/")
                ? fixture.auditEvidence
                : executionEvidence
            ),
            "utf8"
          )
      }
    }));

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(502);
    expect(JSON.parse(result.body)).toEqual({
      error: "control_plane_unavailable"
    });
    expect(result.body).not.toContain("EVENT_4");
    expect(result.body).not.toContain("eventHash");
  });

  test("verifies a durable rejection without inventing mutation checks", async () => {
    const auditId = "2".repeat(64);
    const fixture = terminalFixture(auditId, "REJECT");
    mockSfnSend.mockResolvedValue({
      status: "SUCCEEDED",
      stopDate: new Date("2026-07-23T12:01:04.000Z"),
      output: JSON.stringify({
        remediationResult: fixture.remediationResult,
        mutationResponse: "must-not-leak"
      })
    });
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.input.Key.pk.S.startsWith("AUDIT#")) {
        return {
          Item: {
            output: {
              S: JSON.stringify({
                schemaVersion: "archon.audit-result/v1",
                requiresApproval: true,
                reportDigest: fixture.reportDigest,
                evidenceDigest: fixture.auditEvidence.digest,
                approvalId: fixture.approvalId,
                planDigest: fixture.planDigest
              })
            }
          }
        };
      }
      return {
        Item: {
          status: { S: "DECIDED" },
          evidenceDigest: { S: fixture.auditEvidence.digest },
          planDigest: { S: fixture.planDigest },
          decision: { S: "REJECT" },
          decisionEvidence: { S: fixture.decisionEvidenceText },
          decisionEvidenceDigest: { S: fixture.decisionEvidenceDigest },
          decidedAt: { S: fixture.decidedAt },
          approvalExpiresAt: { S: fixture.approvalExpiresAt },
          expiresAt: {
            N: String(
              Math.floor(Date.parse(fixture.decidedAt) / 1000) +
                90 * 24 * 60 * 60
            )
          }
        }
      };
    });
    mockS3Send.mockImplementation(async (command: any) => ({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(
            JSON.stringify(
              command.input.Key.startsWith("v1/audit/")
                ? fixture.auditEvidence
                : fixture.executionEvidence
            ),
            "utf8"
          )
      }
    }));

    const result = await handler(statusEvent(auditId));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body.result).toEqual({
      outcome: "REJECTED",
      receiptDigest: fixture.receipt.digest,
      completedAt: fixture.receipt.completedAt,
      verification: {
        checks: [],
        eventCount: 5,
        rollbackAvailability: "NOT_APPLICABLE"
      },
      executionEvidenceDigest: fixture.executionEvidence.digest
    });
    expect(JSON.stringify(body)).not.toContain("must-not-leak");
    expect(JSON.stringify(body)).not.toContain("private-steward-subject");
  });

  test("preserves read-only completion without parsing or exposing Step Functions output", async () => {
    const auditId = "1".repeat(64);
    const expectedExecutionArn =
      `arn:aws:states:eu-west-1:111111111111:execution:` +
      `archon-staging-control-loop:${auditId}`;
    const report = {
      scanId: "scan-read-only-terminal",
      classification: {
        totalEntities: 0,
        withLineage: 0,
        sensitiveEntities: 0,
        domains: {},
        platforms: {}
      },
      findings: [],
      narrative: "No findings.",
      trace: []
    };
    const reportDigest = digest(report);
    const auditEvidence = signed({
      schemaVersion: "archon.audit-evidence/v1",
      executionId: expectedExecutionArn,
      request: {
        schemaVersion: "archon.audit-request/v1",
        requestId: auditId,
        requestedAt: "2026-07-23T12:00:00.000Z",
        mode: "READ_ONLY"
      },
      releaseSha: "release-read-only",
      report,
      reportDigest,
      remediation: {
        disposition: "MANUAL_ONLY",
        reason: "READ_ONLY_REQUEST"
      },
      createdAt: "2026-07-23T12:00:01.000Z"
    });
    mockSfnSend.mockResolvedValue({
      status: "SUCCEEDED",
      startDate: new Date("2026-07-23T12:00:00.000Z"),
      stopDate: new Date("2026-07-23T12:00:02.000Z"),
      output: JSON.stringify({
        remediationResult: {
          providerSecret: "read-only-output-must-not-leak"
        }
      })
    });
    mockDdbSend.mockResolvedValue({
      Item: {
        output: {
          S: JSON.stringify({
            schemaVersion: "archon.audit-result/v1",
            requiresApproval: false,
            reportDigest,
            evidenceDigest: auditEvidence.digest
          })
        }
      }
    });
    mockS3Send.mockResolvedValue({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(JSON.stringify(auditEvidence), "utf8")
      }
    });

    const result = await handler(statusEvent(auditId));
    const body = JSON.parse(result.body);

    expect(result.statusCode).toBe(200);
    expect(body.result).toEqual({ outcome: "READ_ONLY_COMPLETE" });
    expect(JSON.stringify(body)).not.toContain("read-only-output-must-not-leak");
    expect(mockDdbSend).toHaveBeenCalledTimes(1);
    expect(mockS3Send).toHaveBeenCalledTimes(1);
    expect(mockS3Send.mock.calls[0]![0].input.Key).toBe(
      `v1/audit/sha256/${auditEvidence.digest.slice(7)}.json`
    );
  });

  test("fails closed on malformed capability ids before AWS", async () => {
    const result = await handler(statusEvent("not-an-audit-id"));

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body)).toEqual({ error: "invalid_audit_id" });
    expect(mockSfnSend).not.toHaveBeenCalled();
    expect(mockDdbSend).not.toHaveBeenCalled();
  });
});
