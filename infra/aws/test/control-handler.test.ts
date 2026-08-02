export {};

const mockDdbSend = jest.fn();
const mockS3Send = jest.fn();
const mockSfnSend = jest.fn();
const { createHash } = require("node:crypto") as typeof import("node:crypto");
const { readFileSync } = require("node:fs") as typeof import("node:fs");
const { resolve } = require("node:path") as typeof import("node:path");

const modelProvenanceCorpus = JSON.parse(
  readFileSync(
    resolve(
      __dirname,
      "../../../contracts/model-provenance-v1.cases.json"
    ),
    "utf8"
  )
) as {
  schemaVersion: string;
  credentialMacros: Record<string, string[]>;
  cases: Array<{
    id: string;
    valid: boolean;
    value: Record<string, unknown>;
  }>;
};

function materializeCredentialMacros(
  value: Record<string, unknown>
): Record<string, unknown> {
  let encoded = JSON.stringify(value);
  for (const [name, fragments] of Object.entries(
    modelProvenanceCorpus.credentialMacros
  )) {
    encoded = encoded.replaceAll(
      `{{credential:${name}}}`,
      fragments.join("")
    );
  }
  return JSON.parse(encoded) as Record<string, unknown>;
}

jest.mock(
  "@aws-sdk/client-dynamodb",
  () => ({
    DynamoDBClient: class {
      send = mockDdbSend;
    },
    GetItemCommand: class {
      readonly kind = "GetItemCommand";
      constructor(readonly input: Record<string, unknown>) {}
    },
    PutItemCommand: class {
      readonly kind = "PutItemCommand";
      constructor(readonly input: Record<string, unknown>) {}
    },
    UpdateItemCommand: class {
      readonly kind = "UpdateItemCommand";
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
process.env.ARCHON_DEMO_QUERY = "domain:Commerce";
process.env.RUNTIME_SESSION_TABLE = "runtime-session-table";
process.env.CORE_LEASE_TABLE = "core-lease-table";
process.env.CORE_SESSION_STATE_MACHINE_ARN =
  "arn:aws:states:eu-west-1:111111111111:stateMachine:archon-core-session";
process.env.RUNTIME_OPERATOR_GROUP = "archon-approvers";

const { handler } = require("../lambda/control/index.js") as {
  handler: (event: Record<string, any>) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    payload: Record<string, any>;
  }>;
};

function startEvent(body: unknown): Record<string, unknown> {
  return {
    operation: "start",
    requestId: "request-123",
    body
  };
}

function statusEvent(auditId: string): Record<string, unknown> {
  return {
    operation: "status",
    requestId: "request-456",
    auditId
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

function fixtureModelProvenance() {
  return {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "deterministic-fixture",
    modelCall: false,
    provider: "fixture",
    requestedModel: "archon-deterministic-fixture-narrator-v1",
    returnedModel: null,
    providerResponseId: null,
    tokenUsage: null,
    latencyMs: null
  };
}

function liveModelProvenance() {
  return {
    schemaVersion: "archon.model-runtime-provenance/v1",
    source: "live-provider",
    modelCall: true,
    provider: "qwen",
    requestedModel: "qwen-plus",
    returnedModel: "qwen-plus-2026-07-01",
    providerResponseId: "chatcmpl-safe-live-001",
    tokenUsage: {
      inputTokens: 40,
      outputTokens: 12,
      totalTokens: 52
    },
    latencyMs: 137
  };
}

function readOnlyFixture(
  auditId: string,
  modelProvenance: Record<string, unknown>,
  includeCurrentSchema = true,
  scanId = "scan-read-only-contract"
) {
  const executionArn =
    `arn:aws:states:eu-west-1:111111111111:execution:` +
    `archon-staging-control-loop:${auditId}`;
  const report = {
    ...(includeCurrentSchema
      ? { schemaVersion: "archon.audit-report/v1" }
      : {}),
    scanId,
    classification: {
      totalEntities: 1,
      withLineage: 0,
      sensitiveEntities: 0,
      domains: {},
      platforms: { snowflake: 1 }
    },
    findings: [],
    narrative: "No findings.",
    ...(includeCurrentSchema ? { modelProvenance } : {}),
    trace: []
  };
  const reportDigest = digest(report);
  const auditEvidence = signed({
    schemaVersion: "archon.audit-evidence/v1",
    executionId: executionArn,
    request: {
      schemaVersion: "archon.audit-request/v1",
      requestId: auditId,
      requestedAt: "2026-07-23T12:00:00.000Z",
      mode: "READ_ONLY"
    },
    releaseSha: "release-read-only-contract",
    report,
    reportDigest,
    remediation: {
      disposition: "MANUAL_ONLY",
      reason: "READ_ONLY_REQUEST"
    },
    createdAt: "2026-07-23T12:00:01.000Z"
  });
  return { auditEvidence, executionArn, report, reportDigest };
}

function mockReadOnlyStatus(
  fixture: ReturnType<typeof readOnlyFixture>,
  checkpointSchema:
    | "archon.audit-result/v1"
    | "archon.audit-result/v2" = "archon.audit-result/v2"
): void {
  mockSfnSend.mockResolvedValue({
    status: "SUCCEEDED",
    startDate: new Date("2026-07-23T12:00:00.000Z"),
    stopDate: new Date("2026-07-23T12:00:02.000Z")
  });
  mockDdbSend.mockResolvedValue({
    Item: {
      output: {
        S: JSON.stringify({
          schemaVersion: checkpointSchema,
          requiresApproval: false,
          reportDigest: fixture.reportDigest,
          evidenceDigest: fixture.auditEvidence.digest,
          manualOnlyReason: "READ_ONLY_REQUEST"
        })
      }
    }
  });
  mockS3Send.mockResolvedValue({
    Body: {
      transformToByteArray: async () =>
        Buffer.from(JSON.stringify(fixture.auditEvidence), "utf8")
    }
  });
}

function terminalFixture(
  auditId: string,
  decisionValue: "APPROVE" | "REJECT" = "APPROVE",
  modelProvenance: Record<string, unknown> = fixtureModelProvenance()
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
    provenance: [
      {
        sourceKind: "current_view",
        entityUrn: "urn:li:dataset:private-customer",
        aspect: "schemaMetadata",
        observedAt: "2026-07-23T12:00:05.000Z",
        valueDigest: `sha256:${"8".repeat(64)}`
      }
    ],
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
    schemaVersion: "archon.audit-report/v1",
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
        detail: {
          ruleId: "G6",
          unclassifiedFields: ["email"],
          blastRadius: {
            rootUrn: "urn:li:dataset:private-customer",
            downstream: [],
            maxHops: 3,
            truncated: false,
            impact: "none"
          },
          provenance: [
            {
              source: "pipeline:snowflake",
              runId: "run-20260725",
              observedAt: "2026-07-25T10:00:00.000Z",
              actor: "private-provenance-actor",
              value: "private-provenance-value",
              status: "trusted"
            }
          ],
          rawResponse: {
            providerDebug: "private-detail-must-not-enter-public-report"
          }
        }
      }
    ],
    narrative: "One exact G6 finding.",
    modelProvenance,
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
    approvalRequestDigest: approvalRequest.digest,
    approvalRequestedAt: approvalRequest.requestedAt,
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

function currentActionableCheckpoint(
  fixture: ReturnType<typeof terminalFixture>
): Record<string, unknown> {
  return {
    schemaVersion: "archon.audit-result/v2",
    requiresApproval: true,
    reportDigest: fixture.reportDigest,
    evidenceDigest: fixture.auditEvidence.digest,
    approvalId: fixture.approvalId,
    planDigest: fixture.planDigest,
    approvalRequestDigest: fixture.approvalRequestDigest,
    approvalRequestedAt: fixture.approvalRequestedAt,
    approvalExpiresAt: fixture.approvalExpiresAt
  };
}

const runtimeIdentity = {
  subject: "2f6dcb5a-9f76-4f65-960d-f2637d65b9cb",
  issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST",
  groups: "[archon-approvers]"
};

function runtimeSessionItem(sessionId: string) {
  const boundAtMs = Date.now() - 60_000;
  const boundAt = new Date(boundAtMs).toISOString();
  const hardExpiresAt = new Date(boundAtMs + 2 * 60 * 60_000).toISOString();
  const session = {
    schemaVersion: "archon.runtime-session/v1",
    sessionId,
    requestedProfile: "cloud",
    binding: {
      schemaVersion: "archon.runtime-binding/v1",
      profileId: "cloud",
      generation: "cloud-2026-08-02",
      capabilityDigest: "sha256:" + "8".repeat(64),
      resolution: "explicit",
      boundAt,
      leaseExpiresAt: hardExpiresAt
    },
    state: "ACTIVE",
    createdAt: boundAt,
    updatedAt: boundAt,
    lastActivityAt: boundAt,
    idleExpiresAt: new Date(Date.now() + 20 * 60_000).toISOString(),
    hardExpiresAt,
    revision: 4,
    endReason: null,
    failureCode: null
  };
  return {
    session,
    item: {
      payload: { S: JSON.stringify(session) },
      revision: { N: "4" },
      principalHash: {
        S: digest({
          issuer: runtimeIdentity.issuer,
          subject: runtimeIdentity.subject
        })
      }
    }
  };
}
describe("async audit control Lambda", () => {
  beforeEach(() => {
    mockDdbSend.mockReset();
    mockS3Send.mockReset();
    mockSfnSend.mockReset();
  });

  test("starts v2 only from an owned active runtime and seals binding evidence", async () => {
    const sessionId = "rs_" + "V".repeat(43);
    const runtime = runtimeSessionItem(sessionId);
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        expect(command.input.Key).toEqual({
          pk: { S: "SESSION#" + sessionId },
          sk: { S: "RUNTIME" }
        });
        return { Item: runtime.item };
      }
      if (
        command.kind === "UpdateItemCommand" ||
        command.kind === "PutItemCommand"
      ) {
        return {};
      }
      throw new Error("unexpected DDB command");
    });
    mockSfnSend.mockResolvedValue({
      executionArn:
        "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:v2"
    });

    const result = await handler({
      operation: "startV2",
      requestId: "request-v2-123",
      body: {
        query: "domain:Commerce",
        mode: "READ_ONLY",
        sessionId
      },
      identity: runtimeIdentity
    });

    expect(result.statusCode).toBe(202);
    expect(result.payload).toMatchObject({
      schemaVersion: "archon.control-loop-start/v2",
      status: "RUNNING",
      pollUrl: expect.stringMatching(/^\/api\/control-loops-v2\/[a-f0-9]{64}$/),
      runtimeEvidence: {
        schemaVersion: "archon.runtime-binding-evidence/v1",
        runtimeSessionId: sessionId,
        profileId: "cloud",
        generation: "cloud-2026-08-02",
        capabilityDigest: runtime.session.binding.capabilityDigest,
        bindingDigest: digest(runtime.session.binding),
        sessionRevision: 5,
        digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/)
      }
    });
    const update = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "UpdateItemCommand") as any;
    expect(update.input.ConditionExpression).toBe("revision = :expected");
    expect(update.input.ExpressionAttributeValues[":expected"]).toEqual({
      N: "4"
    });
    const sealed = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "PutItemCommand") as any;
    const evidence = JSON.parse(sealed.input.Item.payload.S);
    expect(evidence.digest).toBe(digest(without(evidence, ["digest"])));
    const execution = mockSfnSend.mock.calls[0]![0] as any;
    expect(JSON.parse(execution.input.input)).toEqual({
      schemaVersion: "archon.audit-request/v1",
      requestId: result.payload.auditId,
      requestedAt: result.payload.submittedAt,
      mode: "READ_ONLY",
      query: "domain:Commerce"
    });
    expect(JSON.stringify(execution.input.input)).not.toContain("binding");
    expect(JSON.stringify(result.payload)).not.toContain("principalHash");
  });

  test("rejects client-provided v2 binding and missing identity before execution", async () => {
    const sessionId = "rs_" + "W".repeat(43);
    const injected = await handler({
      operation: "startV2",
      requestId: "request-v2-unsafe",
      body: {
        query: "domain:Commerce",
        sessionId,
        binding: { profileId: "core" }
      },
      identity: runtimeIdentity
    });
    const anonymous = await handler({
      operation: "startV2",
      requestId: "request-v2-anonymous",
      body: { query: "domain:Commerce", sessionId }
    });

    expect(injected.statusCode).toBe(400);
    expect(injected.payload).toEqual({
      error: "invalid_runtime_control_request"
    });
    expect(anonymous.statusCode).toBe(404);
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("starts a strict Standard execution and returns only an opaque polling capability", async () => {
    mockSfnSend.mockResolvedValue({
      executionArn:
        "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:ignored"
    });

    const result = await handler(startEvent({ query: "domain:Commerce" }));
    const body = result.payload;

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
    const embeddedWildcard = await handler(
      startEvent({ query: "domain:Commerce*" })
    );
    const singleCharacterWildcard = await handler(
      startEvent({ query: "domain:Commerc?" })
    );
    const emptyObject = await handler(startEvent({ query: "{}" }));
    const padded = await handler(
      startEvent({ query: " domain:Commerce " })
    );
    const outsideDemo = await handler(
      startEvent({ query: "domain:AnotherDataset" })
    );

    expect(unexpected.statusCode).toBe(400);
    expect(unexpected.payload).toEqual({ error: "unexpected_field" });
    expect(tooLong.statusCode).toBe(400);
    expect(missing.payload).toEqual({ error: "query_required" });
    expect(wildcard.payload).toEqual({
      error: "query_must_be_narrow"
    });
    expect(embeddedWildcard.payload).toEqual({
      error: "query_must_be_narrow"
    });
    expect(singleCharacterWildcard.payload).toEqual({
      error: "query_must_be_narrow"
    });
    expect(emptyObject.payload).toEqual({
      error: "query_must_be_narrow"
    });
    expect(padded.payload).toEqual({
      error: "query_must_be_trimmed"
    });
    expect(outsideDemo.payload).toEqual({
      error: "query_outside_demo_scope"
    });
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("rejects any gateway event that carries raw request headers", async () => {
    const unsafeEvent = {
      ...startEvent({ query: "domain:Commerce" }),
      headers: {
        "x-api-key": "must-never-reach-the-lambda",
        authorization: "must-never-reach-the-lambda"
      }
    };
    const result = await handler(unsafeEvent);

    expect(result.statusCode).toBe(404);
    expect(result.payload).toEqual({ error: "not_found" });
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
    const body = result.payload;

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
    const fixture = terminalFixture(
      auditId,
      "APPROVE",
      liveModelProvenance()
    );
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
              S: JSON.stringify(currentActionableCheckpoint(fixture))
            }
          }
        };
      }
      return {
        Item: {
          status: { S: "PENDING" },
          evidenceDigest: { S: fixture.auditEvidence.digest },
          planDigest: { S: fixture.planDigest },
          taskToken: { S: "opaque-task-token-must-never-leak" },
          approvalExpiresAt: { S: fixture.approvalExpiresAt },
          expiresAt: {
            N: String(Math.floor(Date.parse(fixture.approvalExpiresAt) / 1000))
          }
        }
      };
    });
    mockS3Send.mockResolvedValue({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(JSON.stringify(fixture.auditEvidence), "utf8")
      }
    });

    const result = await handler(statusEvent(auditId));
    const body = result.payload;

    expect(result.statusCode).toBe(200);
    expect(body.status).toBe("AWAITING_APPROVAL");
    expect(body.releaseSha).toBe("release-live-terminal");
    expect(body.report.modelProvenance).toEqual(liveModelProvenance());
    expect(body.report.findings[0].detail.dossier).toEqual({
      dossierId: fixture.auditEvidence.remediation.dossier.dossierId,
      digest: fixture.auditEvidence.remediation.dossier.digest,
      policyDigest: fixture.auditEvidence.remediation.dossier.policyDigest,
      generatedAt: fixture.auditEvidence.remediation.dossier.createdAt,
      evidenceCount: 3
    });
    expect(body.report.findings[0].detail.approval).toEqual({
      approvalId: fixture.approvalId,
      expiresAt: fixture.approvalExpiresAt,
      targetField: "email",
      proposedTag: "urn:li:tag:PII",
      before: [],
      after: ["urn:li:tag:PII"],
      planDigest: fixture.planDigest,
      risk: "low"
    });
    expect(body.report.findings[0].detail.provenance).toEqual([
      {
        source: "current_view:schemaMetadata",
        runId: `sha256:${"8".repeat(64)}`,
        observedAt: "2026-07-23T12:00:05.000Z",
        status: "trusted"
      }
    ]);
    expect(JSON.stringify(body)).not.toContain("opaque-task-token");
    expect(JSON.stringify(body)).not.toContain(fixture.executionArn);
    expect(JSON.stringify(body)).not.toContain(
      "private-detail-must-not-enter-public-report"
    );
    expect(JSON.stringify(body)).not.toContain("rawResponse");
    expect(JSON.stringify(body)).not.toContain("private-provenance-actor");
    expect(JSON.stringify(body)).not.toContain("private-provenance-value");
  });

  test("rejects a v2 actionable checkpoint stripped of immutable approval-request bindings", async () => {
    const auditId = "8".repeat(64);
    const fixture = terminalFixture(auditId);
    const checkpoint = without(currentActionableCheckpoint(fixture), [
      "approvalRequestDigest",
      "approvalRequestedAt",
      "approvalExpiresAt"
    ]);
    mockSfnSend.mockResolvedValue({
      status: "RUNNING",
      startDate: new Date("2026-07-23T12:00:00.000Z")
    });
    mockDdbSend.mockResolvedValue({
      Item: { output: { S: JSON.stringify(checkpoint) } }
    });

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(502);
    expect(result.payload).toEqual({ error: "control_plane_unavailable" });
    expect(mockS3Send).not.toHaveBeenCalled();
  });

  const partialApprovalBindingCases: Array<
    [label: string, retainedKeys: string[]]
  > = [
    ["digest only", ["approvalRequestDigest"]],
    ["timestamps only", ["approvalRequestedAt", "approvalExpiresAt"]]
  ];

  test.each(partialApprovalBindingCases)(
    "rejects a v2 actionable checkpoint with partial approval-request bindings: %s",
    async (_label, retainedKeys) => {
      const auditId = "9".repeat(64);
      const fixture = terminalFixture(auditId);
      const complete = currentActionableCheckpoint(fixture);
      const checkpoint = {
        ...without(complete, [
          "approvalRequestDigest",
          "approvalRequestedAt",
          "approvalExpiresAt"
        ]),
        ...Object.fromEntries(
          retainedKeys.map((key) => [key, complete[key]])
        )
      };
      mockSfnSend.mockResolvedValue({
        status: "RUNNING",
        startDate: new Date("2026-07-23T12:00:00.000Z")
      });
      mockDdbSend.mockResolvedValue({
        Item: { output: { S: JSON.stringify(checkpoint) } }
      });

      const result = await handler(statusEvent(auditId));

      expect(result.statusCode).toBe(502);
      expect(result.payload).toEqual({ error: "control_plane_unavailable" });
      expect(mockS3Send).not.toHaveBeenCalled();
    }
  );

  test.each(["2026-07-23", "2026-07-23T12:00:05"])(
    "rejects a v2 actionable checkpoint with a non-RFC3339 request instant: %s",
    async (approvalRequestedAt) => {
      const auditId = "0".repeat(64);
      const fixture = terminalFixture(auditId);
      const checkpoint = {
        ...currentActionableCheckpoint(fixture),
        approvalRequestedAt
      };
      mockSfnSend.mockResolvedValue({
        status: "RUNNING",
        startDate: new Date("2026-07-23T12:00:00.000Z")
      });
      mockDdbSend.mockResolvedValue({
        Item: { output: { S: JSON.stringify(checkpoint) } }
      });

      const result = await handler(statusEvent(auditId));

      expect(result.statusCode).toBe(502);
      expect(result.payload).toEqual({ error: "control_plane_unavailable" });
      expect(mockS3Send).not.toHaveBeenCalled();
    }
  );

  test("retains v1 actionable cutover support when historical request bindings are absent", async () => {
    const auditId = "a".repeat(64);
    const fixture = terminalFixture(auditId);
    const evidence: any = JSON.parse(JSON.stringify(fixture.auditEvidence));
    delete evidence.report.schemaVersion;
    delete evidence.report.modelProvenance;
    evidence.reportDigest = digest(evidence.report);
    delete evidence.digest;
    evidence.digest = digest(evidence);
    const checkpoint = without(
      {
        ...currentActionableCheckpoint(fixture),
        schemaVersion: "archon.audit-result/v1",
        reportDigest: evidence.reportDigest,
        evidenceDigest: evidence.digest
      },
      [
        "approvalRequestDigest",
        "approvalRequestedAt",
        "approvalExpiresAt"
      ]
    );
    mockSfnSend.mockResolvedValue({
      status: "RUNNING",
      startDate: new Date("2026-07-23T12:00:00.000Z")
    });
    mockDdbSend.mockResolvedValue({
      Item: { output: { S: JSON.stringify(checkpoint) } }
    });
    mockS3Send.mockResolvedValue({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(JSON.stringify(evidence), "utf8")
      }
    });

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(410);
    expect(result.payload).toEqual({
      error: "audit_schema_retired",
      rerunRequired: true
    });
  });

  test("rejects outer-digest-valid evidence with a tampered nested remediation plan", async () => {
    const auditId = "b".repeat(64);
    const fixture = terminalFixture(auditId);
    const evidence: any = JSON.parse(JSON.stringify(fixture.auditEvidence));
    evidence.remediation.plan.action.arguments.tag_urns.push(
      "urn:li:tag:UNTRUSTED_SECOND_TAG"
    );
    delete evidence.digest;
    evidence.digest = digest(evidence);
    const checkpoint = {
      ...currentActionableCheckpoint(fixture),
      evidenceDigest: evidence.digest
    };
    mockSfnSend.mockResolvedValue({
      status: "RUNNING",
      startDate: new Date("2026-07-23T12:00:00.000Z")
    });
    mockDdbSend.mockResolvedValue({
      Item: { output: { S: JSON.stringify(checkpoint) } }
    });
    mockS3Send.mockResolvedValue({
      Body: {
        transformToByteArray: async () =>
          Buffer.from(JSON.stringify(evidence), "utf8")
      }
    });

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(502);
    expect(result.payload).toEqual({ error: "control_plane_unavailable" });
    expect(JSON.stringify(result.payload)).not.toContain(
      "UNTRUSTED_SECOND_TAG"
    );
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
              S: JSON.stringify(currentActionableCheckpoint(fixture))
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
    const body = result.payload;

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
    expect(body.report.modelProvenance).toEqual(fixtureModelProvenance());
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
              S: JSON.stringify(currentActionableCheckpoint(fixture))
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
    expect(result.payload).toEqual({
      error: "control_plane_unavailable"
    });
    expect(JSON.stringify(result.payload)).not.toContain("EVENT_4");
    expect(JSON.stringify(result.payload)).not.toContain("eventHash");
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
              S: JSON.stringify(currentActionableCheckpoint(fixture))
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
    const body = result.payload;

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
      schemaVersion: "archon.audit-report/v1",
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
      modelProvenance: fixtureModelProvenance(),
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
            schemaVersion: "archon.audit-result/v2",
            requiresApproval: false,
            reportDigest,
            evidenceDigest: auditEvidence.digest,
            manualOnlyReason: "READ_ONLY_REQUEST"
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
    const body = result.payload;

    expect(result.statusCode).toBe(200);
    expect(body.result).toEqual({ outcome: "READ_ONLY_COMPLETE" });
    expect(body.report.modelProvenance).toEqual(fixtureModelProvenance());
    expect(JSON.stringify(body)).not.toContain("read-only-output-must-not-leak");
    expect(mockDdbSend).toHaveBeenCalledTimes(1);
    expect(mockS3Send).toHaveBeenCalledTimes(1);
    expect(mockS3Send.mock.calls[0]![0].input.Key).toBe(
      `v1/audit/sha256/${auditEvidence.digest.slice(7)}.json`
    );
  });

  test("accepts live provenance with explicitly unavailable token usage", async () => {
    const auditId = "2".repeat(64);
    const fixture = readOnlyFixture(auditId, {
      ...liveModelProvenance(),
      tokenUsage: null
    });
    mockReadOnlyStatus(fixture);

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(200);
    expect(result.payload.report.modelProvenance).toEqual({
      ...liveModelProvenance(),
      tokenUsage: null
    });
  });

  test("keeps the control projection conformant with the shared provenance corpus", async () => {
    expect(modelProvenanceCorpus.schemaVersion).toBe(
      "archon.model-provenance-conformance/v1"
    );
    for (const [index, candidate] of modelProvenanceCorpus.cases.entries()) {
      const auditId = index.toString(16).padStart(64, "0");
      const provenance = materializeCredentialMacros(candidate.value);
      const fixture = readOnlyFixture(auditId, provenance);
      mockReadOnlyStatus(fixture);

      const result = await handler(statusEvent(auditId));

      expect(result.statusCode).toBe(candidate.valid ? 200 : 502);
      if (candidate.valid) {
        expect(result.payload.report.modelProvenance).toEqual(provenance);
      } else {
        expect(result.payload).toEqual({
          error: "control_plane_unavailable"
        });
      }
    }
  });

  const invalidModelProvenanceCases: Array<
    [label: string, provenance: Record<string, unknown>]
  > = [
    [
      "missing required field",
      without(fixtureModelProvenance(), ["latencyMs"])
    ],
    [
      "unexpected private field",
      { ...fixtureModelProvenance(), prompt: "must-not-be-retained" }
    ],
    [
      "fixture/live discriminant confusion",
      {
        ...fixtureModelProvenance(),
        source: "live-provider",
        modelCall: true,
        provider: "qwen"
      }
    ],
    [
      "credential embedded in returned model",
      {
        ...liveModelProvenance(),
        returnedModel: `model_sk-${"x".repeat(32)}`
      }
    ],
    [
      "credential embedded in provider response id",
      {
        ...liveModelProvenance(),
        providerResponseId: `resp_sk-${"x".repeat(32)}`
      }
    ],
    [
      "inconsistent token usage",
      {
        ...liveModelProvenance(),
        tokenUsage: {
          inputTokens: 40,
          outputTokens: 12,
          totalTokens: 999
        }
      }
    ],
    [
      "excessive latency",
      { ...liveModelProvenance(), latencyMs: 3_600_001 }
    ]
  ];

  test.each(invalidModelProvenanceCases)(
    "fails closed on %s in model provenance",
    async (_label, provenance) => {
      const auditId = "3".repeat(64);
      const fixture = readOnlyFixture(auditId, provenance);
      mockReadOnlyStatus(fixture);

      const result = await handler(statusEvent(auditId));

      expect(result.statusCode).toBe(502);
      expect(result.payload).toEqual({ error: "control_plane_unavailable" });
      expect(JSON.stringify(result.payload)).not.toContain("must-not-be-retained");
      expect(JSON.stringify(result.payload)).not.toContain("sk-");
    }
  );

  test("returns an explicit rerun-required cutover for a digest-valid v1 five-key report", async () => {
    const auditId = "4".repeat(64);
    const fixture = readOnlyFixture(
      auditId,
      fixtureModelProvenance(),
      false
    );
    mockReadOnlyStatus(fixture, "archon.audit-result/v1");

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(410);
    expect(result.payload).toEqual({
      error: "audit_schema_retired",
      rerunRequired: true
    });
    expect(JSON.stringify(result.payload)).not.toContain("scan-read-only-contract");
  });

  test("recognizes a historically valid v1 five-key report with an empty scan id", async () => {
    const auditId = "5".repeat(64);
    const fixture = readOnlyFixture(
      auditId,
      fixtureModelProvenance(),
      false,
      ""
    );
    mockReadOnlyStatus(fixture, "archon.audit-result/v1");

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(410);
    expect(result.payload).toEqual({
      error: "audit_schema_retired",
      rerunRequired: true
    });
  });

  test("fails closed when v1 legacy evidence is tampered after signing", async () => {
    const auditId = "6".repeat(64);
    const fixture = readOnlyFixture(
      auditId,
      fixtureModelProvenance(),
      false
    );
    mockReadOnlyStatus(fixture, "archon.audit-result/v1");
    fixture.auditEvidence.executionId =
      "arn:aws:states:eu-west-1:111111111111:execution:" +
      "archon-staging-control-loop:tampered-legacy-binding";

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(502);
    expect(result.payload).toEqual({ error: "control_plane_unavailable" });
  });

  test("does not misclassify a re-signed stripped v2 report as retired evidence", async () => {
    const auditId = "7".repeat(64);
    const fixture = readOnlyFixture(
      auditId,
      fixtureModelProvenance()
    );
    delete fixture.report.schemaVersion;
    delete fixture.report.modelProvenance;
    fixture.reportDigest = digest(fixture.report);
    fixture.auditEvidence.reportDigest = fixture.reportDigest;
    const { digest: _oldDigest, ...unsignedEvidence } = fixture.auditEvidence;
    fixture.auditEvidence.digest = digest(unsignedEvidence);
    mockReadOnlyStatus(fixture);

    const result = await handler(statusEvent(auditId));

    expect(result.statusCode).toBe(502);
    expect(result.payload).toEqual({ error: "control_plane_unavailable" });
  });

  test("fails closed on malformed capability ids before AWS", async () => {
    const result = await handler(statusEvent("not-an-audit-id"));

    expect(result.statusCode).toBe(400);
    expect(result.payload).toEqual({ error: "invalid_audit_id" });
    expect(mockSfnSend).not.toHaveBeenCalled();
    expect(mockDdbSend).not.toHaveBeenCalled();
  });
});
