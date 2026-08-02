export {};

const mockDdbSend = jest.fn();
const mockS3Send = jest.fn();
const mockSfnSend = jest.fn();
const mockKmsSend = jest.fn();
const { createHash, createPublicKey, verify } = require("node:crypto") as typeof import("node:crypto");
const { readFileSync } = require("node:fs") as typeof import("node:fs");
const { resolve } = require("node:path") as typeof import("node:path");

const mutationAuthorizationGolden = JSON.parse(
  readFileSync(
    resolve(
      __dirname,
      "../../../contracts/datahub-core-mutation-authorization-golden.json"
    ),
    "utf8"
  )
) as {
  schemaVersion: "archon.core-mutation-authorization-golden/v1";
  canonicalization: "archon.sorted-json-utf8/v1";
  envelope: Record<string, unknown>;
  canonicalJson: string;
  envelopeDigest: string;
  keySpec: "ECC_NIST_P256";
  algorithm: "ECDSA_SHA_256";
  publicKeyDerBase64: string;
  signatureBase64: string;
};

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
    },
    TransactWriteItemsCommand: class {
      readonly kind = "TransactWriteItemsCommand";
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
jest.mock(
  "@aws-sdk/client-kms",
  () => ({
    KMSClient: class {
      send = mockKmsSend;
    },
    SignCommand: class {
      readonly kind = "SignCommand";
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
process.env.RUNTIME_JOB_TABLE = "runtime-job-table";
process.env.CORE_SESSION_STATE_MACHINE_ARN =
  "arn:aws:states:eu-west-1:111111111111:stateMachine:archon-core-session";
process.env.RUNTIME_OPERATOR_GROUP = "archon-runtime-operators";
process.env.RUNTIME_APPROVER_GROUP = "archon-approvers";
process.env.EXPECTED_COGNITO_ISSUER =
  "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST";
process.env.ARCHON_STAGE = "staging";
process.env.MUTATION_SIGNING_KEY_ARN =
  "arn:aws:kms:eu-west-1:111111111111:key/00000000-1111-2222-3333-444444444444";
process.env.MUTATION_SIGNING_ALGORITHM = "ECDSA_SHA_256";
process.env.ARCHON_AGENT_STACK_DATASET_URN =
  "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)";
process.env.ARCHON_ANALYTICS_QUESTION =
  "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?";
process.env.ARCHON_GOVERNED_COLUMN_PATH = "customer_email";

const { handler } = require("../lambda/control/index.js") as {
  handler: (event: Record<string, any>) => Promise<{
    statusCode: number;
    headers: Record<string, string>;
    payload: Record<string, any>;
  }>;
};
const { handler: remediationHandler } = require(
  "../lambda/control/remediation.js"
) as {
  handler: (event: Record<string, any>) => Promise<{
    batchItemFailures: Array<Record<string, unknown>>;
  }>;
};
const { _test: runtimeV2Test } = require(
  "../lambda/control/runtime-v2.js"
) as {
  _test: {
    canonicalMutationEnvelope: (value: unknown) => string;
    mutationEnvelopeDigest: (value: unknown) => string;
    enrichSkillCompletion: (
      analysisReceipt: Record<string, any>,
      approvalEnvelope: Record<string, any>,
      mutationReceipt: Record<string, any>
    ) => Record<string, any>;
  };
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

const ACK_SKILL_TOOLS = [
  "search",
  "get_entities",
  "list_schema_fields",
  "get_lineage_upstream",
  "get_lineage_downstream",
  "get_dataset_assertions"
] as const;
const OFFICIAL_MCP_SKILL_TOOLS = [
  "search",
  "get_entities",
  "list_schema_fields",
  "get_lineage",
  "get_dataset_queries"
] as const;
const SKILL_WORKFLOW = [
  "datahub-search",
  "datahub-lineage",
  "datahub-quality",
  "datahub-audit",
  "datahub-enrich"
] as const;

function dataHubSkillEvidence(contextDigest: string) {
  const plans: Record<string, Record<string, unknown>> = {
    "datahub-search": {
      phase: "metadata-discovery",
      requiredCalls: {
        ack: ACK_SKILL_TOOLS.slice(0, 3),
        officialMcp: OFFICIAL_MCP_SKILL_TOOLS.slice(0, 3)
      },
      mode: "read-only"
    },
    "datahub-lineage": {
      phase: "impact-analysis",
      requiredCalls: {
        ack: ["get_lineage_upstream", "get_lineage_downstream"],
        officialMcp: ["get_lineage"]
      },
      mode: "read-only"
    },
    "datahub-quality": {
      phase: "quality-evidence",
      requiredCalls: {
        ack: ["get_dataset_assertions"],
        officialMcp: ["get_dataset_queries"]
      },
      mode: "read-only"
    },
    "datahub-audit": {
      phase: "governance-audit",
      requiredCalls: {
        ack: [...ACK_SKILL_TOOLS],
        officialMcp: [...OFFICIAL_MCP_SKILL_TOOLS]
      },
      mode: "read-only"
    },
    "datahub-enrich": {
      phase: "governed-enrichment-preview",
      requiredCalls: {
        ack: [...ACK_SKILL_TOOLS],
        officialMcp: [...OFFICIAL_MCP_SKILL_TOOLS]
      },
      mode: "preview-only"
    },
    "using-datahub": {
      phase: "datahub-operation-policy",
      requiredCalls: {
        ack: [...ACK_SKILL_TOOLS],
        officialMcp: [...OFFICIAL_MCP_SKILL_TOOLS]
      },
      mode: "read-only"
    }
  };
  const artifactFor = (skill: string) => {
    const artifactDigest = digest({ skill, artifact: "locked-SKILL.md" });
    const executionPlan = plans[skill];
    return {
      skill,
      artifactDigest,
      gitBlob: createHash("sha1").update(skill, "utf8").digest("hex"),
      bytes: 1024 + skill.length,
      reviewedExecution: {
        executionPlan,
        executionPlanDigest: digest({ sourceArtifactDigest: artifactDigest, executionPlan })
      }
    };
  };
  const official = [
    "datahub-search",
    "datahub-lineage",
    "datahub-quality",
    "datahub-enrich",
    "using-datahub"
  ].map(artifactFor);
  const custom = ["datahub-audit"].map(artifactFor);
  const skills = signed({
    schemaVersion: "archon.datahub-skills-receipt/v2",
    sourceCommit: "f7c7c53648b71dc0841742781e108051d46fa360",
    official,
    custom,
    workflow: [...SKILL_WORKFLOW],
    reviewedSkillCount: 6,
    mutationAuthority: "archon-remediation-worker"
  });
  const ackDigests = Object.fromEntries(
    ACK_SKILL_TOOLS.map((tool) => [tool, digest({ source: "ack", tool })])
  );
  const officialMcpDigests = Object.fromEntries(
    OFFICIAL_MCP_SKILL_TOOLS.map((tool) => [
      tool,
      digest({ source: "official-mcp", tool })
    ])
  );
  const artifacts = [...official, ...custom];
  const receiptFor = (artifact: ReturnType<typeof artifactFor>) => {
    const executionPlan = artifact.reviewedExecution.executionPlan as {
      requiredCalls: { ack: string[]; officialMcp: string[] };
      mode: string;
    };
    const satisfiedAckCalls = executionPlan.requiredCalls.ack.map((tool) => ({
      tool,
      receiptDigest: ackDigests[tool]
    }));
    const satisfiedOfficialMcpCalls =
      executionPlan.requiredCalls.officialMcp.map((tool) => ({
        tool,
        receiptDigest: officialMcpDigests[tool]
      }));
    return signed({
      schemaVersion: "archon.datahub-skill-execution-receipt/v2",
      skill: artifact.skill,
      sourceArtifactDigest: artifact.artifactDigest,
      executionPlan: artifact.reviewedExecution.executionPlan,
      executionPlanDigest: artifact.reviewedExecution.executionPlanDigest,
      status: artifact.skill === "datahub-enrich" ? "previewed" : "executed",
      satisfiedAckCalls,
      satisfiedOfficialMcpCalls,
      ackReceiptDigests: satisfiedAckCalls.map((call) => call.receiptDigest),
      officialMcpReadReceiptDigests: satisfiedOfficialMcpCalls.map(
        (call) => call.receiptDigest
      ),
      mode: executionPlan.mode,
      requiredCallsSatisfied: true,
      mutationsEnabled: false,
      providerPayloadStored: false
    });
  };
  const receipts = artifacts.map(receiptFor);
  const enrichSkillReceipt = receipts.find(
    (receipt) => receipt.skill === "datahub-enrich"
  )!;
  const skillGrounding = signed({
    schemaVersion: "archon.datahub-skill-grounding/v2",
    skillsReceiptDigest: skills.digest,
    ackContextDigest: contextDigest,
    officialMcpReadReceiptsDigest: digest({
      sequence: [...OFFICIAL_MCP_SKILL_TOOLS],
      receiptDigests: OFFICIAL_MCP_SKILL_TOOLS.map(
        (tool) => officialMcpDigests[tool]
      )
    }),
    executionOrder: [...SKILL_WORKFLOW],
    allRequiredCallsSatisfied: true,
    receipts
  });
  return { skills, skillGrounding, enrichSkillReceipt };
}

function standaloneSkillCompletionFixture() {
  const context = signed({
    schemaVersion: "archon.datahub-context/v2",
    query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
    entityUrns: [process.env.ARCHON_AGENT_STACK_DATASET_URN],
    receipts: [],
    unknownPreserved: false
  });
  const { skills, skillGrounding, enrichSkillReceipt } =
    dataHubSkillEvidence(context.digest);
  const analytics = signed({
    schemaVersion: "archon.analytics-agent-result/v2",
    skillGroundingDigest: skillGrounding.digest
  });
  const result = signed({
    schemaVersion: "archon.datahub-agent-stack-result/v2",
    context,
    skills,
    skillGrounding,
    analytics
  });
  return {
    analysisReceipt: { result },
    approvalEnvelope: {
      decision: { digest: digest({ decision: "APPROVE", plan: "exact" }) }
    },
    mutationReceipt: {
      receiptDigest: digest({ tool: "add_tags", result: "verified" }),
      completedAt: "2026-08-02T08:00:07.000Z"
    },
    enrichSkillReceipt
  };
}

function resealSkillCompletionFixture(
  fixture: ReturnType<typeof standaloneSkillCompletionFixture>
) {
  const result = fixture.analysisReceipt.result as Record<string, any>;
  const grounding = result.skillGrounding as Record<string, any>;
  const receipts = grounding.receipts as Array<Record<string, any>>;
  const enrichIndex = receipts.findIndex(
    (receipt) => receipt.skill === "datahub-enrich"
  );
  const enrich = receipts[enrichIndex];
  if (!enrich) throw new Error("missing datahub-enrich receipt");
  receipts[enrichIndex] = signed(without(enrich, ["digest"]));
  const reboundGrounding = signed(without(grounding, ["digest"]));
  const analytics = result.analytics as Record<string, any>;
  analytics.skillGroundingDigest = reboundGrounding.digest;
  result.analytics = signed(without(analytics, ["digest"]));
  result.skillGrounding = reboundGrounding;
  (fixture.analysisReceipt as { result: Record<string, any> }).result =
    signed(without(result, ["digest"]));
  return fixture;
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

const testKmsSignature = Buffer.from(
  "304402200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200220202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  "hex"
);

const runtimeIdentity = {
  subject: "2f6dcb5a-9f76-4f65-960d-f2637d65b9cb",
  issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST",
  groups: "[archon-runtime-operators,archon-approvers]"
};

const runtimeCapabilities = {
  mcpRead: true,
  mcpGovernedWrite: true,
  agentContextKit: true,
  dataHubSkills: true,
  analyticsAgent: true
};

function runtimeSessionItem(sessionId: string, profileId = "core") {
  const boundAtMs = Date.now() - 60_000;
  const boundAt = new Date(boundAtMs).toISOString();
  const hardExpiresAt = new Date(boundAtMs + 2 * 60 * 60_000).toISOString();
  const generation = profileId + "-2026-08-02";
  const capabilityDigest = digest({
    schemaVersion: "archon.runtime-capabilities/v1",
    profileId,
    generation,
    capabilities: runtimeCapabilities
  });
  const session = {
    schemaVersion: "archon.runtime-session/v1",
    sessionId,
    requestedProfile: profileId,
    binding: {
      schemaVersion: "archon.runtime-binding/v1",
      profileId,
      generation,
      capabilityDigest,
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
    mockKmsSend.mockReset();
    mockKmsSend.mockResolvedValue({
      KeyId: process.env.MUTATION_SIGNING_KEY_ARN,
      SigningAlgorithm: "ECDSA_SHA_256",
      Signature: testKmsSignature
    });
  });

  test("sanitizes and rethrows remediation wrapper failures", async () => {
    const failure = new Error("synthetic remediation stream failure");
    const event = Object.defineProperty({}, "Records", {
      get: () => {
        throw failure;
      }
    }) as Record<string, any>;
    const stderr = jest
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    try {
      await expect(remediationHandler(event)).rejects.toBe(failure);
      expect(stderr).toHaveBeenCalledWith(
        "[runtime-remediation] approval_stream_failed\n"
      );
    } finally {
      stderr.mockRestore();
    }
  });

  test("dispatches profile-bound Core jobs and never starts the legacy audit state machine", async () => {
    const sessionId = "rs_" + "V".repeat(43);
    const runtime = runtimeSessionItem(sessionId);
    mockDdbSend.mockImplementation(async (command: any) => {
      const key = command.input?.Key;
      if (command.kind === "GetItemCommand" && key?.pk?.S === "SESSION#" + sessionId) {
        return { Item: runtime.item };
      }
      if (command.kind === "GetItemCommand" && key?.pk?.S === "RUNTIME#core") {
        return {
          Item: {
            pk: { S: "RUNTIME#core" },
            sk: { S: "HEALTH" },
            status: { S: "READY" },
            sessionId: { S: sessionId },
            generation: { S: runtime.session.binding.generation },
            capabilityDigest: { S: runtime.session.binding.capabilityDigest },
            checkedAt: { S: runtime.session.updatedAt },
            capabilities: {
              M: Object.fromEntries(
                Object.entries(runtimeCapabilities).map(([name, value]) => [
                  name,
                  { BOOL: value }
                ])
              )
            }
          }
        };
      }
      if (command.kind === "GetItemCommand" && key?.pk?.S === "CORE#LEASE") {
        return {
          Item: {
            pk: { S: "CORE#LEASE" },
            sk: { S: "CURRENT" },
            sessionId: { S: sessionId },
            state: { S: "READY" },
            revision: { N: "8" }
          }
        };
      }
      if (["UpdateItemCommand", "TransactWriteItemsCommand"].includes(command.kind)) return {};
      throw new Error("unexpected DDB command " + command.kind);
    });
    mockSfnSend.mockResolvedValue({ executionArn: "core-activity-only" });

    const result = await handler({
      operation: "startV2",
      requestId: "request-v2-123",
      body: {
        query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        question: process.env.ARCHON_ANALYTICS_QUESTION,
        mode: "GOVERNED",
        sessionId
      },
      identity: runtimeIdentity
    });

    expect(result.statusCode).toBe(202);
    expect(result.payload).toMatchObject({
      schemaVersion: "archon.control-loop-start/v2",
      status: "RUNNING",
      phase: "ANALYZING",
      runtimeEvidence: {
        schemaVersion: "archon.runtime-binding-evidence/v2",
        runtimeSessionId: sessionId,
        runtimeBinding: runtime.session.binding,
        capabilities: runtimeCapabilities,
        sessionRevision: 5,
        digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/)
      }
    });
    const transaction = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "TransactWriteItemsCommand") as any;
    expect(transaction.input.TransactItems).toHaveLength(3);
    const jobs = transaction.input.TransactItems
      .map((item: any) => item.Put?.Item)
      .filter((item: any) => item?.schema?.S === "archon.runtime-bound-job/v2");
    expect(jobs.map((item: any) => item.operation.S).sort()).toEqual([
      "ANALYZE",
      "READ_TAGS"
    ]);
    expect(jobs.every((item: any) => item.pk.S === "SESSION#" + sessionId)).toBe(true);
    expect(jobs.every((item: any) => item.profileId.S === "core")).toBe(true);
    expect(mockSfnSend).toHaveBeenCalledTimes(1);
    expect((mockSfnSend.mock.calls[0]![0] as any).input.stateMachineArn).toBe(
      process.env.CORE_SESSION_STATE_MACHINE_ARN
    );
    expect(JSON.stringify(mockSfnSend.mock.calls)).not.toContain(
      process.env.STATE_MACHINE_ARN
    );
    expect(JSON.stringify(result.payload)).not.toContain("principalHash");
  });

  test("dispatches Cloud parity jobs only after exact closed-loop health", async () => {
    const sessionId = "rs_" + "C".repeat(43);
    const runtime = runtimeSessionItem(sessionId, "cloud");
    mockDdbSend.mockImplementation(async (command: any) => {
      const key = command.input?.Key;
      if (command.kind === "GetItemCommand" && key?.pk?.S === "SESSION#" + sessionId) {
        return { Item: runtime.item };
      }
      if (command.kind === "GetItemCommand" && key?.pk?.S === "RUNTIME#cloud") {
        return {
          Item: {
            pk: { S: "RUNTIME#cloud" },
            sk: { S: "HEALTH" },
            status: { S: "READY" },
            generation: { S: runtime.session.binding.generation },
            capabilityDigest: { S: runtime.session.binding.capabilityDigest },
            checkedAt: { S: runtime.session.updatedAt },
            capabilities: {
              M: Object.fromEntries(
                Object.entries(runtimeCapabilities).map(([name, value]) => [
                  name,
                  { BOOL: value }
                ])
              )
            }
          }
        };
      }
      if (["UpdateItemCommand", "TransactWriteItemsCommand"].includes(command.kind)) return {};
      throw new Error("unexpected DDB command " + command.kind);
    });

    const result = await handler({
      operation: "startV2",
      requestId: "request-v2-cloud",
      body: {
        query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        question: process.env.ARCHON_ANALYTICS_QUESTION,
        mode: "GOVERNED",
        sessionId
      },
      identity: runtimeIdentity
    });

    expect(result.statusCode).toBe(202);
    expect(result.payload.runtimeEvidence.runtimeBinding.profileId).toBe("cloud");
    const transaction = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "TransactWriteItemsCommand") as any;
    const jobs = transaction.input.TransactItems
      .map((item: any) => item.Put?.Item)
      .filter((item: any) => item?.schema?.S === "archon.runtime-bound-job/v2");
    expect(jobs.map((item: any) => item.operation.S).sort()).toEqual([
      "ANALYZE",
      "READ_TAGS"
    ]);
    expect(jobs.every((item: any) => item.profileId.S === "cloud")).toBe(true);
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("keeps Cloud fail-closed when any closed-loop capability is absent", async () => {
    const sessionId = "rs_" + "D".repeat(43);
    const runtime = runtimeSessionItem(sessionId, "cloud");
    mockDdbSend
      .mockResolvedValueOnce({ Item: runtime.item })
      .mockResolvedValueOnce({
        Item: {
          pk: { S: "RUNTIME#cloud" },
          sk: { S: "HEALTH" },
          status: { S: "READY" },
          generation: { S: runtime.session.binding.generation },
          capabilityDigest: { S: runtime.session.binding.capabilityDigest },
          checkedAt: { S: runtime.session.updatedAt },
          capabilities: {
            M: {
              ...Object.fromEntries(
                Object.entries(runtimeCapabilities).map(([name, value]) => [
                  name,
                  { BOOL: value }
                ])
              ),
              mcpGovernedWrite: { BOOL: false }
            }
          }
        }
      });

    const result = await handler({
      operation: "startV2",
      requestId: "request-v2-cloud-incomplete",
      body: {
        query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        question: process.env.ARCHON_ANALYTICS_QUESTION,
        sessionId
      },
      identity: runtimeIdentity
    });

    expect(result).toMatchObject({
      statusCode: 409,
      payload: { error: "runtime_identity_mismatch" }
    });
    expect(mockSfnSend).not.toHaveBeenCalled();
  });
  test("enforces exact issuer and separate operator/approver duties before storage access", async () => {
    const auditId = "a".repeat(64);
    const sessionId = "rs_" + "S".repeat(43);
    const operatorOnly = {
      ...runtimeIdentity,
      groups: "[archon-runtime-operators]"
    };
    const approverOnly = {
      ...runtimeIdentity,
      groups: "[archon-approvers]"
    };
    const foreignIssuer = {
      ...runtimeIdentity,
      issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_FOREIGN"
    };

    const operatorDecision = await handler({
      operation: "decideV2",
      requestId: "request-v2-operator-decision",
      auditId,
      body: { decision: "REJECT" },
      identity: operatorOnly
    });
    const approverStart = await handler({
      operation: "startV2",
      requestId: "request-v2-approver-start",
      body: {
        query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        question: process.env.ARCHON_ANALYTICS_QUESTION,
        mode: "GOVERNED",
        sessionId
      },
      identity: approverOnly
    });
    const approverStatus = await handler({
      operation: "statusV2",
      requestId: "request-v2-approver-status",
      auditId,
      identity: approverOnly
    });
    const foreignStart = await handler({
      operation: "startV2",
      requestId: "request-v2-foreign-issuer",
      body: {
        query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
        question: process.env.ARCHON_ANALYTICS_QUESTION,
        mode: "GOVERNED",
        sessionId
      },
      identity: foreignIssuer
    });

    expect(operatorDecision).toMatchObject({
      statusCode: 403,
      payload: { error: "runtime_approver_role_required" }
    });
    for (const denied of [approverStart, approverStatus]) {
      expect(denied).toMatchObject({
        statusCode: 403,
        payload: { error: "runtime_operator_role_required" }
      });
    }
    expect(foreignStart).toMatchObject({
      statusCode: 403,
      payload: { error: "runtime_identity_issuer_mismatch" }
    });
    expect(mockDdbSend).not.toHaveBeenCalled();
    expect(mockSfnSend).not.toHaveBeenCalled();
  });

  test("requires authenticated ownership again on every v2 status request", async () => {
    const auditId = "d".repeat(64);
    const anonymous = await handler({
      operation: "statusV2",
      requestId: "request-v2-status-anonymous",
      auditId
    });
    expect(anonymous.statusCode).toBe(404);
    expect(mockDdbSend).not.toHaveBeenCalled();

    mockDdbSend.mockResolvedValueOnce({
      Item: {
        payload: { S: "{}" },
        principalHash: {
          S: digest({
            issuer: runtimeIdentity.issuer,
            subject: runtimeIdentity.subject
          })
        }
      }
    });
    const foreign = await handler({
      operation: "statusV2",
      requestId: "request-v2-status-foreign",
      auditId,
      identity: {
        ...runtimeIdentity,
        subject: "f7b3ca1a-339a-4f56-b1bb-9e318cc84521"
      }
    });
    expect(foreign.statusCode).toBe(403);
    expect(foreign.payload).toEqual({ error: "runtime_run_owner_mismatch" });
    expect(mockDdbSend).toHaveBeenCalledTimes(1);
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

  test("dispatches explicit improve-context as a SESSION read job without exposing its handle", async () => {
    const auditId = "e".repeat(64);
    const sessionId = "rs_" + "I".repeat(43);
    const runtime = runtimeSessionItem(sessionId);
    const ownerDigest = digest({
      issuer: runtimeIdentity.issuer,
      subject: runtimeIdentity.subject
    });
    const runtimeEvidenceUnsigned = {
      schemaVersion: "archon.runtime-binding-evidence/v2",
      auditId,
      runtimeSessionId: sessionId,
      runtimeBinding: runtime.session.binding,
      capabilities: runtimeCapabilities,
      bindingDigest: digest(runtime.session.binding),
      sessionRevision: runtime.session.revision,
      recordedAt: new Date().toISOString()
    };
    const runtimeEvidence = {
      ...runtimeEvidenceUnsigned,
      digest: digest(runtimeEvidenceUnsigned)
    };
    const analysisJobId = "job_" + "A".repeat(22);
    const readJobId = "job_" + "R".repeat(22);
    const runUnsigned = {
      schemaVersion: "archon.runtime-bound-agent-run/v2",
      auditId,
      query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      question: process.env.ARCHON_ANALYTICS_QUESTION,
      datasetUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      governedColumnPath: process.env.ARCHON_GOVERNED_COLUMN_PATH,
      mode: "GOVERNED",
      runtimeEvidence,
      analysisJobId,
      readJobId,
      submittedAt: runtimeEvidence.recordedAt
    };
    const run = { ...runUnsigned, digest: digest(runUnsigned) };
    const sealed = <T extends Record<string, unknown>>(
      value: T
    ): T & { digest: string } => ({
      ...value,
      digest: digest(value)
    });
    const context = sealed({
      schemaVersion: "archon.datahub-context/v2",
      query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      entityUrns: [process.env.ARCHON_AGENT_STACK_DATASET_URN],
      receipts: [],
      unknownPreserved: false
    });
    const { skills, skillGrounding, enrichSkillReceipt } =
      dataHubSkillEvidence(context.digest);
    const privateRunHandle = "run_" + "H".repeat(84);
    const analytics = sealed({
      schemaVersion: "archon.analytics-agent-result/v2",
      events: [{ event: "INTERNAL", payload: privateRunHandle }],
      contextQuality: { status: "verified", score: 5, label: "excellent" },
      runHandle: privateRunHandle,
      preflightDigest: digest("preflight"),
      contextDigest: context.digest,
      skillGroundingDigest: skillGrounding.digest,
      mutationsEnabled: false,
      improveContextCommandAvailable: true
    });
    const analysisUnsigned = {
      schemaVersion: "archon.datahub-agent-stack-result/v2",
      runtimeBinding: runtime.session.binding,
      context,
      skills,
      skillGrounding,
      analytics,
      enrichment: {
        status: "preview-only",
        writeAuthority: "archon-remediation-worker",
        requiresFreshDigestBoundApproval: true
      }
    };
    const analysisResult = {
      ...analysisUnsigned,
      digest: digest(analysisUnsigned)
    };
    const completedAt = new Date().toISOString();
    const receiptFor = (jobId: string, result: Record<string, unknown>) => {
      const unsigned = {
        schema: "archon.runtime-bound-job-receipt/v2",
        profileId: runtime.session.binding.profileId,
        jobId,
        sessionId,
        generation: runtime.session.binding.generation,
        capabilityDigest: runtime.session.binding.capabilityDigest,
        state: "SUCCEEDED",
        completedAt,
        result
      };
      return { ...unsigned, receiptDigest: digest(unsigned) };
    };
    const readUnsigned = {
      schemaVersion: "archon.core-tag-read-result/v1",
      entityUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      columnPath: process.env.ARCHON_GOVERNED_COLUMN_PATH,
      tagUrns: [] as string[]
    };
    const readResult = {
      ...readUnsigned,
      stateDigest: digest({
        entityUrn: readUnsigned.entityUrn,
        columnPath: readUnsigned.columnPath,
        tagUrns: readUnsigned.tagUrns
      })
    };
    const attribute = (value: any): any => {
      if (value === null) return { NULL: true };
      if (typeof value === "string") return { S: value };
      if (typeof value === "boolean") return { BOOL: value };
      if (typeof value === "number") return { N: String(value) };
      if (Array.isArray(value)) return { L: value.map(attribute) };
      return {
        M: Object.fromEntries(
          Object.entries(value).map(([key, entry]) => [key, attribute(entry)])
        )
      };
    };
    const coreItem = (jobId: string, receipt: Record<string, unknown>) => {
      const value = {
        schema: "archon.runtime-bound-job/v2",
        profileId: runtime.session.binding.profileId,
        jobId,
        auditId,
        runtimeEvidenceDigest: runtimeEvidence.digest,
        sessionId,
        generation: runtime.session.binding.generation,
        capabilityDigest: runtime.session.binding.capabilityDigest,
        state: "SUCCEEDED",
        operation: "FIXTURE",
        request: { fixture: true },
        receipt
      };
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [key, attribute(entry)])
      );
    };
    const itemKey = (pk: string, sk: string) => pk + "|" + sk;
    const items = new Map<string, Record<string, any>>();
    items.set(
      itemKey("AUDIT#" + auditId, "RUNTIME"),
      { payload: { S: JSON.stringify(run) }, principalHash: { S: ownerDigest } }
    );
    items.set(itemKey("SESSION#" + sessionId, "RUNTIME"), runtime.item);
    items.set(
      itemKey("SESSION#" + sessionId, "JOB#" + analysisJobId),
      coreItem(analysisJobId, receiptFor(analysisJobId, analysisResult))
    );
    items.set(
      itemKey("SESSION#" + sessionId, "JOB#" + readJobId),
      coreItem(readJobId, receiptFor(readJobId, readResult))
    );
    const storeItem = (item: Record<string, any>) => {
      const pk = item.pk?.S;
      const sk = item.sk?.S;
      if (typeof pk !== "string" || typeof sk !== "string") {
        throw new Error("stored test item lacks its exact key");
      }
      items.set(itemKey(pk, sk), item);
    };
    const itemAt = (pk: string, sk: string): Record<string, any> => {
      const item = items.get(itemKey(pk, sk));
      if (!item) throw new Error("missing test item " + pk + "/" + sk);
      return item;
    };
    mockDdbSend.mockImplementation(async (command: any) => {
      if (command.kind === "GetItemCommand") {
        const key = command.input.Key;
        const item = items.get(itemKey(key.pk.S, key.sk.S));
        return item ? { Item: item } : {};
      }
      if (command.kind === "PutItemCommand") {
        storeItem(command.input.Item);
        return {};
      }
      if (command.kind === "TransactWriteItemsCommand") {
        for (const entry of command.input.TransactItems) {
          if (entry.Put?.Item) storeItem(entry.Put.Item);
        }
        return {};
      }
      throw new Error("unexpected DDB command " + command.kind);
    });

    const awaiting = await handler({
      operation: "statusV2",
      requestId: "request-v2-awaiting-improvement",
      auditId,
      identity: runtimeIdentity
    });
    expect(awaiting.statusCode).toBe(200);
    expect(awaiting.payload).toMatchObject({
      status: "AWAITING_IMPROVEMENT",
      phase: "IMPROVING_CONTEXT",
      governedState: {
        entityUrn: readResult.entityUrn,
        columnPath: readResult.columnPath,
        tagUrns: [],
        stateDigest: readResult.stateDigest
      }
    });
    expect(awaiting.payload.governedState).not.toHaveProperty("schemaVersion");
    expect(JSON.stringify(awaiting.payload)).not.toContain(privateRunHandle);
    expect(JSON.stringify(awaiting.payload)).toContain("[redacted]");

    const result = await handler({
      operation: "improveV2",
      requestId: "request-v2-improve",
      auditId,
      body: {},
      identity: runtimeIdentity
    });

    expect(result.statusCode).toBe(202);
    expect(result.payload).toMatchObject({
      schemaVersion: "archon.runtime-improve-context-start/v2",
      auditId,
      status: "RUNNING",
      phase: "IMPROVING_CONTEXT"
    });
    expect(JSON.stringify(result.payload)).not.toContain(privateRunHandle);
    const transaction = mockDdbSend.mock.calls
      .map(([command]) => command)
      .find((command) => command.kind === "TransactWriteItemsCommand") as any;
    expect(transaction.input.TransactItems).toHaveLength(2);
    const job = transaction.input.TransactItems[1].Put.Item;
    expect(job.pk.S).toBe("SESSION#" + sessionId);
    expect(job.operation.S).toBe("IMPROVE_CONTEXT");
    expect(job.request.M.runHandle.S).toBe(privateRunHandle);
    expect(JSON.stringify(transaction.input.TransactItems[0])).not.toContain(privateRunHandle);

    const improveMarkerItem = itemAt("AUDIT#" + auditId, "IMPROVE");
    const improveMarker = JSON.parse(improveMarkerItem.payload.S);
    const improveRunHandle = "run_" + "J".repeat(84);
    const improveUnsigned = {
      schemaVersion: "archon.datahub-improve-context/v2",
      runtimeBinding: runtime.session.binding,
      events: [{ event: "TEXT", text: "PII classification proposal prepared." }],
      contextQuality: { status: "verified", score: 5, label: "excellent" },
      runHandle: improveRunHandle,
      preflightDigest: analytics.preflightDigest,
      contextDigest: context.digest,
      skillGroundingDigest: skillGrounding.digest,
      status: "proposal-only",
      writeAuthority: "archon-remediation-worker",
      requiresFreshDigestBoundApproval: true
    };
    const improveResult = {
      ...improveUnsigned,
      digest: digest(improveUnsigned)
    };
    const improveQueued = itemAt(
      "SESSION#" + sessionId,
      "JOB#" + improveMarker.jobId
    );
    const improveReceipt = receiptFor(improveMarker.jobId, improveResult);
    storeItem({
      ...improveQueued,
      state: { S: "SUCCEEDED" },
      receipt: attribute(improveReceipt)
    });

    const approved = await handler({
      operation: "decideV2",
      requestId: "request-v2-decision-approved",
      auditId,
      body: {
        decision: "APPROVE",
        comment: "Approved exact DataHub MCP add_tags plan."
      },
      identity: runtimeIdentity
    });
    expect(approved).toMatchObject({
      statusCode: 202,
      payload: {
        schemaVersion: "archon.runtime-approval-decision-response/v2",
        auditId,
        approval: { status: "APPROVED", decision: "APPROVE" }
      }
    });
    const approvalItem = itemAt("AUDIT#" + auditId, "APPROVAL");
    const approvalEnvelope = JSON.parse(approvalItem.payload.S);

    await remediationHandler({
      Records: [{ eventName: "INSERT", dynamodb: { NewImage: approvalItem } }]
    });
    await remediationHandler({
      Records: [{ eventName: "INSERT", dynamodb: { NewImage: approvalItem } }]
    });
    expect(mockKmsSend).toHaveBeenCalledTimes(1);
    const mutationQueued = itemAt(
      "MUTATION#" + sessionId,
      "JOB#" + approvalEnvelope.mutationJobId
    );
    expect(mutationQueued.operation.S).toBe("GOVERNED_TAG_MUTATION");
    expect(mutationQueued.request.M.policyDigest.S).toBe(
      approvalEnvelope.plan.policyDigest
    );
    expect(mockKmsSend).toHaveBeenCalledTimes(1);
    const signCommand = mockKmsSend.mock.calls[0]![0];
    expect(signCommand.kind).toBe("SignCommand");
    expect(signCommand.input).toMatchObject({
      KeyId: process.env.MUTATION_SIGNING_KEY_ARN,
      MessageType: "DIGEST",
      SigningAlgorithm: "ECDSA_SHA_256"
    });
    expect(Buffer.from(signCommand.input.Message as Uint8Array)).toHaveLength(32);
    const mutationAuthorization = mutationQueued.request.M.authorization.M;
    expect(mutationAuthorization.envelope.M).toMatchObject({
      schemaVersion: { S: "archon.core-mutation-authorization/v1" },
      stage: { S: "staging" },
      sessionId: { S: sessionId },
      generation: { S: runtime.session.binding.generation },
      capabilityDigest: { S: runtime.session.binding.capabilityDigest },
      jobId: { S: approvalEnvelope.mutationJobId },
      approvalId: { S: approvalEnvelope.approvalRequest.approvalId },
      planDigest: { S: approvalEnvelope.plan.digest },
      policyDigest: { S: approvalEnvelope.plan.policyDigest },
      tool: { S: "add_tags" }
    });
    expect(mutationAuthorization.envelope.M.arguments.M).toEqual({
      tag_urns: { L: [{ S: "urn:li:tag:PII" }] },
      entity_urns: { L: [{ S: process.env.ARCHON_AGENT_STACK_DATASET_URN }] },
      column_paths: { L: [{ S: process.env.ARCHON_GOVERNED_COLUMN_PATH }] }
    });
    expect(mutationAuthorization.signature.M).toMatchObject({
      keyArn: { S: process.env.MUTATION_SIGNING_KEY_ARN },
      algorithm: { S: "ECDSA_SHA_256" },
      canonicalization: { S: "archon.sorted-json-utf8/v1" },
      signatureBase64: { S: testKmsSignature.toString("base64") }
    });
    const officialMcpResponseDigest = digest({
      tool: "add_tags",
      target: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      columnPath: process.env.ARCHON_GOVERNED_COLUMN_PATH,
      tagUrns: ["urn:li:tag:PII"]
    });
    const mutationResultUnsigned = {
      schemaVersion: "archon.core-governed-tag-result/v1",
      requestDigest: mutationQueued.request.M.requestDigest.S,
      policyDigest: approvalEnvelope.plan.policyDigest,
      beforeDigest: approvalEnvelope.plan.expectedBeforeDigest,
      afterDigest: approvalEnvelope.plan.expectedAfterDigest,
      verified: true,
      mutationExecutor: "official-datahub-mcp",
      officialMcpMutation: {
        tool: "add_tags",
        policyDigest: approvalEnvelope.plan.policyDigest,
        approvalDigest: mutationQueued.request.M.approval.M.digest.S,
        requestDigest: mutationQueued.request.M.requestDigest.S,
        responseDigest: officialMcpResponseDigest
      },
      authorizationEvidence: {
        keyArn: process.env.MUTATION_SIGNING_KEY_ARN,
        algorithm: "ECDSA_SHA_256",
        canonicalization: "archon.sorted-json-utf8/v1",
        envelopeDigest: mutationAuthorization.signature.M.envelopeDigest.S,
        signatureDigest: `sha256:${createHash("sha256").update(testKmsSignature).digest("hex")}`,
        consumedAt: mutationAuthorization.envelope.M.issuedAt.S
      }
    };
    const mutationResult = {
      ...mutationResultUnsigned,
      responseDigest: digest(mutationResultUnsigned)
    };
    const mutationReceipt = receiptFor(
      approvalEnvelope.mutationJobId,
      mutationResult
    );
    const mutationCompleted = {
      ...mutationQueued,
      state: { S: "SUCCEEDED" },
      receipt: attribute(mutationReceipt)
    };
    storeItem(mutationCompleted);

    await remediationHandler({
      Records: [{ eventName: "MODIFY", dynamodb: { NewImage: mutationCompleted } }]
    });
    const postMarkerItem = itemAt("AUDIT#" + auditId, "POST_VERIFY");
    const postMarker = JSON.parse(postMarkerItem.payload.S);
    const postAnalysisQueued = itemAt(
      "SESSION#" + sessionId,
      "JOB#" + postMarker.analysisJobId
    );
    const postReadQueued = itemAt(
      "SESSION#" + sessionId,
      "JOB#" + postMarker.readJobId
    );
    expect(postAnalysisQueued.operation.S).toBe("POST_ANALYZE");
    expect(postReadQueued.operation.S).toBe("POST_READ_TAGS");
    expect(postAnalysisQueued.request.M.sourceMutationReceiptDigest.S).toBe(
      mutationReceipt.receiptDigest
    );
    expect(
      postReadQueued.request.M.postMutationExpectedTagState.M.tagUrns.L
    ).toEqual([{ S: "urn:li:tag:PII" }]);

    const postContext = signed({
      schemaVersion: "archon.datahub-context/v2",
      query: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      entityUrns: [process.env.ARCHON_AGENT_STACK_DATASET_URN],
      receipts: [
        {
          tool: "get_entities",
          status: "succeeded",
          resultDigest: digest({ tagUrns: ["urn:li:tag:PII"] }),
          result: {
            columnPath: "customer_email",
            tagUrns: ["urn:li:tag:PII"]
          }
        }
      ],
      unknownPreserved: false
    });
    const postAnalytics = sealed({
      schemaVersion: "archon.analytics-agent-result/v2",
      events: [
        {
          event: "SQL",
          sql: "select customer_segment, sum(net_revenue) from orders group by 1"
        },
        { event: "CHART", chart: "bar" },
        {
          event: "COMPLETE",
          answer: "Enterprise; customer_email is governed as PII."
        }
      ],
      contextQuality: { status: "verified", score: 5, label: "excellent" },
      runHandle: "run_" + "K".repeat(84),
      preflightDigest: analytics.preflightDigest,
      contextDigest: postContext.digest,
      skillGroundingDigest: skillGrounding.digest,
      mutationsEnabled: false,
      improveContextCommandAvailable: true
    });
    const postAnalysisUnsigned = {
      schemaVersion: "archon.datahub-agent-stack-result/v2",
      runtimeBinding: runtime.session.binding,
      context: postContext,
      skills,
      skillGrounding,
      analytics: postAnalytics,
      enrichment: {
        status: "preview-only",
        writeAuthority: "archon-remediation-worker",
        requiresFreshDigestBoundApproval: true
      }
    };
    const postAnalysisResult = {
      ...postAnalysisUnsigned,
      digest: digest(postAnalysisUnsigned)
    };
    const postAnalysisWrapper = {
      schemaVersion: "archon.datahub-post-mutation-analysis-result/v1",
      sourceMutationAuditId: auditId,
      sourceMutationReceiptDigest: mutationReceipt.receiptDigest,
      postMutationExpectedTagState: approvalEnvelope.plan.expectedAfter,
      postMutationResult: postAnalysisResult,
      postMutationResultDigest: digest(postAnalysisResult)
    };
    const postReadUnsigned = {
      schemaVersion: "archon.core-tag-read-result/v1",
      entityUrn: process.env.ARCHON_AGENT_STACK_DATASET_URN,
      columnPath: process.env.ARCHON_GOVERNED_COLUMN_PATH,
      tagUrns: ["urn:li:tag:PII"]
    };
    const postReadResult = {
      ...postReadUnsigned,
      stateDigest: digest({
        entityUrn: postReadUnsigned.entityUrn,
        columnPath: postReadUnsigned.columnPath,
        tagUrns: postReadUnsigned.tagUrns
      })
    };
    const postReadWrapper = {
      schemaVersion: "archon.core-post-mutation-tag-read-result/v1",
      sourceMutationAuditId: auditId,
      sourceMutationReceiptDigest: mutationReceipt.receiptDigest,
      postMutationExpectedTagState: approvalEnvelope.plan.expectedAfter,
      postMutationResult: postReadResult,
      postMutationResultDigest: digest(postReadResult)
    };
    storeItem({
      ...postAnalysisQueued,
      state: { S: "SUCCEEDED" },
      receipt: attribute(
        receiptFor(postMarker.analysisJobId, postAnalysisWrapper)
      )
    });
    storeItem({
      ...postReadQueued,
      state: { S: "SUCCEEDED" },
      receipt: attribute(receiptFor(postMarker.readJobId, postReadWrapper))
    });

    const completed = await handler({
      operation: "statusV2",
      requestId: "request-v2-post-mutation-complete",
      auditId,
      identity: runtimeIdentity
    });
    expect(completed).toMatchObject({
      statusCode: 200,
      payload: {
        status: "SUCCEEDED",
        phase: "COMPLETE",
        governedState: { tagUrns: ["urn:li:tag:PII"] },
        remediation: {
          mutationExecutor: "official-datahub-mcp",
          officialMcpMutation: { tool: "add_tags" },
          authorizationEvidence: {
            algorithm: "ECDSA_SHA_256",
            canonicalization: "archon.sorted-json-utf8/v1",
            envelopeDigest: mutationAuthorization.signature.M.envelopeDigest.S,
            signatureDigest: `sha256:${createHash("sha256").update(testKmsSignature).digest("hex")}`
          },
          verified: true
        },
        skillCompletion: {
          schemaVersion: "archon.datahub-skill-completion/v1",
          skill: "datahub-enrich",
          status: "executed-with-human-approval",
          sourceArtifactDigest: enrichSkillReceipt.sourceArtifactDigest,
          executionPlanDigest: enrichSkillReceipt.executionPlanDigest,
          previewSkillReceiptDigest: enrichSkillReceipt.digest,
          skillGroundingDigest: skillGrounding.digest,
          approvalDigest: approvalEnvelope.decision.digest,
          officialMcpMutationReceiptDigest: mutationReceipt.receiptDigest
        },
        contextDelta: {
          ackContextChanged: true,
          analyticsResultChanged: true,
          sourceReadVerified: true,
          addedTagUrns: ["urn:li:tag:PII"]
        }
      }
    });
    expect(completed.payload.contextDelta.beforeContextDigest).not.toBe(
      completed.payload.contextDelta.afterContextDigest
    );
    expect(JSON.stringify(completed.payload)).not.toContain(improveRunHandle);
    expect(JSON.stringify(completed.payload)).not.toContain(
      postAnalysisResult.analytics.runHandle
    );
    expect(JSON.stringify(completed.payload)).not.toContain(
      process.env.MUTATION_SIGNING_KEY_ARN
    );
    expect(completed.payload.remediation.authorizationEvidence.keyReferenceDigest).toMatch(
      /^sha256:[a-f0-9]{64}$/u
    );

    runtime.item.payload.S = JSON.stringify({
      ...runtime.session,
      idleExpiresAt: new Date(Date.now() - 1_000).toISOString()
    });
    const expiredImprove = await handler({
      operation: "improveV2",
      requestId: "request-v2-improve-expired",
      auditId,
      body: {},
      identity: runtimeIdentity
    });
    const expiredDecision = await handler({
      operation: "decideV2",
      requestId: "request-v2-decision-expired",
      auditId,
      body: { decision: "REJECT" },
      identity: runtimeIdentity
    });
    expect(expiredImprove).toMatchObject({
      statusCode: 409,
      payload: { error: "runtime_session_not_active" }
    });
    expect(expiredDecision).toMatchObject({
      statusCode: 409,
      payload: { error: "runtime_session_not_active" }
    });
  });

  test("binds datahub-enrich completion to the exact artifact, plan, reads, grounding, approval, and mutation receipt", () => {
    const valid = standaloneSkillCompletionFixture();
    expect(
      runtimeV2Test.enrichSkillCompletion(
        valid.analysisReceipt,
        valid.approvalEnvelope,
        valid.mutationReceipt
      )
    ).toMatchObject({
      schemaVersion: "archon.datahub-skill-completion/v1",
      skill: "datahub-enrich",
      status: "executed-with-human-approval",
      sourceArtifactDigest: valid.enrichSkillReceipt.sourceArtifactDigest,
      executionPlanDigest: valid.enrichSkillReceipt.executionPlanDigest,
      previewSkillReceiptDigest: valid.enrichSkillReceipt.digest,
      skillGroundingDigest: valid.analysisReceipt.result.skillGrounding.digest,
      approvalDigest: valid.approvalEnvelope.decision.digest,
      officialMcpMutationReceiptDigest: valid.mutationReceipt.receiptDigest
    });

    const missingRequiredFlag = standaloneSkillCompletionFixture();
    const missingReceipt = (
      missingRequiredFlag.analysisReceipt.result.skillGrounding.receipts as
        Array<Record<string, any>>
    ).find((receipt) => receipt.skill === "datahub-enrich")!;
    delete missingReceipt.requiredCallsSatisfied;
    resealSkillCompletionFixture(missingRequiredFlag);

    const mismatchedPlan = standaloneSkillCompletionFixture();
    const planReceipt = (
      mismatchedPlan.analysisReceipt.result.skillGrounding.receipts as
        Array<Record<string, any>>
    ).find((receipt) => receipt.skill === "datahub-enrich")!;
    planReceipt.executionPlanDigest = digest({ mismatch: "execution-plan" });
    resealSkillCompletionFixture(mismatchedPlan);

    const missingAckReceipt = standaloneSkillCompletionFixture();
    const ackReceipt = (
      missingAckReceipt.analysisReceipt.result.skillGrounding.receipts as
        Array<Record<string, any>>
    ).find((receipt) => receipt.skill === "datahub-enrich")!;
    ackReceipt.satisfiedAckCalls = ackReceipt.satisfiedAckCalls.slice(0, -1);
    ackReceipt.ackReceiptDigests = ackReceipt.satisfiedAckCalls.map(
      (call: Record<string, string>) => call.receiptDigest
    );
    resealSkillCompletionFixture(missingAckReceipt);

    const artifactMismatch = standaloneSkillCompletionFixture();
    const artifactReceipt = (
      artifactMismatch.analysisReceipt.result.skillGrounding.receipts as
        Array<Record<string, any>>
    ).find((receipt) => receipt.skill === "datahub-enrich")!;
    artifactReceipt.sourceArtifactDigest = digest({ mismatch: "artifact" });
    artifactReceipt.executionPlanDigest = digest({
      sourceArtifactDigest: artifactReceipt.sourceArtifactDigest,
      executionPlan: artifactReceipt.executionPlan
    });
    resealSkillCompletionFixture(artifactMismatch);

    const groundingMismatch = standaloneSkillCompletionFixture();
    const groundingResult =
      groundingMismatch.analysisReceipt.result as Record<string, any>;
    groundingResult.analytics.skillGroundingDigest = digest({
      mismatch: "grounding"
    });
    groundingResult.analytics = signed(
      without(groundingResult.analytics, ["digest"])
    );
    (
      groundingMismatch.analysisReceipt as {
        result: Record<string, any>;
      }
    ).result = signed(without(groundingResult, ["digest"]));

    for (const invalid of [
      missingRequiredFlag,
      mismatchedPlan,
      missingAckReceipt,
      artifactMismatch,
      groundingMismatch
    ]) {
      expect(() =>
        runtimeV2Test.enrichSkillCompletion(
          invalid.analysisReceipt,
          invalid.approvalEnvelope,
          invalid.mutationReceipt
        )
      ).toThrow(/datahub-enrich/u);
    }
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

describe("Core mutation authorization cross-language golden contract", () => {
  it("canonicalizes, digests, and verifies the shared P-256 fixture", () => {
    expect(mutationAuthorizationGolden.schemaVersion).toBe(
      "archon.core-mutation-authorization-golden/v1"
    );
    expect(mutationAuthorizationGolden.canonicalization).toBe(
      "archon.sorted-json-utf8/v1"
    );
    expect(mutationAuthorizationGolden.keySpec).toBe("ECC_NIST_P256");
    expect(mutationAuthorizationGolden.algorithm).toBe("ECDSA_SHA_256");

    const canonicalJson = runtimeV2Test.canonicalMutationEnvelope(
      mutationAuthorizationGolden.envelope
    );
    expect(canonicalJson).toBe(mutationAuthorizationGolden.canonicalJson);
    expect(runtimeV2Test.mutationEnvelopeDigest(
      mutationAuthorizationGolden.envelope
    )).toBe(mutationAuthorizationGolden.envelopeDigest);
    expect(
      "sha256:" + createHash("sha256").update(canonicalJson, "utf8").digest("hex")
    ).toBe(mutationAuthorizationGolden.envelopeDigest);

    const publicKey = createPublicKey({
      key: Buffer.from(mutationAuthorizationGolden.publicKeyDerBase64, "base64"),
      format: "der",
      type: "spki"
    });
    expect(
      verify(
        "sha256",
        Buffer.from(canonicalJson, "utf8"),
        publicKey,
        Buffer.from(mutationAuthorizationGolden.signatureBase64, "base64")
      )
    ).toBe(true);
  });

  it("fails closed on non-integer or non-ASCII signed values", () => {
    expect(() => runtimeV2Test.canonicalMutationEnvelope({ value: 1.5 })).toThrow(
      "safe integers"
    );
    expect(() => runtimeV2Test.canonicalMutationEnvelope({ value: "π" })).toThrow(
      "printable ASCII"
    );
  });
});
