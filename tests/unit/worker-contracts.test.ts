import assert from "node:assert/strict";
import { test } from "node:test";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  parseQueueMessage,
  WorkerContractError,
} from "../../src/worker/contracts.js";
import {
  DirectGmsTagProjectionReader,
  parseTagProjectionResponse,
} from "../../src/datahub/tag-projection-reader-live.js";
import { RemediationError } from "../../src/remediation/control-loop.js";
import {
  DynamoAuditResultCheckpoint,
  DynamoExecutionJournal,
  retryVisibilitySeconds,
  shouldFinalizePoisonDelivery,
} from "../../src/worker/aws-adapters.js";
import { loadAuditWorkerConfiguration } from "../../src/audit-worker.js";
import { loadRemediationWorkerConfiguration } from "../../src/remediation-worker.js";

const EXECUTION =
  "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0001";
const TOKEN = "opaque-step-functions-task-token-0001";
const DIGEST = `sha256:${"a".repeat(64)}` as `sha256:${string}`;
const ACTIONABLE_REPLAY = {
  schemaVersion: "archon.audit-result/v2",
  requiresApproval: true,
  reportDigest: DIGEST,
  evidenceDigest: DIGEST,
  approvalId: "approval-0001",
  planDigest: DIGEST,
  approvalRequestDigest: DIGEST,
  approvalRequestedAt: "2026-07-23T10:00:00.000Z",
  approvalExpiresAt: "2026-07-23T10:10:00.000Z",
} as const;
const MANUAL_REPLAY = {
  schemaVersion: "archon.audit-result/v2",
  requiresApproval: false,
  reportDigest: DIGEST,
  evidenceDigest: DIGEST,
  manualOnlyReason: "NO_ACTIONABLE_G6_FINDING",
} as const;

const WORKER_ENVIRONMENT = [
  "ARCHON_AUDIT_QUEUE_URL",
  "ARCHON_AUDIT_DLQ_URL",
  "ARCHON_REMEDIATION_QUEUE_URL",
  "ARCHON_REMEDIATION_DLQ_URL",
  "ARCHON_APPROVAL_TABLE",
  "ARCHON_APPROVAL_QUEUE_URL",
  "ARCHON_APPROVAL_DLQ_URL",
  "ARCHON_IDEMPOTENCY_TABLE",
  "ARCHON_EVIDENCE_BUCKET",
  "ARCHON_RELEASE_SHA",
  "DATAHUB_GMS_URL",
  "DATAHUB_GMS_TOKEN",
  "DATAHUB_MCP_URL",
  "DATAHUB_WRITE_GMS_URL",
  "DATAHUB_WRITE_GMS_TOKEN",
  "DATAHUB_WRITE_MCP_URL",
  "LLM_PROVIDER",
  "LLM_API_KEY",
  "LLM_BASE_URL",
  "LLM_MODEL",
  "LLM_PROJECT_ID",
  "AWS_BEARER_TOKEN_BEDROCK",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_PROFILE",
  "AWS_DEFAULT_PROFILE",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_CONFIG_FILE",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "DASHSCOPE_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "AWS_REGION",
] as const;

function withWorkerEnvironment<T>(
  overrides: Record<string, string>,
  fn: () => T
): T {
  const saved = new Map<string, string | undefined>();
  for (const name of WORKER_ENVIRONMENT) {
    saved.set(name, process.env[name]);
    delete process.env[name];
  }
  try {
    Object.assign(process.env, overrides);
    return fn();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

const COMMON_WORKER_ENVIRONMENT = {
  ARCHON_IDEMPOTENCY_TABLE: "archon-idempotency",
  ARCHON_EVIDENCE_BUCKET: "archon-evidence",
  ARCHON_RELEASE_SHA: "abcdef1234567",
};

function auditCheckpoint(output: unknown): DynamoAuditResultCheckpoint {
  const client = {
    async send(command: any): Promise<any> {
      assert.equal(command.input.TableName, "archon-idempotency");
      assert.deepEqual(command.input.Key, {
        pk: { S: "AUDIT#execution-replay-0001" },
        sk: { S: "RESULT" },
      });
      assert.equal(command.input.ConsistentRead, true);
      return {
        Item: {
          requestDigest: { S: DIGEST },
          output: { S: JSON.stringify(output) },
        },
      };
    },
  } as unknown as DynamoDBClient;
  return new DynamoAuditResultCheckpoint(
    client,
    "archon-idempotency"
  );
}

async function rejectsAuditReplay(output: unknown): Promise<void> {
  await assert.rejects(
    auditCheckpoint(output).get("execution-replay-0001", DIGEST),
    (error: unknown) =>
      error instanceof WorkerContractError &&
      error.code === "INVALID_EVIDENCE"
  );
}

function withoutKey(
  value: object,
  omitted: string
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== omitted)
  );
}

test("hosted audit worker accepts only stage-scoped Bedrock task-role auth", () => {
  withWorkerEnvironment(
    {
      ...COMMON_WORKER_ENVIRONMENT,
      ARCHON_AUDIT_QUEUE_URL: "https://sqs.eu-west-1.amazonaws.com/audit",
      ARCHON_AUDIT_DLQ_URL: "https://sqs.eu-west-1.amazonaws.com/audit-dlq",
      DATAHUB_GMS_URL: "https://datahub.example.test",
      DATAHUB_GMS_TOKEN: "read-token",
      DATAHUB_MCP_URL: "https://datahub.example.test/mcp",
      LLM_PROVIDER: "bedrock-mantle",
      AWS_REGION: "eu-west-1",
      LLM_BASE_URL: "https://bedrock-mantle.eu-west-1.api.aws/v1",
      LLM_MODEL: "qwen.qwen3-235b-a22b-2507",
      LLM_PROJECT_ID: "proj_archonstaging001",
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:
        "/v2/credentials/12345678-90ab-cdef-1234-567890abcdef",
    },
    () => {
      const configuration = loadAuditWorkerConfiguration();
      assert.equal(configuration.idempotencyTable, "archon-idempotency");
      assert.equal(configuration.releaseSha, "abcdef1234567");
    }
  );
});

test("hosted audit worker rejects a static LLM key beside task-role auth", () => {
  withWorkerEnvironment(
    {
      ...COMMON_WORKER_ENVIRONMENT,
      ARCHON_AUDIT_QUEUE_URL: "https://sqs.eu-west-1.amazonaws.com/audit",
      ARCHON_AUDIT_DLQ_URL: "https://sqs.eu-west-1.amazonaws.com/audit-dlq",
      DATAHUB_GMS_URL: "https://datahub.example.test",
      DATAHUB_GMS_TOKEN: "read-token",
      DATAHUB_MCP_URL: "https://datahub.example.test/mcp",
      LLM_PROVIDER: "bedrock-mantle",
      AWS_REGION: "eu-west-1",
      LLM_BASE_URL: "https://bedrock-mantle.eu-west-1.api.aws/v1",
      LLM_MODEL: "qwen.qwen3-235b-a22b-2507",
      LLM_PROJECT_ID: "proj_archonstaging001",
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:
        "/v2/credentials/12345678-90ab-cdef-1234-567890abcdef",
      LLM_API_KEY: "forbidden-static-key",
    },
    () => {
      assert.throws(
        loadAuditWorkerConfiguration,
        /LLM_API_KEY is forbidden/u
      );
    }
  );
});

for (const [credentialName, credentialValue] of [
  ["AWS_ACCESS_KEY_ID", "AKIA1234567890ABCDEF"],
  ["AWS_PROFILE", "default"],
  ["AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/token"],
  ["AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1/credentials"],
] as const) {
  test(`hosted audit worker rejects ambient ${credentialName}`, () => {
    withWorkerEnvironment(
      {
        ...COMMON_WORKER_ENVIRONMENT,
        ARCHON_AUDIT_QUEUE_URL: "https://sqs.eu-west-1.amazonaws.com/audit",
        ARCHON_AUDIT_DLQ_URL:
          "https://sqs.eu-west-1.amazonaws.com/audit-dlq",
        DATAHUB_GMS_URL: "https://datahub.example.test",
        DATAHUB_GMS_TOKEN: "read-token",
        DATAHUB_MCP_URL: "https://datahub.example.test/mcp",
        LLM_PROVIDER: "bedrock-mantle",
        AWS_REGION: "eu-west-1",
        LLM_BASE_URL: "https://bedrock-mantle.eu-west-1.api.aws/v1",
        LLM_MODEL: "qwen.qwen3-235b-a22b-2507",
        LLM_PROJECT_ID: "proj_archonstaging001",
        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:
          "/v2/credentials/12345678-90ab-cdef-1234-567890abcdef",
        [credentialName]: credentialValue,
      },
      () => {
        assert.throws(
          loadAuditWorkerConfiguration,
          new RegExp(`${credentialName} is forbidden`, "u")
        );
      }
    );
  });
}

test("hosted audit worker rejects a missing ECS task-role credential endpoint", () => {
  withWorkerEnvironment(
    {
      ...COMMON_WORKER_ENVIRONMENT,
      ARCHON_AUDIT_QUEUE_URL: "https://sqs.eu-west-1.amazonaws.com/audit",
      ARCHON_AUDIT_DLQ_URL: "https://sqs.eu-west-1.amazonaws.com/audit-dlq",
      DATAHUB_GMS_URL: "https://datahub.example.test",
      DATAHUB_GMS_TOKEN: "read-token",
      DATAHUB_MCP_URL: "https://datahub.example.test/mcp",
      LLM_PROVIDER: "bedrock-mantle",
      AWS_REGION: "eu-west-1",
      LLM_BASE_URL: "https://bedrock-mantle.eu-west-1.api.aws/v1",
      LLM_MODEL: "qwen.qwen3-235b-a22b-2507",
      LLM_PROJECT_ID: "proj_archonstaging001",
    },
    () => {
      assert.throws(
        loadAuditWorkerConfiguration,
        /must identify the ECS task-role credential endpoint/u
      );
    }
  );
});

test("remediation worker rejects Bedrock project capability", () => {
  withWorkerEnvironment(
    {
      ...COMMON_WORKER_ENVIRONMENT,
      ARCHON_REMEDIATION_QUEUE_URL:
        "https://sqs.eu-west-1.amazonaws.com/remediation",
      ARCHON_REMEDIATION_DLQ_URL:
        "https://sqs.eu-west-1.amazonaws.com/remediation-dlq",
      DATAHUB_WRITE_GMS_URL: "https://datahub-write.example.test",
      DATAHUB_WRITE_GMS_TOKEN: "write-token",
      DATAHUB_WRITE_MCP_URL: "https://datahub-write.example.test/mcp",
      LLM_PROJECT_ID: "proj_archonstaging001",
    },
    () => {
      assert.throws(
        loadRemediationWorkerConfiguration,
        /LLM_PROJECT_ID/u
      );
    }
  );
});

for (const credential of [
  "DASHSCOPE_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
] as const) {
  test(`remediation worker rejects ${credential} model capability`, () => {
    withWorkerEnvironment(
      {
        ...COMMON_WORKER_ENVIRONMENT,
        ARCHON_REMEDIATION_QUEUE_URL:
          "https://sqs.eu-west-1.amazonaws.com/remediation",
        ARCHON_REMEDIATION_DLQ_URL:
          "https://sqs.eu-west-1.amazonaws.com/remediation-dlq",
        DATAHUB_WRITE_GMS_URL: "https://datahub-write.example.test",
        DATAHUB_WRITE_GMS_TOKEN: "write-token",
        DATAHUB_WRITE_MCP_URL: "https://datahub-write.example.test/mcp",
        [credential]: "forbidden-model-credential",
      },
      () => {
        assert.throws(loadRemediationWorkerConfiguration, new RegExp(credential));
      }
    );
  });
}

test("worker contracts accept the exact audit, approval, and remediation envelopes", () => {
  const audit = parseQueueMessage(
    "audit",
    JSON.stringify({
      type: "AUDIT_REQUESTED",
      taskToken: TOKEN,
      executionId: EXECUTION,
      request: {
        schemaVersion: "archon.audit-request/v1",
        requestId: "request-0001",
        requestedAt: "2026-07-23T10:00:00.000Z",
        query: "customer",
      },
    })
  );
  assert.equal(audit.type, "AUDIT_REQUESTED");

  const approval = parseQueueMessage(
    "approval",
    JSON.stringify({
      type: "APPROVAL_REQUESTED",
      taskToken: TOKEN,
      executionId: EXECUTION,
      approvalId: "approval-0001",
      planDigest: DIGEST,
      evidenceDigest: DIGEST,
      approvalRequestDigest: DIGEST,
      requestedAt: "2026-07-23T10:00:00.000Z",
      expiresAt: "2026-07-29T10:00:00.000Z",
    })
  );
  assert.equal(approval.type, "APPROVAL_REQUESTED");

  const remediation = parseQueueMessage(
    "remediation",
    JSON.stringify({
      type: "REMEDIATION_REQUESTED",
      taskToken: TOKEN,
      executionId: EXECUTION,
      approvalId: "approval-0001",
      planDigest: DIGEST,
      evidenceDigest: DIGEST,
      approvalResult: {
        approvalId: "approval-0001",
        decision: {
          decision: "APPROVE",
          approver: {
            subject: "cognito-user-0001",
            issuer: "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_example",
            roles: ["DataSteward"],
            authenticated: true,
          },
          decidedAt: "2026-07-23T10:01:00.000Z",
        },
      },
    })
  );
  assert.equal(remediation.type, "REMEDIATION_REQUESTED");
});

test("worker contracts reject unknown fields, queue confusion, and forged roles", () => {
  assert.throws(
    () =>
      parseQueueMessage(
        "audit",
        JSON.stringify({
          type: "AUDIT_REQUESTED",
          taskToken: TOKEN,
          executionId: EXECUTION,
          request: {
            schemaVersion: "archon.audit-request/v1",
            requestId: "request-0001",
            requestedAt: "2026-07-23T10:00:00.000Z",
            tool: "add_tags",
          },
        })
      ),
    (error: unknown) =>
      error instanceof WorkerContractError && error.code === "INVALID_MESSAGE"
  );
  assert.throws(() =>
    parseQueueMessage(
      "approval",
      JSON.stringify({
        type: "AUDIT_REQUESTED",
        taskToken: TOKEN,
        executionId: EXECUTION,
        request: {},
      })
    )
  );
  assert.throws(() =>
    parseQueueMessage(
      "remediation",
      JSON.stringify({
        type: "REMEDIATION_REQUESTED",
        taskToken: TOKEN,
        executionId: EXECUTION,
        approvalId: "approval-0001",
        planDigest: DIGEST,
        evidenceDigest: DIGEST,
        approvalResult: {
          approvalId: "approval-0001",
          decision: {
            decision: "APPROVE",
            approver: {
              subject: "attacker-0001",
              issuer: "https://issuer.example.test",
              roles: ["Administrator"],
              authenticated: true,
            },
            decidedAt: "2026-07-23T10:01:00.000Z",
          },
        },
      })
    )
  );
});

test("Dynamo audit checkpoint replays exact actionable and manual v2 results", async () => {
  assert.deepEqual(
    await auditCheckpoint(ACTIONABLE_REPLAY).get(
      "execution-replay-0001",
      DIGEST
    ),
    ACTIONABLE_REPLAY
  );
  assert.deepEqual(
    await auditCheckpoint(MANUAL_REPLAY).get(
      "execution-replay-0001",
      DIGEST
    ),
    MANUAL_REPLAY
  );
});

test("Dynamo audit checkpoint rejects invalid IDs and incomplete v2 bindings", async () => {
  await rejectsAuditReplay({
    ...ACTIONABLE_REPLAY,
    approvalId: "",
  });
  await rejectsAuditReplay({
    ...ACTIONABLE_REPLAY,
    approvalId: "short",
  });
  await rejectsAuditReplay({
    ...ACTIONABLE_REPLAY,
    approvalId: "approval/invalid",
  });
  await rejectsAuditReplay({
    ...ACTIONABLE_REPLAY,
    approvalId: "a".repeat(161),
  });

  for (const key of [
    "approvalId",
    "planDigest",
    "approvalRequestDigest",
    "approvalRequestedAt",
    "approvalExpiresAt",
  ]) {
    await rejectsAuditReplay(withoutKey(ACTIONABLE_REPLAY, key));
  }
  await rejectsAuditReplay(
    withoutKey(ACTIONABLE_REPLAY, "reportDigest")
  );
  await rejectsAuditReplay({
    schemaVersion: "archon.audit-result/v2",
    requiresApproval: true,
    reportDigest: DIGEST,
    evidenceDigest: DIGEST,
    approvalId: "approval-0001",
  });
  await rejectsAuditReplay({
    ...ACTIONABLE_REPLAY,
    unexpectedBinding: DIGEST,
  });
  await rejectsAuditReplay({
    ...MANUAL_REPLAY,
    approvalId: "approval-0001",
  });
  await rejectsAuditReplay(
    withoutKey(MANUAL_REPLAY, "manualOnlyReason")
  );
});

test("Dynamo audit checkpoint rejects malformed, noncanonical, and unordered instants", async () => {
  const cases = [
    {
      ...ACTIONABLE_REPLAY,
      approvalRequestedAt: "not-a-date",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalRequestedAt: "2026-07-23T10:00:00Z",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalRequestedAt: "2026-07-23T12:00:00.000+02:00",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalRequestedAt: "2026-02-30T10:00:00.000Z",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalExpiresAt: "not-a-date",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalExpiresAt: "2026-07-23T09:59:59.999Z",
    },
    {
      ...ACTIONABLE_REPLAY,
      approvalExpiresAt: ACTIONABLE_REPLAY.approvalRequestedAt,
    },
  ];
  for (const output of cases) {
    await rejectsAuditReplay(output);
  }
});

test("direct GMS projection unions base and editable field tag URNs", () => {
  const target = {
    entityUrn:
      "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)",
    columnPath: "email",
  };
  const projection = parseTagProjectionResponse(
    [
      {
        urn: target.entityUrn,
        schemaMetadata: {
          value: {
            fields: [
              {
                fieldPath: "email",
                globalTags: {
                  tags: [
                    { tag: "urn:li:tag:Ingested" },
                    { tag: "urn:li:tag:PII" },
                  ],
                },
              },
            ],
          },
        },
        editableSchemaMetadata: {
          value: {
            editableSchemaFieldInfo: [
              {
                fieldPath: "email",
                globalTags: {
                  tags: [
                    { tag: "urn:li:tag:StewardApproved" },
                    { tag: "urn:li:tag:PII" },
                  ],
                },
              },
            ],
          },
        },
      },
    ],
    target
  );
  assert.deepEqual(projection.tags, [
    "urn:li:tag:Ingested",
    "urn:li:tag:PII",
    "urn:li:tag:StewardApproved",
  ]);

  const withoutEditableAspect = parseTagProjectionResponse(
    [
      {
        urn: target.entityUrn,
        schemaMetadata: {
          value: {
            fields: [{ fieldPath: "email" }],
          },
        },
      },
    ],
    target
  );
  assert.deepEqual(withoutEditableAspect.tags, []);

  assert.throws(() =>
    parseTagProjectionResponse(
      [
        {
          urn: target.entityUrn,
          schemaMetadata: {
            value: {
              fields: [{ fieldPath: "email" }],
            },
          },
          editableSchemaMetadata: {
            value: {
              editableSchemaFieldInfo: [
                {
                  fieldPath: "email",
                  globalTags: { tags: [{ tag: "PII" }] },
                },
              ],
            },
          },
        },
      ],
      target
    )
  );
  assert.throws(() =>
    parseTagProjectionResponse(
      [
        {
          urn: target.entityUrn,
          schemaMetadata: {
            value: {
              fields: [
                { fieldPath: "email" },
                { fieldPath: "email" },
              ],
            },
          },
        },
      ],
      target
    )
  );
});

test("direct GMS projection uses the exact one-URN two-aspect batchGet contract", async () => {
  const target = {
    entityUrn:
      "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)",
    columnPath: "email",
  };
  const expectedBody = JSON.stringify([
    {
      urn: target.entityUrn,
      schemaMetadata: {},
      editableSchemaMetadata: {},
    },
  ]);
  let calls = 0;
  const fetchFn = (async (
    input: string | URL | Request,
    init?: RequestInit
  ) => {
    calls += 1;
    assert.equal(
      input,
      "https://datahub.example/openapi/v3/entity/dataset/batchGet"
    );
    assert.equal(init?.method, "POST");
    assert.deepEqual(init?.headers, {
      Accept: "application/json",
      Authorization: "Bearer dedicated-read-token",
      "Content-Type": "application/json",
    });
    assert.equal(init?.body, expectedBody);
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal instanceof AbortSignal);
    return new Response(
      JSON.stringify([
        {
          urn: target.entityUrn,
          schemaMetadata: {
            value: {
              fields: [{ fieldPath: target.columnPath }],
            },
          },
          editableSchemaMetadata: {
            value: {
              editableSchemaFieldInfo: [
                {
                  fieldPath: target.columnPath,
                  globalTags: {
                    tags: [{ tag: "urn:li:tag:PII" }],
                  },
                },
              ],
            },
          },
        },
      ]),
      {
        status: 200,
        headers: { "content-type": "application/json" },
      }
    );
  }) as typeof fetch;
  const reader = new DirectGmsTagProjectionReader({
    gmsUrl: "https://datahub.example/",
    token: "dedicated-read-token",
    fetchFn,
    requestTimeoutMs: 1_000,
  });

  const projection = await reader.readTagProjection(target);
  assert.equal(calls, 1);
  assert.deepEqual(projection.tags, ["urn:li:tag:PII"]);
});

test("an active remediation journal lease gets a bounded recovery delay", () => {
  const leaseConflict = new RemediationError(
    "EXECUTION_IN_PROGRESS",
    "A prior worker still owns the execution lease."
  );
  assert.equal(retryVisibilitySeconds(leaseConflict), 180);
  for (let receiveCount = 1; receiveCount <= 5; receiveCount += 1) {
    assert.equal(
      shouldFinalizePoisonDelivery(leaseConflict, receiveCount, 5),
      false
    );
  }
  assert.equal(shouldFinalizePoisonDelivery(new Error("transient"), 5, 5), true);
  assert.equal(retryVisibilitySeconds(new Error("transient")), 5);
});

test("worker delivery classifies direct provider HTTP status without unsafe payloads", () => {
  for (const status of [400, 401, 403, 404]) {
    const terminal = Object.assign(new Error("opaque provider failure"), {
      status,
    });
    assert.equal(
      shouldFinalizePoisonDelivery(terminal, 1, 5),
      true,
      `HTTP ${status} must be terminal`
    );
  }

  for (const status of [408, 429, 500, 503]) {
    const retryable = Object.assign(new Error("opaque provider failure"), {
      status,
    });
    assert.equal(
      shouldFinalizePoisonDelivery(retryable, 1, 5),
      false,
      `HTTP ${status} must retry before the delivery cap`
    );
    assert.equal(
      shouldFinalizePoisonDelivery(retryable, 5, 5),
      true,
      `HTTP ${status} must finalize at the delivery cap`
    );
  }

  const taskRoleAuthentication = Object.assign(
    new Error(
      "Unable to mint a valid short-term Bedrock Mantle token from the AWS task role."
    ),
    {
      name: "BedrockMantleAuthenticationError",
      status: 401,
    }
  );
  assert.equal(
    shouldFinalizePoisonDelivery(taskRoleAuthentication, 1, 5),
    true
  );
  const taskRoleProviderOutage = Object.assign(
    new Error(
      "The ECS task-role credential provider is temporarily unavailable for Bedrock Mantle."
    ),
    {
      name: "BedrockMantleTokenProviderUnavailableError",
      retryable: true,
      status: 503,
    }
  );
  assert.equal(
    shouldFinalizePoisonDelivery(taskRoleProviderOutage, 1, 5),
    false
  );
});

test("Dynamo execution claims reconcile transaction cancellations without reasons", async (t) => {
  const binding = {
    approvalId: "approval-transaction-race-0001",
    approvalDecisionDigest: DIGEST,
    idempotencyKey: "execution-transaction-race-0001",
  } as const;
  const canceledWithoutReasons = (): Error =>
    Object.assign(new Error("transaction canceled"), {
      name: "TransactionCanceledException",
      $metadata: { httpStatusCode: 400 },
    });

  await t.test("resolves a concurrently-created valid journal state", async () => {
    let calls = 0;
    const client = {
      async send(command: any): Promise<any> {
        calls += 1;
        if (calls === 1) throw canceledWithoutReasons();
        const pk = command.input.Key.pk.S as string;
        if (pk.startsWith("EXECUTION#")) {
          return {
            Item: {
              status: { S: "IN_PROGRESS" },
              approvalId: { S: binding.approvalId },
              decisionDigest: { S: binding.approvalDecisionDigest },
              fencingToken: { N: "1" },
              leaseExpiresAt: { N: "4102444800" },
            },
          };
        }
        return {
          Item: {
            idempotencyKey: { S: binding.idempotencyKey },
            decisionDigest: { S: binding.approvalDecisionDigest },
          },
        };
      },
    } as unknown as DynamoDBClient;
    const journal = new DynamoExecutionJournal(
      client,
      "archon-idempotency",
      () => new Date("2026-07-23T10:00:00.000Z")
    );

    assert.deepEqual(await journal.claim(binding), {
      disposition: "IN_PROGRESS",
    });
    assert.equal(calls, 3);
  });

  await t.test("classifies an empty consistent read as retryable", async () => {
    let calls = 0;
    const client = {
      async send(): Promise<any> {
        calls += 1;
        if (calls === 1) throw canceledWithoutReasons();
        return {};
      },
    } as unknown as DynamoDBClient;
    const journal = new DynamoExecutionJournal(
      client,
      "archon-idempotency",
      () => new Date("2026-07-23T10:00:00.000Z")
    );

    await assert.rejects(
      journal.claim(binding),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.name, "RetryableExecutionJournalError");
        assert.equal((error as { retryable?: boolean }).retryable, true);
        return true;
      }
    );
    assert.equal(calls, 3);
  });

  await t.test("does not reconcile an explicit non-conditional cancellation", async () => {
    const cancellation = Object.assign(new Error("capacity cancellation"), {
      name: "TransactionCanceledException",
      $metadata: { httpStatusCode: 400 },
      CancellationReasons: [{ Code: "ProvisionedThroughputExceeded" }],
    });
    let calls = 0;
    const client = {
      async send(): Promise<any> {
        calls += 1;
        throw cancellation;
      },
    } as unknown as DynamoDBClient;
    const journal = new DynamoExecutionJournal(
      client,
      "archon-idempotency",
      () => new Date("2026-07-23T10:00:00.000Z")
    );

    await assert.rejects(journal.claim(binding), (error: unknown) => {
      assert.equal(error, cancellation);
      return true;
    });
    assert.equal(calls, 1);
  });
});
