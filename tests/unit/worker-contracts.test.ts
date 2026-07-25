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
