import assert from "node:assert/strict";
import { test } from "node:test";
import type { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  parseQueueMessage,
  WorkerContractError,
} from "../../src/worker/contracts.js";
import { parseTagProjectionResponse } from "../../src/datahub/tag-projection-reader-live.js";
import { RemediationError } from "../../src/remediation/control-loop.js";
import {
  DynamoExecutionJournal,
  retryVisibilitySeconds,
  shouldFinalizePoisonDelivery,
} from "../../src/worker/aws-adapters.js";

const EXECUTION =
  "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0001";
const TOKEN = "opaque-step-functions-task-token-0001";
const DIGEST = `sha256:${"a".repeat(64)}` as `sha256:${string}`;

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

test("direct GMS projection keeps field tag URNs and fails closed on display names", () => {
  const target = {
    entityUrn:
      "urn:li:dataset:(urn:li:dataPlatform:snowflake,customer_pii,PROD)",
    columnPath: "email",
  };
  const projection = parseTagProjectionResponse(
    {
      schemaMetadata: {
        value: {
          fields: [
            {
              fieldPath: "email",
              globalTags: { tags: [{ tag: "urn:li:tag:PII" }] },
            },
          ],
        },
      },
    },
    target
  );
  assert.deepEqual(projection.tags, ["urn:li:tag:PII"]);
  assert.throws(() =>
    parseTagProjectionResponse(
      {
        schemaMetadata: {
          value: {
            fields: [
              {
                fieldPath: "email",
                globalTags: { tags: [{ tag: "PII" }] },
              },
            ],
          },
        },
      },
      target
    )
  );
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
