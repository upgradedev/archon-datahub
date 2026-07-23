import assert from "node:assert/strict";
import { test } from "node:test";
import { parseQueueMessage } from "../../src/worker/contracts.js";

const EXECUTION =
  "arn:aws:states:eu-west-1:111111111111:execution:archon-staging-control-loop:execution-0001";
const TOKEN = "opaque-step-functions-task-token-0001";
const DIGEST = `sha256:${"b".repeat(64)}`;

test("async audit input cannot smuggle a mutation tool, arguments, or credential override", () => {
  for (const injected of [
    { tool: "add_tags" },
    { arguments: { tag_urns: ["urn:li:tag:Attacker"] } },
    { DATAHUB_WRITE_GMS_TOKEN: "stolen" },
  ]) {
    assert.throws(() =>
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
            ...injected,
          },
        })
      )
    );
  }
});

test("remediation rejects a different approval id, arbitrary role, or altered digest", () => {
  const base = {
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
  };
  assert.throws(() =>
    parseQueueMessage(
      "remediation",
      JSON.stringify({
        ...base,
        approvalResult: { ...base.approvalResult, approvalId: "approval-9999" },
      })
    )
  );
  assert.throws(() =>
    parseQueueMessage(
      "remediation",
      JSON.stringify({
        ...base,
        approvalResult: {
          ...base.approvalResult,
          decision: {
            ...base.approvalResult.decision,
            approver: {
              ...base.approvalResult.decision.approver,
              roles: ["DataSteward", "Administrator"],
            },
          },
        },
      })
    )
  );
  assert.throws(() =>
    parseQueueMessage(
      "remediation",
      JSON.stringify({ ...base, planDigest: `${DIGEST}00` })
    )
  );
});
