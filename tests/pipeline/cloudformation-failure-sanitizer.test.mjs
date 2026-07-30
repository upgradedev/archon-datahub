import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  sanitizeCloudFormationFailure,
  serializeCloudFormationFailure,
} from "../../scripts/sanitize-cloudformation-failure.mjs";

function eventDocument(reason, overrides = {}) {
  return {
    StackEvents: [
      {
        LogicalResourceId: "GuardPolicy",
        ResourceStatus: "CREATE_FAILED",
        ResourceStatusReason: reason,
        ResourceType: "AWS::IAM::ManagedPolicy",
        ...overrides,
      },
    ],
  };
}

const options = {
  stackLabel: "staging-iam",
  stackStatus: "ROLLBACK_COMPLETE",
};

test("emits one canonical access-denied diagnostic without the raw reason", () => {
  const rawReason = [
    "Caller is not authorized to perform: ",
    "iam:CreatePolicy",
    " on protected material ",
    ["arn", ":aws:iam::", ["1234", "5678", "9012"].join(""), ":role/example"].join(""),
    " ",
    ["https", "://", "example.invalid/request"].join(""),
  ].join("");
  const diagnostic = sanitizeCloudFormationFailure(eventDocument(rawReason), options);

  assert.deepEqual(Object.keys(diagnostic), [
    "deniedAwsAction",
    "logicalResourceId",
    "rawReasonSha256",
    "reasonCategory",
    "resourceStatus",
    "resourceType",
    "schemaVersion",
    "stackLabel",
    "stackStatus",
  ]);
  assert.equal(diagnostic.deniedAwsAction, "iam:CreatePolicy");
  assert.equal(diagnostic.reasonCategory, "access-denied");
  assert.equal(
    diagnostic.rawReasonSha256,
    createHash("sha256").update(rawReason, "utf8").digest("hex"),
  );
  assert.equal(diagnostic.stackLabel, "staging-iam");
  assert.equal(diagnostic.stackStatus, "ROLLBACK_COMPLETE");
  assert.equal(serializeCloudFormationFailure(diagnostic).endsWith("\n"), true);
});

test("does not emit wildcard or non-denial actions", () => {
  const diagnostic = sanitizeCloudFormationFailure(
    eventDocument("Service quota exceeded while evaluating iam:*"),
    options,
  );
  assert.equal(diagnostic.deniedAwsAction, null);
  assert.equal(diagnostic.reasonCategory, "quota-exceeded");
});

test("selects the newest failed resource event from the bounded event set", () => {
  const document = eventDocument("not authorized to perform: iam:PutRolePolicy");
  document.StackEvents.unshift({
    LogicalResourceId: "FoundationStack",
    ResourceStatus: "ROLLBACK_COMPLETE",
    ResourceStatusReason: "rollback complete",
    ResourceType: "AWS::CloudFormation::Stack",
  });
  const diagnostic = sanitizeCloudFormationFailure(document, options);
  assert.equal(diagnostic.logicalResourceId, "GuardPolicy");
  assert.equal(diagnostic.resourceStatus, "CREATE_FAILED");
});

test("rejects unknown labels, unsafe identities, and oversized event sets", () => {
  assert.throws(() =>
    sanitizeCloudFormationFailure(eventDocument("failed"), {
      ...options,
      stackLabel: "unknown-stack",
    }),
  );
  assert.throws(() =>
    sanitizeCloudFormationFailure(
      eventDocument("failed", { LogicalResourceId: "unsafe/value" }),
      options,
    ),
  );
  assert.throws(() =>
    sanitizeCloudFormationFailure(
      { StackEvents: Array.from({ length: 26 }, () => eventDocument("failed").StackEvents[0]) },
      options,
    ),
  );
});