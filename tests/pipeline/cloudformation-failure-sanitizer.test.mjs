import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
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

test("emits one canonical diagnostic without raw action details", () => {
  const rawReason = [
    "Caller is not authorized to perform: iam:Abc123Secret; ",
    "requestToken=TopSecretValue",
  ].join("");
  const diagnostic = sanitizeCloudFormationFailure(eventDocument(rawReason), options);
  const canonicalSafeFields = {
    logicalResourceId: "GuardPolicy",
    reasonCategory: "access-denied",
    resourceStatus: "CREATE_FAILED",
    resourceType: "AWS::IAM::ManagedPolicy",
    schemaVersion: "archon.aws-foundation-cfn-failure/v1",
    stackLabel: "staging-iam",
    stackStatus: "ROLLBACK_COMPLETE",
  };

  assert.deepEqual(Object.keys(diagnostic), [
    "diagnosticSha256",
    "logicalResourceId",
    "reasonCategory",
    "resourceStatus",
    "resourceType",
    "schemaVersion",
    "stackLabel",
    "stackStatus",
  ]);
  assert.equal(diagnostic.reasonCategory, "access-denied");
  assert.equal(
    diagnostic.diagnosticSha256,
    createHash("sha256").update(JSON.stringify(canonicalSafeFields), "utf8").digest("hex"),
  );
  const serialized = serializeCloudFormationFailure(diagnostic);
  assert.equal(serialized, `${JSON.stringify(diagnostic)}\n`);
  assert.equal(serialized.includes("iam:Abc123Secret"), false);
  assert.equal(serialized.includes("TopSecretValue"), false);
});

test("raw reason variants cannot alter a diagnostic beyond the safe category", () => {
  const first = sanitizeCloudFormationFailure(
    eventDocument("Not authorized to perform: iam:Abc123Secret"),
    options,
  );
  const second = sanitizeCloudFormationFailure(
    eventDocument("AccessDenied password=DifferentSecretValue"),
    options,
  );
  assert.deepEqual(first, second);
});

test("does not emit wildcard or non-denial action details", () => {
  const diagnostic = sanitizeCloudFormationFailure(
    eventDocument("Service quota exceeded while evaluating iam:*"),
    options,
  );
  assert.equal(diagnostic.reasonCategory, "quota-exceeded");
  assert.equal(serializeCloudFormationFailure(diagnostic).includes("iam:*"), false);
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

test("fails closed for missing or non-string failure reasons", () => {
  assert.throws(() =>
    sanitizeCloudFormationFailure(eventDocument(undefined), options),
  );
  assert.throws(() =>
    sanitizeCloudFormationFailure(eventDocument({ reason: "hidden" }), options),
  );
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

test("CLI rejects MAX+1 bytes without stdout or raw stderr", () => {
  const sanitizerPath = fileURLToPath(
    new URL("../../scripts/sanitize-cloudformation-failure.mjs", import.meta.url),
  );
  const result = spawnSync(
    process.execPath,
    [sanitizerPath, "--stack-label", "staging-iam", "--stack-status", "ROLLBACK_COMPLETE"],
    {
      encoding: "utf8",
      input: Buffer.alloc(262_145, 0x20),
      maxBuffer: 1_048_576,
    },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "CloudFormation failure sanitization failed\n");
});