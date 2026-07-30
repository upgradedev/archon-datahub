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

test("prefers the newest non-dependency root event over newer cancellation", () => {
  const cases = [
    {
      category: "access-denied",
      forbidden: ["Abc123Secret", "TopSecretToken"],
      logicalResourceId: "AccessDeniedRoot",
      reason:
        "Caller is not authorized to perform: iam:Abc123Secret token=TopSecretToken",
    },
    {
      category: "invalid-request",
      forbidden: ["https://private.invalid", "InvalidSecretToken"],
      logicalResourceId: "InvalidRequestRoot",
      reason:
        "Invalid configuration at https://private.invalid token=InvalidSecretToken",
    },
    {
      category: "already-exists",
      forbidden: ["123456789012", "ExistingSecretValue"],
      logicalResourceId: "AlreadyExistsRoot",
      reason:
        "Role arn:aws:iam::123456789012:role/private already exists ExistingSecretValue",
    },
    {
      category: "unknown",
      forbidden: ["UnknownRootSecret"],
      logicalResourceId: "UnknownRoot",
      reason: "Opaque provider root cause marker=UnknownRootSecret",
    },
  ];

  for (const scenario of cases) {
    const document = {
      StackEvents: [
        eventDocument("Resource creation cancelled because a dependency failed to create", {
          LogicalResourceId: "ArchonCdkEdgePolicy",
        }).StackEvents[0],
        eventDocument(scenario.reason, {
          LogicalResourceId: scenario.logicalResourceId,
        }).StackEvents[0],
      ],
    };
    const diagnostic = sanitizeCloudFormationFailure(document, options);
    const canonicalSafeFields = {
      logicalResourceId: scenario.logicalResourceId,
      reasonCategory: scenario.category,
      resourceStatus: "CREATE_FAILED",
      resourceType: "AWS::IAM::ManagedPolicy",
      schemaVersion: "archon.aws-foundation-cfn-failure/v1",
      stackLabel: "staging-iam",
      stackStatus: "ROLLBACK_COMPLETE",
    };

    assert.equal(diagnostic.logicalResourceId, scenario.logicalResourceId);
    assert.equal(diagnostic.reasonCategory, scenario.category);
    assert.equal(
      diagnostic.diagnosticSha256,
      createHash("sha256").update(JSON.stringify(canonicalSafeFields), "utf8").digest("hex"),
    );
    const serialized = serializeCloudFormationFailure(diagnostic);
    assert.equal(serialized.includes("cancelled"), false);
    for (const forbidden of scenario.forbidden) {
      assert.equal(serialized.includes(forbidden), false);
    }
  }
});

test("finds an older root at the end of the 100-event bounded window", () => {
  const newerCancellations = Array.from({ length: 99 }, (_, index) =>
    eventDocument("Resource creation cancelled because a dependency failed to create", {
      LogicalResourceId: `CancelledResource${index}`,
    }).StackEvents[0],
  );
  const document = {
    StackEvents: [
      ...newerCancellations,
      eventDocument(
        "Caller is not authorized to perform: iam:DeepRootSecret token=DeepSecretToken",
        { LogicalResourceId: "DeepRootAccessDenied" },
      ).StackEvents[0],
    ],
  };
  const diagnostic = sanitizeCloudFormationFailure(document, options);
  const serialized = serializeCloudFormationFailure(diagnostic);
  assert.equal(document.StackEvents.length, 100);
  assert.equal(diagnostic.logicalResourceId, "DeepRootAccessDenied");
  assert.equal(diagnostic.reasonCategory, "access-denied");
  assert.equal(serialized.includes("DeepRootSecret"), false);
  assert.equal(serialized.includes("DeepSecretToken"), false);
});
test("falls back to the newest failed event when every failure is a dependency symptom", () => {
  const document = {
    StackEvents: [
      eventDocument("Resource creation cancelled", {
        LogicalResourceId: "NewestCancelledResource",
      }).StackEvents[0],
      eventDocument("Required resource dependency failed to create", {
        LogicalResourceId: "OlderDependencyResource",
      }).StackEvents[0],
    ],
  };
  const diagnostic = sanitizeCloudFormationFailure(document, options);
  assert.equal(diagnostic.logicalResourceId, "NewestCancelledResource");
  assert.equal(diagnostic.reasonCategory, "dependency-failure");
});

test("fails closed when the chosen non-dependency event has an unsafe identity", () => {
  const document = {
    StackEvents: [
      eventDocument("Opaque provider root cause", {
        LogicalResourceId: "unsafe/value",
      }).StackEvents[0],
      eventDocument("not authorized to perform: iam:PutRolePolicy").StackEvents[0],
    ],
  };
  assert.throws(() => sanitizeCloudFormationFailure(document, options));
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
      { StackEvents: Array.from({ length: 101 }, () => eventDocument("failed").StackEvents[0]) },
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
      input: Buffer.alloc(1_048_577, 0x20),
      maxBuffer: 1_048_576,
    },
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "CloudFormation failure sanitization failed\n");
});