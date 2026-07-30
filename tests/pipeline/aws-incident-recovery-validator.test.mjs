import assert from "node:assert/strict";
import {
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  TARGET,
  buildRecoveryPlan,
  canonicalJson,
  validateIncidentArtifact,
} from "../../scripts/aws-incident-recovery.mjs";

const accountId = "123456789012";
const controlPlaneSha = "324073874b862e08bf8d80fa70709165cee86851";
const expiresAt = "2026-07-30T14:20:00Z";
const now = new Date("2026-07-30T14:00:00Z");
const stackId =
  "arn:aws:cloudformation:eu-west-1:123456789012:stack/Archon-Staging-IAM-Foundation/11111111-2222-3333-4444-555555555555";
const failurePayload =
  '{"diagnosticSha256":"5929dcc16e72a6bee58b6146b1f10d1948caf1f225552922d61177f518c78625","logicalResourceId":"ArchonCdkGuardPolicy","reasonCategory":"invalid-request","resourceStatus":"CREATE_FAILED","resourceType":"AWS::IAM::ManagedPolicy","schemaVersion":"archon.aws-foundation-cfn-failure/v1","stackLabel":"staging-iam","stackStatus":"ROLLBACK_COMPLETE"}\n';
const checksumManifest =
  "187d4cf683a61a778feec2051f1ef5c99b60cc58344edbf1a7d0189f28c67442  cfn-failure.json\n";

function artifactFixture() {
  const root = mkdtempSync(join(tmpdir(), "archon-incident-artifact-"));
  writeFileSync(join(root, "cfn-failure.json"), failurePayload, "utf8");
  writeFileSync(join(root, "SHA256SUMS"), checksumManifest, "utf8");
  return root;
}

function stackResponse(overrides = {}) {
  return {
    Stacks: [
      {
        EnableTerminationProtection: false,
        StackId: stackId,
        StackName: TARGET.stackName,
        StackStatus: "ROLLBACK_COMPLETE",
        Tags: Object.entries(TARGET.tags).map(([Key, Value]) => ({ Key, Value })),
        ...overrides,
      },
    ],
  };
}

function resourcesResponse(overrides = {}) {
  return {
    StackResourceSummaries: [
      {
        LogicalResourceId: "ArchonCdkGuardPolicy",
        ResourceStatus: "CREATE_FAILED",
        ResourceType: "AWS::IAM::ManagedPolicy",
      },
      {
        LogicalResourceId: "ArchonCdkIdentityPolicy",
        PhysicalResourceId: "deleted-resource-identity-is-not-retained",
        ResourceStatus: "DELETE_COMPLETE",
        ResourceType: "AWS::IAM::ManagedPolicy",
      },
    ],
    ...overrides,
  };
}

function build(overrides = {}) {
  return buildRecoveryPlan({
    accountId,
    controlPlaneSha,
    expiresAt,
    now,
    resourcesResponse: resourcesResponse(),
    sourceTemplateSemanticSha256: TARGET.sourceTemplateSemanticSha256,
    stackResponse: stackResponse(),
    ...overrides,
  });
}

test("accepts only the exact canonical incident artifact", () => {
  const root = artifactFixture();
  try {
    assert.deepEqual(validateIncidentArtifact(root), {
      failurePayloadSha256:
        "sha256:187d4cf683a61a778feec2051f1ef5c99b60cc58344edbf1a7d0189f28c67442",
      inventorySha256:
        "sha256:eab331323a1b4e40e28b5bfef5e7b502ca3b44fe183550362070b469c6abbdef",
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects extra files, links, checksum drift, and noncanonical payloads", () => {
  const cases = [
    (root) => writeFileSync(join(root, "extra"), "x", "utf8"),
    (root) => {
      rmSync(join(root, "cfn-failure.json"));
      symlinkSync(join(root, "SHA256SUMS"), join(root, "cfn-failure.json"));
    },
    (root) => writeFileSync(join(root, "SHA256SUMS"), checksumManifest.replace("187d", "287d"), "utf8"),
    (root) => writeFileSync(join(root, "cfn-failure.json"), `${JSON.stringify(JSON.parse(failurePayload), null, 2)}\n`, "utf8"),
  ];
  for (const mutate of cases) {
    const root = artifactFixture();
    try {
      mutate(root);
      assert.throws(() => validateIncidentArtifact(root));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("seals one exact expiring read and one exact mutating DeleteStack permission", () => {
  const result = build();
  assert.match(result.planDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(result.resourceStateSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(result.plan.target.stackId, stackId);
  assert.equal(result.plan.target.resourceStateSha256, result.resourceStateSha256);
  const exactConditions = {
    DateLessThan: { "aws:CurrentTime": expiresAt },
    StringEquals: {
      "aws:RequestedRegion": "eu-west-1",
      "aws:ResourceTag/Application": "archon-datahub",
      "aws:ResourceTag/Environment": "staging",
      "aws:ResourceTag/ManagedBy": "github-actions",
      "aws:ResourceTag/Purpose": "stage-iam-foundation",
    },
  };
  assert.deepEqual(result.policyDocument, {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadExactSealedIncidentStackBeforeExpiry",
        Effect: "Allow",
        Action: "cloudformation:DescribeStacks",
        Resource: stackId,
        Condition: exactConditions,
      },
      {
        Sid: "DeleteExactSealedIncidentStackBeforeExpiry",
        Effect: "Allow",
        Action: "cloudformation:DeleteStack",
        Resource: stackId,
        Condition: {
          ...exactConditions,
          Null: { "cloudformation:RoleArn": "true" },
        },
      },
    ],
  });
  assert.deepEqual(result.plan.delete, {
    action: "cloudformation:DeleteStack",
    clientRequestToken: `archon-30546241677-a1-${controlPlaneSha.slice(0, 12)}`,
    deletionMode: "STANDARD",
    deploymentConfigOverride: false,
    retainResources: false,
    roleOverride: false,
  });
});

test("delete-stage reconstruction preserves the exact private plan from sealed digests", () => {
  const prepared = build();
  const reconstructed = buildRecoveryPlan({
    accountId,
    controlPlaneSha,
    expiresAt,
    now,
    preparedResourceStateSha256: prepared.resourceStateSha256,
    sourceTemplateSemanticSha256: TARGET.sourceTemplateSemanticSha256,
    stackResponse: stackResponse(),
  });
  assert.equal(reconstructed.planDigest, prepared.planDigest);
  assert.equal(canonicalJson(reconstructed.plan), canonicalJson(prepared.plan));
  assert.equal(reconstructed.policyDocumentSha256, prepared.policyDocumentSha256);
});

test("fails closed for every surviving or non-create failed resource state", () => {
  for (const status of [
    "CREATE_COMPLETE",
    "UPDATE_FAILED",
    "DELETE_FAILED",
    "UPDATE_ROLLBACK_FAILED",
  ]) {
    const resources = resourcesResponse();
    resources.StackResourceSummaries[1] = {
      LogicalResourceId: "UnexpectedResource",
      ResourceStatus: status,
      ResourceType: "AWS::IAM::Role",
    };
    assert.throws(() => build({ resourcesResponse: resources }));
  }
  const physicalCreateFailure = resourcesResponse();
  physicalCreateFailure.StackResourceSummaries[0].PhysicalResourceId = "survivor";
  assert.throws(() => build({ resourcesResponse: physicalCreateFailure }));
});

test("fails closed on target identity, authority, tags, source, and TTL drift", () => {
  const invalidStacks = [
    { StackStatus: "DELETE_FAILED" },
    { RoleARN: "arn:aws:iam::123456789012:role/unreviewed" },
    { ParentId: "parent" },
    { RootId: "root" },
    { EnableTerminationProtection: true },
    { StackName: "Archon-production" },
    { Tags: [{ Key: "Application", Value: "archon-datahub" }] },
  ];
  for (const invalid of invalidStacks) {
    assert.throws(() => build({ stackResponse: stackResponse(invalid) }));
  }
  assert.throws(() =>
    build({ sourceTemplateSemanticSha256: "0".repeat(64) })
  );
  assert.throws(() =>
    build({ expiresAt: "2026-07-30T13:59:59Z" })
  );
  assert.throws(() =>
    build({ expiresAt: "2026-07-30T14:30:01Z" })
  );
});


test("rejects malformed or differently bound stack ARNs", () => {
  const invalidStackIds = [
    stackId.replace(":eu-west-1:", ":us-east-1:"),
    stackId.replace(accountId, "210987654321"),
    stackId.replace(TARGET.stackName, "Archon-production"),
    `arn:aws:cloudformation:eu-west-1:${accountId}:stack/${TARGET.stackName}/not-a-uuid`,
    `${stackId}/extra`,
  ];
  for (const invalidStackId of invalidStackIds) {
    assert.throws(() =>
      build({ stackResponse: stackResponse({ StackId: invalidStackId }) })
    );
  }
});

test("requires exactly one target stack and one incident resource record", () => {
  assert.throws(() => build({ stackResponse: { Stacks: [] } }));
  const duplicateStacks = stackResponse();
  duplicateStacks.Stacks.push({ ...duplicateStacks.Stacks[0] });
  assert.throws(() => build({ stackResponse: duplicateStacks }));

  const missingIncident = resourcesResponse();
  missingIncident.StackResourceSummaries.shift();
  assert.throws(() => build({ resourcesResponse: missingIncident }));

  const duplicateIncident = resourcesResponse();
  duplicateIncident.StackResourceSummaries.push({
    ...duplicateIncident.StackResourceSummaries[0],
  });
  assert.throws(() => build({ resourcesResponse: duplicateIncident }));
});

test("rejects malformed account and control-plane identities", () => {
  for (const invalidAccountId of ["123", "12345678901x", "1234567890123"]) {
    assert.throws(() => build({ accountId: invalidAccountId }));
  }
  for (const invalidControlPlaneSha of [
    "",
    "0".repeat(39),
    "0".repeat(41),
    "A".repeat(40),
  ]) {
    assert.throws(() => build({ controlPlaneSha: invalidControlPlaneSha }));
  }
});
test("rejects invalid prepared resource digests during delete reconstruction", () => {
  for (const digest of ["", "sha256:*", `sha256:${"0".repeat(63)}`]) {
    assert.throws(() =>
      buildRecoveryPlan({
        accountId,
        controlPlaneSha,
        expiresAt,
        now,
        preparedResourceStateSha256: digest,
        sourceTemplateSemanticSha256: TARGET.sourceTemplateSemanticSha256,
        stackResponse: stackResponse(),
      })
    );
  }
});