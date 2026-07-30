import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  CLI_FAILURE_CODES,
  TARGET,
  buildRecoveryPlan,
  canonicalJson,
  main,
  sanitizedCliFailureCode,
  validateIncidentArtifact,
} from "../../scripts/aws-incident-recovery.mjs";

const validatorCli = fileURLToPath(new URL("../../scripts/aws-incident-recovery.mjs", import.meta.url));
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

test("classifies every incident type, status, and physical-ID combination", () => {
  const cases = [
    {
      expected: null,
      resourceStatus: "CREATE_FAILED",
      resourceType: "AWS::IAM::ManagedPolicy",
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_CREATE_FAILED_PHYSICAL_ID,
      physicalResourceId: "physical-id",
      resourceStatus: "CREATE_FAILED",
      resourceType: "AWS::IAM::ManagedPolicy",
    },
    {
      expected:
        CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID,
      resourceStatus: "DELETE_COMPLETE",
      resourceType: "AWS::IAM::ManagedPolicy",
    },
    {
      expected:
        CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID,
      physicalResourceId: "physical-id",
      resourceStatus: "DELETE_COMPLETE",
      resourceType: "AWS::IAM::ManagedPolicy",
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      resourceStatus: "CREATE_FAILED",
      resourceType: "AWS::IAM::Role",
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_CREATE_FAILED_PHYSICAL_ID,
      physicalResourceId: "physical-id",
      resourceStatus: "CREATE_FAILED",
      resourceType: "AWS::IAM::Role",
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      resourceStatus: "DELETE_COMPLETE",
      resourceType: "AWS::IAM::Role",
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      physicalResourceId: "physical-id",
      resourceStatus: "DELETE_COMPLETE",
      resourceType: "AWS::IAM::Role",
    },
  ];

  for (const testCase of cases) {
    const resources = resourcesResponse();
    const incident = resources.StackResourceSummaries[0];
    incident.ResourceStatus = testCase.resourceStatus;
    incident.ResourceType = testCase.resourceType;
    if (testCase.physicalResourceId !== undefined) {
      incident.PhysicalResourceId = testCase.physicalResourceId;
    }
    if (testCase.expected === null) {
      assert.doesNotThrow(() => build({ resourcesResponse: resources }));
    } else {
      assert.throws(
        () => build({ resourcesResponse: resources }),
        (error) => error.publicCode === testCase.expected
      );
    }
  }
});

test("rejects malformed resource-summary fields instead of treating them as absent", () => {
  const cases = [
    (resource) => {
      resource.ResourceType = 42;
    },
    (resource) => {
      resource.PhysicalResourceId = null;
    },
    (resource) => {
      resource.PhysicalResourceId = "";
    },
  ];
  for (const mutate of cases) {
    const resources = resourcesResponse();
    mutate(resources.StackResourceSummaries[0]);
    assert.throws(
      () => build({ resourcesResponse: resources }),
      (error) =>
        error.publicCode === CLI_FAILURE_CODES.RESOURCE_SUMMARY_SHAPE_INVALID
    );
  }
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
test("CLI exposes only allowlisted failure codes and never raw values or paths", () => {
  const privateMarker = "PRIVATE_RECOVERY_VALUE_7f6c2a";
  const privatePath = `/tmp/${privateMarker}/sealed-input.json`;
  const cases = [
    {
      args: ["unsupported-command", privateMarker],
      expected: CLI_FAILURE_CODES.INVALID_INVOCATION,
    },
    {
      args: ["validate-artifact", privatePath],
      expected: CLI_FAILURE_CODES.ARTIFACT_VALIDATION_FAILED,
    },
    {
      args: [
        "build-plan",
        privatePath,
        privatePath,
        privateMarker,
        privateMarker,
        privateMarker,
        privateMarker,
        privatePath,
        privatePath,
      ],
      expected: CLI_FAILURE_CODES.PLAN_VALIDATION_FAILED,
    },
    {
      args: [
        "rebuild-plan",
        privatePath,
        privateMarker,
        privateMarker,
        privateMarker,
        privateMarker,
        privatePath,
        privatePath,
      ],
      expected: CLI_FAILURE_CODES.PLAN_VALIDATION_FAILED,
    },
  ];

  for (const { args, expected } of cases) {
    const result = spawnSync(process.execPath, [validatorCli, ...args], {
      encoding: "utf8",
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, `::error::${expected}\n`);
    assert.doesNotMatch(result.stderr, /PRIVATE_RECOVERY_VALUE|ENOENT|sealed-input/u);
    assert.equal(result.stderr.includes(privateMarker), false);
    assert.equal(result.stderr.includes(privatePath), false);
  }
});

test("CLI failure-code sanitizer rejects raw and spoofed error properties", () => {
  assert.deepEqual(Object.values(CLI_FAILURE_CODES), [
    "AWS_RECOVERY_ARTIFACT_VALIDATION_FAILED",
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID",
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID",
    "AWS_RECOVERY_INCIDENT_RECORD_NOT_UNIQUE",
    "AWS_RECOVERY_INCIDENT_RESOURCE_TYPE_MISMATCH",
    "AWS_RECOVERY_INVALID_INVOCATION",
    "AWS_RECOVERY_PLAN_VALIDATION_FAILED",
    "AWS_RECOVERY_RESOURCE_CREATE_FAILED_PHYSICAL_ID",
    "AWS_RECOVERY_RESOURCE_STATE_EMPTY",
    "AWS_RECOVERY_RESOURCE_STATE_UNAVAILABLE",
    "AWS_RECOVERY_RESOURCE_SUMMARY_SHAPE_INVALID",
    "AWS_RECOVERY_RESOURCE_UNSUPPORTED_STATUS",
    "AWS_RECOVERY_STACK_AUTHORITY_INVALID",
    "AWS_RECOVERY_STACK_ID_INVALID",
    "AWS_RECOVERY_STACK_NESTING_INVALID",
    "AWS_RECOVERY_STACK_STATUS_INVALID",
    "AWS_RECOVERY_STACK_TAGS_INVALID",
    "AWS_RECOVERY_STACK_TERMINATION_PROTECTION_INVALID",
    "AWS_RECOVERY_TEMPLATE_IDENTITY_INVALID",
    "AWS_RECOVERY_TTL_INVALID",
    "AWS_RECOVERY_VALIDATOR_FAILED",
  ]);
  const privateMarker = "PRIVATE_SANITIZER_MARKER";
  const spoofed = new Error(privateMarker);
  spoofed.publicCode = CLI_FAILURE_CODES.PLAN_VALIDATION_FAILED;
  for (const error of [
    new Error(privateMarker),
    { code: CLI_FAILURE_CODES.ARTIFACT_VALIDATION_FAILED, path: privateMarker },
    spoofed,
  ]) {
    assert.equal(
      sanitizedCliFailureCode(error),
      CLI_FAILURE_CODES.VALIDATOR_FAILED
    );
  }

  let invocationFailure;
  try {
    main(["unsupported-command", privateMarker]);
  } catch (error) {
    invocationFailure = error;
  }
  assert.equal(
    sanitizedCliFailureCode(invocationFailure),
    CLI_FAILURE_CODES.INVALID_INVOCATION
  );
});
test("CLI maps every plan invariant to an exact sanitized code", () => {
  const privateMarker = "PRIVATE_PLAN_INVARIANT_4b91";
  const root = mkdtempSync(join(tmpdir(), `archon-${privateMarker}-`));
  const stackPath = join(root, "stack.json");
  const resourcesPath = join(root, "resources.json");
  const planPath = join(root, "plan.json");
  const policyPath = join(root, "policy.json");
  const liveExpiry = new Date(Date.now() + 5 * 60 * 1_000)
    .toISOString()
    .replace(/\.\d{3}Z$/u, "Z");
  const cases = [
    {
      expected: CLI_FAILURE_CODES.STACK_ID_INVALID,
      stackOverrides: { StackId: privateMarker },
    },
    {
      expected: CLI_FAILURE_CODES.STACK_STATUS_INVALID,
      stackOverrides: { StackStatus: `DELETE_FAILED_${privateMarker}` },
    },
    {
      expected: CLI_FAILURE_CODES.STACK_AUTHORITY_INVALID,
      stackOverrides: { RoleARN: privateMarker },
    },
    {
      expected: CLI_FAILURE_CODES.STACK_NESTING_INVALID,
      stackOverrides: { ParentId: privateMarker },
    },
    {
      expected: CLI_FAILURE_CODES.STACK_TERMINATION_PROTECTION_INVALID,
      stackOverrides: { EnableTerminationProtection: true },
    },
    {
      expected: CLI_FAILURE_CODES.STACK_TAGS_INVALID,
      stackOverrides: { Tags: [{ Key: "Application", Value: privateMarker }] },
    },
    {
      expected: CLI_FAILURE_CODES.TEMPLATE_IDENTITY_INVALID,
      templateSha: privateMarker,
    },
    {
      expected: CLI_FAILURE_CODES.TTL_INVALID,
      expiresAt: privateMarker,
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_STATE_UNAVAILABLE,
      resources: {},
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_STATE_EMPTY,
      resources: { StackResourceSummaries: [] },
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_UNSUPPORTED_STATUS,
      mutateResources(resources) {
        resources.StackResourceSummaries[1].ResourceStatus =
          `UPDATE_FAILED_${privateMarker}`;
      },
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_CREATE_FAILED_PHYSICAL_ID,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].PhysicalResourceId = privateMarker;
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].ResourceType = privateMarker;
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].ResourceStatus = "DELETE_COMPLETE";
        resources.StackResourceSummaries[0].ResourceType = privateMarker;
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].PhysicalResourceId = privateMarker;
        resources.StackResourceSummaries[0].ResourceStatus = "DELETE_COMPLETE";
        resources.StackResourceSummaries[0].ResourceType = privateMarker;
      },
    },
    {
      expected:
        CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].ResourceStatus = "DELETE_COMPLETE";
      },
    },
    {
      expected:
        CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].PhysicalResourceId = privateMarker;
        resources.StackResourceSummaries[0].ResourceStatus = "DELETE_COMPLETE";
      },
    },
    {
      expected: CLI_FAILURE_CODES.RESOURCE_SUMMARY_SHAPE_INVALID,
      mutateResources(resources) {
        resources.StackResourceSummaries[0].PhysicalResourceId = "";
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RECORD_NOT_UNIQUE,
      mutateResources(resources) {
        resources.StackResourceSummaries.push({
          ...resources.StackResourceSummaries[0],
        });
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RECORD_NOT_UNIQUE,
      mutateResources(resources) {
        resources.StackResourceSummaries.push({
          ...resources.StackResourceSummaries[0],
          ResourceType: privateMarker,
        });
      },
    },
    {
      expected: CLI_FAILURE_CODES.INCIDENT_RECORD_NOT_UNIQUE,
      mutateResources(resources) {
        resources.StackResourceSummaries.unshift({
          ...resources.StackResourceSummaries[0],
          ResourceType: privateMarker,
        });
      },
    },
  ];

  try {
    for (const testCase of cases) {
      const stack = stackResponse(testCase.stackOverrides);
      const resources = testCase.resources ?? resourcesResponse();
      testCase.mutateResources?.(resources);
      writeFileSync(stackPath, JSON.stringify(stack), "utf8");
      writeFileSync(resourcesPath, JSON.stringify(resources), "utf8");
      const result = spawnSync(
        process.execPath,
        [
          validatorCli,
          "build-plan",
          stackPath,
          resourcesPath,
          testCase.templateSha ?? TARGET.sourceTemplateSemanticSha256,
          accountId,
          testCase.expiresAt ?? liveExpiry,
          controlPlaneSha,
          planPath,
          policyPath,
        ],
        {
          encoding: "utf8",
          env: { ...process.env, GITHUB_ACTIONS: "true", RUNNER_TEMP: root },
        }
      );
      assert.equal(result.status, 1);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, `::error::${testCase.expected}\n`);
      assert.equal(result.stderr.includes(privateMarker), false);
      assert.doesNotMatch(
        result.stderr,
        /DELETE_FAILED|PhysicalResourceId|UPDATE_FAILED|ENOENT/u
      );
      assert.equal(existsSync(planPath), false);
      assert.equal(existsSync(policyPath), false);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
