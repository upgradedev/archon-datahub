#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  chmodSync,
  lstatSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { isAbsolute, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

export const INCIDENT = Object.freeze({
  artifactDigest:
    "sha256:7aa20586b970ac938fba9299e0c3c2538482b92086db811ea583f84bd3b02e24",
  artifactId: "8760846578",
  artifactName:
    "aws-foundation-failure-aea65845e3a9456403a7fb6e9f338e4c14c0b781-30546241677-1",
  artifactSizeBytes: 697,
  controlPlaneSha: "aea65845e3a9456403a7fb6e9f338e4c14c0b781",
  runAttempt: "1",
  runId: "30546241677",
  workflowId: 323358060,
});

export const TARGET = Object.freeze({
  label: "staging-iam",
  region: "eu-west-1",
  sourceTemplateSemanticSha256:
    "80a2b02326bbaa3ae145d0fff52cc1c20f3a330d4ef5c7fa2d816182f7c2b825",
  stackName: "Archon-Staging-IAM-Foundation",
  tags: Object.freeze({
    Application: "archon-datahub",
    Environment: "staging",
    ManagedBy: "github-actions",
    Purpose: "stage-iam-foundation",
  }),
});

export const RECOVERY = Object.freeze({
  basePolicyName: "archon-staging-stack-read",
  environment: "governed-canary-recovery",
  maximumTtlSeconds: 1_800,
  minimumRemainingTtlSeconds: 30,
  policyName: "archon-incident-30546241677-delete",
  roleName: "archon-datahub-github-governed-canary-recovery",
  roleStackName: "Archon-Governed-Canary-Roles",
});

const EXPECTED_FAILURE = Object.freeze({
  diagnosticSha256:
    "5929dcc16e72a6bee58b6146b1f10d1948caf1f225552922d61177f518c78625",
  logicalResourceId: "ArchonCdkGuardPolicy",
  reasonCategory: "invalid-request",
  resourceStatus: "CREATE_FAILED",
  resourceType: "AWS::IAM::ManagedPolicy",
  schemaVersion: "archon.aws-foundation-cfn-failure/v1",
  stackLabel: "staging-iam",
  stackStatus: "ROLLBACK_COMPLETE",
});
const EXPECTED_FAILURE_SHA256 =
  "187d4cf683a61a778feec2051f1ef5c99b60cc58344edbf1a7d0189f28c67442";
const EXPECTED_SUMS_SHA256 =
  "9ecfdff27c6de11ab7403ad75780a7fae3339efe05684c6b3ec3185be6a52703";
const EXACT_INVENTORY = Object.freeze(["SHA256SUMS", "cfn-failure.json"]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const CONTROL_PLANE_PATTERN = /^[a-f0-9]{40}$/u;
const ACCOUNT_PATTERN = /^[0-9]{12}$/u;
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;

export const CLI_FAILURE_CODES = Object.freeze({
  ARTIFACT_VALIDATION_FAILED: "AWS_RECOVERY_ARTIFACT_VALIDATION_FAILED",
  INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID:
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID",
  INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID:
    "AWS_RECOVERY_INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID",
  INCIDENT_RECORD_NOT_UNIQUE: "AWS_RECOVERY_INCIDENT_RECORD_NOT_UNIQUE",
  INCIDENT_RESOURCE_TYPE_MISMATCH:
    "AWS_RECOVERY_INCIDENT_RESOURCE_TYPE_MISMATCH",
  INVALID_INVOCATION: "AWS_RECOVERY_INVALID_INVOCATION",
  PLAN_VALIDATION_FAILED: "AWS_RECOVERY_PLAN_VALIDATION_FAILED",
  RESOURCE_CREATE_FAILED_PHYSICAL_ID:
    "AWS_RECOVERY_RESOURCE_CREATE_FAILED_PHYSICAL_ID",
  RESOURCE_STATE_EMPTY: "AWS_RECOVERY_RESOURCE_STATE_EMPTY",
  RESOURCE_STATE_UNAVAILABLE: "AWS_RECOVERY_RESOURCE_STATE_UNAVAILABLE",
  RESOURCE_SUMMARY_SHAPE_INVALID:
    "AWS_RECOVERY_RESOURCE_SUMMARY_SHAPE_INVALID",
  RESOURCE_UNSUPPORTED_STATUS: "AWS_RECOVERY_RESOURCE_UNSUPPORTED_STATUS",
  STACK_AUTHORITY_INVALID: "AWS_RECOVERY_STACK_AUTHORITY_INVALID",
  STACK_ID_INVALID: "AWS_RECOVERY_STACK_ID_INVALID",
  STACK_NESTING_INVALID: "AWS_RECOVERY_STACK_NESTING_INVALID",
  STACK_STATUS_INVALID: "AWS_RECOVERY_STACK_STATUS_INVALID",
  STACK_TAGS_INVALID: "AWS_RECOVERY_STACK_TAGS_INVALID",
  STACK_TERMINATION_PROTECTION_INVALID:
    "AWS_RECOVERY_STACK_TERMINATION_PROTECTION_INVALID",
  TEMPLATE_IDENTITY_INVALID: "AWS_RECOVERY_TEMPLATE_IDENTITY_INVALID",
  TTL_INVALID: "AWS_RECOVERY_TTL_INVALID",
  VALIDATOR_FAILED: "AWS_RECOVERY_VALIDATOR_FAILED",
});
const CLI_FAILURE_CODE_ALLOWLIST = new Set(Object.values(CLI_FAILURE_CODES));

class CliFailure extends Error {
  constructor(publicCode) {
    super(publicCode);
    this.name = "CliFailure";
    this.publicCode = publicCode;
  }
}

class PlanInvariantError extends Error {
  constructor(message, publicCode) {
    super(message);
    this.name = "PlanInvariantError";
    this.publicCode = publicCode;
  }
}

function withCliFailureCode(publicCode, action) {
  try {
    return action();
  } catch (error) {
    const resolvedCode =
      error instanceof PlanInvariantError &&
      CLI_FAILURE_CODE_ALLOWLIST.has(error.publicCode)
        ? error.publicCode
        : publicCode;
    throw new CliFailure(resolvedCode);
  }
}
export function sanitizedCliFailureCode(error) {
  if (
    error instanceof CliFailure &&
    CLI_FAILURE_CODE_ALLOWLIST.has(error.publicCode)
  ) {
    return error.publicCode;
  }
  return CLI_FAILURE_CODES.VALIDATOR_FAILED;
}

function invariant(value, message, publicCode) {
  if (!value) {
    if (publicCode !== undefined) {
      throw new PlanInvariantError(message, publicCode);
    }
    throw new Error(message);
  }
}

export function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function exactKeys(value, expected, label, publicCode) {
  invariant(
    value !== null && typeof value === "object",
    `${label} is not an object`,
    publicCode
  );
  invariant(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    `${label} has an unexpected shape`,
    publicCode
  );
}

function safeRegularFile(path, label) {
  const stat = lstatSync(path);
  invariant(!stat.isSymbolicLink(), `${label} must not be a symlink`);
  invariant(stat.isFile(), `${label} must be a regular file`);
}

export function validateIncidentArtifact(directory) {
  const root = lstatSync(directory);
  invariant(root.isDirectory() && !root.isSymbolicLink(), "artifact root is unsafe");
  const entries = readdirSync(directory, { withFileTypes: true });
  invariant(
    canonicalJson(entries.map((entry) => entry.name).sort()) ===
      canonicalJson(EXACT_INVENTORY),
    "artifact inventory differs from the sealed incident"
  );
  for (const entry of entries) {
    invariant(entry.isFile() && !entry.isSymbolicLink(), "artifact entry is unsafe");
    safeRegularFile(resolve(directory, entry.name), entry.name);
  }

  const sumsPath = resolve(directory, "SHA256SUMS");
  const failurePath = resolve(directory, "cfn-failure.json");
  const sums = readFileSync(sumsPath, "utf8");
  const failure = readFileSync(failurePath, "utf8");
  invariant(sha256(sums) === EXPECTED_SUMS_SHA256, "checksum manifest identity differs");
  invariant(
    sums === `${EXPECTED_FAILURE_SHA256}  cfn-failure.json\n`,
    "checksum manifest is not exact"
  );
  invariant(sha256(failure) === EXPECTED_FAILURE_SHA256, "failure payload checksum differs");

  let parsed;
  try {
    parsed = JSON.parse(failure);
  } catch {
    throw new Error("failure payload is not JSON");
  }
  exactKeys(parsed, Object.keys(EXPECTED_FAILURE), "failure payload");
  invariant(
    `${canonicalJson(parsed)}\n` === failure,
    "failure payload is not canonical JSON"
  );
  invariant(
    canonicalJson(parsed) === canonicalJson(EXPECTED_FAILURE),
    "failure payload does not describe the sealed incident"
  );
  const diagnosticFields = { ...parsed };
  delete diagnosticFields.diagnosticSha256;
  invariant(
    sha256(canonicalJson(diagnosticFields)) === parsed.diagnosticSha256,
    "diagnostic digest is invalid"
  );
  return Object.freeze({
    failurePayloadSha256: `sha256:${EXPECTED_FAILURE_SHA256}`,
    inventorySha256: `sha256:${sha256(canonicalJson(EXACT_INVENTORY))}`,
  });
}

function exactTags(tags) {
  const code = CLI_FAILURE_CODES.STACK_TAGS_INVALID;
  invariant(Array.isArray(tags), "stack tags are unavailable", code);
  const observed = {};
  for (const tag of tags) {
    exactKeys(tag, ["Key", "Value"], "stack tag", code);
    invariant(
      typeof tag.Key === "string" && typeof tag.Value === "string",
      "stack tag is invalid",
      code
    );
    invariant(!Object.hasOwn(observed, tag.Key), "stack tag key is duplicated", code);
    observed[tag.Key] = tag.Value;
  }
  invariant(
    canonicalJson(observed) === canonicalJson(TARGET.tags),
    "stack tags differ",
    code
  );
}
function validateResourceSummaries(resources) {
  invariant(
    Array.isArray(resources.StackResourceSummaries),
    "stack resources are unavailable",
    CLI_FAILURE_CODES.RESOURCE_STATE_UNAVAILABLE
  );
  invariant(
    resources.StackResourceSummaries.length > 0,
    "stack resource inventory is empty",
    CLI_FAILURE_CODES.RESOURCE_STATE_EMPTY
  );
  const sanitized = resources.StackResourceSummaries.map((resource) => {
    const shapeCode = CLI_FAILURE_CODES.RESOURCE_SUMMARY_SHAPE_INVALID;
    invariant(
      resource !== null && typeof resource === "object" && !Array.isArray(resource),
      "a stack resource summary has an invalid shape",
      shapeCode
    );
    for (const field of ["LogicalResourceId", "ResourceStatus", "ResourceType"]) {
      invariant(
        typeof resource[field] === "string" && resource[field].length > 0,
        "a stack resource summary field is invalid",
        shapeCode
      );
    }
    const hasPhysicalResourceId = Object.hasOwn(resource, "PhysicalResourceId");
    invariant(
      !hasPhysicalResourceId ||
        (typeof resource.PhysicalResourceId === "string" &&
          resource.PhysicalResourceId.length > 0),
      "a stack resource physical ID is invalid",
      shapeCode
    );
    const isDeleted = resource.ResourceStatus === "DELETE_COMPLETE";
    const isCreateFailed = resource.ResourceStatus === "CREATE_FAILED";
    invariant(
      !(isCreateFailed && hasPhysicalResourceId),
      "a CREATE_FAILED resource has a physical ID",
      CLI_FAILURE_CODES.RESOURCE_CREATE_FAILED_PHYSICAL_ID
    );
    invariant(
      isDeleted || isCreateFailed,
      "an unsupported stack resource status was observed",
      CLI_FAILURE_CODES.RESOURCE_UNSUPPORTED_STATUS
    );
    return {
      hasPhysicalResourceId,
      logicalResourceId: resource.LogicalResourceId,
      resourceStatus: resource.ResourceStatus,
      resourceType: resource.ResourceType,
    };
  });

  const incidentRecords = sanitized.filter(
    (resource) =>
      resource.logicalResourceId === EXPECTED_FAILURE.logicalResourceId
  );
  invariant(
    incidentRecords.length === 1,
    "the exact incident resource record is not unique",
    CLI_FAILURE_CODES.INCIDENT_RECORD_NOT_UNIQUE
  );
  const incidentRecord = incidentRecords[0];
  invariant(
    incidentRecord.resourceType === EXPECTED_FAILURE.resourceType,
    "the incident resource type differs",
    CLI_FAILURE_CODES.INCIDENT_RESOURCE_TYPE_MISMATCH
  );
  if (incidentRecord.resourceStatus === "DELETE_COMPLETE") {
    invariant(
      !incidentRecord.hasPhysicalResourceId,
      "the DELETE_COMPLETE incident resource retains a physical ID",
      CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_WITH_PHYSICAL_ID
    );
    invariant(
      false,
      "the incident resource is DELETE_COMPLETE without a physical ID",
      CLI_FAILURE_CODES.INCIDENT_DELETE_COMPLETE_NO_PHYSICAL_ID
    );
  }

  return sanitized.sort((left, right) =>
    canonicalJson(left).localeCompare(canonicalJson(right), "en")
  );
}
function parseExpiry(expiresAt, now) {
  const code = CLI_FAILURE_CODES.TTL_INVALID;
  invariant(ISO_UTC_PATTERN.test(expiresAt), "policy expiry is not canonical UTC", code);
  const expiryMs = Date.parse(expiresAt);
  invariant(Number.isFinite(expiryMs), "policy expiry is invalid", code);
  const remainingSeconds = Math.floor((expiryMs - now.getTime()) / 1_000);
  invariant(
    remainingSeconds >= RECOVERY.minimumRemainingTtlSeconds,
    "temporary authorization is expired or too close to expiry",
    code
  );
  invariant(
    remainingSeconds <= RECOVERY.maximumTtlSeconds,
    "temporary authorization exceeds the reviewed TTL",
    code
  );
}
export function buildRecoveryPlan({
  accountId,
  controlPlaneSha,
  expiresAt,
  now = new Date(),
  preparedResourceStateSha256,
  resourcesResponse,
  sourceTemplateSemanticSha256,
  stackResponse,
}) {
  invariant(ACCOUNT_PATTERN.test(accountId), "account identity is invalid");
  invariant(CONTROL_PLANE_PATTERN.test(controlPlaneSha), "control-plane SHA is invalid");
  invariant(
    sourceTemplateSemanticSha256 === TARGET.sourceTemplateSemanticSha256,
    "deployed source template identity differs",
    CLI_FAILURE_CODES.TEMPLATE_IDENTITY_INVALID
  );
  parseExpiry(expiresAt, now);
  invariant(
    Array.isArray(stackResponse.Stacks) && stackResponse.Stacks.length === 1,
    "target stack is not unique",
    CLI_FAILURE_CODES.STACK_ID_INVALID
  );
  const stack = stackResponse.Stacks[0];
  invariant(
    stack.StackName === TARGET.stackName,
    "target stack name differs",
    CLI_FAILURE_CODES.STACK_ID_INVALID
  );
  const expectedStackIdPrefix =
    `arn:aws:cloudformation:${TARGET.region}:${accountId}:stack/${TARGET.stackName}/`;
  const stackIdSuffix =
    typeof stack.StackId === "string" && stack.StackId.startsWith(expectedStackIdPrefix)
      ? stack.StackId.slice(expectedStackIdPrefix.length)
      : "";
  invariant(
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(stackIdSuffix),
    "target stack ID is invalid",
    CLI_FAILURE_CODES.STACK_ID_INVALID
  );
  invariant(
    stack.StackStatus === "ROLLBACK_COMPLETE",
    "target stack status is not recoverable",
    CLI_FAILURE_CODES.STACK_STATUS_INVALID
  );
  invariant(
    stack.RoleARN == null,
    "target stack has a service role",
    CLI_FAILURE_CODES.STACK_AUTHORITY_INVALID
  );
  invariant(
    stack.ParentId == null && stack.RootId == null,
    "target stack is not a root stack",
    CLI_FAILURE_CODES.STACK_NESTING_INVALID
  );
  invariant(
    stack.EnableTerminationProtection === false,
    "target stack termination protection is enabled",
    CLI_FAILURE_CODES.STACK_TERMINATION_PROTECTION_INVALID
  );
  exactTags(stack.Tags);

  let resourceStateSha256;
  if (resourcesResponse !== undefined) {
    const resources = validateResourceSummaries(resourcesResponse);
    resourceStateSha256 = `sha256:${sha256(canonicalJson(resources))}`;
  } else {
    invariant(
      typeof preparedResourceStateSha256 === "string" &&
        preparedResourceStateSha256.startsWith("sha256:") &&
        SHA256_PATTERN.test(preparedResourceStateSha256.slice(7)),
      "prepared resource-state digest is invalid",
      CLI_FAILURE_CODES.RESOURCE_STATE_UNAVAILABLE
    );
    resourceStateSha256 = preparedResourceStateSha256;
  }

  const exactReadConditions = {
    DateLessThan: { "aws:CurrentTime": expiresAt },
    StringEquals: {
      "aws:RequestedRegion": TARGET.region,
      "aws:ResourceTag/Application": TARGET.tags.Application,
      "aws:ResourceTag/Environment": TARGET.tags.Environment,
      "aws:ResourceTag/ManagedBy": TARGET.tags.ManagedBy,
      "aws:ResourceTag/Purpose": TARGET.tags.Purpose,
    },
  };
  const policyDocument = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadExactSealedIncidentStackBeforeExpiry",
        Effect: "Allow",
        Action: "cloudformation:DescribeStacks",
        Resource: stack.StackId,
        Condition: exactReadConditions,
      },
      {
        Sid: "DeleteExactSealedIncidentStackBeforeExpiry",
        Effect: "Allow",
        Action: "cloudformation:DeleteStack",
        Resource: stack.StackId,
        Condition: {
          ...exactReadConditions,
          Null: { "cloudformation:RoleArn": "true" },
        },
      },
    ],
  };
  const policyDocumentSha256 = sha256(canonicalJson(policyDocument));
  const clientRequestToken = `archon-${INCIDENT.runId}-a${INCIDENT.runAttempt}-${controlPlaneSha.slice(0, 12)}`;
  const stackIdSha256 = sha256(stack.StackId);
  const plan = {
    schemaVersion: "archon.aws-incident-recovery-plan/v1",
    authorization: {
      expiresAt,
      policyDocumentSha256: `sha256:${policyDocumentSha256}`,
      policyName: RECOVERY.policyName,
      roleName: RECOVERY.roleName,
    },
    controlPlaneSha,
    delete: {
      action: "cloudformation:DeleteStack",
      clientRequestToken,
      deletionMode: "STANDARD",
      deploymentConfigOverride: false,
      retainResources: false,
      roleOverride: false,
    },
    incident: INCIDENT,
    target: {
      label: TARGET.label,
      region: TARGET.region,
      resourceStateSha256,
      sourceTemplateSemanticSha256,
      stackId: stack.StackId,
      stackIdSha256: `sha256:${stackIdSha256}`,
      status: stack.StackStatus,
    },
  };
  return Object.freeze({
    clientRequestToken,
    expiresAt,
    plan,
    planDigest: `sha256:${sha256(canonicalJson(plan))}`,
    policyDocument,
    policyDocumentSha256: `sha256:${policyDocumentSha256}`,
    resourceStateSha256,
    stackIdSha256: `sha256:${stackIdSha256}`,
  });
}
function requireRunnerTemp(path) {
  const runnerTemp = process.env.RUNNER_TEMP;
  invariant(process.env.GITHUB_ACTIONS === "true", "CLI writes are CI-only");
  invariant(typeof runnerTemp === "string" && isAbsolute(runnerTemp), "RUNNER_TEMP is invalid");
  const root = resolve(runnerTemp);
  const output = resolve(path);
  invariant(output.startsWith(`${root}${sep}`), "output must remain under RUNNER_TEMP");
  return output;
}

function writePrivate(path, value) {
  const output = requireRunnerTemp(path);
  writeFileSync(output, `${canonicalJson(value)}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  chmodSync(output, 0o600);
}

function readJson(path, label) {
  safeRegularFile(path, label);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}

function usage() {
  throw new CliFailure(CLI_FAILURE_CODES.INVALID_INVOCATION);
}

function emitSafePlan(result) {
  process.stdout.write(
    `${canonicalJson({
      clientRequestToken: result.clientRequestToken,
      expiresAt: result.expiresAt,
      planDigest: result.planDigest,
      policyDocumentSha256: result.policyDocumentSha256,
      resourceStateSha256: result.resourceStateSha256,
      stackIdSha256: result.stackIdSha256,
    })}\n`
  );
}

export function main(argv = process.argv.slice(2)) {
  const [command, ...args] = argv;
  if (command === "validate-artifact") {
    if (args.length !== 1) usage();
    return withCliFailureCode(CLI_FAILURE_CODES.ARTIFACT_VALIDATION_FAILED, () => {
      process.stdout.write(`${canonicalJson(validateIncidentArtifact(args[0]))}\n`);
    });
  }
  if (command === "build-plan") {
    if (args.length !== 8) usage();
    return withCliFailureCode(CLI_FAILURE_CODES.PLAN_VALIDATION_FAILED, () => {
      const [
        stackPath,
        resourcesPath,
        templateSha,
        accountId,
        expiresAt,
        controlPlaneSha,
        planPath,
        policyPath,
      ] = args;
      const result = buildRecoveryPlan({
        accountId,
        controlPlaneSha,
        expiresAt,
        resourcesResponse: readJson(resourcesPath, "stack resources"),
        sourceTemplateSemanticSha256: templateSha,
        stackResponse: readJson(stackPath, "stack description"),
      });
      writePrivate(planPath, result.plan);
      writePrivate(policyPath, result.policyDocument);
      emitSafePlan(result);
    });
  }
  if (command === "rebuild-plan") {
    if (args.length !== 7) usage();
    return withCliFailureCode(CLI_FAILURE_CODES.PLAN_VALIDATION_FAILED, () => {
      const [
        stackPath,
        resourceStateSha256,
        accountId,
        expiresAt,
        controlPlaneSha,
        planPath,
        policyPath,
      ] = args;
      const result = buildRecoveryPlan({
        accountId,
        controlPlaneSha,
        expiresAt,
        preparedResourceStateSha256: resourceStateSha256,
        sourceTemplateSemanticSha256: TARGET.sourceTemplateSemanticSha256,
        stackResponse: readJson(stackPath, "stack description"),
      });
      writePrivate(planPath, result.plan);
      writePrivate(policyPath, result.policyDocument);
      emitSafePlan(result);
    });
  }
  usage();
}
const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`::error::${sanitizedCliFailureCode(error)}\n`);
    process.exitCode = 1;
  }
}
