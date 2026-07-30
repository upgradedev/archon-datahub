#!/usr/bin/env node

import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";

const MAX_INPUT_BYTES = 262_144;
const MAX_EVENTS = 25;
const MAX_OUTPUT_BYTES = 2_048;

export const ALLOWLISTED_STACK_LABELS = Object.freeze([
  "governed-canary-roles",
  "production-bootstrap-edge",
  "production-bootstrap-primary",
  "production-deploy",
  "production-iam",
  "shared-api-gateway",
  "staging-bootstrap-edge",
  "staging-bootstrap-primary",
  "staging-deploy",
  "staging-iam",
]);

const stackLabels = new Set(ALLOWLISTED_STACK_LABELS);
const stackStatuses = new Set([
  "CREATE_COMPLETE",
  "CREATE_FAILED",
  "CREATE_IN_PROGRESS",
  "DELETE_COMPLETE",
  "DELETE_FAILED",
  "DELETE_IN_PROGRESS",
  "IMPORT_COMPLETE",
  "IMPORT_IN_PROGRESS",
  "IMPORT_ROLLBACK_COMPLETE",
  "IMPORT_ROLLBACK_FAILED",
  "IMPORT_ROLLBACK_IN_PROGRESS",
  "REVIEW_IN_PROGRESS",
  "ROLLBACK_COMPLETE",
  "ROLLBACK_FAILED",
  "ROLLBACK_IN_PROGRESS",
  "UNKNOWN",
  "UPDATE_COMPLETE",
  "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
  "UPDATE_FAILED",
  "UPDATE_IN_PROGRESS",
  "UPDATE_ROLLBACK_COMPLETE",
  "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
  "UPDATE_ROLLBACK_FAILED",
  "UPDATE_ROLLBACK_IN_PROGRESS",
]);
const resourceFailureStatuses = new Set([
  "CREATE_FAILED",
  "DELETE_FAILED",
  "IMPORT_ROLLBACK_FAILED",
  "ROLLBACK_FAILED",
  "UPDATE_FAILED",
  "UPDATE_ROLLBACK_FAILED",
]);
const logicalIdPattern = /^[A-Za-z][A-Za-z0-9]{0,254}$/;
const resourceTypePattern = /^(?:AWS::[A-Za-z0-9]+::[A-Za-z0-9]+|Custom::[A-Za-z0-9._-]+)$/;

function classifyReason(reason) {
  if (/access\s*denied|accessdenied|not authorized|unauthori[sz]ed|explicit deny/i.test(reason)) {
    return "access-denied";
  }
  if (/already exists|already in use|duplicate/i.test(reason)) {
    return "already-exists";
  }
  if (/quota|limit exceeded|too many/i.test(reason)) {
    return "quota-exceeded";
  }
  if (/invalid|validation|malformed|unsupported/i.test(reason)) {
    return "invalid-request";
  }
  if (/dependenc|failed to create|required resource|cancelled/i.test(reason)) {
    return "dependency-failure";
  }
  if (/timed?\s*out|timeout/i.test(reason)) {
    return "timeout";
  }
  if (/conflict|concurrent|in progress/i.test(reason)) {
    return "resource-conflict";
  }
  if (/internal|service unavailable|service error/i.test(reason)) {
    return "service-failure";
  }
  return "unknown";
}


function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export async function readBoundedInput(stream) {
  const chunks = [];
  let retainedBytes = 0;
  for await (const value of stream) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const remaining = MAX_INPUT_BYTES + 1 - retainedBytes;
    if (remaining > 0) {
      const retained = chunk.subarray(0, remaining);
      chunks.push(retained);
      retainedBytes += retained.length;
    }
    if (retainedBytes > MAX_INPUT_BYTES) {
      stream.destroy();
      throw new Error("sanitizer input exceeds hard limit");
    }
  }
  if (retainedBytes === 0) {
    throw new Error("sanitizer input is empty");
  }
  return Buffer.concat(chunks, retainedBytes);
}

export function sanitizeCloudFormationFailure(document, options) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("invalid CloudFormation event document");
  }
  const { stackLabel, stackStatus } = options ?? {};
  if (!stackLabels.has(stackLabel) || !stackStatuses.has(stackStatus)) {
    throw new Error("unapproved diagnostic stack identity");
  }
  if (!Array.isArray(document.StackEvents) || document.StackEvents.length === 0 || document.StackEvents.length > MAX_EVENTS) {
    throw new Error("invalid bounded CloudFormation event set");
  }

  const failedEvents = document.StackEvents.filter(
    (candidate) => candidate && resourceFailureStatuses.has(candidate.ResourceStatus),
  );
  if (failedEvents.length === 0) {
    throw new Error("no failed CloudFormation resource event");
  }
  const event =
    failedEvents.find((candidate) => {
      const reason = candidate.ResourceStatusReason;
      return (
        typeof reason !== "string" ||
        reason.length === 0 ||
        classifyReason(reason) !== "dependency-failure"
      );
    }) ?? failedEvents[0];

  const logicalResourceId = event.LogicalResourceId;
  const resourceType = event.ResourceType;
  const resourceStatus = event.ResourceStatus;
  if (!logicalIdPattern.test(logicalResourceId ?? "") || !resourceTypePattern.test(resourceType ?? "")) {
    throw new Error("unsafe CloudFormation event identity");
  }
  if (typeof event.ResourceStatusReason !== "string" || event.ResourceStatusReason.length === 0) {
    throw new Error("missing CloudFormation failure reason");
  }

  const rawReason = event.ResourceStatusReason;
  const reasonCategory = classifyReason(rawReason);
  const canonicalSafeFields = Object.freeze({
    logicalResourceId,
    reasonCategory,
    resourceStatus,
    resourceType,
    schemaVersion: "archon.aws-foundation-cfn-failure/v1",
    stackLabel,
    stackStatus,
  });
  const diagnostic = Object.freeze({
    diagnosticSha256: sha256(JSON.stringify(canonicalSafeFields)),
    logicalResourceId,
    reasonCategory,
    resourceStatus,
    resourceType,
    schemaVersion: canonicalSafeFields.schemaVersion,
    stackLabel,
    stackStatus,
  });
  if (Buffer.byteLength(JSON.stringify(diagnostic), "utf8") > MAX_OUTPUT_BYTES) {
    throw new Error("sanitized CloudFormation diagnostic is oversized");
  }
  return diagnostic;
}

export function serializeCloudFormationFailure(diagnostic) {
  return `${JSON.stringify(diagnostic)}\n`;
}

function parseOptions(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!value || (flag !== "--stack-label" && flag !== "--stack-status")) {
      throw new Error("invalid sanitizer arguments");
    }
    options[flag === "--stack-label" ? "stackLabel" : "stackStatus"] = value;
  }
  if (argv.length !== 4 || !options.stackLabel || !options.stackStatus) {
    throw new Error("missing sanitizer arguments");
  }
  return options;
}

async function main() {
  try {
    const input = await readBoundedInput(process.stdin);
    const document = JSON.parse(input.toString("utf8"));
    const diagnostic = sanitizeCloudFormationFailure(document, parseOptions(process.argv.slice(2)));
    process.stdout.write(serializeCloudFormationFailure(diagnostic));
  } catch {
    process.stderr.write("CloudFormation failure sanitization failed\n");
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}