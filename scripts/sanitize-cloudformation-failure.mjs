#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
const deniedActionPattern = /\b([a-z0-9][a-z0-9-]{1,62}:[A-Z][A-Za-z0-9]{1,127})\b/;

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

function extractDeniedAction(reason, category) {
  if (category !== "access-denied") {
    return null;
  }
  const match = deniedActionPattern.exec(reason);
  return match ? match[1] : null;
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
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

  const event = document.StackEvents.find(
    (candidate) => candidate && resourceFailureStatuses.has(candidate.ResourceStatus),
  );
  if (!event) {
    throw new Error("no failed CloudFormation resource event");
  }

  const logicalResourceId = event.LogicalResourceId;
  const resourceType = event.ResourceType;
  const resourceStatus = event.ResourceStatus;
  if (!logicalIdPattern.test(logicalResourceId ?? "") || !resourceTypePattern.test(resourceType ?? "")) {
    throw new Error("unsafe CloudFormation event identity");
  }

  const rawReason = typeof event.ResourceStatusReason === "string" ? event.ResourceStatusReason : "";
  const reasonCategory = classifyReason(rawReason);
  const diagnostic = Object.freeze({
    deniedAwsAction: extractDeniedAction(rawReason, reasonCategory),
    logicalResourceId,
    rawReasonSha256: sha256(rawReason),
    reasonCategory,
    resourceStatus,
    resourceType,
    schemaVersion: "archon.aws-foundation-cfn-failure/v1",
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
    const input = readFileSync(0);
    if (input.length === 0 || input.length > MAX_INPUT_BYTES) {
      throw new Error("invalid sanitizer input size");
    }
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