#!/usr/bin/env node

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync, writeFileSync } from "node:fs";

const SHA = /^[0-9a-f]{40}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const BARE_DIGEST = /^[0-9a-f]{64}$/u;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

function fail(message) {
  throw new Error(message);
}

function record(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  return value;
}

function keys(value, expected, label) {
  record(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has an unexpected schema`);
  }
}

function string(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} is invalid`);
  }
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail(`${label} must be a positive safe integer`);
  }
}

function timestamp(value, label) {
  string(value, UTC, label);
  if (!Number.isFinite(Date.parse(value))) {
    fail(`${label} is not a real timestamp`);
  }
}

function exactBoolean(value, expected, label) {
  if (value !== expected) {
    fail(`${label} must be ${String(expected)}`);
  }
}

function canonicalValue(value) {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("non-finite number in JSON");
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  record(value, "JSON value");
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalValue(value[key])])
  );
}

function canonical(value) {
  return `${JSON.stringify(canonicalValue(value))}\n`;
}

function read(path, label) {
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail(`${label} must be a readable regular non-symlink file`);
  }
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) {
      fail(`${label} must be a regular non-symlink file`);
    }
    const bytes = readFileSync(descriptor);
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail(`${label} is not valid JSON`);
    }
    return { bytes, value };
  } finally {
    closeSync(descriptor);
  }
}

function write(path, value) {
  writeFileSync(path, canonical(value), {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
  });
}

function validateExpectations(value) {
  keys(
    value,
    [
      "ciRunId",
      "cloudImageDigest",
      "cloudRuntimeReleaseDigest",
      "coreCapabilityDigest",
      "coreImageManifestDigest",
      "deploymentRunId",
      "lambdaArtifactDigest",
      "releaseSha",
      "stage",
      "webArtifactDigest",
    ],
    "expectations"
  );
  if (value.stage !== "production") {
    fail("expectations.stage must be production");
  }
  string(value.releaseSha, SHA, "expectations.releaseSha");
  positiveInteger(value.ciRunId, "expectations.ciRunId");
  positiveInteger(value.deploymentRunId, "expectations.deploymentRunId");
  for (const name of [
    "cloudImageDigest",
    "cloudRuntimeReleaseDigest",
    "coreCapabilityDigest",
    "coreImageManifestDigest",
    "lambdaArtifactDigest",
    "webArtifactDigest",
  ]) {
    string(value[name], DIGEST, `expectations.${name}`);
  }
}

function validateObservation(value, expected = undefined) {
  keys(
    value,
    [
      "observedAt",
      "releaseSha",
      "runtime",
      "schemaVersion",
      "security",
      "stage",
      "topology",
    ],
    "observation"
  );
  if (
    value.schemaVersion !== "archon.lean-runtime-observation/v1" ||
    value.stage !== "production"
  ) {
    fail("observation identity is invalid");
  }
  string(value.releaseSha, SHA, "observation.releaseSha");
  timestamp(value.observedAt, "observation.observedAt");

  keys(
    value.topology,
    ["coreIdle", "legacyAlwaysOnRuntimeAbsent", "stackFingerprintSha256"],
    "observation.topology"
  );
  exactBoolean(value.topology.coreIdle, true, "topology.coreIdle");
  exactBoolean(
    value.topology.legacyAlwaysOnRuntimeAbsent,
    true,
    "topology.legacyAlwaysOnRuntimeAbsent"
  );
  string(
    value.topology.stackFingerprintSha256,
    BARE_DIGEST,
    "topology.stackFingerprintSha256"
  );

  keys(
    value.runtime,
    [
      "cloudImageDigest",
      "functions",
      "imageFunctions",
      "privateVersionedBuckets",
      "sessionTables",
    ],
    "observation.runtime"
  );
  string(
    value.runtime.cloudImageDigest,
    DIGEST,
    "runtime.cloudImageDigest"
  );
  if (
    value.runtime.functions !== 6 ||
    value.runtime.imageFunctions !== 3 ||
    value.runtime.sessionTables !== 2 ||
    value.runtime.privateVersionedBuckets !== 2
  ) {
    fail("runtime cardinalities are invalid");
  }

  keys(
    value.security,
    [
      "alarmRouteBound",
      "cloudFrontOac",
      "encryptedState",
      "noLambdaVpcAttachments",
      "pointInTimeRecovery",
      "rawIdentifiersProjected",
      "wafOnApiAndCognito",
    ],
    "observation.security"
  );
  for (const name of [
    "alarmRouteBound",
    "cloudFrontOac",
    "encryptedState",
    "noLambdaVpcAttachments",
    "pointInTimeRecovery",
    "wafOnApiAndCognito",
  ]) {
    exactBoolean(value.security[name], true, `security.${name}`);
  }
  exactBoolean(
    value.security.rawIdentifiersProjected,
    false,
    "security.rawIdentifiersProjected"
  );

  if (expected) {
    if (
      value.stage !== expected.stage ||
      value.releaseSha !== expected.releaseSha ||
      value.runtime.cloudImageDigest !== expected.cloudImageDigest
    ) {
      fail("observation differs from expected deployed identity");
    }
  }
}

function validateEvidence(value, observationBytes, expected) {
  keys(
    value,
    [
      "applicationUrl",
      "ciRunId",
      "deploymentRunId",
      "generatedAt",
      "promotion",
      "releaseSha",
      "schemaVersion",
      "secretsProjected",
      "stage",
      "verification",
    ],
    "deployment evidence"
  );
  if (
    value.schemaVersion !== "archon.aws-deployment-evidence/v2" ||
    value.stage !== "production"
  ) {
    fail("deployment evidence identity is invalid");
  }
  string(value.releaseSha, SHA, "evidence.releaseSha");
  positiveInteger(value.ciRunId, "evidence.ciRunId");
  positiveInteger(value.deploymentRunId, "evidence.deploymentRunId");
  string(
    value.applicationUrl,
    /^https:\/\/[a-z0-9.-]+$/u,
    "evidence.applicationUrl"
  );
  timestamp(value.generatedAt, "evidence.generatedAt");
  exactBoolean(value.secretsProjected, false, "evidence.secretsProjected");

  keys(
    value.promotion,
    [
      "cloudRuntimeReleaseDigest",
      "coreCapabilityDigest",
      "coreImageManifestDigest",
      "lambdaArtifactDigest",
      "policy",
      "webArtifactDigest",
    ],
    "evidence.promotion"
  );
  if (
    value.promotion.policy !== "build-once-promote-exact-artifacts"
  ) {
    fail("deployment promotion policy is invalid");
  }
  for (const name of [
    "cloudRuntimeReleaseDigest",
    "coreCapabilityDigest",
    "coreImageManifestDigest",
    "lambdaArtifactDigest",
    "webArtifactDigest",
  ]) {
    string(value.promotion[name], DIGEST, `promotion.${name}`);
  }

  keys(
    value.verification,
    [
      "canonicalHostEnforced",
      "directApiRejected",
      "httpBoundary",
      "observationSha256",
      "result",
      "securityHeaders",
      "zeroIdleCore",
    ],
    "evidence.verification"
  );
  if (value.verification.result !== "passed") {
    fail("deployment verification did not pass");
  }
  for (const name of [
    "canonicalHostEnforced",
    "directApiRejected",
    "httpBoundary",
    "securityHeaders",
    "zeroIdleCore",
  ]) {
    exactBoolean(value.verification[name], true, `verification.${name}`);
  }
  string(
    value.verification.observationSha256,
    BARE_DIGEST,
    "verification.observationSha256"
  );
  const observedDigest = createHash("sha256")
    .update(observationBytes)
    .digest("hex");
  if (value.verification.observationSha256 !== observedDigest) {
    fail("evidence does not hash the exact observation bytes");
  }

  if (
    value.releaseSha !== expected.releaseSha ||
    value.ciRunId !== expected.ciRunId ||
    value.deploymentRunId !== expected.deploymentRunId
  ) {
    fail("deployment identity differs from expectations");
  }
  for (const name of [
    "cloudRuntimeReleaseDigest",
    "coreCapabilityDigest",
    "coreImageManifestDigest",
    "lambdaArtifactDigest",
    "webArtifactDigest",
  ]) {
    if (value.promotion[name] !== expected[name]) {
      fail(`promotion.${name} differs from expectations`);
    }
  }
}

function exactArguments(actual, count, usage) {
  if (actual.length !== count) {
    fail(`usage: ${usage}`);
  }
}

function main() {
  const [mode, ...args] = process.argv.slice(2);

  if (mode === "pair") {
    exactArguments(
      args,
      5,
      "pair EVIDENCE OBSERVATION EXPECTATIONS CANONICAL_EVIDENCE CANONICAL_OBSERVATION"
    );
    const evidence = read(args[0], "deployment evidence");
    const observation = read(args[1], "deployment observation");
    const expectations = read(args[2], "expectations");
    validateExpectations(expectations.value);
    validateObservation(observation.value, expectations.value);
    validateEvidence(evidence.value, observation.bytes, expectations.value);
    write(args[3], evidence.value);
    write(args[4], observation.value);
    return;
  }

  if (mode === "observation") {
    exactArguments(
      args,
      3,
      "observation OBSERVATION EXPECTATIONS CANONICAL_OBSERVATION"
    );
    const observation = read(args[0], "runtime observation");
    const expectations = read(args[1], "expectations");
    validateExpectations(expectations.value);
    validateObservation(observation.value, expectations.value);
    write(args[2], observation.value);
    return;
  }

  if (mode === "stable") {
    exactArguments(args, 2, "stable OBSERVATION OUTPUT");
    const observation = read(args[0], "runtime observation");
    validateObservation(observation.value);
    const projection = structuredClone(observation.value);
    delete projection.observedAt;
    write(args[1], projection);
    return;
  }

  fail("mode must be pair, observation, or stable");
}

try {
  main();
} catch (error) {
  const message =
    error instanceof Error ? error.message : "unknown validation failure";
  process.stderr.write(`::error::${message}\n`);
  process.exitCode = 1;
}
