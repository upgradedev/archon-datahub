#!/usr/bin/env node

import { readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";

function fail(message) {
  process.stderr.write(`AWS foundation policy render failed: ${message}\n`);
  process.exit(1);
}

const rawArgs = process.argv.slice(2);
if (rawArgs.length % 2 !== 0) {
  fail("arguments must be supplied as --kebab-case value pairs");
}
const allowedArgs = new Set([
  "input",
  "account",
  "stdoutGroup",
  "controlOutput",
  "assetsOutput",
  "identityOutput",
  "attachmentsOutput"
]);
const args = {};
for (let index = 0; index < rawArgs.length; index += 2) {
  const flag = rawArgs[index];
  const value = rawArgs[index + 1];
  if (!/^--[a-z]+(?:-[a-z]+)*$/.test(flag)) {
    fail(`invalid argument name: ${flag ?? "<missing>"}`);
  }
  const name = flag
    .slice(2)
    .replace(/-([a-z])/g, (_, character) => character.toUpperCase());
  if (!allowedArgs.has(name)) fail(`unsupported argument: ${flag}`);
  if (Object.hasOwn(args, name)) fail(`duplicate argument: ${flag}`);
  args[name] = value;
}
const policyGroups = ["control", "assets", "identity", "attachments"];
const stdoutMode = policyGroups.includes(args.stdoutGroup);
const fileMode =
  Boolean(args.controlOutput) &&
  Boolean(args.assetsOutput) &&
  Boolean(args.identityOutput) &&
  Boolean(args.attachmentsOutput);
if (!args.input || !args.account || stdoutMode === fileMode) {
  fail(
    "expected --input, --account, and exactly one mode: four named outputs or --stdout-group control|assets|identity|attachments"
  );
}
if (!/^[0-9]{12}$/.test(args.account)) fail("account must be exactly 12 digits");

const inputPath = resolve(args.input);
const outputPaths = fileMode
  ? {
      control: resolve(args.controlOutput),
      assets: resolve(args.assetsOutput),
      identity: resolve(args.identityOutput),
      attachments: resolve(args.attachmentsOutput)
    }
  : {};
if (fileMode && new Set(Object.values(outputPaths)).size !== 4) {
  fail("all four outputs must be distinct");
}
if (fileMode && process.env.GITHUB_ACTIONS === "true") {
  const runnerTemp = process.env.RUNNER_TEMP;
  if (!runnerTemp) fail("RUNNER_TEMP is required in GitHub Actions");
  const tempRoot = `${await realpath(runnerTemp)}${sep}`;
  for (const outputPath of Object.values(outputPaths)) {
    const outputParent = `${await realpath(dirname(outputPath))}${sep}`;
    if (!outputParent.startsWith(tempRoot)) {
      fail("rendered outputs must remain below RUNNER_TEMP in GitHub Actions");
    }
  }
}

const sourceText = await readFile(inputPath, "utf8");
const source = JSON.parse(sourceText);
if (
  source?.Version !== "2012-10-17" ||
  !Array.isArray(source.Statement) ||
  source.Statement.length === 0
) {
  fail("source is not the approved IAM policy template shape");
}
const placeholder = "${aws:PrincipalAccount}";
const occurrences = sourceText.split(placeholder).length - 1;
if (occurrences < 1) fail("account placeholder is missing");
const renderedText = sourceText.replaceAll(placeholder, args.account);
if (
  renderedText.includes(placeholder) ||
  /\$\{aws:PrincipalAccount\}/.test(renderedText)
) {
  fail("an unresolved account placeholder survived");
}
const rendered = JSON.parse(renderedText);
const statementGroups = {
  control: new Set([
    "VerifyCaller",
    "ReconcileExactFoundationStacks",
    "InspectFoundationTemplates",
    "InspectExistingApplicationStackRoles",
    "ConfigureSharedApiGatewayLogging",
    "ReconcileExactCoreAmiFoundationStack",
    "ReconcileExactCoreAmiFoundationRoles",
    "ReconcileExactCoreAmiBuilderProfile",
    "AttachExactCoreAmiBuilderSsmPolicy",
    "PassExactCoreAmiBuilderRoleForProfile"
  ]),
  assets: new Set([
    "ReadExactBootstrapBucketsForDrift",
    "ReadExactStagePoliciesForDrift",
    "ReconcileExactBootstrapBuckets",
    "ReconcileExactBootstrapRepositories",
    "ReconcileExactBootstrapVersionParameters"
  ]),
  attachments: new Set([
    "AttachExactStagingPrimaryExecutionPolicies",
    "AttachExactStagingEdgeExecutionPolicies",
    "AttachExactProductionPrimaryExecutionPolicies",
    "AttachExactProductionEdgeExecutionPolicies",
    "AttachReadOnlyLookupPolicy",
    "DetachLegacyDeploymentReadOnlyPolicy"
  ])
};
const assigned = new Set();
for (const [group, sids] of Object.entries(statementGroups)) {
  const statements = rendered.Statement.filter((statement) => sids.has(statement.Sid));
  if (statements.length !== sids.size) {
    fail(`${group} policy statement inventory is incomplete`);
  }
  for (const statement of statements) assigned.add(statement.Sid);
}
statementGroups.identity = new Set(
  rendered.Statement
    .map((statement) => statement.Sid)
    .filter((sid) => !assigned.has(sid))
);
if (statementGroups.identity.size === 0) {
  fail("identity policy statement inventory is empty");
}
if (
  rendered.Statement.some(
    (statement) =>
      typeof statement.Sid !== "string" ||
      statement.Sid.length === 0
  ) ||
  new Set(rendered.Statement.map((statement) => statement.Sid)).size !==
    rendered.Statement.length
) {
  fail("source statement Sids must be unique, non-empty strings");
}

for (const [group, sids] of Object.entries(statementGroups)) {
  const policy = {
    Version: "2012-10-17",
    Statement: rendered.Statement.filter((statement) => sids.has(statement.Sid))
  };
  const compact = JSON.stringify(policy);
  if (Buffer.byteLength(compact, "utf8") > 6144) {
    fail(`${group} managed policy exceeds the 6,144-byte IAM quota`);
  }
  const serialized = JSON.stringify(policy, null, 2) + "\n";
  if (
    !serialized.includes(`:${args.account}:`) ||
    serialized.includes(placeholder)
  ) {
    fail(`${group} account binding is incomplete`);
  }
  if (stdoutMode && group === args.stdoutGroup) {
    process.stdout.write(`${compact}\n`);
  }
  if (fileMode) {
    await writeFile(outputPaths[group], serialized, {
      encoding: "utf8",
      mode: 0o600
    });
  }
}
