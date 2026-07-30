#!/usr/bin/env node

import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";

function fail(message) {
  process.stderr.write(`AWS runtime boundary verification failed: ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      fail("expected --contract, --stage, and --templates arguments");
    }
    values[key.slice(2)] = value;
  }
  for (const required of ["contract", "stage", "templates"]) {
    if (!values[required]) fail(`missing --${required}`);
  }
  if (!["staging", "production"].includes(values.stage)) {
    fail("--stage must be staging or production");
  }
  return values;
}

async function templatePaths(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = [];
  for (const entry of entries) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await templatePaths(path)));
    if (entry.isFile() && entry.name.endsWith(".template.json")) paths.push(path);
  }
  return paths.sort();
}

function array(value) {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function actionMatches(allowed, required) {
  if (allowed === required) return true;
  if (!allowed.endsWith("*")) return false;
  return required.startsWith(allowed.slice(0, -1));
}

function collectAllowActions(policyDocument, destination) {
  for (const statement of array(policyDocument?.Statement)) {
    if (statement?.Effect !== "Allow") continue;
    for (const action of array(statement.Action)) {
      if (typeof action !== "string") fail("an IAM Allow action is not a string");
      destination.add(action);
    }
  }
}

const args = parseArgs(process.argv.slice(2));
const contract = JSON.parse(await readFile(resolve(args.contract), "utf8"));
const boundary = contract?.aws?.runtimeBoundary;
if (boundary?.schemaVersion !== "archon.aws-runtime-boundary/v1") {
  fail("runtime boundary contract schema is not v1");
}
const allowedActions = array(boundary.allowedActions);
if (
  allowedActions.length === 0 ||
  allowedActions.some((action) => typeof action !== "string" || action === "*") ||
  new Set(allowedActions).size !== allowedActions.length
) {
  fail("allowedActions must be a unique, non-empty string inventory without *");
}
const approvedPolicies = boundary.approvedAwsManagedPolicies;
if (
  approvedPolicies === null ||
  typeof approvedPolicies !== "object" ||
  Array.isArray(approvedPolicies)
) {
  fail("approvedAwsManagedPolicies must be an object");
}
for (const [policyArn, actions] of Object.entries(approvedPolicies)) {
  if (!policyArn.startsWith("arn:aws:iam::aws:policy/service-role/")) {
    fail(`managed policy is outside the service-role path: ${policyArn}`);
  }
  for (const action of array(actions)) {
    if (!allowedActions.some((allowed) => actionMatches(allowed, action))) {
      fail(`managed policy action ${action} is outside allowedActions`);
    }
  }
}

const templates = await templatePaths(resolve(args.templates));
if (templates.length === 0) fail("no synthesized CloudFormation templates found");
const requiredActions = new Set();
const seenManagedPolicies = new Set();
let roleCount = 0;
const expectedBoundary = `archon-datahub-runtime-boundary-${args.stage}`;

for (const path of templates) {
  const template = JSON.parse(await readFile(path, "utf8"));
  for (const [logicalId, resource] of Object.entries(template.Resources ?? {})) {
    if (resource?.Type === "AWS::IAM::Role") {
      roleCount += 1;
      const serializedBoundary = JSON.stringify(
        resource.Properties?.PermissionsBoundary
      );
      if (!serializedBoundary.includes(expectedBoundary)) {
        fail(`${logicalId} does not use ${expectedBoundary}`);
      }
      for (const policy of array(resource.Properties?.Policies)) {
        collectAllowActions(policy?.PolicyDocument, requiredActions);
      }
      for (const managedPolicy of array(resource.Properties?.ManagedPolicyArns)) {
        const serialized = JSON.stringify(managedPolicy);
        const matches = Object.keys(approvedPolicies).filter((policyArn) =>
          serialized.includes(policyArn.split("arn:aws:").at(-1))
        );
        if (matches.length !== 1) {
          fail(`${logicalId} has an unapproved or ambiguous managed policy`);
        }
        seenManagedPolicies.add(matches[0]);
        for (const action of approvedPolicies[matches[0]]) {
          requiredActions.add(action);
        }
      }
    }
    if (
      resource?.Type === "AWS::IAM::Policy" ||
      resource?.Type === "AWS::IAM::ManagedPolicy"
    ) {
      collectAllowActions(resource.Properties?.PolicyDocument, requiredActions);
    }
  }
}

if (roleCount === 0) fail("no synthesized runtime roles were reviewed");
const unseenApprovedPolicies = Object.keys(approvedPolicies)
  .filter((policyArn) => !seenManagedPolicies.has(policyArn))
  .sort();
if (unseenApprovedPolicies.length > 0) {
  fail(
    `approved managed policies absent from synthesis: ${unseenApprovedPolicies.join(", ")}`
  );
}
const uncovered = [...requiredActions]
  .filter(
    (required) =>
      !allowedActions.some((allowed) => actionMatches(allowed, required))
  )
  .sort();
if (uncovered.length > 0) {
  fail(`boundary misses synthesized actions: ${uncovered.join(", ")}`);
}
const unusedAllowed = allowedActions
  .filter(
    (allowed) =>
      ![...requiredActions].some((required) => actionMatches(allowed, required))
  )
  .sort();
if (unusedAllowed.length > 0) {
  fail(`boundary contains actions absent from synthesis: ${unusedAllowed.join(", ")}`);
}

process.stdout.write(
  JSON.stringify({
    allowedActionCount: allowedActions.length,
    approvedManagedPolicies: [...seenManagedPolicies].sort(),
    requiredActionCount: requiredActions.size,
    roleCount,
    stage: args.stage,
    templateCount: templates.length,
    validation: "passed"
  }) + "\n"
);
