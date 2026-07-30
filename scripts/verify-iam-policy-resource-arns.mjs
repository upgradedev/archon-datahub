#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function collectArnTemplates(value, path, encoding, output) {
  if (typeof value === "string") {
    if (value.startsWith("arn:")) output.push({ arn: value, encoding, path });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      collectArnTemplates(entry, `${path}[${index}]`, encoding, output)
    );
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Object.hasOwn(value, "Fn::Sub")) {
    const substitution = value["Fn::Sub"];
    const template = Array.isArray(substitution) ? substitution[0] : substitution;
    collectArnTemplates(template, `${path}.Fn::Sub`, "intrinsic-sub", output);
    if (Array.isArray(substitution) && substitution.length === 2) {
      collectArnTemplates(substitution[1], `${path}.Fn::Sub.variables`, "intrinsic-sub-variable", output);
    }
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    collectArnTemplates(entry, `${path}.${key}`, encoding, output);
  }
}

function inspectPolicyNode(node, context, state) {
  if (Array.isArray(node)) {
    node.forEach((entry, index) => inspectPolicyNode(entry, { ...context, path: `${context.path}[${index}]` }, state));
    return;
  }
  if (node === null || typeof node !== "object") return;
  const statementSid = typeof node.Sid === "string" ? node.Sid : context.statementSid;
  for (const [key, value] of Object.entries(node)) {
    const path = `${context.path}.${key}`;
    if (key === "Resource") {
      const arnTemplates = [];
      collectArnTemplates(value, path, "direct", arnTemplates);
      state.resourceArnCount += arnTemplates.length;
      for (const template of arnTemplates) {
        const serviceSegment = template.arn.split(":")[2] ?? "";
        if (serviceSegment.includes("*") || serviceSegment.includes("?")) {
          state.violations.push({
            encoding: template.encoding,
            logicalResourceId: context.logicalResourceId,
            path: template.path,
            serviceSegment,
            statementSid: statementSid ?? "<unknown>"
          });
        }
      }
    } else {
      inspectPolicyNode(value, { ...context, path, statementSid }, state);
    }
  }
}

function inspectResourceForPolicyDocuments(node, context, state) {
  if (Array.isArray(node)) {
    node.forEach((entry, index) =>
      inspectResourceForPolicyDocuments(entry, { ...context, path: `${context.path}[${index}]` }, state)
    );
    return;
  }
  if (node === null || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    const path = `${context.path}.${key}`;
    if (key === "PolicyDocument") {
      state.policyDocumentCount += 1;
      inspectPolicyNode(value, { ...context, path, statementSid: undefined }, state);
    } else {
      inspectResourceForPolicyDocuments(value, { ...context, path }, state);
    }
  }
}

export function inspectIamPolicyResourceArns(template) {
  if (template === null || typeof template !== "object" || Array.isArray(template)) {
    throw new TypeError("CloudFormation template must be an object");
  }
  if (template.Resources === null || typeof template.Resources !== "object" || Array.isArray(template.Resources)) {
    throw new TypeError("CloudFormation template Resources must be an object");
  }
  const state = { policyDocumentCount: 0, resourceArnCount: 0, violations: [] };
  for (const [logicalResourceId, resource] of Object.entries(template.Resources)) {
    if (resource === null || typeof resource !== "object" || typeof resource.Type !== "string" || !resource.Type.startsWith("AWS::IAM::")) continue;
    inspectResourceForPolicyDocuments(resource.Properties, { logicalResourceId, path: `Resources.${logicalResourceId}.Properties` }, state);
  }
  return state;
}

export function assertNoWildcardIamResourceArnServices(template) {
  const result = inspectIamPolicyResourceArns(template);
  if (result.policyDocumentCount === 0 || result.resourceArnCount === 0) {
    throw new Error("No IAM PolicyDocument Resource ARNs were available for validation");
  }
  if (result.violations.length > 0) {
    const summary = result.violations
      .map(({ encoding, logicalResourceId, serviceSegment, statementSid }) => `${logicalResourceId}/${statementSid}:${encoding}:service=${serviceSegment}`)
      .join(", ");
    throw new Error(`IAM Resource ARN wildcard service segment is forbidden: ${summary}`);
  }
  return result;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    process.stderr.write("Usage: verify-iam-policy-resource-arns.mjs <canonical-template.json>\n");
    process.exit(1);
  }
  try {
    const template = JSON.parse(await readFile(resolve(process.argv[2]), "utf8"));
    const result = assertNoWildcardIamResourceArnServices(template);
    process.stdout.write(`Validated ${result.resourceArnCount} IAM PolicyDocument Resource ARN templates across ${result.policyDocumentCount} policy documents.\n`);
  } catch (error) {
    process.stderr.write(`IAM Resource ARN validation failed: ${error.message}\n`);
    process.exit(1);
  }
}
