#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

function collectArnTemplates(value, path, output) {
  if (typeof value === "string") {
    if (value.startsWith("arn:")) {
      output.push({ arn: value, encoding: "direct", path, substitutions: null });
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectArnTemplates(entry, `${path}[${index}]`, output));
    return;
  }
  if (value === null || typeof value !== "object") return;

  if (Object.hasOwn(value, "Fn::Sub")) {
    const substitution = value["Fn::Sub"];
    const arrayForm = Array.isArray(substitution);
    const template = arrayForm ? substitution[0] : substitution;
    const substitutions = arrayForm ? substitution[1] : null;
    if (
      typeof template !== "string" ||
      (arrayForm &&
        (substitution.length !== 2 ||
          substitutions === null ||
          typeof substitutions !== "object" ||
          Array.isArray(substitutions)))
    ) {
      output.push({ encoding: "intrinsic-sub", parseError: "invalid-fn-sub-shape", path });
      return;
    }
    if (!template.startsWith("arn:")) {
      if (template !== "*") {
        output.push({ encoding: "intrinsic-sub", parseError: "nonliteral-arn-prefix", path });
      }
      return;
    }
    output.push({
      arn: template,
      encoding: "intrinsic-sub",
      path: `${path}.Fn::Sub`,
      substitutions
    });
    return;
  }

  for (const [key, entry] of Object.entries(value)) {
    collectArnTemplates(entry, `${path}.${key}`, output);
  }
}

function splitArnTemplate(arn) {
  const segments = [];
  let segment = "";
  for (let index = 0; index < arn.length; index += 1) {
    const character = arn[index];
    if (character === "$" && arn[index + 1] === "{") {
      const closing = arn.indexOf("}", index + 2);
      if (closing === -1) return { error: "unclosed-placeholder" };
      const placeholder = arn.slice(index + 2, closing);
      if (!/^[A-Za-z0-9_.:-]+$/.test(placeholder)) {
        return { error: "malformed-placeholder" };
      }
      segment += arn.slice(index, closing + 1);
      index = closing;
    } else if (character === ":") {
      segments.push(segment);
      segment = "";
    } else {
      segment += character;
    }
  }
  segments.push(segment);
  return { segments };
}

function isExactAwsPartitionReference(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    value.Ref === "AWS::Partition"
  );
}

function validateArnTemplate(record) {
  if (record.parseError) return { reason: record.parseError };
  const parsed = splitArnTemplate(record.arn);
  if (parsed.error) return { reason: parsed.error };
  const segments = parsed.segments;
  if (segments.length < 6 || segments[0] !== "arn") {
    return { reason: "incomplete-arn" };
  }

  const partition = segments[1];
  const literalPartition = /^aws(?:-[a-z0-9]+)*$/.test(partition);
  const intrinsicPartition =
    record.encoding === "intrinsic-sub" && partition === "${AWS::Partition}";
  const mappedPartitionMatch = /^\$\{([A-Za-z0-9_.-]+)\}$/.exec(partition);
  const mappedPartition =
    record.encoding === "intrinsic-sub" &&
    mappedPartitionMatch !== null &&
    isExactAwsPartitionReference(record.substitutions?.[mappedPartitionMatch[1]]);
  if (!literalPartition && !intrinsicPartition && !mappedPartition) {
    return { reason: "invalid-partition" };
  }

  const serviceSegment = segments[2];
  if (serviceSegment.includes("*") || serviceSegment.includes("?")) {
    return { reason: "wildcard-service", serviceSegment };
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(serviceSegment)) {
    return { reason: "nonliteral-service", serviceSegment };
  }
  if (segments.slice(5).join(":").length === 0) {
    return { reason: "missing-resource", serviceSegment };
  }
  return { serviceSegment };
}

function inspectPolicyNode(node, context, state) {
  if (Array.isArray(node)) {
    node.forEach((entry, index) =>
      inspectPolicyNode(entry, { ...context, path: `${context.path}[${index}]` }, state)
    );
    return;
  }
  if (node === null || typeof node !== "object") return;
  const statementSid = typeof node.Sid === "string" ? node.Sid : context.statementSid;
  for (const [key, value] of Object.entries(node)) {
    const path = `${context.path}.${key}`;
    if (key === "Resource") {
      const records = [];
      collectArnTemplates(value, path, records);
      state.resourceArnCount += records.length;
      for (const record of records) {
        const validation = validateArnTemplate(record);
        if (validation.reason) {
          state.violations.push({
            encoding: record.encoding,
            logicalResourceId: context.logicalResourceId,
            path: record.path,
            reason: validation.reason,
            serviceSegment: validation.serviceSegment ?? "<unparsed>",
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
    inspectResourceForPolicyDocuments(
      resource.Properties,
      { logicalResourceId, path: `Resources.${logicalResourceId}.Properties` },
      state
    );
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
      .map(
        ({ encoding, logicalResourceId, reason, serviceSegment, statementSid }) =>
          `${logicalResourceId}/${statementSid}:${encoding}:${reason}:service=${serviceSegment}`
      )
      .join(", ");
    throw new Error(`IAM Resource ARN validation failed: ${summary}`);
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
    process.stdout.write(
      `Validated ${result.resourceArnCount} IAM PolicyDocument Resource ARN templates across ${result.policyDocumentCount} policy documents.\n`
    );
  } catch (error) {
    process.stderr.write(`IAM Resource ARN validation failed: ${error.message}\n`);
    process.exit(1);
  }
}
