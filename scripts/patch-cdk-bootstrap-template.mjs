#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

function fail(message) {
  process.stderr.write(`CDK bootstrap patch failed: ${message}\n`);
  process.exit(1);
}

const args = Object.fromEntries(
  Array.from({ length: process.argv.slice(2).length / 2 }, (_, index) => {
    const offset = index * 2 + 2;
    return [process.argv[offset]?.replace(/^--/, ""), process.argv[offset + 1]];
  })
);
if (
  !args.input ||
  !args.output ||
  !["staging", "production"].includes(args.stage) ||
  !["eu-west-1", "us-east-1"].includes(args.region)
) {
  fail(
    "expected --input, --output, --stage staging|production, and --region eu-west-1|us-east-1"
  );
}

const input = await readFile(resolve(args.input), "utf8");
const roleStart = input.indexOf("  DeploymentActionRole:\n");
const roleEnd = input.indexOf("  CloudFormationExecutionRole:\n", roleStart);
if (roleStart < 0 || roleEnd < 0) fail("DeploymentActionRole section not found");
const role = input.slice(roleStart, roleEnd);
const policiesStart = role.indexOf("      Policies:\n");
const roleNameStart = role.indexOf("      RoleName:\n", policiesStart);
if (policiesStart < 0 || roleNameStart < 0) {
  fail("DeploymentActionRole policy boundaries not found");
}
for (const required of [
  "cloudformation:DeleteStack",
  "cloudformation:CreateStackRefactor",
  "AWSCloudFormationReadOnlyAccess",
  'Resource: "*"'
]) {
  if (!role.includes(required)) fail(`pinned v32 source marker missing: ${required}`);
}

const stackNames =
  args.region === "us-east-1"
    ? [`Archon-${args.stage}-Edge`]
    : args.stage === "staging"
      ? ["Archon-staging", "Archon-Registry"]
      : ["Archon-production"];
const stackResources = stackNames
  .map(
    (stack) =>
      `                  - Fn::Sub: "arn:\${AWS::Partition}:cloudformation:\${AWS::Region}:\${AWS::AccountId}:stack/${stack}/*"`
  )
  .join("\n");
const customPolicies = `      Policies:
        - PolicyDocument:
            Statement:
              - Sid: InspectOnlyStageStacks
                Effect: Allow
                Action:
                  - cloudformation:DescribeStackEvents
                  - cloudformation:DescribeStackResource
                  - cloudformation:DescribeStackResources
                  - cloudformation:DescribeStacks
                  - cloudformation:GetTemplate
                  - cloudformation:ListStackResources
                  - cloudformation:UpdateTerminationProtection
                Resource:
${stackResources}
              - Sid: CreateOrUpdateOnlyWithBootstrapExecutionRole
                Effect: Allow
                Action:
                  - cloudformation:CreateStack
                  - cloudformation:UpdateStack
                Resource:
${stackResources}
                Condition:
                  ArnEquals:
                    cloudformation:RoleArn:
                      Fn::GetAtt:
                        - CloudFormationExecutionRole
                        - Arn
              - Sid: CreateOnlyCdkDeployChangeSet
                Effect: Allow
                Action: cloudformation:CreateChangeSet
                Resource:
${stackResources}
                Condition:
                  ArnEquals:
                    cloudformation:RoleArn:
                      Fn::GetAtt:
                        - CloudFormationExecutionRole
                        - Arn
                  StringEquals:
                    cloudformation:ChangeSetName: cdk-deploy-change-set
              - Sid: UseOnlyCdkDeployChangeSets
                Effect: Allow
                Action:
                  - cloudformation:DeleteChangeSet
                  - cloudformation:DescribeChangeSet
                  - cloudformation:ExecuteChangeSet
                Resource:
${stackResources}
                Condition:
                  StringEquals:
                    cloudformation:ChangeSetName: cdk-deploy-change-set
              - Sid: InspectTemplatesWithoutStackMutation
                Effect: Allow
                Action:
                  - cloudformation:GetTemplateSummary
                  - cloudformation:ValidateTemplate
                Resource: "*"
              - Sid: PassOnlyThisBootstrapExecutionRole
                Effect: Allow
                Action: iam:PassRole
                Resource:
                  Fn::Sub: "\${CloudFormationExecutionRole.Arn}"
                Condition:
                  StringEquals:
                    iam:PassedToService: cloudformation.amazonaws.com
              - Sid: VerifyCaller
                Effect: Allow
                Action: sts:GetCallerIdentity
                Resource: "*"
              - Sid: ReadOnlyThisBootstrapStagingBucket
                Effect: Allow
                Action:
                  - s3:GetObject*
                  - s3:GetBucket*
                  - s3:List*
                Resource:
                  - Fn::Sub: \${StagingBucket.Arn}
                  - Fn::Sub: \${StagingBucket.Arn}/*
              - Sid: ReadOnlyThisBootstrapVersion
                Effect: Allow
                Action:
                  - ssm:GetParameter
                  - ssm:GetParameters
                Resource:
                  - Fn::Sub: "arn:\${AWS::Partition}:ssm:\${AWS::Region}:\${AWS::AccountId}:parameter\${CdkBootstrapVersion}"
            Version: "2012-10-17"
          PolicyName: default
`;
const patchedRole =
  role.slice(0, policiesStart) + customPolicies + role.slice(roleNameStart);
let output = input.slice(0, roleStart) + patchedRole + input.slice(roleEnd);
const defaultVariant = "    Default: 'AWS CDK: Default Resources'";
if (output.split(defaultVariant).length !== 2) {
  fail("expected exactly one default BootstrapVariant marker");
}
output = output.replace(
  defaultVariant,
  `    Default: 'Archon DataHub ${args.stage} ${args.region} isolated bootstrap v1'`
);

const outputRoleEnd = output.indexOf(
  "  CloudFormationExecutionRole:\n",
  roleStart
);
if (outputRoleEnd < 0) fail("patched DeploymentActionRole boundary not found");
const outputRole = output.slice(roleStart, outputRoleEnd);
for (const forbidden of [
  "cloudformation:DeleteStack",
  "cloudformation:RollbackStack",
  "cloudformation:ContinueUpdateRollback",
  "cloudformation:CreateStackRefactor",
  "cloudformation:ExecuteStackRefactor",
  "AWSCloudFormationReadOnlyAccess",
  "PipelineCrossAccountArtifactsBucket",
  "PipelineCrossAccountArtifactsKey"
]) {
  if (outputRole.includes(forbidden)) {
    fail(`forbidden deployment-role permission survived: ${forbidden}`);
  }
}
if (
  !output.includes(
    `Archon DataHub ${args.stage} ${args.region} isolated bootstrap v1`
  )
) {
  fail("custom BootstrapVariant was not written");
}
for (const required of [
  "cloudformation:RoleArn:",
  "cloudformation:ChangeSetName: cdk-deploy-change-set",
  "Fn::GetAtt:",
  "InspectOnlyStageStacks",
  "CreateOrUpdateOnlyWithBootstrapExecutionRole",
  "CreateOnlyCdkDeployChangeSet",
  "UseOnlyCdkDeployChangeSets"
]) {
  if (!outputRole.includes(required)) {
    fail(`required deployment-role restriction missing: ${required}`);
  }
}
await writeFile(resolve(args.output), output, { encoding: "utf8", mode: 0o600 });
