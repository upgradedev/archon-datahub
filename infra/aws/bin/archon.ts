#!/usr/bin/env node
import {
  App,
  DefaultStackSynthesizer,
  Tags
} from "aws-cdk-lib";
import { ArchonEdgeStack } from "../lib/archon-edge-stack";
import { ArchonJudgeStack } from "../lib/archon-judge-stack";
import { ArchonEphemeralDataHubCoreStack } from "../lib/ephemeral-datahub-core-stack";

const app = new App();
const stage = String(
  app.node.tryGetContext("stage") ?? "staging"
).toLowerCase();
if (stage !== "staging" && stage !== "production") {
  throw new Error(
    "CDK context 'stage' must be exactly staging or production"
  );
}
const bootstrapQualifier =
  stage === "production" ? "archonprd" : "archonstg";
const synthesizer = (): DefaultStackSynthesizer =>
  new DefaultStackSynthesizer({
    qualifier: bootstrapQualifier
  });
const account = process.env.CDK_DEFAULT_ACCOUNT;
const region =
  process.env.AWS_REGION ??
  process.env.AWS_DEFAULT_REGION ??
  process.env.CDK_DEFAULT_REGION ??
  "eu-west-1";
const regionalEnv = { account, region };

const edge = new ArchonEdgeStack(
  app,
  `Archon-${stage}-Edge`,
  {
    env: { account, region: "us-east-1" },
    stage,
    description:
      `Archon DataHub ${stage} global certificate and WAF`,
    synthesizer: synthesizer(),
    terminationProtection: stage === "production"
  }
);
const core = new ArchonEphemeralDataHubCoreStack(
  app,
  `Archon-${stage}-Core`,
  {
    env: regionalEnv,
    stage,
    description:
      `Archon DataHub ${stage} zero-idle OSS Core runtime`,
    synthesizer: synthesizer(),
    terminationProtection: stage === "production"
  }
);
const judge = new ArchonJudgeStack(
  app,
  `Archon-${stage}-Judge`,
  {
    env: regionalEnv,
    stage,
    description:
      `Archon DataHub ${stage} serverless dual-runtime judge application`,
    synthesizer: synthesizer(),
    terminationProtection: stage === "production"
  }
);
judge.addDependency(core);

for (const stack of [edge, core, judge]) {
  Tags.of(stack).add("Application", "archon-datahub");
  Tags.of(stack).add("Environment", stage);
  Tags.of(stack).add("ManagedBy", "aws-cdk");
  Tags.of(stack).add(
    "CostModel",
    stack === core ? "zero-idle-ephemeral" : "serverless"
  );
}
