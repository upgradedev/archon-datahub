#!/usr/bin/env node
import { App, DefaultStackSynthesizer, Tags } from "aws-cdk-lib";
import { ArchonEdgeStack } from "../lib/archon-edge-stack";
import { ArchonPlatformStack, ArchonRegistryStack } from "../lib/archon-stack";

const app = new App();
const stage = String(app.node.tryGetContext("stage") ?? "staging").toLowerCase();
if (!/^[a-z][a-z0-9-]{1,15}$/.test(stage)) {
  throw new Error("CDK context 'stage' must match ^[a-z][a-z0-9-]{1,15}$");
}
if (stage !== "staging" && stage !== "production") {
  throw new Error("CDK context 'stage' must be exactly staging or production");
}
const bootstrapQualifier = stage === "production" ? "archonprd" : "archonstg";
const stackSynthesizer = (): DefaultStackSynthesizer =>
  new DefaultStackSynthesizer({ qualifier: bootstrapQualifier });

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  // AWS_REGION/AWS_DEFAULT_REGION are deployment inputs. CDK_DEFAULT_REGION
  // is emitted by the CLI and may fall back to us-east-1 without credentials.
  region:
    process.env.AWS_REGION ??
    process.env.AWS_DEFAULT_REGION ??
    process.env.CDK_DEFAULT_REGION ??
    "eu-west-1"
};

const registry =
  stage === "staging"
    ? new ArchonRegistryStack(app, "Archon-Registry", {
        env,
        description:
          "Shared immutable container registry for Archon build-once promotion",
        synthesizer: stackSynthesizer(),
        terminationProtection: true
      })
    : undefined;

const edge = new ArchonEdgeStack(app, `Archon-${stage}-Edge`, {
  env: {
    account: env.account,
    region: "us-east-1"
  },
  stage,
  description: `Archon DataHub ${stage} global CloudFront WAF and logging`,
  synthesizer: stackSynthesizer(),
  terminationProtection: stage === "production"
});

const platform = new ArchonPlatformStack(app, `Archon-${stage}`, {
  env,
  stage,
  repository: registry?.repository,
  description: `Archon DataHub ${stage} control plane`,
  synthesizer: stackSynthesizer(),
  terminationProtection: stage === "production"
});
if (registry !== undefined) {
  platform.addStackDependency(registry);
}

for (const stack of [edge, platform, ...(registry === undefined ? [] : [registry])]) {
  Tags.of(stack).add("Application", "archon-datahub");
  Tags.of(stack).add("ManagedBy", "aws-cdk");
  Tags.of(stack).add(
    "Environment",
    registry !== undefined && stack === registry ? "shared" : stage
  );
}
