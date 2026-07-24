#!/usr/bin/env node
import { App, Tags } from "aws-cdk-lib";
import { ArchonEdgeStack } from "../lib/archon-edge-stack";
import { ArchonPlatformStack, ArchonRegistryStack } from "../lib/archon-stack";

const app = new App();
const stage = String(app.node.tryGetContext("stage") ?? "staging").toLowerCase();
if (!/^[a-z][a-z0-9-]{1,15}$/.test(stage)) {
  throw new Error("CDK context 'stage' must match ^[a-z][a-z0-9-]{1,15}$");
}

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

const registry = new ArchonRegistryStack(app, "Archon-Registry", {
  env,
  description: "Shared immutable container registry for Archon build-once promotion",
  terminationProtection: true
});

const edge = new ArchonEdgeStack(app, `Archon-${stage}-Edge`, {
  env: {
    account: env.account,
    region: "us-east-1"
  },
  stage,
  description: `Archon DataHub ${stage} global CloudFront certificate and WAF`,
  terminationProtection: stage === "production"
});

const platform = new ArchonPlatformStack(app, `Archon-${stage}`, {
  env,
  stage,
  repository: registry.repository,
  description: `Archon DataHub ${stage} control plane`,
  terminationProtection: stage === "production"
});
platform.addStackDependency(registry);

for (const stack of [registry, edge, platform]) {
  Tags.of(stack).add("Application", "archon-datahub");
  Tags.of(stack).add("ManagedBy", "aws-cdk");
  Tags.of(stack).add("Environment", stack === registry ? "shared" : stage);
}
