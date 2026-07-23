#!/usr/bin/env node
import { App, Tags } from "aws-cdk-lib";
import { ArchonPlatformStack, ArchonRegistryStack } from "../lib/archon-stack";

const app = new App();
const stage = String(app.node.tryGetContext("stage") ?? "staging").toLowerCase();
if (!/^[a-z][a-z0-9-]{1,15}$/.test(stage)) {
  throw new Error("CDK context 'stage' must match ^[a-z][a-z0-9-]{1,15}$");
}

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? "eu-west-1"
};

const registry = new ArchonRegistryStack(app, "Archon-Registry", {
  env,
  description: "Shared immutable container registry for Archon build-once promotion"
});

const platform = new ArchonPlatformStack(app, `Archon-${stage}`, {
  env,
  stage,
  repository: registry.repository,
  description: `Archon DataHub ${stage} control plane`
});
platform.addDependency(registry);

for (const stack of [registry, platform]) {
  Tags.of(stack).add("Application", "archon-datahub");
  Tags.of(stack).add("ManagedBy", "aws-cdk");
  Tags.of(stack).add("Environment", stack === registry ? "shared" : stage);
}
