import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(".github/workflows/production-posture.yml"),
  "utf8"
);

test("posture proves drift, alarms, encryption controls and zero idle", () => {
  assert.match(workflow, /^permissions:\s*\{\}/m);
  assert.match(workflow, /environment: production-observer/);
  assert.match(
    workflow,
    /OBSERVER_ROLE: \$\{\{ vars\.AWS_READ_ROLE_ARN \}\}/u
  );
  assert.match(workflow, /role\/archon-production-posture-observer/u);
  assert.doesNotMatch(
    workflow,
    /AWS_OBSERVER_ROLE_ARN|role\/archon-production-observer/u
  );
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /verify-github-control-plane\.sh/);
  assert.match(workflow, /observe-aws-live-runtime\.sh/);
  assert.match(workflow, /EXPECT_CORE_IDLE: "true"/);
  assert.match(workflow, /detect-stack-drift/);
  assert.match(workflow, /Archon-production-Edge/);
  assert.match(workflow, /Archon-production-Core/);
  assert.match(workflow, /Archon-production-Judge/);
  assert.match(workflow, /StackDriftStatus == "IN_SYNC"/);
  assert.match(workflow, /StateValue != "ALARM"/);
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(workflow, /rawIdentifiersRetained:false/);
  assert.doesNotMatch(workflow, /ECS|Fargate|NLB|VpcLink|codex.security/i);
});
