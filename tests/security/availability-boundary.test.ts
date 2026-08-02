import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(".github/workflows/availability.yml"),
  "utf8"
);

test("availability is a protected attested lean-runtime probe", () => {
  assert.match(workflow, /^permissions:\s*\{\}/m);
  assert.match(workflow, /environment: production-observer/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /verify-github-control-plane\.sh/);
  assert.match(workflow, /configure-aws-credentials@[0-9a-f]{40}/);
  assert.match(workflow, /vars\\.AWS_READ_ROLE_ARN/);
  assert.doesNotMatch(workflow, /AWS_OBSERVER_ROLE_ARN/);
  assert.match(workflow, /role/archon-production-posture-observer/);
  assert.doesNotMatch(workflow, /role/archon-production-observer/);
  assert.match(workflow, /observe-aws-live-runtime\.sh/);
  assert.match(workflow, /EXPECT_CORE_IDLE: "true"/);
  assert.match(workflow, /--proto '=https' --tlsv1\.2/);
  assert.match(workflow, /archon\.runtime-profiles\/v1/);
  assert.match(workflow, /\.autoSelection == "cloud"/);
  assert.match(
    workflow,
    /select\(\.profileId == "cloud"\)[\s\S]*== \["READY"\]/
  );
  assert.match(
    workflow,
    /select\(\.profileId == "core"\)[\s\S]*== \["LAUNCHABLE"\]/
  );
  assert.match(workflow, /all\(\.capabilities\[\]; \. == true\)/);
  for (const capability of [
    "agentContextKit",
    "analyticsAgent",
    "dataHubSkills",
    "mcpGovernedWrite",
    "mcpRead"
  ]) {
    assert.match(workflow, new RegExp(capability));
  }
  assert.match(workflow, /archon\.production-availability\/v2/);
  assert.match(
    workflow,
    /attestations\/production-availability\/v2/
  );
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(
    workflow,
    /name: production-availability-\$\{\{ github\.sha \}\}-\$\{\{ github\.run_id \}\}/
  );
  assert.match(workflow, /availability\/evidence\.json/);
  assert.match(workflow, /availability\/observation\.json/);
  assert.match(workflow, /retention-days: 90/);
  assert.doesNotMatch(
    workflow,
    /ECS|Fargate|NLB|VpcLink|codex\.security|live-runtime-manifest|production-availability\/v1/i
  );
});
