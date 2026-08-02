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
  assert.match(workflow, /observe-aws-live-runtime\.sh/);
  assert.match(workflow, /EXPECT_CORE_IDLE: "true"/);
  assert.match(workflow, /--proto '=https' --tlsv1\.2/);
  assert.match(workflow, /archon\.runtime-profiles\/v1/);
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(workflow, /retention-days: 90/);
  assert.doesNotMatch(workflow, /ECS|Fargate|NLB|VpcLink|codex.security/i);
});
