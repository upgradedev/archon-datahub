import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/governed-canary.yml", import.meta.url),
  "utf8"
);
const recovery = readFileSync(
  new URL("../../.github/workflows/governed-canary-recovery.yml", import.meta.url),
  "utf8"
);
const driver = readFileSync(
  new URL("../../scripts/governed-canary.ts", import.meta.url),
  "utf8"
);
const deploy = readFileSync(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8"
);

test("governed canary is staging-only, manually approved and rollback-bound", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /^\s{2}(push|pull_request|schedule):/m);
  assert.match(workflow, /Archon-staging/);
  assert.doesNotMatch(workflow, /CANARY_STACK_NAME: Archon-production/);
  assert.match(workflow, /RUN ISOLATED GOVERNED CANARY/);
  assert.match(workflow, /environment:\n      name: governed-canary/);
  assert.match(workflow, /datahub-canary-fixture\.yml/);
  assert.match(workflow, /gh attestation verify/);
  assert.match(workflow, /rollback/);
  assert.match(recovery, /workflow_dispatch/);
  assert.match(driver, /GOVERNED_TAG_MUTATION|add_tags/);
});

test("production promotion is independent of mutable canary state", () => {
  assert.match(deploy, /staging_evidence_artifact_id/);
  assert.match(deploy, /archon\.aws-deployment-evidence\/v2/);
  assert.doesNotMatch(deploy, /repository_dispatch|workflow_run:/);
  assert.doesNotMatch(deploy, /Codex Security/i);
});
