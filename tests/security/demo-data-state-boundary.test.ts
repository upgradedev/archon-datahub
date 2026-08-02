import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/datahub-demo-state.yml", import.meta.url),
  "utf8"
);
const deploy = readFileSync(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8"
);
const liveProof = readFileSync(
  new URL("../../.github/workflows/live-datahub-proof.yml", import.meta.url),
  "utf8"
);
const contract = JSON.parse(readFileSync(
  new URL("../../contracts/datahub-demo-state-v1.json", import.meta.url),
  "utf8"
)) as any;

test("demo-state mutation remains manual, exact, approved and attested", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /^\s{2}(push|pull_request|schedule):/m);
  assert.match(workflow, /environment: datahub-demo/);
  assert.match(workflow, /APPROVE ARCHON DATAHUB DEMO/);
  assert.match(workflow, /sha256sum --check --strict SHA256SUMS/);
  assert.match(workflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(workflow, /datahub-demo-state\.py (?:apply|reset)/);
  assert.doesNotMatch(workflow, /configure-aws-credentials|Codex Security/i);
});

test("one canonical synthetic dataset binds deploy and live proof", () => {
  assert.equal(contract.schemaVersion, "archon.datahub-demo-state/v1");
  assert.equal(contract.binding.query, contract.binding.targetUrn);
  assert.match(contract.binding.targetUrn, /^urn:li:dataset:/);
  assert.ok(contract.officialBaseline.files.length >= 4);
  assert.match(deploy, /DATAHUB_DEMO_QUERY/);
  assert.match(deploy, /runtime-config\.json/);
});

test("live proof binds exact lean deployment and dual runtime identity", () => {
  for (const input of [
    "stage:",
    "release_sha:",
    "deployment_run_id:",
    "deployment_artifact_id:",
    "deployment_artifact_digest:",
    "governed_canary_run_id:",
    "profile:",
    "runtime_session_id:",
    "query:",
  ]) {
    assert.match(liveProof, new RegExp("^      " + input, "m"));
  }
  assert.match(
    liveProof,
    /deployment-evidence-\$\{STAGE\}-\$\{RELEASE_SHA\}-\$\{DEPLOYMENT_RUN_ID\}/
  );
  assert.match(liveProof, /archon\.aws-deployment-evidence\/v2/);
  assert.match(liveProof, /gh attestation verify/);
  assert.match(liveProof, /--signer-digest "\$\{RELEASE_SHA\}"/);
  assert.match(liveProof, /\/api\/runtime-profiles/);
  assert.match(liveProof, /\/api\/runtime-sessions\/\$\{RUNTIME_SESSION_ID\}/);
  assert.match(liveProof, /DATAHUB_CLOUD_GMS_URL/);
  assert.match(liveProof, /archon\.live-dual-runtime-proof\/v2/);
  assert.match(liveProof, /credentialed-live-semantic/);
  assert.match(liveProof, /active-session-capability/);
  assert.match(liveProof, /all\(\.fourComponents\[\]; \. == true\)/);
  assert.match(liveProof, /\.github\/workflows\/governed-canary\.yml/);
  assert.match(
    liveProof,
    /governed-canary-rollback-\$\{GOVERNED_CANARY_RUN_ID\}-1/
  );
  assert.match(liveProof, /--deny-self-hosted-runners/);
  assert.match(liveProof, /archon\.governed-canary-recovery-evidence\/v2/);
  assert.match(liveProof, /archon\.live-datahub-proof\/v3/);
  assert.match(liveProof, /archon\.deployed-datahub-semantic-proof\/v2/);
  assert.match(liveProof, /archon\.live-datahub-proof-attestation\/v4/);
  assert.match(
    liveProof,
    /attestations\/live-datahub-proof\/v4/
  );
  assert.match(liveProof, /proof-subject\.sha256/);
  for (const subject of [
    "proof.json",
    "deployment-evidence.json",
    "deployed-datahub-semantic-proof.json",
  ]) {
    assert.match(liveProof, new RegExp(subject.replaceAll(".", "\\.")));
  }
  assert.match(
    liveProof,
    /name: live-datahub-proof-\$\{\{ inputs\.release_sha \}\}-\$\{\{ github\.run_attempt \}\}/
  );
  assert.match(liveProof, /write-verified-and-rollback-proven/);  assert.match(liveProof, /retention-days: 90/);
  assert.match(liveProof, /rm -rf -- "\$\{RUNNER_TEMP\}\/live-proof"/);
  assert.doesNotMatch(
    liveProof,
    /staging-deployment-evidence|Archon-production|ECS|Fargate|VpcLink|Codex Security/i
  );
});
