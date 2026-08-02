import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resolve } from "node:path";

const deployWorkflow = readFileSync(
  resolve(".github/workflows/deploy.yml"),
  "utf8"
);
const ciWorkflow = readFileSync(
  resolve(".github/workflows/ci.yml"),
  "utf8"
);
const supplyChainWorkflow = readFileSync(
  resolve(".github/workflows/supply-chain.yml"),
  "utf8"
);

test("deploy promotes only exact attested build-once artifacts", () => {
  assert.match(deployWorkflow, /release_sha:/);
  assert.match(deployWorkflow, /ci_run_id:/);
  assert.match(deployWorkflow, /cloud_runtime_artifact_id:/);
  assert.match(deployWorkflow, /cloud_runtime_artifact_digest:/);
  assert.match(deployWorkflow, /core_ami_artifact_id:/);
  assert.match(deployWorkflow, /core_ami_artifact_digest:/);
  assert.match(deployWorkflow, /staging_evidence_artifact_id:/);
  assert.match(deployWorkflow, /gh attestation verify/);
  assert.match(deployWorkflow, /datahub-cloud-runtime-release-/);
  assert.match(deployWorkflow, /archon\.datahub-core-ami-build\/v2/);
  assert.match(deployWorkflow, /@sha256:/);
  assert.match(deployWorkflow, /CloudRuntimeReleaseDigest/);
  assert.match(deployWorkflow, /DataHubCoreImageManifestDigest/);
  assert.match(deployWorkflow, /archon\.aws-deployment-evidence\/v2/);
  assert.match(deployWorkflow, /actions\/attest@[0-9a-f]{40}/);
  assert.match(deployWorkflow, /retention-days: 90/);
  assert.doesNotMatch(
    deployWorkflow,
    /docker build|cdk deploy.*Registry|Codex Security/i
  );
});

test("CI packages only the two deployed Node Lambda trees", () => {
  const start = ciWorkflow.indexOf(
    "- name: Package deterministic Lambda release candidate"
  );
  const end = ciWorkflow.indexOf(
    "- name: Upload exact Lambda release candidate"
  );
  assert.ok(start >= 0 && end > start);
  const packageStep = ciWorkflow.slice(start, end);
  assert.match(packageStep, /for name in control runtime-control/);
  assert.match(
    packageStep,
    /--directory "\$\{lambda_stage\}"[\s\S]*control runtime-control \|/
  );
  assert.match(
    packageStep,
    /control\|control\/\*\|runtime-control\|runtime-control\/\*/
  );
  assert.match(packageStep, /control\/remediation\.js/);
  assert.match(packageStep, /runtime-control\/index\.js/);
  assert.match(packageStep, /runtime-control\/session\.js/);
  assert.match(packageStep, /Duplicate Lambda release archive member/);
  assert.doesNotMatch(packageStep, /\bapproval\b/);
});

test("supply-chain revalidates the exact lean Lambda archive", () => {
  assert.match(
    supplyChainWorkflow,
    /control\|control\/\*\|runtime-control\|runtime-control\/\*/
  );
  for (const required of [
    "control/index.js",
    "control/remediation.js",
    "runtime-control/index.js",
    "runtime-control/session.js",
    "runtime-control/node_modules",
    "archon-production-runtime-control:runtime-control.json",
    "archon-production-runtime-remediation:control.json"
  ]) {
    assert.ok(supplyChainWorkflow.includes(required), required);
  }
  assert.doesNotMatch(
    supplyChainWorkflow,
    /approval\|approval\/\*|LAMBDA_CONTENT_DIR\/approval/
  );
});
