import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("lean deploy workflow contract", () => {
  const source = readFileSync(
    resolve(__dirname, "../../../.github/workflows/deploy.yml"),
    "utf8"
  );

  test("promotes immutable CI, image, AMI and staging receipts", () => {
    for (const required of [
      "release_sha:",
      "ci_run_id:",
      "cloud_runtime_artifact_id:",
      "cloud_runtime_artifact_digest:",
      "core_ami_artifact_id:",
      "core_ami_artifact_digest:",
      "staging_evidence_artifact_id:",
      "gh attestation verify",
      "archon.datahub-cloud-runtime-release/v1",
      "archon.datahub-core-ami-build/v2",
      "archon.aws-deployment-evidence/v2",
      "Archon-${STAGE}-Edge",
      "Archon-${STAGE}-Core",
      "Archon-${STAGE}-Judge",
      "DataHubCoreAmiId",
      "CloudRuntimeImageUri",
      "CloudRuntimeReleaseDigest",
      "LambdaArtifactSha256",
      "spa_tar_sha256=",
      "lambda_tar_sha256=",
      "control|control/*|runtime-control|runtime-control/*",
      "runtime-control/session.js",
      "actions/attest@",
      "retention-days: 90"
    ]) {
      expect(source).toContain(required);
    }
  });

  test("binds CloudFormation to verified inner tar bytes", () => {
    expect(source).toContain(
      '--parameters "${judge_stack}:SpaArtifactSha256=${SPA_TAR_SHA256}"'
    );
    expect(source).toContain(
      '--parameters "${judge_stack}:LambdaArtifactSha256=${LAMBDA_TAR_SHA256}"'
    );
    expect(source).toContain(
      "SPA_TAR_SHA256: ${{ steps.receipts.outputs.spa_tar_sha256 }}"
    );
    expect(source).toContain(
      "LAMBDA_TAR_SHA256: ${{ steps.receipts.outputs.lambda_tar_sha256 }}"
    );
    expect(source).not.toContain(
      "SpaArtifactSha256=${WEB_DIGEST#sha256:}"
    );
    expect(source).not.toContain(
      "LambdaArtifactSha256=${LAMBDA_DIGEST#sha256:}"
    );
  });

  test("does not rebuild candidates or restore retired topology", () => {
    expect(source).not.toMatch(/docker build/);
    expect(source).not.toMatch(/Archon-.*Registry/);
    expect(source).not.toMatch(/ECS|Fargate|NLB|VpcLink|Codex Security/i);
    expect(source).toContain('${RUNNER_TEMP}/promotion');
    expect(source).toContain("rm -rf --");
  });
});
