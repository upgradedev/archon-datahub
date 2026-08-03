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

  test("gates exact stage authority and post-deploy role bindings", () => {
    for (const required of [
      "Fail closed on exact stage deployment role before AWS trust",
      "AWS_DEPLOY_ROLE_ARN: ${{ vars.AWS_DEPLOY_ROLE_ARN }}",
      "archon-datahub-github-${STAGE}-deploy",
      "role-to-assume: ${{ steps.deploy_authority.outputs.role_arn }}",
      "allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}",
      "Preflight exact lean stack execution-role bindings",
      "ALLOW_ABSENT=true",
      "Verify exact post-deploy CloudFormation role bindings",
      "ALLOW_ABSENT=false",
      "ALLOW_ROLE_MIGRATION=false",
      "bash scripts/validate-cloudformation-role-bindings.sh"
    ]) {
      expect(source).toContain(required);
    }
    expect(source.match(
      /bash scripts\/validate-cloudformation-role-bindings[.]sh/g
    )).toHaveLength(2);
    expect(source).not.toContain(
      "role-to-assume: ${{ vars.AWS_DEPLOY_ROLE_ARN }}"
    );

    const beforeTrust = source.indexOf(
      "Fail closed on exact stage deployment role before AWS trust"
    );
    const acquire = source.indexOf(
      "Acquire short-lived deployment authority"
    );
    const preflight = source.indexOf(
      "Preflight exact lean stack execution-role bindings"
    );
    const deploy = source.indexOf(
      "Deploy Edge, zero-idle Core, then serverless Judge"
    );
    const postDeploy = source.indexOf(
      "Verify exact post-deploy CloudFormation role bindings"
    );
    expect(beforeTrust).toBeLessThan(acquire);
    expect(acquire).toBeLessThan(preflight);
    expect(preflight).toBeLessThan(deploy);
    expect(deploy).toBeLessThan(postDeploy);
  });

  test("scopes AWS mutation permissions to only the deploy job", () => {
    expect(source).toMatch(/^permissions: \{\}$/m);
    expect(source).toMatch(
      /jobs:\n  deploy:[\s\S]*?    permissions:\n      actions: read\n      attestations: write\n      contents: read\n      id-token: write\n/
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
