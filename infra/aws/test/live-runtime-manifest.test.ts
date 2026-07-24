import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(__dirname, "../../../.github/workflows/deploy.yml"),
  "utf8"
);
const ciWorkflow = readFileSync(
  resolve(__dirname, "../../../.github/workflows/ci.yml"),
  "utf8"
);
const observer = readFileSync(
  resolve(__dirname, "../../../scripts/observe-aws-live-runtime.sh"),
  "utf8"
);

describe("live production runtime byte binding", () => {
  test("runs only in production after publish/smoke and before promotion evidence", () => {
    const production = workflow.indexOf("\n  production:");
    const spa = workflow.indexOf(
      "\n      - name: Publish the identical SPA after workload readiness",
      production
    );
    const smoke = workflow.indexOf(
      "\n      - name: Production smoke and security contracts",
      production
    );
    const liveRuntime = workflow.indexOf(
      "\n      - name: Bind exact live production runtime bytes",
      production
    );
    const evidence = workflow.indexOf(
      "\n      - name: Emit promotion evidence",
      production
    );

    expect(production).toBeGreaterThan(0);
    expect(spa).toBeGreaterThan(production);
    expect(smoke).toBeGreaterThan(spa);
    expect(liveRuntime).toBeGreaterThan(smoke);
    expect(evidence).toBeGreaterThan(liveRuntime);
    expect(workflow.indexOf("Bind exact live production runtime bytes")).toBe(
      liveRuntime + "\n      - name: ".length
    );
  });

  test("calls one reusable read-only observer with exact CI candidates", () => {
    const start = workflow.indexOf(
      "\n      - name: Bind exact live production runtime bytes"
    );
    const end = workflow.indexOf("\n      - name: Emit promotion evidence", start);
    const step = workflow.slice(start, end);

    expect(step).toContain("VERIFY_LOCAL_CANDIDATES: \"true\"");
    expect(step).toContain(
      "EXPECTED_IMAGE_DIGEST: ${{ steps.deploy.outputs.image_digest }}"
    );
    expect(step).toContain(
      "WEB_DIR: ${{ steps.artifacts.outputs.web_dir }}"
    );
    expect(step).toContain(
      "LAMBDA_DIR: ${{ steps.artifacts.outputs.lambda_dir }}"
    );
    expect(step).toContain(
      "RUNTIME_CONFIG: ${{ steps.spa.outputs.runtime_config }}"
    );
    expect(step).toContain("bash scripts/observe-aws-live-runtime.sh");
    expect(step).not.toMatch(
      /\baws\s+(?:create|delete|put|update)-[a-z-]+/u
    );
  });

  test("keeps observer mode AWS-derived and gates local candidates to deploy mode", () => {
    expect(observer).toContain(
      'VERIFY_LOCAL_CANDIDATES="${VERIFY_LOCAL_CANDIDATES:-false}"'
    );
    const deployMode = observer.indexOf(
      'if [[ "${VERIFY_LOCAL_CANDIDATES}" == "true" ]]'
    );
    expect(deployMode).toBeGreaterThan(0);
    expect(observer.indexOf(
      ': "${WEB_DIR:?WEB_DIR is required in deploy verification mode}"'
    )).toBeGreaterThan(deployMode);
    expect(observer.indexOf(
      ': "${LAMBDA_DIR:?LAMBDA_DIR is required in deploy verification mode}"'
    )).toBeGreaterThan(deployMode);
    expect(observer).not.toMatch(
      /\baws\s+(?:create|delete|put|update)-[a-z-]+/u
    );
    expect(observer).toContain(
      'test "$(basename "${OUTPUT_PATH}")" = "live-runtime-manifest.json"'
    );
  });

  test("verifies exact ECS task-definition and every running container digest", () => {
    expect(observer).toContain("aws ecs describe-services");
    expect(observer).toContain("aws ecs describe-task-definition");
    expect(observer).toContain("aws ecs list-tasks");
    expect(observer).toContain("aws ecs describe-tasks");
    expect(observer).toContain(".deployments | length) == 1");
    expect(observer).toContain('.deployments[0].status == "PRIMARY"');
    expect(observer).toContain('.deployments[0].rolloutState == "COMPLETED"');
    expect(observer).toContain('endswith("@" + $digest)');
    expect(observer).toContain(".imageDigest == $digest");
    expect(observer).toContain("imageReferenceSha256");
    expect(observer).toContain("Production ECS changed during live-runtime observation");
  });

  test("retries only complete isolated ECS snapshots with bounded backoff", () => {
    expect(observer).toContain("ECS_SNAPSHOT_ATTEMPTS=3");
    expect(observer).toContain("ECS_SNAPSHOT_BACKOFF_SECONDS=5");
    expect(observer).toContain("observe_ecs_once()");
    expect(observer).toContain("while (( attempt <= ECS_SNAPSHOT_ATTEMPTS )); do");
    expect(observer).toContain(
      'snapshot_dir="${work_dir}/ecs-snapshot-${attempt}"'
    );
    expect(observer).toContain(
      'service_entries="${snapshot_dir}/ecs-services.ndjson"'
    );
    expect(observer).toContain(
      '"${snapshot_dir}/task-definition-${role}.ndjson"'
    );
    expect(observer).toContain(
      'observe_ecs_once "${attempt_manifest}" "${snapshot_dir}"'
    );
    expect(observer).toContain('rm -rf -- "${snapshot_dir}"');
    expect(observer).toContain(
      'mv -- "${attempt_manifest}" "${manifest_path}"'
    );
    expect(observer).toContain("retrying from an empty snapshot");
    expect(observer).toContain("Unable to obtain one stable ECS snapshot after");
    expect(ciWorkflow).toContain("scripts/observe-aws-live-runtime.sh");
    expect(ciWorkflow).toContain('bash -n "${script}"');
  });

  test("verifies exact Lambda ZIP and sanitized stable configuration", () => {
    expect(observer).toContain("aws lambda get-function");
    expect(observer).toContain("aws lambda get-function-configuration");
    expect(observer).toContain(
      "approval|archon-production-approval|index.handler|approval"
    );
    expect(observer).toContain(
      "approval-handoff|archon-production-approval-handoff|handoff.handler|approval"
    );
    expect(observer).toContain(
      "control|archon-production-control|index.handler|control"
    );
    expect(observer).toContain("--arg version '$LATEST'");
    expect(observer).toContain("version: $version");
    expect(observer).toContain("RevisionId");
    expect(observer).toContain("configurationSha256");
    expect(observer).toContain("CodeSha256");
    expect(observer).toContain("openssl dgst -sha256 -binary");
    expect(observer).toContain("symlink or special Lambda ZIP entry");
    expect(observer).toContain(
      "live Lambda bytes differ from exact CI candidate"
    );
    expect(observer).not.toContain("Code.Location:");
  });

  test("binds exact latest KMS-encrypted SPA versions and removes stale assets", () => {
    expect(observer).toContain("aws s3api get-bucket-versioning");
    expect(observer).toContain("aws s3api get-bucket-encryption");
    expect(observer).toContain("aws s3api list-object-versions");
    expect(observer).toContain("aws s3api get-object");
    expect(observer).toContain("--version-id \"${version_id}\"");
    expect(observer).toContain("ArchonSpaKeyArn");
    expect(observer).toContain(".SSEKMSKeyId == $keyArn");
    expect(observer).toContain("select(.IsLatest == true)");
    expect(observer).toContain("DeleteMarkers");
    expect(observer).toContain("MAX_SPA_VERSION_RECORDS=20000");
    expect(observer).toContain("MAX_SPA_LATEST_STATES=8192");
    expect(observer).toContain("MAX_SPA_LIVE_OBJECTS=4096");
    expect(observer).toContain("MAX_SPA_TOTAL_BYTES=536870912");
    expect(observer).toContain('--max-items "${MAX_SPA_VERSION_RECORDS}"');
    expect(observer).toContain(
      "Production SPA latest versions changed during observation"
    );
    expect(observer).toContain("bucket_versioning_projection_initial");
    expect(observer).toContain("bucket_versioning_projection_final");
    expect(observer).toContain("bucket_encryption_projection_initial");
    expect(observer).toContain("bucket_encryption_projection_final");
    expect(observer).toContain(
      "Production SPA bucket versioning changed during observation"
    );
    expect(observer).toContain(
      "Production SPA bucket encryption changed during observation"
    );

    const productionSpa = workflow.slice(
      workflow.indexOf(
        "\n      - name: Publish the identical SPA after workload readiness"
      ),
      workflow.indexOf("\n      - name: Production smoke and security contracts")
    );
    expect(productionSpa).toMatch(
      /aws s3 sync "\$\{WEB_DIR\}\/" "s3:\/\/\$\{BUCKET\}\/" \\\n\s+--delete \\\n\s+--exclude 'runtime-config\.json'/u
    );
    const productionSync = productionSpa.slice(
      productionSpa.indexOf("aws s3 sync"),
      productionSpa.indexOf("aws s3 cp")
    );
    expect(productionSync).not.toContain("--exclude 'assets/*'");
    expect(productionSync).not.toContain("--exclude 'index.html'");
    expect(productionSpa).toContain("--paths '/*'");
    expect(productionSpa).toContain(
      "aws cloudfront wait invalidation-completed"
    );

    const stagingSpa = workflow.slice(
      workflow.indexOf(
        "\n      - name: Publish the exact SPA after workload readiness"
      ),
      workflow.indexOf("\n      - name: Staging smoke and security contracts")
    );
    const stagingSync = stagingSpa.slice(
      stagingSpa.indexOf("aws s3 sync"),
      stagingSpa.indexOf("aws s3 cp")
    );
    expect(stagingSync).toContain("--delete");
    expect(stagingSync).toContain("--exclude 'runtime-config.json'");
    expect(stagingSync).not.toContain("--exclude 'assets/*'");
    expect(stagingSync).not.toContain("--exclude 'index.html'");
    expect(stagingSpa).toContain("--paths '/*'");
  });

  test("seals canonical manifest into 90-day deployment evidence", () => {
    expect(observer).toContain(
      'schemaVersion: "archon.live-runtime-manifest/v1"'
    );
    expect(observer).toContain("sort_by(.role)");
    expect(observer).toContain("sort_by(.key)");
    expect(workflow).toContain(
      "liveRuntimeManifestSha256: $liveRuntimeManifestSha256"
    );
    expect(workflow).toContain(
      '"${evidence_dir}/live-runtime-manifest.json"'
    );
    expect(workflow).toMatch(
      /name: Upload immutable deployment evidence[\s\S]+retention-days: 90/u
    );
  });
});
