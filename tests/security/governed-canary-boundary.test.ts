import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

const workflow = readFileSync(
  new URL("../../.github/workflows/governed-canary.yml", import.meta.url),
  "utf8"
);
const deploymentWorkflow = readFileSync(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8"
);
const driver = readFileSync(
  new URL("../../scripts/governed-canary.ts", import.meta.url),
  "utf8"
);
const recoveryWorkflow = readFileSync(
  new URL(
    "../../.github/workflows/governed-canary-recovery.yml",
    import.meta.url
  ),
  "utf8"
);

test("governed canary is dispatch-only, staging-only, and independently approved", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/mu);
  assert.doesNotMatch(workflow, /^\s{2}(?:push|pull_request|schedule):/mu);
  assert.match(workflow, /CANARY_STACK_NAME: Archon-staging/u);
  assert.doesNotMatch(workflow, /CANARY_STACK_NAME: Archon-production/u);
  assert.match(workflow, /name: governed-canary\n/u);
  assert.match(workflow, /name: governed-canary-rollback\n/u);
  assert.match(workflow, /prevent_self_review == true/u);
  assert.match(workflow, /RUN ISOLATED GOVERNED CANARY/u);
  assert.match(workflow, /\.path == "\.github\/workflows\/deploy\.yml"/u);
  assert.match(workflow, /\.head_repository\.full_name == \$repository/u);
  assert.match(
    workflow,
    /expected_artifact="staging-deployment-evidence-\$\{CANARY_RELEASE_SHA\}-\$\{run_attempt\}"/u
  );
  assert.match(
    workflow,
    /gh run download "\$\{CANARY_DEPLOYMENT_RUN_ID\}" \\\n\s+--repo "\$\{GITHUB_REPOSITORY\}"/u
  );
  assert.doesNotMatch(workflow, /startsWith\(\$prefix\)|startswith\(\$prefix\)/u);
});

test("production requires a fail-closed exact-run governed canary gate", () => {
  const gateStart = deploymentWorkflow.indexOf("\n  preproduction_canary:");
  const productionStart = deploymentWorkflow.indexOf("\n  production:");
  assert.ok(gateStart > 0);
  assert.ok(productionStart > gateStart);
  const gate = deploymentWorkflow.slice(gateStart, productionStart);
  const production = deploymentWorkflow.slice(productionStart);

  assert.match(gate, /needs: staging/u);
  assert.match(
    gate,
    /permissions:\n      actions: write\n      attestations: read\n      contents: read/u
  );
  assert.match(
    gate,
    /X-GitHub-Api-Version: 2026-03-10[\s\S]+actions\/workflows\/governed-canary\.yml\/dispatches/u
  );
  assert.match(gate, /return_run_details: true/u);
  assert.match(gate, /\.workflow_run_id == \$runId/u);
  assert.match(gate, /\.run_url == \$apiUrl/u);
  assert.match(gate, /\.html_url == \$htmlUrl/u);
  assert.match(gate, /\.path == "\.github\/workflows\/governed-canary\.yml"/u);
  assert.match(gate, /\.head_repository\.full_name == \$repository/u);
  assert.match(gate, /\.head_sha == \$sha/u);
  assert.match(gate, /\.event == "workflow_dispatch"/u);
  assert.match(gate, /\.conclusion'\s+<<<"\$\{canary_json\}"/u);
  assert.match(gate, /governed-canary-rollback-\$\{canary_run_id\}-1/u);
  assert.match(gate, /test "\$\{#archive_entries\[@\]\}" = "3"/u);
  assert.match(gate, /Unsafe rollback evidence path/u);
  assert.match(gate, /Symlinks are not permitted in rollback evidence/u);
  assert.match(gate, /sha256sum --check --strict rollback-subject\.sha256/u);
  assert.match(gate, /gh attestation verify/u);
  assert.match(gate, /--signer-digest "\$\{CONTROL_PLANE_SHA\}"/u);
  assert.match(gate, /--source-digest "\$\{CONTROL_PLANE_SHA\}"/u);
  assert.match(
    gate,
    /\.verificationResult\.statement\.predicate ==\s+\$expectedPredicate/u
  );
  assert.match(
    gate,
    /\.verificationResult\.statement\.subject\[\][\s\S]+\.digest\.sha256 == \$subjectSha256/u
  );
  assert.match(
    gate,
    /result == "write-verified-and-rollback-proven"/u
  );

  assert.match(
    production,
    /needs:\n      - staging\n      - preproduction_canary/u
  );
  assert.match(
    production,
    /CANARY_RUN_ID: \$\{\{ needs\.preproduction_canary\.outputs\.run_id \}\}/u
  );
  assert.match(
    production,
    /preProductionGovernedCanary: \{[\s\S]+rollbackSubjectSha256:[\s\S]+attestationVerificationSha256:[\s\S]+result: "write-verified-and-rollback-proven"/u
  );
});

test("an active parent deployment is accepted only after same-attempt staging and before production", () => {
  assert.match(
    workflow,
    /\.status == "completed" and\s+\.conclusion == "success"[\s\S]+\.status == "in_progress" and\s+\.conclusion == null/u
  );
  assert.match(
    workflow,
    /actions\/runs\/\$\{CANARY_DEPLOYMENT_RUN_ID\}\/attempts\/\$\{run_attempt\}\/jobs/u
  );
  assert.match(
    workflow,
    /select\(\.name == "Verify once and deploy staging"\)/u
  );
  assert.match(workflow, /\$staging\[0\]\.run_attempt == \$runAttempt/u);
  assert.match(workflow, /\$staging\[0\]\.status == "completed"/u);
  assert.match(workflow, /\$staging\[0\]\.conclusion == "success"/u);
  assert.match(
    workflow,
    /select\(\.name == "Approve and promote identical artifacts"\)/u
  );
  assert.match(
    workflow,
    /\.started_at != null or\s+\(\.status != "queued" and \.status != "pending"\)/u
  );
});

test("canary mutation and recovery require one exact green control plane", () => {
  const sharedConcurrency =
    /concurrency:\n  group: archon-governed-canary-mutation-recovery\n  cancel-in-progress: false/u;
  assert.match(workflow, sharedConcurrency);
  assert.match(recoveryWorkflow, sharedConcurrency);

  assert.match(workflow, /-f "head_sha=\$\{GITHUB_SHA\}"/u);
  assert.doesNotMatch(workflow, /-f status=(?:completed|success)/u);
  assert.match(workflow, /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u);
  assert.match(workflow, /workflow_success ci\.yml CI/u);
  assert.match(workflow, /workflow_success codeql\.yml CodeQL/u);
  assert.match(
    workflow,
    /workflow_success workflow-security\.yml "Workflow security"/u
  );
  assert.match(
    workflow,
    /\.head_sha == \$controlPlane[\s\S]+\.source\.deploymentControlPlaneSha == \$controlPlane/u
  );
  assert.match(
    workflow,
    /\.schemaVersion == "archon\.deployment-control-plane-gates\/v1"/u
  );
  assert.match(
    workflow,
    /test "\$\{current_default_sha\}" = "\$\{GITHUB_SHA\}"/u
  );
  assert.match(
    workflow,
    /control_plane_gate_sha256: \$\{\{ steps\.source\.outputs\.control_plane_gate_sha256 \}\}/u
  );
  assert.match(
    workflow,
    /echo "control_plane_gate_sha256=\$\{expected_gate_sha\}"/u
  );
  assert.match(
    workflow,
    /control_plane_output="\$\{recovery_dir\}\/control-plane-security-gates\.json"/u
  );
  assert.match(
    workflow,
    /path: \$\{\{ steps\.prepare\.outputs\.artifact_path \}\}/u
  );
  assert.match(
    driver,
    /const RECOVERY_SCHEMA = "archon\.governed-canary-recovery\/v2"/u
  );
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/u);
  assert.match(workflow, /controlPlaneSha: \$controlPlaneSha/u);
  assert.match(
    workflow,
    /deploymentEvidenceSha256: \$deploymentEvidenceSha256/u
  );

  assert.match(
    recoveryWorkflow,
    /EVENT_PARENT_HEAD_SHA: \$\{\{ github\.event\.workflow_run\.head_sha \}\}/u
  );
  const recoveryDriverSeal = recoveryWorkflow.indexOf(
    "Seal trusted recovery driver before protected approval"
  );
  assert.ok(recoveryDriverSeal > 0);
  const historicalRecoveryValidation = recoveryWorkflow.slice(
    0,
    recoveryDriverSeal
  );
  assert.doesNotMatch(
    historicalRecoveryValidation,
    /actions\/workflows\//u
  );
  assert.doesNotMatch(
    historicalRecoveryValidation,
    /-f "head_sha=\$\{PARENT_HEAD_SHA\}"/u
  );
  assert.doesNotMatch(
    historicalRecoveryValidation,
    /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u
  );
  assert.match(
    recoveryWorkflow,
    /CONTROL_PLANE_GATES_PATH: \$\{\{ runner\.temp \}\}\/parent-recovery\/control-plane-security-gates\.json/u
  );
  assert.match(
    recoveryWorkflow,
    /\.schemaVersion == "archon\.governed-canary-recovery\/v2"/u
  );
  assert.match(
    recoveryWorkflow,
    /id: manifest\n\s+env:\n\s+GH_TOKEN: \$\{\{ github\.token \}\}/u
  );
  assert.match(
    recoveryWorkflow,
    /test "\$\(sha256sum "\$\{CONTROL_PLANE_GATES_PATH\}" \| awk '\{print \$1\}'\)" = \\\n\s+"\$\{expected_gate_sha256\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /jq -cS 'del\(\.recoveryDigest\)' "\$\{RECOVERY_PATH\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /test "\$\{actual_recovery_digest\}" = \\\n\s+"\$\(jq -er '\.recoveryDigest' "\$\{RECOVERY_PATH\}"\)"/u
  );
  assert.match(
    recoveryWorkflow,
    /PARENT_HEAD_SHA="\$\(jq -er '\.head_sha' <<<"\$\{parent_json\}"\)"/u
  );
  assert.match(
    recoveryWorkflow,
    /test "\$\{EVENT_PARENT_HEAD_SHA\}" = "\$\{PARENT_HEAD_SHA\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /\.schemaVersion == "archon\.deployment-control-plane-gates\/v1" and\s+\.sourceSha == \$sha/u
  );
  assert.match(
    recoveryWorkflow,
    /\(\[\.workflows\[\]\.path\] \| sort\) == \[\s+"\.github\/workflows\/ci\.yml",\s+"\.github\/workflows\/codeql\.yml",\s+"\.github\/workflows\/workflow-security\.yml"/u
  );
  assert.match(
    recoveryWorkflow,
    /actions\/runs\/\$\{run_id\}\/attempts\/\$\{run_attempt\}/u
  );
  assert.match(recoveryWorkflow, /\.workflow_id == \$workflowId/u);
  assert.match(recoveryWorkflow, /\.run_attempt == \$runAttempt/u);
  assert.match(recoveryWorkflow, /\.name == \$name/u);
  assert.match(
    recoveryWorkflow,
    /\.head_sha == \$sha and\s+\.event == "push" and\s+\.status == "completed" and\s+\.conclusion == "success"/u
  );
  assert.match(
    recoveryWorkflow,
    /CANARY_CONTROL_PLANE_SHA: \$\{\{ needs\.resolve-parent\.outputs\.control_plane_sha \}\}/u
  );
  assert.match(
    recoveryWorkflow,
    /id: recovery_driver[\s\S]+\/git\/ref\/heads\/master/u
  );
  assert.match(
    recoveryWorkflow,
    /ref: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}/u
  );
  assert.doesNotMatch(
    recoveryWorkflow,
    /ref: \$\{\{ steps\.recovery_driver\.outputs\.sha \}\}/u
  );
  assert.doesNotMatch(
    recoveryWorkflow,
    /ref: \$\{\{ needs\.resolve-parent\.outputs\.control_plane_sha \}\}/u
  );
  assert.match(recoveryWorkflow, /\.head_sha == \$controlPlane/u);
  assert.match(recoveryWorkflow, /controlPlaneSha: \$controlPlaneSha/u);
  assert.match(
    recoveryWorkflow,
    /parentControlPlaneGatesSha256:\s+\$parentControlPlaneGatesSha256/u
  );
  assert.match(recoveryWorkflow, /recoveryDriverSha: \$recoveryDriverSha/u);
  assert.match(
    recoveryWorkflow,
    /recoveryDriverControlPlaneGatesSha256:\s+\$recoveryDriverControlPlaneGatesSha256/u
  );

  assert.match(workflow, /\.path == \$path/u);
  assert.match(workflow, /\.head_sha == \$sha/u);
  assert.match(workflow, /\.head_repository\.full_name == \$repository/u);
  assert.match(workflow, /\.event == "push"/u);
  assert.match(workflow, /\.conclusion == "success"/u);
  assert.match(recoveryWorkflow, /\.conclusion == "success"/u);
});

test("every canary AWS, secret, and mutation boundary revalidates one sealed gate digest", () => {
  assert.equal(
    (workflow.match(/bash scripts\/verify-github-control-plane\.sh/gu) ?? [])
      .length,
    5
  );
  assert.equal(
    (workflow.match(/EXPECTED_GATE_SHA256:/gu) ?? []).length,
    5
  );
  assert.equal(
    (
      workflow.match(
        /EXPECTED_GATE_SHA256: \$\{\{ needs\.prepare\.outputs\.control_plane_gate_sha256 \}\}/gu
      ) ?? []
    ).length,
    4
  );

  const prepareStart = workflow.indexOf("\n  prepare:");
  const approvalStart = workflow.indexOf("\n  approval:");
  const rollbackStart = workflow.indexOf("\n  rollback:");
  assert.ok(prepareStart > 0);
  assert.ok(approvalStart > prepareStart);
  assert.ok(rollbackStart > approvalStart);
  const prepareJob = workflow.slice(prepareStart, approvalStart);
  const approvalJob = workflow.slice(approvalStart, rollbackStart);
  const rollbackJob = workflow.slice(rollbackStart);

  const prepareGate = prepareJob.indexOf(
    "Revalidate exact control plane before prepare AWS trust"
  );
  const prepareOidc = prepareJob.indexOf(
    "Assume the read-only canary evidence role"
  );
  assert.ok(prepareGate > 0);
  assert.ok(prepareOidc > prepareGate);
  assert.match(
    prepareJob.slice(prepareGate, prepareOidc),
    /EXPECTED_GATE_SHA256: \$\{\{ steps\.source\.outputs\.control_plane_gate_sha256 \}\}/u
  );

  const approvalAwsGate = approvalJob.indexOf(
    "Revalidate exact control plane before approval AWS trust"
  );
  const approvalOidc = approvalJob.indexOf(
    "Assume the read-only canary evidence role"
  );
  const identityGate = approvalJob.indexOf(
    "Revalidate exact control plane before approver identity secret"
  );
  const identitySecret = approvalJob.indexOf(
    "CANARY_COGNITO_USERNAME: ${{ secrets.CANARY_COGNITO_USERNAME }}"
  );
  const mutationGate = approvalJob.indexOf(
    "Revalidate exact control plane before password-backed mutation"
  );
  const passwordSecret = approvalJob.indexOf(
    "CANARY_COGNITO_PASSWORD: ${{ secrets.CANARY_COGNITO_PASSWORD }}"
  );
  assert.ok(approvalAwsGate > 0);
  assert.ok(approvalOidc > approvalAwsGate);
  assert.ok(identityGate > approvalOidc);
  assert.ok(identitySecret > identityGate);
  assert.ok(mutationGate > identitySecret);
  assert.ok(passwordSecret > mutationGate);

  const rollbackGate = rollbackJob.indexOf(
    "Authenticate sealed original control plane before rollback mutation"
  );
  const rollbackSecret = rollbackJob.indexOf(
    "CANARY_DATAHUB_READ_TOKEN: ${{ secrets.CANARY_DATAHUB_READ_TOKEN }}"
  );
  assert.ok(rollbackGate > 0);
  assert.ok(rollbackSecret > rollbackGate);
  assert.match(
    rollbackJob.slice(rollbackGate, rollbackSecret),
    /EXPECTED_GATE_SHA256: \$\{\{ needs\.prepare\.outputs\.control_plane_gate_sha256 \}\}/u
  );
  assert.match(
    rollbackJob.slice(rollbackGate, rollbackSecret),
    /VERIFICATION_MODE: sealed[\s\S]+SEALED_GATE_PATH: \$\{\{ runner\.temp \}\}\/governed-canary\/recovery\/control-plane-security-gates\.json/u
  );
});

test("independent recovery separates the immutable parent from its pre-approval sealed driver", () => {
  assert.equal(
    (
      recoveryWorkflow.match(
        /bash scripts\/verify-github-control-plane\.sh/gu
      ) ?? []
    ).length,
    2
  );
  assert.equal(
    (recoveryWorkflow.match(/EXPECTED_GATE_SHA256:/gu) ?? []).length,
    2
  );
  assert.match(
    recoveryWorkflow,
    /CANARY_CONTROL_PLANE_SHA: \$\{\{ needs\.resolve-parent\.outputs\.control_plane_sha \}\}/u
  );

  const resolveStart = recoveryWorkflow.indexOf("\n  resolve-parent:");
  const recoverStart = recoveryWorkflow.indexOf("\n  recover:");
  assert.ok(resolveStart > 0);
  assert.ok(recoverStart > resolveStart);
  const resolveJob = recoveryWorkflow.slice(resolveStart, recoverStart);
  const recoverJob = recoveryWorkflow.slice(recoverStart);

  assert.match(
    resolveJob,
    /Seal trusted recovery driver before protected approval[\s\S]+driver_sha="\$\{GITHUB_SHA\}"/u
  );
  assert.match(
    resolveJob,
    /-f "head_sha=\$\{driver_sha\}"[\s\S]+sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u
  );
  assert.match(
    resolveJob,
    /first_gates="\$\(read_driver_gates\)"[\s\S]+second_gates="\$\(read_driver_gates\)"[\s\S]+test "\$\{second_gates\}" = "\$\{first_gates\}"/u
  );
  assert.doesNotMatch(resolveJob, /id-token:\s+write|secrets\./u);

  assert.match(
    recoverJob,
    /ref: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}[\s\S]+EXPECTED_RECOVERY_DRIVER_SHA: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}[\s\S]+run: test "\$\(git rev-parse HEAD\)" = "\$\{EXPECTED_RECOVERY_DRIVER_SHA\}"/u
  );
  assert.doesNotMatch(
    recoverJob,
    /\/git\/ref\/heads\/master|actions\/workflows\/|steps\.recovery_driver\.outputs/u
  );

  const driverGate = recoveryWorkflow.indexOf(
    "Authenticate sealed recovery driver before AWS trust"
  );
  const recoveryOidc = recoveryWorkflow.indexOf(
    "Assume read-only staging binding role"
  );
  const mutationGate = recoveryWorkflow.indexOf(
    "Authenticate sealed recovery driver before token mutation"
  );
  const mutationSecret = recoveryWorkflow.indexOf(
    "CANARY_DATAHUB_READ_TOKEN: ${{ secrets.CANARY_DATAHUB_READ_TOKEN }}"
  );
  assert.ok(driverGate > 0);
  assert.ok(recoveryOidc > driverGate);
  assert.ok(mutationGate > recoveryOidc);
  assert.ok(mutationSecret > mutationGate);
  assert.match(
    recoveryWorkflow.slice(driverGate, recoveryOidc),
    /CONTROL_PLANE_SHA: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}[\s\S]+EXPECTED_GATE_SHA256: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_gate_sha256 \}\}[\s\S]+VERIFICATION_MODE: sealed[\s\S]+SEALED_GATE_PATH: \$\{\{ steps\.recovery_driver_receipt\.outputs\.path \}\}/u
  );
  assert.match(
    recoveryWorkflow.slice(mutationGate, mutationSecret),
    /CONTROL_PLANE_SHA: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}[\s\S]+EXPECTED_GATE_SHA256: \$\{\{ steps\.recovery_driver_gates\.outputs\.gate_sha256 \}\}/u
  );
  assert.match(
    recoveryWorkflow.slice(mutationGate, mutationSecret),
    /VERIFICATION_MODE: sealed[\s\S]+SEALED_GATE_PATH: \$\{\{ runner\.temp \}\}\/governed-canary\/recovery-aws-gates\/control-plane-security-gates\.json/u
  );
  assert.match(
    recoveryWorkflow,
    /--arg controlPlaneSha "\$\{CANARY_CONTROL_PLANE_SHA\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /RECOVERY_DRIVER_SHA: \$\{\{ needs\.resolve-parent\.outputs\.recovery_driver_sha \}\}[\s\S]+--arg recoveryDriverSha "\$\{RECOVERY_DRIVER_SHA\}"/u
  );
});

test("a reviewer approves the sealed plan, not a generic pre-plan dispatch", () => {
  const prepare = workflow.indexOf("\n  prepare:");
  const approval = workflow.indexOf("\n  approval:");
  const rollback = workflow.indexOf("\n  rollback:");
  assert.ok(prepare > 0);
  assert.ok(approval > prepare);
  assert.ok(rollback > approval);

  const prepareJob = workflow.slice(prepare, approval);
  const approvalJob = workflow.slice(approval, rollback);
  assert.doesNotMatch(prepareJob, /^\s{4}environment:/mu);
  assert.doesNotMatch(prepareJob, /CANARY_COGNITO_PASSWORD/u);
  assert.doesNotMatch(prepareJob, /governed-canary\.ts approve/u);
  assert.match(
    approvalJob,
    /name: Human approval — plan \$\{\{ needs\.prepare\.outputs\.plan_digest \}\} \/ recovery \$\{\{ needs\.prepare\.outputs\.recovery_digest \}\}/u
  );
  assert.match(approvalJob, /name: governed-canary\n/u);
  assert.match(approvalJob, /CANARY_COGNITO_PASSWORD: \$\{\{ secrets\./u);
  assert.match(
    approvalJob,
    /Download the exact pre-mutation plan approved by this job/u
  );
  assert.match(
    approvalJob,
    /Revalidate both protected gates immediately before approval/u
  );
  assert.match(prepareJob, /AWS_CANARY_PREPARE_ROLE_ARN/u);
  assert.match(approvalJob, /AWS_CANARY_APPROVAL_ROLE_ARN/u);
  assert.doesNotMatch(prepareJob, /AWS_CANARY_APPROVAL_ROLE_ARN/u);
});

test("governed canary cannot add an unreviewed auth or browser dependency", () => {
  const source = `${workflow}\n${driver}`;
  assert.doesNotMatch(
    source,
    /USER_PASSWORD_AUTH|AdminInitiateAuth|InitiateAuthCommand|setup-chrome|playwright|selenium|npx\s|npm install/iu
  );
  assert.match(workflow, /npm ci --ignore-scripts/u);
  assert.match(workflow, /CANARY_CHROME_VERSION/u);
  assert.match(workflow, /CANARY_CHROME_BINARY_SHA256/u);
  assert.match(driver, /code_challenge_method: "S256"/u);
  assert.match(driver, /Fetch\.failRequest/u);
});

test("Cognito runtime auth is sealed to the staging stack before credential use", () => {
  const stackBinding = workflow.indexOf(
    'test "$(output ArchonUserPoolClientId)" = "${CANARY_COGNITO_CLIENT_ID}"'
  );
  const browserApproval = workflow.indexOf(
    "Authenticate with Cognito PKCE, approve, and verify receipt"
  );
  const runtimeBinding = workflow.indexOf(
    "Bind deployed runtime auth before any browser or password use"
  );
  assert.ok(stackBinding > 0);
  assert.ok(runtimeBinding > stackBinding);
  assert.ok(browserApproval > stackBinding);
  assert.ok(browserApproval > runtimeBinding);
  assert.match(workflow, /output ArchonUserPoolClientId/u);
  assert.match(workflow, /output ArchonCognitoHostedUiOrigin/u);
  assert.match(
    workflow,
    /test "\$\(output ArchonUserPoolClientId\)" = "\$\{CANARY_COGNITO_CLIENT_ID\}"/u
  );
  assert.match(driver, /auth\["clientId"\] !== identity\.cognitoClientId/u);
  assert.match(
    driver,
    /new URL\(authorizationEndpoint\)\.origin !== identity\.cognitoHostedUiOrigin/u
  );
  assert.ok(
    driver.indexOf("const runtime = await loadRuntimeConfig(identity)") <
      driver.indexOf(
        'const password = required(process.env, "CANARY_COGNITO_PASSWORD"'
      )
  );
  assert.doesNotMatch(
    workflow,
    /echo "::add-mask::\$\{CANARY_COGNITO_PASSWORD\}"/u
  );
});

test("the recovery artifact is verified locally but never drives approval HTTP", () => {
  assert.match(
    workflow,
    /CANARY_EXPECTED_AUDIT_ID: \$\{\{ needs\.prepare\.outputs\.audit_id \}\}/u
  );
  assert.match(
    workflow,
    /CANARY_EXPECTED_PLAN_DIGEST: \$\{\{ needs\.prepare\.outputs\.plan_digest \}\}/u
  );
  assert.match(
    workflow,
    /CANARY_EXPECTED_RECOVERY_DIGEST: \$\{\{ needs\.prepare\.outputs\.recovery_digest \}\}/u
  );
  assert.match(
    driver,
    /verifyCanaryApprovalBindings\(recovery, expected\)/u
  );
  assert.match(driver, /readStatus\(identity, expected\.auditId\)/u);
  assert.match(driver, /submitApproval\(identity, approval, token\)/u);
  assert.match(
    driver,
    /waitForStatus\(\s+identity,\s+expected\.auditId,/u
  );
  assert.doesNotMatch(
    driver,
    /readStatus\(identity,\s*recovery\.auditId\)/u
  );
  assert.doesNotMatch(
    driver,
    /submitApproval\(identity,\s*recovery,/u
  );
  assert.doesNotMatch(
    driver,
    /waitForStatus\(\s+identity,\s+recovery\.auditId,/u
  );
});

test("governed canary seals recovery before approval and proves rollback by read", () => {
  const recoveryUpload = workflow.indexOf("Seal recovery state before approval");
  const approval = workflow.indexOf(
    "Authenticate with Cognito PKCE, approve, and verify receipt"
  );
  assert.ok(recoveryUpload > 0);
  assert.ok(approval > recoveryUpload);
  assert.match(
    workflow,
    /needs:\n\s+- prepare\n\s+- approval\n\s+if: >-\n\s+always\(\) &&\n\s+needs\.prepare\.outputs\.recovery_digest != ''/u
  );
  assert.match(
    workflow,
    /Revalidate rollback protection immediately before recovery/u
  );
  assert.match(
    driver,
    /rollbackDispositionForObservedDigest\(\s+current\.digest,\s+recovery\.expectedBefore\.digest,\s+expectedCurrentDigest\s+\)/u
  );
  assert.doesNotMatch(driver, /rollbackManifest && !shouldRemove/u);
  assert.match(driver, /"ALREADY_RESTORED" \| "ROLLED_BACK"/u);
  assert.match(
    driver,
    /rollbackManifestDigest: rollbackManifest\.digest/u
  );
  assert.match(driver, /\n\s+disposition,\n/u);
  assert.match(
    driver,
    /restored\.digest !== recovery\.expectedBefore\.digest/u
  );
  assert.match(driver, /LiveDataHubMutationClient\(\)\.removeTags/u);
  assert.match(workflow, /attestations\/governed-canary\/v1/u);
});

test("failed or cancelled parents have automatic and idempotent manual recovery", () => {
  assert.match(recoveryWorkflow, /^on:\n  workflow_run:/mu);
  assert.match(recoveryWorkflow, /^\s{2}workflow_dispatch:/mu);
  assert.doesNotMatch(
    recoveryWorkflow,
    /^\s{2}(?:push|pull_request|schedule):/mu
  );
  assert.match(
    recoveryWorkflow,
    /parent_run_id:[\s\S]+parent_run_attempt:[\s\S]+confirmation:[\s\S]+RECOVER SEALED GOVERNED CANARY/u
  );
  assert.match(recoveryWorkflow, /cancel-in-progress: false/u);
  assert.match(
    recoveryWorkflow,
    /EVENT_PARENT_PATH: \$\{\{ github\.event\.workflow_run\.path \}\}/u
  );
  assert.match(
    recoveryWorkflow,
    /\.path == "\.github\/workflows\/governed-canary\.yml"/u
  );
  assert.match(recoveryWorkflow, /EVENT_PARENT_HEAD_REPOSITORY/u);
  assert.match(recoveryWorkflow, /EVENT_PARENT_HEAD_BRANCH/u);
  assert.match(recoveryWorkflow, /CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT/u);
  assert.match(
    recoveryWorkflow,
    /actions\/runs\/\$\{CANARY_SOURCE_WORKFLOW_RUN_ID\}\/attempts\/\$\{CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT\}/u
  );
  assert.match(recoveryWorkflow, /name: governed-canary-recovery\n/u);
  assert.match(recoveryWorkflow, /prevent_self_review == true/u);
  assert.match(
    recoveryWorkflow,
    /\.branch_policies\[0\]\.name == "master"/u
  );
  assert.match(
    recoveryWorkflow,
    /governed-canary-recovery-\$\{CANARY_SOURCE_WORKFLOW_RUN_ID\}-\$\{CANARY_SOURCE_WORKFLOW_RUN_ATTEMPT\}/u
  );
  assert.match(
    recoveryWorkflow,
    /node --import tsx scripts\/governed-canary\.ts rollback/u
  );
  assert.match(
    recoveryWorkflow,
    /\.status == "in_progress" and\s+\.conclusion == null[\s\S]+\.conclusion == "failure"[\s\S]+\.conclusion == "cancelled"/u
  );
  assert.match(
    recoveryWorkflow,
    /actions\/runs\/\$\{CANARY_DEPLOYMENT_RUN_ID\}\/attempts\/\$\{deployment_attempt\}\/jobs/u
  );
  assert.match(
    recoveryWorkflow,
    /select\(\.name == "Verify once and deploy staging"\)/u
  );
  assert.match(
    recoveryWorkflow,
    /\$staging\[0\]\.run_attempt == \$runAttempt[\s\S]+\$staging\[0\]\.conclusion == "success"/u
  );
  assert.match(
    recoveryWorkflow,
    /select\(\.name == "Approve and promote identical artifacts"\)[\s\S]+Active-parent recovery is forbidden after production starts/u
  );
  assert.match(
    recoveryWorkflow,
    /: "\$\{CANARY_DATAHUB_READ_TOKEN:\?CANARY_DATAHUB_READ_TOKEN is required\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /: "\$\{CANARY_DATAHUB_WRITE_TOKEN:\?CANARY_DATAHUB_WRITE_TOKEN is required\}"/u
  );
  assert.match(
    recoveryWorkflow,
    /attestations\/governed-canary-recovery\/v1/u
  );
  assert.doesNotMatch(
    recoveryWorkflow,
    /github\.event\.workflow_run\.conclusion == 'success'/u
  );
});
