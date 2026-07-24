import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

const workflow = readFileSync(
  new URL("../../.github/workflows/governed-canary.yml", import.meta.url),
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

test("governed canary is manual-only, staging-only, and independently approved", () => {
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

test("failed or cancelled parent runs have an independent exact recovery workflow", () => {
  assert.match(recoveryWorkflow, /^on:\n  workflow_run:/mu);
  assert.doesNotMatch(
    recoveryWorkflow,
    /^\s{2}(?:workflow_dispatch|push|pull_request|schedule):/mu
  );
  assert.match(recoveryWorkflow, /cancel-in-progress: false/u);
  assert.match(
    recoveryWorkflow,
    /PARENT_PATH: \$\{\{ github\.event\.workflow_run\.path \}\}/u
  );
  assert.match(
    recoveryWorkflow,
    /test "\$\{PARENT_PATH\}" = "\.github\/workflows\/governed-canary\.yml"/u
  );
  assert.match(recoveryWorkflow, /PARENT_HEAD_REPOSITORY/u);
  assert.match(recoveryWorkflow, /PARENT_HEAD_BRANCH/u);
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
