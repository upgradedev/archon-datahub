import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { test } from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/production-posture.yml", import.meta.url),
  "utf8"
);
const documentation = readFileSync(
  new URL("../../docs/PRODUCTION_POSTURE.md", import.meta.url),
  "utf8"
);
const controlPlaneVerifier = readFileSync(
  new URL("../../scripts/verify-github-control-plane.sh", import.meta.url),
  "utf8"
);
const judgeUserWorkflow = readFileSync(
  new URL("../../.github/workflows/judge-user.yml", import.meta.url),
  "utf8"
);
const judgeUserManager = readFileSync(
  new URL("../../scripts/manage-cognito-judge-user.sh", import.meta.url),
  "utf8"
);
const judgeApprovalVerifier = readFileSync(
  new URL(
    "../../scripts/verify-judge-environment-approval.sh",
    import.meta.url
  ),
  "utf8"
);
const judgeEmergencyControlPlaneVerifier = readFileSync(
  new URL(
    "../../scripts/verify-judge-emergency-control-plane.sh",
    import.meta.url
  ),
  "utf8"
);
const judgeAccessDocumentation = readFileSync(
  new URL("../../docs/JUDGE_ACCESS.md", import.meta.url),
  "utf8"
);
const archonInfrastructure = readFileSync(
  new URL("../../infra/aws/lib/archon-stack.ts", import.meta.url),
  "utf8"
);
const exampleEnvironment = readFileSync(
  new URL("../../.env.example", import.meta.url),
  "utf8"
);

test("shared privileged-workflow gate rejects a changing whole snapshot", () => {
  assert.match(controlPlaneVerifier, /read_gate_snapshot\(\)/u);
  assert.match(
    controlPlaneVerifier,
    /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u
  );

  const firstRead = controlPlaneVerifier.indexOf(
    'first_gate_snapshot="$(read_gate_snapshot)"'
  );
  const branchReread = controlPlaneVerifier.indexOf(
    'test "$(read_current_branch_sha)"',
    firstRead
  );
  const secondRead = controlPlaneVerifier.indexOf(
    'second_gate_snapshot="$(read_gate_snapshot)"',
    branchReread
  );
  const snapshotEquality = controlPlaneVerifier.indexOf(
    'test "${second_gate_snapshot}" = "${first_gate_snapshot}"',
    secondRead
  );
  const finalBranchReread = controlPlaneVerifier.indexOf(
    'test "$(read_current_branch_sha)"',
    snapshotEquality
  );

  assert.ok(firstRead >= 0);
  assert.ok(branchReread > firstRead);
  assert.ok(secondRead > branchReread);
  assert.ok(snapshotEquality > secondRead);
  assert.ok(finalBranchReread > snapshotEquality);
  assert.match(
    controlPlaneVerifier,
    /workflow snapshot changed or is no longer successful/u
  );
});

test("production posture is scheduled/manual and gates AWS credentials on exact green master", () => {
  assert.match(workflow, /^on:\n  schedule:/mu);
  assert.match(workflow, /^\s{2}workflow_dispatch:/mu);
  assert.doesNotMatch(
    workflow,
    /^\s{2}(?:push|pull_request|workflow_run):/mu
  );

  const controlPlane = workflow.indexOf("\n  control-plane:");
  const observer = workflow.indexOf("\n  observe:");
  assert.ok(controlPlane > 0);
  assert.ok(observer > controlPlane);

  const unprivilegedGate = workflow.slice(controlPlane, observer);
  const privilegedObserver = workflow.slice(observer);
  assert.doesNotMatch(unprivilegedGate, /id-token: write/u);
  assert.doesNotMatch(unprivilegedGate, /configure-aws-credentials/u);
  assert.doesNotMatch(unprivilegedGate, /\baws\s+(?:cloudformation|sns|sts)\b/u);
  assert.match(privilegedObserver, /needs: control-plane/u);
  assert.match(privilegedObserver, /environment: production-observer/u);
  assert.match(privilegedObserver, /id-token: write/u);

  assert.match(workflow, /test "\$\{default_branch\}" = "master"/u);
  assert.match(
    workflow,
    /test "\$\{default_sha\}" = "\$\{GITHUB_SHA\}"/u
  );
  assert.match(workflow, /require_latest_success ci\.yml CI/u);
  assert.match(workflow, /require_latest_success codeql\.yml CodeQL/u);
  assert.match(
    workflow,
    /require_latest_success workflow-security\.yml "Workflow security"/u
  );
  assert.doesNotMatch(workflow, /max_by\(\.id\)/u);
  assert.match(workflow, /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u);
  assert.match(
    workflow,
    /\.status == "completed" and\s+\.conclusion == "success"/u
  );

  const protectedValidation = privilegedObserver.indexOf(
    "Validate protected observer configuration"
  );
  const checkout = privilegedObserver.indexOf(
    "Check out the exact posture control plane"
  );
  const preTrustGate = privilegedObserver.indexOf(
    "Revalidate exact latest gates before AWS trust"
  );
  const oidc = privilegedObserver.indexOf(
    "Configure least-privilege production observer through OIDC"
  );
  assert.ok(protectedValidation >= 0);
  assert.ok(checkout > protectedValidation);
  assert.ok(preTrustGate > checkout);
  assert.ok(oidc > preTrustGate);
  assert.match(
    privilegedObserver,
    /OUTPUT_PATH="\$\{current_gates\}"\s+\\\s+bash scripts\/verify-github-control-plane\.sh/u
  );
  assert.match(
    privilegedObserver,
    /\(\$sealed\[0\]\.workflows \| receipt\) ==\s+\(\$current\[0\]\.workflows \| receipt\)/u
  );
});

test("production posture checks exact protected stacks, drift, and termination protection", () => {
  assert.match(workflow, /READ_ROLE_ARN: \$\{\{ vars\.AWS_READ_ROLE_ARN \}\}/u);
  assert.match(
    workflow,
    /uses: aws-actions\/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c/u
  );
  assert.match(workflow, /allowed-account-ids: \$\{\{ vars\.AWS_ACCOUNT_ID \}\}/u);
  assert.match(workflow, /unset-current-credentials: true/u);

  assert.match(
    workflow,
    /stack_names=\(\s+"Archon-Registry"\s+"Archon-production"\s+"Archon-production-Edge"/u
  );
  assert.match(workflow, /\["Archon-production-Edge"\]="us-east-1"/u);
  assert.match(workflow, /\.Stacks\[0\]\.EnableTerminationProtection == true/u);
  assert.match(workflow, /aws cloudformation detect-stack-drift/u);
  assert.match(
    workflow,
    /aws cloudformation describe-stack-drift-detection-status/u
  );
  assert.match(workflow, /for attempt in \{1\.\.90\}/u);
  assert.match(workflow, /sleep 10/u);
  assert.match(workflow, /\.StackDriftStatus == "IN_SYNC"/u);
  assert.match(workflow, /\.DriftedStackResourceCount == 0/u);

  assert.match(
    workflow,
    /final_snapshot="\$\(snapshot_stack "\$\{name\}" "\$\{region\}"\)"/u
  );
  assert.match(
    workflow,
    /test "\$\{final_snapshot\}" = "\$\{initial_snapshots\[\$name\]\}"/u
  );
});

test("alarm verification is exact and evidence never projects the SNS endpoint", () => {
  assert.match(
    workflow,
    /ALARM_SUBSCRIPTION_ARN: \$\{\{ vars\.ALARM_SUBSCRIPTION_ARN \}\}/u
  );
  assert.match(workflow, /OutputKey == "ArchonAlarmTopicArn"/u);
  assert.match(workflow, /aws sns get-subscription-attributes/u);
  assert.match(
    workflow,
    /\.Attributes\.SubscriptionArn == \$subscription and\s+\.Attributes\.TopicArn == \$topic/u
  );
  assert.match(workflow, /\.Attributes\.PendingConfirmation == "false"/u);
  assert.match(workflow, /\.Attributes\.Owner == \$account/u);
  assert.doesNotMatch(workflow, /\.Attributes\.Endpoint/u);
  assert.match(workflow, /final_subscription_projection/u);

  assert.match(
    workflow,
    /schemaVersion: "archon\.production-posture-evidence\/v1"/u
  );
  assert.match(workflow, /topicArnSha256: \$alarmTopicSha256/u);
  assert.match(workflow, /subscriptionArnSha256: \$subscriptionArnSha256/u);
  assert.match(workflow, /pendingConfirmation: false/u);
});

test("posture evidence is checksum-sealed, signed, retained, and documented", () => {
  assert.match(
    workflow,
    /uses: actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/u
  );
  assert.match(
    workflow,
    /predicate-type: https:\/\/github\.com\/upgradedev\/archon-datahub\/attestations\/production-posture\/v1/u
  );
  assert.match(
    workflow,
    /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u
  );
  assert.match(workflow, /retention-days: 90/u);
  assert.match(workflow, /sha256sum --check --strict SHA256SUMS/u);
  assert.match(workflow, /Remove AWS credentials before evidence publication/u);
  assert.match(
    workflow,
    /Revalidate exact control plane without AWS credentials/u
  );
  assert.match(workflow, /test "\$\{#gate_runs\[@\]\}" = "3"/u);
  assert.match(workflow, /\[\.runId, \.runAttempt, \.path\]/u);
  assert.match(workflow, /\.run_attempt == \$runAttempt/u);
  assert.match(workflow, /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u);

  assert.match(documentation, /production-observer/u);
  assert.match(documentation, /cloudformation:DetectStackDrift/u);
  assert.match(documentation, /sns:GetSubscriptionAttributes/u);
  assert.match(documentation, /never stores its endpoint/u);
});

test("judge-user lifecycle is manual, protected, serialized, and gate-bound", () => {
  assert.match(judgeUserWorkflow, /^on:\n  workflow_dispatch:/mu);
  assert.doesNotMatch(
    judgeUserWorkflow,
    /^\s{2}(?:push|pull_request|schedule|workflow_run):/mu
  );
  assert.match(
    judgeUserWorkflow,
    /group: archon-judge-user-\$\{\{ inputs\.stage \}\}/u
  );
  assert.match(judgeUserWorkflow, /cancel-in-progress: false/u);

  const controlPlane = judgeUserWorkflow.indexOf("\n  control-plane:");
  const manage = judgeUserWorkflow.indexOf("\n  manage:");
  assert.ok(controlPlane > 0);
  assert.ok(manage > controlPlane);
  const unprivileged = judgeUserWorkflow.slice(controlPlane, manage);
  const privileged = judgeUserWorkflow.slice(manage);
  const approvalPhrasePublisher = unprivileged.slice(
    unprivileged.indexOf(
      "Publish the opaque-identity approval receipt phrase"
    )
  );

  assert.doesNotMatch(unprivileged, /id-token: write/u);
  assert.doesNotMatch(unprivileged, /configure-aws-credentials/u);
  assert.match(approvalPhrasePublisher, /GITHUB_STEP_SUMMARY/u);
  assert.match(approvalPhrasePublisher, /request_sha256/u);
  assert.doesNotMatch(
    approvalPhrasePublisher,
    /(?:echo|printf).*(?:JUDGE_USERNAME|secrets\.JUDGE_USERNAME)/u
  );
  assert.doesNotMatch(
    judgeUserWorkflow,
    /inputs\.username|confirmed_username/u
  );
  assert.doesNotMatch(unprivileged, /JUDGE_USERNAME|JUDGE_PASSWORD/u);
  assert.match(
    unprivileged,
    /JUDGE_STAGING_ACCOUNT_ID: \$\{\{ vars\.JUDGE_STAGING_ACCOUNT_ID \}\}/u
  );
  assert.match(
    unprivileged,
    /JUDGE_PRODUCTION_ACCOUNT_ID: \$\{\{ vars\.JUDGE_PRODUCTION_ACCOUNT_ID \}\}/u
  );
  for (const targetVariable of [
    "JUDGE_STAGING_AWS_ACCOUNT_ID",
    "JUDGE_PRODUCTION_AWS_ACCOUNT_ID",
    "JUDGE_STAGING_AWS_REGION",
    "JUDGE_PRODUCTION_AWS_REGION",
    "JUDGE_STAGING_APPLICATION_URL",
    "JUDGE_PRODUCTION_APPLICATION_URL"
  ]) {
    assert.match(
      unprivileged,
      new RegExp(`${targetVariable}: \\\$\\{\\{ vars\\.${targetVariable} \\}\\}`, "u")
    );
  }
  assert.match(unprivileged, /target_sha256/u);
  assert.equal(
    [
      ...judgeUserWorkflow.matchAll(
        /bash scripts\/verify-judge-emergency-control-plane\.sh/gu
      )
    ].length,
    3
  );
  assert.equal(
    [
      ...judgeUserWorkflow.matchAll(
        /bash scripts\/verify-github-control-plane\.sh/gu
      )
    ].length,
    3
  );
  assert.match(
    unprivileged,
    /emergency_workflow_file_sha256: \$\{\{ steps\.gate\.outputs\.emergency_workflow_file_sha256 \}\}/u
  );
  assert.match(
    unprivileged,
    /\.workflow\.fileSha256 \|\s+select\(type == "string" and test\("\^\[0-9a-f\]\{64\}\$"\)\)/u
  );
  assert.match(
    unprivileged,
    /if \[\[ "\$\{gate_mode\}" == "emergency-deactivate-current-master" \]\]; then\s+echo "emergency_workflow_file_sha256=\$\{emergency_workflow_file_sha256\}"/u
  );
  assert.match(
    approvalPhrasePublisher,
    /EMERGENCY_WORKFLOW_FILE_SHA256: \$\{\{ steps\.gate\.outputs\.emergency_workflow_file_sha256 \}\}/u
  );
  assert.match(
    approvalPhrasePublisher,
    /\[\[ "\$\{EMERGENCY_WORKFLOW_FILE_SHA256\}" =~ \^\[0-9a-f\]\{64\}\$ \]\]/u
  );
  assert.match(
    approvalPhrasePublisher,
    /Workflow file SHA-256: \\`\$\{EMERGENCY_WORKFLOW_FILE_SHA256\}\\`/u
  );
  assert.match(privileged, /needs: control-plane/u);
  assert.match(
    privileged,
    /name: judge-access-\$\{\{ inputs\.stage \}\}/u
  );
  assert.match(privileged, /id-token: write/u);
  assert.match(
    privileged,
    /role-to-assume: \$\{\{ vars\.AWS_JUDGE_USER_ROLE_ARN \}\}/u
  );
  assert.doesNotMatch(privileged, /role-to-assume:.*AWS_DEPLOY_ROLE_ARN/u);
  assert.match(
    privileged,
    /uses: aws-actions\/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c/u
  );
  assert.match(privileged, /role-duration-seconds: 900/u);
  assert.match(
    privileged,
    /role\/archon-\$\{ARCHON_STAGE\}-judge-user/u
  );
  assert.match(
    judgeUserWorkflow,
    /uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/u
  );
  assert.match(
    privileged,
    /EXPECTED_GATE_SHA256: \$\{\{ needs\.control-plane\.outputs\.gate_sha256 \}\}/u
  );
  assert.match(
    privileged,
    /SEALED_TARGET_ACCOUNT_ID: \$\{\{ needs\.control-plane\.outputs\.target_account_id \}\}/u
  );
  assert.match(
    privileged,
    /test "\$\{EXPECTED_ACCOUNT_ID\}" = "\$\{SEALED_TARGET_ACCOUNT_ID\}"/u
  );
  assert.match(
    privileged,
    /EXPECTED_APPLICATION_URL: \$\{\{ needs\.control-plane\.outputs\.target_application_url \}\}/u
  );
  assert.match(
    privileged,
    /JUDGE_PASSWORD: \$\{\{ secrets\.JUDGE_PASSWORD \}\}/u
  );
  assert.match(
    privileged,
    /JUDGE_USERNAME: \$\{\{ secrets\.JUDGE_USERNAME \}\}/u
  );
  assert.equal(
    [...judgeUserWorkflow.matchAll(/secrets\.JUDGE_PASSWORD/gu)].length,
    1
  );
  assert.equal(
    [...judgeUserWorkflow.matchAll(/secrets\.JUDGE_USERNAME/gu)].length,
    3
  );
  assert.match(
    privileged,
    /if: inputs\.operation == 'provision' \|\| inputs\.operation == 'rotate' \|\| inputs\.operation == 'reactivate'/u
  );
  assert.match(privileged, /if: inputs\.operation == 'deactivate'/u);
  assert.match(
    judgeApprovalVerifier,
    /\/environments\/\$\{environment_name\}"/u
  );
  assert.match(judgeApprovalVerifier, /\.name == \$name/u);
  assert.match(judgeApprovalVerifier, /\.type == "required_reviewers"/u);
  assert.match(judgeApprovalVerifier, /\.prevent_self_review == true/u);
  assert.match(
    judgeApprovalVerifier,
    /\.deployment_branch_policy\.custom_branch_policies == true/u
  );
  assert.match(judgeApprovalVerifier, /\.total_count == 1/u);
  assert.match(
    judgeApprovalVerifier,
    /\.branch_policies\[0\]\.type == "branch"/u
  );
  assert.match(
    judgeApprovalVerifier,
    /test "\$\{default_branch\}" = "master"/u
  );
  assert.match(
    privileged,
    /JUDGE_REVIEWER_USER_ID: \$\{\{ vars\.JUDGE_REVIEWER_USER_ID \}\}/u
  );
  assert.match(
    privileged,
    /EXPECTED_REQUEST_SHA256: \$\{\{ needs\.control-plane\.outputs\.request_sha256 \}\}/u
  );
  assert.match(
    judgeApprovalVerifier,
    /actions\/runs\/\$\{GITHUB_RUN_ID\}\/approvals/u
  );
  assert.match(judgeApprovalVerifier, /\.state == "approved"/u);
  assert.match(judgeApprovalVerifier, /\.comment == \$comment/u);
  assert.match(judgeApprovalVerifier, /\.user\.id == \$reviewer_id/u);
  assert.match(judgeApprovalVerifier, /\.user\.type == "User"/u);
  assert.match(judgeApprovalVerifier, /\.type == "User"/u);
  assert.doesNotMatch(judgeApprovalVerifier, /\.type == "Team"/u);
  assert.match(
    judgeApprovalVerifier,
    /\(\.user\.login \| ascii_downcase\) != \(\$actor \| ascii_downcase\)/u
  );
  assert.match(
    judgeApprovalVerifier,
    /\(\.user\.login \| ascii_downcase\) !=\s+\(\$triggering_actor \| ascii_downcase\)/u
  );
  assert.match(
    judgeApprovalVerifier,
    /ARCHON_JUDGE_ACCESS_APPROVAL_V3\|run_id=%s\|run_attempt=%s\|request_sha256=%s/u
  );
  assert.match(
    judgeApprovalVerifier,
    /stage=%s\\noperation=%s\\naccount_id=%s\\ntarget_account_id=%s\\ntarget_region=%s\\ntarget_role_arn=%s\\ntarget_application_url=%s\\ngate_sha256=%s\\nrelease_sha=%s/u
  );
  assert.doesNotMatch(judgeApprovalVerifier, /JUDGE_USERNAME|username=%s/u);
  const approvalCommentFunction = judgeApprovalVerifier.slice(
    judgeApprovalVerifier.indexOf("approval_comment()"),
    judgeApprovalVerifier.indexOf('case "${mode}"')
  );
  assert.doesNotMatch(approvalCommentFunction, /JUDGE_USERNAME/u);
  assert.doesNotMatch(judgeUserWorkflow, /admin_bypass_disabled_when_exposed/u);
  const environmentPosture = privileged.indexOf(
    "Require exact independent approval receipt before any privileged setup"
  );
  const roleConfiguration = privileged.indexOf(
    "Validate protected role configuration"
  );
  const checkout = privileged.indexOf(
    "Check out the exact protected control plane"
  );
  assert.match(
    privileged,
    /steps:\n      - name: Require exact independent approval receipt before any privileged setup/u
  );
  const oidc = privileged.indexOf(
    "Configure dedicated judge-user AWS credentials through OIDC"
  );
  const postOidcGate = privileged.indexOf(
    "Revalidate unchanged control plane after AWS trust"
  );
  const mutation = privileged.indexOf(
    "Provision, rotate, or reactivate and read back the exact Cognito state"
  );
  const deactivation = privileged.indexOf(
    "Deactivate and read back the exact Cognito state"
  );
  assert.ok(environmentPosture >= 0);
  assert.ok(roleConfiguration > environmentPosture);
  assert.ok(checkout > roleConfiguration);
  assert.ok(oidc > environmentPosture);
  assert.ok(postOidcGate > oidc);
  assert.ok(mutation > postOidcGate);
  assert.ok(deactivation > mutation);
  const firstManageStep = privileged.slice(
    environmentPosture,
    roleConfiguration
  );
  assert.match(
    firstManageStep,
    /actions\/runs\/\$\{GITHUB_RUN_ID\}\/approvals/u
  );
  assert.match(firstManageStep, /\.state == "approved"/u);
  assert.match(firstManageStep, /\.comment == \$comment/u);
  assert.match(firstManageStep, /\.user\.id == \$reviewer_id/u);
  assert.match(firstManageStep, /\.type == "User"/u);
  assert.match(
    firstManageStep,
    /\.environments\[0\]\.name == \$environment/u
  );
  assert.match(
    firstManageStep,
    /ARCHON_JUDGE_ACCESS_APPROVAL_V3\|run_id=\$\{GITHUB_RUN_ID\}\|run_attempt=\$\{GITHUB_RUN_ATTEMPT\}\|request_sha256=\$\{EXPECTED_REQUEST_SHA256\}/u
  );
  assert.doesNotMatch(firstManageStep, /\.type == "Team"/u);
  assert.match(
    firstManageStep,
    /\(\.user\.login \| ascii_downcase\) !=\s+\(\$actor \| ascii_downcase\)/u
  );
  assert.match(
    firstManageStep,
    /\(\.user\.login \| ascii_downcase\) !=\s+\(\$triggering_actor \| ascii_downcase\)/u
  );
  assert.doesNotMatch(
    firstManageStep,
    /(?:JUDGE_USERNAME|AWS_JUDGE_USER_ROLE_ARN|AWS_ACCOUNT_ID|AWS_REGION|JUDGE_PASSWORD|actions\/checkout|scripts\/)/u
  );
  assert.equal(
    [...firstManageStep.matchAll(/\$\{\{ vars\./gu)].length,
    1
  );
  assert.doesNotMatch(
    privileged.slice(deactivation),
    /JUDGE_PASSWORD/u
  );
  assert.doesNotMatch(judgeUserWorkflow, /upload-artifact/u);
});

test("judge emergency deactivation binds current master without claiming green CI", () => {
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{JUDGE_USER_OPERATION\}" = "deactivate"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /expected_repository="upgradedev\/archon-datahub"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /expected_branch="master"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /expected_workflow_path="\.github\/workflows\/judge-user\.yml"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{GITHUB_SHA\}" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{EXECUTING_WORKFLOW_REPOSITORY\}" = "\$\{expected_repository\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{EXECUTING_WORKFLOW_FILE_PATH\}" = "\$\{expected_workflow_path\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{EXECUTING_WORKFLOW_REF\}" = "\$\{expected_workflow_ref\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{EXECUTING_WORKFLOW_SHA\}" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /\/actions\/runs\/\$\{GITHUB_RUN_ID\}\/attempts\/\$\{GITHUB_RUN_ATTEMPT\}/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{initial_master_sha\}" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /\/contents\/\$\{expected_workflow_path\}\?ref=\$\{CONTROL_PLANE_SHA\}/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /printf 'blob %s\\0' "\$\{workflow_api_size\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{computed_workflow_blob_sha\}" = "\$\{workflow_blob_sha\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /workflow_file_sha256="\$\(\s+sha256sum "\$\{workflow_file\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\(read_master_sha\)" = "\$\{CONTROL_PLANE_SHA\}"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /schemaVersion: "archon\.judge-emergency-control-plane\/v1"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /ciStatus: "not-asserted"/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /fileSha256: \$workflow_file_sha256/u
  );
  assert.match(
    judgeEmergencyControlPlaneVerifier,
    /test "\$\{gate_sha256\}" = "\$\{expected_gate_sha256\}"/u
  );
  assert.doesNotMatch(
    judgeEmergencyControlPlaneVerifier,
    /(?:ci\.yml|codeql\.yml|workflow-security\.yml|read_gate_snapshot)/u
  );
});

test("judge-user manager keeps operations distinct and verifies exact state", () => {
  assert.match(
    judgeUserManager,
    /provision\|rotate\|reactivate\|deactivate/u
  );
  assert.match(judgeUserManager, /stack_name="Archon-\$\{ARCHON_STAGE\}"/u);
  assert.match(judgeUserManager, /ArchonUserPoolId/u);
  assert.match(judgeUserManager, /ArchonApproverGroupName/u);
  assert.match(judgeUserManager, /test "\$\{approver_group\}" = "archon-approvers"/u);
  assert.match(judgeUserManager, /admin-create-user/u);
  assert.match(judgeUserManager, /admin-set-user-password/u);
  assert.match(judgeUserManager, /admin-disable-user/u);
  assert.match(judgeUserManager, /admin-enable-user/u);
  assert.match(judgeUserManager, /admin-add-user-to-group/u);
  assert.match(judgeUserManager, /admin-remove-user-from-group/u);
  assert.match(judgeUserManager, /admin-list-groups-for-user/u);
  assert.match(judgeUserManager, /describe-user-pool/u);
  assert.match(judgeUserManager, /describe-user-pool-client/u);
  assert.match(judgeUserManager, /list-user-pool-clients/u);
  assert.match(judgeUserManager, /--max-results 60/u);
  assert.match(judgeUserManager, /\.UserPoolClients \| length\) == 1/u);
  assert.match(judgeUserManager, /describe-risk-configuration/u);
  assert.match(judgeUserManager, /AllowAdminCreateUserOnly == true/u);
  assert.match(
    judgeUserManager,
    /AccountRecoverySetting\.RecoveryMechanisms == \[/u
  );
  assert.match(judgeUserManager, /UsernameAttributes == \["email"\]/u);
  assert.match(judgeUserManager, /CaseSensitive == false/u);
  assert.match(
    judgeUserManager,
    /PasswordHistorySize == 24/u
  );
  assert.match(judgeUserManager, /EnableTokenRevocation == true/u);
  assert.match(
    judgeUserManager,
    /PreventUserExistenceErrors == "ENABLED"/u
  );
  assert.match(
    judgeUserManager,
    /ExplicitAuthFlows == \["ALLOW_REFRESH_TOKEN_AUTH"\]/u
  );
  assert.match(judgeUserManager, /AllowedOAuthFlows == \["code"\]/u);
  assert.match(
    judgeUserManager,
    /AllowedOAuthFlowsUserPoolClient == true/u
  );
  assert.match(
    judgeUserManager,
    /\["archon\/approve", "email", "openid"\]/u
  );
  assert.match(
    judgeUserManager,
    /\. != "aws\.cognito\.signin\.user\.admin"/u
  );
  assert.match(judgeUserManager, /ArchonApplicationUrl/u);
  assert.match(
    judgeUserManager,
    /\.UserPoolClient\.CallbackURLs == \[\$redirect\]/u
  );
  assert.match(
    judgeUserManager,
    /\.UserPoolClient\.LogoutURLs == \[\$redirect\]/u
  );
  assert.match(judgeUserManager, /DefaultRedirectURI/u);
  assert.match(
    judgeUserManager,
    /ArchonApplicationUrl does not match the independently approved target/u
  );
  assert.match(judgeUserManager, /email_verified/u);
  assert.match(judgeUserManager, /UserMFASettingList/u);
  assert.match(judgeUserManager, /PreferredMfaSetting/u);
  assert.match(judgeUserManager, /MFAOptions/u);
  assert.match(
    judgeUserManager,
    /AccountTakeoverRiskConfiguration\.Actions == \{/u
  );
  assert.match(
    judgeUserManager,
    /CompromisedCredentialsRiskConfiguration\.Actions == \{/u
  );
  assert.equal(
    [...judgeUserManager.matchAll(/EventAction: "NO_ACTION"/gu)].length,
    3
  );
  assert.equal(
    [...judgeUserManager.matchAll(/Notify: false/gu)].length,
    3
  );
  assert.match(judgeUserManager, /EventAction: "BLOCK"/u);
  assert.match(
    judgeUserManager,
    /\["PASSWORD_CHANGE", "SIGN_IN"\]/u
  );
  const riskRead = judgeUserManager.indexOf(
    "aws cognito-idp describe-risk-configuration"
  );
  const cognitoWafRead = judgeUserManager.indexOf(
    "aws wafv2 get-web-acl-for-resource"
  );
  const firstUserRead = judgeUserManager.indexOf(
    "aws cognito-idp admin-get-user"
  );
  const firstUserMutation = judgeUserManager.indexOf(
    "aws cognito-idp admin-create-user"
  );
  assert.ok(riskRead >= 0);
  assert.ok(cognitoWafRead > riskRead);
  assert.ok(firstUserRead > cognitoWafRead);
  assert.ok(firstUserMutation > cognitoWafRead);
  assert.match(judgeUserManager, /ArchonRegionalWebAclArn/u);
  assert.match(judgeUserManager, /AWS_ENDPOINT_URL_WAFV2/u);
  assert.match(judgeUserManager, /\.WebACL\.ARN == \$arn/u);
  assert.match(judgeUserManager, /AWSManagedRulesCommonRuleSet/u);
  assert.match(judgeUserManager, /PerIpRateLimit/u);
  assert.match(
    judgeUserManager,
    /\.Statement\.ManagedRuleGroupStatement \|\s+keys/isu
  );
  assert.match(
    judgeUserManager,
    /\.Statement\.RateBasedStatement \|\s+keys/isu
  );
  assert.match(judgeUserManager, /has\("Captcha"\)/u);
  assert.match(judgeUserManager, /admin-user-global-sign-out/u);
  assert.match(judgeUserManager, /--limit 60/u);
  assert.match(judgeUserManager, /\(\. \| has\("NextToken"\) \| not\)/u);
  assert.match(judgeUserManager, /custom:archon_judge_binding/u);
  assert.match(judgeUserManager, /--arg binding "\$\{JUDGE_ACCOUNT_ID\}"/u);
  assert.match(judgeUserManager, /\.Value == \$binding/u);
  assert.match(judgeUserManager, /automatic_containment\(\)/u);
  assert.match(judgeUserManager, /user_identity_matches_binding/u);
  assert.match(judgeUserManager, /file:\/\/\/dev\/stdin/u);
  assert.match(judgeUserManager, /internal_temporary_password/u);
  assert.match(
    judgeUserManager,
    /operation_binding="\$\{JUDGE_ACCOUNT_ID\}"/u
  );
  assert.match(
    judgeUserManager,
    /"FORCE_CHANGE_PASSWORD"\s+"" "\$\{operation_binding\}"/u
  );
  assert.match(judgeUserManager, /Permanent: true/u);
  assert.equal(
    [...judgeUserManager.matchAll(/Permanent: true/gu)].length,
    3
  );
  assert.doesNotMatch(judgeUserManager, /Permanent: false/u);
  assert.match(
    judgeUserManager,
    /PasswordHistoryPolicyViolationException/u
  );
  assert.match(judgeUserManager, /24-password history policy/u);
  assert.match(
    judgeUserManager,
    /wait_for_enabled_status "CONFIRMED" "\$\{canonical\}"/u
  );
  assert.equal(
    [
      ...judgeUserManager.matchAll(
        /wait_for_enabled_status "CONFIRMED" "\$\{canonical\}"/gu
      )
    ].length,
    5
  );
  const provisionOperation = judgeUserManager.slice(
    judgeUserManager.indexOf("\n  provision)"),
    judgeUserManager.indexOf("\n  rotate)")
  );
  const rotateOperation = judgeUserManager.slice(
    judgeUserManager.indexOf("\n  rotate)"),
    judgeUserManager.indexOf("\n  reactivate)")
  );
  const reactivateOperation = judgeUserManager.slice(
    judgeUserManager.indexOf("\n  reactivate)"),
    judgeUserManager.indexOf("\n  deactivate)")
  );
  for (const [operation, groupProof] of [
    [provisionOperation, "wait_for_only_approver_group"],
    [rotateOperation, "require_only_approver_group"],
    [reactivateOperation, "wait_for_only_approver_group"]
  ] as const) {
    assert.equal(
      [...operation.matchAll(/Permanent: true/gu)].length,
      1
    );
    const finalGroupProof = operation.lastIndexOf(groupProof);
    const finalEnabledProof = operation.lastIndexOf("wait_for_enabled_status");
    assert.ok(finalGroupProof >= 0);
    assert.ok(finalEnabledProof > finalGroupProof);
    assert.match(
      operation.slice(finalEnabledProof),
      /"CONFIRMED" "\$\{canonical\}"/u
    );
    assert.doesNotMatch(operation, /operation_complete=true/u);
  }
  const lifecycleReceipt = judgeUserManager.lastIndexOf(
    "\nwrite_lifecycle_state_receipt"
  );
  const lifecycleCompletion = judgeUserManager.lastIndexOf(
    "\noperation_complete=true"
  );
  assert.ok(lifecycleReceipt >= 0);
  assert.ok(lifecycleCompletion > lifecycleReceipt);
  assert.equal(
    [...judgeUserManager.matchAll(/^operation_complete=true$/gmu)].length,
    1
  );
  assert.match(judgeUserManager, /\.Enabled == false/u);
  const provisionContainment = judgeUserManager.indexOf(
    'containment_mode="provision"'
  );
  const createMutation = judgeUserManager.indexOf(
    "aws cognito-idp admin-create-user",
    provisionContainment
  );
  const provisionPasswordMutation = judgeUserManager.indexOf(
    "aws cognito-idp admin-set-user-password",
    createMutation
  );
  const rotationContainment = judgeUserManager.indexOf(
    'containment_mode="existing"'
  );
  const passwordMutation = judgeUserManager.indexOf(
    "aws cognito-idp admin-set-user-password",
    rotationContainment
  );
  assert.ok(provisionContainment >= 0);
  assert.ok(createMutation > provisionContainment);
  assert.ok(provisionPasswordMutation > createMutation);
  assert.ok(rotationContainment > provisionPasswordMutation);
  assert.ok(passwordMutation > rotationContainment);
  assert.match(judgeUserManager, /disable_response_proved=false/u);
  assert.match(judgeUserManager, /sign_out_response_proved=false/u);
  assert.match(judgeUserManager, /group_removal_response_proved=false/u);
  assert.match(judgeUserManager, /deactivation_state_proved/u);
  assert.doesNotMatch(judgeUserManager, /set -x/u);
  assert.doesNotMatch(
    judgeUserManager,
    /(?:echo|printf).{0,80}JUDGE_PASSWORD/u
  );
  const passwordImport = judgeUserManager.indexOf(
    'judge_password="${JUDGE_PASSWORD:-}"'
  );
  const usernameImport = judgeUserManager.indexOf(
    'judge_username="${JUDGE_USERNAME:-}"'
  );
  const passwordUnset = judgeUserManager.indexOf(
    "unset JUDGE_PASSWORD JUDGE_USERNAME",
    passwordImport
  );
  const firstAwsCall = judgeUserManager.indexOf("aws sts get-caller-identity");
  assert.ok(passwordImport >= 0);
  assert.ok(usernameImport >= 0);
  assert.ok(passwordUnset > passwordImport);
  assert.ok(firstAwsCall > passwordUnset);
  assert.match(
    judgeUserManager,
    /expected_role_name="archon-\$\{ARCHON_STAGE\}-judge-user"/u
  );
  assert.match(judgeUserManager, /\.Arn == \$arn/u);
  assert.match(
    judgeUserManager,
    /AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER/u
  );
  assert.match(
    judgeUserManager,
    /export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true/u
  );

  assert.match(
    archonInfrastructure,
    /new cognito\.CfnUserPoolRiskConfigurationAttachment/u
  );
  assert.match(
    archonInfrastructure,
    /lowAction: \{ eventAction: "NO_ACTION", notify: false \}/u
  );
  assert.match(
    archonInfrastructure,
    /mediumAction: \{ eventAction: "NO_ACTION", notify: false \}/u
  );
  assert.match(
    archonInfrastructure,
    /highAction: \{ eventAction: "NO_ACTION", notify: false \}/u
  );
  assert.match(
    archonInfrastructure,
    /actions: \{ eventAction: "BLOCK" \}/u
  );
  assert.match(
    archonInfrastructure,
    /eventFilter: \["SIGN_IN", "PASSWORD_CHANGE"\]/u
  );
  assert.match(archonInfrastructure, /passwordHistorySize: 24/u);
  assert.match(archonInfrastructure, /preventUserExistenceErrors: true/u);
  assert.match(archonInfrastructure, /"CognitoWebAclAssociation"/u);
  assert.match(archonInfrastructure, /resourceArn: userPool\.userPoolArn/u);
  assert.match(archonInfrastructure, /webAclArn: webAcl\.attrArn/u);

  assert.match(judgeAccessDocumentation, /self-sign-up remains disabled/iu);
  assert.match(judgeAccessDocumentation, /AWS_JUDGE_USER_ROLE_ARN/u);
  assert.match(judgeAccessDocumentation, /judge-access-staging/u);
  assert.match(judgeAccessDocumentation, /judge-access-production/u);
  assert.match(judgeAccessDocumentation, /never put.*workflow input/isu);
  assert.match(judgeAccessDocumentation, /out of band/iu);
  assert.match(judgeAccessDocumentation, /JUDGE_PASSWORD/u);
  assert.match(judgeAccessDocumentation, /JUDGE_USERNAME/u);
  assert.match(judgeAccessDocumentation, /JUDGE_STAGING_ACCOUNT_ID/u);
  assert.match(judgeAccessDocumentation, /JUDGE_PRODUCTION_ACCOUNT_ID/u);
  assert.match(judgeAccessDocumentation, /JUDGE_STAGING_AWS_ACCOUNT_ID/u);
  assert.match(judgeAccessDocumentation, /JUDGE_PRODUCTION_APPLICATION_URL/u);
  assert.match(judgeAccessDocumentation, /Permanent: true/u);
  assert.match(judgeAccessDocumentation, /UserStatus: CONFIRMED/u);
  assert.match(judgeAccessDocumentation, /does not depend.*temporary-password TTL/isu);
  assert.match(judgeAccessDocumentation, /first-login password-change challenge/iu);
  assert.match(judgeAccessDocumentation, /15-minute expiry/iu);
  assert.match(judgeAccessDocumentation, /administrator-bypass/iu);
  assert.match(judgeAccessDocumentation, /REST and GraphQL schemas do not expose/iu);
  assert.match(judgeAccessDocumentation, /defense in depth/iu);
  assert.match(judgeAccessDocumentation, /approval-history receipt/iu);
  assert.match(judgeAccessDocumentation, /validated workflow-file SHA-256/iu);
  assert.match(judgeAccessDocumentation, /JUDGE_REVIEWER_USER_ID/u);
  assert.match(judgeAccessDocumentation, /protected environment variable/iu);
  assert.match(judgeAccessDocumentation, /protected environment secret/iu);
  assert.match(
    judgeAccessDocumentation,
    /Do not define organization- or repository-level values named/iu
  );
  assert.match(judgeAccessDocumentation, /900-second/iu);
  assert.match(
    judgeAccessDocumentation,
    /ARCHON_JUDGE_ACCESS_APPROVAL_V3\|run_id=RUN_ID\|run_attempt=RUN_ATTEMPT\|request_sha256=REQUEST_SHA256/u
  );
  assert.match(judgeAccessDocumentation, /email is not an input/iu);
  assert.match(judgeAccessDocumentation, /opaque account ID/iu);
  assert.match(judgeAccessDocumentation, /immutable.*binding/isu);
  assert.match(judgeAccessDocumentation, /PasswordHistorySize: 24/u);
  assert.match(
    judgeAccessDocumentation,
    /AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true/u
  );
  assert.match(judgeAccessDocumentation, /DescribeRiskConfiguration/u);
  assert.match(judgeAccessDocumentation, /ListUserPoolClients/u);
  assert.match(judgeAccessDocumentation, /GetWebACLForResource/u);
  assert.match(
    judgeAccessDocumentation,
    /cognito-idp:GetWebACLForResource/u
  );
  assert.match(judgeAccessDocumentation, /wafv2:GetWebACL/u);
  assert.match(judgeAccessDocumentation, /cognito-idp:AdminEnableUser/u);
  assert.match(judgeAccessDocumentation, /ArchonRegionalWebAclArn/u);
  assert.match(judgeAccessDocumentation, /aws\.cognito\.signin\.user\.admin/u);
  assert.match(judgeAccessDocumentation, /NO_ACTION/u);
  assert.match(judgeAccessDocumentation, /PASSWORD_CHANGE/u);
  assert.match(judgeAccessDocumentation, /multi-network Hosted UI/iu);
});

test("example DataHub endpoint requires authenticated HTTPS and runner-reachable routing", () => {
  assert.match(
    exampleEnvironment,
    /DATAHUB_GMS_URL=https:\/\/datahub\.example\.com/u
  );
  assert.match(exampleEnvironment, /Remote endpoints MUST use authenticated/u);
  assert.match(exampleEnvironment, /GitHub-hosted demo\/live/u);
  assert.match(exampleEnvironment, /public HTTPS endpoint/u);
  assert.match(
    exampleEnvironment,
    /private endpoints require a self-hosted runner/u
  );
  assert.match(exampleEnvironment, /authenticated SSH\/VPN tunnel/u);
  assert.doesNotMatch(exampleEnvironment, /DATAHUB_GMS_URL=http:\/\//u);
});
