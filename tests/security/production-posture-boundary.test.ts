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
