import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  expectedApprovalComment,
  verifiedApproverFromReceipt,
} from "../../scripts/github-environment-approval.js";

const workflowPath = new URL(
  "../../.github/workflows/live-governed-proof.yml",
  import.meta.url
);
const serverPath = new URL("../../src/http/server.ts", import.meta.url);
const tunnelPath = new URL("../../scripts/open-datahub-iap-tunnel.sh", import.meta.url);
const approvalCapturePath = new URL(
  "../../scripts/capture-github-environment-approval.sh",
  import.meta.url
);
const protectionVerifierPath = new URL(
  "../../scripts/verify-github-environment-protection.sh",
  import.meta.url
);
const proofPath = new URL("../../scripts/live-governed-proof.ts", import.meta.url);
const deployRunbookPath = new URL("../../docs/HOSTED_DEMO_DEPLOY.md", import.meta.url);
const hostedWorkflowPath = new URL(
  "../../.github/workflows/hosted-demo.yml",
  import.meta.url
);
const firebaseConfigPath = new URL("../../firebase.json", import.meta.url);

test("live governed proof keeps public HTTP read-only and requires two human gates", async () => {
  const [workflow, server, tunnel] = await Promise.all([
    readFile(workflowPath, "utf8"),
    readFile(serverPath, "utf8"),
    readFile(tunnelPath, "utf8"),
  ]);

  assert.match(workflow, /environment: governed-canary\s/u);
  assert.match(workflow, /environment: governed-canary-recovery\s/u);
  assert.match(workflow, /APPROVE SYNTHETIC G6 WRITE/u);
  assert.match(workflow, /APPROVE SYNTHETIC G6 ROLLBACK/u);
  assert.match(workflow, /127\.0\.0\.1:18080/u);
  assert.doesNotMatch(workflow, /DATAHUB_WRITE_GMS_TOKEN/u);
  assert.doesNotMatch(workflow, /--tunnel-through-iap.*ssh/iu);
  assert.match(tunnel, /gcloud compute start-iap-tunnel/u);
  assert.match(tunnel, /--local-host-port=127\.0\.0\.1:18080/u);

  assert.match(server, /pathname === "\/api\/audits"/u);
  assert.doesNotMatch(server, /\/api\/(?:remediation|write|mutation|rollback)/u);
  assert.doesNotMatch(server, /createDataHubMutationClient|LiveDataHubMutationClient/u);
});

test("privileged jobs fail closed on protection, reviewer evidence, and proof identity", async () => {
  const [workflow, capture, verifier, proof, deployRunbook] = await Promise.all([
    readFile(workflowPath, "utf8"),
    readFile(approvalCapturePath, "utf8"),
    readFile(protectionVerifierPath, "utf8"),
    readFile(proofPath, "utf8"),
    readFile(deployRunbookPath, "utf8"),
  ]);
  const executeStart = workflow.indexOf("\n  execute:");
  const rollbackStart = workflow.indexOf("\n  rollback:");
  assert.ok(executeStart > 0 && rollbackStart > executeStart);
  const execute = workflow.slice(executeStart, rollbackStart);
  const rollback = workflow.slice(rollbackStart);

  assert.equal(workflow.match(/service_account: \$\{\{ vars\.GCP_PROOF_SERVICE_ACCOUNT \}\}/gu)?.length, 3);
  assert.equal(workflow.match(/name: Require a dedicated proof identity/gu)?.length, 3);
  assert.doesNotMatch(workflow, /service_account: \$\{\{ vars\.GCP_DEPLOY_SERVICE_ACCOUNT \}\}/u);
  for (const job of [execute, rollback]) {
    assert.match(job, /^      deployments: read$/mu);
    const protection = job.indexOf("bash scripts/verify-github-environment-protection.sh");
    const reviewer = job.indexOf("bash scripts/capture-github-environment-approval.sh");
    const oidc = job.indexOf("google-github-actions/auth@");
    assert.ok(protection > 0 && reviewer > protection && oidc > reviewer);
  }

  assert.match(verifier, /governed-canary\) ;;/u);
  assert.match(capture, /expected exactly one matching approval/u);
  assert.match(capture, /\.state == "approved"/u);
  assert.match(capture, /\.comment == \$expected/u);
  assert.match(capture, /\.environments\[0\]\.id == \$environmentId/u);
  assert.match(capture, /\.user\.id == \$reviewer\.id/u);
  assert.match(
    capture,
    /APPROVE ARCHON GOVERNED PROOF run_id=\$\{GITHUB_RUN_ID\} run_attempt=\$\{GITHUB_RUN_ATTEMPT\} operation=\$\{operation\} plan_digest=\$\{plan_digest\}/u
  );
  assert.match(proof, /store\.path\(`approval-\$\{operation\}\.json`\)/u);
  assert.doesNotMatch(proof, /subject: `github-environment:/u);
  assert.match(deployRunbook, /assertion\.ref=='refs\/heads\/master'/u);
  assert.match(
    deployRunbook,
    /job_workflow_ref=='upgradedev\/archon-datahub\/\.github\/workflows\/hosted-demo\.yml@refs\/heads\/master'/u
  );
  assert.match(
    deployRunbook,
    /job_workflow_ref=='upgradedev\/archon-datahub\/\.github\/workflows\/live-governed-proof\.yml@refs\/heads\/master'/u
  );
});

test("approval parsing binds the exact run, operation, plan, environment, and reviewer", () => {
  const planDigest = `sha256:${"a".repeat(64)}`;
  const expected = {
    repository: "upgradedev/archon-datahub",
    workflowRunId: "12345",
    workflowRunAttempt: "2",
    environment: "governed-canary",
    reviewerLogin: "upgradedev",
    operation: "write" as const,
    planDigest,
  };
  const receipt = {
    schemaVersion: "archon.github-environment-approval/v1",
    repository: expected.repository,
    workflowRunId: expected.workflowRunId,
    workflowRunAttempt: expected.workflowRunAttempt,
    operation: expected.operation,
    planDigest,
    state: "approved",
    comment: expectedApprovalComment(expected),
    environment: { name: expected.environment, id: 678 },
    reviewer: { login: "upgradedev", id: 42 },
  };

  assert.deepEqual(verifiedApproverFromReceipt(receipt, expected), {
    subject: "github-user:upgradedev#42",
    issuer: "https://api.github.com",
    roles: ["DataSteward"],
    authenticated: true,
  });
  assert.throws(
    () => verifiedApproverFromReceipt({ ...receipt, comment: "APPROVE" }, expected),
    /not bound to the exact reviewer event/u
  );
  assert.throws(
    () =>
      verifiedApproverFromReceipt(
        { ...receipt, reviewer: { login: "other-user", id: 99 } },
        expected
      ),
    /not bound to the exact reviewer event/u
  );
});

test("hosted release is cost bounded and sealed by post-deploy DAST", async () => {
  const [workflow, firebaseConfig] = await Promise.all([
    readFile(hostedWorkflowPath, "utf8"),
    readFile(firebaseConfigPath, "utf8"),
  ]);

  assert.match(workflow, /--cpu-throttling/u);
  assert.match(workflow, /--min-instances 0/u);
  assert.match(workflow, /--max-instances 1/u);
  assert.doesNotMatch(workflow, /--no-cpu-throttling/u);
  assert.match(workflow, /--env-vars-file "\$\{env_file\}"/u);
  assert.doesNotMatch(workflow, /--set-env-vars/u);
  assert.match(
    workflow,
    /ghcr\.io\/zaproxy\/zaproxy@sha256:[a-f0-9]{64}/u
  );
  assert.match(workflow, /zap-baseline\.py/u);
  assert.match(workflow, /zap_status=0/u);
  assert.match(workflow, /test "\$\{zap_status\}" -le 1/u);
  assert.match(workflow, /test -s "\$\{report_dir\}\/zap-report\.json"/u);
  assert.match(workflow, /select\(\(\.riskcode \| tonumber\) >= 2\)/u);
  assert.match(workflow, /hosted-demo-dast-\$\{\{ github\.sha \}\}/u);
  assert.match(workflow, /id: dast/u);
  assert.match(
    workflow,
    /if: always\(\) && steps\.dast\.outcome != 'skipped'/u
  );
  for (const header of [
    "Content-Security-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
  ]) {
    assert.ok(
      firebaseConfig.includes(`"key": "${header}"`),
      `Firebase hosting must emit ${header}`
    );
  }
  assert.match(firebaseConfig, /frame-ancestors 'none'/u);
  assert.match(firebaseConfig, /object-src 'none'/u);
});
