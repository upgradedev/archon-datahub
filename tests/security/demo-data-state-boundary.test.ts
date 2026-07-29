import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/datahub-demo-state.yml", import.meta.url),
  "utf8"
);
const driver = readFileSync(
  new URL("../../scripts/datahub-demo-state.py", import.meta.url),
  "utf8"
);
const ciWorkflow = readFileSync(
  new URL("../../.github/workflows/ci.yml", import.meta.url),
  "utf8"
);
const deploymentWorkflow = readFileSync(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8"
);
const liveProofWorkflow = readFileSync(
  new URL("../../.github/workflows/live-datahub-proof.yml", import.meta.url),
  "utf8"
);
const contractText = readFileSync(
  new URL("../../contracts/datahub-demo-state-v1.json", import.meta.url),
  "utf8"
);
const contract = JSON.parse(contractText) as {
  schemaVersion: string;
  officialBaseline: {
    name: string;
    commit: string;
    tree: string;
    expectedMcpCount: number;
    expectedUniqueEntityUrnCount: number;
    files: Array<{ gitBlob: string; path: string; sha256: string; size: number }>;
    anchors: unknown[];
  };
  binding: {
    query: string;
    targetUrn: string;
    danglingUpstreamUrn: string;
    sensitiveFieldPath: string;
    ownedUrns: string[];
  };
  state: {
    ownershipHistory: Array<{ pipelineName: string; runId: string; owner: string }>;
  };
  resetConfirmation: string;
};
const documentation = readFileSync(
  new URL("../../docs/DEMO_DATA_STATE.md", import.meta.url),
  "utf8"
);
const environmentExample = readFileSync(
  new URL("../../.env.example", import.meta.url),
  "utf8"
);

function section(source: string, start: string, end: string): string {
  const first = source.indexOf(start);
  const last = source.indexOf(end, first + start.length);
  assert.ok(first >= 0, `missing section start: ${start}`);
  assert.ok(last > first, `missing section end: ${end}`);
  return source.slice(first, last);
}

test("demo data mutation is manual, serialized, and isolated behind protected environments", () => {
  assert.match(workflow, /^on:\n  workflow_dispatch:/mu);
  assert.doesNotMatch(
    workflow,
    /^\s{2}(?:push|pull_request|schedule|workflow_run|repository_dispatch):/mu
  );
  assert.match(
    workflow,
    /concurrency:\n  group: datahub-demo-state\n  cancel-in-progress: false/u
  );
  assert.match(workflow, /environment: datahub-demo/u);
  assert.match(
    workflow,
    /environment:\n      name: datahub-demo-seed/u
  );
  assert.match(workflow, /required_reviewers/u);
  assert.match(workflow, /prevent_self_review == false/u);
  assert.match(
    workflow,
    /\(\.reviewer\.login \| ascii_downcase\) ==\s+\(\$owner \| ascii_downcase\)/u
  );
  assert.match(workflow, /\.type == "User"/u);
  assert.match(workflow, /\.reviewer\.id/u);
  assert.doesNotMatch(workflow, /can_admins_bypass/u);
  assert.match(workflow, /branch_policies\[0\]\.name == \$branch/u);
  assert.doesNotMatch(
    workflow,
    /configure-aws-credentials|AWS_DEMO_(?:READ|WRITE)_ROLE_ARN|aws sts/u
  );

  const applyJob = workflow.indexOf("\n  apply:");
  const attestationJob = workflow.indexOf("\n  attest-receipt:");
  assert.ok(applyJob >= 0);
  assert.ok(attestationJob > applyJob);
  assert.doesNotMatch(workflow.slice(0, attestationJob), /id-token: write/u);
  const secretlessAttestation = workflow.slice(attestationJob);
  assert.match(secretlessAttestation, /id-token: write/u);
  assert.doesNotMatch(
    secretlessAttestation,
    /setup-uv|materialize-datahub|secrets\.DATAHUB_GMS/u
  );
  assert.match(secretlessAttestation, /sha256sum --check --strict SHA256SUMS/u);
  assert.match(
    secretlessAttestation,
    /actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/u
  );

  const approvalGate = workflow.indexOf(
    "Bind the exact solo-owner environment approval receipt"
  );
  const checkout = workflow.indexOf(
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    applyJob
  );
  const driverApply = workflow.indexOf("datahub-demo-state.py apply");
  assert.ok(approvalGate > applyJob);
  assert.ok(checkout > approvalGate);
  assert.ok(driverApply > checkout);
  const reconstructedRuntime = workflow.indexOf(
    "Recreate the exact wheel-only runtime and official baseline",
    applyJob
  );
  const finalControlPlaneGate = workflow.indexOf(
    "Final exact-SHA green recheck before DataHub credentials",
    reconstructedRuntime
  );
  const credentialedApply = workflow.indexOf(
    "Repeat official dry-run, apply exact plan, and post-read",
    finalControlPlaneGate
  );
  assert.ok(reconstructedRuntime > checkout);
  assert.ok(finalControlPlaneGate > reconstructedRuntime);
  assert.ok(credentialedApply > finalControlPlaneGate);
  assert.doesNotMatch(
    workflow.slice(finalControlPlaneGate, credentialedApply),
    /secrets\.DATAHUB_GMS/u
  );
  assert.match(
    workflow.slice(finalControlPlaneGate, credentialedApply),
    /workflow_success workflow-security\.yml/u
  );
  assert.match(
    workflow.slice(finalControlPlaneGate, credentialedApply),
    /git ls-files --others --exclude-standard/u
  );
  assert.match(
    workflow,
    /actions\/runs\/\$\{GITHUB_RUN_ID\}\/approvals/u
  );
  assert.equal(
    workflow.match(
      /actions\/runs\/\$\{GITHUB_RUN_ID\}\/approvals/gu
    )?.length,
    2
  );
  assert.match(workflow, /\.state == "approved"/u);
  assert.match(workflow, /\.environments \| length\) == 1/u);
  assert.match(workflow, /\.environments\[0\]\.id == \$environmentId/u);
  assert.match(workflow, /\$reviewerIds \| index\(\$userId\)/u);
  assert.match(
    workflow,
    /\(\.user\.login \| ascii_downcase\) ==\s+\(\$owner \| ascii_downcase\)/u
  );
  assert.doesNotMatch(
    workflow,
    /\(\.user\.login \| ascii_downcase\) !=\s+\(\$(?:actor|triggeringActor) \| ascii_downcase\)/u
  );
  assert.equal(
    workflow.match(
      /APPROVE ARCHON DATAHUB DEMO run_id=\$\{GITHUB_RUN_ID\} run_attempt=\$\{GITHUB_RUN_ATTEMPT\}/gu
    )?.length,
    3
  );
  assert.match(workflow, /archon\.datahub-demo-approval\/v1/u);
  assert.match(workflow, /approval-receipt\.json/u);
  assert.match(workflow, /configuredReviewerIds/u);
  assert.match(workflow, /approvalReceiptSha256/u);
  assert.match(driver, /load_approval_receipt/u);
  assert.match(driver, /--approval-receipt/u);
  assert.match(driver, /approvalReceiptSha256/u);
  for (const subject of [
    "SHA256SUMS",
    "approval-receipt.json",
    "baseline-manifest.json",
    "control-plane.json",
    "plan.json",
    "receipt.json",
  ]) {
    assert.match(secretlessAttestation, new RegExp(`subject-path:[\\s\\S]*${subject}`));
  }
  assert.match(documentation, /admin-bypass toggle/u);
  assert.match(documentation, /defense-in-depth/u);
  assert.match(documentation, /cannot reach a DataHub mutation step/u);
  assert.match(
    documentation,
    /APPROVE ARCHON DATAHUB DEMO run_id=<run_id> run_attempt=<run_attempt> action=<seed-or-reset> release_sha=<40-character-release-sha> plan_sha256=<64-character-plan-sha256>/u
  );
});

test("official showcase bytes and exact query/URN are immutable contract data", () => {
  assert.equal(contract.schemaVersion, "archon.datahub-demo-state/v1");
  assert.equal(contract.officialBaseline.name, "showcase-ecommerce");
  assert.match(contract.officialBaseline.commit, /^[0-9a-f]{40}$/u);
  assert.match(contract.officialBaseline.tree, /^[0-9a-f]{40}$/u);
  assert.equal(contract.officialBaseline.expectedMcpCount, 3873);
  assert.equal(contract.officialBaseline.expectedUniqueEntityUrnCount, 1088);
  assert.deepEqual(
    contract.officialBaseline.files.map((file) => file.path),
    ["index.json", "01-definitions.json", "02-data.json", "03-context.json"]
  );
  for (const file of contract.officialBaseline.files) {
    assert.match(file.gitBlob, /^[0-9a-f]{40}$/u);
    assert.match(file.sha256, /^[0-9a-f]{64}$/u);
    assert.ok(file.size > 0);
  }
  assert.ok(contract.officialBaseline.anchors.length >= 8);
  assert.equal(contract.binding.query, contract.binding.targetUrn);
  assert.match(contract.binding.query, /^urn:li:dataset:/u);
  assert.match(workflow, /materialize-baseline/u);
  assert.match(workflow, /cmp --silent/u);
  assert.equal(
    workflow.match(/\.commit\.verification\.verified == true/gu)?.length,
    2
  );
  assert.equal(
    workflow.match(/\.commit\.verification\.reason == "valid"/gu)?.length,
    2
  );
  assert.equal(
    workflow.match(
      /\/repos\/datahub-project\/static-assets\/git\/trees\/\$\{parent_tree\}/gu
    )?.length,
    2
  );
  assert.equal(workflow.match(/tree_child\(\)/gu)?.length, 2);
  assert.match(workflow, /upstreamPackTree/u);
  assert.match(workflow, /officialBaseline\.packTree/u);
  assert.match(workflow, /sha: \.gitBlob/u);
  assert.match(driver, /def git_blob_sha1/u);
  assert.match(driver, /hashlib\.sha1\(usedforsecurity=False\)/u);
  assert.match(driver, /git_blob_sha1\(payload\) != git_blob/u);
  assert.match(documentation, /Git SHA-1 is used only as Git object identity/u);
  assert.equal(workflow.match(/--no-time-shift/gu)?.length, 2);
  assert.match(driver, /"--no-time-shift"/u);
});

test("dry-run plan and GitHub digest receipt precede all mutation paths", () => {
  const firstDryRun = workflow.indexOf("--dry-run");
  const seal = workflow.indexOf("Seal digest receipt before any mutation");
  const upload = workflow.indexOf("Upload the immutable pre-mutation plan receipt");
  const applyJob = workflow.indexOf("\n  apply:");
  const driverApply = workflow.indexOf("datahub-demo-state.py apply");
  assert.ok(firstDryRun >= 0);
  assert.ok(seal > firstDryRun);
  assert.ok(upload > seal);
  assert.ok(applyJob > upload);
  assert.ok(driverApply > applyJob);
  assert.match(
    workflow,
    /artifact_digest: "sha256:\$\{\{ steps\.upload\.outputs\['artifact-digest'\] \}\}"/u
  );
  assert.match(
    workflow,
    /receipt_artifact_digest: "sha256:\$\{\{ steps\.receipt-upload\.outputs\['artifact-digest'\] \}\}"/u
  );
  assert.match(workflow, /\.digest == \$digest/u);
  assert.match(workflow, /sha256sum --check --strict SHA256SUMS/u);
  assert.match(driver, /live DataHub state changed after the reviewed plan was sealed/u);
  assert.match(driver, /plan artifact digest differs from the pre-mutation receipt/u);
  assert.equal(
    workflow.match(/--dry-run >\/dev\/null 2>&1; then/gu)?.length,
    2
  );
  const configPreflights = [...workflow.matchAll(/validate-config/gu)].map(
    (match) => match.index ?? -1
  );
  const directDryRuns = [...workflow.matchAll(/--dry-run/gu)].map(
    (match) => match.index ?? -1
  );
  assert.equal(configPreflights.length, 2);
  assert.equal(directDryRuns.length, 2);
  const [planConfigPreflight, applyConfigPreflight] = configPreflights;
  const [planDryRun, applyDryRun] = directDryRuns;
  assert.ok(planConfigPreflight !== undefined && planDryRun !== undefined);
  assert.ok(applyConfigPreflight !== undefined && applyDryRun !== undefined);
  assert.ok(planConfigPreflight < planDryRun);
  assert.ok(applyConfigPreflight < applyDryRun);
  assert.match(workflow, /--expected-fingerprint/u);
  assert.match(driver, /def gms_endpoint_fingerprint/u);
  assert.match(driver, /apply DataHub endpoint differs from the reviewed plan/u);
  assert.match(driver, /"gmsEndpointFingerprint": plan\["gmsEndpointFingerprint"\]/u);
  assert.equal(workflow.match(/actual_inventory="\$\(/gu)?.length, 4);
  assert.match(workflow, /plan evidence directory contains an unexpected entry/u);
  assert.match(workflow, /downloaded plan contains an unexpected entry/u);
  assert.match(workflow, /receipt evidence directory contains an unexpected entry/u);
  assert.match(workflow, /downloaded evidence contains an unexpected entry/u);
  assert.match(workflow, /is not canonical JSON/u);
  assert.match(workflow, /baseline manifest content digest is invalid/u);
  assert.match(workflow, /\.successfulRuns \| map\(\.path\)/u);
  assert.match(workflow, /\.retainedOwnershipHistory == \[/u);
});

test("the pinned SDK is fully prepared before mutation and reused for emission", () => {
  const applyStart = driver.indexOf("def command_apply(");
  const applyEnd = driver.indexOf("def command_materialize(", applyStart);
  assert.ok(applyStart >= 0);
  assert.ok(applyEnd > applyStart);
  const apply = driver.slice(applyStart, applyEnd);
  const prepare = apply.indexOf("prepare_demo_emission(");
  const deleteOwned = apply.indexOf("delete_owned_urn(");
  const loadPack = apply.indexOf('"datapack",');
  const emitPrepared = apply.indexOf("emit_prepared_demo_state(prepared)");
  const closePrepared = apply.indexOf("close_prepared_demo_emission(prepared)");
  assert.ok(prepare >= 0);
  assert.ok(deleteOwned > prepare);
  assert.ok(loadPack > prepare);
  assert.ok(emitPrepared > loadPack);
  assert.ok(closePrepared > emitPrepared);
  assert.match(driver, /proposal\.make_mcp\(\)\.validate\(\)/u);
  assert.match(driver, /emitter\.test_connection\(\)/u);
  assert.match(ciWorkflow, /datahub-demo-state\.py \\\n\s+validate-runtime/u);
});

test("reset is exact-confirmation and hard-delete allowlist only", () => {
  assert.equal(contract.resetConfirmation, "RESET ARCHON DATAHUB DEMO");
  assert.equal(contract.binding.ownedUrns.length, 2);
  assert.equal(contract.binding.ownedUrns[0], contract.binding.targetUrn);
  assert.ok(!contract.binding.ownedUrns.includes(contract.binding.danglingUpstreamUrn));
  assert.match(workflow, /RESET ARCHON DATAHUB DEMO/u);
  assert.match(driver, /binding\["ownedUrns"\] != \[target, domain\]/u);
  assert.match(
    driver,
    /\[str\(cli\), "delete", "--urn", urn, "--hard", "--force"\]/u
  );
  assert.doesNotMatch(driver, /"delete", "--(?:query|platform|env|entity-type)"/u);
  assert.doesNotMatch(workflow, /datapack unload/u);
  assert.match(driver, /outside the delete allowlist/u);
  assert.match(driver, /ownedUrnPresence/u);
  assert.match(driver, /"datasetKey"/u);
  assert.match(driver, /"domainKey"/u);
  assert.match(
    driver,
    /binding\["danglingUpstreamUrn"\],\s+"datasetKey"/u
  );
  assert.match(driver, /reset_delete_candidates/u);
  assert.match(driver, /absence-proved-after-cli-error/u);
  assert.match(driver, /exact live readback/u);
  assert.match(documentation, /Dispatch a new `reset`/u);
  assert.match(documentation, /skips already-absent owned\s+URNs/u);
});

test("the planted state is exact and proves two stable sources, G6, and dangling lineage", () => {
  assert.deepEqual(
    contract.state.ownershipHistory.map((entry) => entry.pipelineName),
    ["snowflake-prod", "dbt-prod"]
  );
  assert.equal(
    new Set(contract.state.ownershipHistory.map((entry) => entry.runId)).size,
    2
  );
  assert.equal(
    new Set(contract.state.ownershipHistory.map((entry) => entry.owner)).size,
    2
  );
  assert.equal(contract.binding.sensitiveFieldPath, "email");
  assert.notEqual(contract.binding.danglingUpstreamUrn, contract.binding.targetUrn);
  assert.match(driver, /unexpected_history/u);
  assert.match(driver, /g6-gap-classified/u);
  assert.match(driver, /dangling-upstream-exists/u);
  assert.match(driver, /def schema_field_logical_type/u);
  assert.match(driver, /if payload != \{\}:/u);
  assert.match(
    driver,
    /"logicalType": schema_field_logical_type\(field\)/u
  );
  assert.match(
    driver,
    /"logicalType": field\["logicalType"\]/u
  );
  assert.match(driver, /post-mutation state did not match the exact reviewed contract/u);
  assert.match(documentation, /expires at `2026-08-22T11:30:00Z`/u);
  assert.match(
    documentation,
    /gates begin failing at `2026-08-08T11:30:00Z`/u
  );
  assert.match(documentation, /Renew the\s+statement before submission or judging/u);
});

test("credentials stay out of dispatch, argv, plans, and retained receipts", () => {
  assert.doesNotMatch(
    workflow,
    /^\s{6}(?:token|gms_url|secret|password):\n/mu
  );
  assert.match(
    workflow,
    /DATAHUB_GMS_TOKEN: \$\{\{ secrets\.DATAHUB_GMS_TOKEN \}\}/u
  );
  assert.match(
    workflow,
    /DATAHUB_GMS_URL: \$\{\{ secrets\.DATAHUB_GMS_URL \}\}/u
  );
  assert.doesNotMatch(workflow, /--(?:token|password|secret)\b/u);
  assert.doesNotMatch(contractText, /DATAHUB_GMS_TOKEN|Bearer\s+[A-Za-z0-9]/u);
  assert.doesNotMatch(driver, /print\([^)]*token/u);
  assert.doesNotMatch(driver, /dict\(os\.environ\)/u);
  assert.match(driver, /DATAHUB_CLI_ENVIRONMENT_KEYS/u);
  assert.match(driver, /set\(environment\) != DATAHUB_CLI_ENVIRONMENT_KEYS/u);
  assert.equal(workflow.match(/env -i \\\n/gu)?.length, 6);
  assert.equal(
    workflow.match(/unset DATAHUB_GMS_TOKEN DATAHUB_GMS_URL/gu)?.length,
    2
  );
  assert.match(driver, /ProxyHandler\(\{\}\)/u);
  assert.match(driver, /RejectDataHubRedirects/u);
  assert.match(driver, /DATAHUB_API_OPENER\.open/u);
  assert.doesNotMatch(driver, /urlopen\(request, timeout=20\)/u);
  assert.match(driver, /stdout=subprocess\.DEVNULL/u);
  assert.match(driver, /stderr=subprocess\.DEVNULL/u);
  assert.match(driver, /DataHub SDK initialization failed: \{type\(exc\)\.__name__\}/u);
  assert.match(driver, /DataHub SDK connection failed: \{type\(exc\)\.__name__\}/u);
  assert.match(driver, /DataHub SDK emission failed: \{type\(exc\)\.__name__\}/u);
  assert.match(driver, /DataHub SDK close failed: \{type\(exc\)\.__name__\}/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/u);
  assert.match(workflow, /retention-days: 90/u);
  assert.doesNotMatch(workflow, /codex-security|Codex Security/iu);

  assert.match(documentation, /source-complete CI\/CD capability/u);
  assert.match(documentation, /not a claim that the hosted demo has already been seeded/u);
  assert.match(documentation, /It never deletes, unloads, or resets official pack entities/u);
  assert.match(documentation, /fresh two-key environment/u);
  assert.match(documentation, /AWS credentials must not coexist/u);
  assert.match(
    documentation,
    /`DATAHUB_GMS_URL` and `DATAHUB_GMS_TOKEN` are environment-only secret names/u
  );
  assert.match(documentation, /organization or repository scope/u);
  assert.match(documentation, /rejects every\s+HTTP redirect/u);
  assert.match(documentation, /exception messages are not surfaced in CI logs/u);
  assert.match(documentation, /`gmsEndpointFingerprint` is sealed into the plan/u);
  assert.match(documentation, /approval-receipt\.json/u);
  assert.match(documentation, /attests all five JSON subjects plus `SHA256SUMS`/u);
  assert.match(
    environmentExample,
    /GitHub-hosted demo\/live\s+# workflows can use a public HTTPS endpoint/u
  );
  assert.match(
    environmentExample,
    /private endpoints require a self-hosted runner\s+# or tunnel/u
  );
  assert.doesNotMatch(
    environmentExample,
    /Remote endpoints MUST[\s\S]{0,120}stay private behind/u
  );
});

test("deploy and live proof bind the exact sealed receipt and semantic state", () => {
  for (const input of [
    "demo_state_run_id",
    "demo_state_run_attempt",
    "demo_state_artifact_id",
    "demo_state_artifact_digest",
    "demo_state_receipt_sha256",
  ]) {
    assert.match(
      deploymentWorkflow,
      new RegExp(`${input}:\\n\\s+description:[^\\n]+\\n\\s+required: true`, "u")
    );
  }
  assert.equal(
    deploymentWorkflow.match(
      /actions\/runs\/\$\{DEMO_STATE_RUN_ID\}\/attempts\/\$\{DEMO_STATE_RUN_ATTEMPT\}/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /actions\/artifacts\/\$\{DEMO_STATE_ARTIFACT_ID\}/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /datahub-demo-receipt-\$\{DEMO_STATE_RUN_ID\}-\$\{DEMO_STATE_RUN_ATTEMPT\}/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /scripts\/datahub-demo-state\.py verify-receipt/gu
    )?.length,
    2
  );
  assert.match(
    deploymentWorkflow,
    /--expected-receipt-sha256 "\$\{DEMO_STATE_RECEIPT_SHA256\}"/u
  );
  assert.equal(
    deploymentWorkflow.match(
      /attestations\/datahub-demo-state\/v1/gu
    )?.length,
    2
  );
  assert.match(
    driver,
    /"schemaVersion": "archon\.datahub-demo-receipt-binding\/v1"/u
  );
  for (const field of [
    '"runId": run_id',
    '"runAttempt": run_attempt',
    '"id": artifact_id',
    '"digest": artifact_digest',
    '"predicateType":',
    '"predicateSha256": plan_sha256',
    '"gmsEndpointFingerprint": receipt["gmsEndpointFingerprint"]',
    '"postStateSha256": receipt["postStateSha256"]',
    '"queryBindingSha256": digest_obj(query_binding)',
    '"semanticContractSha256": digest_obj(semantic_contract)',
  ]) {
    assert.ok(driver.includes(field), `missing sealed binding field: ${field}`);
  }
  assert.match(
    driver,
    /SEALED_RECEIPT_INVENTORY = \("SHA256SUMS", \*SEALED_RECEIPT_SUBJECTS\)/u
  );
  assert.match(driver, /sealed receipt checksum mismatch/u);
  assert.match(driver, /sealed receipt directory inventory differs/u);

  assert.equal(
    deploymentWorkflow.match(
      /datahub-demo-state\.py fingerprint-endpoint/gu
    )?.length,
    2
  );
  assert.match(
    liveProofWorkflow,
    /datahub-demo-state\.py validate-config \\\n\s+--expected-fingerprint/u
  );
  assert.match(
    liveProofWorkflow,
    /\.datasetUrnSha256 == \$datasetUrnSha/u
  );
  assert.match(liveProofWorkflow, /\.retainedHistories == 1/u);
  assert.match(liveProofWorkflow, /\.stableSourceCount == 2/u);
  assert.match(liveProofWorkflow, /\.recoveredContradictions == 1/u);
  assert.match(liveProofWorkflow, /\.contradictionAttributeCount == 1/u);

  for (const source of [deploymentWorkflow, liveProofWorkflow]) {
    assert.match(source, /\$g6\[0\]\.detail\.unclassifiedFields == \[\$field\]/u);
    assert.match(source, /\$gaps\[0\]\.subject == \$dangling/u);
    assert.match(
      source,
      /\$g6\[0\]\.detail\.blastRadius\.downstream == \[\]/u
    );
    assert.match(
      source,
      /\$g6\[0\]\.detail\.blastRadius\.truncated == false/u
    );
    assert.match(
      source,
      /\$g6\[0\]\.detail\.blastRadius\.impact == "none"/u
    );
    assert.match(
      source,
      /\$gaps\[0\]\.detail\.blastRadius\.downstream == \[\s+\{urn: \$target, minHops: 1\}\s+\]/u
    );
    assert.match(
      source,
      /\$gaps\[0\]\.detail\.blastRadius\.truncated == false/u
    );
    assert.match(
      source,
      /\$gaps\[0\]\.detail\.blastRadius\.impact == "low"/u
    );
    assert.match(source, /\$retained\[0\]\.detail\.attribute == "owner"/u);
    assert.match(
      source,
      /\(\[\$provenance\[\]\.status\] \| sort\) ==\s+\["conflicting", "trusted"\]/u
    );
  }
  assert.match(
    deploymentWorkflow,
    /schemaVersion: "archon\.deployed-datahub-semantic-proof\/v1"/u
  );
  assert.match(
    liveProofWorkflow,
    /current production semantics differ from the promoted proof/u
  );
  const preSecretGate = section(
    liveProofWorkflow,
    "- name: Revalidate exact control plane immediately before DataHub secrets",
    "- name: Prove one-dataset MCP, retention, provenance, and contradiction path"
  );
  assert.match(
    preSecretGate,
    /EXPECTED_GATE_SHA256: \$\{\{ steps\.gate\.outputs\.control_plane_gate_sha \}\}/u
  );
  assert.match(
    preSecretGate,
    /test "\$\(sha256sum "\$\{exact_gates\}" \| awk '\{print \$1\}'\)" = \\\n\s+"\$\{EXPECTED_GATE_SHA256\}"/u
  );
  assert.match(
    preSecretGate,
    /The pre-secret control-plane receipt changed/u
  );
  assert.doesNotMatch(
    preSecretGate,
    /DATAHUB_GMS_URL|DATAHUB_GMS_TOKEN/u
  );

  const stagingEvidence = section(
    deploymentWorkflow,
    "- name: Create staging deployment evidence",
    "- name: Clear staging credentials"
  );
  const productionEvidence = section(
    deploymentWorkflow,
    "- name: Emit promotion evidence",
    "- name: Clear production credentials"
  );
  const liveEvidence = section(
    liveProofWorkflow,
    "- name: Prepare digest-bound proof evidence",
    "- name: Revalidate exact control plane immediately before proof attestation"
  );
  for (const evidence of [stagingEvidence, productionEvidence, liveEvidence]) {
    assert.doesNotMatch(evidence, /DATAHUB_GMS_URL|DATAHUB_GMS_TOKEN/u);
    assert.match(evidence, /sha256sum --check --strict/u);
  }
  assert.match(
    deploymentWorkflow,
    /attestations\/staging-deployment\/v1/u
  );
  assert.match(
    deploymentWorkflow,
    /attestations\/production-deployment\/v1/u
  );
  assert.match(
    liveProofWorkflow,
    /attestations\/live-datahub-proof\/v4/u
  );
  assert.equal(
    deploymentWorkflow.match(
      /\.verificationResult\.statement\.predicate ==\s+\$expectedPredicate\[0\]/gu
    )?.length,
    2
  );
  assert.equal(
    liveProofWorkflow.match(
      /\.verificationResult\.statement\.predicate ==\s+\$expectedPredicate\[0\]/gu
    )?.length,
    2
  );
  for (const source of [deploymentWorkflow, liveProofWorkflow]) {
    assert.match(source, /--format json >"\$\{verification\}"/u);
    assert.match(
      source,
      /\.digest\.sha256 == \$subjectSha256/u
    );
  }
  assert.match(
    liveProofWorkflow,
    /datahub-demo-state-binding\.json/u
  );
  assert.match(
    liveProofWorkflow,
    /sealed-datahub-demo-receipt\/receipt\.json/u
  );
  const bindingProjection = section(
    driver,
    "    binding = {",
    "    write_exclusive("
  );
  assert.doesNotMatch(
    bindingProjection,
    /"gms(?:Url|URL)"|"token":|"DATAHUB_GMS_TOKEN":/u
  );
});
