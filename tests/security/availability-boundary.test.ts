import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/availability.yml", import.meta.url),
  "utf8"
);
const documentation = readFileSync(
  new URL("../../docs/AVAILABILITY.md", import.meta.url),
  "utf8"
);
const deploymentWorkflow = readFileSync(
  new URL("../../.github/workflows/deploy.yml", import.meta.url),
  "utf8"
);
const ciWorkflow = readFileSync(
  new URL("../../.github/workflows/ci.yml", import.meta.url),
  "utf8"
);
const reportValidator = readFileSync(
  new URL("../../scripts/validate-audit-report.jq", import.meta.url),
  "utf8"
);

test("availability is scheduled/manual on a protected, unprivileged observer", () => {
  assert.match(workflow, /^on:\n  schedule:/mu);
  assert.match(workflow, /^\s{2}workflow_dispatch:/mu);
  assert.doesNotMatch(
    workflow,
    /^\s{2}(?:push|pull_request|workflow_run|repository_dispatch):/mu
  );
  assert.match(
    workflow,
    /concurrency:\n  group: production-availability\n  cancel-in-progress: false/u
  );
  assert.match(workflow, /runs-on: ubuntu-24\.04/u);
  assert.match(workflow, /timeout-minutes: 15/u);
  assert.match(workflow, /environment: production-observer/u);
  assert.match(
    workflow,
    /environment: production-observer\n    permissions:\n      actions: read\n      contents: read/u
  );
  assert.match(
    workflow,
    /attest:\n    name: Independently revalidate and attest availability evidence[\s\S]*?permissions:\n      actions: read\n      attestations: write\n      contents: read\n      id-token: write/u
  );
  assert.doesNotMatch(workflow, /^\s+(?:deployments|packages):/mu);
  assert.deepEqual(
    workflow.match(/^\s+[A-Za-z-]+: write\s*$/gmu)?.map((line) => line.trim()),
    ["attestations: write", "id-token: write"]
  );
  assert.doesNotMatch(workflow, /\$\{\{\s*secrets\./u);
  assert.doesNotMatch(
    workflow,
    /configure-aws-credentials|\baws\s+[a-z]|AWS_(?:ACCESS|SECRET|SESSION)|sts:AssumeRole/u
  );

  const actions = workflow.match(/^\s+uses:\s+\S+/gmu) ?? [];
  assert.deepEqual(actions.map((line) => line.trim()), [
    "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "uses: actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
  ]);
});

test("availability executes one bounded read-only request without credentials", () => {
  assert.match(
    workflow,
    /APPLICATION_URL: \$\{\{ inputs\.application_url \|\| vars\.ARCHON_APPLICATION_URL \}\}/u
  );
  assert.match(
    workflow,
    /AUDIT_QUERY: \$\{\{ inputs\.query \|\| vars\.DATAHUB_DEMO_QUERY \}\}/u
  );
  assert.match(workflow, /\(\$query \| length\) >= 1/u);
  assert.match(workflow, /\(\$query \| length\) <= 256/u);
  assert.match(workflow, /\(\$query \| test\("\[\*\?\]"\) \| not\)/u);
  assert.match(workflow, /jq -cnS --arg query "\$\{AUDIT_QUERY\}" '\{query: \$query\}'/u);
  assert.equal(workflow.match(/--request POST/gu)?.length, 1);
  assert.match(workflow, /"\$\{APPLICATION_URL\}\/api\/audits"/u);
  assert.doesNotMatch(
    workflow,
    /api\/(?:approvals|control-loops|remediations?|rollbacks?)|\b(?:PUT|PATCH|DELETE)\b|add_tags|remove_tags/u
  );
  assert.doesNotMatch(
    workflow,
    /Authorization:|Bearer |x-api-key|client_secret|access_token|refresh_token/u
  );

  assert.equal(workflow.match(/--proto '=https'/gu)?.length, 3);
  assert.equal(workflow.match(/--proto-redir '=https'/gu)?.length, 3);
  assert.equal(workflow.match(/--tlsv1\.3/gu)?.length, 3);
  assert.equal(workflow.match(/--max-redirs 0/gu)?.length, 3);
  assert.match(workflow, /--connect-timeout 10 --max-time 50 --max-filesize 4194304/u);
  assert.match(workflow, /test "\$\{audit_redirects\}" = "0"/u);
  assert.match(workflow, /test "\$\{audit_tls\}" = "0"/u);
  assert.match(
    workflow,
    /if grep -qi '\^set-cookie:' "\$\{audit_headers\}"; then/u
  );
  assert.match(
    workflow,
    /if grep -qi '\^location:' "\$\{audit_headers\}"; then/u
  );
  assert.match(workflow, /public audit response must not set cookies/u);
  assert.match(workflow, /public audit response must not redirect/u);
});

test("deploy and availability enforce the same non-wildcard demo scope", () => {
  for (const candidate of [workflow, deploymentWorkflow]) {
    assert.match(
      candidate,
      /\(\$query \| test\("\[\*\?\]"\) \| not\) and\s+\$query != "\{\}"/u
    );
  }
  assert.equal(
    deploymentWorkflow.match(
      /\(\$query \| test\("\[\*\?\]"\) \| not\) and\s+\$query != "\{\}"/gu
    )?.length,
    7
  );
  assert.doesNotMatch(deploymentWorkflow, /\$query != "\*" and/u);
});

test("hosted observers share one strict report and model-provenance contract", () => {
  assert.match(
    workflow,
    /contents\/scripts\/validate-audit-report\.jq/u
  );
  assert.match(
    workflow,
    /jq -e -f "\$\{report_validator\}" >\/dev\/null/u
  );
  assert.equal(
    deploymentWorkflow.match(
      /jq -e -f scripts\/validate-audit-report\.jq >\/dev\/null/gu
    )?.length,
    3
  );

  assert.match(
    reportValidator,
    /\.schemaVersion == "archon\.audit-report\/v1"/u
  );
  assert.match(
    reportValidator,
    /\.schemaVersion != "archon\.model-runtime-provenance\/v1"/u
  );
  assert.match(reportValidator, /\.source == "deterministic-fixture"/u);
  assert.match(reportValidator, /\.source == "live-provider"/u);
  assert.match(reportValidator, /def has_credential_substring:/u);
  assert.match(
    reportValidator,
    /\(has_credential_substring \| not\)/u
  );
  assert.match(
    reportValidator,
    /\.totalTokens == \(\.inputTokens \+ \.outputTokens\)/u
  );
  assert.match(reportValidator, /\.latencyMs <= 3600000/u);
  assert.match(reportValidator, /def valid_public_detail:/u);
  assert.match(reportValidator, /def public_safe:/u);
  assert.match(reportValidator, /def forbidden_public_key:/u);
  assert.match(
    ciWorkflow,
    /bash scripts\/validate-model-provenance-corpus\.sh/u
  );

  assert.match(
    workflow,
    /schemaVersion: "archon\.production-availability\/v2"/u
  );
  assert.match(workflow, /reportSchemaVersion: \$reportSchemaVersion/u);
  assert.match(workflow, /modelProvenance: \$modelProvenance/u);
  assert.equal(
    deploymentWorkflow.match(
      /schemaVersion: "archon\.audit-smoke-evidence\/v3"/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /reportSchemaVersion: \.report\.schemaVersion/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /modelProvenance: \.report\.modelProvenance/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(/semanticProof: \$semantic\[0\]/gu)?.length,
    2
  );
});

test("public runtime, response, and header contracts are exact and sanitized", () => {
  assert.match(workflow, /"\$\{APPLICATION_URL\}\/runtime-config\.json"/u);
  assert.match(
    workflow,
    /exact_keys\(\.; \["schemaVersion", "demoQuery", "auth"\]\)/u
  );
  assert.match(workflow, /--arg demoQuery "\$\{AUDIT_QUERY\}"/u);
  assert.match(workflow, /\.demoQuery == \$demoQuery/u);
  assert.match(
    workflow,
    /\.auth\.scopes == \["openid", "email", "archon\/approve"\]/u
  );
  assert.match(workflow, /\.auth\.redirectUri == \$root/u);
  assert.match(workflow, /\.auth\.logoutUri == \$root/u);
  assert.match(workflow, /cache-control:\.\*no-store/u);
  assert.match(
    workflow,
    /expected_csp="default-src 'self'; base-uri 'self'; connect-src 'self' \$\{auth_origin\}; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'"/u
  );
  assert.match(
    workflow,
    /"strict-transport-security":\s+"max-age=63072000; includeSubDomains; preload"/u
  );
  for (const exactHeader of [
    '"x-content-type-options": "nosniff"',
    '"x-frame-options": "DENY"',
    '"referrer-policy": "no-referrer"',
    '"x-xss-protection": "1; mode=block"',
  ]) {
    assert.ok(workflow.includes(exactHeader));
  }
  assert.match(workflow, /def exactly_one\(name: str\) -> str:/u);
  assert.equal(
    (
      workflow.match(
        /assert_exact_security_headers "\$\{[^}]+_headers\}"/gu
      ) ?? []
    ).length,
    3
  );

  assert.match(
    workflow,
    /exact_keys\(\.; \["requestId", "releaseSha", "report"\]\)/u
  );
  assert.match(workflow, /\.report\.classification\.totalEntities == 1/u);
  assert.match(
    workflow,
    /map\(\.agent\) == \[\s+"classifier",\s+"lineage-analyzer",\s+"governance-auditor",\s+"narrator"/u
  );
  assert.match(
    workflow,
    /\(\?i\)\(secret\|password\|credential\|authorization\|cookie\|api\[_-\]\?key/u
  );
  assert.match(workflow, /PRIVATE KEY-----\|Bearer/u);
  assert.match(workflow, /responseSha256: \$responseSha256/u);
  assert.match(workflow, /requestIdSha256: \$requestIdSha256/u);
  assert.match(workflow, /scanIdSha256: \$scanIdSha256/u);
  assert.match(
    workflow,
    /assert_exact_security_headers "\$\{audit_headers\}" "\$\{request_id\}"/u
  );
  assert.match(
    workflow,
    /exactly_one\("x-request-id"\) != expected_request_id/u
  );
  assert.match(workflow, /requestIdHeaderMatchesBody: true/u);
  assert.doesNotMatch(
    workflow,
    /requestId: \.requestId|scanId: \.report\.scanId|query: \$AUDIT_QUERY/u
  );
});

test("only the newest successful deployment and its sealed CI receipt are accepted", () => {
  assert.match(workflow, /test "\$\{default_branch\}" = "master"/u);
  assert.match(
    workflow,
    /test "\$\{GITHUB_REF\}" = "refs\/heads\/\$\{default_branch\}"/u
  );
  assert.match(workflow, /test "\$\{default_sha\}" = "\$\{GITHUB_SHA\}"/u);
  assert.match(
    workflow,
    /compare\/\$\{release_sha\}\.\.\.\$\{default_sha\}/u
  );
  assert.match(workflow, /\.merge_base_commit\.sha == \$release/u);
  assert.equal(
    workflow.match(/actions\/workflows\/deploy\.yml\/runs/gu)?.length,
    2
  );
  assert.equal(workflow.match(/-f status=success/gu)?.length, 2);
  assert.match(
    workflow,
    /sort_by\(\.id, \.run_attempt\) \|\s+last \|\s+select\(/u
  );
  assert.doesNotMatch(
    workflow,
    /deployment_candidates|for encoded_run|candidate_artifact/u
  );
  assert.match(
    workflow,
    /deployment_artifact_name="deployment-evidence-\$\{release_sha\}-\$\{deployment_attempt\}"/u
  );
  assert.match(
    workflow,
    /\.rollbackSelector\.ciRunId \|[\s\S]+test\("\^\[1-9\]\[0-9\]\{0,19\}\$"\)/u
  );
  assert.equal(
    (workflow.match(/actions\/runs\/\$\{ci_run_id\}"/gu) ?? []).length,
    2
  );
  assert.match(workflow, /\.rollbackSelector\.ciRunId == \$ciRunId/u);
  assert.match(workflow, /\.source\.sourceRunUrl == \$ciRunUrl/u);
  assert.match(workflow, /\.head_sha == \$release/u);
  assert.match(workflow, /\.status == "completed" and\s+\.conclusion == "success"/u);

  for (const exactPathVariant of [
    '.path == ".github/workflows/deploy.yml"',
    '.path == (".github/workflows/deploy.yml@" + $branch)',
    '.path == ".github/workflows/ci.yml"',
    '.path == (".github/workflows/ci.yml@" + $branch)',
  ]) {
    assert.ok(workflow.includes(exactPathVariant));
  }
  assert.doesNotMatch(workflow, /\.path \| startswith/u);

  assert.match(
    workflow,
    /GitHub deployment-evidence artifact digest verification failed/u
  );
  assert.match(workflow, /\.rollbackSelector\.releaseSha == \$release/u);
  assert.match(
    workflow,
    /\.source\.deploymentControlPlaneSha ==\s+\$deploymentControlSha/u
  );
  assert.match(workflow, /\.production\.applicationUrl == \$applicationUrl/u);
  assert.match(
    workflow,
    /\.production\.runtimeConfigSha256 ==\s+\$runtimeConfigSha256/u
  );
  assert.match(workflow, /\.production\.liveRuntimeManifestSha256/u);
  assert.match(workflow, /\.staging\.result == "passed"/u);
  assert.match(workflow, /\.production\.result == "passed"/u);
  assert.match(workflow, /newestSuccessfulDeployment: true/u);
});

test("deployment ZIP metadata is bounded before streaming three required files", () => {
  assert.doesNotMatch(workflow, /\bunzip\b/u);
  assert.match(workflow, /import zipfile/u);
  assert.match(workflow, /entries = archive\.infolist\(\)/u);
  assert.match(workflow, /max_entries = 256/u);
  assert.match(workflow, /max_entry_size = 16_777_216/u);
  assert.match(workflow, /max_total_size = 67_108_864/u);
  assert.match(workflow, /max_compression_ratio = 200/u);
  assert.match(workflow, /canonical_names: set\[str\]/u);
  assert.match(workflow, /stat\.S_IFREG/u);
  assert.match(workflow, /entry\.flag_bits & 0x1/u);
  assert.match(workflow, /deployment archive compression ratio is out of bounds/u);
  assert.match(workflow, /set\(required_entries\) != set\(required_limits\)/u);
  assert.match(workflow, /destination\.open\("xb"\)/u);

  const metadataStart = workflow.indexOf("entries = archive.infolist()");
  const extractionStart = workflow.indexOf('destination.open("xb")');
  assert.ok(metadataStart >= 0 && extractionStart > metadataStart);
  for (const preExtractionCheck of [
    "canonical_names: set[str]",
    "stat.S_IFREG",
    "max_compression_ratio",
    "set(required_entries) != set(required_limits)",
  ]) {
    const checkIndex = workflow.indexOf(preExtractionCheck, metadataStart);
    assert.ok(checkIndex > metadataStart && checkIndex < extractionStart);
  }

  assert.match(
    workflow,
    /test "\$\(stat -c '%s' "\$\{deployment_archive\}"\)" = \\\s+"\$\{deployment_artifact_size\}"/u
  );
  assert.match(
    workflow,
    /cmp --silent "\$\{production_runtime_config\}" "\$\{runtime_body\}"/u
  );
  assert.match(
    workflow,
    /\.schemaVersion == "archon\.live-runtime-manifest\/v1"/u
  );
  assert.match(workflow, /select\(\.key == "index\.html"\)/u);
  assert.match(workflow, /select\(\.key == "runtime-config\.json"\)/u);
  assert.match(workflow, /publicBytesMatchLiveManifest: true/u);
  assert.match(workflow, /runtimeConfigMatchesDeployment: true/u);
});

test("control-plane, newest deployment, CI, and artifact are rechecked before sealing", () => {
  assert.equal(
    workflow.match(/git\/ref\/heads\/\$\{default_branch\}/gu)?.length,
    2
  );
  assert.match(workflow, /final_default_sha/u);
  assert.match(
    workflow,
    /actions\/runs\/\$\{deployment_run_id\}\/attempts\/\$\{deployment_attempt\}/u
  );
  assert.match(workflow, /final_newest_deployment_run/u);
  assert.match(
    workflow,
    /actions\/artifacts\/\$\{deployment_artifact_id\}"/u
  );
  assert.match(workflow, /\.digest == \$artifactDigest/u);
  assert.match(workflow, /\.size_in_bytes == \$artifactSize/u);
  assert.match(workflow, /\.workflow_run\.id == \$runId/u);

  const finalRef = workflow.indexOf('final_default_ref="$(');
  const finalDeployment = workflow.indexOf('final_deployment_runs="$(');
  const finalArtifact = workflow.indexOf('final_deployment_artifact="$(');
  const evidenceCreation = workflow.indexOf('observed_at="$(date -u');
  assert.ok(finalRef >= 0);
  assert.ok(finalDeployment > finalRef);
  assert.ok(finalArtifact > finalDeployment);
  assert.ok(evidenceCreation > finalArtifact);

  assert.match(workflow, /finalControlPlaneRevalidated: true/u);
  assert.match(workflow, /finalDeploymentAttemptRevalidated: true/u);
  assert.match(workflow, /finalCiRunRevalidated: true/u);
  assert.match(workflow, /finalArtifactMetadataRevalidated: true/u);
  assert.match(
    workflow,
    /schemaVersion: "archon\.production-availability\/v2"/u
  );
  assert.match(workflow, /masterAncestor: true/u);
});

test("evidence is minimal, checksum-sealed, attested, retained, and honestly documented", () => {
  assert.match(
    workflow,
    /evidence_dir="\$\{RUNNER_TEMP\}\/availability-evidence"/u
  );
  assert.match(
    workflow,
    /schemaVersion: "archon\.production-availability-manifest\/v1"/u
  );
  assert.match(workflow, /path: "availability\.json"/u);
  assert.match(workflow, /sha256sum --check --strict SHA256SUMS/u);
  assert.match(
    workflow,
    /schemaVersion:\s+"archon\.production-availability-attestation\/v1"/u
  );
  assert.match(
    workflow,
    /predicate-type: https:\/\/github\.com\/upgradedev\/archon-datahub\/attestations\/production-availability\/v1/u
  );
  assert.match(
    workflow,
    /artifact-ids: \$\{\{ needs\.probe\.outputs\.artifact_id \}\}/u
  );
  assert.match(
    workflow,
    /subject-checksums: \$\{\{ runner\.temp \}\}\/availability-attestation\/availability-subject\.sha256/u
  );
  assert.match(
    workflow,
    /predicate-path: \$\{\{ runner\.temp \}\}\/availability-attestation\/attestation-predicate\.json/u
  );
  assert.match(
    workflow,
    /printf '%s\\n' \\\s+SHA256SUMS \\\s+attestation-predicate\.json \\\s+availability-subject\.sha256 \\\s+availability\.json \\\s+manifest\.json/u
  );
  assert.match(
    workflow,
    /sha256sum --check --strict availability-subject\.sha256/u
  );
  assert.match(workflow, /maximumExpectedGapMinutes: 420/u);
  assert.match(workflow, /result: "public-read-path-verified"/u);
  assert.match(workflow, /\.workflow_run\.head_sha == \$sha/u);
  assert.match(workflow, /\.workflow_run\.id == \$runId/u);
  assert.match(workflow, /\.digest == \$digest/u);
  assert.match(workflow, /\.name == \$name/u);
  assert.match(
    workflow,
    /uses: actions\/attest@59d89421af93a897026c735860bf21b6eb4f7b26/u
  );
  assert.match(
    workflow,
    /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u
  );
  assert.match(
    workflow,
    /name: production-availability-\$\{\{ steps\.probe\.outputs\.release_sha \}\}-\$\{\{ github\.run_attempt \}\}/u
  );
  assert.match(workflow, /path: \$\{\{ runner\.temp \}\}\/availability-evidence/u);
  assert.match(workflow, /if-no-files-found: error/u);
  assert.match(workflow, /retention-days: 90/u);

  assert.match(documentation, /ARCHON_APPLICATION_URL/u);
  assert.match(documentation, /DATAHUB_DEMO_QUERY/u);
  assert.match(documentation, /production-observer/u);
  assert.match(documentation, /does not contain a release SHA/u);
  assert.match(documentation, /does not provide an SLA/u);
  assert.match(
    documentation,
    /does not use AWS credentials, cloud-deployment authority, or long-lived secrets/u
  );
  assert.match(
    documentation,
    /id-token: write[\s\S]*?attestations: write[\s\S]*only in a dependent attestation job[\s\S]*never available to the\s+probe script/u
  );
  assert.match(
    documentation,
    /never calls an approval,\s+remediation, or rollback route/u
  );
  assert.match(documentation, /newest successful/u);
  assert.match(documentation, /no older historical run/u);
  assert.match(documentation, /rollbackSelector\.ciRunId/u);
  assert.match(documentation, /Header presence alone is not sufficient/u);
  assert.match(documentation, /Before any file is extracted/u);
  assert.match(documentation, /point-in-time observation/u);
});
