import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/supply-chain.yml", import.meta.url),
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
const cdkPatch = readFileSync(
  new URL("../../scripts/patch-cdk-brace-expansion.sh", import.meta.url),
  "utf8"
);
const cdkAuditCompensation = readFileSync(
  new URL(
    "../../scripts/verify-cdk-npm-audit-compensation.sh",
    import.meta.url
  ),
  "utf8"
);
const npmAuditRetry = readFileSync(
  new URL("../../scripts/npm-audit-retry.sh", import.meta.url),
  "utf8"
);
const overrideVerifier = readFileSync(
  new URL("../../scripts/verify-exact-npm-overrides.mjs", import.meta.url),
  "utf8"
);
const mcpMaterializer = readFileSync(
  new URL("../../scripts/materialize-datahub-mcp-lock.sh", import.meta.url),
  "utf8"
);
const openVexMaintenanceContracts = readFileSync(
  new URL(
    "../pipeline/openvex-maintenance-contracts.test.sh",
    import.meta.url
  ),
  "utf8"
);
const infraDocumentation = readFileSync(
  new URL("../../infra/aws/README.md", import.meta.url),
  "utf8"
);
const liveDataHubDocumentation = readFileSync(
  new URL("../../docs/LIVE_DATAHUB_PROOF.md", import.meta.url),
  "utf8"
);

test("OpenVEX renewal is bounded and enforced before dependency tooling", () => {
  assert.match(mcpMaterializer, /--openvex-maintenance-only/u);
  assert.match(mcpMaterializer, /--minimum-remaining-days DAYS/u);
  assert.match(
    mcpMaterializer,
    /minimum_remaining_days\}" =~ \^\[1-9\]\[0-9\]\?\$/u
  );
  assert.match(mcpMaterializer, /minimum_remaining_days > 30/u);
  assert.match(
    mcpMaterializer,
    /test "\$\{vex_max_validity_days\}" = "30"/u
  );
  assert.match(
    mcpMaterializer,
    /vex_expires_epoch - vex_issued_epoch\)\)" -le[\s\S]+vex_max_validity_days \* 24 \* 60 \* 60/u
  );

  const maintenanceBranch = mcpMaterializer.indexOf(
    'if [[ "${maintenance_only}" == "true" ]]'
  );
  const repositoryRead = mcpMaterializer.indexOf(
    'readonly repository="$(jq -er'
  );
  const destinationCreation = mcpMaterializer.indexOf(
    'mkdir -p "${destination}"'
  );
  const sourceFetch = mcpMaterializer.indexOf('git -C "${destination}" init');
  const resolver = mcpMaterializer.indexOf("uv lock \\");
  const provenanceDownload = mcpMaterializer.indexOf(
    "curl --fail --silent --show-error --location"
  );
  assert.ok(maintenanceBranch >= 0);
  for (const laterOperation of [
    repositoryRead,
    destinationCreation,
    sourceFetch,
    resolver,
    provenanceDownload,
  ]) {
    assert.ok(laterOperation > maintenanceBranch);
  }
  const maintenanceMode = mcpMaterializer.slice(
    maintenanceBranch,
    repositoryRead
  );
  assert.match(
    maintenanceMode,
    /vex_remaining_seconds < minimum_remaining_days \* 86400/u
  );
  assert.match(
    maintenanceMode,
    /schemaVersion: "archon\.openvex-maintenance\/v1"/u
  );
  assert.match(maintenanceMode, /\n  exit 0\n/u);

  const mcpJobStart = ciWorkflow.indexOf("\n  mcp-dependency:");
  const mcpJobEnd = ciWorkflow.indexOf("\n  dependency-review:", mcpJobStart);
  assert.ok(mcpJobStart >= 0);
  assert.ok(mcpJobEnd > mcpJobStart);
  const mcpJob = ciWorkflow.slice(mcpJobStart, mcpJobEnd);
  const normalGate = mcpJob.indexOf("Enforce the OpenVEX renewal horizon");
  const setupUv = mcpJob.indexOf("astral-sh/setup-uv");
  const materialization = mcpJob.indexOf(
    "Verify upstream and derive the wheel-only runtime lock"
  );
  assert.ok(normalGate >= 0);
  assert.ok(setupUv > normalGate);
  assert.ok(materialization > setupUv);
  assert.match(
    mcpJob.slice(normalGate, setupUv),
    /--openvex-maintenance-only[\s\S]+--minimum-remaining-days 14/u
  );

  const independentJobStart = workflow.indexOf("\n  openvex-maintenance:");
  const resolverJobStart = workflow.indexOf("\n  resolve-production:");
  assert.ok(independentJobStart >= 0);
  assert.ok(resolverJobStart > independentJobStart);
  const independentJob = workflow.slice(independentJobStart, resolverJobStart);
  assert.match(independentJob, /if: github\.event_name == 'schedule'/u);
  assert.match(independentJob, /ref: master/u);
  assert.match(independentJob, /permissions:\r?\n      contents: read/u);
  assert.doesNotMatch(independentJob, /\n    needs:/u);
  assert.doesNotMatch(independentJob, /\n    environment:/u);
  assert.doesNotMatch(independentJob, /id-token: write/u);
  assert.match(
    independentJob,
    /--openvex-maintenance-only[\s\S]+--minimum-remaining-days 14/u
  );

  const scanStart = workflow.indexOf("\n  scan:");
  const scanEnd = workflow.indexOf("\n  revalidate-production:", scanStart);
  assert.ok(scanStart >= 0);
  assert.ok(scanEnd > scanStart);
  const scan = workflow.slice(scanStart, scanEnd);
  const sourceCheckout = scan.indexOf(
    "Check out the exact successful CI source"
  );
  const dailyGate = scan.indexOf(
    "Enforce the scanned source OpenVEX renewal horizon"
  );
  const scanPreparation = scan.indexOf("Prepare ephemeral directories");
  assert.ok(sourceCheckout >= 0);
  assert.ok(dailyGate > sourceCheckout);
  assert.ok(scanPreparation > dailyGate);
  assert.match(
    scan.slice(dailyGate, scanPreparation),
    /--openvex-maintenance-only[\s\S]+--minimum-remaining-days 14/u
  );
  assert.match(workflow, /schedule:\r?\n    - cron: "23 3 \* \* \*"/u);

  assert.match(
    ciWorkflow,
    /bash tests\/pipeline\/openvex-maintenance-contracts\.test\.sh/u
  );
  assert.match(
    openVexMaintenanceContracts,
    /for command in cp curl git mkdir python3 uv/u
  );
  assert.match(
    openVexMaintenanceContracts,
    /ln -s forbidden "\$\{temporary\}\/bin\/\$\{command\}"/u
  );
  assert.match(openVexMaintenanceContracts, /fifteen_days_before/u);
  assert.match(openVexMaintenanceContracts, /fourteen_days_before/u);
  assert.match(openVexMaintenanceContracts, /thirteen_days_before/u);
  assert.match(
    openVexMaintenanceContracts,
    /for invalid_days in 0 00 014 08 31 invalid/u
  );

  assert.match(liveDataHubDocumentation, /OpenVEX renewal runbook/u);
  assert.match(
    liveDataHubDocumentation,
    /fail when fewer than 14 days remain/u
  );
  assert.match(
    liveDataHubDocumentation,
    /validity is at most 30 days/u
  );
  assert.match(
    liveDataHubDocumentation,
    /If the runtime is affected or the disposition is\s+uncertain, upgrade the dependency or remove the disposition; do not renew it/u
  );
});

test("scheduled rescans bind exact live deployment, CI run, and subjects", () => {
  const resolverStart = workflow.indexOf("\n  resolve-production:");
  const scanStart = workflow.indexOf("\n  scan:");
  const revalidateStart = workflow.indexOf("\n  revalidate-production:");
  const sarifStart = workflow.indexOf("\n  publish-sarif:");
  const attestStart = workflow.indexOf("\n  attest:");

  assert.ok(resolverStart >= 0);
  assert.ok(scanStart > resolverStart);
  assert.ok(revalidateStart > scanStart);
  assert.ok(sarifStart > revalidateStart);
  assert.ok(attestStart > sarifStart);

  const resolver = workflow.slice(resolverStart, scanStart);
  const scan = workflow.slice(scanStart, revalidateStart);
  const revalidate = workflow.slice(revalidateStart, sarifStart);
  const sarif = workflow.slice(sarifStart, attestStart);
  const attest = workflow.slice(attestStart);

  assert.match(resolver, /environment: production-observer/u);
  assert.match(
    resolver,
    /permissions:\n      actions: read\n      contents: read\n      id-token: write/u
  );
  assert.match(
    resolver,
    /git\/ref\/heads\/\$\{default_branch\}[\s\S]+test "\$\{master_sha\}" = "\$\{GITHUB_SHA\}"/u
  );
  assert.match(
    resolver,
    /for workflow in ci\.yml codeql\.yml workflow-security\.yml/u
  );
  assert.match(
    resolver,
    /actions\/workflows\/\$\{workflow\}\/runs/u
  );
  assert.match(
    resolver,
    /sort_by\(\.id, \.run_attempt\)[\s\S]+\.status == "completed"[\s\S]+\.conclusion == "success"/u
  );
  assert.ok(
    resolver.indexOf("Check out the exact observer control plane") <
      resolver.indexOf("Configure read-only production observer through OIDC")
  );
  for (const output of [
    "ArchonReleaseSha",
    "ArchonContainerImageDigest",
    "ArchonSpaArtifactSha256",
    "ArchonContainerArchiveSha256",
    "ArchonLambdaArchiveSha256",
    "ArchonDeploymentWorkflowRunId",
    "ArchonDeploymentWorkflowRunAttempt",
    "ArchonCiRunId",
    "ArchonSpaKeyArn"
  ]) {
    assert.match(resolver, new RegExp(output, "u"));
  }
  assert.match(
    resolver,
    /actions\/runs\/\$\{deployment_run_id\}\/attempts\/\$\{deployment_run_attempt\}/u
  );
  assert.match(
    resolver,
    /deployment-evidence-\$\{release_sha\}-\$\{deployment_run_attempt\}/u
  );
  assert.match(
    resolver,
    /Production deployment evidence failed GitHub artifact digest verification/u
  );
  assert.match(resolver, /deployment-evidence\.json/u);
  assert.match(resolver, /control-plane-security-gates\.json/u);
  assert.match(
    resolver,
    /The deployment control-plane receipt differs from deployment evidence/u
  );
  assert.match(resolver, /write-verified-and-rollback-proven/u);
  assert.match(resolver, /bash scripts\/observe-aws-live-runtime\.sh/u);
  assert.ok(
    resolver.indexOf("bash scripts/observe-aws-live-runtime.sh") >
      resolver.indexOf("Configure read-only production observer through OIDC")
  );
  assert.match(
    resolver,
    /Current production bytes differ from the sealed deployment manifest/u
  );
  assert.match(resolver, /liveManifestDigest: \$liveRuntimeManifestDigest/u);
  assert.match(resolver, /observedManifestDigest: \$liveRuntimeManifestDigest/u);
  assert.match(resolver, /exactlyMatches: true/u);
  assert.match(resolver, /deployment_artifact_id=\$\{deployment_artifact_id\}/u);

  assert.match(scan, /DEPLOYED_CI_RUN_ID/u);
  assert.doesNotMatch(scan, /max_by\(\.id\)/u);
  assert.match(
    scan,
    /actual_artifact_digest[\s\S]+sha256:\$\{expected_artifact_sha\}/u
  );
  assert.match(
    scan,
    /Scanned subjects differ from the exact production deployment/u
  );
  assert.match(
    scan,
    /deployment-evidence\.json[\s\S]+production-binding\.json/u
  );
  assert.match(
    scan,
    /actions\/artifacts\/\$\{EXPECTED_DEPLOYMENT_ARTIFACT_ID\}\/zip/u
  );
  assert.match(
    scan,
    /The deployment evidence artifact changed before scan/u
  );
  assert.match(scan, /live-runtime-manifest\.json/u);
  assert.match(
    scan,
    /live bytes differ from the exact CI Lambda candidate/u
  );
  assert.match(
    scan,
    /Live SPA bytes differ from the exact CI web candidate/u
  );
  assert.match(scan, /runningImageDigests == \[\$image\]/u);
  assert.doesNotMatch(scan, /observed-live-runtime-manifest\.json/u);

  assert.match(revalidate, /LastUpdatedTime \/\/ \.Stacks\[0\]\.CreationTime/u);
  assert.match(
    revalidate,
    /actions\/runs\/\$\{deployment_run_id\}\/attempts\/\$\{deployment_run_attempt\}/u
  );
  assert.match(
    revalidate,
    /Production deployment evidence artifact metadata changed/u
  );
  assert.match(revalidate, /The exact CI source run is no longer valid/u);
  assert.match(
    revalidate,
    /changed during the production rescan/u
  );
  assert.match(revalidate, /bash scripts\/observe-aws-live-runtime\.sh/u);
  assert.ok(
    revalidate.indexOf("bash scripts/observe-aws-live-runtime.sh") >
      revalidate.indexOf("changed during the production rescan")
  );
  assert.match(
    revalidate,
    /Production runtime bytes changed during the rescan/u
  );
  for (const runtimeEvidence of [
    "deployment-control-plane-gates.json",
    "live-runtime-manifest.json",
    "revalidated-live-runtime-manifest.json",
    "production-runtime-config.json",
    "supply-chain-control-plane-gates.json"
  ]) {
    assert.match(
      revalidate,
      new RegExp(runtimeEvidence.replaceAll(".", "\\."), "u")
    );
  }
  assert.match(
    revalidate,
    /Clear observer credentials before artifact handling[\s\S]+AWS_SESSION_TOKEN=/u
  );

  assert.match(
    sarif,
    /needs\.revalidate-production\.result == 'success'/u
  );
  assert.match(
    attest,
    /github\.event_name == 'schedule'[\s\S]+needs\.revalidate-production\.result == 'success'/u
  );
  assert.doesNotMatch(attest, /-f status=success/u);
  assert.match(attest, /def latest_exact\(\$path\):/u);
  assert.match(attest, /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u);
  assert.match(attest, /Deployment evidence differs between scan and revalidation/u);
  assert.match(attest, /\.runtime\.sealedManifestDigest == \$runtime/u);
  assert.match(attest, /\.runtime\.revalidatedManifestDigest == \$runtime/u);
  assert.match(attest, /\.runtime\.exactlyMatches == true/u);
  assert.match(
    attest,
    /Production runtime bytes changed before attestation/u
  );
  assert.match(attest, /revalidated-live-runtime-manifest\.json/u);
  const bindSecurityGates = attest.indexOf(
    "Bind independent security workflow gates"
  );
  const finalCheckout = attest.indexOf(
    "Check out the exact observer control plane before attestation"
  );
  const finalObserverGate = attest.indexOf(
    "Revalidate sealed observer control plane immediately before attestation"
  );
  const provenanceAttestation = attest.indexOf(
    "Sign verified CI-artifact provenance"
  );
  const finalSourceGate = attest.indexOf(
    "Revalidate sealed source security gates immediately before attestation"
  );
  assert.ok(bindSecurityGates >= 0);
  assert.ok(finalCheckout > bindSecurityGates);
  assert.ok(finalObserverGate > finalCheckout);
  assert.ok(finalSourceGate > finalObserverGate);
  assert.ok(provenanceAttestation > finalSourceGate);
  assert.match(
    attest,
    /if: github\.event_name == 'schedule'[\s\S]+ref: \$\{\{ github\.sha \}\}/u
  );
  assert.match(attest, /bash scripts\/verify-github-control-plane\.sh/u);
  assert.match(
    attest,
    /\(\$sealed\[0\]\.workflows \| receipt\) ==\s+\(\$current\[0\]\.workflows \| receipt\)/u
  );
  assert.match(
    attest,
    /The observer control plane changed before attestation/u
  );
  const finalSourceGateScript = attest.slice(
    finalSourceGate,
    provenanceAttestation
  );
  assert.doesNotMatch(finalSourceGateScript, /-f status=/u);
  assert.doesNotMatch(finalSourceGateScript, /git\/ref\/heads/u);
  assert.match(finalSourceGateScript, /read_source_gate_snapshot\(\)/u);
  assert.equal(
    finalSourceGateScript.match(/read_source_gate_snapshot\)"/gu)?.length,
    2
  );
  assert.match(
    finalSourceGateScript,
    /sort_by\(\.id, \.run_attempt\)\s+\|\s+last/u
  );
  assert.match(
    finalSourceGateScript,
    /\.status == "completed" and\s+\.conclusion == "success"/u
  );
  assert.match(
    finalSourceGateScript,
    /test "\$\{second_snapshot\}" = "\$\{first_snapshot\}"/u
  );
  assert.match(
    finalSourceGateScript,
    /test "\$\{second_snapshot\}" = "\$\{sealed_snapshot\}"/u
  );
  assert.match(
    finalSourceGateScript,
    /The sealed source security gates are no longer the latest successful runs/u
  );
  assert.equal(
    workflow.match(/bash scripts\/verify-github-control-plane\.sh/gu)?.length,
    3
  );
});

test("normal npm dependency gates reject every moderate-or-higher advisory", () => {
  assert.match(npmAuditRetry, /--audit-level=moderate\)/u);
  assert.match(npmAuditRetry, /--audit-level\|--audit-level=\*/u);
  assert.match(npmAuditRetry, /--json\|--json=\*/u);
  assert.match(npmAuditRetry, /audit_level_count != 1/u);
  assert.match(
    npmAuditRetry,
    /\.metadata\.vulnerabilities\.moderate \/\/ 0/u
  );
  assert.match(npmAuditRetry, /\.severity == "moderate"/u);
  assert.match(npmAuditRetry, /moderate or higher vulnerability/u);
  assert.doesNotMatch(npmAuditRetry, /--audit-level=high/u);

  assert.equal(
    [
      ...ciWorkflow.matchAll(
        /bash "\$\{GITHUB_WORKSPACE\}\/scripts\/npm-audit-retry\.sh"/gu
      )
    ].length,
    6
  );
  assert.equal(
    [...ciWorkflow.matchAll(/--audit-level=moderate/gu)].length,
    6
  );
  const web = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  web:"),
    ciWorkflow.indexOf("\n  infra-lock-candidate:")
  );
  assert.match(web, /npm-audit-retry\.sh[\s\S]*--audit-level=moderate/u);

  const candidate = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  infra-lock-candidate:"),
    ciWorkflow.indexOf("\n  infra:")
  );
  assert.equal(
    [...candidate.matchAll(/scripts\/npm-audit-retry\.sh/gu)].length,
    2
  );
  assert.equal(
    [...candidate.matchAll(/--audit-level=moderate/gu)].length,
    2
  );

  const infra = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  infra:"),
    ciWorkflow.indexOf("\n  publish-infra-sarif:")
  );
  assert.equal(
    [...infra.matchAll(/scripts\/npm-audit-retry\.sh/gu)].length,
    2
  );
  assert.equal(
    [
      ...infra.matchAll(
        /npm-audit-retry\.sh"\s+--omit=dev\s+--audit-level=moderate/gu
      )
    ].length,
    2
  );
  assert.equal(
    [...infra.matchAll(/--audit-level=moderate/gu)].length,
    2
  );
  assert.match(
    infra,
    /bash scripts\/verify-cdk-npm-audit-compensation\.sh infra\/aws/u
  );

  const security = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  security:"),
    ciWorkflow.indexOf("\n  mcp-dependency:")
  );
  assert.equal(
    [...security.matchAll(/scripts\/npm-audit-retry\.sh/gu)].length,
    1
  );
  assert.equal(
    [...security.matchAll(/--audit-level=moderate/gu)].length,
    1
  );

  const dependencyReview = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  dependency-review:"),
    ciWorkflow.indexOf("\n  load:")
  );
  assert.match(dependencyReview, /fail-on-severity: moderate/u);
  assert.equal(
    [...dependencyReview.matchAll(/allow-ghsas:/gu)].length,
    1
  );
  assert.match(
    dependencyReview,
    /allow-ghsas: GHSA-mh99-v99m-4gvg/u
  );
  assert.doesNotMatch(dependencyReview, /allow-dependencies:/u);
});

test("CDK bundled advisory is repaired and admitted only by an exact CI receipt", () => {
  const lockCandidateStart = ciWorkflow.indexOf("\n  infra-lock-candidate:");
  const lockCandidateEnd = ciWorkflow.indexOf(
    "\n  infra:",
    lockCandidateStart
  );
  assert.ok(
    lockCandidateStart >= 0 && lockCandidateEnd > lockCandidateStart,
    "infra lock-candidate job must remain independently addressable"
  );
  const lockCandidateJob = ciWorkflow.slice(
    lockCandidateStart,
    lockCandidateEnd
  );
  assert.match(ciWorkflow, /INFRA_NODE_VERSION: "22\.23\.1"/u);
  assert.match(
    ciWorkflow,
    /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/u
  );
  assert.match(ciWorkflow, /Seal candidate provenance before validation/u);
  assert.match(ciWorkflow, /clean-lock-generation/u);
  assert.match(ciWorkflow, /NPM_CONFIG_USERCONFIG: \/dev\/null/u);
  assert.match(ciWorkflow, /NPM_CONFIG_REGISTRY: https:\/\/registry\.npmjs\.org\//u);
  assert.equal(lockCandidateJob.match(/cmp --silent/gu)?.length, 3);
  assert.match(
    ciWorkflow,
    /Committed root lock differs from clean npm 10\.9\.8 resolution/u
  );
  assert.match(
    ciWorkflow,
    /Committed infrastructure lock differs from clean npm 10\.9\.8 resolution/u
  );
  assert.match(
    ciWorkflow,
    /Committed web lock differs from clean npm 10\.9\.8 resolution/u
  );
  assert.match(ciWorkflow, /pullRequestHeadSha: \$headSha/u);
  assert.match(ciWorkflow, /headRepository: \$headRepository/u);
  assert.match(ciWorkflow, /pullRequestNumber: \$pullRequestNumber/u);
  assert.match(ciWorkflow, /workflowRef: \$workflowRef/u);
  assert.match(ciWorkflow, /workflowSha: \$workflowSha/u);
  assert.match(ciWorkflow, /packageJsonSha256: \$infraManifestSha256/u);
  assert.match(ciWorkflow, /lockSha256: \$infraLockSha256/u);
  assert.match(ciWorkflow, /packageJsonSha256: \$webManifestSha256/u);
  assert.match(ciWorkflow, /lockSha256: \$webLockSha256/u);

  const infraStart = ciWorkflow.indexOf("\n  infra:");
  const publisherStart = ciWorkflow.indexOf(
    "\n  publish-infra-sarif:",
    infraStart
  );
  const infra = ciWorkflow.slice(infraStart, publisherStart);
  const install = infra.indexOf("Install locked infrastructure dependencies");
  const overrides = infra.indexOf("Verify every exact infrastructure override");
  const patch = infra.indexOf("Repair the exact vulnerable CDK bundled dependency");
  const typecheck = infra.indexOf("Typecheck CDK and Lambda contract tests");
  const audit = infra.indexOf("Infrastructure SCA gate");
  const receipt = infra.indexOf(
    "Retain exact CDK dependency-compensation evidence"
  );
  assert.ok(install >= 0);
  assert.ok(overrides > install);
  assert.ok(patch > overrides);
  assert.ok(typecheck > patch);
  assert.ok(audit > typecheck);
  assert.ok(receipt > audit);
  assert.match(
    infra,
    /bash scripts\/verify-cdk-npm-audit-compensation\.sh infra\/aws/u
  );
  assert.doesNotMatch(infra, /security-events: write/u);
  assert.doesNotMatch(infra, /github\/codeql-action\/upload-sarif/u);
  assert.match(infra, /Retain partial synth and Guard failure evidence/u);

  const publisherEnd = ciWorkflow.indexOf("\n  readiness:", publisherStart);
  const publisher = ciWorkflow.slice(publisherStart, publisherEnd);
  assert.ok(publisherStart > infraStart);
  assert.match(
    publisher,
    /github\.ref_name == github\.event\.repository\.default_branch/u
  );
  assert.match(publisher, /needs: infra/u);
  assert.match(publisher, /security-events: write/u);
  assert.match(publisher, /name: infra-\$\{\{ github\.sha \}\}/u);
  assert.match(publisher, /\(\[\.runs\[\]\.results\[\]\] \| length\) == 0/u);
  assert.ok(
    publisher.indexOf("Revalidate zero-finding SARIF before publication") <
      publisher.indexOf("Upload trusted IaC SARIF")
  );

  const dependencyReview = ciWorkflow.slice(
    ciWorkflow.indexOf("\n  dependency-review:"),
    ciWorkflow.indexOf("\n  load:")
  );
  assert.match(dependencyReview, /fail-on-severity: moderate/u);
  assert.match(
    dependencyReview,
    /allow-ghsas: GHSA-mh99-v99m-4gvg/u
  );
  assert.doesNotMatch(dependencyReview, /allow-dependencies:/u);

  assert.match(cdkPatch, /GITHUB_ACTIONS:-\}" != "true"/u);
  assert.match(cdkPatch, /expected_cdk_version="2\.262\.1"/u);
  assert.match(
    cdkPatch,
    /aws-cdk-lib-2\.262\.1\.tgz[\s\S]+sha512-B6YP4r6ojUZCDhl\+qBu\/CrWzcipR8sIgshcqYvgw013sghPXmVkYdJ3yuI9\+DKML3YLSjQrHy1nGJs\+Nqq7JCg==/u
  );
  assert.match(cdkPatch, /vulnerable_version="5\.0\.7"/u);
  assert.match(cdkPatch, /patched_version="5\.0\.8"/u);
  assert.match(
    cdkPatch,
    /sha512-JZyDyq3D4AUifKTPOB7DELf6XsB3WdPuNxCtob1vFXPsSXhdAiHBWJ\/tJ8HAc9aH84BK\+5JFZLNkJKx3G9kzQg==/u
  );
  assert.match(cdkPatch, /archive_size <= 131072/u);
  assert.match(cdkPatch, /The fixed-package archive contains an unsafe path/u);
  assert.match(
    cdkPatch,
    /node_modules\/aws-cdk-lib\/node_modules\/brace-expansion/u
  );
  assert.match(cdkPatch, /assert\.deepEqual\(expand\("x\{a,b\}y"\)/u);
  assert.match(cdkPatch, /installedTreeSha256/u);

  assert.match(cdkAuditCompensation, /Object\.keys\(report\.vulnerabilities/u);
  assert.match(cdkAuditCompensation, /high: 1, critical: 0, total: 1/u);
  assert.match(
    cdkAuditCompensation,
    /node_modules\/aws-cdk-lib\/node_modules\/brace-expansion/u
  );
  assert.match(cdkAuditCompensation, /otherHighOrCritical: 0/u);
  assert.match(cdkAuditCompensation, /sha256sum --check --strict SHA256SUMS/u);

  assert.match(overrideVerifier, /Exact npm override verification is CI\/CD-only/u);
  assert.match(overrideVerifier, /override must be an exact version/u);
  assert.match(overrideVerifier, /resolved\.hostname,[\s\S]+"registry\.npmjs\.org"/u);
  assert.match(overrideVerifier, /\^sha512-/u);
  assert.match(overrideVerifier, /O_NOFOLLOW/u);
  assert.match(overrideVerifier, /fstatSync\(descriptor\)/u);
  assert.match(overrideVerifier, /readFileSync\(descriptor/u);
  assert.doesNotMatch(overrideVerifier, /lstatSync/u);
  assert.doesNotMatch(overrideVerifier, /existsSync/u);
  assert.match(
    overrideVerifier,
    /exact-bundled-compensation-required/u
  );
  assert.match(infraDocumentation, /Temporary bundled dependency compensation/u);
  assert.match(
    infraDocumentation,
    /must be removed, rather than broadened/u
  );
});

test("staging and production synth only with the same repaired CDK tree", () => {
  assert.match(deploymentWorkflow, /NODE_VERSION: "22\.23\.1"/u);
  const stagingStart = deploymentWorkflow.indexOf("\n  staging:");
  const canaryStart = deploymentWorkflow.indexOf(
    "\n  preproduction_canary:",
    stagingStart
  );
  const productionStart = deploymentWorkflow.indexOf(
    "\n  production:",
    canaryStart
  );
  assert.ok(stagingStart >= 0);
  assert.ok(canaryStart > stagingStart);
  assert.ok(productionStart > canaryStart);

  const staging = deploymentWorkflow.slice(stagingStart, canaryStart);
  const production = deploymentWorkflow.slice(productionStart);
  for (const [segment, synthName] of [
    [staging, "Synthesize the exact staging deployment assembly"],
    [production, "Synthesize the exact production deployment assembly"],
  ] as const) {
    const install = segment.indexOf("npm ci --prefix infra/aws --ignore-scripts");
    const overrides = segment.indexOf(
      "node scripts/verify-exact-npm-overrides.mjs infra/aws"
    );
    const patch = segment.indexOf(
      "bash scripts/patch-cdk-brace-expansion.sh infra/aws"
    );
    const audit = segment.indexOf(
      "bash scripts/verify-cdk-npm-audit-compensation.sh infra/aws"
    );
    const synth = segment.indexOf(synthName);
    assert.ok(install >= 0);
    assert.ok(overrides > install);
    assert.ok(patch > overrides);
    assert.ok(audit > patch);
    assert.ok(synth > audit);
    assert.match(segment, /test "\$\(npm --version\)" = "10\.9\.8"/u);
    assert.match(
      segment,
      /\$\{\{ runner\.temp \}\}\/cdk-brace-expansion-compensation\//u
    );
  }
  assert.equal(
    deploymentWorkflow.match(
      /bash scripts\/patch-cdk-brace-expansion\.sh infra\/aws/gu
    )?.length,
    2
  );
  assert.equal(
    deploymentWorkflow.match(
      /bash scripts\/verify-cdk-npm-audit-compensation\.sh infra\/aws/gu
    )?.length,
    2
  );
});
