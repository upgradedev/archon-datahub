import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(
  new URL("../../.github/workflows/supply-chain.yml", import.meta.url),
  "utf8"
);

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
