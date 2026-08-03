import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const deployWorkflow = readFileSync(
  resolve(".github/workflows/deploy.yml"),
  "utf8"
);
const ciWorkflow = readFileSync(
  resolve(".github/workflows/ci.yml"),
  "utf8"
);
const supplyChainWorkflow = readFileSync(
  resolve(".github/workflows/supply-chain.yml"),
  "utf8"
);
const validatorPath = resolve(
  "scripts/validate-lean-production-evidence.mjs"
);
const validatorSource = readFileSync(validatorPath, "utf8");

test("deploy promotes only exact attested build-once artifacts", () => {
  for (const required of [
    "release_sha:",
    "ci_run_id:",
    "cloud_runtime_artifact_id:",
    "cloud_runtime_artifact_digest:",
    "core_ami_artifact_id:",
    "core_ami_artifact_digest:",
    "staging_evidence_artifact_id:",
    "gh attestation verify",
    "datahub-cloud-runtime-release-",
    "archon.datahub-core-ami-build/v2",
    "CloudRuntimeReleaseDigest",
    "DataHubCoreImageManifestDigest",
    "archon.aws-deployment-evidence/v2",
    "archon-web.tar.gz.sha256",
    "archon-lambdas.tar.gz.sha256",
    "SpaArtifactSha256=${SPA_TAR_SHA256}",
    "LambdaArtifactSha256=${LAMBDA_TAR_SHA256}",
  ]) {
    assert.ok(deployWorkflow.includes(required), required);
  }
  assert.match(deployWorkflow, /actions\/attest@[0-9a-f]{40}/u);
  assert.match(deployWorkflow, /retention-days: 90/u);
  assert.doesNotMatch(
    deployWorkflow,
    /docker build|cdk deploy.*Registry|Codex Security/iu
  );
});

test("CI packages only the two deployed Node Lambda trees", () => {
  const start = ciWorkflow.indexOf(
    "- name: Package deterministic Lambda release candidate"
  );
  const end = ciWorkflow.indexOf(
    "- name: Upload exact Lambda release candidate"
  );
  assert.ok(start >= 0 && end > start);
  const packageStep = ciWorkflow.slice(start, end);
  for (const required of [
    "for name in control runtime-control",
    "control runtime-control |",
    "control|control/*|runtime-control|runtime-control/*",
    "control/remediation.js",
    "runtime-control/index.js",
    "runtime-control/session.js",
    "Duplicate Lambda release archive member",
  ]) {
    assert.ok(packageStep.includes(required), required);
  }
  assert.doesNotMatch(packageStep, /\bapproval\b/u);
});

test("supply chain binds only lean production and the exact deployment artifact", () => {
  for (const required of [
    "archon.aws-deployment-evidence/v2",
    "archon.lean-runtime-observation/v1",
    "archon.lean-production-binding/v2",
    "archon.lean-production-revalidation/v2",
    'artifact_name="deployment-evidence-production-${release_sha}-${deployment_run_id}"',
    "Archon-production-Core",
    "Archon-production-Edge",
    "Archon-production-Judge",
    "ArchonCloudRuntimeImageUri",
    "ArchonCloudRuntimeReleaseDigest",
    "ArchonCoreCapabilityDigest",
    "DataHubCoreImageManifestDigest",
    "legacyMonolithContainerProductionSubject:false",
    "legacyAlwaysOnRuntimeAbsent:true",
    'excludedFields:["observedAt"]',
    "exactStableProjectionMatch:true",
  ]) {
    assert.ok(supplyChainWorkflow.includes(required), required);
  }
  for (const legacy of [
    /archon\.production-deployment-binding\/v1/u,
    /archon\.production-deployment-revalidation\/v1/u,
    /archon\.live-runtime-manifest\/v1/u,
    /live-runtime-manifest\.json/u,
    /ArchonContainerImageDigest/u,
    /ArchonContainerArchiveSha256/u,
    /STACK_NAME:\s*Archon-production(?:\s|$)/u,
    /grype-production-image/u,
    /Sign container SPDX/u,
    /Download the exact CI-built container candidate/u,
  ]) {
    assert.doesNotMatch(supplyChainWorkflow, legacy);
  }
});

test("scheduled production observers bind exact control-plane SHA before AWS trust", () => {
  const gates = [
    [
      "- name: Seal current observer control-plane gates before AWS trust",
      "- name: Configure read-only production observer through OIDC",
    ],
    [
      "- name: Revalidate observer control plane before AWS trust",
      "- name: Configure read-only production observer through OIDC",
    ],
  ] as const;
  for (const [startMarker, endMarker] of gates) {
    const start = supplyChainWorkflow.indexOf(startMarker);
    const end = supplyChainWorkflow.indexOf(
      endMarker,
      start + startMarker.length
    );
    assert.ok(start >= 0 && end > start, startMarker);
    const gate = supplyChainWorkflow.slice(start, end);
    const binding = gate.indexOf(
      "CONTROL_PLANE_SHA: ${{ github.sha }}"
    );
    const verifier = gate.indexOf(
      "bash scripts/verify-github-control-plane.sh"
    );
    assert.ok(
      binding >= 0 && verifier > binding,
      startMarker + " must bind the exact checked-out SHA before verification"
    );
    assert.equal(
      gate.match(/bash scripts\/verify-github-control-plane\.sh/gu)?.length,
      1,
      startMarker
    );
  }
  assert.equal(
    supplyChainWorkflow.match(
      /CONTROL_PLANE_SHA: \$\{\{ github\.sha \}\}/gu
    )?.length,
    2
  );
});

test("supply chain normalizes archive digests before REST binding", () => {
  const normalized = `"sha256:\${{ steps.upload.outputs['artifact-digest'] }}"`;
  assert.equal(supplyChainWorkflow.split(normalized).length - 1, 2);
  for (const output of ["evidence_artifact_digest", "artifact_digest"]) {
    assert.ok(supplyChainWorkflow.includes(`${output}: ${normalized}`), output);
    assert.ok(
      !supplyChainWorkflow.includes(
        `${output}: \${{ steps.upload.outputs['artifact-digest'] }}`
      ),
      `${output} must not expose an unqualified digest`
    );
  }
  assert.ok(
    supplyChainWorkflow.includes(
      'test "$(jq -r .digest <<<"${scan_artifact}")" = \\'
    )
  );
  assert.ok(
    supplyChainWorkflow.includes(
      'test "$(jq -r .digest <<<"${artifact}")" = \\'
    )
  );
});

test("supply chain verifies and signs only deployed SPA and Lambda subjects", () => {
  for (const required of [
    "web-${release_sha}",
    "lambdas-${release_sha}",
    "archon-web.tar.gz",
    "archon-lambdas.tar.gz",
    "web-subject.sha256",
    "lambda-subject.sha256",
    "archon-web.spdx.json",
    "archon-lambda.spdx.json",
    "archon-web.cyclonedx.json",
    "archon-lambda.cyclonedx.json",
    "grype-web-report.sarif",
    "grype-lambda-report.sarif",
    "datahub-agent-stack.openvex.json",
    "SYFT_ARCHIVE_SHA256",
    "SYFT_BINARY_SHA256",
    "GRYPE_ARCHIVE_SHA256",
    "GRYPE_BINARY_SHA256",
    "control|control/*|runtime-control|runtime-control/*",
    "control/index.js",
    "control/remediation.js",
    "runtime-control/index.js",
    "runtime-control/session.js",
    "runtime-control/node_modules",
    "archon-production-runtime-control:runtime-control.json",
    "archon-production-runtime-remediation:control.json",
  ]) {
    assert.ok(supplyChainWorkflow.includes(required), required);
  }
  assert.doesNotMatch(
    supplyChainWorkflow,
    /approval\|approval\/\*|LAMBDA_CONTENT_DIR\/approval/u
  );
});

test("deployed Cloud runtime is independently attested twice", () => {
  assert.ok(
    (supplyChainWorkflow.match(
      /attestations\/datahub-cloud-runtime\/v1/gu
    )?.length ?? 0) >= 2
  );
  assert.equal(
    supplyChainWorkflow.match(
      /gh attestation verify "oci:\/\/\$\{cloud_image_uri\}"/gu
    )?.length,
    2
  );
  assert.equal(
    supplyChainWorkflow.match(/aws ecr get-login-password/gu)?.length,
    2
  );
  assert.match(
    supplyChainWorkflow,
    /deploymentAttestationReverified:true/u
  );
  assert.match(
    supplyChainWorkflow,
    /cloudRuntimeAttestationReverified:true/u
  );
});

test("stable projection can exclude only observedAt", () => {
  assert.match(validatorSource, /delete projection\.observedAt;/u);
  assert.equal(
    validatorSource.match(/delete projection\./gu)?.length,
    1
  );
  assert.doesNotMatch(
    validatorSource,
    /delete projection\.(?:releaseSha|runtime|schemaVersion|security|stage|topology)/u
  );
  assert.match(
    supplyChainWorkflow,
    /validate-lean-production-evidence\.mjs stable/gu
  );
});

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, member]) => [key, canonicalValue(member)])
    );
  }
  return value;
}

function canonical(value: unknown): string {
  return `${JSON.stringify(canonicalValue(value))}\n`;
}

function invoke(...args: string[]) {
  return spawnSync(process.execPath, [validatorPath, ...args], {
    encoding: "utf8",
  });
}

test("lean evidence validator is fail-closed and timestamp-stable", () => {
  const directory = mkdtempSync(join(tmpdir(), "archon-lean-contract-"));
  try {
    const releaseSha = "a".repeat(40);
    const cloudImageDigest = `sha256:${"6".repeat(64)}`;
    const promotion = {
      webArtifactDigest: `sha256:${"1".repeat(64)}`,
      lambdaArtifactDigest: `sha256:${"2".repeat(64)}`,
      cloudRuntimeReleaseDigest: `sha256:${"3".repeat(64)}`,
      coreCapabilityDigest: `sha256:${"4".repeat(64)}`,
      coreImageManifestDigest: `sha256:${"5".repeat(64)}`,
    };
    const observation = {
      schemaVersion: "archon.lean-runtime-observation/v1",
      stage: "production",
      releaseSha,
      observedAt: "2026-08-02T09:00:00Z",
      topology: {
        coreIdle: true,
        legacyAlwaysOnRuntimeAbsent: true,
        stackFingerprintSha256: "7".repeat(64),
      },
      runtime: {
        cloudImageDigest,
        functions: 6,
        imageFunctions: 3,
        sessionTables: 2,
        privateVersionedBuckets: 2,
      },
      security: {
        noLambdaVpcAttachments: true,
        wafOnApiAndCognito: true,
        cloudFrontOac: true,
        encryptedState: true,
        pointInTimeRecovery: true,
        alarmRouteBound: true,
        rawIdentifiersProjected: false,
      },
    };
    const rawObservation = `${JSON.stringify(observation, null, 2)}\n`;
    const evidence = {
      schemaVersion: "archon.aws-deployment-evidence/v2",
      stage: "production",
      releaseSha,
      ciRunId: 101,
      deploymentRunId: 202,
      applicationUrl: "https://demo.example.com",
      promotion: {
        policy: "build-once-promote-exact-artifacts",
        ...promotion,
      },
      verification: {
        result: "passed",
        zeroIdleCore: true,
        httpBoundary: true,
        securityHeaders: true,
        directApiRejected: true,
        canonicalHostEnforced: true,
        observationSha256: createHash("sha256")
          .update(rawObservation)
          .digest("hex"),
      },
      secretsProjected: false,
      generatedAt: "2026-08-02T09:00:01Z",
    };
    const expectations = {
      stage: "production",
      releaseSha,
      ciRunId: 101,
      deploymentRunId: 202,
      ...promotion,
      cloudImageDigest,
    };
    const evidencePath = join(directory, "evidence.json");
    const observationPath = join(directory, "observation.json");
    const expectationsPath = join(directory, "expectations.json");
    const canonicalEvidence = join(directory, "canonical-evidence.json");
    const canonicalObservation = join(directory, "canonical-observation.json");
    writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
    writeFileSync(observationPath, rawObservation);
    writeFileSync(expectationsPath, canonical(expectations));

    const valid = invoke(
      "pair",
      evidencePath,
      observationPath,
      expectationsPath,
      canonicalEvidence,
      canonicalObservation
    );
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(readFileSync(canonicalEvidence, "utf8"), canonical(evidence));
    assert.equal(
      readFileSync(canonicalObservation, "utf8"),
      canonical(observation)
    );

    const firstProjection = join(directory, "first-projection.json");
    assert.equal(
      invoke("stable", canonicalObservation, firstProjection).status,
      0
    );
    const later = { ...observation, observedAt: "2026-08-02T09:05:00Z" };
    const laterRaw = join(directory, "later.json");
    const laterCanonical = join(directory, "later-canonical.json");
    const laterProjection = join(directory, "later-projection.json");
    writeFileSync(laterRaw, `${JSON.stringify(later)}\n`);
    assert.equal(
      invoke(
        "observation",
        laterRaw,
        expectationsPath,
        laterCanonical
      ).status,
      0
    );
    assert.equal(
      invoke("stable", laterCanonical, laterProjection).status,
      0
    );
    assert.equal(
      readFileSync(firstProjection, "utf8"),
      readFileSync(laterProjection, "utf8")
    );

    const drifted = join(directory, "drifted.json");
    writeFileSync(
      drifted,
      `${JSON.stringify({
        ...later,
        runtime: {
          ...later.runtime,
          cloudImageDigest: `sha256:${"8".repeat(64)}`,
        },
      })}\n`
    );
    assert.notEqual(
      invoke(
        "observation",
        drifted,
        expectationsPath,
        join(directory, "drifted-output.json")
      ).status,
      0
    );

    const extra = join(directory, "extra.json");
    writeFileSync(extra, `${JSON.stringify({ ...later, hidden: true })}\n`);
    assert.notEqual(
      invoke(
        "observation",
        extra,
        expectationsPath,
        join(directory, "extra-output.json")
      ).status,
      0
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
