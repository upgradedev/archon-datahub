import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const workflow = readFileSync(
  resolve(__dirname, "../../../.github/workflows/deploy.yml"),
  "utf8"
);
const liveProofWorkflow = readFileSync(
  resolve(__dirname, "../../../.github/workflows/live-datahub-proof.yml"),
  "utf8"
);
const controlPlaneVerifier = readFileSync(
  resolve(__dirname, "../../../scripts/verify-github-control-plane.sh"),
  "utf8"
);

describe("deployment workflow release-subject binding", () => {
  test("requires the latest exact control-plane run to be completed successfully", () => {
    const gateStart = workflow.indexOf("workflow_success() {");
    const gateEnd = workflow.indexOf(
      'control_plane_gate_file="${RUNNER_TEMP}/control-plane-security-gates.json"'
    );
    expect(gateStart).toBeGreaterThanOrEqual(0);
    expect(gateEnd).toBeGreaterThan(gateStart);

    const gate = workflow.slice(gateStart, gateEnd);
    expect(gate).not.toContain("-f status=success");
    expect(gate).toContain("sort_by(.id, .run_attempt)");
    expect(gate).toContain('.status == "completed"');
    expect(gate).toContain('.conclusion == "success"');
  });

  test("applies the same latest-run rule to the privileged live proof", () => {
    expect(liveProofWorkflow).not.toContain("-f status=completed");
    expect(liveProofWorkflow).not.toContain("-f status=success");
    expect(liveProofWorkflow).toContain("sort_by(.id, .run_attempt)");
    expect(liveProofWorkflow).toContain('.status == "completed"');
    expect(liveProofWorkflow).toContain('.conclusion == "success"');
    expect(liveProofWorkflow).toContain(
      "/git/ref/heads/${default_branch}"
    );
    expect(
      liveProofWorkflow.match(
        /bash scripts\/verify-github-control-plane\.sh/gu
      )
    ).toHaveLength(4);
    const preSecretGate = liveProofWorkflow.indexOf(
      "Revalidate exact control plane immediately before DataHub secrets"
    );
    const liveProof = liveProofWorkflow.indexOf(
      "Prove one-dataset MCP, retention, provenance, and contradiction path"
    );
    const postProofGate = liveProofWorkflow.indexOf(
      "Revalidate and bind the exact control plane after live proof"
    );
    const proofEvidence = liveProofWorkflow.indexOf(
      "Prepare digest-bound proof evidence"
    );
    const preAttestationGate = liveProofWorkflow.indexOf(
      "Revalidate exact control plane immediately before proof attestation"
    );
    const proofAttestation = liveProofWorkflow.indexOf(
      "Attest exact live proof evidence"
    );
    for (const boundary of [
      preSecretGate,
      liveProof,
      postProofGate,
      proofEvidence,
      preAttestationGate,
      proofAttestation
    ]) {
      expect(boundary).toBeGreaterThanOrEqual(0);
    }
    expect(preSecretGate).toBeLessThan(liveProof);
    expect(liveProof).toBeLessThan(postProofGate);
    expect(postProofGate).toBeLessThan(proofEvidence);
    expect(proofEvidence).toBeLessThan(preAttestationGate);
    expect(preAttestationGate).toBeLessThan(proofAttestation);
    expect(liveProofWorkflow).toContain(
      "The enriched live-proof receipt differs from the enforced exact gate"
    );
    expect(liveProofWorkflow).toContain(
      "The signed live-proof gate subject is no longer current"
    );
    expect(liveProofWorkflow).toContain(
      "The signed exact and enriched live-proof receipts differ"
    );
    expect(liveProofWorkflow).toContain(
      "control-plane-security-gates.json"
    );
    expect(liveProofWorkflow).toContain(
      "controlPlaneSecurityGatesSha256"
    );
  });

  test("revalidates the current branch and latest gates at every AWS trust boundary", () => {
    expect(controlPlaneVerifier).toContain(
      "/git/ref/heads/${default_branch}"
    );
    expect(controlPlaneVerifier).not.toContain("-f status=completed");
    expect(controlPlaneVerifier).not.toContain("-f status=success");
    expect(controlPlaneVerifier).toContain(
      "sort_by(.id, .run_attempt)"
    );
    expect(controlPlaneVerifier).toContain(
      '.status == "completed"'
    );
    expect(controlPlaneVerifier).toContain(
      '.conclusion == "success"'
    );

    const verifierCalls =
      workflow.match(
        /bash scripts\/verify-github-control-plane\.sh/gu
      ) ?? [];
    expect(verifierCalls).toHaveLength(6);
    expect(workflow.indexOf("before staging AWS trust")).toBeLessThan(
      workflow.indexOf("Configure staging AWS credentials through OIDC")
    );
    expect(workflow.indexOf("before staging mutation")).toBeLessThan(
      workflow.indexOf(
        "Deploy edge, registry, verified image, and staging platform"
      )
    );
    expect(
      workflow.indexOf("after production approval")
    ).toBeLessThan(
      workflow.indexOf("Configure production AWS credentials through OIDC")
    );
    expect(workflow.indexOf("before production AWS trust")).toBeLessThan(
      workflow.indexOf("Configure production AWS credentials through OIDC")
    );
    expect(workflow.indexOf("before production mutation")).toBeLessThan(
      workflow.indexOf(
        "Deploy edge, registry, identical image, and production platform"
      )
    );
    expect(
      workflow.indexOf("Bind exact live production runtime bytes")
    ).toBeLessThan(
      workflow.indexOf(
        "Revalidate exact control plane before sealing promotion evidence"
      )
    );
    expect(
      workflow.indexOf(
        "Revalidate exact control plane before sealing promotion evidence"
      )
    ).toBeLessThan(workflow.indexOf("Emit promotion evidence"));
    expect(workflow).toContain(
      "EXPECTED_GATE_SHA256: ${{ steps.production_control_plane.outputs.control_plane_gate_sha }}"
    );
    expect(workflow).toContain(
      '"${evidence_dir}/control-plane-security-gates.json"'
    );
  });

  test("passes the same exact CI and deployment subjects on every platform reconciliation", () => {
    const platformDeployments =
      workflow.match(
        /--parameters "\$\{(?:stack_name|STACK_NAME)\}:ImageDigest=[\s\S]+?--outputs-file "\$\{(?:stack_outputs|STACK_OUTPUTS)\}"/gu
      ) ?? [];

    expect(platformDeployments).toHaveLength(4);
    for (const deployment of platformDeployments) {
      expect(deployment).toContain(
        ":ContainerArchiveSha256=${CONTAINER_ARCHIVE_SHA}"
      );
      expect(deployment).toContain(
        ":LambdaArchiveSha256=${LAMBDA_ARCHIVE_SHA}"
      );
      expect(deployment).toContain(
        ":DeploymentWorkflowRunId=${GITHUB_RUN_ID}"
      );
      expect(deployment).toContain(
        ":DeploymentWorkflowRunAttempt=${GITHUB_RUN_ATTEMPT}"
      );
      expect(deployment).toContain(":CiRunId=${CI_RUN_ID}");
      expect(deployment).toContain(
        ":SpaArtifactSha256=${SPA_ARTIFACT_SHA}"
      );
      expect(deployment).toContain(":ReleaseSha=${RELEASE_SHA}");
    }
  });
});
