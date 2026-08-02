from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/datahub-cloud-runtime-image.yml"
LOCK = ROOT / ".github/locks/datahub-cloud-runtime-image.json"
DOCKERFILE = ROOT / "services/datahub-cloud-runtime/Dockerfile"


def test_cloud_runtime_pipeline_is_ci_only_and_sha_pinned():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "pull_request_target:" not in workflow
    assert "secrets." not in workflow
    required = {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
        "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
        "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25",
        "github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81",
    }
    observed = set(re.findall(r"uses:\s+([^\s#]+)", workflow))
    assert observed == required


def test_publish_authority_is_isolated_after_all_candidate_gates():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    candidate = workflow.index("\n  candidate:")
    publish = workflow.index("\n  publish:")
    assert candidate < publish
    candidate_block = workflow[candidate:publish]
    publish_block = workflow[publish:]
    assert "id-token: write" not in candidate_block
    assert "configure-aws-credentials" not in candidate_block
    assert "environment: production" in publish_block
    assert "needs: candidate" in publish_block
    for gate in (
        "Run all runtime and negative security tests inside the image",
        "Dependency SCA against the exact lock",
        "Trivy scan of the exact production image",
        "Generate exact CycloneDX SBOM",
        "Generate exact SPDX SBOM",
        "Enforce scan and SBOM gates",
    ):
        assert gate in candidate_block


def test_release_contract_is_digest_only_and_attested():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "archon.datahub-cloud-runtime-release/v1" in workflow
    assert "datahub-cloud-runtime-release-${{ env.SOURCE_SHA }}" in workflow
    assert "imageDigest" in workflow
    assert "actions/attest@" in workflow
    assert "subject-checksums:" in workflow
    assert "sbom-path:" in workflow
    assert "retention-days: 90" in workflow
    assert "imageTagMutability" in workflow
    assert "archon-datahub-cloud-runtime-v2" in workflow
    assert "aws ecr create-repository" in workflow
    assert "--image-tag-mutability IMMUTABLE" in workflow
    assert "--image-scanning-configuration scanOnPush=true" in workflow
    assert "--encryption-configuration encryptionType=KMS" in workflow
    assert "cloud-v2-$SOURCE_SHA" in workflow


def test_cleanup_is_prefix_scoped_bounded_and_runner_material_is_removed():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert 'startswith("cloud-v2-")' in workflow
    assert ".[20:70]" in workflow
    assert "][0:50][]" in workflow
    assert "7 days ago" in workflow
    assert 'rm -rf "$RUNNER_TEMP/candidate"' in workflow
    assert 'rm -rf "$RUNNER_TEMP/datahub-skills"' in workflow


def test_dockerfile_is_exact_lambda_amd64_input_without_secret_values():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert (
        "public.ecr.aws/lambda/python:3.12@sha256:"
        "182ce4c13bce31bc9fcff9a2705f2f946b59e2d32e10cdf7700883d8a59c25da"
    ) in dockerfile
    assert (
        "ghcr.io/astral-sh/uv@sha256:"
        "ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437"
    ) in dockerfile
    assert "services/datahub-companion/demo/archon_demo.sql" in dockerfile
    assert 'CMD ["handlers.read_handler"]' in dockerfile
    for name in (
        "DATAHUB_GMS_TOKEN=",
        "AWS_ACCESS_KEY_ID=",
        "AWS_SECRET_ACCESS_KEY=",
        "AWS_SESSION_TOKEN=",
    ):
        assert name not in dockerfile
