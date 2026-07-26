#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for submission project access."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "submission-project-access.yml"
)

EXPECTED_INPUTS = (
    "release_sha",
    "deployment_run_id",
    "availability_run_id",
    "provision_run_id",
    "rotate_run_id",
    "deactivate_run_id",
    "reactivate_run_id",
    "judge_journey_run_id",
)
EXPECTED_JOBS = ("produce", "attest")
EXPECTED_PRODUCE_STEPS = (
    "Bind dispatch to the exact current release",
    "Check out the exact unprivileged producer",
    "Resolve exact immutable prerequisite artifacts",
    "Download exact deployment evidence",
    "Download exact availability evidence",
    "Download exact provision evidence",
    "Download exact rotate evidence",
    "Download exact deactivate evidence",
    "Download exact reactivate evidence",
    "Download exact fresh judge journey",
    "Verify every upstream inventory and full attested subject set",
    "Reconstruct and validate exact upstream semantic bindings",
    "Probe public application and repository without credentials",
    "Assemble exact registered SQ3 SQ4 and SQ5 subjects",
    "Recheck public runtime bytes without credentials",
    "Recheck canonical source state before retention",
    "Retain exact standard project-access subjects",
)
EXPECTED_ATTEST_STEPS = (
    "Bind attester to the exact current workflow run",
    "Check out the exact unprivileged attester",
    "Verify attester control plane before repository validation",
    "Resolve one immutable project-access producer artifact",
    "Download the exact immutable project-access artifact",
    "Independently validate exact standard-v1 bytes and semantics",
    "Reverify all exact upstream attestations from retained facts",
    "Independently repeat credentialless public access probes",
    "Recheck cross-source semantics and canonical state before attestation",
    "Attest all fifteen exact project-access subjects",
)
EXPECTED_FILES = (
    "SHA256SUMS",
    "attestation-predicate.json",
    "proofs/SQ3.json",
    "proofs/SQ4.json",
    "proofs/SQ5.json",
    "support/SQ3/availability-verification.json",
    "support/SQ3/deployment-verification.json",
    "support/SQ3/public-probe.json",
    "support/SQ4/credential-rotation-recovery.json",
    "support/SQ4/deployment-verification.json",
    "support/SQ4/fresh-identity-lifecycle.json",
    "support/SQ4/fresh-judge-journey.json",
    "support/SQ4/testing-instructions.json",
    "support/SQ5/license-detection.json",
    "support/SQ5/logged-out-repository-probe.json",
    "support/SQ5/release-tree-inventory.json",
)
PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-project-access/v1"
)
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact": (
        "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
    ),
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    ),
    "actions/attest": "59d89421af93a897026c735860bf21b6eb4f7b26",
}
EXPECTED_ACTION_COUNTS = {
    "actions/checkout": 2,
    "actions/download-artifact": 8,
    "actions/upload-artifact": 1,
    "actions/attest": 1,
}


class ContractError(AssertionError):
    """Raised when a workflow trust-boundary contract is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def job_sections(workflow: str) -> dict[str, str]:
    marker = "\njobs:\n"
    require(workflow.count(marker) == 1, "workflow must define one jobs map")
    body = workflow.split(marker, maxsplit=1)[1]
    matches = list(
        re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", body)
    )
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(body)
        )
        sections[match.group(1)] = body[match.start() : end]
    return sections


def job_steps(job: str) -> tuple[tuple[str, str], ...]:
    boundaries = list(re.finditer(r"(?m)^      -[^\n]*\n", job))
    require(boundaries, "job must contain at least one step")
    steps: list[tuple[str, str]] = []
    for index, boundary in enumerate(boundaries):
        header = boundary.group(0)
        require(
            header.startswith("      - name: "),
            f"every job step must be named: {header.strip()}",
        )
        name = header.removeprefix("      - name: ").removesuffix("\n")
        require(
            bool(name) and name.strip() == name,
            "job step name must be one non-empty canonical scalar",
        )
        end = (
            boundaries[index + 1].start()
            if index + 1 < len(boundaries)
            else len(job)
        )
        steps.append((name, job[boundary.start() : end]))
    return tuple(steps)


def named_step(job: str, name: str) -> str:
    matches = tuple(
        section
        for step_name, section in job_steps(job)
        if step_name == name
    )
    require(len(matches) == 1, f"step is missing or duplicated: {name}")
    return matches[0]


def step_names(job: str) -> tuple[str, ...]:
    return tuple(name for name, _ in job_steps(job))


def permission_map(job: str, label: str) -> dict[str, str]:
    marker = "    permissions:\n"
    require(job.count(marker) == 1, f"{label} must have one permissions map")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following is not None else len(job)
    entries = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$",
        job[start:end],
    )
    require(entries, f"{label} permissions map is empty")
    require(
        len(entries) == len(dict(entries)),
        f"{label} permissions contain a duplicate capability",
    )
    return dict(entries)


def dispatch_inputs(workflow: str) -> dict[str, str]:
    start_marker = "\n  workflow_dispatch:\n"
    end_marker = "\npermissions: {}\n"
    require(
        workflow.count(start_marker) == 1
        and workflow.count(end_marker) == 1,
        "dispatch or deny-by-default boundary changed",
    )
    body = workflow.split(start_marker, maxsplit=1)[1].split(
        end_marker, maxsplit=1
    )[0]
    matches = list(
        re.finditer(r"(?m)^      ([a-z][a-z0-9_]*):\n", body)
    )
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(body)
        )
        blocks[match.group(1)] = body[match.start() : end]
    return blocks


def attester_inventory(step: str) -> tuple[str, ...]:
    start_marker = "          expected_files = sorted(\n              [\n"
    end_marker = "\n              ]\n          )"
    require(
        step.count(start_marker) == 1,
        "attester must define one literal standard-v1 inventory",
    )
    body = step.split(start_marker, maxsplit=1)[1]
    require(end_marker in body, "attester inventory is unterminated")
    body = body.split(end_marker, maxsplit=1)[0]
    values = re.findall(r'(?m)^\s+"([^"]+)",$', body)
    require(
        len(values) == len(body.splitlines()),
        "attester inventory contains a non-literal entry",
    )
    return tuple(values)


def lifecycle_last_four_block(step: str, label: str) -> str:
    start_marker = "] as $production |\n"
    end_marker = "all($production[]; .id <= $reactivate)"
    require(
        step.count(start_marker) == 1 and step.count(end_marker) == 1,
        f"{label} must define one exact lifecycle-tail boundary",
    )
    return step.split(start_marker, maxsplit=1)[1].split(
        end_marker, maxsplit=1
    )[0]


def require_tokens(
    text: str,
    label: str,
    tokens: tuple[str, ...],
) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def validate_workflow(workflow: str) -> None:
    require("\t" not in workflow, "workflow must not contain tabs")
    require(
        workflow.startswith("name: Submission project access\n"),
        "workflow identity changed",
    )
    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch must expose exactly eight ordered scalar identifiers",
    )
    for name, block in inputs.items():
        require(
            block.count("        required: true\n") == 1
            and block.count("        type: string\n") == 1,
            f"{name} must remain one required scalar string",
        )
    require(
        set(
            re.findall(
                r"\$\{\{\s*inputs\.([a-z][a-z0-9_]*)\s*\}\}",
                workflow,
            )
        )
        == set(EXPECTED_INPUTS),
        "workflow references an undeclared or unused dispatch input",
    )
    for forbidden in (
        "url",
        "origin",
        "stage",
        "json",
        "credential",
        "secret",
        "password",
        "username",
        "account",
    ):
        require(
            all(forbidden not in name for name in inputs),
            f"dispatch accepted a {forbidden}-bearing input",
        )
    require(
        "fromJSON(inputs." not in workflow
        and "fromJson(inputs." not in workflow
        and "github.event.inputs" not in workflow,
        "dispatch identifiers must not become structured payloads",
    )
    require(
        "\npermissions: {}\n" in workflow,
        "top-level permissions must remain deny-by-default",
    )
    require(
        "\nconcurrency:\n"
        "  group: archon-judge-user-production\n"
        "  cancel-in-progress: false\n" in workflow,
        "workflow must share the production judge-user serialization lock",
    )
    require(
        workflow.count(f"  PREDICATE_TYPE: {PREDICATE_TYPE}\n") == 1,
        "predicate type must have one canonical definition",
    )
    require(
        re.search(r"(?m)^\s+environment:", workflow) is None,
        "project-access workflow must not bind a protected environment",
    )
    require(
        "${{ secrets." not in workflow
        and "${{ vars." not in workflow,
        "project-access workflow must not consume secrets or protected vars",
    )

    jobs = job_sections(workflow)
    require(
        tuple(jobs) == EXPECTED_JOBS,
        "workflow must contain exactly produce and attest jobs",
    )
    produce = jobs["produce"]
    attest = jobs["attest"]
    require(
        step_names(produce) == EXPECTED_PRODUCE_STEPS,
        "producer steps or their exact order changed",
    )
    require(
        step_names(attest) == EXPECTED_ATTEST_STEPS,
        "attester steps or their exact order changed",
    )
    require(
        permission_map(produce, "producer")
        == {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "producer permissions are not exact read-only capabilities",
    )
    require(
        permission_map(attest, "attester")
        == {
            "actions": "read",
            "attestations": "write",
            "contents": "read",
            "id-token": "write",
        },
        "attester permissions are not exact isolated write capabilities",
    )
    require(
        workflow.count("attestations: write") == 1
        and workflow.count("id-token: write") == 1,
        "attestation write authority escaped the isolated job",
    )
    require(
        "${{ needs.produce.outputs." not in attest,
        "attester must not trust producer outputs for artifact discovery",
    )

    resolver = named_step(
        produce, "Resolve exact immutable prerequisite artifacts"
    )
    require_tokens(
        resolver,
        "centralized upstream artifact resolver",
        (
            "scripts/validate-submission-proof-receipts.py",
            "select-run-artifact",
            '--policy "${selection_policy}"',
            '--artifact-prefix "${artifact_prefix}"',
            '--run-id "${run_id}"',
            '--release-sha "${RELEASE_SHA}"',
            '--maximum-attempt "${current_attempt}"',
            ".workflow_run.id == $runId",
            ".workflow_run.head_sha == $release",
            "/actions/artifacts/${artifact_id}",
            ".run_attempt",
            ".status == \"completed\"",
            ".conclusion == \"success\"",
        ),
    )
    require(
        resolver.count("exact-current") == 1,
        "deployment must use exact-current artifact policy",
    )
    require(
        resolver.count("single-retained") == 4,
        "all four lifecycle operations must use single-retained policy",
    )
    require(
        resolver.count("latest-retained") == 2,
        "availability and journey must use latest-retained policy",
    )
    upstream_downloads = (
        (
            "Download exact deployment evidence",
            "deployment_artifact_id",
            "deployment_run_id",
        ),
        (
            "Download exact availability evidence",
            "availability_artifact_id",
            "availability_run_id",
        ),
        (
            "Download exact provision evidence",
            "provision_artifact_id",
            "provision_run_id",
        ),
        (
            "Download exact rotate evidence",
            "rotate_artifact_id",
            "rotate_run_id",
        ),
        (
            "Download exact deactivate evidence",
            "deactivate_artifact_id",
            "deactivate_run_id",
        ),
        (
            "Download exact reactivate evidence",
            "reactivate_artifact_id",
            "reactivate_run_id",
        ),
        (
            "Download exact fresh judge journey",
            "journey_artifact_id",
            "judge_journey_run_id",
        ),
    )
    for step_name, artifact_output, run_input in upstream_downloads:
        download = named_step(produce, step_name)
        require_tokens(
            download,
            f"cross-run artifact download {step_name}",
            (
                "actions/download-artifact@",
                f"artifact-ids: "
                f"${{{{ steps.sources.outputs.{artifact_output} }}}}",
                f"run-id: ${{{{ inputs.{run_input} }}}}",
                "github-token: ${{ github.token }}",
            ),
        )
    require_tokens(
        resolver,
        "current production source boundary",
        (
            "all($deployments[]; .id <= $selected)",
            ')" = "${AVAILABILITY_RUN_ID}"',
            'all($production[]; .id <= $reactivate)',
            'all($journeys[]; .id <= $selected)',
            "[-4:]",
            '{id: $provision, operation: "provision"}',
            '{id: $reactivate, operation: "reactivate"}',
            "bash scripts/verify-github-control-plane.sh",
        ),
    )

    producer_verify = named_step(
        produce,
        "Verify every upstream inventory and full attested subject set",
    )
    require_tokens(
        producer_verify,
        "producer full-subject attestation verification",
        (
            "availability-subject.sha256",
            "judge-user-operation-subject.sha256",
            "journey-subject.sha256",
            "sha256sum --check --strict",
            'gh attestation verify "${subject}"',
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref refs/heads/master",
            "--predicate-type",
            "--deny-self-hosted-runners",
            ") == $expectedSubjects",
            "unique_by(.statement)",
            "exactly one attestation must bind the full subject set",
        ),
    )
    require(
        producer_verify.count("verify_subject_set \\") == 4
        and "for operation in provision rotate deactivate reactivate"
        in producer_verify,
        "producer must verify all seven upstream subject sets",
    )

    semantic_bindings = named_step(
        produce,
        "Reconstruct and validate exact upstream semantic bindings",
    )
    require_tokens(
        semantic_bindings,
        "producer live-runtime and availability bindings",
        (
            "live-runtime-manifest.json",
            '"liveRuntimeManifestSha256"',
            '!= sha(live_manifest_path).removeprefix("sha256:")',
            '"archon.live-runtime-manifest/v1"',
            '"containerImageDigest"',
            '"productionEcrImageDigest"',
            '"spaArtifactSha256"',
            '"webArchiveSha256"',
            'live_manifest["verification"].get("result") != "passed"',
            'live_manifest.get("spa", {}).get("objects")',
            '"publicBytesMatchLiveManifest"',
            "availability_observed = instant(",
            "availability_observed > now + dt.timedelta(minutes=5)",
            "now - availability_observed > dt.timedelta(hours=7)",
        ),
    )

    public_steps = (
        named_step(
            produce,
            "Probe public application and repository without credentials",
        ),
        named_step(
            produce,
            "Recheck public runtime bytes without credentials",
        ),
        named_step(
            attest,
            "Independently repeat credentialless public access probes",
        ),
    )
    for index, public_step in enumerate(public_steps):
        require(
            "test -z \"${GH_TOKEN:-}\"" in public_step,
            f"public probe {index} must prove GH_TOKEN absence",
        )
        require(
            "GH_TOKEN:" not in public_step
            and "github.token" not in public_step
            and "Authorization:" not in public_step,
            f"public probe {index} gained credential material",
        )
        require_tokens(
            public_step,
            f"credentialless public probe {index}",
            (
                "--proto '=https'",
                "--tlsv1.2",
                "--max-redirs 0",
                "'%{http_code}",
                "%{num_redirects}",
                "%{url_effective}",
                "%{ssl_verify_result}",
            ),
        )
    for public_label, public_step in (
        ("producer public manifest proof", public_steps[0]),
        ("attester public manifest proof", public_steps[2]),
    ):
        require_tokens(
            public_step,
            public_label,
            (
                "live-runtime-manifest.json",
                ".production.liveRuntimeManifestSha256",
                '.schemaVersion == "archon.live-runtime-manifest/v1"',
                ".releaseBinding.releaseSha == $release",
                '.verification.result == "passed"',
                '(.spa.objects | type) == "array"',
                (
                    "(keys | sort) == [\n"
                    '                  "key",\n'
                    '                  "sha256",\n'
                    '                  "size",\n'
                    '                  "versionId"\n'
                    "                ]"
                ),
                '(.versionId | type) == "string"',
                "(.versionId | length) >= 1",
                "(.versionId | length) <= 1024",
                '(.sha256 | test("^[0-9a-f]{64}$"))',
                ".size == (.size | floor)",
                "[.spa.objects[].key] as $keys",
                'select(.key == "index.html")',
                "sha256: $indexSha256",
                "size: $indexSize",
                'select(.key == "runtime-config.json")',
                "sha256: $runtimeSha256",
                "size: $runtimeSize",
            ),
        )
    require_tokens(
        public_steps[0],
        "producer public project proof",
        (
            "${application_url}/runtime-config.json",
            "https://github.com/upgradedev/archon-datahub",
            "/tree/${RELEASE_SHA}",
            "/blob/${RELEASE_SHA}/LICENSE",
            "https://api.github.com/repos/upgradedev/archon-datahub/license?ref=${RELEASE_SHA}",
            "https://codeload.github.com/upgradedev/archon-datahub/tar.gz/${RELEASE_SHA}",
            "set(archived) != tracked",
            "local.read_bytes() != data",
            '"spdx_id"',
            '"Apache-2.0"',
            "credentialMaterialUsed",
        ),
    )
    require(
        workflow.count("set(archived) != tracked") == 2,
        "producer and attester must compare the complete public source tree",
    )
    require(
        workflow.count(
            "submission-project-access-upstream/deployment/"
            "production-runtime-config.json"
        )
        >= 2
        and "submission-project-access-upstream-attester/deployment/"
        "source/production-runtime-config.json" in attest,
        "public runtime bytes must be compared in both trust domains",
    )

    package = named_step(
        produce, "Assemble exact registered SQ3 SQ4 and SQ5 subjects"
    )
    require_tokens(
        package,
        "standard-v1 source assembler",
        (
            "SQ3.json",
            "SQ4.json",
            "SQ5.json",
            "assemble-standard",
            "--source-key project-access",
            '--facts-dir "${facts}"',
            '--output-dir "${output}"',
            '--run-id "${GITHUB_RUN_ID}"',
            '--run-attempt "${GITHUB_RUN_ATTEMPT}"',
            "--notice NOTICE.md",
            ".subjectCount == 15",
            '.proofIds == ["SQ3", "SQ4", "SQ5"]',
            "pipeline-managed-confirmed",
            "2026-08-31T21:00:00Z",
            '"Apache-2.0"',
            "secretMaterialRetained",
        ),
    )
    for relative in EXPECTED_FILES:
        require(
            relative in package,
            f"producer package omitted {relative}",
        )
    require(
        'artifact_name=submission-project-access-${RELEASE_SHA}-'
        '${GITHUB_RUN_ATTEMPT}' in package,
        "producer artifact name lost producing-attempt binding",
    )
    upload = named_step(
        produce, "Retain exact standard project-access subjects"
    )
    require_tokens(
        upload,
        "exact artifact retention",
        (
            "actions/upload-artifact@",
            "name: ${{ steps.package.outputs.artifact_name }}",
            "path: ${{ runner.temp }}/submission-project-access-evidence",
            "if-no-files-found: error",
            "include-hidden-files: false",
            "compression-level: 0",
            "retention-days: 90",
        ),
    )
    require(
        "submission-project-access-upstream" not in upload,
        "raw upstream evidence must not enter the standard artifact",
    )

    attester_bind = named_step(
        attest,
        "Bind attester to the exact current workflow run",
    )
    require_tokens(
        attester_bind,
        "shell-only attester trust binding",
        (
            "GITHUB_WORKFLOW_REF",
            'test "${GITHUB_REF}" = "refs/heads/master"',
            'test "${GITHUB_SHA}" = "${RELEASE_SHA}"',
            "/actions/runs/${GITHUB_RUN_ID}",
            ".run_attempt == $runAttempt",
            ".head_sha == $release",
            "/git/ref/heads/master",
            'test "${current_release}" = "${RELEASE_SHA}"',
        ),
    )
    require(
        "scripts/" not in attester_bind
        and "uses:" not in attester_bind,
        "attester trust binding must remain shell-only before checkout",
    )
    attester_checkout = named_step(
        attest,
        "Check out the exact unprivileged attester",
    )
    attester_preflight = named_step(
        attest,
        "Verify attester control plane before repository validation",
    )
    attester_resolver = named_step(
        attest,
        "Resolve one immutable project-access producer artifact",
    )
    require(
        attest.index(attester_bind)
        < attest.index(attester_checkout)
        < attest.index(attester_preflight)
        < attest.index(attester_resolver),
        "attester must bind, check out, and verify controls before selection",
    )
    require_tokens(
        attester_resolver,
        "attester-only retry resolver",
        (
            "/actions/runs/${GITHUB_RUN_ID}/artifacts?per_page=100",
            'artifact_prefix="submission-project-access-'
            '${RELEASE_SHA}-"',
            "select-run-artifact",
            "--policy latest-retained",
            '--run-id "${GITHUB_RUN_ID}"',
            '--maximum-attempt "${GITHUB_RUN_ATTEMPT}"',
            "/actions/artifacts/${artifact_id}",
            ".workflow_run.id == $runId",
            ".workflow_run.head_sha == $release",
        ),
    )
    require_tokens(
        attester_checkout,
        "exact unprivileged attester checkout",
        (
            "actions/checkout@",
            "ref: ${{ inputs.release_sha }}",
            "fetch-depth: 1",
            "persist-credentials: false",
        ),
    )
    require_tokens(
        attester_preflight,
        "pre-repository-code attester control-plane gate",
        (
            "GH_TOKEN: ${{ github.token }}",
            'test "$(git rev-parse HEAD)" = "${RELEASE_SHA}"',
            "git diff --quiet",
            "git diff --cached --quiet",
            "git ls-files --others --exclude-standard",
            "bash scripts/verify-github-control-plane.sh",
        ),
    )
    require(
        "artifact-ids: ${{ steps.artifact.outputs.artifact_id }}"
        in attest,
        "attester must download only its independently selected artifact ID",
    )

    standard_validation = named_step(
        attest,
        "Independently validate exact standard-v1 bytes and semantics",
    )
    require(
        attester_inventory(standard_validation) == EXPECTED_FILES,
        "attester exact 16-file standard-v1 inventory changed",
    )
    require_tokens(
        standard_validation,
        "independent standard source validation",
        (
            "validate-standard-source",
            "--source-key project-access",
            '--run-id "${GITHUB_RUN_ID}"',
            '--run-attempt "${PRODUCER_ATTEMPT}"',
            "sha256sum --check --strict SHA256SUMS",
            "any(path.is_symlink() for path in entries)",
            ')\" = \"15\"',
            ".subjectCount == 15",
            '.proofIds == ["SQ3", "SQ4", "SQ5"]',
        ),
    )

    upstream_reverify = named_step(
        attest,
        "Reverify all exact upstream attestations from retained facts",
    )
    require_tokens(
        upstream_reverify,
        "attester upstream independence",
        (
            "/actions/artifacts/${artifact_id}/zip",
            'test "sha256:$(',
            "zipfile.ZipFile",
            "sha256sum --check --strict SHA256SUMS",
            "sha256sum --check --strict \"${subject_inventory}\"",
            'gh attestation verify "${subject_path}"',
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref refs/heads/master",
            "--predicate-type",
            "--deny-self-hosted-runners",
            ") == $expectedSubjects",
            "unique_by(.verificationResult.statement)",
            "length == 1",
        ),
    )
    require(
        workflow.count("gh attestation verify") == 2,
        "producer and attester must each contain a full-set verifier",
    )

    final_recheck = named_step(
        attest,
        "Recheck cross-source semantics and canonical state before attestation",
    )
    require_tokens(
        final_recheck,
        "pre-attestation canonical recheck",
        (
            "/actions/artifacts/${PROJECT_ACCESS_ARTIFACT_ID}",
            ".workflow_run.id == $runId",
            ".workflow_run.head_sha == $release",
            "bash scripts/verify-github-control-plane.sh",
            "all($deployments[]; .id <= $selected)",
            ')" = "${AVAILABILITY_RUN_ID}"',
            "all($production[]; .id <= $reactivate)",
            "all($journeys[]; .id <= $selected)",
            "journey_deployment != sq3[\"deployment\"]",
            "journey_lifecycle != sq4[\"judgeUserLifecycle\"]",
        ),
    )
    require_tokens(
        final_recheck,
        "pre-attestation live-runtime and availability bindings",
        (
            "live-runtime-manifest.json",
            '"liveRuntimeManifestSha256"',
            '!= sha(live_manifest_path).removeprefix("sha256:")',
            '"archon.live-runtime-manifest/v1"',
            '"containerImageDigest"',
            '"productionEcrImageDigest"',
            '"spaArtifactSha256"',
            '"webArchiveSha256"',
            'live_manifest.get("verification", {}).get("result")',
            'live_manifest.get("spa", {}).get("objects")',
            "availability_observed = instant(",
            "availability_observed > now + dt.timedelta(minutes=5)",
            "now - availability_observed > dt.timedelta(hours=7)",
        ),
    )
    require_tokens(
        final_recheck,
        "late attester upstream reselection",
        (
            "sources.ndjson",
            "current-attempts.ndjson",
            "[.[].key] == [",
            "[.[].runId] == [",
            "all(.[]; .runAttempt == .producerAttempt)",
            "missing or ambiguous observed current run attempt",
            "reselected_count=0",
            'selection_policy="exact-current"',
            'selection_policy="latest-retained"',
            'selection_policy="single-retained"',
            "select-run-artifact",
            '--policy "${selection_policy}"',
            '--artifact-prefix "${artifact_prefix}"',
            '--run-id "${run_id}"',
            '--release-sha "${RELEASE_SHA}"',
            '--maximum-attempt "${current_attempt}"',
            ".run_attempt == $observedAttempt",
            ".producerAttempt == $producerAttempt",
            ".metadata.id == $artifactId",
            ".metadata.name == $name",
            ".metadata.digest == $digest",
            ".metadata.workflow_run.id == $runId",
            ".metadata.workflow_run.head_sha == $release",
            ".run_attempt == $currentAttempt",
            'test "${reselected_count}" = "7"',
            "/actions/artifacts/${PROJECT_ACCESS_ARTIFACT_ID}",
            "bash scripts/verify-github-control-plane.sh",
            'test "${current_release}" = "${RELEASE_SHA}"',
            'test "$(git rev-parse HEAD)" = "${RELEASE_SHA}"',
        ),
    )
    require(
        final_recheck.count('selection_policy="exact-current"') == 1
        and final_recheck.count('selection_policy="latest-retained"') == 2
        and final_recheck.count('selection_policy="single-retained"') == 1,
        "late attester reselection policy map changed",
    )
    producer_recheck = named_step(
        produce,
        "Recheck canonical source state before retention",
    )
    require_tokens(
        producer_recheck,
        "late producer upstream reselection",
        (
            "sources.ndjson",
            "reselected_count=0",
            'selection_policy="exact-current"',
            'selection_policy="latest-retained"',
            'selection_policy="single-retained"',
            "select-run-artifact",
            '--policy "${selection_policy}"',
            '--artifact-prefix "${artifact_prefix}"',
            '--run-id "${run_id}"',
            '--release-sha "${RELEASE_SHA}"',
            '--maximum-attempt "${current_attempt}"',
            ".run_attempt == $initialAttempt",
            ".producerAttempt == $producerAttempt",
            ".metadata.id == $artifactId",
            ".metadata.name == $name",
            ".metadata.digest == $digest",
            ".metadata.workflow_run.id == $runId",
            ".metadata.workflow_run.head_sha == $release",
            ".run_attempt == $currentAttempt",
            'test "${reselected_count}" = "7"',
            "bash scripts/verify-github-control-plane.sh",
            'test "${current_release}" = "${RELEASE_SHA}"',
            'test "$(git rev-parse HEAD)" = "${RELEASE_SHA}"',
        ),
    )
    require(
        producer_recheck.count('selection_policy="exact-current"') == 1
        and producer_recheck.count(
            'selection_policy="latest-retained"'
        )
        == 2
        and producer_recheck.count(
            'selection_policy="single-retained"'
        )
        == 1,
        "late producer reselection policy map changed",
    )
    require(
        produce.index(package)
        < produce.index(public_steps[1])
        < produce.index(producer_recheck)
        < produce.index(upload),
        "producer must public-recheck before its final canonical gate and upload",
    )
    source_key_order = (
        "              [.[].key] == [\n"
        '                "deployment",\n'
        '                "availability",\n'
        '                "provision",\n'
        '                "rotate",\n'
        '                "deactivate",\n'
        '                "reactivate",\n'
        '                "journey"\n'
        "              ]"
    )
    source_run_id_order = (
        "              [.[].runId] == [\n"
        "                $deployment,\n"
        "                $availability,\n"
        "                $provision,\n"
        "                $rotate,\n"
        "                $deactivate,\n"
        "                $reactivate,\n"
        "                $journey\n"
        "              ]"
    )
    for reselection_label, reselection_step in (
        ("late producer reselection", producer_recheck),
        ("late attester reselection", final_recheck),
    ):
        require(
            reselection_step.count(source_key_order) == 1
            and reselection_step.count(source_run_id_order) == 1,
            f"{reselection_label} lost the exact seven-source ordering",
        )
    for lifecycle_label, lifecycle_step in (
        ("initial producer resolver", resolver),
        ("producer retention recheck", producer_recheck),
        ("attester final recheck", final_recheck),
    ):
        require(
            lifecycle_step.count(
                "all($deployments[]; .id <= $selected)"
            )
            == 1,
            f"{lifecycle_label} lost the no-newer-deployment run gate",
        )
        lifecycle_block = lifecycle_last_four_block(
            lifecycle_step,
            lifecycle_label,
        )
        require(
            "select(" not in lifecycle_block,
            f"{lifecycle_label} must inspect the last four total lifecycle runs",
        )
        require(
            lifecycle_block.count("status: .status") == 1
            and lifecycle_block.count("conclusion: .conclusion") == 1
            and lifecycle_block.count('status: "completed"') == 4
            and lifecycle_block.count('conclusion: "success"') == 4
            and lifecycle_block.count("sort_by(.id)") == 1
            and lifecycle_block.count(".[-4:]") == 1,
            f"{lifecycle_label} lost exact completed/success last-four-total binding",
        )
    attestation = named_step(
        attest, "Attest all fifteen exact project-access subjects"
    )
    require(
        attest.index(public_steps[2])
        < attest.index(final_recheck)
        < attest.index(attestation),
        "credentialless proof must precede the final canonical attestation gate",
    )
    require_tokens(
        attestation,
        "custom project-access attestation",
        (
            "actions/attest@",
            "subject-checksums: "
            "${{ runner.temp }}/submission-project-access-attestation/"
            "SHA256SUMS",
            "predicate-type: ${{ env.PREDICATE_TYPE }}",
            "predicate-path: "
            "${{ runner.temp }}/submission-project-access-attestation/"
            "attestation-predicate.json",
        ),
    )

    action_references = re.findall(
        r"(?m)^        uses: "
        r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
        workflow,
    )
    all_uses = re.findall(r"(?m)^        uses: ([^\s#]+)", workflow)
    require(
        action_references and len(action_references) == len(all_uses),
        "workflow contains a non-registry or unversioned action",
    )
    action_counts: dict[str, int] = {}
    for action, reference in action_references:
        require(
            re.fullmatch(r"[0-9a-f]{40}", reference) is not None,
            f"{action} is not commit-SHA pinned",
        )
        require(
            action in ACTION_PINS and reference == ACTION_PINS[action],
            f"unexpected action identity or pin: {action}@{reference}",
        )
        action_counts[action] = action_counts.get(action, 0) + 1
    require(
        action_counts == EXPECTED_ACTION_COUNTS,
        "workflow action identity/count multiset changed",
    )


def replace_exact(
    workflow: str,
    old: str,
    new: str,
    *,
    count: int = 1,
) -> str:
    require(
        workflow.count(old) == count,
        f"tamper fixture expected {count} copies of {old!r}",
    )
    return workflow.replace(old, new)


def replace_in_step(
    workflow: str,
    job_name: str,
    step_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    step = named_step(jobs[job_name], step_name)
    require(
        step.count(old) == 1,
        f"tamper step expected one copy of {old!r}",
    )
    return workflow.replace(step, step.replace(old, new, 1), 1)


def swap_adjacent_steps(
    workflow: str,
    job_name: str,
    first_name: str,
    second_name: str,
) -> str:
    jobs = job_sections(workflow)
    job = jobs[job_name]
    first = named_step(job, first_name)
    second = named_step(job, second_name)
    adjacent = first + second
    require(
        job.count(adjacent) == 1,
        f"tamper steps are not adjacent: {first_name}, {second_name}",
    )
    return workflow.replace(adjacent, second + first, 1)


def expect_rejected(label: str, workflow: str) -> None:
    try:
        validate_workflow(workflow)
    except ContractError:
        return
    raise AssertionError(f"workflow contract accepted tamper: {label}")


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
validate_workflow(workflow_text)

tamper_cases = {
    "arbitrary URL input": replace_exact(
        workflow_text,
        "      deployment_run_id:\n",
        (
            "      application_url:\n"
            "        description: Unsafe application URL\n"
            "        required: true\n"
            "        type: string\n"
            "      deployment_run_id:\n"
        ),
    ),
    "top permissions widened": replace_exact(
        workflow_text,
        "\npermissions: {}\n",
        "\npermissions:\n  contents: read\n",
    ),
    "serialization lock changed": replace_exact(
        workflow_text,
        "  group: archon-judge-user-production\n",
        "  group: submission-project-access\n",
    ),
    "producer write authority": replace_in_step(
        workflow_text,
        "produce",
        "Bind dispatch to the exact current release",
        "        env:\n",
        "        environment: production\n        env:\n",
    ),
    "secret consumption": replace_in_step(
        workflow_text,
        "produce",
        "Probe public application and repository without credentials",
        "          RELEASE_SHA: ${{ inputs.release_sha }}\n",
        (
            "          RELEASE_SHA: ${{ inputs.release_sha }}\n"
            "          UNSAFE: ${{ secrets.JUDGE_PASSWORD }}\n"
        ),
    ),
    "anonymous run step": replace_exact(
        workflow_text,
        "      - name: Bind dispatch to the exact current release\n",
        (
            "      - run: echo unexpected-anonymous-step\n"
            "\n"
            "      - name: Bind dispatch to the exact current release\n"
        ),
    ),
    "extra pinned action step": replace_exact(
        workflow_text,
        "      - name: Bind dispatch to the exact current release\n",
        (
            "      - uses: actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1\n"
            "\n"
            "      - name: Bind dispatch to the exact current release\n"
        ),
    ),
    "pinned action multiset changed": replace_in_step(
        workflow_text,
        "produce",
        "Retain exact standard project-access subjects",
        (
            "actions/upload-artifact@"
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        ),
        (
            "actions/checkout@"
            "3d3c42e5aac5ba805825da76410c181273ba90b1"
        ),
    ),
    "deployment retry policy weakened": replace_in_step(
        workflow_text,
        "produce",
        "Resolve exact immutable prerequisite artifacts",
        "            exact-current\n",
        "            latest-retained\n",
    ),
    "lifecycle rerun accepted": replace_exact(
        workflow_text,
        "            single-retained \\\n",
        "            latest-retained \\\n",
        count=4,
    ),
    "lifecycle tail filters failures before last four": replace_in_step(
        workflow_text,
        "produce",
        "Resolve exact immutable prerequisite artifacts",
        "                  $production[] |\n                  {\n",
        (
            "                  $production[] |\n"
            "                  select(\n"
            "                    .status == \"completed\" and\n"
            "                    .conclusion == \"success\"\n"
            "                  ) |\n"
            "                  {\n"
        ),
    ),
    "lifecycle tail drops observed status": replace_in_step(
        workflow_text,
        "produce",
        "Resolve exact immutable prerequisite artifacts",
        "                    status: .status,\n",
        "",
    ),
    "lifecycle tail accepts non-success provision": replace_in_step(
        workflow_text,
        "produce",
        "Resolve exact immutable prerequisite artifacts",
        (
            '                  operation: "provision",\n'
            '                  status: "completed",\n'
            '                  conclusion: "success"\n'
        ),
        (
            '                  operation: "provision",\n'
            '                  status: "completed",\n'
            '                  conclusion: "failure"\n'
        ),
    ),
    "central selector removed": replace_in_step(
        workflow_text,
        "produce",
        "Resolve exact immutable prerequisite artifacts",
        "                select-run-artifact \\\n",
        "                validate-registry \\\n",
    ),
    "cross-run download loses run binding": replace_in_step(
        workflow_text,
        "produce",
        "Download exact deployment evidence",
        "          run-id: ${{ inputs.deployment_run_id }}\n",
        "          run-id: ${{ github.run_id }}\n",
    ),
    "full subject set weakened": replace_in_step(
        workflow_text,
        "produce",
        "Verify every upstream inventory and full attested subject set",
        "                      ) == $expectedSubjects and\n",
        "                      ) != [] and\n",
    ),
    "duplicate producer statements become ambiguous": replace_in_step(
        workflow_text,
        "produce",
        "Verify every upstream inventory and full attested subject set",
        "                  unique_by(.statement) |\n",
        "",
    ),
    "public redirects accepted": workflow_text.replace(
        "--max-redirs 0",
        "--max-redirs 1",
    ),
    "public probe receives token": replace_in_step(
        workflow_text,
        "attest",
        "Independently repeat credentialless public access probes",
        "          RELEASE_SHA: ${{ inputs.release_sha }}\n",
        (
            "          GH_TOKEN: ${{ github.token }}\n"
            "          RELEASE_SHA: ${{ inputs.release_sha }}\n"
        ),
    ),
    "source completeness removed": replace_exact(
        workflow_text,
        "          if set(archived) != tracked:\n",
        "          if False:\n",
        count=2,
    ),
    "producer live manifest digest detached": replace_in_step(
        workflow_text,
        "produce",
        "Reconstruct and validate exact upstream semantic bindings",
        (
            '              != sha(live_manifest_path).removeprefix("sha256:")\n'
        ),
        (
            "              != deployment_evidence[\"production\"].get(\n"
            '                  "liveRuntimeManifestSha256"\n'
            "              )\n"
        ),
    ),
    "producer availability freshness widened": replace_in_step(
        workflow_text,
        "produce",
        "Reconstruct and validate exact upstream semantic bindings",
        "              or now - availability_observed > dt.timedelta(hours=7)\n",
        "              or now - availability_observed > dt.timedelta(hours=24)\n",
    ),
    "producer public manifest byte binding weakened": replace_in_step(
        workflow_text,
        "produce",
        "Probe public application and repository without credentials",
        "                    sha256: $runtimeSha256,\n",
        "                    sha256: .sha256,\n",
    ),
    "producer public manifest accepts empty version ID": replace_in_step(
        workflow_text,
        "produce",
        "Probe public application and repository without credentials",
        "                (.versionId | length) >= 1 and\n",
        "                (.versionId | length) >= 0 and\n",
    ),
    "package subject count weakened": replace_exact(
        workflow_text,
        "              .subjectCount == 15 and\n",
        "              .subjectCount >= 1 and\n",
        count=2,
    ),
    "artifact includes upstream": replace_in_step(
        workflow_text,
        "produce",
        "Retain exact standard project-access subjects",
        (
            "          path: "
            "${{ runner.temp }}/submission-project-access-evidence\n"
        ),
        (
            "          path: |\n"
            "            ${{ runner.temp }}/submission-project-access-evidence\n"
            "            ${{ runner.temp }}/submission-project-access-upstream\n"
        ),
    ),
    "late producer selector removed": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        "                select-run-artifact \\\n",
        "                validate-registry \\\n",
    ),
    "late producer lifecycle policy weakened": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        '                selection_policy="single-retained"\n',
        '                selection_policy="latest-retained"\n',
    ),
    "late producer retained artifact identity weakened": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        "                .metadata.id == $artifactId and\n",
        "                .metadata.id > 0 and\n",
    ),
    "late producer run-after binding weakened": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        "                .run_attempt == $currentAttempt and\n",
        "                .run_attempt >= $currentAttempt and\n",
    ),
    "late producer source count weakened": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        '          test "${reselected_count}" = "7"\n',
        '          test "${reselected_count}" -gt "0"\n',
    ),
    "late producer source ordering changed": replace_in_step(
        workflow_text,
        "produce",
        "Recheck canonical source state before retention",
        (
            '                "reactivate",\n'
            '                "journey"\n'
            "              ] and\n"
            "              [.[].runId] == [\n"
        ),
        (
            '                "reactivate",\n'
            '                "availability"\n'
            "              ] and\n"
            "              [.[].runId] == [\n"
        ),
    ),
    "producer public recheck moved after canonical gate": swap_adjacent_steps(
        workflow_text,
        "produce",
        "Recheck public runtime bytes without credentials",
        "Recheck canonical source state before retention",
    ),
    "attester trusts producer output": replace_in_step(
        workflow_text,
        "attest",
        "Download the exact immutable project-access artifact",
        "artifact-ids: ${{ steps.artifact.outputs.artifact_id }}",
        "artifact-ids: ${{ needs.produce.outputs.artifact_id }}",
    ),
    "attester checkout before trust binding": swap_adjacent_steps(
        workflow_text,
        "attest",
        "Bind attester to the exact current workflow run",
        "Check out the exact unprivileged attester",
    ),
    "attester preflight loses API token": replace_in_step(
        workflow_text,
        "attest",
        "Verify attester control plane before repository validation",
        "          GH_TOKEN: ${{ github.token }}\n",
        "",
    ),
    "attester retry policy exact": replace_in_step(
        workflow_text,
        "attest",
        "Resolve one immutable project-access producer artifact",
        "              --policy latest-retained \\\n",
        "              --policy exact-current \\\n",
    ),
    "attester source reverify removed": replace_in_step(
        workflow_text,
        "attest",
        "Reverify all exact upstream attestations from retained facts",
        '              --deny-self-hosted-runners \\\n',
        "",
    ),
    "duplicate attester statements become ambiguous": replace_in_step(
        workflow_text,
        "attest",
        "Reverify all exact upstream attestations from retained facts",
        "                  unique_by(.verificationResult.statement) |\n",
        "",
    ),
    "attester public manifest byte binding weakened": replace_in_step(
        workflow_text,
        "attest",
        "Independently repeat credentialless public access probes",
        "                    sha256: $runtimeSha256,\n",
        "                    sha256: .sha256,\n",
    ),
    "attester public manifest accepts empty version ID": replace_in_step(
        workflow_text,
        "attest",
        "Independently repeat credentialless public access probes",
        "                (.versionId | length) >= 1 and\n",
        "                (.versionId | length) >= 0 and\n",
    ),
    "public probe after final canonical gate": swap_adjacent_steps(
        workflow_text,
        "attest",
        "Independently repeat credentialless public access probes",
        "Recheck cross-source semantics and canonical state before attestation",
    ),
    "final lifecycle race accepted": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "              all($production[]; .id <= $reactivate)\n",
        "              all($production[]; true)\n",
    ),
    "final deployment race accepted": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "              all($deployments[]; .id <= $selected)\n",
        "              all($deployments[]; true)\n",
    ),
    "final live manifest digest detached": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        (
            '              != sha(live_manifest_path).removeprefix("sha256:")\n'
        ),
        (
            "              != deployment.get(\"production\", {}).get(\n"
            '                  "liveRuntimeManifestSha256"\n'
            "              )\n"
        ),
    ),
    "final availability freshness widened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "              or now - availability_observed > dt.timedelta(hours=7)\n",
        "              or now - availability_observed > dt.timedelta(hours=24)\n",
    ),
    "final retained attempts no longer match producer": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "              all(.[]; .runAttempt == .producerAttempt)\n",
        "              all(.[]; true)\n",
    ),
    "final observed attempt binding weakened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "                .run_attempt == $observedAttempt and\n",
        "                .run_attempt >= $observedAttempt and\n",
    ),
    "final lifecycle retry policy weakened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        '                selection_policy="single-retained"\n',
        '                selection_policy="latest-retained"\n',
    ),
    "final upstream selector removed": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "                select-run-artifact \\\n",
        "                validate-registry \\\n",
    ),
    "final retained artifact identity weakened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "                .metadata.id == $artifactId and\n",
        "                .metadata.id > 0 and\n",
    ),
    "final run-after attempt binding weakened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        "                .run_attempt == $currentAttempt and\n",
        "                .run_attempt >= $currentAttempt and\n",
    ),
    "final upstream source count weakened": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        '          test "${reselected_count}" = "7"\n',
        '          test "${reselected_count}" -gt "0"\n',
    ),
    "final upstream source ordering changed": replace_in_step(
        workflow_text,
        "attest",
        "Recheck cross-source semantics and canonical state before attestation",
        (
            '                "reactivate",\n'
            '                "journey"\n'
            "              ] and\n"
            "              [.[].runId] == [\n"
        ),
        (
            '                "reactivate",\n'
            '                "availability"\n'
            "              ] and\n"
            "              [.[].runId] == [\n"
        ),
    ),
    "wrong attestation inventory": replace_in_step(
        workflow_text,
        "attest",
        "Attest all fifteen exact project-access subjects",
        "SHA256SUMS",
        "attestation-predicate.json",
    ),
    "predicate type changed": workflow_text.replace(
        PREDICATE_TYPE,
        "https://example.invalid/project-access/v1",
    ),
    "floating attest action": replace_exact(
        workflow_text,
        (
            "actions/attest@"
            "59d89421af93a897026c735860bf21b6eb4f7b26"
        ),
        "actions/attest@v4",
    ),
}
for tamper_label, tampered in tamper_cases.items():
    expect_rejected(tamper_label, tampered)

print(
    json.dumps(
        {
            "schemaVersion":
                "archon.submission-project-access-contract-test/v1",
            "artifactFiles": list(EXPECTED_FILES),
            "dispatchInputs": list(EXPECTED_INPUTS),
            "tamperCases": sorted(tamper_cases),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
