#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for the optional SQ9 producer."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "submission-judge-pack.yml"
)
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
EXPECTED_INPUTS = ("release_sha", "ci_run_id")
EXPECTED_JOBS = ("produce", "attest")
EXPECTED_PRODUCE_STEPS = (
    "Bind dispatch to the exact current release and CI run",
    "Check out the exact unprivileged producer",
    "Resolve the exact successful CI attempt and immutable artifacts",
    "Download and safely extract the exact upstream archives",
    "Verify the judge pack and signed CI release predicate",
    "Assemble the exact registered SQ9 subjects",
    "Recheck upstream identity and canonical release before retention",
    "Retain the exact standard judge-pack subjects",
)
EXPECTED_ATTEST_STEPS = (
    "Bind attester to the exact current release and workflow run",
    "Check out the exact unprivileged attester",
    "Independently resolve producer and upstream artifact identities",
    "Download the exact immutable producer artifact",
    "Independently download and safely extract upstream archives",
    "Independently validate standard bytes and upstream semantics",
    "Recheck all immutable identities before attestation",
    "Attest all four exact judge-pack subjects",
)
EXPECTED_STANDARD_FILES = (
    "SHA256SUMS",
    "attestation-predicate.json",
    "proofs/SQ9.json",
    "support/SQ9/ci-attestation.json",
    "support/SQ9/judge-pack-manifest.json",
)
EXPECTED_JUDGE_FILES = (
    "README.md",
    "SHA256SUMS",
    "audit/report.json",
    "audit/report.md",
    "audit/report.sarif",
    "control/approval-decision.json",
    "control/approval-request.json",
    "control/evidence-dossier.json",
    "control/execution-receipt.json",
    "control/remediation-plan.json",
    "control/rollback-proposal.json",
    "manifest.json",
)
PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-judge-pack/v1"
)
CI_PREDICATE_TYPE = (
    "https://github.com/upgradedev/archon-datahub/"
    "attestations/ci-release/v1"
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
    "actions/download-artifact": 1,
    "actions/upload-artifact": 1,
    "actions/attest": 1,
}
EXPECTED_CI_UPLOAD_COUNT = 16


class ContractError(AssertionError):
    """Raised when a workflow trust boundary is absent."""


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
    marker = "    steps:\n"
    require(job.count(marker) == 1, "job must define one steps list")
    steps_body = job.split(marker, maxsplit=1)[1]
    boundaries = list(re.finditer(r"(?m)^      -[^\n]*\n", steps_body))
    require(boundaries, "job must contain steps")
    steps: list[tuple[str, str]] = []
    for index, boundary in enumerate(boundaries):
        header = boundary.group(0)
        require(
            header.startswith("      - name: "),
            f"every workflow step must be named: {header.strip()}",
        )
        name = header.removeprefix("      - name: ").removesuffix("\n")
        end = (
            boundaries[index + 1].start()
            if index + 1 < len(boundaries)
            else len(steps_body)
        )
        steps.append((name, steps_body[boundary.start() : end]))
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
    require(job.count(marker) == 1, f"{label} must have one permission map")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following is not None else len(job)
    entries = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$",
        job[start:end],
    )
    require(
        len(entries) == len(dict(entries)) and bool(entries),
        f"{label} permissions are empty or duplicated",
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


def require_tokens(text: str, label: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def step_sections(workflow: str) -> tuple[str, ...]:
    boundaries = list(re.finditer(r"(?m)^      -[^\n]*\n", workflow))
    sections: list[str] = []
    for index, boundary in enumerate(boundaries):
        end = (
            boundaries[index + 1].start()
            if index + 1 < len(boundaries)
            else len(workflow)
        )
        sections.append(workflow[boundary.start() : end])
    return tuple(sections)


def validate_ci_retry_contract(ci_workflow: str) -> None:
    jobs = job_sections(ci_workflow)
    require(
        {"benchmark", "judge-evidence", "contrib", "mcp-dependency",
         "container", "attest-release"} <= set(jobs),
        "CI lost a predicate-bound producer or attester job",
    )
    uploads = tuple(
        section
        for section in step_sections(ci_workflow)
        if "uses: actions/upload-artifact@" in section
    )
    require(
        len(uploads) == EXPECTED_CI_UPLOAD_COUNT,
        "CI upload-artifact inventory changed",
    )
    for index, upload in enumerate(uploads):
        require(
            upload.count("          overwrite: true\n") == 1,
            f"CI upload {index + 1} is not retry-safe",
        )
        reference = re.search(
            r"uses: actions/upload-artifact@([0-9a-f]{40})",
            upload,
        )
        require(reference is not None, f"CI upload {index + 1} is not pinned")

    judge = jobs["judge-evidence"]
    container = jobs["container"]
    attester = jobs["attest-release"]
    require_tokens(
        judge,
        "attempt-scoped CI judge artifact",
        (
            "artifact_id: ${{ steps.evidence.outputs['artifact-id'] }}",
            "artifact_name: judge-evidence-${{ github.sha }}-"
            "${{ github.run_attempt }}",
            "artifact_digest: sha256:"
            "${{ steps.evidence.outputs['artifact-digest'] }}",
            "producer_attempt: ${{ github.run_attempt }}",
            "name: judge-evidence-${{ github.sha }}-"
            "${{ github.run_attempt }}",
        ),
    )
    require(
        judge.count(
            "      artifact_name: judge-evidence-${{ github.sha }}-"
            "${{ github.run_attempt }}\n"
        )
        == 1
        and judge.count(
            "          name: judge-evidence-${{ github.sha }}-"
            "${{ github.run_attempt }}\n"
        )
        == 1,
        "CI judge artifact output and upload names must remain exact",
    )
    require_tokens(
        container,
        "stable retry-safe CI container artifact",
        (
            "artifact_id: ${{ steps.candidate.outputs['artifact-id'] }}",
            "artifact_name: container-${{ github.sha }}",
            "artifact_digest: sha256:"
            "${{ steps.candidate.outputs['artifact-digest'] }}",
            "producer_attempt: ${{ github.run_attempt }}",
            "id: candidate",
            "name: container-${{ github.sha }}",
            "overwrite: true",
        ),
    )
    require(
        container.count(
            "      artifact_name: container-${{ github.sha }}\n"
        )
        == 1
        and container.count(
            "          name: container-${{ github.sha }}\n"
        )
        == 1,
        "CI container artifact output and upload must remain an exact stable alias",
    )
    require_tokens(
        ci_workflow,
        "normalized predicate-bound CI digests",
        (
            "artifact_digest: sha256:"
            "${{ steps.evidence.outputs['artifact-digest'] }}",
            "validation_receipt_digest: sha256:"
            "${{ steps.evidence.outputs['artifact-digest'] }}",
        ),
    )
    require(
        ci_workflow.count(
            "artifact_digest: sha256:"
            "${{ steps.evidence.outputs['artifact-digest'] }}"
        )
        == 3,
        "benchmark, judge, and MCP digests must each be normalized once",
    )
    require_tokens(
        attester,
        "current-attempt exact CI predicate binding",
        (
            "artifact-ids: ${{ needs.container.outputs.artifact_id }}",
            "CI_RUN_ATTEMPT: ${{ github.run_attempt }}",
            "CONTAINER_ARTIFACT_ID: "
            "${{ needs.container.outputs.artifact_id }}",
            "JUDGE_EVIDENCE_ARTIFACT_ID: "
            "${{ needs.judge-evidence.outputs.artifact_id }}",
            "runAttempt: $runAttempt",
            "releaseArtifacts: {",
            "judgeEvidence: {",
            "id: $judgeEvidenceArtifactId",
            "name: $judgeEvidenceArtifactName",
            "digest: $judgeEvidenceArtifactDigest",
            "producerAttempt: $judgeEvidenceProducerAttempt",
            "container: {",
            "id: $containerArtifactId",
            "name: $containerArtifactName",
            "digest: $containerArtifactDigest",
            "producerAttempt: $containerProducerAttempt",
            ".releaseArtifacts.judgeEvidence.digest ==",
            ".capabilityEvidence.judgeEvidenceArtifactDigest",
            ".releaseArtifacts.container.name ==",
            '("container-" + .source.commit)',
        ),
    )
    require(
        "name: container-${{ github.sha }}" not in named_step(
            attester,
            "Download exact container candidate",
        ),
        "CI attester must download the exact container artifact ID",
    )


def validate_workflow(workflow: str) -> None:
    require("\t" not in workflow, "workflow must not contain tabs")
    require(
        workflow.startswith("name: Submission judge pack\n"),
        "workflow identity changed",
    )
    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch must expose exactly two ordered scalar identifiers",
    )
    for name, block in inputs.items():
        require(
            block.count("        required: true\n") == 1
            and block.count("        type: string\n") == 1,
            f"{name} must remain a required scalar string",
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
        "artifact",
        "predicate",
        "json",
        "secret",
        "credential",
        "stage",
    ):
        require(
            all(forbidden not in name for name in inputs),
            f"dispatch accepted a {forbidden}-bearing input",
        )
    require(
        "fromJSON(inputs." not in workflow
        and "fromJson(inputs." not in workflow
        and "github.event.inputs" not in workflow,
        "dispatch values must never become structured payloads",
    )
    require(
        "${{ secrets." not in workflow
        and "${{ vars." not in workflow
        and re.search(r"(?m)^\s+environment:", workflow) is None,
        "judge-pack producer must not consume protected configuration",
    )
    require(
        "\npermissions: {}\n" in workflow,
        "top-level permissions must remain deny-by-default",
    )
    require(
        "\nconcurrency:\n"
        "  group: submission-judge-pack-${{ inputs.release_sha }}\n"
        "  cancel-in-progress: false\n" in workflow,
        "release-scoped non-cancelling serialization changed",
    )
    require(
        workflow.count(f"  PREDICATE_TYPE: {PREDICATE_TYPE}\n") == 1
        and workflow.count(
            f"  CI_PREDICATE_TYPE: {CI_PREDICATE_TYPE}\n"
        )
        == 1,
        "predicate definitions changed",
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
        "producer steps or order changed",
    )
    require(
        step_names(attest) == EXPECTED_ATTEST_STEPS,
        "attester steps or order changed",
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
        "attester permissions are not exact isolated capabilities",
    )
    require(
        workflow.count("attestations: write") == 1
        and workflow.count("id-token: write") == 1,
        "attestation authority escaped the isolated attester",
    )
    require(
        "${{ needs.produce.outputs." not in attest,
        "attester must independently discover the producer artifact",
    )

    producer_resolver = named_step(
        produce,
        "Resolve the exact successful CI attempt and immutable artifacts",
    )
    attester_resolver = named_step(
        attest,
        "Independently resolve producer and upstream artifact identities",
    )
    for label, resolver in (
        ("producer upstream resolver", producer_resolver),
        ("attester upstream resolver", attester_resolver),
    ):
        require_tokens(
            resolver,
            label,
            (
                ".path == \".github/workflows/ci.yml\"",
                ".event == \"push\"",
                ".head_sha == $release",
                ".head_branch == \"master\"",
                ".head_repository.full_name == $repository",
                ".repository.full_name == $repository",
                ".status == \"completed\"",
                ".conclusion == \"success\"",
                "(( current_attempt <= 20 ))",
                'for attempt in $(seq 1 "${current_attempt}")',
                "/attempts/${attempt}/jobs?per_page=100",
                ". + {observedRunAttempt: $observedRunAttempt}",
                'latest_successful_job "Reproducible judge evidence"',
                'latest_successful_job "Production container"',
                'current_successful_job "Sign exact CI release candidates"',
                ".observedRunAttempt <= $currentAttempt",
                ".observedRunAttempt == $currentAttempt",
                "map(.observedRunAttempt) | max",
                ".created_at >= $startedAt",
                ".created_at <= $completedAt",
                ".workflow_run.id == $runId",
                ".workflow_run.head_sha == $release",
                ".digest | test(\"^sha256:[0-9a-f]{64}$\")",
                '"judge-evidence-${RELEASE_SHA}-${judge_producer_attempt}"',
                '"container-${RELEASE_SHA}"',
                "producerAttempt: $judgeJob.runAttempt",
                "producerAttempt: $containerJob.runAttempt",
                "sort_by(.id, .run_attempt)",
                ')" = "${CI_RUN_ID}"',
                "bash scripts/verify-github-control-plane.sh",
            ),
        )
        require(
            resolver.count('.event == "push"') == 2,
            f"{label} must bind both selected and latest CI runs to push",
        )
    require_tokens(
        attester_resolver,
        "independent producer resolver",
        (
            "/actions/runs/${GITHUB_RUN_ID}/artifacts?per_page=100",
            "^submission-judge-pack-",
            "select(.producerAttempt <= $currentAttempt)",
            "map(.producerAttempt) | max",
            "if length == 1 then .[0]",
            "latest producer attempt has ambiguous judge-pack artifacts",
            "/attempts/${producer_attempt}/jobs?per_page=100",
            'name == "Produce exact recommended judge-pack evidence"',
        ),
    )
    require(
        "select(.producerAttempt == $currentAttempt)" not in attester_resolver,
        "attester retry must be able to consume the latest retained producer attempt",
    )

    producer_extract = named_step(
        produce,
        "Download and safely extract the exact upstream archives",
    )
    attester_extract = named_step(
        attest,
        "Independently download and safely extract upstream archives",
    )
    for label, extraction in (
        ("producer safe extraction", producer_extract),
        ("attester safe extraction", attester_extract),
    ):
        require(
            extraction.count("python3 - \\") == 2,
            f"{label} must independently extract exactly two archives",
        )
        require(
            extraction.count('or canonical.startswith("../")') == 2,
            f"{label} lost explicit traversal rejection",
        )
        require(
            extraction.count(
                'canonical not in {str(path).replace(os.sep, "/") for path in allowed_dirs}'
            )
            == 2,
            f"{label} must reject every unexpected directory entry",
        )
        require(
            extraction.count("canonical not in expected") == 2,
            f"{label} must reject every unexpected file entry",
        )
        require(
            extraction.count("mode_type not in (0, stat.S_IFDIR)") == 2
            and extraction.count(
                "mode_type not in (0, stat.S_IFREG)"
            )
            == 2,
            f"{label} lost directory/file type rejection",
        )
        require(
            extraction.count("entry.flag_bits & 0x1") == 2
            and extraction.count("if total > limits[kind]") == 2
            and extraction.count('destination.open("xb")') == 2
            and extraction.count("if seen_files != expected") == 2,
            f"{label} lost encrypted/size/exclusive/exact inventory checks",
        )
        require(
            extraction.count('raw.startswith("/")') == 2
            and extraction.count('"\\\\" in raw') == 2
            and extraction.count('"\\x00" in raw') == 2,
            f"{label} lost absolute, backslash, or NUL rejection",
        )
        require(
            extraction.count(
                '"/repos/${GITHUB_REPOSITORY}/actions/artifacts/${id}/zip"'
            )
            == 1
            and extraction.count(
                'test "sha256:$('
            )
            >= 1,
            f"{label} must download exact IDs and verify archive digests",
        )
        for filename in EXPECTED_JUDGE_FILES:
            require(
                extraction.count(f'"{filename}",') == 2,
                f"{label} lost exact judge file {filename}",
            )

    producer_verify = named_step(
        produce,
        "Verify the judge pack and signed CI release predicate",
    )
    attester_verify = named_step(
        attest,
        "Independently validate standard bytes and upstream semantics",
    )
    for label, verification in (
        ("producer upstream verification", producer_verify),
        ("attester upstream verification", attester_verify),
    ):
        require_tokens(
            verification,
            label,
            (
                "sha256sum --check --strict SHA256SUMS",
                '"archon.judge-evidence-pack/v1"',
                '"SYNTHETIC_OFFLINE_FIXTURE"',
                '"liveDataHub": False',
                '"liveMutation": False',
                "judge manifest canonical digest is invalid",
                "judge manifest descriptor digest is invalid",
                'gh attestation verify "',
                "--signer-workflow",
                "--signer-digest",
                "--source-digest",
                "--source-ref refs/heads/master",
                "--predicate-type",
                "--deny-self-hosted-runners",
                "--format json",
                '"archon.ci-release/v1"',
                '"releaseArtifacts"',
                "runAttempt: $runAttempt",
                ".verificationResult.statement.predicate |\n"
                "                    keys | sort",
                '"judgeEvidenceArtifactDigest"',
                "== $judgeDigest",
                "producerAttempt: $judgeProducerAttempt",
                "producerAttempt: $containerProducerAttempt",
                '"archon-image.tar.gz"',
                '"archon-lambdas.tar.gz"',
                '"archon-web.tar.gz"',
                "unique |",
                "if length == 1 then .[0]",
                "exactly one signed CI statement must bind the judge artifact",
                "jq -cS '.predicate'",
            ),
        )
        require(
            verification.count('all(. == "success")') == 1,
            f"{label} must require every exact CI gate to succeed",
        )
    require(
        producer_verify.count("SHA256SUMS") >= 2,
        "producer must bind the exact judge inventory",
    )
    require_tokens(
        producer_verify,
        "producer exact CI artifact identities",
        (
            "releaseArtifacts: {",
            "id: $judgeArtifactId",
            "name: $judgeArtifactName",
            "digest: $judgeDigest",
            "producerAttempt: $judgeProducerAttempt",
            "id: $containerArtifactId",
            "name: $containerArtifactName",
            "digest: $containerArtifactDigest",
            "producerAttempt: $containerProducerAttempt",
        ),
    )
    require_tokens(
        attester_verify,
        "attester exact CI artifact identities",
        (
            ".verificationResult.statement.predicate.releaseArtifacts == {",
            "id: $judgeArtifactId",
            "name: $judgeArtifactName",
            "digest: $judgeDigest",
            "producerAttempt: $judgeProducerAttempt",
            "id: $containerArtifactId",
            "name: $containerArtifactName",
            "digest: $containerArtifactDigest",
            "producerAttempt: $containerProducerAttempt",
        ),
    )

    assembly = named_step(
        produce,
        "Assemble the exact registered SQ9 subjects",
    )
    require_tokens(
        assembly,
        "registered standard-v1 assembly",
        (
            "assemble-standard",
            "validate-standard-source",
            "--source-key judge-pack",
            "--registry scripts/submission-evidence-registry.json",
            "--run-id \"${GITHUB_RUN_ID}\"",
            "--run-attempt \"${GITHUB_RUN_ATTEMPT}\"",
            "--notice NOTICE.md",
            ".subjectCount == 4",
            '.proofIds == ["SQ9"]',
            "proofs/SQ9.json",
            "support/SQ9/ci-attestation.json",
            "support/SQ9/judge-pack-manifest.json",
            "attestation-predicate.json",
            "manifestDigest: $manifestDigest",
            "producerAttempt: $artifactProducerAttempt",
            "sanitized: true",
            "notLiveProof: true",
        ),
    )
    for filename in EXPECTED_STANDARD_FILES:
        require(
            filename in assembly,
            f"standard producer inventory lost {filename}",
        )
    require(
        assembly.count("--source-key judge-pack") == 2,
        "both standard assembly and validation must use judge-pack registry data",
    )
    require(
        assembly.count("cmp --silent") == 1,
        "producer must compare independent standard validations",
    )

    upload = named_step(
        produce,
        "Retain the exact standard judge-pack subjects",
    )
    require_tokens(
        upload,
        "immutable retention",
        (
            "actions/upload-artifact@",
            "name: submission-judge-pack-${{ inputs.release_sha }}-"
            "${{ github.run_attempt }}",
            "path: ${{ runner.temp }}/submission-judge-pack",
            "if-no-files-found: error",
            "retention-days: 90",
        ),
    )
    download = named_step(
        attest,
        "Download the exact immutable producer artifact",
    )
    require_tokens(
        download,
        "independent exact-ID download",
        (
            "actions/download-artifact@",
            "artifact-ids: ${{ steps.artifacts.outputs.artifact_id }}",
            "path: ${{ runner.temp }}/submission-judge-pack-attestation",
            "github-token: ${{ github.token }}",
            "merge-multiple: true",
        ),
    )
    require(
        "${{ needs.produce.outputs." not in download,
        "download must not trust producer outputs",
    )

    require_tokens(
        attester_verify,
        "independent standard and facts validation",
        (
            "validate-standard-source",
            "--source-key judge-pack",
            "--run-attempt \"${PRODUCER_ATTEMPT}\"",
            ".subjectCount == 4",
            ".facts == {",
            "predicateDigest: $predicateDigest",
            "manifestDigest: $manifestDigest",
            "producerAttempt: $artifactProducerAttempt",
            "sanitized: true",
            "notLiveProof: true",
        ),
    )
    for filename in EXPECTED_STANDARD_FILES:
        require(
            filename in attester_verify,
            f"attester inventory lost {filename}",
        )

    producer_recheck = named_step(
        produce,
        "Recheck upstream identity and canonical release before retention",
    )
    attester_recheck = named_step(
        attest,
        "Recheck all immutable identities before attestation",
    )
    for label, recheck in (
        ("producer TOCTOU recheck", producer_recheck),
        ("attester TOCTOU recheck", attester_recheck),
    ):
        require_tokens(
            recheck,
            label,
            (
                "/git/ref/heads/master",
                "/actions/runs/${CI_RUN_ID}",
                ".run_attempt == $attempt",
                ".status == \"completed\"",
                ".conclusion == \"success\"",
                "/actions/artifacts/${artifact_id}",
                ".id == $artifactId",
                ".name == $name",
                ".digest == $digest",
                ".expired == false",
                ".workflow_run.id == $runId",
                ".workflow_run.head_sha == $release",
                "bash scripts/verify-github-control-plane.sh",
                "git diff --quiet",
                "git diff --cached --quiet",
            ),
        )
    require_tokens(
        attester_recheck,
        "retained artifact TOCTOU recheck",
        (
            "/actions/artifacts/${ARTIFACT_ID}",
            "--arg digest \"${ARTIFACT_DIGEST}\"",
            "--arg name \"${ARTIFACT_NAME}\"",
            "--argjson runId \"${GITHUB_RUN_ID}\"",
        ),
    )

    attestation = named_step(
        attest,
        "Attest all four exact judge-pack subjects",
    )
    require_tokens(
        attestation,
        "custom SQ9 attestation",
        (
            "actions/attest@",
            "subject-checksums: "
            "${{ runner.temp }}/submission-judge-pack-attestation/"
            "SHA256SUMS",
            "predicate-type: ${{ env.PREDICATE_TYPE }}",
            "predicate-path: "
            "${{ runner.temp }}/submission-judge-pack-attestation/"
            "attestation-predicate.json",
        ),
    )

    action_references = re.findall(
        r"(?m)^\s+uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
        workflow,
    )
    all_uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", workflow)
    require(
        action_references and len(action_references) == len(all_uses),
        "workflow contains a local, Docker, or unversioned action",
    )
    for action, reference in action_references:
        require(
            re.fullmatch(r"[0-9a-f]{40}", reference) is not None,
            f"{action} is not commit-SHA pinned",
        )
    for action, digest in ACTION_PINS.items():
        require(
            workflow.count(f"{action}@{digest}")
            == EXPECTED_ACTION_COUNTS[action],
            f"{action} pin or cardinality changed",
        )


def replace_exact(
    workflow: str,
    old: str,
    new: str,
    *,
    count: int = 1,
) -> str:
    require(
        workflow.count(old) >= count,
        f"tamper fixture lost marker: {old}",
    )
    return workflow.replace(old, new, count)


def replace_in_job(
    workflow: str,
    job_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    original = jobs[job_name]
    require(old in original, f"tamper marker missing from {job_name}: {old}")
    return workflow.replace(original, original.replace(old, new, 1), 1)


def replace_in_step(
    workflow: str,
    job_name: str,
    step_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    original_job = jobs[job_name]
    original_step = named_step(original_job, step_name)
    require(old in original_step, f"tamper marker missing from {step_name}: {old}")
    mutated_step = original_step.replace(old, new, 1)
    return workflow.replace(
        original_job,
        original_job.replace(original_step, mutated_step, 1),
        1,
    )


def expect_rejected(label: str, workflow: str) -> None:
    try:
        validate_workflow(workflow)
    except ContractError:
        return
    raise AssertionError(f"workflow tamper was accepted: {label}")


def expect_ci_rejected(label: str, workflow: str) -> None:
    try:
        validate_ci_retry_contract(workflow)
    except ContractError:
        return
    raise AssertionError(f"CI retry tamper was accepted: {label}")


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
validate_workflow(workflow_text)
ci_workflow_text = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
validate_ci_retry_contract(ci_workflow_text)

tamper_cases = {
    "add artifact input": replace_exact(
        workflow_text,
        "\npermissions: {}\n",
        (
            "      artifact_id:\n"
            "        description: Caller-selected artifact\n"
            "        required: true\n"
            "        type: string\n"
            "\npermissions: {}\n"
        ),
    ),
    "structured dispatch input": replace_exact(
        workflow_text,
        "        type: string\n",
        "        type: boolean\n",
    ),
    "cancel in progress": replace_exact(
        workflow_text,
        "  cancel-in-progress: false",
        "  cancel-in-progress: true",
    ),
    "producer gains write": replace_in_job(
        workflow_text,
        "produce",
        "      contents: read\n",
        "      contents: write\n",
    ),
    "producer gains a secret": replace_exact(
        workflow_text,
        "name: Submission judge pack\n",
        "name: Submission judge pack\n# ${{ secrets.CI_TOKEN }}\n",
    ),
    "accept pull request CI": replace_exact(
        workflow_text,
        '.event == "push"',
        '.event == "pull_request"',
    ),
    "artifact owner removed": replace_exact(
        workflow_text,
        ".workflow_run.id == $runId",
        "true",
    ),
    "artifact head removed": replace_exact(
        workflow_text,
        ".workflow_run.head_sha == $release",
        "true",
    ),
    "artifact time window widened": replace_exact(
        workflow_text,
        ".created_at >= $startedAt",
        "true",
    ),
    "CI attempt history unbounded": replace_exact(
        workflow_text,
        "(( current_attempt <= 20 ))",
        "(( current_attempt > 0 ))",
    ),
    "oldest CI producer job selected": replace_exact(
        workflow_text,
        "map(.observedRunAttempt) | max",
        "map(.observedRunAttempt) | min",
    ),
    "old attestation job accepted": replace_exact(
        workflow_text,
        ".observedRunAttempt == $currentAttempt",
        ".observedRunAttempt <= $currentAttempt",
    ),
    "archive digest ignored": replace_in_step(
        workflow_text,
        "produce",
        "Download and safely extract the exact upstream archives",
        'test "sha256:$(',
        'test -n "$(',
    ),
    "path traversal accepted": replace_in_step(
        workflow_text,
        "produce",
        "Download and safely extract the exact upstream archives",
        'or canonical.startswith("../")',
        "or False",
    ),
    "unexpected directory accepted": replace_in_step(
        workflow_text,
        "attest",
        "Independently download and safely extract upstream archives",
        (
            'canonical not in {str(path).replace(os.sep, "/") '
            "for path in allowed_dirs}"
        ),
        "False",
    ),
    "unexpected file accepted": replace_in_step(
        workflow_text,
        "produce",
        "Download and safely extract the exact upstream archives",
        "canonical not in expected",
        "False",
    ),
    "symlink type accepted": replace_in_step(
        workflow_text,
        "attest",
        "Independently download and safely extract upstream archives",
        "mode_type not in (0, stat.S_IFREG)",
        "False",
    ),
    "encrypted zip accepted": replace_in_step(
        workflow_text,
        "produce",
        "Download and safely extract the exact upstream archives",
        "entry.flag_bits & 0x1",
        "False",
    ),
    "zip total unbounded": replace_in_step(
        workflow_text,
        "attest",
        "Independently download and safely extract upstream archives",
        "if total > limits[kind]:",
        "if False:",
    ),
    "CI judge digest unbound": replace_exact(
        workflow_text,
        "== $judgeDigest",
        "!= \"\"",
    ),
    "producer judge artifact ID self-referenced": replace_in_step(
        workflow_text,
        "produce",
        "Verify the judge pack and signed CI release predicate",
        "id: $judgeArtifactId",
        (
            "id: .verificationResult.statement.predicate"
            ".releaseArtifacts.judgeEvidence.id"
        ),
    ),
    "attester container producer attempt self-referenced": replace_in_step(
        workflow_text,
        "attest",
        "Independently validate standard bytes and upstream semantics",
        "producerAttempt: $containerProducerAttempt",
        (
            "producerAttempt: .verificationResult.statement.predicate"
            ".releaseArtifacts.container.producerAttempt"
        ),
    ),
    "CI gates not all green": replace_exact(
        workflow_text,
        'all(. == "success")',
        "all(. != null)",
    ),
    "duplicate CI statements accepted": replace_in_step(
        workflow_text,
        "produce",
        "Verify the judge pack and signed CI release predicate",
        "if length == 1 then .[0]",
        "if length >= 1 then .[0]",
    ),
    "manifest claims live": replace_exact(
        workflow_text,
        '"liveDataHub": False',
        '"liveDataHub": True',
    ),
    "standard source key changed": replace_in_step(
        workflow_text,
        "produce",
        "Assemble the exact registered SQ9 subjects",
        "--source-key judge-pack",
        "--source-key operations",
    ),
    "subject count weakened": replace_exact(
        workflow_text,
        ".subjectCount == 4",
        ".subjectCount >= 3",
    ),
    "fixture mislabeled live": replace_exact(
        workflow_text,
        "notLiveProof: true",
        "notLiveProof: false",
    ),
    "retention shortened": replace_exact(
        workflow_text,
        "retention-days: 90",
        "retention-days: 30",
    ),
    "retry attempt equality": replace_in_step(
        workflow_text,
        "attest",
        "Independently resolve producer and upstream artifact identities",
        "select(.producerAttempt <= $currentAttempt)",
        "select(.producerAttempt == $currentAttempt)",
    ),
    "oldest producer selected": replace_in_step(
        workflow_text,
        "attest",
        "Independently resolve producer and upstream artifact identities",
        "map(.producerAttempt) | max",
        "map(.producerAttempt) | min",
    ),
    "floating attestation action": replace_exact(
        workflow_text,
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "actions/attest@v4",
    ),
    "attest wrong subject set": replace_in_step(
        workflow_text,
        "attest",
        "Attest all four exact judge-pack subjects",
        "submission-judge-pack-attestation/SHA256SUMS",
        "submission-judge-pack-attestation/proofs/SQ9.json",
    ),
}
for tamper_label, tampered_workflow in tamper_cases.items():
    expect_rejected(tamper_label, tampered_workflow)

ci_tamper_cases = {
    "CI overwrite disabled": replace_exact(
        ci_workflow_text,
        "          overwrite: true",
        "          overwrite: false",
    ),
    "CI capability digest left bare": replace_exact(
        ci_workflow_text,
        "artifact_digest: sha256:"
        "${{ steps.evidence.outputs['artifact-digest'] }}",
        "artifact_digest: "
        "${{ steps.evidence.outputs['artifact-digest'] }}",
    ),
    "CI judge artifact not attempt scoped": replace_exact(
        ci_workflow_text,
        "artifact_name: judge-evidence-${{ github.sha }}-"
        "${{ github.run_attempt }}",
        "artifact_name: judge-evidence-${{ github.sha }}",
    ),
    "CI container alias made attempt scoped": replace_exact(
        ci_workflow_text,
        "artifact_name: container-${{ github.sha }}",
        "artifact_name: container-${{ github.sha }}-${{ github.run_attempt }}",
    ),
    "CI container selected by mutable name": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Download exact container candidate",
        "artifact-ids: ${{ needs.container.outputs.artifact_id }}",
        "name: container-${{ github.sha }}",
    ),
    "CI signed predicate loses current attempt": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Bind successful CI gates to exact release bytes",
        "runAttempt: $runAttempt",
        "runAttempt: 1",
    ),
    "CI release artifact identities removed": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Bind successful CI gates to exact release bytes",
        "releaseArtifacts: {",
        "unboundReleaseArtifacts: {",
    ),
    "CI judge identity digest detached": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Bind successful CI gates to exact release bytes",
        ".releaseArtifacts.judgeEvidence.digest ==",
        ".releaseArtifacts.judgeEvidence.digest !=",
    ),
    "CI judge identity ID replaced": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Bind successful CI gates to exact release bytes",
        "id: $judgeEvidenceArtifactId",
        "id: 1",
    ),
    "CI container producer attempt replaced": replace_in_step(
        ci_workflow_text,
        "attest-release",
        "Bind successful CI gates to exact release bytes",
        "producerAttempt: $containerProducerAttempt",
        "producerAttempt: 1",
    ),
}
for tamper_label, tampered_workflow in ci_tamper_cases.items():
    expect_ci_rejected(tamper_label, tampered_workflow)

print(
    json.dumps(
        {
            "schemaVersion":
                "archon.submission-judge-pack-contract-test/v1",
            "artifactFiles": list(EXPECTED_STANDARD_FILES),
            "dispatchInputs": list(EXPECTED_INPUTS),
            "judgeFiles": list(EXPECTED_JUDGE_FILES),
            "ciTamperCases": sorted(ci_tamper_cases),
            "tamperCases": sorted(tamper_cases),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
