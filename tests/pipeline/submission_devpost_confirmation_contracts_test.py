#!/usr/bin/env python3
"""Remote-CI trust contracts for the post-submit SQ11 producer."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "submission-devpost-confirmation.yml"
)
DOCUMENTATION_PATH = ROOT / "docs" / "SUBMISSION_DEVPOST_CONFIRMATION.md"
FORBIDDEN_CANONICAL_PATH = (
    ROOT / "docs" / "SUBMISSION_DEVPOST_CONFIRMATION.json"
)

EXPECTED_INPUTS = (
    "release_sha",
    "readiness_run_id",
    "readiness_run_attempt",
    "readiness_artifact_id",
    "readiness_artifact_digest",
    "readiness_predicate_digest",
    "devpost_project_url",
    "submitted_at",
    "confirmation_digest",
)
EXPECTED_JOBS = ("prepare", "review", "attest")
EXPECTED_STEPS = {
    "prepare": (
        "Bind dispatch inputs and protected environment",
        "Check out the exact unprivileged candidate producer",
        "Verify exact pre-submit readiness seal and derive bindings",
        "Reobserve official rules and all public judging URLs",
        "Package immutable privacy-safe SQ11 candidate",
        "Upload immutable post-submit candidate",
        "Publish exact protected-review request",
    ),
    "review": (
        "Verify exact solo-owner protected-environment approval",
        "Check out the exact unprivileged evidence producer",
        "Validate exact candidate metadata before download",
        "Download exact approved post-submit candidate",
        "Independently revalidate candidate and sealed pre-submit source",
        "Reobserve rules and public judging URLs after approval",
        "Assemble exact existing SQ11 standard-v1 proof schema",
        "Recheck approval and immutable inputs before retention",
        "Upload solo-owner approved SQ11 evidence",
    ),
    "attest": (
        "Validate exact attestation context and retained artifacts",
        "Check out the exact unprivileged attestation verifier",
        "Download exact approved candidate",
        "Download exact solo-owner approved SQ11 evidence",
        "Revalidate exact retained candidate and SQ11 evidence",
        "Independently reverify sealed readiness and reviewed content sources",
        "Independently reconstruct and verify protected approval receipt",
        "Reobserve official rules and every public judging URL before signing",
        "Apply final fail-closed TOCTOU gate",
        "Attest all six exact SQ11 subjects",
        "Verify persisted signed attestation for every SQ11 subject",
    ),
}
EXPECTED_PERMISSIONS = {
    "prepare": {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
    },
    "review": {
        "actions": "read",
        "attestations": "read",
        "contents": "read",
    },
    "attest": {
        "actions": "read",
        "attestations": "write",
        "contents": "read",
        "id-token": "write",
    },
}
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
ACTION_COUNTS = {
    "actions/checkout": 3,
    "actions/download-artifact": 3,
    "actions/upload-artifact": 2,
    "actions/attest": 1,
}
PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-devpost-confirmation/v1"
)
READINESS_PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-readiness-seal/v1"
)
STANDARD_FILES = (
    "attestation-predicate.json",
    "proofs/SQ11.json",
    "support/SQ11/devpost-submission-confirmation.json",
    "support/SQ11/logged-out-url-probes.json",
    "support/SQ11/pre-submit-readiness-seal.json",
    "support/SQ11/public-devpost-entry.json",
)
APPROVAL_BINDINGS = (
    "run_id=${GITHUB_RUN_ID}",
    " run_attempt=",
    " candidate_run_attempt=",
    " release_sha=${RELEASE_SHA}",
    " candidate_artifact_id=",
    " candidate_artifact_digest=",
    " candidate_digest=",
    " readiness_run_id=",
    " readiness_run_attempt=",
    " readiness_artifact_id=",
    " readiness_artifact_digest=",
    " readiness_predicate_digest=",
    " seal_binding_digest=",
    " submission_binding_digest=",
    " public_observation_digest=",
    " devpost_project_url=",
    " submitted_at=",
    " prepared_at=",
    " confirmation_digest=",
)
CANDIDATE_KEY_GUARDS = (
    'keys == [\n'
    '                "preparedAt",\n'
    '                "privacy",\n'
    '                "publicObservationDigest",\n'
    '                "readiness",\n'
    '                "releaseSha",\n'
    '                "repository",\n'
    '                "rulesObservationDigest",\n'
    '                "schemaVersion",\n'
    '                "submission",\n'
    '                "submissionBindingDigest",\n'
    '                "workflow"\n'
    "              ]",
    '(.workflow | keys) == [\n'
    '                "path",\n'
    '                "runAttempt",\n'
    '                "runId"\n'
    "              ]",
    '(.submission | keys) == [\n'
    '                "challengeUrl",\n'
    '                "confirmation",\n'
    '                "devpostProjectUrl",\n'
    '                "status",\n'
    '                "submittedAt"\n'
    "              ]",
    '(.submission.confirmation | keys) == [\n'
    '                "digest",\n'
    '                "scheme"\n'
    "              ]",
    '(.readiness | keys) == [\n'
    '                "artifactDigest",\n'
    '                "artifactId",\n'
    '                "predicateDigest",\n'
    '                "runAttempt",\n'
    '                "runId",\n'
    '                "sealBindingDigest",\n'
    '                "verificationSetDigest"\n'
    "              ]",
    '(.privacy | keys) == [\n'
    '                "devpostCredentialsIncluded",\n'
    '                "devpostSessionMaterialIncluded",\n'
    '                "privateConfirmationBytesIncluded",\n'
    '                "rawEntrantPersonalDataIncluded",\n'
    '                "saltedConfirmationCommitmentIncluded"\n'
    "              ]",
)


class ContractError(AssertionError):
    """Raised when an SQ11 workflow trust boundary is absent."""


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
    body = job.split(marker, maxsplit=1)[1]
    boundaries = list(re.finditer(r"(?m)^      -[^\n]*\n", body))
    require(bool(boundaries), "job must contain steps")
    steps: list[tuple[str, str]] = []
    for index, boundary in enumerate(boundaries):
        header = boundary.group(0)
        require(
            header.startswith("      - name: "),
            f"every step must be named: {header.strip()}",
        )
        name = header.removeprefix("      - name: ").removesuffix("\n")
        end = (
            boundaries[index + 1].start()
            if index + 1 < len(boundaries)
            else len(body)
        )
        steps.append((name, body[boundary.start() : end]))
    return tuple(steps)


def named_step(job: str, name: str) -> str:
    matches = [
        section for step_name, section in job_steps(job) if step_name == name
    ]
    require(len(matches) == 1, f"step missing or duplicated: {name}")
    return matches[0]


def permission_map(job: str, label: str) -> dict[str, str]:
    marker = "    permissions:\n"
    require(job.count(marker) == 1, f"{label} permission map changed")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following else len(job)
    entries = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$",
        job[start:end],
    )
    require(
        len(entries) == len(dict(entries)) and bool(entries),
        f"{label} permissions are empty or duplicated",
    )
    return dict(entries)


def job_condition(job: str, label: str) -> str:
    lines = job.splitlines()
    indexes = [
        index for index, line in enumerate(lines) if line.startswith("    if:")
    ]
    require(len(indexes) == 1, f"{label} job condition changed")
    start = indexes[0]
    end = start + 1
    while end < len(lines) and not re.match(
        r"^    [a-z][a-z0-9_-]*:",
        lines[end],
    ):
        end += 1
    return "\n".join(lines[start:end])


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


def require_all(text: str, values: tuple[str, ...], label: str) -> None:
    for value in values:
        require(value in text, f"{label} missing: {value}")


def validate_contract(workflow: str, documentation: str) -> None:
    normalized_docs = re.sub(r"\s+", " ", documentation)
    require("\t" not in workflow, "workflow must not contain tabs")
    require(
        workflow.startswith(
            "name: Submission Devpost confirmation evidence\n"
        ),
        "workflow identity changed",
    )
    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch input set or order changed",
    )
    for name, block in inputs.items():
        require(
            block.count("        required: true\n") == 1
            and block.count("        type: string\n") == 1,
            f"{name} must remain one required scalar string",
        )
    referenced_inputs = set(
        re.findall(
            r"\$\{\{\s*inputs\.([a-z][a-z0-9_]*)\s*\}\}",
            workflow,
        )
    )
    require(
        referenced_inputs == set(EXPECTED_INPUTS),
        "workflow references an undeclared or unused dispatch input",
    )
    require(
        re.search(
            r"\bfromjson\s*\(\s*inputs\.",
            workflow,
            flags=re.IGNORECASE,
        )
        is None
        and not re.search(
            r"github\s*\.\s*event\s*\.\s*inputs",
            workflow,
            flags=re.IGNORECASE,
        ),
        "dispatch values must stay scalar and unparsed",
    )
    require(
        workflow.count("\npermissions: {}\n") == 1,
        "top-level permissions must remain deny-by-default",
    )
    require(
        len(
            re.findall(
                rf"(?m)^  PREDICATE_TYPE: {re.escape(PREDICATE_TYPE)}$",
                workflow,
            )
        )
        == 1,
        "SQ11 predicate type changed",
    )
    require(
        len(
            re.findall(
                r"(?m)^  READINESS_PREDICATE_TYPE: "
                rf"{re.escape(READINESS_PREDICATE_TYPE)}$",
                workflow,
            )
        )
        == 1,
        "readiness predicate type changed",
    )
    require(
        len(
            re.findall(r"(?m)^\s*PREDICATE_TYPE:", workflow)
        )
        == 1
        and len(
            re.findall(r"(?m)^\s*READINESS_PREDICATE_TYPE:", workflow)
        )
        == 1,
        "predicate types must be defined once at top level",
    )
    require(
        "group: submission-devpost-confirmation-${{ inputs.release_sha }}"
        in workflow
        and "cancel-in-progress: false" in workflow,
        "release-scoped non-cancelling concurrency is required",
    )
    require_all(
        workflow,
        (
            'SUBMISSION_START: "2026-07-06T13:00:00Z"',
            'SUBMISSION_DEADLINE: "2026-08-10T21:00:00Z"',
            'JUDGING_START: "2026-08-17T14:00:00Z"',
            'JUDGING_END: "2026-08-31T21:00:00Z"',
            "https://datahub.devpost.com/rules",
            "https://datahub.devpost.com/",
        ),
        "official challenge binding",
    )

    jobs = job_sections(workflow)
    require(tuple(jobs) == EXPECTED_JOBS, "job set or order changed")
    require(
        len(
            re.findall(
                r"(?m)^    name: "
                r"Prepare immutable post-submit candidate$",
                jobs["prepare"],
            )
        )
        == 1
        and len(
            re.findall(
                r"(?m)^    name: "
                r"Approve and seal Devpost confirmation as solo owner$",
                jobs["review"],
            )
        )
        == 1
        and len(
            re.findall(
                r"(?m)^    name: Attest and persist all SQ11 subjects$",
                jobs["attest"],
            )
        )
        == 1,
        "canonical job display names changed",
    )
    require(
        workflow.count(
            "Approve and seal Devpost confirmation as solo owner"
        )
        == 3,
        "review display name must match both approval job lookups",
    )
    for name, expected_steps in EXPECTED_STEPS.items():
        actual_steps = tuple(step for step, _ in job_steps(jobs[name]))
        require(
            actual_steps == expected_steps,
            f"{name} step set or order changed",
        )
        require(
            permission_map(jobs[name], name) == EXPECTED_PERMISSIONS[name],
            f"{name} least-privilege permissions changed",
        )
    quoted_review_name = (
        '"Approve and seal Devpost confirmation as solo owner"'
    )
    require(
        quoted_review_name
        in named_step(
            jobs["review"],
            "Verify exact solo-owner protected-environment approval",
        )
        and quoted_review_name
        in named_step(
            jobs["attest"],
            "Independently reconstruct and verify protected approval receipt",
        ),
        "review job display name is detached from an API lookup",
    )
    require(
        len(
            re.findall(
                r"(?m)^    environment: "
                r"submission-devpost-confirmation$",
                jobs["review"],
            )
        )
        == 1,
        "review must use the protected confirmation environment",
    )
    require(
        not re.search(r"(?m)^    environment:", jobs["prepare"])
        and not re.search(r"(?m)^    environment:", jobs["attest"]),
        "only the independent review job may wait on the environment",
    )
    expected_job_conditions = {
        "prepare": (
            "    if: >-\n"
            "      github.repository == 'upgradedev/archon-datahub' &&\n"
            "      github.ref == 'refs/heads/master'"
        ),
        "review": "    if: needs.prepare.result == 'success'",
        "attest": (
            "    if: >-\n"
            "      needs.prepare.result == 'success' &&\n"
            "      needs.review.result == 'success'"
        ),
    }
    for name, expected_condition in expected_job_conditions.items():
        require(
            job_condition(jobs[name], name) == expected_condition,
            f"{name} job condition must remain exact and fail closed",
        )
    require(
        re.search(r"(?m)^\s+continue-on-error:", workflow) is None,
        "continue-on-error is forbidden at every trust boundary",
    )
    require(
        re.search(r"(?m)^        (?:if|shell):", workflow) is None,
        "step-level conditions and shell overrides are forbidden",
    )
    require(
        workflow.count("\ndefaults:\n  run:\n    shell: bash\n") == 1
        and len(re.findall(r"(?m)^\s+shell:", workflow)) == 1,
        "the single fail-closed Bash default changed",
    )

    action_references: list[tuple[str, str]] = []
    for raw_reference in re.findall(
        r"(?m)^\s+uses:\s+(.+?)\s*$",
        workflow,
    ):
        executable_reference = raw_reference.split("#", maxsplit=1)[0].strip()
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})",
            executable_reference,
        )
        require(
            match is not None,
            f"local, Docker, unversioned, or mutable action: {raw_reference}",
        )
        action_references.append((match.group(1), match.group(2)))
    expected_action_references = sorted(
        (action, digest)
        for action, digest in ACTION_PINS.items()
        for _ in range(ACTION_COUNTS[action])
    )
    require(
        sorted(action_references) == expected_action_references,
        "executable action identities, pins, or cardinalities changed",
    )
    require(
        len(action_references) == sum(ACTION_COUNTS.values()),
        "unexpected executable action entered the workflow",
    )
    for action in ACTION_PINS:
        require(
            not re.search(
                rf"(?m)^\s+uses:\s+{re.escape(action)}@v[0-9]",
                workflow,
            ),
            f"{action} became mutable",
        )
    require(
        workflow.count("runs-on: ubuntu-24.04") == 3,
        "all jobs must use GitHub-hosted Ubuntu 24.04",
    )
    require(
        "self-hosted" not in "\n".join(
            line
            for line in workflow.splitlines()
            if "deny-self-hosted-runners" not in line
        ),
        "self-hosted execution entered the workflow",
    )
    readiness_verifiers = (
        named_step(
            jobs["prepare"],
            "Verify exact pre-submit readiness seal and derive bindings",
        ),
        named_step(
            jobs["review"],
            "Independently revalidate candidate and sealed pre-submit source",
        ),
        named_step(
            jobs["attest"],
            "Independently reverify sealed readiness and reviewed content sources",
        ),
    )
    require(
        workflow.count("--deny-self-hosted-runners") == 5
        and all(
            verifier.count("--deny-self-hosted-runners") == 1
            for verifier in readiness_verifiers
        ),
        "readiness and SQ11 attestation provenance checks changed",
    )

    require(
        workflow.count("retention-days: 90") == 2
        and workflow.count("overwrite: true") == 2
        and workflow.count("compression-level: 0") == 2,
        "candidate and producer retention/immutability posture changed",
    )
    require_all(
        workflow,
        (
            "submission-devpost-confirmation-candidate-${RELEASE_SHA}-${GITHUB_RUN_ATTEMPT}",
            "submission-devpost-confirmation-${RELEASE_SHA}-${GITHUB_RUN_ATTEMPT}",
            "submission-readiness-${RELEASE_SHA}",
            "submission-content-review-candidate-${RELEASE_SHA}-${content_candidate_attempt}",
        ),
        "artifact identity",
    )
    require(
        workflow.count(
            "/git/ref/heads/master"
        )
        >= 4
        and workflow.count(
            "refs/heads/master"
        )
        >= 8
        and workflow.count(
            "test \"${GITHUB_SHA}\" = \"${RELEASE_SHA}\""
        )
        >= 3,
        "current-master binding is not repeated at trust boundaries",
    )

    prepare_posture = named_step(
        jobs["prepare"],
        "Bind dispatch inputs and protected environment",
    )
    review_approval = named_step(
        jobs["review"],
        "Verify exact solo-owner protected-environment approval",
    )
    attester_approval = named_step(
        jobs["attest"],
        "Independently reconstruct and verify protected approval receipt",
    )
    final_gate = named_step(
        jobs["attest"],
        "Apply final fail-closed TOCTOU gate",
    )
    posture_tokens = (
        "prevent_self_review == false",
        '.type == "User"',
        '[.[].branch_policies[].name] == ["master"]',
        '[.[].branch_policies[].type] == ["branch"]',
    )
    require_all(prepare_posture, posture_tokens, "prepare environment posture")
    for label, boundary in (
        ("review approval", review_approval),
        ("attester approval reconstruction", attester_approval),
        ("final TOCTOU gate", final_gate),
    ):
        require_all(
            boundary,
            posture_tokens
            + (
                ".user.id == $actorId",
                ".user.id == $triggeringActorId",
                ".comment == $expected",
            ),
            label,
        )
    require(
        workflow.count("prevent_self_review == false") == 4
        and workflow.count('.type == "User"') == 5
        and workflow.count(
            '[.[].branch_policies[].name] == ["master"]'
        )
        == 4
        and workflow.count(
            '[.[].branch_policies[].type] == ["branch"]'
        )
        == 4
        and workflow.count(".user.id == $actorId") == 3
        and workflow.count(".user.id == $triggeringActorId") == 3
        and workflow.count(".comment == $expected") == 4,
        "solo-owner approval posture cardinality changed",
    )
    require_all(
        review_approval,
        (
            "authoritativeTimestampAvailable: false",
            "reviewJobStartedAt",
            "($reviewerIds | index($id)) != null",
        ),
        "approval timing honesty",
    )
    require(
        "index($reviewerId) != null" in attester_approval
        and ".reviewer.id == $reviewerId" in final_gate,
        "approved reviewer is detached from the current allowed-user set",
    )
    require(
        workflow.count("APPROVE ARCHON DATAHUB DEVPOST ") == 5,
        "exact approval binding must be published and independently rechecked",
    )
    approval_boundaries = (
        (
            jobs["prepare"],
            "Publish exact protected-review request",
        ),
        (
            jobs["review"],
            "Verify exact solo-owner protected-environment approval",
        ),
        (
            jobs["review"],
            "Recheck approval and immutable inputs before retention",
        ),
        (
            jobs["attest"],
            "Independently reconstruct and verify protected approval receipt",
        ),
        (
            jobs["attest"],
            "Apply final fail-closed TOCTOU gate",
        ),
    )
    for job, step_name in approval_boundaries:
        step = named_step(job, step_name)
        require(
            step.count("APPROVE ARCHON DATAHUB DEVPOST ") == 1,
            f"{step_name} must construct one exact approval string",
        )
        require_all(step, APPROVAL_BINDINGS, step_name)
    require(
        "contains(\"confirmation_digest=\")" not in workflow
        and "startswith(\"APPROVE ARCHON" not in workflow,
        "fuzzy approval matching is forbidden",
    )

    require_all(
        workflow,
        (
            "archive entry count is outside policy",
            "archive expands beyond policy",
            "archive contains a symlink",
            "archive escapes extraction root",
            "duplicate archive path",
            "info.flag_bits & 0x1",
            'any(part in ("", ".", "..") for part in pure.parts)',
            'destination.open("xb")',
            "sha256sum --check --strict SHA256SUMS",
            "diff -u",
        ),
        "safe archive and inventory handling",
    )
    require(
        workflow.count("--max-redirs 0") == 6
        and workflow.count("--proto '=https'") == 6
        and workflow.count("--tlsv1.2") == 6,
        "strict HTTPS no-redirect probes must cover every observation phase",
    )
    observation_steps = (
        named_step(
            jobs["prepare"],
            "Reobserve official rules and all public judging URLs",
        ),
        named_step(
            jobs["review"],
            "Reobserve rules and public judging URLs after approval",
        ),
        named_step(
            jobs["attest"],
            "Reobserve official rules and every public judging URL before signing",
        ),
    )
    exact_rules_curl = (
        '              "https://datahub.devpost.com/rules"\n'
        '          )"'
    )
    for observation in observation_steps:
        require(
            observation.count(exact_rules_curl) == 1,
            "an observation phase is detached from the canonical rules origin",
        )
    for label in ("devpostEntry", "application", "repository", "video"):
        require(
            workflow.count(f"probe {label} ") == 3,
            f"{label} must be probed before and after protected review",
        )

    require(
        workflow.count(
            "scripts/validate-submission-proof-receipts.py"
        )
        >= 7
        and workflow.count(
            "--source-key devpost-confirmation"
        )
        >= 4
        and "assemble-standard" in workflow
        and workflow.count("validate-standard-source") >= 3
        and workflow.count("validate-bundle") >= 3,
        "standard SQ11 and nested readiness semantic validation changed",
    )
    require(
        workflow.count('index("SQ11")) == null') >= 3
        and workflow.count(
            'test ! -e "${seal}/source/receipts/SQ11.json"'
        )
        >= 2
        and 'test ! -e "${readiness}/source/receipts/SQ11.json"'
        in workflow,
        "pre-submit source must exclude SQ11 to prevent circular trust",
    )
    require_all(
        workflow,
        (
            "SQ3 SQ4 SQ5 SQ6 SQ7 SQ8",
            '"submissionFieldsDigest"',
            '"testingInstructionsDigest"',
            '"submissionClaimsDigest"',
            '"videoClaimsDigest"',
            '"applicationAuthenticationRequired"',
            'content["writtenFields"]["description"]',
            "verificationSetDigest",
            "subjectSetDigest",
        ),
        "source-complete readiness/content derivation",
    )

    for subject in STANDARD_FILES:
        require(
            workflow.count(subject) >= 3,
            f"standard subject is not retained and rechecked: {subject}",
        )
    require(
        workflow.count(".subjectCount == 6") >= 3
        and workflow.count(
            'test "$(wc -l <"${output}/SHA256SUMS")" = "6"'
        )
        == 1,
        "exact six-subject standard source contract changed",
    )
    attest_step = named_step(
        jobs["attest"], "Attest all six exact SQ11 subjects"
    )
    require(
        "subject-checksums: ${{ runner.temp }}/submission-devpost-attestation/SHA256SUMS"
        in attest_step
        and "predicate-type: ${{ env.PREDICATE_TYPE }}" in attest_step
        and "predicate-path: ${{ runner.temp }}/submission-devpost-attestation/attestation-predicate.json"
        in attest_step,
        "attestation must sign the complete checksum inventory",
    )
    persisted = named_step(
        jobs["attest"],
        "Verify persisted signed attestation for every SQ11 subject",
    )
    require_all(
        persisted,
        (
            "${{ steps.attest.outputs.bundle-path }}",
            "${{ steps.attest.outputs.attestation-id }}",
            "${{ steps.attest.outputs.attestation-url }}",
            '"https://github.com/${GITHUB_REPOSITORY}/attestations/'
            '${ATTESTATION_ID}"',
            'test -f "${ATTESTATION_BUNDLE_PATH}"',
            'test ! -L "${ATTESTATION_BUNDLE_PATH}"',
            "bundle_size >= 1 && bundle_size <= 16777216",
            'length == 1 and\n            (.[0] | type == "object")',
            "sha256sum --check --strict SHA256SUMS",
            "expected_names=(\n"
            "            attestation-predicate.json\n"
            "            proofs/SQ11.json\n"
            "            support/SQ11/devpost-submission-confirmation.json\n"
            "            support/SQ11/logged-out-url-probes.json\n"
            "            support/SQ11/pre-submit-readiness-seal.json\n"
            "            support/SQ11/public-devpost-entry.json\n"
            "          )",
            'test "${observed_names[*]}" = "${expected_names[*]}"',
            'test "$(jq \'length\' <<<"${expected_subjects}")" = "6"',
            "cleanup() {",
            'rm -rf -- "${verification_dir}"',
            "trap cleanup EXIT",
            'type == "array" and',
            ".attestation == $bundle[0]",
            ".verificationResult.statement.predicateType ==",
            ".verificationResult.statement.predicate ==",
            "sort_by(.name)",
            "                      ) == $expectedSubjects\n",
            'for index in "${!expected_names[@]}"; do',
            '"${root}/${expected_names[$index]}"',
            '"${verification_dir}/bundle-${index}.json"',
            '"${verification_dir}/persisted-${index}.json"',
            "for attempt in {1..12}",
            "gh attestation verify",
            '--bundle "${ATTESTATION_BUNDLE_PATH}"',
            '--predicate-type "${PREDICATE_TYPE}"',
            "github.com/${GITHUB_REPOSITORY}/.github/workflows/"
            "submission-devpost-confirmation.yml",
            '--signer-digest "${RELEASE_SHA}"',
            '--source-digest "${RELEASE_SHA}"',
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "length == 1",
            "-name 'bundle-*.json'",
            "-name 'persisted-*.json'",
            "Offline bundle verification: all 6 subjects independently verified",
            "Persisted lookup verification: all 6 subjects independently verified",
        ),
        "persisted all-subject verification",
    )
    require(
        persisted.count("gh attestation verify") == 2
        and persisted.count(
            '--bundle "${ATTESTATION_BUNDLE_PATH}"'
        )
        == 1
        and persisted.count("--signer-workflow") == 2
        and persisted.count(
            "github.com/${GITHUB_REPOSITORY}/.github/workflows/"
            "submission-devpost-confirmation.yml"
        )
        == 2
        and persisted.count('--signer-digest "${RELEASE_SHA}"') == 2
        and persisted.count('--source-digest "${RELEASE_SHA}"') == 2
        and persisted.count("--source-ref refs/heads/master") == 2
        and persisted.count("--deny-self-hosted-runners") == 2
        and persisted.count("length == 1") == 2
        and persisted.count('= "6"') == 3
        and "length >= 1" not in persisted,
        "offline/persisted 6-of-6 verification cardinalities changed",
    )
    require(
        "subject-path:" not in attest_step,
        "attestation must use the authoritative six-row checksum inventory",
    )

    require(
        re.search(
            r"\$\{\{\s*(?:secrets|vars)\s*\.",
            workflow,
            flags=re.IGNORECASE,
        )
        is None
        and not re.search(
            r"\b(?:DEVPOST_TOKEN|DEVPOST_PASSWORD|DEVPOST_COOKIE)\b",
            workflow,
            flags=re.IGNORECASE,
        )
        and "DEVPOST_TOKEN" not in workflow
        and "DEVPOST_PASSWORD" not in workflow
        and "DEVPOST_COOKIE" not in workflow
        and "report.md" not in workflow,
        "Devpost secrets or unrelated report output entered the workflow",
    )
    require_all(
        workflow,
        (
            "devpostCredentialsIncluded: false",
            "devpostSessionMaterialIncluded: false",
            "privateConfirmationBytesIncluded: false",
            "rawEntrantPersonalDataIncluded: false",
            "saltedConfirmationCommitmentIncluded: true",
            "archon.salted-private-devpost-confirmation/v1",
            "Private Devpost data: salted commitment only; no credentials, cookies, screenshots, confirmation bytes, or private entrant data retained",
            "Approval identity: public GitHub numeric actor/owner IDs retain explicit solo-owner approval provenance; no dynamic GitHub login names retained",
        ),
        "privacy boundary",
    )
    candidate_boundaries = (
        (
            named_step(
                jobs["review"],
                "Independently revalidate candidate and sealed pre-submit source",
            ),
            "review candidate validation",
        ),
        (
            named_step(
                jobs["attest"],
                "Revalidate exact retained candidate and SQ11 evidence",
            ),
            "attester candidate validation",
        ),
    )
    for boundary, label in candidate_boundaries:
        for guard in CANDIDATE_KEY_GUARDS:
            require(
                boundary.count(guard) == 1,
                f"{label} exact key allowlist changed",
            )
    require(
        all(workflow.count(guard) == 2 for guard in CANDIDATE_KEY_GUARDS),
        "candidate key allowlists must exist only at review and attestation",
    )

    require_all(
        normalized_docs,
        (
            "pre-submit aggregate without `SQ11`",
            "Submit the real project in Devpost.",
            "Do not regenerate the pre-submit readiness seal from an aggregate that already contains `SQ11`.",
            "salted privacy-preserving commitment, not a Devpost signature",
            "GitHub's approvals API does not expose an authoritative approval timestamp",
            "An HTTP `200` response is only logged-out reachability evidence.",
            "`submission-devpost-confirmation`",
            "`prevent_self_review` disabled so the owner may approve",
            "No Devpost secret belongs in the environment.",
            "at least 32 random bytes of salt",
            "keys sorted, no insignificant whitespace, and exactly one trailing line feed",
            "Never put either value in an issue, approval comment, workflow input, artifact, log, or step summary.",
            "The digest is a salted privacy-preserving commitment, not a Devpost signature",
            "`SHA256SUMS` is the complete inventory, not a seventh signed subject.",
            "verifies each of the six exact files offline against the single bundle returned by `actions/attest`",
            "calls `gh attestation verify` again, without the bundle, for every one of the six files",
            "Both passes require the same bundle identity, predicate bytes, predicate type, signer workflow, release provenance, and complete sorted six-subject set.",
            "Dynamic response bodies and headers may legitimately change between phases.",
            "public GitHub numeric account IDs solely to prove solo-owner approval",
            "It retains no GitHub login names.",
            "Only after that successful run may the reporting aggregate include `SQ11`.",
            "actual Devpost form remain end-of-process operator actions",
        ),
        "operator documentation",
    )
    require(
        "confirmation_digest" in documentation
        and all(f"`{name}`" in documentation for name in EXPECTED_INPUTS),
        "documentation must describe every dispatch input",
    )
    require(
        not FORBIDDEN_CANONICAL_PATH.exists(),
        "a canonical confirmation file must not exist before real submission",
    )


def replace_first(text: str, old: str, new: str, label: str) -> str:
    require(old in text, f"mutation fixture missing: {label}")
    return text.replace(old, new, 1)


def replace_last(text: str, old: str, new: str, label: str) -> str:
    index = text.rfind(old)
    require(index >= 0, f"mutation fixture missing: {label}")
    return text[:index] + new + text[index + len(old) :]


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
documentation_text = DOCUMENTATION_PATH.read_text(encoding="utf-8")
validate_contract(workflow_text, documentation_text)

mutations = {
    "top permissions widened": replace_first(
        workflow_text,
        "\npermissions: {}\n",
        "\npermissions:\n  contents: write\n",
        "top permissions",
    ),
    "required input becomes optional": replace_first(
        workflow_text,
        "        required: true\n",
        "        required: false\n",
        "required scalar input",
    ),
    "scalar input becomes boolean": replace_first(
        workflow_text,
        "        type: string\n",
        "        type: boolean\n",
        "scalar input",
    ),
    "structured input expression": replace_first(
        workflow_text,
        "${{ inputs.release_sha }}",
        "${{fromJSON( inputs.release_sha )}}",
        "structured input",
    ),
    "prepare job condition forced false": replace_first(
        workflow_text,
        "      github.ref == 'refs/heads/master'\n",
        "      github.ref == 'refs/heads/master' && false\n",
        "prepare job condition",
    ),
    "review job condition forced false": replace_first(
        workflow_text,
        "    if: needs.prepare.result == 'success'\n",
        "    if: needs.prepare.result == 'success' && false\n",
        "review job condition",
    ),
    "attest job condition forced false": replace_first(
        workflow_text,
        "      needs.review.result == 'success'\n",
        "      needs.review.result == 'success' && false\n",
        "attest job condition",
    ),
    "persisted verifier skipped": replace_first(
        workflow_text,
        "      - name: Verify persisted signed attestation for every SQ11 subject\n",
        "      - name: Verify persisted signed attestation for every SQ11 subject\n"
        "        if: ${{ false }}\n",
        "persisted verifier condition",
    ),
    "persisted verifier soft failed": replace_first(
        workflow_text,
        "      - name: Verify persisted signed attestation for every SQ11 subject\n",
        "      - name: Verify persisted signed attestation for every SQ11 subject\n"
        "        continue-on-error: true\n",
        "persisted verifier continue-on-error",
    ),
    "persisted verifier masks shell failure": replace_first(
        workflow_text,
        "      - name: Verify persisted signed attestation for every SQ11 subject\n",
        "      - name: Verify persisted signed attestation for every SQ11 subject\n"
        "        shell: bash {0} || true\n",
        "persisted verifier shell",
    ),
    "self review prevented": replace_first(
        workflow_text,
        "prevent_self_review == false",
        "prevent_self_review == true",
        "prevent self review",
    ),
    "floating attest action": replace_first(
        workflow_text,
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "actions/attest@v4",
        "attest pin",
    ),
    "unknown SHA-pinned executable action": replace_first(
        workflow_text,
        "        uses: actions/checkout@"
        "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
        "        uses: attacker/action@"
        "0000000000000000000000000000000000000000 "
        "# actions/checkout@"
        "3d3c42e5aac5ba805825da76410c181273ba90b1\n",
        "executable action identity",
    ),
    "SQ11 predicate moved into attester": replace_first(
        replace_first(
            workflow_text,
            f"  PREDICATE_TYPE: {PREDICATE_TYPE}\n",
            "",
            "top-level SQ11 predicate",
        ),
        "  attest:\n",
        "  attest:\n"
        "    env:\n"
        f"      PREDICATE_TYPE: {PREDICATE_TYPE}\n",
        "attester predicate move",
    ),
    "readiness predicate moved into review": replace_first(
        replace_first(
            workflow_text,
            f"  READINESS_PREDICATE_TYPE: {READINESS_PREDICATE_TYPE}\n",
            "",
            "top-level readiness predicate",
        ),
        "  review:\n",
        "  review:\n"
        "    env:\n"
        f"      READINESS_PREDICATE_TYPE: {READINESS_PREDICATE_TYPE}\n",
        "review readiness predicate move",
    ),
    "attester shadows predicate": replace_first(
        workflow_text,
        "  attest:\n",
        "  attest:\n"
        "    env:\n"
        "      PREDICATE_TYPE: https://attacker.invalid/predicate/v1\n",
        "attester predicate shadow",
    ),
    "review job display renamed": replace_first(
        workflow_text,
        "    name: Approve and seal Devpost confirmation as solo owner\n",
        "    name: Renamed protected Devpost reviewer\n",
        "review display name",
    ),
    "review API lookup renamed": replace_first(
        workflow_text,
        '"Approve and seal Devpost confirmation as solo owner"',
        '"Renamed protected Devpost reviewer"',
        "review approval lookup",
    ),
    "attester API lookup renamed": replace_last(
        workflow_text,
        '"Approve and seal Devpost confirmation as solo owner"',
        '"Renamed protected Devpost reviewer"',
        "attester approval lookup",
    ),
    "retention shortened": replace_first(
        workflow_text,
        "retention-days: 90",
        "retention-days: 7",
        "retention",
    ),
    "redirects allowed": replace_first(
        workflow_text,
        "--max-redirs 0",
        "--max-redirs 3",
        "redirect policy",
    ),
    "one observation fetches alternate rules origin": replace_first(
        workflow_text,
        '              "https://datahub.devpost.com/rules"\n'
        '          )"',
        '              "https://attacker.invalid/rules"\n'
        '          )"',
        "canonical rules curl",
    ),
    "approval made fuzzy": replace_first(
        workflow_text,
        ".comment == $expected",
        '(.comment | contains("confirmation_digest="))',
        "exact approval",
    ),
    "one approval drops confirmation commitment": replace_first(
        workflow_text,
        " confirmation_digest=${CONFIRMATION_DIGEST}",
        "",
        "approval confirmation binding",
    ),
    "one approval drops exact run attempt": replace_first(
        workflow_text,
        " run_attempt=${GITHUB_RUN_ATTEMPT}",
        "",
        "approval run-attempt binding",
    ),
    "nested SQ11 allowed": replace_first(
        workflow_text,
        'index("SQ11")) == null',
        'index("SQ11")) != null',
        "pre-submit SQ11 exclusion",
    ),
    "subject count weakened": replace_first(
        workflow_text,
        ".subjectCount == 6",
        ".subjectCount > 0",
        "subject count",
    ),
    "candidate top-level allowlist widened": replace_first(
        workflow_text,
        '                "workflow"\n'
        "              ] and\n",
        '                "workflow",\n'
        '                "entrantLogin"\n'
        "              ] and\n",
        "candidate top-level allowlist",
    ),
    "candidate readiness allowlist widened": replace_first(
        workflow_text,
        '                "verificationSetDigest"\n'
        "              ] and\n",
        '                "verificationSetDigest",\n'
        '                "reviewerLogin"\n'
        "              ] and\n",
        "candidate readiness allowlist",
    ),
    "checksum signing weakened": replace_first(
        workflow_text,
        "subject-checksums: ${{ runner.temp }}/submission-devpost-attestation/SHA256SUMS",
        "subject-path: ${{ runner.temp }}/submission-devpost-attestation/proofs/SQ11.json",
        "checksum subjects",
    ),
    "bundle document cardinality weakened": replace_first(
        workflow_text,
        "            length == 1 and\n"
        '            (.[0] | type == "object")\n',
        "            length >= 1\n",
        "bundle document cardinality",
    ),
    "bundle checksum recheck removed": replace_first(
        workflow_text,
        "          (\n"
        '            cd "${root}"\n'
        "            sha256sum --check --strict SHA256SUMS\n"
        "          )\n"
        "          expected_names=(\n",
        "          expected_names=(\n",
        "bundle checksum recheck",
    ),
    "only five exact persisted subjects": replace_first(
        workflow_text,
        "          expected_names=(\n"
        "            attestation-predicate.json\n"
        "            proofs/SQ11.json\n"
        "            support/SQ11/devpost-submission-confirmation.json\n"
        "            support/SQ11/logged-out-url-probes.json\n"
        "            support/SQ11/pre-submit-readiness-seal.json\n"
        "            support/SQ11/public-devpost-entry.json\n"
        "          )",
        "          expected_names=(\n"
        "            attestation-predicate.json\n"
        "            proofs/SQ11.json\n"
        "            support/SQ11/devpost-submission-confirmation.json\n"
        "            support/SQ11/logged-out-url-probes.json\n"
        "            support/SQ11/pre-submit-readiness-seal.json\n"
        "          )",
        "exact persisted subject inventory",
    ),
    "six-subject cardinality weakened": replace_first(
        workflow_text,
        'test "$(jq \'length\' <<<"${expected_subjects}")" = "6"',
        'test "$(jq \'length\' <<<"${expected_subjects}")" -ge "1"',
        "six-subject cardinality",
    ),
    "cleanup trap removed": replace_first(
        workflow_text,
        "          trap cleanup EXIT\n",
        "",
        "cleanup trap",
    ),
    "bundle identity detached": replace_first(
        workflow_text,
        ".attestation == $bundle[0] and",
        ".attestation != null and",
        "bundle identity",
    ),
    "predicate bytes detached": replace_first(
        workflow_text,
        ".verificationResult.statement.predicate ==\n"
        "                        $predicate[0] and",
        ".verificationResult.statement.predicate != null and",
        "predicate bytes",
    ),
    "full subject set weakened": replace_first(
        workflow_text,
        "                      ) == $expectedSubjects\n",
        "                      ) != []\n",
        "full subject set",
    ),
    "offline bundle verification removed": replace_first(
        workflow_text,
        '              --bundle "${ATTESTATION_BUNDLE_PATH}" \\\n',
        "",
        "offline bundle verification",
    ),
    "online lookup reuses local bundle": replace_first(
        workflow_text,
        "                --repo \"${GITHUB_REPOSITORY}\" \\\n"
        "                --predicate-type \"${PREDICATE_TYPE}\" \\\n",
        "                --repo \"${GITHUB_REPOSITORY}\" \\\n"
        '                --bundle "${ATTESTATION_BUNDLE_PATH}" \\\n'
        "                --predicate-type \"${PREDICATE_TYPE}\" \\\n",
        "online persisted lookup",
    ),
    "only one subject receives both verification passes": replace_first(
        workflow_text,
        '          for index in "${!expected_names[@]}"; do\n',
        "          for index in 0; do\n",
        "six-of-six verification loop",
    ),
    "wrong persisted signer workflow": replace_first(
        workflow_text,
        "github.com/${GITHUB_REPOSITORY}/.github/workflows/"
        "submission-devpost-confirmation.yml",
        "github.com/${GITHUB_REPOSITORY}/.github/workflows/"
        "submission-content-review.yml",
        "persisted signer workflow",
    ),
    "final reviewer membership detached": replace_first(
        workflow_text,
        ".reviewer.id == $reviewerId and",
        ".reviewer.id > 0 and",
        "final reviewer membership",
    ),
    "self-hosted provenance allowed": replace_first(
        workflow_text,
        "--deny-self-hosted-runners",
        "--format json",
        "self-hosted provenance",
    ),
    "protected review removed": replace_first(
        workflow_text,
        "    environment: submission-devpost-confirmation\n",
        "",
        "protected environment",
    ),
    "review permission widened": replace_first(
        workflow_text,
        "  review:\n",
        "  review:\n    permissions:\n      contents: write\n",
        "review permissions",
    ),
    "workflow gets Devpost secret": replace_first(
        workflow_text,
        "permissions: {}\n",
        "permissions: {}\nenv:\n"
        "  DEVPOST_TOKEN: ${{secrets.DEVPOST_TOKEN}}\n",
        "secret ingress",
    ),
    "workflow gets repository variable": replace_first(
        workflow_text,
        "permissions: {}\n",
        "permissions: {}\nenv:\n"
        "  UNTRUSTED_VALUE: ${{vars.UNTRUSTED_VALUE}}\n",
        "variable ingress",
    ),
}

for mutation_name, mutation in mutations.items():
    try:
        validate_contract(mutation, documentation_text)
    except ContractError:
        continue
    raise ContractError(f"contract accepted mutation: {mutation_name}")

print(
    json.dumps(
        {
            "jobs": list(EXPECTED_JOBS),
            "mutationsRejected": len(mutations),
            "result": "verified",
            "signedSubjects": len(STANDARD_FILES),
            "workflow": str(WORKFLOW_PATH.relative_to(ROOT)),
        },
        sort_keys=True,
    )
)
