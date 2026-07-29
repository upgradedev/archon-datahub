#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for the BONUS-FEEDBACK producer."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "submission-bonus-feedback.yml"
)
DOCUMENTATION_PATH = ROOT / "docs" / "SUBMISSION_BONUS_FEEDBACK.md"
CANONICAL_EVIDENCE_PATH = (
    ROOT / "docs" / "SUBMISSION_FEEDBACK_CONFIRMATION.json"
)

EXPECTED_INPUTS = ("release_sha",)
EXPECTED_JOBS = ("prepare", "review", "attest")
EXPECTED_STEPS = {
    "prepare": (
        "Bind dispatch to the exact current release",
        "Check out the exact unprivileged candidate producer",
        "Verify official rules and canonical confirmation projection",
        "Prepare immutable digest-bound feedback candidate",
        "Upload immutable feedback candidate",
        "Publish exact private-review approval request",
    ),
    "review": (
        "Verify exact solo-owner protected-environment approval",
        "Check out the exact protected producer",
        "Resolve exact current-attempt candidate artifact",
        "Download exact immutable feedback candidate",
        "Revalidate private-reference candidate and public rules",
        "Assemble exact protected BONUS-FEEDBACK facts",
        "Recheck candidate approval and master before retention",
        "Retain exact checksum-sealed feedback subjects",
    ),
    "attest": (
        "Bind attester to the exact current release and workflow run",
        "Check out the exact unprivileged attester",
        "Resolve latest retained producer and exact candidate artifacts",
        "Download exact retained feedback subjects",
        "Download exact approved feedback candidate",
        "Rederive candidate rules approval and retained facts",
        "Recheck immutable evidence approval rules and master before signing",
        "Attest all three exact feedback subjects",
        "Verify persisted signed full-subject attestation",
    ),
}
EXPECTED_PERMISSIONS = {
    "prepare": {"actions": "read", "contents": "read"},
    "review": {"actions": "read", "contents": "read"},
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
    "submission-bonus-feedback/v1"
)
STANDARD_FILES = (
    "attestation-predicate.json",
    "proofs/BONUS-FEEDBACK.json",
    "support/BONUS-FEEDBACK/feedback-confirmation.json",
)
APPROVAL_BINDINGS = (
    "run_id=${GITHUB_RUN_ID}",
    " run_attempt=",
    " candidate_run_attempt=",
    " release_sha=${RELEASE_SHA}",
    " candidate_artifact_id=",
    " candidate_artifact_digest=",
    " candidate_digest=",
    " canonical_evidence_digest=",
    " confirmation_digest=",
    " entrant_binding_digest=",
    " submitted_at=",
)


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
    normalized_documentation = re.sub(r"\s+", " ", documentation)
    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "workflow inputs must remain release_sha only",
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
        "fromJSON(inputs." not in workflow
        and "fromJson(inputs." not in workflow
        and "github.event.inputs" not in workflow,
        "dispatch identifiers must never become structured payloads",
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
        == 1
        and len(
            re.findall(r"(?m)^\s*PREDICATE_TYPE:", workflow)
        )
        == 1,
        "feedback predicate type must have one canonical top-level definition",
    )
    require(
        "cancel-in-progress: false" in workflow,
        "release-scoped runs must not cancel each other",
    )
    require(
        "group: submission-bonus-feedback-${{ inputs.release_sha }}"
        in workflow,
        "concurrency must remain release-scoped",
    )
    jobs = job_sections(workflow)
    require(
        tuple(jobs) == EXPECTED_JOBS,
        f"unexpected job graph: {tuple(jobs)}",
    )
    require(
        len(
            re.findall(
                r"(?m)^    name: "
                r"Approve and seal feedback evidence as solo owner$",
                jobs["review"],
            )
        )
        == 1,
        "review display name must match approval and attester job lookups",
    )
    for job_name, expected_steps in EXPECTED_STEPS.items():
        actual_steps = tuple(name for name, _ in job_steps(jobs[job_name]))
        require(
            actual_steps == expected_steps,
            f"{job_name} steps changed: {actual_steps}",
        )
        require(
            permission_map(jobs[job_name], job_name)
            == EXPECTED_PERMISSIONS[job_name],
            f"{job_name} permissions changed",
        )

    require(
        "    environment: submission-bonus-feedback\n" in jobs["review"],
        "protected review environment is absent",
    )
    require(
        not re.search(r"(?m)^    environment:", jobs["prepare"])
        and not re.search(r"(?m)^    environment:", jobs["attest"]),
        "only the human review job may target the protected environment",
    )
    require(
        "needs: prepare" in jobs["review"]
        and "needs:\n      - prepare\n      - review\n" in jobs["attest"],
        "candidate-review-attester dependency chain changed",
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
    require(
        "secrets." not in workflow
        and "DEVPOST_PASSWORD" not in workflow
        and "DEVPOST_COOKIE" not in workflow
        and "DEVPOST_TOKEN" not in workflow,
        "Devpost credentials or secrets entered the workflow",
    )

    require_all(
        workflow,
        (
            PREDICATE_TYPE,
            "docs/SUBMISSION_FEEDBACK_CONFIRMATION.json",
            "archon.submission-feedback-confirmation/v1",
            "archon.salted-devpost-entrant-binding/v1",
            "archon.salted-private-feedback-reference/v1",
            '"2026-07-06T13:00:00Z"',
            '"2026-08-10T21:00:00Z"',
            "https://datahub.devpost.com/",
            "https://datahub.devpost.com/rules",
            "One Feedback Submission per Entrant.",
            "completeness, viability, and potential impact of the feedback",
            "Feedback Prizes are awarded to individuals, not to Projects",
            "complete the feedback section during submission",
        ),
        "official feedback contract",
    )
    for official_phrase in (
        "One Feedback Submission per Entrant.",
        "completeness, viability, and potential impact of the feedback",
        "Feedback Prizes are awarded to individuals, not to Projects",
        "complete the feedback section during submission",
    ):
        require(
            workflow.count(official_phrase) == 4,
            f"every public-rules observation must enforce: {official_phrase}",
        )
    require(
        workflow.count("docs/SUBMISSION_FEEDBACK_CONFIRMATION.json") == 4,
        "canonical evidence path must be identical in every stage",
    )
    require(
        workflow.count("--max-redirs 0") == 4,
        "every authoritative page observation must deny redirects",
    )
    require(
        workflow.count("--proto '=https'") == 4
        and workflow.count("--max-filesize 2097152") == 4,
        "public fetch transport/size boundary changed",
    )
    fetch_pair = (
        'fetch_public \\\n'
        '            "https://datahub.devpost.com/rules" \\\n',
        'fetch_public \\\n'
        '            "https://datahub.devpost.com/" \\\n',
    )
    for job, step_name in (
        (
            jobs["prepare"],
            "Verify official rules and canonical confirmation projection",
        ),
        (
            jobs["review"],
            "Independently revalidate private-reference candidate and public rules",
        ),
        (
            jobs["attest"],
            "Independently rederive candidate rules approval and retained facts",
        ),
    ):
        require_all(
            named_step(job, step_name),
            fetch_pair,
            f"{step_name} authoritative public sources",
        )
    require_all(
        named_step(
            jobs["attest"],
            "Recheck immutable evidence approval rules and master before signing",
        ),
        (
            '"https://datahub.devpost.com/rules|${final_rules}" \\\n',
            '"https://datahub.devpost.com/|${final_challenge}"',
        ),
        "final authoritative public sources",
    )
    require(
        workflow.count("scripts/verify-github-control-plane.sh") == 3,
        "each trust stage must recheck the GitHub control plane",
    )
    require(
        workflow.count('.event == "workflow_dispatch"') == 5,
        "current and producer workflow-run API identities are not fully bound",
    )
    require(
        workflow.count(
            '/environments/submission-bonus-feedback"'
        )
        == 3
        and workflow.count(
            "/environments/submission-bonus-feedback/"
            "deployment-branch-policies?per_page=100"
        )
        == 3
        and workflow.count("prevent_self_review == false") == 3,
        "environment posture must be checked before, during, and after review",
    )
    require(
        workflow.count('branch_policies[].name] == ["master"]') == 3
        and workflow.count('branch_policies[].type] == ["branch"]') == 3,
        "every environment-posture check must enforce the master branch only",
    )

    approval_phrase = "APPROVE ARCHON DATAHUB FEEDBACK "
    require(
        workflow.count(approval_phrase) == 5,
        "approval must be reconstructed at every initial and final trust check",
    )
    approval_construction_steps = (
        (
            jobs["prepare"],
            "Publish exact private-review approval request",
        ),
        (
            jobs["review"],
            "Verify exact solo-owner protected-environment approval",
        ),
        (
            jobs["review"],
            "Recheck candidate approval and master before retention",
        ),
        (
            jobs["attest"],
            "Rederive candidate rules approval and retained facts",
        ),
        (
            jobs["attest"],
            "Recheck immutable evidence approval rules and master before signing",
        ),
    )
    for job, step_name in approval_construction_steps:
        step = named_step(job, step_name)
        require_all(
            step,
            (approval_phrase, *APPROVAL_BINDINGS),
            f"{step_name} approval construction",
        )
    approval_step = named_step(
        jobs["review"],
        "Verify exact solo-owner protected-environment approval",
    )
    require_all(
        approval_step,
        (
            'prevent_self_review == false',
            '.type == "User"',
            '.user.id == $actorId',
            '.user.id == $triggeringActorId',
            'length == 1 then .[0]',
            'branch_policies[].name] == ["master"]',
            'branch_policies[].type] == ["branch"]',
            '"submission-bonus-feedback"',
            '"archon.submission-feedback-approval/v1"',
            "submitted <= review_job_started <= deadline",
            "(( CANDIDATE_RUN_ATTEMPT <= GITHUB_RUN_ATTEMPT ))",
        ),
        "protected approval",
    )

    require_all(
        workflow,
        (
            "registeredEntrant: true",
            "oneEntryPerEntrant: true",
            "individualNotProjectPrize: true",
            "distinctFeedbackSubmissionUnderRules: true",
            "complete: true",
            "actionable: true",
            "viable: true",
            "potentialImpact: true",
            "authenticatedUiObserved: false",
            "publicOverviewInstruction",
            "complete-feedback-section-during-submission",
            "rawFeedbackIncluded: false",
            "rawEntrantPersonalDataIncluded: false",
            "devpostCredentialsIncluded: false",
            "privateConfirmationBytesIncluded: false",
            "pseudonymousEntrantCommitmentIncluded: true",
            "publicReviewerNumericIdentifierIncluded: true",
            "entrantKind: \"individual\"",
            "canonicalEvidenceDigest",
            "confirmationDigest",
            "entrantBindingDigest",
            "approvalTiming",
            "authoritativeApprovalTimestampAvailable: false",
            "reviewJobStartedAt",
            "reviewApproval",
            'approvalMode: "solo-owner"',
            'mode: "solo-owner"',
            "selfApproved: true",
            "approvalCommentDigest",
            "approvalReceiptDigest",
            '"rawFeedbackIncluded": False,',
            '"rawEntrantPersonalDataIncluded": False,',
            '"devpostCredentialsIncluded": False,',
            '"pseudonymousEntrantCommitmentIncluded": True,',
        ),
        "privacy-preserving facts",
    )
    require(
        workflow.count('"authenticatedUiObserved": False,') == 4
        and workflow.count("authenticatedUiObserved: false") == 2
        and workflow.count("publicOverviewInstruction") == 6
        and workflow.count(
            "complete-feedback-section-during-submission"
        )
        == 6,
        "public-overview observation must not become an authenticated-UI claim",
    )
    require(
        workflow.count(
            '"pseudonymousEntrantCommitmentIncluded": True,'
        )
        == 1
        and workflow.count(
            "pseudonymousEntrantCommitmentIncluded: true"
        )
        == 5
        and workflow.count(
            "publicReviewerNumericIdentifierIncluded: true"
        )
        == 2,
        "pseudonymous and public-reviewer disclosures must remain explicit",
    )
    require(
        workflow.count(
            "authoritativeApprovalTimestampAvailable: false"
        )
        == 4
        and workflow.count("reviewJobStartedAt") == 12
        and workflow.count(
            "submitted <= review_job_started <= deadline"
        )
        == 2
        and "reviewedAt" not in workflow,
        "review job start must remain an explicit approval upper bound",
    )
    require(
        workflow.count(".comment == $expected") == 4
        and 'contains("confirmation_digest="' not in workflow,
        "every approval check must retain the exact full binding",
    )

    require(
        workflow.count("--policy exact-current") == 2,
        "candidate artifact must use exact-current selection",
    )
    require(
        workflow.count("--policy latest-retained") == 1,
        "attester must select the latest retained producer",
    )
    require(
        workflow.count("retention-days: 90") == 2,
        "candidate and standard evidence must be retained for 90 days",
    )
    require(
        workflow.count("sha256sum --check --strict SHA256SUMS") >= 5,
        "checksum verification coverage weakened",
    )
    require(
        workflow.count(".subjectCount == 3") == 2,
        "standard source must retain exactly three signed subjects",
    )
    minimum_subject_references = {
        "attestation-predicate.json": 4,
        "proofs/BONUS-FEEDBACK.json": 4,
        "support/BONUS-FEEDBACK/feedback-confirmation.json": 3,
    }
    for path in STANDARD_FILES:
        require(
            workflow.count(path) >= minimum_subject_references[path],
            f"registered subject is not fully enforced: {path}",
        )
    require_all(
        workflow,
        (
            "assemble-standard",
            "validate-standard-source",
            "--source-key bonus-feedback",
            "sourceKey == \"bonus-feedback\"",
            'proofIds == ["BONUS-FEEDBACK"]',
        ),
        "standard source assembly",
    )

    attester = jobs["attest"]
    require_all(
        attester,
        (
            "Rederive candidate rules approval and retained facts",
            "/attempts/${PRODUCER_ATTEMPT}",
            "successful review job is missing or ambiguous",
            "exact solo-owner approval is missing or ambiguous",
            'jq -cS \'.facts\'',
            "cmp --silent",
            "Recheck immutable evidence approval rules and master before signing",
        ),
        "independent attester",
    )
    persisted = named_step(
        attester, "Verify persisted signed full-subject attestation"
    )
    require_all(
        persisted,
        (
            "${{ steps.attest.outputs.bundle-path }}",
            "${{ steps.attest.outputs.attestation-id }}",
            "gh attestation verify",
            '--bundle "${ATTESTATION_BUNDLE_PATH}"',
            "--predicate-type",
            "--signer-workflow",
            "--signer-digest",
            "--source-digest",
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "sort_by(.name)",
            "length == 1",
            'length == 1 and\n            (.[0] | type == "object")',
            ".attestation == $bundle[0]",
            'type == "array" and',
            "expected_names=(\n"
            "            attestation-predicate.json\n"
            "            proofs/BONUS-FEEDBACK.json\n"
            "            support/BONUS-FEEDBACK/feedback-confirmation.json\n"
            "          )",
            'test "${observed_names[*]}" = "${expected_names[*]}"',
            'for index in "${!expected_names[@]}"; do',
            '"${root}/${expected_names[$index]}"',
            '"${verification_dir}/bundle-${index}.json"',
            '"${verification_dir}/persisted-${index}.json"',
            'test "$(jq \'length\' <<<"${expected_subjects}")" = "3"',
        ),
        "persisted attestation verification",
    )
    require(
        persisted.count("gh attestation verify") == 2
        and persisted.count('--bundle "${ATTESTATION_BUNDLE_PATH}"') == 1
        and persisted.count("--signer-workflow") == 2
        and persisted.count('--signer-digest "${RELEASE_SHA}"') == 2
        and persisted.count('--source-digest "${RELEASE_SHA}"') == 2
        and persisted.count("--source-ref refs/heads/master") == 2
        and persisted.count("--deny-self-hosted-runners") == 2
        and persisted.count("length == 1") == 2
        and "length >= 1" not in persisted,
        "offline-bundle and persisted feedback verification cardinalities changed",
    )

    require_all(
        normalized_documentation,
        (
            "Do not create",
            "`docs/SUBMISSION_FEEDBACK_CONFIRMATION.json`",
            "The workflow never receives or stores",
            "This is public wording, not an authenticated-UI",
            "pipeline cannot independently prove the form directly",
            "pseudonymous rather than described as",
            "authoritativeApprovalTimestampAvailable: false",
            "conservative “approval observed no later than” bound",
            "individualNotProjectPrize",
            "distinctFeedbackSubmissionUnderRules",
            "If no independent private verification is possible, do not claim",
        ),
        "feedback documentation",
    )
    require(
        "SUBMISSION_FEEDBACK_CONFIRMATION.json" in workflow
        and (
            not CANONICAL_EVIDENCE_PATH.exists()
            or CANONICAL_EVIDENCE_PATH.is_file()
        ),
        "canonical evidence path contract changed",
    )


def replace_first(source: str, old: str, new: str, label: str) -> str:
    require(old in source, f"mutation anchor missing: {label}")
    return source.replace(old, new, 1)


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
documentation_text = DOCUMENTATION_PATH.read_text(encoding="utf-8")
validate_contract(workflow_text, documentation_text)

mutations = {
    "extra workflow input": replace_first(
        workflow_text,
        "      release_sha:\n",
        "      confirmation_digest:\n"
        "        description: Untrusted caller digest\n"
        "        required: true\n"
        "        type: string\n"
        "      release_sha:\n",
        "extra workflow input",
    ),
    "release input becomes optional": replace_first(
        workflow_text,
        "        required: true\n",
        "        required: false\n",
        "required release input",
    ),
    "release input becomes boolean": replace_first(
        workflow_text,
        "        type: string\n",
        "        type: boolean\n",
        "scalar release input",
    ),
    "structured release input": replace_first(
        workflow_text,
        "${{ inputs.release_sha }}",
        "${{ fromJSON(inputs.release_sha) }}",
        "structured release input",
    ),
    "review environment removed": replace_first(
        workflow_text,
        "    environment: submission-bonus-feedback\n",
        "",
        "review environment",
    ),
    "review job display name changed": replace_first(
        workflow_text,
        "    name: Approve and seal feedback evidence as solo owner\n",
        "    name: Renamed protected reviewer\n",
        "review job display name",
    ),
    "producer gains signing authority": replace_first(
        workflow_text,
        "      contents: read\n    outputs:\n",
        "      contents: read\n      id-token: write\n    outputs:\n",
        "producer permission",
    ),
    "unknown SHA-pinned action": replace_first(
        workflow_text,
        "        uses: actions/checkout@"
        "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
        "        uses: attacker/action@"
        "0000000000000000000000000000000000000000 "
        "# actions/checkout@"
        "3d3c42e5aac5ba805825da76410c181273ba90b1\n",
        "executable action identity",
    ),
    "attester shadows predicate type": replace_first(
        workflow_text,
        "  attest:\n",
        "  attest:\n"
        "    env:\n"
        "      PREDICATE_TYPE: https://attacker.invalid/predicate/v1\n",
        "attester predicate shadow",
    ),
    "self review prevented": replace_first(
        workflow_text,
        "prevent_self_review == false",
        "prevent_self_review == true",
        "self review",
    ),
    "master policy weakened": replace_first(
        workflow_text,
        'branch_policies[].name] == ["master"]',
        "branch_policies | length) >= 1",
        "master policy",
    ),
    "branch policy accepts tags": replace_first(
        workflow_text,
        'branch_policies[].type] == ["branch"]',
        'branch_policies[].type] == ["tag"]',
        "branch policy type",
    ),
    "confirmation digest removed from approval": replace_first(
        workflow_text,
        " confirmation_digest=${CONFIRMATION_DIGEST}",
        "",
        "confirmation approval binding",
    ),
    "run attempt removed from approval": replace_first(
        workflow_text,
        " run_attempt=${GITHUB_RUN_ATTEMPT}",
        "",
        "run-attempt approval binding",
    ),
    "reviewer detached from actor": replace_first(
        workflow_text,
        ".user.id == $actorId and",
        "true and",
        "solo-owner actor binding",
    ),
    "official period ordering removed": replace_first(
        workflow_text,
        "submitted <= review_job_started <= deadline",
        "submitted <= deadline",
        "time ordering",
    ),
    "public wording relabeled as authenticated observation": replace_first(
        workflow_text,
        '"authenticatedUiObserved": False,',
        '"authenticatedUiObserved": True,',
        "authenticated UI provenance",
    ),
    "pseudonymous commitment hidden": replace_first(
        workflow_text,
        '"pseudonymousEntrantCommitmentIncluded": True,',
        '"pseudonymousEntrantCommitmentIncluded": False,',
        "pseudonymous disclosure",
    ),
    "review job start mislabeled as approval time": replace_first(
        workflow_text,
        "reviewJobStartedAt",
        "reviewedAt",
        "approval timestamp semantics",
    ),
    "raw feedback permitted": replace_first(
        workflow_text,
        '"rawFeedbackIncluded": False,',
        '"rawFeedbackIncluded": True,',
        "privacy assertion",
    ),
    "redirects enabled": replace_first(
        workflow_text,
        "--max-redirs 0",
        "--max-redirs 5",
        "redirect policy",
    ),
    "one authoritative fetch uses alternate origin": replace_first(
        workflow_text,
        'fetch_public \\\n'
        '            "https://datahub.devpost.com/rules" \\\n',
        'fetch_public \\\n'
        '            "https://attacker.invalid/rules" \\\n',
        "authoritative rules fetch",
    ),
    "one-entry rule removed": replace_first(
        workflow_text,
        '"One Feedback Submission per Entrant.",',
        '"Feedback Submission",',
        "one entry rule",
    ),
    "latest retained weakened": replace_first(
        workflow_text,
        "--policy latest-retained",
        "--policy single-retained",
        "latest retained",
    ),
    "candidate selector weakened": replace_first(
        workflow_text,
        "--policy exact-current",
        "--policy latest-retained",
        "exact candidate",
    ),
    "retention shortened": replace_first(
        workflow_text,
        "retention-days: 90",
        "retention-days: 7",
        "retention",
    ),
    "floating attestation action": replace_first(
        workflow_text,
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "actions/attest@v4",
        "attest pin",
    ),
    "subject count weakened": replace_first(
        workflow_text,
        ".subjectCount == 3",
        ".subjectCount > 0",
        "subject count",
    ),
    "persisted verification removed": replace_first(
        workflow_text,
        "      - name: Verify persisted signed full-subject attestation\n",
        "      - name: Skip persisted signed full-subject attestation\n",
        "persisted verification",
    ),
    "only two persisted subjects verified": replace_first(
        workflow_text,
        "          expected_names=(\n"
        "            attestation-predicate.json\n"
        "            proofs/BONUS-FEEDBACK.json\n"
        "            support/BONUS-FEEDBACK/feedback-confirmation.json\n"
        "          )",
        "          expected_names=(\n"
        "            attestation-predicate.json\n"
        "            proofs/BONUS-FEEDBACK.json\n"
        "          )",
        "persisted subject inventory",
    ),
    "offline bundle verification removed": replace_first(
        workflow_text,
        '              --bundle "${ATTESTATION_BUNDLE_PATH}" \\\n',
        "",
        "offline bundle verification",
    ),
    "bundle identity detached": replace_first(
        workflow_text,
        ".attestation == $bundle[0] and",
        "true and",
        "bundle identity",
    ),
    "self-hosted provenance allowed": replace_first(
        workflow_text,
        "--deny-self-hosted-runners",
        "--format json",
        "self-hosted provenance",
    ),
    "canonical evidence path changed": replace_first(
        workflow_text,
        "docs/SUBMISSION_FEEDBACK_CONFIRMATION.json",
        "feedback.json",
        "canonical path",
    ),
    "exact final approval weakened": replace_first(
        workflow_text,
        ".comment == $expected",
        '(.comment | contains("confirmation_digest="))',
        "exact approval recheck",
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
