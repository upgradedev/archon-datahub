#!/usr/bin/env python3
"""Remote-CI trust contracts for the final submission content producer."""

from __future__ import annotations

import importlib.util
import json
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    ROOT / ".github" / "workflows" / "submission-content-review.yml"
)
EXAMPLE_PATH = ROOT / "docs" / "SUBMISSION_CONTENT.example.json"
VIDEO_VALIDATOR_PATH = ROOT / "scripts" / "validate-submission-video.py"

EXPECTED_INPUTS = (
    "release_sha",
    "project_access_run_id",
    "video_url",
)
EXPECTED_JOBS = ("prepare", "review", "attest")
EXPECTED_STEPS = {
    "prepare": (
        "Bind dispatch to current master and protected review posture",
        "Check out exact release and complete history",
        "Verify exact attested project-access source",
        "Validate canonical final content and credentialless video",
        "Capture exact repository history and immutable candidate",
        "Upload immutable final-content candidate",
        "Publish exact independent approval request",
    ),
    "review": (
        "Verify exact independent environment approval",
        "Check out exact reviewed release and complete history",
        "Validate immutable candidate metadata before download",
        "Download exact immutable candidate",
        "Independently re-resolve the attested project-access source",
        "Independently revalidate exact candidate bytes and semantics",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "Recheck exact source selection and canonical state before retention",
        "Retain exact reviewed content subjects",
    ),
    "attest": (
        "Bind attester to exact current workflow run",
        "Check out exact unprivileged release with complete history",
        "Resolve latest retained reviewed producer",
        "Download exact retained reviewed subjects",
        "Validate exact retry-safe standard-v1 source",
        "Resolve exact signed candidate provenance",
        "Download exact signed immutable candidate",
        "Independently re-resolve exact project-access attestations",
        "Independently reproduce candidate content and Git history",
        "Independently repeat credentialless exact video observation",
        "Reconstruct exact approval receipt and all retained facts",
        "Recheck latest producer, upstream source, and current master",
        "Attest all sixteen exact reviewed subjects",
        "Verify persisted signed full-subject attestation",
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
EXPECTED_ACTION_COUNTS = {
    "actions/checkout": 3,
    "actions/download-artifact": 3,
    "actions/upload-artifact": 2,
    "actions/attest": 1,
}
PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-content-review/v1"
)
EXPECTED_SUBJECT_FILES = (
    "attestation-predicate.json",
    "proofs/SQ6.json",
    "proofs/SQ7.json",
    "proofs/SQ8.json",
    "support/SQ6/english-review.json",
    "support/SQ6/submission-fields.json",
    "support/SQ6/testing-instructions.json",
    "support/SQ7/english-accessibility.json",
    "support/SQ7/functioning-footage-review.json",
    "support/SQ7/logged-out-video-probe.json",
    "support/SQ7/media-rights.json",
    "support/SQ7/provider-metadata.json",
    "support/SQ8/cross-medium-review.json",
    "support/SQ8/independent-approval.json",
    "support/SQ8/preexisting-work-inventory.json",
    "support/SQ8/repository-history.json",
)
REVIEW_APPROVAL_FIELDS = (
    "environment",
    "workflowPath",
    "runId",
    "runAttempt",
    "environmentId",
    "workflowActorId",
    "triggeringActorId",
    "reviewerId",
    "candidateRunAttempt",
    "candidateArtifactId",
    "candidateArtifactDigest",
    "candidateDigest",
    "approvalCommentDigest",
    "approvalReceiptDigest",
)


class ContractError(AssertionError):
    """Raised when a workflow trust contract is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


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
    require(
        len(entries) == len(dict(entries)),
        f"{label} permissions contain a duplicate capability",
    )
    return dict(entries)


def require_tokens(text: str, label: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def validate_video_validator(source: str) -> None:
    require_tokens(
        source,
        "shared public-video validator",
        (
            'parsed.scheme != "https"',
            "parsed.username is not None",
            "parsed.password is not None",
            "explicit_port is not None",
            "parsed.netloc != parsed.hostname",
            'if url != canonical_url:',
            'node.get("videoId") == video_id',
            'node.get("videoDetails")',
            'node.get("playabilityStatus")',
            "direct_id_matches(node, provider, video_id)",
            "if len(candidates) != 1:",
            "target video duration must be from 1 through 179 seconds",
            "json.JSONDecoder(object_pairs_hook=reject_duplicate_pairs)",
            "decoded = json.loads(\n"
            "                    candidate,\n"
            "                    object_pairs_hook=reject_duplicate_pairs,\n"
            "                )",
            'hashlib.sha256(raw).hexdigest()',
            "STABLE_OBSERVATION_KEYS = OBSERVATION_KEYS -",
            'type(value["durationSeconds"]) is not int',
            'type(value["publiclyAccessible"]) is not bool',
            'type(value["loggedOutAccessible"]) is not bool',
            'type(value["httpStatus"]) is not int',
            'type(value["redirectsObserved"]) is not int',
            "canonical_bytes(value) != raw",
            'fresh provider metadata differs from the prepared observation',
        ),
    )
    require(
        "re.findall(" not in source,
        "provider metadata must not return to global duration regex collection",
    )
    require(
        source.count("if len(candidates) != 1:") == 2,
        "YouTube and Vimeo/Youku must both reject ambiguous target objects",
    )


def load_video_validator():
    spec = importlib.util.spec_from_file_location(
        "archon_submission_video_validator",
        VIDEO_VALIDATOR_PATH,
    )
    require(
        spec is not None and spec.loader is not None,
        "shared public-video validator cannot be imported",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expect_video_rejected(module, label: str, operation) -> None:
    try:
        operation()
    except module.ValidationError:
        return
    raise ContractError(f"public-video validator accepted {label}")


def youtube_document(
    video_id: str,
    duration: int,
    *,
    related_duration: int | None = None,
    duplicate_target: bool = False,
) -> str:
    roots = [
        {
            "playabilityStatus": {"status": "OK"},
            "videoDetails": {
                "videoId": video_id,
                "lengthSeconds": str(duration),
            },
        }
    ]
    if related_duration is not None:
        roots.append(
            {
                "playabilityStatus": {"status": "OK"},
                "videoDetails": {
                    "videoId": "RelateVid01",
                    "lengthSeconds": str(related_duration),
                },
            }
        )
    if duplicate_target:
        roots.append(json.loads(json.dumps(roots[0])))
    return "".join(
        "<script>window.ytInitialPlayerResponse="
        + json.dumps(root, separators=(",", ":"), sort_keys=True)
        + ";</script>"
        for root in roots
    )


def exercise_video_validator() -> None:
    module = load_video_validator()
    target_id = "TargetVid01"
    target_url = f"https://www.youtube.com/watch?v={target_id}"
    preflight = module.exact_video_url(target_url)
    require(
        preflight
        == {
            "schemaVersion": "archon.submission-video-preflight/v1",
            "url": target_url,
            "provider": "www.youtube.com",
            "videoId": target_id,
        },
        "valid YouTube preflight is not canonical",
    )
    require(
        module.target_duration(
            preflight,
            youtube_document(target_id, 179, related_duration=30),
        )
        == 179,
        "target-bound YouTube duration was not selected",
    )
    expect_video_rejected(
        module,
        "a related short duration for an overlong target",
        lambda: module.target_duration(
            preflight,
            youtube_document(target_id, 200, related_duration=30),
        ),
    )
    expect_video_rejected(
        module,
        "zero exact target objects",
        lambda: module.target_duration(
            preflight,
            youtube_document("RelateVid01", 30),
        ),
    )
    expect_video_rejected(
        module,
        "multiple exact target objects",
        lambda: module.target_duration(
            preflight,
            youtube_document(target_id, 179, duplicate_target=True),
        ),
    )
    expect_video_rejected(
        module,
        "duplicate provider metadata keys",
        lambda: module.target_duration(
            preflight,
            "<script>window.ytInitialPlayerResponse="
            '{"playabilityStatus":{"status":"OK"},'
            '"videoDetails":{"videoId":"TargetVid01",'
            '"videoId":"RelateVid01","lengthSeconds":"30"}};'
            "</script>",
        ),
    )
    duplicate_nested_metadata = (
        '{"playabilityStatus":{"status":"OK"},'
        '"videoDetails":{"videoId":"TargetVid01",'
        '"videoId":"RelateVid01","lengthSeconds":"30"}}'
    )
    expect_video_rejected(
        module,
        "duplicate nested provider metadata keys",
        lambda: module.target_duration(
            preflight,
            '<script type="application/json">'
            + json.dumps({"payload": duplicate_nested_metadata})
            + "</script>",
        ),
    )
    expect_video_rejected(
        module,
        "an exact target longer than 179 seconds",
        lambda: module.target_duration(
            preflight,
            youtube_document(target_id, 180),
        ),
    )
    for label, url in {
        "URL userinfo":
            f"https://user:pass@www.youtube.com/watch?v={target_id}",
        "an explicit provider port":
            f"https://www.youtube.com:443/watch?v={target_id}",
        "a noncanonical provider host":
            f"https://WWW.YOUTUBE.COM/watch?v={target_id}",
        "a non-TLS URL":
            f"http://www.youtube.com/watch?v={target_id}",
    }.items():
        expect_video_rejected(
            module,
            label,
            lambda url=url: module.exact_video_url(url),
        )

    vimeo = module.exact_video_url("https://vimeo.com/123456789")
    require(
        module.target_duration(
            vimeo,
            '<script type="application/json">'
            '{"clip":{"duration":178,"id":123456789}}'
            "</script>",
        )
        == 178,
        "valid target-bound Vimeo metadata was rejected",
    )
    youku = module.exact_video_url(
        "https://v.youku.com/v_show/id_XNDemo_001.html"
    )
    require(
        module.target_duration(
            youku,
            '<script type="application/json">'
            '{"video":{"duration":177,"videoId":"XNDemo_001"}}'
            "</script>",
        )
        == 177,
        "valid target-bound Youku metadata was rejected",
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        prepared_body = root / "prepared.html"
        reviewed_body = root / "reviewed.html"
        prepared_path = root / "prepared.json"
        reviewed_path = root / "reviewed.json"
        prepared_body.write_text(
            youtube_document(target_id, 179) + "<div>prepared</div>",
            encoding="utf-8",
        )
        reviewed_body.write_text(
            youtube_document(target_id, 179) + "<div>dynamic review</div>",
            encoding="utf-8",
        )
        prepared = module.observe(target_url, prepared_body)
        module.write_json(prepared_path, prepared)
        module.command_revalidate(
            SimpleNamespace(
                url=target_url,
                body=reviewed_body,
                prepared=prepared_path,
                output=reviewed_path,
            )
        )
        reviewed = module.load_observation(reviewed_path)
        require(
            re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                prepared["responseDigest"],
            )
            is not None
            and re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                reviewed["responseDigest"],
            )
            is not None,
            "prepared/review provider-response digests are malformed",
        )
        require(
            prepared["responseDigest"] != reviewed["responseDigest"],
            "dynamic provider bodies were incorrectly forced to one digest",
        )
        require(
            all(
                prepared[key] == reviewed[key]
                for key in module.STABLE_OBSERVATION_KEYS
            ),
            "review revalidation did not preserve stable target metadata",
        )
        poisoned_observations = {
            "boolean duration in prepared observation": (
                "durationSeconds",
                True,
            ),
            "integer public-access flag in prepared observation": (
                "publiclyAccessible",
                1,
            ),
            "integer logged-out flag in prepared observation": (
                "loggedOutAccessible",
                1,
            ),
            "boolean HTTP status in prepared observation": (
                "httpStatus",
                True,
            ),
            "boolean redirect count in prepared observation": (
                "redirectsObserved",
                False,
            ),
        }
        for label, (field, poisoned_value) in poisoned_observations.items():
            poisoned = dict(prepared)
            poisoned[field] = poisoned_value
            module.write_json(prepared_path, poisoned)
            expect_video_rejected(
                module,
                label,
                lambda: module.command_revalidate(
                    SimpleNamespace(
                        url=target_url,
                        body=reviewed_body,
                        prepared=prepared_path,
                        output=reviewed_path,
                    )
                ),
            )
        prepared_path.write_text(
            json.dumps(prepared, indent=2),
            encoding="utf-8",
        )
        expect_video_rejected(
            module,
            "noncanonical prepared observation JSON",
            lambda: module.command_revalidate(
                SimpleNamespace(
                    url=target_url,
                    body=reviewed_body,
                    prepared=prepared_path,
                    output=reviewed_path,
                )
            ),
        )


def validate_workflow(workflow: str) -> None:
    require("\t" not in workflow, "workflow must not contain tabs")
    require(
        workflow.startswith("name: Submission content review\n"),
        "workflow identity changed",
    )
    require(
        "(run ${{ github.run_id }}, attempt ${{ github.run_attempt }})"
        in workflow,
        "current retry attempt must remain visible before environment approval",
    )
    require(
        "permissions: {}\n" in workflow,
        "top-level permissions must remain deny-by-default",
    )
    require(
        "cancel-in-progress: false\n" in workflow
        and "group: submission-content-review-${{ inputs.release_sha }}"
        in workflow,
        "release-scoped non-cancelling concurrency changed",
    )
    require(
        "pull_request_target" not in workflow
        and "secrets." not in workflow
        and "aws-actions/" not in workflow,
        "content review must not gain privileged trigger or credentials",
    )

    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch must expose exactly three ordered scalar inputs",
    )
    for name, block in inputs.items():
        require(
            block.count("        required: true\n") == 1
            and block.count("        type: string\n") == 1,
            f"{name} must remain one required scalar string",
        )
    forbidden_inputs = (
        "facts",
        "json",
        "path",
        "application",
        "reviewer",
        "approval",
        "bypass",
    )
    require(
        not any(name in inputs for name in forbidden_inputs),
        "arbitrary evidence or approval input was introduced",
    )

    jobs = job_sections(workflow)
    require(tuple(jobs) == EXPECTED_JOBS, "job topology changed")
    for name, expected in EXPECTED_STEPS.items():
        observed = tuple(step_name for step_name, _ in job_steps(jobs[name]))
        require(observed == expected, f"{name} step topology changed")
        require(
            permission_map(jobs[name], name) == EXPECTED_PERMISSIONS[name],
            f"{name} least-privilege permissions changed",
        )
    require(
        len(
            re.findall(
                r"(?m)^    environment: submission-content-review$",
                jobs["review"],
            )
        )
        == 1,
        "review must use the exact protected environment",
    )
    require(
        re.search(r"(?m)^    environment:", jobs["prepare"]) is None
        and re.search(r"(?m)^    environment:", jobs["attest"]) is None,
        "prepare or attester must not inherit an approval environment",
    )
    require(
        jobs["review"].count("    needs: prepare\n") == 1
        and jobs["attest"].count("    needs: review\n") == 1,
        "candidate-review-attester dependency chain changed",
    )

    uses_rows = re.findall(
        r"(?m)^\s+uses:\s+(\S+)(?:\s+#.*)?$",
        workflow,
    )
    require(
        len(uses_rows) == sum(EXPECTED_ACTION_COUNTS.values()),
        "action invocation count changed or a floating action was added",
    )
    action_rows: list[tuple[str, str]] = []
    for reference in uses_rows:
        match = re.fullmatch(
            r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})",
            reference,
        )
        require(
            match is not None,
            f"action reference is not an exact reviewed SHA pin: {reference}",
        )
        action_rows.append((match.group(1), match.group(2)))
    for action, expected_pin in ACTION_PINS.items():
        pins = [pin for observed, pin in action_rows if observed == action]
        require(
            pins == [expected_pin] * EXPECTED_ACTION_COUNTS[action],
            f"{action} pin or invocation count changed",
        )
    require(
        all(action in ACTION_PINS for action, _ in action_rows),
        "an unreviewed action dependency was introduced",
    )
    require(
        workflow.count("          fetch-depth: 0\n") == 3,
        "full Git history is required in all phases",
    )
    require(
        workflow.count("          retention-days: 90\n") == 2,
        "candidate and final artifacts must both retain for 90 days",
    )
    require(
        workflow.count("          digest-mismatch: error\n") == 3,
        "every downloaded artifact must fail on digest mismatch",
    )
    require(PREDICATE_TYPE in workflow, "predicate type changed")
    require(
        workflow.count("python3 scripts/validate-submission-video.py") == 6,
        "all three phases must share preflight and observation validation",
    )

    prepare_binding = named_step(
        jobs["prepare"],
        "Bind dispatch to current master and protected review posture",
    )
    require_tokens(
        prepare_binding,
        "prepare release binding",
        (
            'test "${GITHUB_REF}" = "refs/heads/master"',
            'test "${GITHUB_SHA}" = "${RELEASE_SHA}"',
            'test "${current_release}" = "${RELEASE_SHA}"',
            '.prevent_self_review == true',
            '.type == "User"',
            '[.[].branch_policies[].name] == ["master"]',
        ),
    )
    prepare_content = named_step(
        jobs["prepare"],
        "Validate canonical final content and credentialless video",
    )
    require_tokens(
        prepare_content,
        "prepare content validator",
        (
            'content="docs/SUBMISSION_CONTENT.json"',
            'content["status"] != "final"',
            '"https://datahub.devpost.com/rules"',
            '"submissionStart": "2026-07-06T13:00:00Z"',
            '"submissionEnd": "2026-08-10T21:00:00Z"',
            "scripts/validate-submission-video.py",
            "preflight",
            "observe",
            'probe_url="$(jq -er \'.url\'',
            "--max-redirs 0",
            "--proto '=https'",
            "--tlsv1.2",
        ),
    )
    history = named_step(
        jobs["prepare"],
        "Capture exact repository history and immutable candidate",
    )
    approval_request = named_step(
        jobs["prepare"],
        "Publish exact independent approval request",
    )
    require_tokens(
        approval_request,
        "retry-aware approval request",
        (
            "candidate_run_attempt=${GITHUB_RUN_ATTEMPT}",
            "For a partial retry, replace only",
            "with the current attempt shown in the Actions run title",
            "and all candidate bindings remain unchanged",
        ),
    )
    require_tokens(
        history,
        "candidate history",
        (
            'git rev-list --reverse "${RELEASE_SHA}"',
            '"rootCommitParentCount": len(rows[0]["parents"])',
            '"allReachableCommitsWithinSubmissionPeriod": True',
            '"archon.submission-content-review-candidate/v1"',
            "submission-content-review-candidate-${RELEASE_SHA}-${GITHUB_RUN_ATTEMPT}",
            "project-access-binding.json",
            "find . -type f ! -name SHA256SUMS",
        ),
    )

    approval = named_step(
        jobs["review"],
        "Verify exact independent environment approval",
    )
    require_tokens(
        approval,
        "independent approval",
        (
            ".prevent_self_review == true",
            '.type == "User"',
            ".user.id != $actorId",
            ".user.id != $triggeringActorId",
            "expected exactly one matching independent approval",
            "archon.submission-content-approval/v1",
            "candidateArtifactDigest",
            "candidateRunAttempt",
            "candidate_run_attempt=${CANDIDATE_RUN_ATTEMPT}",
            "attempts/${GITHUB_RUN_ATTEMPT}",
            "projectAccessRunId",
            "contentDigest: $contentDigest",
            "videoObservationDigest: $videoObservationDigest",
            "projectAccessBindingDigest:",
            "printf '%s' \"${expected_approval}\"",
            "comment_digest=sha256:",
        ),
    )
    review_revalidation = named_step(
        jobs["review"],
        "Independently revalidate exact candidate bytes and semantics",
    )
    require_tokens(
        review_revalidation,
        "independent review",
        (
            "sha256sum --check --strict SHA256SUMS",
            "content projection was not independently reproduced",
            "Git history was not independently reproduced",
            "scripts/validate-submission-video.py",
            "preflight",
            "revalidate",
            'reviewed_video="${RUNNER_TEMP}/submission-content-review-video.json"',
            "project-access-binding.json",
            '"projectAccessBindingDigest",',
            ".projectAccessBindingDigest ==",
            "attempts/${CANDIDATE_RUN_ATTEMPT}",
            '--argjson attempt "${CANDIDATE_RUN_ATTEMPT}"',
            "git diff --quiet",
        ),
    )
    package = named_step(
        jobs["review"],
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
    )
    require_tokens(
        package,
        "registered content package",
        (
            "assemble-standard",
            "--source-key content-review",
            '.subjectCount == 16',
            '.proofIds == ["SQ6", "SQ7", "SQ8"]',
            'test "$(wc -l <"${output}/SHA256SUMS")" = "16"',
            "LC_ALL=C sort -u",
            "approvalCommentDigest",
            "candidateRunAttempt: $candidateRunAttempt",
            "candidateArtifactId: $candidateArtifactId",
            "candidateArtifactDigest: $candidateArtifactDigest",
            "candidateDigest",
            "environmentId",
            "providerResponseDigests",
            "preparedResponseDigest: $video[0].responseDigest",
            "reviewResponseDigest: $reviewedVideo[0].responseDigest",
            "runAttempt",
            "runId",
            "workflowPath",
        ),
    )
    for field in REVIEW_APPROVAL_FIELDS:
        require(
            re.search(rf"(?m)^\s+{re.escape(field)}:", package) is not None,
            f"SQ8 reviewApproval lost {field}",
        )
    require(
        package.count("reviewedAt: $reviewedAt") == 3,
        "SQ6/SQ7/SQ8 must use one common reviewedAt",
    )
    for name in EXPECTED_SUBJECT_FILES:
        require(
            name in package,
            f"review package lost exact subject {name}",
        )

    resolver = named_step(
        jobs["attest"],
        "Resolve latest retained reviewed producer",
    )
    require_tokens(
        resolver,
        "attester artifact resolver",
        (
            "--policy latest-retained",
            "submission-content-review-${RELEASE_SHA}-",
            '--maximum-attempt "${GITHUB_RUN_ATTEMPT}"',
        ),
    )
    attester_validation = named_step(
        jobs["attest"],
        "Validate exact retry-safe standard-v1 source",
    )
    require_tokens(
        attester_validation,
        "standard-v1 attester",
        (
            "validate-standard-source",
            "--source-key content-review",
            '--run-attempt "${PRODUCER_ATTEMPT}"',
            '.subjectCount == 16',
            'test "$(wc -l <"${root}/SHA256SUMS")" = "16"',
        ),
    )
    candidate_resolver = named_step(
        jobs["attest"],
        "Resolve exact signed candidate provenance",
    )
    require_tokens(
        candidate_resolver,
        "signed candidate artifact resolver",
        (
            ".facts.reviewApproval.candidateRunAttempt",
            ".facts.reviewApproval.candidateArtifactId",
            ".facts.reviewApproval.candidateArtifactDigest",
            "--policy exact-current",
            "submission-content-review-candidate-${RELEASE_SHA}-",
            '--maximum-attempt "${candidate_attempt}"',
            "candidate_attempt <= PRODUCER_ATTEMPT",
            ".metadata.id == $artifactId",
            ".metadata.digest == $digest",
        ),
    )
    reconstruction = named_step(
        jobs["attest"],
        "Reconstruct exact approval receipt and all retained facts",
    )
    require_tokens(
        reconstruction,
        "attester fact reconstruction",
        (
            "expected exactly one matching independent approval",
            "printf '%s' \"${expected_approval}\"",
            "candidate_run_attempt=${CANDIDATE_RUN_ATTEMPT}",
            "attempts/${PRODUCER_ATTEMPT}",
            'test "${#reviewed_at_values[@]}" = "1"',
            "approvalCommentDigest",
            "runAttempt: $candidateRunAttempt",
            "artifactId: $candidateArtifactId",
            "artifactDigest: $candidateArtifactDigest",
            "candidateRunAttempt: $candidateRunAttempt",
            "candidateArtifactId: $candidateArtifactId",
            "candidateArtifactDigest: $candidateArtifactDigest",
            "candidateDigest",
            "environmentId",
            "providerResponseDigests",
            "reviewResponseDigest",
            "contentDigest: $contentDigest",
            "videoObservationDigest: $videoObservationDigest",
            "projectAccessBindingDigest:",
            "project_access_binding_digest=${project_access_binding_digest}",
            "content_digest=${content_digest}",
            "video_observation_digest=${video_observation_digest}",
            'cmp --silent \\\n              "${RUNNER_TEMP}/${proof_id}-expected.json"',
        ),
    )
    candidate_reproduction = named_step(
        jobs["attest"],
        "Independently reproduce candidate content and Git history",
    )
    require_tokens(
        candidate_reproduction,
        "attester candidate binding",
        (
            '"projectAccessBindingDigest",',
            ".projectAccessBindingDigest ==",
            '--arg projectAccessBindingDigest "sha256:$(',
            "project-access-binding.json",
            'attempts/${CANDIDATE_RUN_ATTEMPT}',
            "candidate_triggering_actor_id",
        ),
    )
    attest = named_step(
        jobs["attest"],
        "Attest all sixteen exact reviewed subjects",
    )
    require_tokens(
        attest,
        "native attestation",
        (
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            "submission-content-attestation/SHA256SUMS",
            "submission-content-attestation/attestation-predicate.json",
        ),
    )
    persisted = named_step(
        jobs["attest"],
        "Verify persisted signed full-subject attestation",
    )
    require_tokens(
        persisted,
        "persisted attestation verification",
        (
            "ATTESTATION_BUNDLE_PATH",
            "ATTESTATION_ID",
            "ATTESTATION_URL",
            "expected_subjects",
            "sort_by(.name)",
            "--signer-digest",
            "--source-digest",
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "validate_verification_result",
        ),
    )
    require(
        workflow.count("bash scripts/collect-submission-evidence-source.sh")
        == 3,
        "project-access must be independently collected in all three phases",
    )
    probe_contracts = (
        (prepare_content, "prepare", "observe"),
        (review_revalidation, "review", "revalidate"),
        (
            named_step(
                jobs["attest"],
                "Independently repeat credentialless exact video observation",
            ),
            "attester",
            "revalidate",
        ),
    )
    for step, label, observation_command in probe_contracts:
        preflight_at = step.find("\n            preflight \\\n")
        curl_at = step.find("\n          curl \\\n")
        observation_at = step.find(f"\n            {observation_command} \\\n")
        require(
            0 <= preflight_at < curl_at < observation_at,
            f"{label} must validate the exact provider URL before curl",
        )


def replace_exact(text: str, old: str, new: str) -> str:
    require(text.count(old) == 1, f"mutation anchor is not unique: {old}")
    return text.replace(old, new, 1)


def replace_in_step(
    workflow: str,
    job_name: str,
    step_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    require(job_name in jobs, f"mutation job is missing: {job_name}")
    step = named_step(jobs[job_name], step_name)
    mutated_step = replace_exact(step, old, new)
    require(workflow.count(step) == 1, "mutation step block is ambiguous")
    return workflow.replace(step, mutated_step, 1)


def expect_rejected(label: str, workflow: str) -> None:
    try:
        validate_workflow(workflow)
    except ContractError:
        return
    raise ContractError(f"mutation was not rejected: {label}")


def expect_video_validator_rejected(label: str, source: str) -> None:
    try:
        validate_video_validator(source)
    except ContractError:
        return
    raise ContractError(f"video-validator mutation was not rejected: {label}")


video_validator_text = VIDEO_VALIDATOR_PATH.read_text(encoding="utf-8")
validate_video_validator(video_validator_text)
exercise_video_validator()

workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
validate_workflow(workflow_text)

example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
require(
    set(example)
    == {
        "schemaVersion",
        "status",
        "writtenFields",
        "languages",
        "submissionClaims",
        "videoReview",
        "disclosures",
        "rules",
    },
    "submission content example keys changed",
)
require(
    example["schemaVersion"] == "archon.submission-content-input/v1"
    and example["status"] == "draft",
    "example must be structurally current but intentionally non-final",
)
require(
    example["rules"]
    == {
        "officialRulesUrl": "https://datahub.devpost.com/rules",
        "submissionStart": "2026-07-06T13:00:00Z",
        "submissionEnd": "2026-08-10T21:00:00Z",
    },
    "example official-rules binding changed",
)

tamper_cases = {
    "arbitrary facts input": replace_exact(
        workflow_text,
        "      video_url:\n",
        "      facts_json:\n"
        "        description: Arbitrary facts\n"
        "        required: true\n"
        "        type: string\n"
        "      video_url:\n",
    ),
    "top permissions widened": replace_exact(
        workflow_text,
        "permissions: {}\n",
        "permissions:\n  contents: write\n",
    ),
    "review environment removed": replace_exact(
        workflow_text,
        "    environment: submission-content-review\n",
        "    environment: production\n",
    ),
    "prevent-self-review weakened": replace_in_step(
        workflow_text,
        "review",
        "Verify exact independent environment approval",
        ".prevent_self_review == true",
        ".prevent_self_review == false",
    ),
    "individual reviewer weakened": replace_in_step(
        workflow_text,
        "review",
        "Verify exact independent environment approval",
        '.type == "User"',
        '.type == "Team"',
    ),
    "candidate digest omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  candidateDigest: $candidateDigest,\n",
        "",
    ),
    "candidate run attempt omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  candidateRunAttempt: $candidateRunAttempt,\n",
        "",
    ),
    "candidate artifact ID omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  candidateArtifactId: $candidateArtifactId,\n",
        "",
    ),
    "candidate artifact digest omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  candidateArtifactDigest: $candidateArtifactDigest,\n",
        "",
    ),
    "review response digest omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  reviewResponseDigest: $reviewedVideo[0].responseDigest\n",
        "                  reviewResponseDigest: $video[0].responseDigest\n",
    ),
    "approval comment digest omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  approvalCommentDigest: $approvalCommentDigest,\n",
        "",
    ),
    "approval environment ID omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  environmentId: $environmentId,\n",
        "",
    ),
    "approval workflow path omitted": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "                  workflowPath:\n"
        "                    \".github/workflows/submission-content-review.yml\",\n",
        "",
    ),
    "reviewer candidate binding digest omitted": replace_in_step(
        workflow_text,
        "review",
        "Independently revalidate exact candidate bytes and semantics",
        '                "projectAccessBindingDigest",\n',
        "",
    ),
    "attester candidate binding comparison omitted": replace_in_step(
        workflow_text,
        "attest",
        "Independently reproduce candidate content and Git history",
        "              .projectAccessBindingDigest ==\n"
        "                $projectAccessBindingDigest and\n",
        "",
    ),
    "review candidate attempt rebound to current retry": replace_in_step(
        workflow_text,
        "review",
        "Independently revalidate exact candidate bytes and semantics",
        '--argjson attempt "${CANDIDATE_RUN_ATTEMPT}" \\\n',
        '--argjson attempt "${GITHUB_RUN_ATTEMPT}" \\\n',
    ),
    "attester receipt content digest omitted": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        "                  contentDigest: $contentDigest,\n",
        "",
    ),
    "attester receipt video digest omitted": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        "                  videoObservationDigest: $videoObservationDigest,\n",
        "",
    ),
    "attester receipt project binding digest omitted": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        "                  projectAccessBindingDigest:\n"
        "                    $projectAccessBindingDigest\n",
        "",
    ),
    "common reviewed time weakened": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        '          test "${#reviewed_at_values[@]}" = "1"\n',
        '          test "${#reviewed_at_values[@]}" -gt "0"\n',
    ),
    "current master equality weakened": replace_in_step(
        workflow_text,
        "prepare",
        "Bind dispatch to current master and protected review posture",
        '          test "${current_release}" = "${RELEASE_SHA}"\n',
        '          test -n "${current_release}"\n',
    ),
    "full history removed": replace_in_step(
        workflow_text,
        "prepare",
        "Check out exact release and complete history",
        "          fetch-depth: 0\n",
        "          fetch-depth: 1\n",
    ),
    "prepare provider preflight removed": replace_in_step(
        workflow_text,
        "prepare",
        "Validate canonical final content and credentialless video",
        "            preflight \\\n",
        "            observe \\\n",
    ),
    "review provider preflight removed": replace_in_step(
        workflow_text,
        "review",
        "Independently revalidate exact candidate bytes and semantics",
        "            preflight \\\n",
        "            revalidate \\\n",
    ),
    "attester provider preflight removed": replace_in_step(
        workflow_text,
        "attest",
        "Independently repeat credentialless exact video observation",
        "            preflight \\\n",
        "            revalidate \\\n",
    ),
    "video redirect enabled": replace_in_step(
        workflow_text,
        "prepare",
        "Validate canonical final content and credentialless video",
        "            --max-redirs 0 \\\n",
        "            --max-redirs 5 \\\n",
    ),
    "review collector removed": replace_exact(
        workflow_text,
        "      - name: Independently re-resolve the attested project-access source\n",
        "      - name: Trust project-access job output\n",
    ),
    "latest retained weakened": replace_in_step(
        workflow_text,
        "attest",
        "Resolve latest retained reviewed producer",
        "              --policy latest-retained \\\n",
        "              --policy single-retained \\\n",
    ),
    "matching candidate weakened": replace_in_step(
        workflow_text,
        "attest",
        "Resolve exact signed candidate provenance",
        "              --policy exact-current \\\n",
        "              --policy latest-retained \\\n",
    ),
    "signed candidate attempt rebound to producer": replace_in_step(
        workflow_text,
        "attest",
        "Resolve exact signed candidate provenance",
        '              --maximum-attempt "${candidate_attempt}" \\\n',
        '              --maximum-attempt "${PRODUCER_ATTEMPT}" \\\n',
    ),
    "attester producer actor projection made mutable": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        "/attempts/${PRODUCER_ATTEMPT}",
        "",
    ),
    "attester candidate attempt fact omitted": replace_in_step(
        workflow_text,
        "attest",
        "Reconstruct exact approval receipt and all retained facts",
        "                  candidateRunAttempt: $candidateRunAttempt,\n",
        "",
    ),
    "subject count weakened": replace_in_step(
        workflow_text,
        "review",
        "Assemble exact reviewed SQ6, SQ7, and SQ8 facts",
        "              .subjectCount == 16 and\n",
        "              .subjectCount > 0 and\n",
    ),
    "retention weakened": replace_in_step(
        workflow_text,
        "review",
        "Retain exact reviewed content subjects",
        "          retention-days: 90\n",
        "          retention-days: 7\n",
    ),
    "floating attest action": replace_exact(
        workflow_text,
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "actions/attest@v4",
    ),
    "wrong attestation inventory": replace_exact(
        workflow_text,
        "subject-checksums: "
        "${{ runner.temp }}/submission-content-attestation/SHA256SUMS",
        "subject-checksums: "
        "${{ runner.temp }}/submission-content-attestation/proofs/SQ6.json",
    ),
    "persisted verification removed": replace_exact(
        workflow_text,
        "      - name: Verify persisted signed full-subject attestation\n",
        "      - name: Skip persisted attestation verification\n",
    ),
    "predicate changed": replace_exact(
        workflow_text,
        PREDICATE_TYPE,
        "https://example.invalid/submission-content-review/v1",
    ),
}
for tamper_label, tampered_workflow in tamper_cases.items():
    expect_rejected(tamper_label, tampered_workflow)

ambiguity_anchor = "if len(candidates) != 1:"
require(
    video_validator_text.count(ambiguity_anchor) == 2,
    "provider ambiguity mutation anchors changed",
)
video_validator_mutations = {
    "userinfo accepted": replace_exact(
        video_validator_text,
        "parsed.username is not None",
        "False",
    ),
    "explicit port accepted": replace_exact(
        video_validator_text,
        "explicit_port is not None",
        "False",
    ),
    "YouTube target ID unbound": replace_exact(
        video_validator_text,
        'node.get("videoId") == video_id',
        'node.get("videoId") is not None',
    ),
    "provider duplicate keys accepted": replace_exact(
        video_validator_text,
        "json.JSONDecoder(object_pairs_hook=reject_duplicate_pairs)",
        "json.JSONDecoder()",
    ),
    "nested provider duplicate keys accepted": replace_exact(
        video_validator_text,
        "decoded = json.loads(\n"
        "                    candidate,\n"
        "                    object_pairs_hook=reject_duplicate_pairs,\n"
        "                )",
        "decoded = json.loads(candidate)",
    ),
    "YouTube ambiguity accepted": video_validator_text.replace(
        ambiguity_anchor,
        "if not candidates:",
        1,
    ),
    "Vimeo Youku ambiguity accepted": video_validator_text.rsplit(
        ambiguity_anchor,
        1,
    )[0]
    + "if not candidates:"
    + video_validator_text.rsplit(ambiguity_anchor, 1)[1],
    "target duration widened": replace_exact(
        video_validator_text,
        "if not 1 <= result <= 179:",
        "if not 1 <= result <= 360:",
    ),
    "raw response digest discarded": replace_exact(
        video_validator_text,
        "hashlib.sha256(raw).hexdigest()",
        "hashlib.sha256(b'constant').hexdigest()",
    ),
    "dynamic response digest forced stable": replace_exact(
        video_validator_text,
        "STABLE_OBSERVATION_KEYS = OBSERVATION_KEYS - {\"responseDigest\"}",
        "STABLE_OBSERVATION_KEYS = OBSERVATION_KEYS",
    ),
    "prepared duration boolean collision accepted": replace_exact(
        video_validator_text,
        'type(value["durationSeconds"]) is not int',
        'not isinstance(value["durationSeconds"], int)',
    ),
    "prepared public flag integer collision accepted": replace_exact(
        video_validator_text,
        'type(value["publiclyAccessible"]) is not bool',
        'not isinstance(value["publiclyAccessible"], int)',
    ),
    "prepared HTTP status boolean collision accepted": replace_exact(
        video_validator_text,
        'type(value["httpStatus"]) is not int',
        'not isinstance(value["httpStatus"], int)',
    ),
    "noncanonical prepared observation accepted": replace_exact(
        video_validator_text,
        "if canonical_bytes(value) != raw:",
        "if False:",
    ),
}
for mutation_label, mutated_validator in video_validator_mutations.items():
    expect_video_validator_rejected(mutation_label, mutated_validator)

print(
    json.dumps(
        {
            "schemaVersion":
                "archon.submission-content-review-contract-test/v1",
            "artifactSubjects": list(EXPECTED_SUBJECT_FILES),
            "dispatchInputs": list(EXPECTED_INPUTS),
            "reviewApprovalFields": list(REVIEW_APPROVAL_FIELDS),
            "tamperCases": sorted(tamper_cases),
            "videoValidatorMutations": sorted(video_validator_mutations),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
