#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for the production judge journey."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "submission-judge-journey.yml"

EXPECTED_INPUTS = (
    "release_sha",
    "deployment_run_id",
    "provision_run_id",
    "rotate_run_id",
    "deactivate_run_id",
    "reactivate_run_id",
)
EXPECTED_JOBS = ("prerequisites", "journey", "attest")
EXPECTED_ARTIFACT_FILES = (
    "SHA256SUMS",
    "attestation-predicate.json",
    "browser-journey-receipt.json",
    "deployment-binding.json",
    "judge-user-lifecycle.json",
    "journey-subject.sha256",
    "manifest.json",
    "production-runtime-config.json",
    "terminal-observation.json",
)
EXPECTED_PRIMARY_SUBJECTS = {
    "browser-journey": "browser-journey-receipt.json",
    "deployment-binding": "deployment-binding.json",
    "judge-user-lifecycle": "judge-user-lifecycle.json",
    "runtime-config": "production-runtime-config.json",
    "terminal-observation": "terminal-observation.json",
}
EXPECTED_NETWORK_COUNTERS = (
    "allowedApplicationRequests",
    "allowedHostedUiRequests",
    "allowedIssuerRequests",
    "startRequests",
    "decisionRequests",
    "tokenRequests",
    "authorizationRequests",
    "callbackRequests",
    "logoutRequests",
    "unexpectedRequests",
    "blockedWebSockets",
    "serviceWorkerViolations",
)
PREDICATE_TYPE = (
    "https://archon.datahub.dev/attestations/"
    "submission-judge-journey/v1"
)
MANIFEST_SCHEMA = "archon.submission-judge-journey-manifest/v1"
PREDICATE_SCHEMA = "archon.submission-judge-journey-attestation/v1"
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/attest": "59d89421af93a897026c735860bf21b6eb4f7b26",
}


class ContractError(AssertionError):
    """Raised when a workflow trust-boundary contract is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def job_sections(workflow: str) -> dict[str, str]:
    marker = "\njobs:\n"
    require(workflow.count(marker) == 1, "workflow must define one jobs map")
    jobs_body = workflow.split(marker, maxsplit=1)[1]
    matches = list(
        re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", jobs_body)
    )
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(jobs_body)
        )
        sections[match.group(1)] = jobs_body[match.start() : end]
    return sections


def named_step(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    require(job.count(marker) == 1, f"step is missing or duplicated: {name}")
    start = job.index(marker)
    following = re.search(r"(?m)^      - name: ", job[start + len(marker) :])
    end = (
        start + len(marker) + following.start()
        if following is not None
        else len(job)
    )
    return job[start:end]


def permission_map(job: str, label: str) -> dict[str, str]:
    marker = "    permissions:\n"
    require(job.count(marker) == 1, f"{label} must have one permissions map")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following is not None else len(job)
    block = job[start:end]
    entries = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$",
        block,
    )
    require(entries, f"{label} permissions map is empty")
    require(
        len(entries) == len(dict(entries)),
        f"{label} permissions map contains a duplicate capability",
    )
    return dict(entries)


def dispatch_input_blocks(workflow: str) -> dict[str, str]:
    start_marker = "\n  workflow_dispatch:\n"
    end_marker = "\npermissions: {}\n"
    require(
        workflow.count(start_marker) == 1
        and workflow.count(end_marker) == 1,
        "workflow_dispatch or deny-by-default permissions boundary changed",
    )
    dispatch = workflow.split(start_marker, maxsplit=1)[1].split(
        end_marker, maxsplit=1
    )[0]
    matches = list(
        re.finditer(r"(?m)^      ([a-z][a-z0-9_]*):\n", dispatch)
    )
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(dispatch)
        )
        blocks[match.group(1)] = dispatch[match.start() : end]
    return blocks


def expected_inventory(attest_job: str) -> tuple[str, ...]:
    start_marker = (
        "          expected_files = sorted(\n"
        "              [\n"
    )
    end_marker = "\n              ]\n          )"
    require(
        attest_job.count(start_marker) == 1,
        "attester must construct one explicit literal artifact inventory",
    )
    body = attest_job.split(start_marker, maxsplit=1)[1]
    require(
        end_marker in body,
        "attester literal artifact inventory is unterminated",
    )
    body = body.split(end_marker, maxsplit=1)[0]
    values = re.findall(r'(?m)^\s+"([^"]+)",$', body)
    require(
        len(values) == len(body.splitlines()),
        "attester expected inventory contains a non-literal entry",
    )
    return tuple(values)


def require_tokens(text: str, label: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def validate_workflow(workflow: str) -> None:
    require("\t" not in workflow, "workflow must not contain tab indentation")
    require(
        workflow.startswith("name: Submission judge journey\n"),
        "workflow identity changed",
    )

    inputs = dispatch_input_blocks(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch must expose exactly six ordered scalar identifiers",
    )
    for name, block in inputs.items():
        require(
            block.count("        required: true\n") == 1,
            f"{name} must be required",
        )
        require(
            block.count("        type: string\n") == 1,
            f"{name} must remain a scalar string",
        )
    referenced_inputs = set(
        re.findall(r"\$\{\{\s*inputs\.([a-z][a-z0-9_]*)\s*\}\}", workflow)
    )
    require(
        referenced_inputs == set(EXPECTED_INPUTS),
        "workflow references an undeclared or unused dispatch input",
    )
    require(
        "fromJSON(inputs." not in workflow
        and "fromJson(inputs." not in workflow
        and "github.event.inputs" not in workflow,
        "dispatch identifiers must not become structured payloads",
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
            all(forbidden not in input_name for input_name in inputs),
            f"dispatch must not accept a {forbidden}-bearing input",
        )
    require(
        '[[ "${RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]]' in workflow,
        "release input must be an exact commit digest",
    )
    require(
        '[[ "${run_id}" =~ ^[1-9][0-9]*$ ]]' in workflow,
        "run inputs must be positive scalar IDs",
    )
    require(
        'LC_ALL=C sort -u' in workflow and ')" = "5"' in workflow,
        "five prerequisite run IDs must be distinct",
    )

    require(
        "\npermissions: {}\n" in workflow,
        "top-level permissions must remain deny-by-default",
    )
    require_tokens(
        workflow,
        "concurrency",
        (
            "concurrency:\n"
            "  group: archon-judge-user-production\n"
            "  cancel-in-progress: false",
        ),
    )

    jobs = job_sections(workflow)
    require(
        tuple(jobs) == EXPECTED_JOBS,
        "workflow must contain only prerequisites, journey, and attest jobs",
    )
    prerequisites = jobs["prerequisites"]
    journey = jobs["journey"]
    attest = jobs["attest"]
    resolver = named_step(
        prerequisites, "Resolve exact prerequisite runs and artifacts"
    )
    verification = named_step(
        prerequisites,
        "Verify deployment, ordered lifecycle, and every attestation",
    )
    attester_resolver = named_step(
        attest, "Resolve one immutable producer artifact"
    )
    attester_semantics = named_step(
        attest, "Independently validate exact journey bytes and semantics"
    )
    attester_recheck = named_step(
        attest, "Recheck canonical state immediately before attestation"
    )
    attester_action = named_step(
        attest, "Attest the exact sanitized journey subjects"
    )
    require(
        permission_map(prerequisites, "prerequisites")
        == {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "prerequisites permissions are not exact read-only capabilities",
    )
    require(
        permission_map(journey, "journey")
        == {"actions": "read", "contents": "read"},
        "journey permissions are not exact read-only capabilities",
    )
    require(
        permission_map(attest, "attest")
        == {
            "actions": "read",
            "attestations": "write",
            "contents": "read",
            "id-token": "write",
        },
        "attester permissions are not exact isolated write capabilities",
    )
    require(
        workflow.count("    environment: judge-access-production\n") == 1
        and "    environment: judge-access-production\n" in journey,
        "only the browser journey may use the protected environment",
    )
    require(
        "    environment:" not in prerequisites
        and "    environment:" not in attest,
        "unprivileged prerequisite and attester jobs must not use environments",
    )
    require(
        workflow.count("      attestations: write\n") == 1
        and workflow.count("      id-token: write\n") == 1,
        "attestation write and OIDC capabilities must exist only once",
    )
    require(
        "    needs: prerequisites\n" in journey
        and "    needs: journey\n" in attest,
        "job dependency chain must be prerequisites -> journey -> attest",
    )

    protected = named_step(
        journey, "Run the protected reject-only browser journey"
    )
    observer = named_step(
        journey, "Reobserve terminal state without protected values"
    )
    cleanup = named_step(
        journey, "Remove transient observer capability on every path"
    )
    package = named_step(
        journey, "Recheck release and package sanitized journey evidence"
    )
    upload = named_step(journey, "Upload immutable sanitized journey evidence")
    sensitive_bindings = (
        "JUDGE_USERNAME: ${{ secrets.JUDGE_USERNAME }}",
        "JUDGE_PASSWORD: ${{ secrets.JUDGE_PASSWORD }}",
        "JUDGE_ACCOUNT_ID: ${{ vars.JUDGE_PRODUCTION_ACCOUNT_ID }}",
    )
    for binding in sensitive_bindings:
        require(
            workflow.count(binding) == 1 and binding in protected,
            f"protected binding escaped its single browser step: {binding}",
        )
    for protected_name, expected_count in {
        "JUDGE_USERNAME": 2,
        "JUDGE_PASSWORD": 2,
        "JUDGE_ACCOUNT_ID": 1,
        "JUDGE_PRODUCTION_ACCOUNT_ID": 1,
    }.items():
        require(
            workflow.count(protected_name) == expected_count,
            f"protected variable appears outside its exact binding: {protected_name}",
        )
    sensitive_references = set(
        re.findall(
            r"\$\{\{\s*(?:secrets|vars)\.([A-Za-z0-9_]+)\s*\}\}",
            workflow,
        )
    )
    require(
        sensitive_references
        == {
            "JUDGE_USERNAME",
            "JUDGE_PASSWORD",
            "JUDGE_PRODUCTION_ACCOUNT_ID",
        },
        "workflow contains an unexpected or missing protected reference",
    )
    workflow_without_protected = workflow.replace(protected, "", 1)
    require(
        "${{ secrets." not in workflow_without_protected
        and "${{ vars." not in workflow_without_protected,
        "protected values must not reach observer, packaging, or attester steps",
    )

    current_release_tokens = (
        "submission-judge-journey.yml@refs/heads/master",
        'test "${GITHUB_REF}" = "refs/heads/master"',
        "/repos/${GITHUB_REPOSITORY}/git/ref/heads/master",
        'test "${current_release}" = "${RELEASE_SHA}"',
    )
    for label, job in (
        ("prerequisites", prerequisites),
        ("journey", journey),
        ("attest", attest),
    ):
        require_tokens(job, label, current_release_tokens)

    latest_deployment_tokens = (
        "/actions/workflows/deploy.yml/runs?"
        "branch=master&event=workflow_dispatch&per_page=100",
        '.path == ".github/workflows/deploy.yml"',
        '.event == "workflow_dispatch"',
        '.status == "completed"',
        '.conclusion == "success"',
        '.head_branch == "master"',
        ".head_repository.full_name == $repository",
        "sort_by(.id, .run_attempt)",
    )
    for label, job in (
        ("prerequisites", prerequisites),
        ("journey", journey),
        ("attest", attest),
    ):
        require_tokens(job, label, latest_deployment_tokens)

    closed_lifecycle_tokens = (
        "/actions/workflows/judge-user.yml/runs?"
        "branch=master&event=workflow_dispatch&per_page=100",
        '.path == ".github/workflows/judge-user.yml"',
        '.event == "workflow_dispatch"',
        ".head_sha == $release",
        '.head_branch == "master"',
        ".head_repository.full_name == $repository",
        '.status == "completed"',
        '.conclusion == "success"',
        ".[-4:]",
        '{id: $provision, operation: "provision"}',
        '{id: $rotate, operation: "rotate"}',
        '{id: $deactivate, operation: "deactivate"}',
        '{id: $reactivate, operation: "reactivate"}',
        "all($production[]; .id <= $reactivate)",
    )
    for label, job in (("journey", journey), ("attest", attest)):
        require_tokens(job, label, closed_lifecycle_tokens)

    require(
        resolver.count(".workflow_run.id == $runId") == 2
        and resolver.count(".workflow_run.head_sha == $release") == 2,
        "prerequisite artifacts must bind both deployment and lifecycle owners",
    )
    require_tokens(
        resolver,
        "prerequisite artifact ownership",
        (
            ".expired == false",
            '(.digest | test("^sha256:[0-9a-f]{64}$"))',
            'else error("expected one exact deployment artifact")',
            'else error("expected one exact lifecycle artifact")',
        ),
    )
    require(
        verification.count(") == $expectedSubjects") == 2,
        "deployment and lifecycle attestations must bind their full subject sets",
    )
    require_tokens(
        verification,
        "prerequisite attestations",
        (
            'gh attestation verify "${deployment_evidence}"',
            'gh attestation verify "${subject_path}"',
            "--signer-digest",
            "--source-digest",
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "exactly one deployment attestation must bind the full subject set",
            "exactly one lifecycle attestation must bind the full subject set",
        ),
    )

    sidecar = "terminal-observer-capability.json"
    require_tokens(
        observer,
        "independent observer",
        (
            f'capability="${{journey_dir}}/{sidecar}"',
            "trap cleanup_capability EXIT",
            'test -f "${capability}"',
            'rm -- "${capability}"',
            "trap - EXIT",
        ),
    )
    require(
        "        if: always()\n" in cleanup
        and f"/live-judge-journey/{sidecar}" in cleanup
        and "rm -f --" in cleanup,
        "transient observer capability needs unconditional cleanup",
    )
    require(
        package.count(f"/{sidecar}") == 2
        and package.count("          test ! -e \\\n") >= 2,
        "packaging must reject the observer capability before and after sealing",
    )
    require(
        sidecar not in upload
        and "path: ${{ runner.temp }}/submission-judge-journey-evidence"
        in upload
        and "live-judge-journey" not in upload,
        "transient capability must never enter the uploaded artifact",
    )
    package_lifecycle_bindings = (
        "PROVISION_RUN_ID: ${{ inputs.provision_run_id }}",
        "ROTATE_RUN_ID: ${{ inputs.rotate_run_id }}",
        "DEACTIVATE_RUN_ID: ${{ inputs.deactivate_run_id }}",
        "REACTIVATE_RUN_ID: ${{ inputs.reactivate_run_id }}",
        '--argjson provision "${PROVISION_RUN_ID}"',
        '--argjson rotate "${ROTATE_RUN_ID}"',
        '--argjson deactivate "${DEACTIVATE_RUN_ID}"',
        '--argjson reactivate "${REACTIVATE_RUN_ID}"',
        '{id: $provision, operation: "provision"}',
        '{id: $rotate, operation: "rotate"}',
        '{id: $deactivate, operation: "deactivate"}',
        '{id: $reactivate, operation: "reactivate"}',
    )
    for binding in package_lifecycle_bindings:
        require(
            package.count(binding) == 1,
            f"package step lost exact lifecycle binding: {binding}",
        )

    for role, filename in EXPECTED_PRIMARY_SUBJECTS.items():
        require(
            f'("{role}", "{filename}")' in package,
            f"primary subject role changed: {role}",
        )
    require_tokens(
        package,
        "producer evidence inventory",
        (
            'retained != sorted([*final_names, "SHA256SUMS"])',
            "journey artifact inventory is not exact",
            "journey-subject.sha256",
            MANIFEST_SCHEMA,
            PREDICATE_SCHEMA,
        ),
    )
    require(
        expected_inventory(attest) == EXPECTED_ARTIFACT_FILES,
        "attester artifact inventory is not the exact nine-file tree",
    )
    for filename in EXPECTED_ARTIFACT_FILES:
        require(
            filename in attest,
            f"attester does not semantically consume {filename}",
        )
    require(
        sidecar not in expected_inventory(attest),
        "transient sidecar appeared in attester inventory",
    )
    require_tokens(
        attester_semantics,
        "attester semantic validation",
        (
            "len(checksum_lines) != 8",
            "checksum_names != expected_checksum_names",
            '"journey-subject.sha256").read_bytes()',
            "!= expected_subject_lines",
            MANIFEST_SCHEMA,
            PREDICATE_SCHEMA,
            'manifest["subjects"] != expected_subjects',
            'predicate["subjects"] != expected_subjects',
        ),
    )
    require_tokens(
        attester_semantics,
        "network counter inventory",
        tuple(f'"{counter}",' for counter in EXPECTED_NETWORK_COUNTERS),
    )
    require_tokens(
        attester_semantics,
        "network counter numeric boundary",
        (
            "for name, value in network.items():",
            "isinstance(value, bool)",
            "not isinstance(value, int)",
            "or value < 0",
            "network counter {name} is not a non-negative integer",
        ),
    )
    require_tokens(
        attester_semantics,
        "network journey cardinality",
        (
            'network["startRequests"] != 1',
            'network["decisionRequests"] != 1',
            'network["tokenRequests"] != 1',
            'network["authorizationRequests"] != 2',
            'network["callbackRequests"] != 1',
            'network["logoutRequests"] != 1',
            'network["allowedApplicationRequests"] < 1',
            'network["allowedHostedUiRequests"] < 1',
            'network["unexpectedRequests"] != 0',
            'network["blockedWebSockets"] != 0',
            'network["serviceWorkerViolations"] != 0',
        ),
    )
    require(
        attester_semantics.count('"allowedIssuerRequests"') == 1
        and "'allowedIssuerRequests'" not in attester_semantics
        and 'network["allowedIssuerRequests"]' not in attester_semantics,
        "issuer requests must allow zero and use only the shared counter boundary",
    )

    require(
        workflow.count(f"  PREDICATE_TYPE: {PREDICATE_TYPE}\n") == 1,
        "predicate type must have one canonical workflow definition",
    )
    require(
        "ARTIFACT_NAME="
        '"submission-judge-journey-${RELEASE_SHA}-${GITHUB_RUN_ATTEMPT}"'
        in package,
        "producer artifact name must bind the producing attempt",
    )
    require_tokens(
        attester_resolver,
        "attester-only retry",
        (
            "/actions/runs/${GITHUB_RUN_ID}/artifacts?per_page=100",
            'pattern="^submission-judge-journey-${RELEASE_SHA}-'
            '(?<attempt>[1-9][0-9]*)$"',
            "capture($pattern)",
            ".attempt |",
            "tonumber",
            "select($producerAttempt <= $currentAttempt)",
            'producer_attempt="$(\n'
            "            jq -er '.producerAttempt' <<<\"${selected}\"",
            "$artifact.workflow_run.id == $runId",
            "$artifact.workflow_run.head_sha == $release",
            "$artifact.expired == false",
            "] as $eligible",
            "if ($eligible | length) == 0 then",
            "no eligible immutable journey artifact exists",
            "map(.producerAttempt)",
            "max",
            "as $latestAttempt",
            "select(.producerAttempt == $latestAttempt)",
            'if length == 1 then .[0]',
            "latest producer attempt has ambiguous journey artifacts",
        ),
    )
    require(
        "expected exactly one eligible immutable journey artifact"
        not in attester_resolver,
        "attester must allow older immutable artifacts from full reruns",
    )
    require_tokens(
        attester_semantics,
        "producer-attempt manifest binding",
        (
            '"runAttempt": producer_attempt',
            'manifest["artifactName"] != artifact_name',
            'predicate["source"] != expected_source',
            'predicate["artifactName"] != artifact_name',
        ),
    )
    require(
        "${{ needs.journey.outputs." not in attest
        and "artifact-ids: ${{ steps.artifact.outputs.artifact_id }}"
        in attest
        and "actions/download-artifact@" in attest
        and attest.index("/actions/runs/${GITHUB_RUN_ID}/artifacts")
        < attest.index("actions/download-artifact@"),
        "attester must resolve immutable ownership before exact-ID download",
    )
    require_tokens(
        attester_recheck,
        "pre-attestation ownership and canonical-state recheck",
        (
            "/actions/artifacts/${JOURNEY_ARTIFACT_ID}",
            ".id == $artifactId",
            ".name == $name",
            ".digest == $digest",
            ".expired == false",
            ".workflow_run.id == $runId",
            ".workflow_run.head_sha == $release",
            "/actions/artifacts/${artifact_id}",
            "/actions/runs/${run_id}",
            "bash scripts/verify-github-control-plane.sh",
            'test "${latest_deployment}" = "${DEPLOYMENT_RUN_ID}"',
            "all($production[]; .id <= $reactivate)",
        ),
    )
    require_tokens(
        attester_action,
        "custom attestation",
        (
            "subject-checksums: "
            "${{ runner.temp }}/submission-judge-journey-attestation/"
            "journey-subject.sha256",
            "predicate-path: "
            "${{ runner.temp }}/submission-judge-journey-attestation/"
            "attestation-predicate.json",
            "predicate-type: ${{ env.PREDICATE_TYPE }}",
        ),
    )

    action_references = re.findall(
        r"(?m)^\s+uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
        workflow,
    )
    all_uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", workflow)
    require(action_references, "workflow contains no pinned actions")
    require(
        len(action_references) == len(all_uses),
        "workflow contains a non-registry or unversioned action reference",
    )
    for action, reference in action_references:
        require(
            re.fullmatch(r"[0-9a-f]{40}", reference) is not None,
            f"{action} is not commit-SHA pinned",
        )
    for action, digest in ACTION_PINS.items():
        require(
            f"{action}@{digest}" in workflow,
            f"required action pin changed: {action}",
        )
    require(
        attest.count(
            "actions/attest@"
            "59d89421af93a897026c735860bf21b6eb4f7b26"
        )
        == 1,
        "attester must issue exactly one custom attestation",
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
        f"tamper fixture no longer has expected marker: {old}",
    )
    return workflow.replace(old, new, count)


def replace_in_job(
    workflow: str,
    job_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    require(job_name in jobs, f"tamper fixture lacks job: {job_name}")
    original = jobs[job_name]
    require(old in original, f"tamper marker is absent from {job_name}: {old}")
    mutated = original.replace(old, new, 1)
    return workflow.replace(original, mutated, 1)


def replace_in_step(
    workflow: str,
    job_name: str,
    step_name: str,
    old: str,
    new: str,
) -> str:
    jobs = job_sections(workflow)
    require(job_name in jobs, f"tamper fixture lacks job: {job_name}")
    original_job = jobs[job_name]
    original_step = named_step(original_job, step_name)
    require(old in original_step, f"tamper marker is absent from {step_name}: {old}")
    mutated_step = original_step.replace(old, new, 1)
    mutated_job = original_job.replace(original_step, mutated_step, 1)
    return workflow.replace(original_job, mutated_job, 1)


def expect_rejected(label: str, workflow: str) -> None:
    try:
        validate_workflow(workflow)
    except ContractError:
        return
    raise AssertionError(f"workflow tamper was accepted: {label}")


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
validate_workflow(workflow_text)

tamper_cases = {
    "remove scalar input": replace_exact(
        workflow_text,
        "      rotate_run_id:\n",
        "      rotate_run_id_removed:\n",
    ),
    "add stage input": replace_exact(
        workflow_text,
        "\npermissions: {}\n",
        (
            "      stage:\n"
            "        description: Unsafe caller-selected stage\n"
            "        required: true\n"
            "        type: string\n"
            "\npermissions: {}\n"
        ),
    ),
    "structured input": replace_exact(
        workflow_text,
        "        type: string\n",
        "        type: boolean\n",
    ),
    "cancel protected concurrency": replace_exact(
        workflow_text,
        "  cancel-in-progress: false",
        "  cancel-in-progress: true",
    ),
    "journey gains write permission": replace_in_job(
        workflow_text,
        "journey",
        "      contents: read\n",
        "      contents: write\n",
    ),
    "attester gains protected environment": replace_in_job(
        workflow_text,
        "attest",
        "    runs-on: ubuntu-24.04\n",
        (
            "    environment: judge-access-production\n"
            "    runs-on: ubuntu-24.04\n"
        ),
    ),
    "observer receives a secret": replace_exact(
        workflow_text,
        "      - name: Reobserve terminal state without protected values\n",
        (
            "      - name: Reobserve terminal state without protected values\n"
            "        # ${{ secrets.JUDGE_PASSWORD }}\n"
        ),
    ),
    "stale release accepted": replace_exact(
        workflow_text,
        'test "${current_release}" = "${RELEASE_SHA}"',
        'test -n "${current_release}"',
        count=workflow_text.count(
            'test "${current_release}" = "${RELEASE_SHA}"'
        ),
    ),
    "latest deployment check removed": replace_exact(
        workflow_text,
        ".conclusion == \"success\"",
        "true",
        count=workflow_text.count('.conclusion == "success"'),
    ),
    "later lifecycle check removed": replace_exact(
        workflow_text,
        "all($production[]; .id <= $reactivate)",
        "all($production[]; true)",
        count=workflow_text.count(
            "all($production[]; .id <= $reactivate)"
        ),
    ),
    "package drops lifecycle input": replace_in_step(
        workflow_text,
        "journey",
        "Recheck release and package sanitized journey evidence",
        "          PROVISION_RUN_ID: ${{ inputs.provision_run_id }}\n",
        "",
    ),
    "artifact owner removed": replace_in_job(
        workflow_text,
        "prerequisites",
        ".workflow_run.id == $runId",
        "true",
    ),
    "final journey artifact owner removed": replace_exact(
        workflow_text,
        "/actions/artifacts/${JOURNEY_ARTIFACT_ID}",
        "/actions/artifacts/0",
    ),
    "full subject set removed": replace_in_job(
        workflow_text,
        "prerequisites",
        ") == $expectedSubjects",
        ") != []",
    ),
    "attester full subject set removed": replace_in_job(
        workflow_text,
        "attest",
        'manifest["subjects"] != expected_subjects',
        "False",
    ),
    "negative network counter accepted": replace_in_step(
        workflow_text,
        "attest",
        "Independently validate exact journey bytes and semantics",
        "                  or value < 0\n",
        "                  or value < -1\n",
    ),
    "issuer request incorrectly required": replace_in_step(
        workflow_text,
        "attest",
        "Independently validate exact journey bytes and semantics",
        '              or network["unexpectedRequests"] != 0\n',
        (
            '              or network["allowedIssuerRequests"] < 1\n'
            '              or network["unexpectedRequests"] != 0\n'
        ),
    ),
    "sidecar cleanup removed": replace_exact(
        workflow_text,
        '          rm -- "${capability}"\n',
        "          true\n",
    ),
    "extra artifact file": replace_in_job(
        workflow_text,
        "attest",
        '                  "terminal-observation.json",\n',
        (
            '                  "unexpected.json",\n'
            '                  "terminal-observation.json",\n'
        ),
    ),
    "manifest schema changed": workflow_text.replace(
        MANIFEST_SCHEMA,
        "archon.submission-judge-journey-manifest/v2",
    ),
    "predicate schema changed": workflow_text.replace(
        PREDICATE_SCHEMA,
        "archon.submission-judge-journey-attestation/v2",
    ),
    "predicate type changed": workflow_text.replace(
        PREDICATE_TYPE,
        "https://example.invalid/unsafe-predicate/v1",
    ),
    "floating action reference": replace_exact(
        workflow_text,
        (
            "actions/attest@"
            "59d89421af93a897026c735860bf21b6eb4f7b26"
        ),
        "actions/attest@v4",
    ),
    "retry attempt equality": replace_in_job(
        workflow_text,
        "attest",
        "select($producerAttempt <= $currentAttempt)",
        "select($producerAttempt == $currentAttempt)",
    ),
    "oldest producer attempt selected": replace_in_step(
        workflow_text,
        "attest",
        "Resolve one immutable producer artifact",
        "                    max\n",
        "                    min\n",
    ),
    "duplicate latest artifacts accepted": replace_in_step(
        workflow_text,
        "attest",
        "                  if length == 1 then .[0]\n",
        "                  if length >= 1 then .[0]\n",
    ),
    "attest wrong subject inventory": replace_in_job(
        workflow_text,
        "attest",
        (
            "subject-checksums: "
            "${{ runner.temp }}/submission-judge-journey-attestation/"
            "journey-subject.sha256"
        ),
        (
            "subject-checksums: "
            "${{ runner.temp }}/submission-judge-journey-attestation/"
            "SHA256SUMS"
        ),
    ),
}
for tamper_label, tampered_workflow in tamper_cases.items():
    expect_rejected(tamper_label, tampered_workflow)

print(
    json.dumps(
        {
            "schemaVersion":
                "archon.submission-judge-journey-contract-test/v1",
            "artifactFiles": list(EXPECTED_ARTIFACT_FILES),
            "dispatchInputs": list(EXPECTED_INPUTS),
            "tamperCases": sorted(tamper_cases),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
