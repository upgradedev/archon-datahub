#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for the BONUS-OSS producer."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/submission-bonus-oss.yml"
COLLECTOR_PATH = ROOT / "scripts/collect-submission-bonus-oss.py"
CONTRIB_VERIFIER_PATH = ROOT / "scripts/verify-contrib.mjs"
DOCUMENTATION_PATH = ROOT / "docs/SUBMISSION_BONUS_OSS.md"
EXPECTED_INPUTS = (
    "release_sha",
    "ci_run_id",
    "upstream_pull_request_number",
)
EXPECTED_JOBS = ("produce", "attest")
EXPECTED_PRODUCE_STEPS = (
    "Bind dispatch to the exact current release and scalar inputs",
    "Check out the exact unprivileged producer",
    "Verify the merged-status and repository control-plane contracts",
    "Collect the exact CI receipt to merged upstream byte binding",
    "Assemble the exact registered BONUS OSS subjects",
    "Recollect every external identity before retention",
    "Retain the exact BONUS OSS standard subjects",
)
EXPECTED_ATTEST_STEPS = (
    "Bind attester to the exact current release and workflow run",
    "Check out the exact unprivileged attester",
    "Independently resolve the latest retained producer artifact",
    "Download the exact immutable producer artifact",
    "Independently reconstruct all CI and upstream facts",
    "Recollect and recheck every immutable identity before attestation",
    "Attest all four exact BONUS OSS subjects",
    "Verify persisted signed full-subject attestation",
)
EXPECTED_STANDARD_FILES = (
    "SHA256SUMS",
    "attestation-predicate.json",
    "proofs/BONUS-OSS.json",
    "support/BONUS-OSS/ci-validation.json",
    "support/BONUS-OSS/upstream-pr.json",
)
EXPECTED_UPSTREAM_PATHS = (
    "src/mcp_server_datahub/mcp_server.py",
    "src/mcp_server_datahub/tools/__init__.py",
    "src/mcp_server_datahub/tools/aspect_history.py",
    "tests/test_mcp/test_get_aspect_history.py",
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


class ContractError(AssertionError):
    """Raised when an OSS evidence trust boundary is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_tokens(text: str, label: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def job_sections(workflow: str) -> dict[str, str]:
    marker = "\njobs:\n"
    require(workflow.count(marker) == 1, "workflow must define one jobs map")
    body = workflow.split(marker, maxsplit=1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", body))
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
    require(bool(boundaries), "job must contain named steps")
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
            else len(body)
        )
        steps.append((name, body[boundary.start() : end]))
    return tuple(steps)


def step_names(job: str) -> tuple[str, ...]:
    return tuple(name for name, _ in job_steps(job))


def named_step(job: str, name: str) -> str:
    matches = tuple(
        section for step_name, section in job_steps(job) if step_name == name
    )
    require(len(matches) == 1, f"step is missing or duplicated: {name}")
    return matches[0]


def permission_map(job: str, label: str) -> dict[str, str]:
    marker = "    permissions:\n"
    require(job.count(marker) == 1, f"{label} must define one permission map")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following is not None else len(job)
    entries = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$",
        job[start:end],
    )
    require(
        bool(entries) and len(entries) == len(dict(entries)),
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


def validate_workflow(workflow: str) -> None:
    require("\t" not in workflow, "workflow must not contain tabs")
    require(
        workflow.startswith("name: Submission BONUS OSS\n"),
        "workflow identity changed",
    )
    inputs = dispatch_inputs(workflow)
    require(
        tuple(inputs) == EXPECTED_INPUTS,
        "dispatch must expose exactly three ordered scalar identifiers",
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
        "${{ secrets." not in workflow
        and "${{ vars." not in workflow
        and re.search(r"(?m)^\s+environment:", workflow) is None,
        "BONUS-OSS workflow must not consume protected configuration",
    )
    require(
        "\npermissions: {}\n" in workflow,
        "top-level permissions must remain deny-by-default",
    )
    require(
        "\nconcurrency:\n"
        "  group: submission-bonus-oss-${{ inputs.release_sha }}\n"
        "  cancel-in-progress: false\n" in workflow,
        "release-scoped non-cancelling serialization changed",
    )
    require(
        workflow.count("runs-on: ubuntu-24.04") == 2,
        "both jobs must remain GitHub-hosted Ubuntu 24.04 jobs",
    )
    require(
        "self-hosted" not in "\n".join(
            line
            for line in workflow.splitlines()
            if line.strip() != "--deny-self-hosted-runners \\"
        ),
        "self-hosted execution entered the workflow",
    )
    require(
        workflow.count(
            "  PREDICATE_TYPE: "
            "https://archon.datahub.dev/attestations/"
            "submission-bonus-oss/v1\n"
        )
        == 1,
        "custom BONUS-OSS predicate type changed",
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
        and workflow.count("id-token: write") == 1
        and "    needs: produce\n" in attest,
        "signing authority escaped the isolated dependent attester",
    )
    require(
        "${{ needs.produce.outputs." not in attest,
        "attester must not trust producer-selected outputs",
    )
    require(
        workflow.count("node scripts/verify-contrib.mjs") == 2,
        "producer and attester must independently verify manifest status",
    )
    require(
        workflow.count("bash scripts/verify-github-control-plane.sh") == 2,
        "producer and attester must independently enforce control-plane gates",
    )
    require(
        workflow.count(
            "python3 scripts/collect-submission-bonus-oss.py collect"
        )
        == 4,
        "both jobs must independently collect and recollect all facts",
    )

    first_collect = named_step(
        produce,
        "Collect the exact CI receipt to merged upstream byte binding",
    )
    require_tokens(
        first_collect,
        "producer collection",
        (
            "--repository \"${GITHUB_REPOSITORY}\"",
            "--release-sha \"${RELEASE_SHA}\"",
            "--ci-run-id \"${CI_RUN_ID}\"",
            "--upstream-pull-request-number",
            ".state == \"merged\"",
            ".publiclyAccessible == true",
            ".acceptedByMaintainer == true",
            ".candidateBinding.exactHeadTreeMatch == true",
            ".candidateBinding.exactMergedPathBytesMatch == true",
            ".validatedCandidateDigest ==",
            ".candidateBinding.canonicalFileManifestDigest",
            ".ciValidation.artifactProducerAttempt <=",
            ".ciValidation.runAttempt",
        ),
    )

    assembly = named_step(
        produce,
        "Assemble the exact registered BONUS OSS subjects",
    )
    require_tokens(
        assembly,
        "registered standard-v1 assembly",
        (
            "assemble-standard",
            "validate-standard-source",
            "--source-key bonus-oss",
            "--registry scripts/submission-evidence-registry.json",
            "--run-id \"${GITHUB_RUN_ID}\"",
            "--run-attempt \"${GITHUB_RUN_ATTEMPT}\"",
            ".subjectCount == 4",
            ".proofIds == [\"BONUS-OSS\"]",
            ".result == \"verified\"",
            "sha256sum --check --strict SHA256SUMS",
        ),
    )
    for filename in EXPECTED_STANDARD_FILES:
        require(filename in assembly, f"assembly lost exact subject {filename}")
    require(
        assembly.count("--source-key bonus-oss") == 2,
        "assembly and validation must use the same registered source",
    )

    producer_recollect = named_step(
        produce,
        "Recollect every external identity before retention",
    )
    attester_recollect = named_step(
        attest,
        "Recollect and recheck every immutable identity before attestation",
    )
    for label, step in (
        ("producer TOCTOU recollection", producer_recollect),
        ("attester TOCTOU recollection", attester_recollect),
    ):
        require_tokens(
            step,
            label,
            (
                "collect-submission-bonus-oss.py collect",
                "cmp --silent",
                "/git/ref/heads/master",
                "git diff --quiet",
                "git diff --cached --quiet",
                "git ls-files --others --exclude-standard",
            ),
        )

    upload = named_step(
        produce,
        "Retain the exact BONUS OSS standard subjects",
    )
    require_tokens(
        upload,
        "attempt-scoped immutable retention",
        (
            "actions/upload-artifact@",
            "name: submission-bonus-oss-${{ inputs.release_sha }}-"
            "${{ github.run_attempt }}",
            "path: ${{ runner.temp }}/submission-bonus-oss",
            "if-no-files-found: error",
            "retention-days: 90",
            "overwrite: true",
        ),
    )
    require(
        upload.count(
            "          name: submission-bonus-oss-"
            "${{ inputs.release_sha }}-${{ github.run_attempt }}\n"
        )
        == 1,
        "BONUS-OSS upload name must remain exactly attempt scoped",
    )

    resolver = named_step(
        attest,
        "Independently resolve the latest retained producer artifact",
    )
    require_tokens(
        resolver,
        "independent producer resolver",
        (
            "select-run-artifact",
            "--policy latest-retained",
            '"submission-bonus-oss-${RELEASE_SHA}-"',
            "--run-id \"${GITHUB_RUN_ID}\"",
            "--release-sha \"${RELEASE_SHA}\"",
            "--maximum-attempt \"${GITHUB_RUN_ATTEMPT}\"",
            ".producerAttempt",
            ".metadata.id",
            ".metadata.name",
            ".metadata.digest",
            "/attempts/${producer_attempt}/jobs?per_page=100",
            '"Produce exact merged upstream contribution evidence"',
            '.status == "completed"',
            '.conclusion == "success"',
            ".metadata.created_at >= $startedAt",
            ".metadata.created_at <= $completedAt",
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
            "artifact-ids: ${{ steps.producer.outputs.artifact_id }}",
            "path: ${{ runner.temp }}/submission-bonus-oss-attestation",
            "github-token: ${{ github.token }}",
            "merge-multiple: true",
        ),
    )

    independent = named_step(
        attest,
        "Independently reconstruct all CI and upstream facts",
    )
    require_tokens(
        independent,
        "independent retained-source validation",
        (
            "collect-submission-bonus-oss.py collect",
            "validate-standard-source",
            "--source-key bonus-oss",
            "--run-attempt \"${PRODUCER_ATTEMPT}\"",
            ".subjectCount == 4",
            "sha256sum --check --strict SHA256SUMS",
            "jq -cS '.facts'",
            "cmp --silent",
        ),
    )
    for filename in EXPECTED_STANDARD_FILES:
        require(
            filename in independent,
            f"attester inventory lost exact subject {filename}",
        )
    require_tokens(
        attester_recollect,
        "retained artifact identity recheck",
        (
            "/actions/artifacts/${ARTIFACT_ID}",
            ".id == $artifactId",
            ".name == $name",
            ".digest == $digest",
            ".expired == false",
            ".workflow_run.id == $runId",
            ".workflow_run.head_sha == $release",
        ),
    )

    signing = named_step(
        attest,
        "Attest all four exact BONUS OSS subjects",
    )
    require_tokens(
        signing,
        "custom independent BONUS-OSS attestation",
        (
            "id: attest",
            "actions/attest@",
            "subject-checksums: "
            "${{ runner.temp }}/submission-bonus-oss-attestation/"
            "SHA256SUMS",
            "predicate-type: ${{ env.PREDICATE_TYPE }}",
            "predicate-path: "
            "${{ runner.temp }}/submission-bonus-oss-attestation/"
            "attestation-predicate.json",
        ),
    )
    require(
        workflow.count("        id: attest\n") == 1,
        "the exact signing step must be the sole attestation output authority",
    )

    persisted = named_step(
        attest,
        "Verify persisted signed full-subject attestation",
    )
    require_tokens(
        persisted,
        "persisted full-subject attestation verification",
        (
            "${{ steps.attest.outputs.bundle-path }}",
            "${{ steps.attest.outputs.attestation-id }}",
            "${{ steps.attest.outputs.attestation-url }}",
            '"https://github.com/${GITHUB_REPOSITORY}/attestations/'
            '${ATTESTATION_ID}"',
            'test -f "${ATTESTATION_BUNDLE_PATH}"',
            'test ! -L "${ATTESTATION_BUNDLE_PATH}"',
            "bundle_size >= 1 && bundle_size <= 16777216",
            "length == 1 and",
            '(.[0] | type == "object")',
            "sha256sum --check --strict SHA256SUMS",
            "expected_names=(",
            "attestation-predicate.json",
            "proofs/BONUS-OSS.json",
            "support/BONUS-OSS/ci-validation.json",
            "support/BONUS-OSS/upstream-pr.json",
            'test "${observed_names[*]}" = "${expected_names[*]}"',
            'test "$(jq \'length\' <<<"${expected_subjects}")" = "4"',
            '.attestation == $bundle[0]',
            ".verificationResult.statement.predicateType ==",
            ".verificationResult.statement.predicate ==",
            "sort_by(.name)",
            ") == $expectedSubjects",
            "length == 1",
            "gh attestation verify",
            '--bundle "${ATTESTATION_BUNDLE_PATH}"',
            "--repo \"${GITHUB_REPOSITORY}\"",
            "--predicate-type \"${PREDICATE_TYPE}\"",
            "--signer-workflow",
            "github.com/${GITHUB_REPOSITORY}/.github/workflows/"
            "submission-bonus-oss.yml",
            '--signer-digest "${RELEASE_SHA}"',
            '--source-digest "${RELEASE_SHA}"',
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "for attempt in {1..12}",
            'for index in "${!expected_names[@]}"',
            "Persisted full-subject BONUS-OSS attestation could not be verified",
        ),
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
        "local-bundle and persisted verification cardinalities are not exact",
    )

    action_references = re.findall(
        r"(?m)^\s+uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)",
        workflow,
    )
    all_uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", workflow)
    require(
        bool(action_references) and len(action_references) == len(all_uses),
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


def validate_collector(collector: str) -> None:
    try:
        module = ast.parse(collector)
    except SyntaxError as error:
        raise ContractError(f"collector is not valid Python: {error}") from error
    require("\t" not in collector, "collector must not contain tabs")
    literal_assignments: dict[str, object] = {}
    for node in module.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            try:
                literal_assignments[node.targets[0].id] = ast.literal_eval(
                    node.value
                )
            except (ValueError, TypeError):
                continue
    require(
        literal_assignments.get("EXPECTED_PATHS")
        == EXPECTED_UPSTREAM_PATHS,
        "collector upstream path tuple is not exact",
    )
    require(
        literal_assignments.get("EXPECTED_FILE_STATUS")
        == {
            EXPECTED_UPSTREAM_PATHS[0]: "modified",
            EXPECTED_UPSTREAM_PATHS[1]: "modified",
            EXPECTED_UPSTREAM_PATHS[2]: "added",
            EXPECTED_UPSTREAM_PATHS[3]: "added",
        },
        "collector upstream path status map is not exact",
    )
    require(
        literal_assignments.get("STAGED_SOURCE_BY_DESTINATION")
        == {
            EXPECTED_UPSTREAM_PATHS[2]: (
                "contrib/mcp-get-aspect-history/upstream/"
                "src/mcp_server_datahub/tools/aspect_history.py"
            ),
            EXPECTED_UPSTREAM_PATHS[3]: (
                "contrib/mcp-get-aspect-history/upstream/"
                "tests/test_mcp/test_get_aspect_history.py"
            ),
        },
        "collector staged source mapping is not exact",
    )
    require(
        literal_assignments.get("RECEIPT_FILES")
        == {"SHA256SUMS", "applied.diff", "manifest.json", "receipt.json"}
        and literal_assignments.get("LAMBDA_FILES")
        == {
            "archon-lambdas.tar.gz",
            "archon-lambdas.tar.gz.sha256",
        },
        "collector archive inventories are not exact",
    )
    require(
        literal_assignments.get("CI_GATE_KEYS")
        == {
            "buildTest",
            "container",
            "contribution",
            "dataHubBenchmark",
            "dataHubMcpDependency",
            "infrastructure",
            "judgeEvidence",
            "load",
            "readiness",
            "secretScan",
            "security",
            "web",
        }
        and literal_assignments.get("CI_CAPABILITY_KEYS")
        == {
            "dataHubBenchmarkArtifactDigest",
            "judgeEvidenceArtifactDigest",
            "ossContributionValidationArtifactDigest",
        },
        "collector signed CI predicate key sets are not exact",
    )
    require_tokens(
        collector,
        "canonical upstream constants",
        (
            'REPOSITORY = "upgradedev/archon-datahub"',
            'UPSTREAM_REPOSITORY = "acryldata/mcp-server-datahub"',
            'UPSTREAM_REPOSITORY_URL = "https://github.com/'
            'acryldata/mcp-server-datahub"',
            'UPSTREAM_BRANCH = "main"',
            'UPSTREAM_LICENSE = "Apache-2.0"',
            'CI_WORKFLOW_PATH = ".github/workflows/ci.yml"',
            'RECEIPT_SCHEMA = "archon.oss-validation-receipt/v1"',
            'CANDIDATE_SCHEMA = "archon.oss-candidate-binding/v1"',
            "SUBMISSION_START = dt.datetime(2026, 7, 6, 13, 0, 0",
            "SUBMISSION_DEADLINE = dt.datetime(2026, 8, 10, 21, 0, 0",
        ),
    )
    for path in EXPECTED_UPSTREAM_PATHS:
        require(path in collector, f"collector lost exact upstream path {path}")

    require_tokens(
        collector,
        "credentialless public observation",
        (
            "class RejectRedirects(urllib.request.HTTPRedirectHandler):",
            "raise urllib.error.HTTPError(",
            'parsed.scheme == "https"',
            'parsed.hostname == "api.github.com"',
            "parsed.port is None",
            "parsed.username is None",
            "parsed.password is None",
            'headers["Authorization"] = f"Bearer {self.token}"',
            "public_api = GitHubApi(token=None)",
            "credentialless=True",
            '"GH_TOKEN",',
            '"GITHUB_TOKEN",',
            '"GIT_ALTERNATE_OBJECT_DIRECTORIES",',
            '"GIT_CONFIG_GLOBAL"',
            '"GIT_CONFIG_NOSYSTEM"',
            '"GIT_CONFIG_COUNT"',
            '"GIT_CONFIG_PARAMETERS",',
            '"GIT_CONFIG_KEY_"',
            '"GIT_CONFIG_VALUE_"',
            '"GIT_DIR",',
            '"GIT_EXEC_PATH",',
            '"GIT_INDEX_FILE",',
            '"GIT_OBJECT_DIRECTORY",',
            '"GIT_TEMPLATE_DIR",',
            '"GIT_WORK_TREE",',
            '"credential.helper=",',
            '"http.extraHeader=",',
            '"http.https://github.com/.extraHeader=",',
            '"http.followRedirects=false",',
            "GIT_TERMINAL_PROMPT",
        ),
    )
    require(
        collector.count("public_api = GitHubApi(token=None)") == 1
        and collector.count("own_api = GitHubApi(token=token)") == 1,
        "public and source-repository API identities must remain separated",
    )

    require_tokens(
        collector,
        "safe immutable artifact extraction",
        (
            'f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"',
            "sha256_file(output) == expected_digest",
            "not raw.startswith(\"/\")",
            '"\\\\" not in raw',
            '"\\x00" not in raw',
            'canonical not in {"", ".", ".."}',
            'not canonical.startswith("../")',
            "canonical in allowed_directories",
            "canonical not in seen_directories",
            "mode_type in {0, stat.S_IFDIR}",
            "canonical in expected_files",
            "canonical not in seen_files",
            "mode_type in {0, stat.S_IFREG}",
            "not entry.flag_bits & 0x1",
            "total <= maximum_total",
            'destination.open("xb")',
            "seen_files == expected_files",
        ),
    )

    require_tokens(
        collector,
        "exact current-release CI resolution",
        (
            'run.get("path") == CI_WORKFLOW_PATH',
            'run.get("event") == "push"',
            'run.get("head_sha") == release',
            'run.get("head_branch") == "master"',
            'run["head_repository"].get("full_name") == REPOSITORY',
            'run["repository"].get("full_name") == REPOSITORY',
            'run.get("status") == "completed"',
            'run.get("conclusion") == "success"',
            'require(current_attempt <= 20',
            '"CI run is not the latest successful release run"',
            '"DataHub ecosystem contribution"',
            '"AWS CDK build, test, synth, IaC gate"',
            '"Sign exact CI release candidates"',
            '<= parse_utc(attestation_job["started_at"], "attestation start")',
            'f"oss-validation-receipt-{release}"',
            'f"lambdas-{release}"',
            "artifact.get(\"expired\") is False",
            'not isinstance(artifact.get("id"), bool)',
            'not isinstance(artifact.get("size_in_bytes"), bool)',
            'artifact["workflow_run"].get("id") == ci_run_id',
            'artifact["workflow_run"].get("head_sha") == release',
            "started",
            '<= parse_utc(artifact.get("created_at"), f"{name} creation")',
            "<= completed",
        ),
    )

    require_tokens(
        collector,
        "phase-aware merged manifest and public acceptance",
        (
            'manifest.get("schemaVersion") == 2',
            '"state": "merged-upstream"',
            '"pullRequestOpened": True',
            '"appliedToUpstream": True',
            '"localBuildRun": False',
            '"localTestsRun": False',
            '"localSecurityScanRun": False',
            'repository.get("full_name") == UPSTREAM_REPOSITORY',
            'repository.get("private") is False',
            'repository.get("visibility") == "public"',
            'repository.get("default_branch") == UPSTREAM_BRANCH',
            'repository["license"].get("spdx_id") == UPSTREAM_LICENSE',
            'pull.get("state") == "closed"',
            'pull.get("merged") is True',
            'pull.get("draft") is False',
            'pull["base"].get("ref") == UPSTREAM_BRANCH',
            'pull["base"].get("sha") == base_commit',
            'pull["base"]["repo"].get("full_name") == UPSTREAM_REPOSITORY',
            'pull["head"].get("sha") == manifest_status["headSha"]',
            'pull.get("changed_files") == len(EXPECTED_PATHS)',
            'positive_int(author.get("id"), "PR author ID")',
            '!= positive_int(merger.get("id"), "PR merger ID")',
            'file.get("status") == EXPECTED_FILE_STATUS[file["filename"]]',
            '"previous_filename" not in file',
            'accept="application/vnd.github.v3.diff"',
        ),
    )

    require_tokens(
        collector,
        "exact CI receipt binding",
        (
            "seen_files == expected_files",
            'len(lines) == 3',
            'expected_sum_names = ["applied.diff", "manifest.json", '
            '"receipt.json"]',
            '(root / "manifest.json").read_bytes() == manifest_bytes',
            'receipt["schemaVersion"] == RECEIPT_SCHEMA',
            '"eventName": "push"',
            '"pullRequestHeadSha": None',
            '"credentialsIncluded": False',
            '"format": "git-diff-binary-full-index"',
            'candidate["files"] == expected_files',
            'validation["result"] == "pass"',
            '"setupResult": "pass"',
            '{**entry, "result": "pass"}',
        ),
    )

    require_tokens(
        collector,
        "candidate/base/head/merge byte reconstruction",
        (
            '"fetch", "--quiet", "--no-tags", "--depth=1", "origin", '
            "base_commit",
            '"apply", "--binary", "--index"',
            '"diff",',
            '"--binary",',
            '"--full-index",',
            "tuple(changed) == EXPECTED_PATHS",
            "diff_bytes(repository) == applied_diff",
            '"clean",',
            '"-fdx",',
            '"apply",',
            '"--check",',
            "release_tree == candidate_tree",
            'f"refs/pull/{pr_number}/head"',
            "fetched_head == head_sha",
            "head_tree == candidate_tree",
            "fetched_merge == merge_commit_sha",
            "(candidate_mode, candidate_bytes) == (merge_mode, merge_bytes)",
            '"gitBlobSha": candidate_blob',
            '"sha256": sha256_bytes(candidate_bytes)',
            '"canonicalFileManifestDigest": candidate_digest',
            '"exactHeadTreeMatch": True',
            '"exactMergedPathBytesMatch": True',
        ),
    )

    require_tokens(
        collector,
        "signed CI receipt evidence",
        (
            '"attestation",',
            '"verify",',
            '"--signer-workflow",',
            '"--signer-digest",',
            '"--source-digest",',
            '"--source-ref",',
            '"refs/heads/master",',
            '"--predicate-type",',
            '"--deny-self-hosted-runners",',
            'statement.get("predicateType") != CI_PREDICATE_TYPE',
            'set(predicate) != {',
            'predicate.get("schemaVersion") != CI_PREDICATE_SCHEMA',
            '"runAttempt": ci_attempt',
            "set(gates) != CI_GATE_KEYS",
            'any(value != "success" for value in gates.values())',
            'capability.get("ossContributionValidationArtifactDigest")',
            "!= receipt_artifact_digest",
            'release_artifacts["judgeEvidence"]["digest"]',
            '!= capability["judgeEvidenceArtifactDigest"]',
            '"archon-image.tar.gz"',
            '"archon-lambdas.tar.gz"',
            '"archon-web.tar.gz"',
            "len(matching) == 1",
        ),
    )

    require_tokens(
        collector,
        "canonical facts and ephemeral cleanup",
        (
            '"schemaVersion": CANDIDATE_SCHEMA',
            '"upstreamRepository": UPSTREAM_REPOSITORY',
            "candidate_digest = sha256_bytes(canonical_json_bytes(",
            '"validatedCandidateDigest": binding["validatedCandidateDigest"]',
            '"upstreamPullRequest": upstream_pull_request',
            '"candidateBinding": candidate_binding',
            '"ciValidation": ci_validation',
            '"artifactProducerAttempt": '
            'ci["contributionJob"]["observedRunAttempt"]',
            '"predicateDigest": attestation["predicateDigest"]',
            "temporary_evidence.parent == output",
            "shutil.rmtree(temporary_evidence)",
            "not any(output.iterdir())",
            'write_json(output / "facts/BONUS-OSS.json", facts)',
        ),
    )


def validate_contrib_verifier(verifier: str) -> None:
    staged_status_block = """const stagedStatus = {
  state: "staged-not-submitted",
  pullRequestOpened: false,
  appliedToUpstream: false,
  localBuildRun: false,
  localTestsRun: false,
  localSecurityScanRun: false,
};"""
    merged_status_key_block = """const mergedStatusKeys = [
  "appliedToUpstream",
  "headSha",
  "localBuildRun",
  "localSecurityScanRun",
  "localTestsRun",
  "mergeCommitSha",
  "mergedAt",
  "pullRequestNumber",
  "pullRequestOpened",
  "state",
  "url",
];"""
    local_execution_absent_block = """const localExecutionAbsent =
  status?.localBuildRun === false &&
  status?.localTestsRun === false &&
  status?.localSecurityScanRun === false;"""
    require(
        verifier.count(staged_status_block) == 1
        and verifier.count(merged_status_key_block) == 1
        and verifier.count(local_execution_absent_block) == 1,
        "staged and merged manifest phases must preserve their exact fields "
        "and shared local-execution prohibition",
    )
    require_tokens(
        verifier,
        "phase-aware contribution status",
        (
            "const stagedStatus = {",
            'state: "staged-not-submitted"',
            "pullRequestOpened: false",
            "appliedToUpstream: false",
            "localBuildRun: false",
            "localTestsRun: false",
            "localSecurityScanRun: false",
            "const mergedStatusKeys = [",
            '"pullRequestNumber"',
            '"headSha"',
            '"mergeCommitSha"',
            '"mergedAt"',
            'status?.state === "merged-upstream"',
            "status?.pullRequestOpened === true",
            "status?.appliedToUpstream === true",
            "Number.isSafeInteger(status?.pullRequestNumber)",
            "status.pullRequestNumber > 0",
            "https://github.com/acryldata/mcp-server-datahub/pull/",
            "/^[0-9a-f]{40}$/.test(status.headSha)",
            "/^[0-9a-f]{40}$/.test(status.mergeCommitSha)",
            "const mergedAtIsCanonical =",
            'toISOString().replace(".000Z", "Z")',
            'Date.parse("2026-07-06T13:00:00Z")',
            'Date.parse("2026-08-10T21:00:00Z")',
            "localExecutionAbsent",
            "if (!stagedStatusValid && !mergedStatusValid)",
            "const stagedReadmeStatus =",
            "**Staged, not submitted.** No pull request was opened",
            "const mergedReadmeStatus =",
            "**Merged upstream.** Pull request "
            "[#${status.pullRequestNumber}](${status.url})",
            "${status.mergedAt}",
            "${status.headSha}",
            "${status.mergeCommitSha}",
            "all validation and security evidence was produced by CI/CD",
            "const stagedReadmeStatusValid =",
            "const mergedReadmeStatusValid =",
            'includes("**Merged upstream.**")',
            'includes("**Staged, not submitted.**")',
            'includes("No pull request was opened")',
            "if (stagedStatusValid && !stagedReadmeStatusValid)",
            "if (mergedStatusValid && !mergedReadmeStatusValid)",
        ),
    )
    require(
        verifier.count("localBuildRun: false") == 1
        and verifier.count("localTestsRun: false") == 1
        and verifier.count("localSecurityScanRun: false") == 1,
        "local execution claims must exist only in the staged literal",
    )


def validate_documentation(documentation: str) -> None:
    normalized = re.sub(r"\s+", " ", documentation)
    require_tokens(
        normalized,
        "BONUS-OSS operational documentation",
        (
            "source-complete and intentionally blocked",
            "No pull request has been opened or changed",
            "`staged-not-submitted`",
            "An open pull request is not sufficient evidence",
            "`merged-upstream`",
            "contribution README's",
            "phase-aware verifier rejects",
            "`release_sha`, `ci_run_id`, and `upstream_pull_request_number`",
            "independent upstream maintainer",
            "exact four changed paths",
            "local security scan",
            "All security and integrity enforcement is inside CI/CD",
            "does not use Codex Security",
            "single-document Sigstore bundle",
            "persisted GitHub attestation online for each of",
            "Every verification must resolve exactly one result",
            "self-hosted provenance is",
            "signs that exact checksum inventory",
            "optional and never changes the required submission-readiness",
        ),
    )


def replace_once(text: str, old: str, new: str) -> str:
    require(old in text, f"tamper fixture lost marker: {old}")
    return text.replace(old, new, 1)


def replace_all(text: str, old: str, new: str) -> str:
    require(old in text, f"tamper fixture lost marker: {old}")
    return text.replace(old, new)


def expect_rejected(
    label: str,
    validator,
    tampered: str,
) -> None:
    try:
        validator(tampered)
    except ContractError:
        return
    raise AssertionError(f"BONUS-OSS tamper was accepted: {label}")


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
collector_text = COLLECTOR_PATH.read_text(encoding="utf-8")
verifier_text = CONTRIB_VERIFIER_PATH.read_text(encoding="utf-8")
documentation_text = DOCUMENTATION_PATH.read_text(encoding="utf-8")
validate_workflow(workflow_text)
validate_collector(collector_text)
validate_contrib_verifier(verifier_text)
validate_documentation(documentation_text)

workflow_tamper_cases = {
    "add caller artifact input": replace_once(
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
    "structured PR input": replace_once(
        workflow_text,
        "        type: string\n",
        "        type: boolean\n",
    ),
    "cancel current evidence": replace_once(
        workflow_text,
        "  cancel-in-progress: false",
        "  cancel-in-progress: true",
    ),
    "producer gains write": replace_once(
        workflow_text,
        "      contents: read\n",
        "      contents: write\n",
    ),
    "producer gains secret": replace_once(
        workflow_text,
        "name: Submission BONUS OSS\n",
        "name: Submission BONUS OSS\n# ${{ secrets.UPSTREAM_TOKEN }}\n",
    ),
    "self-hosted runner": replace_once(
        workflow_text,
        "runs-on: ubuntu-24.04",
        "runs-on: self-hosted",
    ),
    "manifest verification removed": replace_once(
        workflow_text,
        "node scripts/verify-contrib.mjs",
        "true # manifest verification removed",
    ),
    "external recollection removed": replace_once(
        workflow_text,
        "python3 scripts/collect-submission-bonus-oss.py collect",
        "python3 scripts/collect-submission-bonus-oss.py skipped",
    ),
    "current-only retained attempt": replace_once(
        workflow_text,
        "--policy latest-retained",
        "--policy current-attempt",
    ),
    "producer artifact selected by name": replace_once(
        workflow_text,
        "artifact-ids: ${{ steps.producer.outputs.artifact_id }}",
        "name: ${{ steps.producer.outputs.artifact_name }}",
    ),
    "producer outputs trusted": replace_once(
        workflow_text,
        "    needs: produce\n",
        (
            "    needs: produce\n"
            "    # ${{ needs.produce.outputs.artifact_id }}\n"
        ),
    ),
    "producer owner job changed": replace_once(
        workflow_text,
        '"Produce exact merged upstream contribution evidence"',
        '"Any producer"',
    ),
    "producer window widened": replace_once(
        workflow_text,
        ".metadata.created_at >= $startedAt",
        "true",
    ),
    "retention overwrite disabled": replace_once(
        workflow_text,
        "          overwrite: true",
        "          overwrite: false",
    ),
    "retention name gains mutable suffix": replace_once(
        workflow_text,
        "          name: submission-bonus-oss-"
        "${{ inputs.release_sha }}-${{ github.run_attempt }}\n",
        (
            "          name: submission-bonus-oss-"
            "${{ inputs.release_sha }}-${{ github.run_attempt }}-latest\n"
        ),
    ),
    "subject count weakened": replace_all(
        workflow_text,
        ".subjectCount == 4",
        ".subjectCount >= 3",
    ),
    "wrong standard source": replace_all(
        workflow_text,
        "--source-key bonus-oss",
        "--source-key operations",
    ),
    "floating attest action": replace_once(
        workflow_text,
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "actions/attest@v4",
    ),
    "single proof attested": replace_once(
        workflow_text,
        "submission-bonus-oss-attestation/SHA256SUMS",
        "submission-bonus-oss-attestation/proofs/BONUS-OSS.json",
    ),
    "persisted verification removed": replace_once(
        workflow_text,
        "      - name: Verify persisted signed full-subject attestation\n",
        "      - name: Skip persisted signed full-subject attestation\n",
    ),
    "attestation output identity removed": replace_once(
        workflow_text,
        "        id: attest\n",
        "",
    ),
    "attestation URL origin weakened": replace_once(
        workflow_text,
        '"https://github.com/${GITHUB_REPOSITORY}/attestations/'
        '${ATTESTATION_ID}"',
        '"${ATTESTATION_URL}"',
    ),
    "bundle symlink accepted": replace_once(
        workflow_text,
        '          test ! -L "${ATTESTATION_BUNDLE_PATH}"\n',
        "",
    ),
    "bundle document cardinality weakened": replace_once(
        workflow_text,
        "            length == 1 and\n"
        '            (.[0] | type == "object")\n',
        "            length >= 1\n",
    ),
    "bundle identity detached": replace_once(
        workflow_text,
        ".attestation == $bundle[0]",
        ".attestation != null",
    ),
    "persisted predicate bytes detached": replace_once(
        workflow_text,
        ".verificationResult.statement.predicate ==\n"
        "                        $predicate[0]",
        ".verificationResult.statement.predicate != null",
    ),
    "persisted subject set weakened": replace_once(
        workflow_text,
        "                      ) == $expectedSubjects",
        "                      ) | length == 4",
    ),
    "persisted result cardinality weakened": replace_once(
        workflow_text,
        "                  length == 1\n"
        "                )\n",
        "                  length >= 1\n"
        "                )\n",
    ),
    "offline bundle verification removed": replace_once(
        workflow_text,
        '              --bundle "${ATTESTATION_BUNDLE_PATH}" \\\n',
        "",
    ),
    "online persistence verification bypassed": replace_once(
        workflow_text,
        "            for attempt in {1..12}; do\n"
        "              if gh attestation verify \\\n",
        "            for attempt in {1..12}; do\n"
        "              if gh attestation verify \\\n"
        '                --bundle "${ATTESTATION_BUNDLE_PATH}" \\\n',
    ),
    "only one signed subject verified": replace_once(
        workflow_text,
        '          for index in "${!expected_names[@]}"; do\n',
        "          for index in 0; do\n",
    ),
    "wrong persisted signer workflow": replace_all(
        workflow_text,
        "submission-bonus-oss.yml",
        "submission-content-review.yml",
    ),
    "persisted release digest removed": replace_once(
        workflow_text,
        '              --signer-digest "${RELEASE_SHA}" \\\n',
        "",
    ),
    "persisted master binding weakened": replace_once(
        workflow_text,
        "              --source-ref refs/heads/master \\\n",
        "              --source-ref \"${GITHUB_REF}\" \\\n",
    ),
    "persisted self-hosted provenance allowed": replace_once(
        workflow_text,
        "              --deny-self-hosted-runners \\\n",
        "",
    ),
}
for tamper_label, tampered_workflow in workflow_tamper_cases.items():
    expect_rejected(tamper_label, validate_workflow, tampered_workflow)

collector_tamper_cases = {
    "fifth upstream path accepted": replace_once(
        collector_text,
        '    "tests/test_mcp/test_get_aspect_history.py",\n)',
        (
            '    "tests/test_mcp/test_get_aspect_history.py",\n'
            '    "src/mcp_server_datahub/unrelated.py",\n'
            ")"
        ),
    ),
    "extra receipt member accepted": replace_once(
        collector_text,
        '    "receipt.json",\n}',
        '    "receipt.json",\n    "debug.log",\n}',
    ),
    "extra CI gate accepted": replace_once(
        collector_text,
        '    "web",\n}',
        '    "web",\n    "untrustedGate",\n}',
    ),
    "wrong upstream repository": replace_all(
        collector_text,
        "acryldata/mcp-server-datahub",
        "attacker/mcp-server-datahub",
    ),
    "wrong upstream branch": replace_all(
        collector_text,
        'UPSTREAM_BRANCH = "main"',
        'UPSTREAM_BRANCH = "develop"',
    ),
    "wrong upstream license": replace_all(
        collector_text,
        'UPSTREAM_LICENSE = "Apache-2.0"',
        'UPSTREAM_LICENSE = "NOASSERTION"',
    ),
    "public API receives token": replace_all(
        collector_text,
        "public_api = GitHubApi(token=None)",
        "public_api = GitHubApi(token=token)",
    ),
    "redirects allowed": replace_all(
        collector_text,
        "raise urllib.error.HTTPError(",
        "return urllib.error.HTTPError(",
    ),
    "Git credentials enabled": replace_all(
        collector_text,
        '"credential.helper=",',
        '"credential.helper=store",',
    ),
    "Git environment config injection retained": replace_all(
        collector_text,
        '                "GIT_CONFIG_PARAMETERS",\n',
        "",
    ),
    "artifact archive digest ignored": replace_all(
        collector_text,
        "sha256_file(output) == expected_digest",
        "output.stat().st_size > 0",
    ),
    "boolean artifact identifier accepted": replace_all(
        collector_text,
        '            and not isinstance(artifact.get("id"), bool)\n',
        "",
    ),
    "ZIP traversal accepted": replace_all(
        collector_text,
        'not canonical.startswith("../")',
        "True",
    ),
    "unexpected ZIP directory accepted": replace_all(
        collector_text,
        "canonical in allowed_directories",
        "bool(canonical)",
    ),
    "ZIP symlink accepted": replace_all(
        collector_text,
        "mode_type in {0, stat.S_IFREG}",
        "mode_type != stat.S_IFDIR",
    ),
    "CI pull-request run accepted": replace_all(
        collector_text,
        'run.get("event") == "push"',
        'run.get("event") in {"push", "pull_request"}',
    ),
    "CI attempt history unbounded": replace_all(
        collector_text,
        "require(current_attempt <= 20",
        "require(current_attempt > 0",
    ),
    "CI producer may finish after signing": replace_all(
        collector_text,
        '<= parse_utc(attestation_job["started_at"], "attestation start")',
        '<= parse_utc(attestation_job["completed_at"], '
        '"attestation completion")',
    ),
    "unmerged PR accepted": replace_all(
        collector_text,
        'pull.get("merged") is True',
        'pull.get("merged") in {True, False}',
    ),
    "wrong base branch accepted": replace_all(
        collector_text,
        'pull["base"].get("ref") == UPSTREAM_BRANCH',
        'bool(pull["base"].get("ref"))',
    ),
    "self-merge accepted": replace_all(
        collector_text,
        '!= positive_int(merger.get("id"), "PR merger ID")',
        '== positive_int(merger.get("id"), "PR merger ID")',
    ),
    "renamed path accepted": replace_all(
        collector_text,
        '"previous_filename" not in file',
        "True",
    ),
    "receipt manifest bytes ignored": replace_all(
        collector_text,
        '(root / "manifest.json").read_bytes() == manifest_bytes',
        '(root / "manifest.json").is_file()',
    ),
    "diff applied without index": replace_all(
        collector_text,
        '"apply", "--binary", "--index"',
        '"apply", "--binary"',
    ),
    "candidate path inventory widened": replace_all(
        collector_text,
        "tuple(changed) == EXPECTED_PATHS",
        "set(changed).issuperset(EXPECTED_PATHS)",
    ),
    "receipt diff equality removed": replace_all(
        collector_text,
        "diff_bytes(repository) == applied_diff",
        "bool(diff_bytes(repository))",
    ),
    "head tree equality removed": replace_all(
        collector_text,
        "head_tree == candidate_tree",
        "bool(head_tree)",
    ),
    "merged bytes equality removed": replace_all(
        collector_text,
        "(candidate_mode, candidate_bytes) == (merge_mode, merge_bytes)",
        "bool(merge_bytes)",
    ),
    "CI receipt digest detached": replace_all(
        collector_text,
        "!= receipt_artifact_digest",
        '!= ""',
    ),
    "CI green gates weakened": replace_all(
        collector_text,
        'any(value != "success" for value in gates.values())',
        "any(value is None for value in gates.values())",
    ),
    "self-hosted attestation accepted": replace_all(
        collector_text,
        '"--deny-self-hosted-runners",',
        '"--format",',
    ),
    "duplicate CI statements accepted": replace_all(
        collector_text,
        "len(matching) == 1",
        "len(matching) >= 1",
    ),
    "judge predicate digest detached": replace_all(
        collector_text,
        '!= capability["judgeEvidenceArtifactDigest"]',
        '!= ""',
    ),
    "intermediate evidence retained": replace_all(
        collector_text,
        "shutil.rmtree(temporary_evidence)",
        "pass # retained",
    ),
}
for tamper_label, tampered_collector in collector_tamper_cases.items():
    expect_rejected(tamper_label, validate_collector, tampered_collector)

verifier_tamper_cases = {
    "staged PR falsely open": replace_once(
        verifier_text,
        "pullRequestOpened: false",
        "pullRequestOpened: true",
    ),
    "merged state weakened": replace_all(
        verifier_text,
        'status?.state === "merged-upstream"',
        "Boolean(status?.state)",
    ),
    "zero PR accepted": replace_all(
        verifier_text,
        "status.pullRequestNumber > 0",
        "status.pullRequestNumber >= 0",
    ),
    "wrong PR origin": replace_all(
        verifier_text,
        "https://github.com/acryldata/mcp-server-datahub/pull/",
        "https://github.com/attacker/mcp-server-datahub/pull/",
    ),
    "head SHA weakened": replace_all(
        verifier_text,
        "/^[0-9a-f]{40}$/.test(status.headSha)",
        "Boolean(status.headSha)",
    ),
    "merge time noncanonical": replace_all(
        verifier_text,
        "const mergedAtIsCanonical =",
        "const mergedAtWasNotChecked =",
    ),
    "submission start changed": replace_all(
        verifier_text,
        'Date.parse("2026-07-06T13:00:00Z")',
        'Date.parse("2026-01-01T00:00:00Z")',
    ),
    "local execution claim allowed": replace_all(
        verifier_text,
        "status?.localSecurityScanRun === false",
        "Boolean(status?.localSecurityScanRun) || true",
    ),
    "staged README truthfulness skipped": replace_all(
        verifier_text,
        "if (stagedStatusValid && !stagedReadmeStatusValid)",
        "if (false)",
    ),
    "merged README truthfulness skipped": replace_all(
        verifier_text,
        "if (mergedStatusValid && !mergedReadmeStatusValid)",
        "if (false)",
    ),
    "merged README permits staged contradiction": replace_all(
        verifier_text,
        '!normalizedAspectHistoryReadme.includes("**Staged, not submitted.**")',
        "true",
    ),
}
for tamper_label, tampered_verifier in verifier_tamper_cases.items():
    expect_rejected(
        tamper_label,
        validate_contrib_verifier,
        tampered_verifier,
    )

documentation_tamper_cases = {
    "claims PR exists": replace_all(
        documentation_text,
        "No pull\nrequest has been opened or changed",
        "A pull\nrequest has been opened",
    ),
    "allows open PR": replace_all(
        documentation_text,
        "An open pull request is not sufficient evidence",
        "An open pull request is sufficient evidence",
    ),
    "claims Codex Security": replace_all(
        documentation_text,
        "does not use Codex Security",
        "uses Codex Security",
    ),
}
for tamper_label, tampered_documentation in documentation_tamper_cases.items():
    expect_rejected(
        tamper_label,
        validate_documentation,
        tampered_documentation,
    )

print(
    json.dumps(
        {
            "schemaVersion": "archon.submission-bonus-oss-contract-test/v1",
            "artifactFiles": list(EXPECTED_STANDARD_FILES),
            "dispatchInputs": list(EXPECTED_INPUTS),
            "upstreamPaths": list(EXPECTED_UPSTREAM_PATHS),
            "workflowTamperCases": sorted(workflow_tamper_cases),
            "collectorTamperCases": sorted(collector_tamper_cases),
            "verifierTamperCases": sorted(verifier_tamper_cases),
            "documentationTamperCases": sorted(documentation_tamper_cases),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
