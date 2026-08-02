#!/usr/bin/env python3
"""Remote-CI contracts for lean dual-runtime submission project access."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "submission-project-access.yml"
HELPER_PATH = ROOT / "scripts" / "verify-lean-submission-runtime-source.sh"

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
    "Verify lean deployment, availability, and full lifecycle attestations",
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
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/attest": "59d89421af93a897026c735860bf21b6eb4f7b26",
}
EXPECTED_ACTION_COUNTS = {
    "actions/checkout": 2,
    "actions/download-artifact": 8,
    "actions/upload-artifact": 1,
    "actions/attest": 1,
}


class ContractError(AssertionError):
    """Raised when a workflow trust boundary is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_tokens(text: str, label: str, tokens: tuple[str, ...]) -> None:
    for token in tokens:
        require(token in text, f"{label} lost required contract: {token}")


def job_sections(workflow: str) -> dict[str, str]:
    marker = "\njobs:\n"
    require(workflow.count(marker) == 1, "workflow must define one jobs map")
    body = workflow.split(marker, 1)[1]
    matches = list(re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", body))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[match.group(1)] = body[match.start():end]
    return sections


def job_steps(job: str) -> tuple[tuple[str, str], ...]:
    boundaries = list(re.finditer(r"(?m)^      -[^\n]*\n", job))
    require(boundaries, "job must contain named steps")
    result: list[tuple[str, str]] = []
    for index, boundary in enumerate(boundaries):
        header = boundary.group(0)
        require(header.startswith("      - name: "), "every step must be named")
        name = header.removeprefix("      - name: ").removesuffix("\n")
        end = (
            boundaries[index + 1].start()
            if index + 1 < len(boundaries)
            else len(job)
        )
        result.append((name, job[boundary.start():end]))
    return tuple(result)


def named_step(job: str, name: str) -> str:
    matches = tuple(section for current, section in job_steps(job) if current == name)
    require(len(matches) == 1, f"step missing or duplicated: {name}")
    return matches[0]


def permission_map(job: str) -> dict[str, str]:
    marker = "    permissions:\n"
    require(job.count(marker) == 1, "job must define one permissions map")
    start = job.index(marker) + len(marker)
    following = re.search(r"(?m)^    [a-z][a-z0-9_-]*:", job[start:])
    end = start + following.start() if following is not None else len(job)
    values = re.findall(
        r"(?m)^      ([a-z][a-z0-9-]*): (read|write)$", job[start:end]
    )
    require(values and len(values) == len(dict(values)), "permissions are invalid")
    return dict(values)


def dispatch_inputs(workflow: str) -> dict[str, str]:
    start = workflow.index("\n  workflow_dispatch:\n")
    end = workflow.index("\npermissions: {}\n")
    body = workflow[start:end]
    matches = list(re.finditer(r"(?m)^      ([a-z][a-z0-9_]*):\n", body))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        stop = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        blocks[match.group(1)] = body[match.start():stop]
    return blocks


def validate_actions(workflow: str) -> None:
    counts: dict[str, int] = {}
    for action, revision in re.findall(
        r"(?m)^\s+uses: ([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})",
        workflow,
    ):
        require(ACTION_PINS.get(action) == revision, f"action pin changed: {action}")
        counts[action] = counts.get(action, 0) + 1
    require(counts == EXPECTED_ACTION_COUNTS, "action identity/count multiset changed")
    require(not re.search(r"(?m)^\s+uses: [^\s#]+@(?![0-9a-f]{40})", workflow),
            "floating action reference is forbidden")


def validate_helper(helper: str) -> None:
    require("\t" not in helper, "helper must not contain tabs")
    require(helper.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"),
            "helper shell safety prelude changed")
    require_tokens(
        helper,
        "lean source verifier",
        (
            "expected_name=\"deployment-evidence-production-${release_sha}-${run_id}\"",
            "expected_files=(deployment-evidence.json observation.json)",
            "expected_name=\"production-availability-${release_sha}-${run_id}\"",
            "expected_files=(evidence.json observation.json)",
            "attestations/aws-deployment/v2",
            "attestations/production-availability/v2",
            "scripts/validate-lean-production-evidence.mjs pair",
            "scripts/validate-lean-production-evidence.mjs stable",
            "--signer-digest \"${release_sha}\"",
            "--source-digest \"${release_sha}\"",
            "--source-ref refs/heads/master",
            "--deny-self-hosted-runners",
            "archon.submission-lean-runtime-source/v2",
            "\"Archon-production-Core\",\"Archon-production-Edge\",\"Archon-production-Judge\"",
            "coreIdle:true",
            "legacyAlwaysOnRuntimeAbsent:true",
            "cloudImageDigestBound:true",
            "coreMode:\"ephemeral-optional-live-session\"",
            "secretMaterialRetained:false",
        ),
    )
    for forbidden in (
        "live-runtime-manifest",
        "Archon-production\"",
        "production-deployment/v1",
        "production-availability/v1",
        "cloudOci:true",
    ):
        require(forbidden not in helper, f"helper retained legacy claim: {forbidden}")


def validate_contract(workflow: str, helper: str) -> None:
    require("\t" not in workflow, "workflow must not contain tabs")
    require(workflow.startswith("name: Submission project access\n"),
            "workflow identity changed")
    require(workflow.count("\npermissions: {}\n") == 1,
            "top-level deny-by-default permissions changed")
    require("  group: archon-judge-user-production\n" in workflow,
            "production judge serialization lock changed")
    require("  cancel-in-progress: false\n" in workflow,
            "production cancellation policy changed")
    require("${{ secrets." not in workflow, "workflow must not consume secrets")
    require("    environment:" not in workflow, "project access jobs must be unprivileged")

    inputs = dispatch_inputs(workflow)
    require(tuple(inputs) == EXPECTED_INPUTS, "dispatch input contract changed")
    for name, block in inputs.items():
        require(block.count("        required: true\n") == 1,
                f"{name} must remain required")
        require(block.count("        type: string\n") == 1,
                f"{name} must remain a scalar string")

    jobs = job_sections(workflow)
    require(tuple(jobs) == ("produce", "attest"), "job topology changed")
    produce = jobs["produce"]
    attest = jobs["attest"]
    require(tuple(name for name, _ in job_steps(produce)) == EXPECTED_PRODUCE_STEPS,
            "producer step order changed")
    require(tuple(name for name, _ in job_steps(attest)) == EXPECTED_ATTEST_STEPS,
            "attester step order changed")
    require(permission_map(produce) == {
        "actions": "read", "attestations": "read", "contents": "read"
    }, "producer authority changed")
    require(permission_map(attest) == {
        "actions": "read", "attestations": "write",
        "contents": "read", "id-token": "write"
    }, "attester authority changed")

    resolver = named_step(produce, "Resolve exact immutable prerequisite artifacts")
    require_tokens(
        resolver,
        "prerequisite resolver",
        (
            "select-run-artifact",
            "deployment-evidence-production-${RELEASE_SHA}-",
            "production-availability-${RELEASE_SHA}-",
            ".github/workflows/deploy.yml",
            ".github/workflows/availability.yml",
            ".github/workflows/judge-user.yml",
            ".github/workflows/submission-judge-journey.yml",
            "all($production[]; .id <= $reactivate)",
            "all($journeys[]; .id <= $selected)",
        ),
    )
    require(workflow.count("exact-run-id") == 6,
            "deploy/availability run-ID selector policy changed")
    require(workflow.count("deployment-evidence-production-${RELEASE_SHA}-") == 3,
            "deployment artifact naming must be reselected three times")
    require(workflow.count("production-availability-${RELEASE_SHA}-") == 3,
            "availability artifact naming must be reselected three times")

    for step_name, input_name in (
        ("Download exact deployment evidence", "deployment_run_id"),
        ("Download exact availability evidence", "availability_run_id"),
        ("Download exact provision evidence", "provision_run_id"),
        ("Download exact rotate evidence", "rotate_run_id"),
        ("Download exact deactivate evidence", "deactivate_run_id"),
        ("Download exact reactivate evidence", "reactivate_run_id"),
        ("Download exact fresh judge journey", "judge_journey_run_id"),
    ):
        step = named_step(produce, step_name)
        require(f"run-id: ${{{{ inputs.{input_name} }}}}\n" in step,
                f"{step_name} lost cross-run binding")
        require("merge-multiple: true\n" in step,
                f"{step_name} lost exact extraction policy")

    verify = named_step(
        produce, "Verify lean deployment, availability, and full lifecycle attestations"
    )
    require_tokens(
        verify,
        "producer upstream verification",
        (
            "verify-lean-submission-runtime-source.sh",
            "verify_lean_source deployment deployment",
            "verify_lean_source availability availability",
            "verify_subject_set",
            "attestations/judge-user-operation/v1",
            "submission-judge-journey/v1",
            "--deny-self-hosted-runners",
            "unique_by(.statement)",
        ),
    )

    semantic = named_step(
        produce, "Reconstruct and validate exact upstream semantic bindings"
    )
    require_tokens(
        semantic,
        "producer lean semantics",
        (
            "deployment/deployment-evidence.json",
            "archon.aws-deployment-evidence/v2",
            'deployment_dir / "observation.json"',
            "archon.lean-runtime-observation/v1",
            "build-once-promote-exact-artifacts",
            "zeroIdleCore",
            "legacyAlwaysOnRuntimeAbsent",
            "attestations/aws-deployment/v2",
            'availability_dir / "evidence.json"',
            "archon.production-availability/v2",
            "attestations/production-availability/v2",
            'availability_dir / "observation.json"',
            '["openid", "email", "profile", "archon/approve"]',
            "dt.timedelta(hours=7)",
            "availability_binding",
        ),
    )

    public = named_step(
        produce, "Probe public application and repository without credentials"
    )
    require_tokens(
        public,
        "producer public surface",
        (
            "${application_url}/runtime-config.json",
            "${application_url}/api/runtime-profiles",
            "archon.runtime-profiles/v1",
            '.autoSelection == "cloud"',
            '== ["READY"]',
            '== ["LAUNCHABLE"]',
            "all(.capabilities[]; . == true)",
            "submission-project-access-upstream-verifications/runtime-config.json",
            "submission-project-access-upstream/journey/production-runtime-config.json",
            "archon.aws-deployment-evidence/v2",
            "archon.lean-runtime-observation/v1",
            "--max-redirs 0",
            "test -z \"${GH_TOKEN:-}\"",
        ),
    )

    package = named_step(
        produce, "Assemble exact registered SQ3 SQ4 and SQ5 subjects"
    )
    require_tokens(
        package,
        "standard-v1 package",
        (
            "validate-submission-proof-receipts.py",
            "assemble-standard",
            "--source-key project-access",
            '"availabilityObservedAt":',
            'availability["observedAt"]',
            '"deployment": deployment',
            ".subjectCount == 15",
            "sha256sum --check --strict SHA256SUMS",
        ),
    )
    retained = named_step(produce, "Retain exact standard project-access subjects")
    require(
        "path: ${{ runner.temp }}/submission-project-access-evidence\n" in retained,
        "retained artifact path widened",
    )
    require("retention-days: 14\n" in retained, "retention policy changed")

    reverify = named_step(attest, "Reverify all exact upstream attestations from retained facts")
    require_tokens(
        reverify,
        "attester upstream verification",
        (
            'if [[ "${key}" == "deployment" || "${key}" == "availability" ]]',
            "verify-lean-submission-runtime-source.sh",
            "lean-verification/binding.json",
            "archon.submission-lean-runtime-source/v2",
            "Archon-production-Core",
            "Archon-production-Edge",
            "Archon-production-Judge",
            "ephemeral-optional-live-session",
            "continue",
            "sha256sum --check --strict SHA256SUMS",
            "--deny-self-hosted-runners",
            "unique_by(.verificationResult.statement)",
        ),
    )
    attester_public = named_step(
        attest, "Independently repeat credentialless public access probes"
    )
    require_tokens(
        attester_public,
        "attester public surface",
        (
            "${application_url}/api/runtime-profiles",
            "archon.runtime-profiles/v1",
            '.autoSelection == "cloud"',
            '== ["READY"]',
            '== ["LAUNCHABLE"]',
            "all(.capabilities[]; . == true)",
            "upstream-attester/journey/source/production-runtime-config.json",
            "archon.aws-deployment-evidence/v2",
            "archon.lean-runtime-observation/v1",
            "test -z \"${GH_TOKEN:-}\"",
        ),
    )
    final = named_step(
        attest, "Recheck cross-source semantics and canonical state before attestation"
    )
    require_tokens(
        final,
        "final cross-source gate",
        (
            "deployment_dir / \"deployment-evidence.json\"",
            "deployment_dir / \"observation.json\"",
            "availability_dir / \"evidence.json\"",
            "availability_dir / \"observation.json\"",
            "journey_dir / \"production-runtime-config.json\"",
            "archon.aws-deployment-evidence/v2",
            "archon.lean-runtime-observation/v1",
            "archon.production-availability/v2",
            '["openid", "email", "profile", "archon/approve"]',
            "deployment_binding != sq3[\"deployment\"]",
            "availability_binding != expected_availability_binding",
            "dt.timedelta(hours=7)",
            "all($production[]; .id <= $reactivate)",
            "all($deployments[]; .id <= $selected)",
            "all(.[]; .runAttempt == .producerAttempt)",
        ),
    )

    for forbidden in (
        "live-runtime-manifest",
        "archon.live-runtime-manifest/v1",
        "attestations/production-deployment/v1",
        "attestations/production-availability/v1",
        "availability.json",
        "availability-subject.sha256",
        "rollbackSelector",
        "immutableArtifacts",
        "Archon-production\"",
    ):
        require(forbidden not in workflow, f"workflow retained legacy contract: {forbidden}")

    validate_actions(workflow)
    validate_helper(helper)


def replace_exact(text: str, old: str, new: str, *, count: int = 1) -> str:
    require(text.count(old) >= count, f"tamper expected at least {count} copies of {old!r}")
    return text.replace(old, new, count)


def expect_rejected(label: str, workflow: str, helper: str) -> None:
    try:
        validate_contract(workflow, helper)
    except ContractError:
        return
    raise AssertionError(f"contract accepted tamper: {label}")


workflow_text = WORKFLOW_PATH.read_text(encoding="utf-8")
helper_text = HELPER_PATH.read_text(encoding="utf-8")
validate_contract(workflow_text, helper_text)

tamper_cases: dict[str, tuple[str, str]] = {
    "arbitrary URL input": (
        replace_exact(
            workflow_text,
            "      deployment_run_id:\n",
            "      application_url:\n        required: true\n        type: string\n      deployment_run_id:\n",
        ),
        helper_text,
    ),
    "top permissions widened": (
        replace_exact(workflow_text, "\npermissions: {}\n", "\npermissions:\n  contents: read\n"),
        helper_text,
    ),
    "serialization lock changed": (
        replace_exact(workflow_text, "  group: archon-judge-user-production\n", "  group: project-access\n"),
        helper_text,
    ),
    "secret consumed": (
        replace_exact(
            workflow_text,
            "          RELEASE_SHA: ${{ inputs.release_sha }}\n",
            "          RELEASE_SHA: ${{ inputs.release_sha }}\n          LEAK: ${{ secrets.JUDGE_PASSWORD }}\n",
        ),
        helper_text,
    ),
    "run-ID policy weakened": (
        replace_exact(workflow_text, "            exact-run-id\n", "            latest-retained\n"),
        helper_text,
    ),
    "producer helper removed": (
        replace_exact(
            workflow_text,
            "verify-lean-submission-runtime-source.sh",
            "verify-obsolete-runtime-source.sh",
        ),
        helper_text,
    ),
    "producer drops deployment observation binding": (
        replace_exact(
            workflow_text,
            'deployment_dir / "observation.json"',
            'deployment_dir / "deployment-evidence.json"',
            count=2,
        ),
        helper_text,
    ),
    "producer drops availability observation binding": (
        replace_exact(
            workflow_text,
            'availability_dir / "observation.json"',
            'availability_dir / "evidence.json"',
        ),
        helper_text,
    ),
    "profile scope removed": (
        replace_exact(
            workflow_text,
            '["openid", "email", "profile", "archon/approve"]',
            '["openid", "email", "archon/approve"]',
        ),
        helper_text,
    ),
    "Cloud no longer canonical": (
        replace_exact(workflow_text, '.autoSelection == "cloud"', '.autoSelection == "core"'),
        helper_text,
    ),
    "Core no longer launchable": (
        replace_exact(workflow_text, '== ["LAUNCHABLE"]', '== ["UNAVAILABLE"]'),
        helper_text,
    ),
    "capability can be false": (
        replace_exact(
            workflow_text,
            "all(.capabilities[]; . == true)",
            "all(.capabilities[]; type == \"boolean\")",
        ),
        helper_text,
    ),
    "availability freshness widened": (
        replace_exact(
            workflow_text,
            "or now - availability_observed > dt.timedelta(hours=7)\n",
            "or now - availability_observed > dt.timedelta(hours=24)\n",
        ),
        helper_text,
    ),
    "legacy deployment schema": (
        replace_exact(
            workflow_text,
            "archon.aws-deployment-evidence/v2",
            "archon.live-runtime-manifest/v1",
        ),
        helper_text,
    ),
    "retention includes upstream": (
        replace_exact(
            workflow_text,
            "          path: ${{ runner.temp }}/submission-project-access-evidence\n",
            "          path: ${{ runner.temp }}/submission-project-access-upstream\n",
        ),
        helper_text,
    ),
    "floating attestation action": (
        replace_exact(
            workflow_text,
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            "actions/attest@v4",
        ),
        helper_text,
    ),
    "helper drops deployment observation": (
        workflow_text,
        replace_exact(
            helper_text,
            "expected_files=(deployment-evidence.json observation.json)",
            "expected_files=(deployment-evidence.json)",
        ),
    ),
    "helper drops availability observation": (
        workflow_text,
        replace_exact(
            helper_text,
            "expected_files=(evidence.json observation.json)",
            "expected_files=(evidence.json)",
        ),
    ),
    "helper accepts self-hosted provenance": (
        workflow_text,
        replace_exact(helper_text, "  --deny-self-hosted-runners \\\n", ""),
    ),
    "helper revives legacy runtime": (
        workflow_text,
        replace_exact(helper_text, "legacyAlwaysOnRuntimeAbsent:true", "legacyAlwaysOnRuntimeAbsent:false"),
    ),
    "helper overclaims OCI verification": (
        workflow_text,
        replace_exact(helper_text, "cloudImageDigestBound:true", "cloudOci:true"),
    ),
}
for tamper_label, (tampered_workflow, tampered_helper) in tamper_cases.items():
    expect_rejected(tamper_label, tampered_workflow, tampered_helper)

print(json.dumps({
    "schemaVersion": "archon.submission-project-access-contract-test/v2",
    "artifactFiles": list(EXPECTED_FILES),
    "dispatchInputs": list(EXPECTED_INPUTS),
    "runtimeProfiles": ["cloud", "core"],
    "tamperCases": sorted(tamper_cases),
    "result": "passed",
}, separators=(",", ":"), sort_keys=True))