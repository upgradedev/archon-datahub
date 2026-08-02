#!/usr/bin/env python3
"""Remote-CI trust-boundary contracts for submission operations."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "submission-operations.yml"

EXPECTED_INPUTS = (
    "release_sha",
    "availability_run_id",
    "posture_run_id",
    "paging_run_id",
    "governed_canary_run_id",
    "project_access_run_id",
    "live_datahub_run_id",
)
EXPECTED_JOBS = ("produce", "attest")
EXPECTED_PRODUCE_STEPS = (
    "Bind dispatch to exact scalar source identifiers",
    "Check out the exact unprivileged producer",
    "Verify exact producer control plane",
    "Materialize exact reviewed operations collector",
    "Independently collect and reconstruct exact SQ10 facts",
    "Assemble exact registered SQ10 subjects",
    "Recheck canonical state before retention",
    "Retain exact standard operations subjects",
)
EXPECTED_ATTEST_STEPS = (
    "Bind attester to exact current workflow run",
    "Check out the exact unprivileged attester",
    "Verify exact attester control plane",
    "Resolve one immutable operations producer artifact",
    "Download exact immutable operations archive",
    "Validate exact retry-safe standard-v1 source",
    "Materialize exact reviewed operations collector",
    "Independently recollect every upstream and compare SQ10 facts",
    "Recheck producer artifact and canonical state",
    "Attest all nine exact operations subjects",
)
EXPECTED_FILES = (
    "SHA256SUMS",
    "attestation-predicate.json",
    "proofs/SQ10.json",
    "support/SQ10/availability-attestation.json",
    "support/SQ10/credential-rotation.json",
    "support/SQ10/judge-access-validity.json",
    "support/SQ10/monitor-configuration.json",
    "support/SQ10/paging-delivery.json",
    "support/SQ10/posture-attestation.json",
    "support/SQ10/rollback-recovery.json",
)
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact": (
        "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    ),
    "actions/attest": "59d89421af93a897026c735860bf21b6eb4f7b26",
}


class ContractError(AssertionError):
    """Raised when an operations trust-boundary contract is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def count(source: str, token: str) -> int:
    return source.count(token)


def between(source: str, start: str, end: str) -> str:
    start_index = source.find(start)
    end_index = source.find(end, start_index + len(start))
    require(start_index >= 0, f"missing start marker: {start}")
    require(end_index > start_index, f"missing end marker: {end}")
    return source[start_index:end_index]


def job_sections(source: str) -> tuple[str, str]:
    jobs = source.find("\njobs:\n")
    produce = source.find("\n  produce:\n", jobs)
    attest = source.find("\n  attest:\n", produce)
    collector = source.find(
        "\n# BEGIN ARCHON SUBMISSION OPERATIONS COLLECTOR\n", attest
    )
    require(jobs >= 0 and produce > jobs, "produce job is absent")
    require(attest > produce, "attest job is absent or out of order")
    require(collector > attest, "reviewed collector block is absent")
    return source[produce:attest], source[attest:collector]


def reviewed_collector(source: str) -> str:
    begin = "# BEGIN ARCHON SUBMISSION OPERATIONS COLLECTOR\n"
    end = "# END ARCHON SUBMISSION OPERATIONS COLLECTOR\n"
    require(count(source, begin) == 1, "collector begin marker must be unique")
    require(count(source, end) == 1, "collector end marker must be unique")
    block = between(source, begin, end).splitlines()[1:]
    require(block, "collector block is empty")
    require(
        all(line == "#|" or line.startswith("#| ") for line in block),
        "collector source lines must use the exact reviewed prefix",
    )
    collector = "\n".join(
        "" if line == "#|" else line[3:] for line in block
    ) + "\n"
    require(
        collector.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"),
        "collector must be fail-closed bash",
    )
    return collector


def step_names(job: str) -> tuple[str, ...]:
    return tuple(
        match.group(1).strip()
        for match in re.finditer(r"^\s{6}- name: (.+)$", job, re.MULTILINE)
    )


def job_permissions(job: str, label: str) -> dict[str, str]:
    matches = tuple(
        re.finditer(
            r"^    permissions:\n"
            r"((?:      [a-z][a-z0-9-]*: (?:read|write|none)\n)+)",
            job,
            re.MULTILINE,
        )
    )
    require(len(matches) == 1, f"{label} must have one explicit permission map")
    entries = tuple(
        re.findall(
            r"^      ([a-z][a-z0-9-]*): (read|write|none)$",
            matches[0].group(1),
            re.MULTILINE,
        )
    )
    require(
        len(entries) == len({scope for scope, _ in entries}),
        f"{label} permission scopes must be unique",
    )
    return dict(entries)


def validate_workflow(source: str) -> None:
    require(
        source.startswith("name: Submission operations\n"),
        "workflow identity changed",
    )
    dispatch = between(source, "on:\n", "\npermissions: {}\n")
    inputs = tuple(
        match.group(1)
        for match in re.finditer(
            r"^      ([a-z][a-z0-9_]*):$", dispatch, re.MULTILINE
        )
    )
    require(inputs == EXPECTED_INPUTS, "dispatch inputs are not exact scalars")
    for index, input_name in enumerate(EXPECTED_INPUTS):
        start = dispatch.index(f"      {input_name}:\n")
        end = (
            dispatch.index(f"      {EXPECTED_INPUTS[index + 1]}:\n", start)
            if index + 1 < len(EXPECTED_INPUTS)
            else len(dispatch)
        )
        input_block = dispatch[start:end]
        require("required: true" in input_block, f"{input_name} became optional")
        require("type: string" in input_block, f"{input_name} is not scalar")
    require(
        count(source, "\npermissions: {}\n") == 1,
        "top-level permissions must be empty",
    )
    require(
        "cancel-in-progress: false" in source,
        "retry-safe concurrency changed",
    )
    require(
        "group: submission-operations-${{ inputs.release_sha }}" in source,
        "release-scoped concurrency is absent",
    )

    jobs = tuple(
        match.group(1)
        for match in re.finditer(
            r"^  ([a-z][a-z0-9-]*):$", source[source.index("\njobs:\n"):],
            re.MULTILINE,
        )
    )
    require(jobs == EXPECTED_JOBS, "operations job topology changed")
    produce, attest = job_sections(source)
    require(
        step_names(produce) == EXPECTED_PRODUCE_STEPS,
        "producer steps changed or were reordered",
    )
    require(
        step_names(attest) == EXPECTED_ATTEST_STEPS,
        "attester steps changed or were reordered",
    )
    require(
        job_permissions(produce, "producer")
        == {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "producer permissions are not the exact read-only map",
    )
    require(
        "needs: produce" in attest
        and "if: needs.produce.result == 'success'" in attest,
        "attester is not fail-closed behind the producer",
    )
    require(
        job_permissions(attest, "attester")
        == {
            "actions": "read",
            "attestations": "write",
            "contents": "read",
            "id-token": "write",
        },
        "attester permissions are not the exact least-privilege map",
    )

    for action, pin in ACTION_PINS.items():
        marker = f"uses: {action}@{pin}"
        expected_count = 2 if action == "actions/checkout" else 1
        require(
            count(source, marker) == expected_count,
            f"{action} is absent, duplicated, or not exactly pinned",
        )
    require(
        re.search(r"uses:\s+[^@\s]+@(?![0-9a-f]{40}\b)", source) is None,
        "workflow contains a mutable action reference",
    )
    require("secrets." not in source, "operations must not consume secrets")
    require("AWS_" not in source, "operations must not consume AWS state")
    require(
        re.search(r"^\s{4}environment:", source, re.MULTILINE) is None,
        "operations jobs must remain unprivileged",
    )
    require("workflow_run:" not in source, "untrusted workflow_run trigger appeared")

    for relative in EXPECTED_FILES:
        require(relative in source, f"registered file is absent: {relative}")
    require(
        "test \"$(wc -l <\"${output}/SHA256SUMS\")\" = \"9\"" in source,
        "producer no longer seals exactly nine subjects",
    )
    require(
        "subject-checksums: "
        "${{ runner.temp }}/submission-operations-attestation/SHA256SUMS"
        in attest,
        "attester no longer signs the exact inventory",
    )
    require(
        "predicate-type: ${{ env.PREDICATE_TYPE }}" in attest,
        "attester predicate type is no longer immutable",
    )
    for archive_contract in (
        'expected_directories = {"proofs", "support", "support/SQ10"}',
        'canonical.startswith("../")',
        "canonical not in expected_directories",
        "mode not in (0, stat.S_IFREG)",
        "entry.flag_bits & 0x1",
        "total > 64 * 1024 * 1024",
        "if files != expected:",
    ):
        require(
            archive_contract in attest,
            f"attester archive safety contract is absent: {archive_contract}",
        )

    collector = reviewed_collector(source)
    required_collector_contracts = (
        "scripts/collect-submission-evidence-source.sh",
        "select-run-artifact",
        "--paginate",
        "--slurp",
        "--deny-self-hosted-runners",
        "--signer-workflow",
        "--signer-digest",
        "--source-digest",
        "--source-ref refs/heads/master",
        "unique |",
        "latest-retained",
        "exact-current",
        "availability-subject.sha256",
        "posture-subject.sha256",
        "paging-subject.sha256",
        "recovery-evidence.sha256",
        "https://github.com/upgradedev/archon-datahub/attestations/governed-canary-cloud-v2",
        '"archon.governed-canary-recovery-evidence/v2"',
        '"archon.governed-canary-recovery/v4"',
        'exact(recovery["runtimeProfile"], "cloud", "canary runtime profile")',
        '"Archon-staging-Judge"',
        '"archon_demo.customers,PROD)"',
        'exact(canary_predicate, recovery, "canary attestation predicate/evidence")',
        'canonical_digest(recovery, "canary recovery evidence")',
        'canonical_digest(manifest, "canary recovery manifest")',
        "production-paging-delivery-${RELEASE_SHA}-",
        "governed-canary-rollback-${GOVERNED_CANARY_RUN_ID}-",
        "availabilityObservedAt",
        "dt.timedelta(hours=7)",
        "dt.timedelta(hours=30)",
        "dt.timedelta(days=7)",
        '"alarmCount": 10',
        '"allActionsEnabled": True',
        '"alarmActionsBoundToTopic": True',
        '"okActionsBoundToTopic": True',
        '"insufficientDataActionsEmpty": True',
        'canary_dir.parent / "verification" / "recovery-evidence.json.json"',
        'recovery["deploymentEvidenceSha256"]',
        'manifest["endpointBindingSha256"]',
        'positive_decimal(source["runId"]',
        '"canary source runAttempt exceeds ten digits"',
        "dt.timedelta(hours=2)",
        '"17 */6 * * *"',
        '"2026-08-31T21:00:00Z"',
        '.state == "active"',
        "recheck_native",
        'canonical.startswith("../")',
        "canonical not in expected_directories",
        "unexpected native artifact directory",
    )
    for marker in required_collector_contracts:
        require(marker in collector, f"collector lost contract: {marker}")
    forbidden_collector_contracts = (
        "rm -rf",
        "eval ",
        "curl ",
        "wget ",
        "secrets.",
        "production-paging-delivery-candidate-",
    )
    for marker in forbidden_collector_contracts:
        require(marker not in collector, f"collector contains forbidden token: {marker}")
    require(
        'observation["availabilityObservedAt"],\n'
        '    availability["observedAt"],'
        in collector,
        "SQ10 availability is not bound to the attested SQ3 timestamp",
    )
    require(
        '.state == "active" and\n'
        '  (.id | type) == "number" and'
        in collector,
        "monitor state is not bound to the exact active workflow record",
    )
    require(
        "cmp --silent" in attest
        and "submission-operations-retained-facts.json" in attest,
        "attester no longer reconstructs and byte-compares facts",
    )


def replace_once(source: str, old: str, new: str) -> str:
    require(count(source, old) == 1, f"mutation anchor is not unique: {old}")
    return source.replace(old, new, 1)


workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
validate_workflow(workflow)

mutations = {
    "top-level write permission": replace_once(
        workflow,
        "\npermissions: {}\n",
        "\npermissions:\n  contents: write\n",
    ),
    "optional canary selector": replace_once(
        workflow,
        "      governed_canary_run_id:\n"
        "        description: Exact successful governed DataHub Cloud canary v2 run\n"
        "        required: true\n",
        "      governed_canary_run_id:\n"
        "        description: Exact successful governed DataHub Cloud canary v2 run\n"
        "        required: false\n",
    ),
    "producer signing authority": replace_once(
        workflow,
        "      attestations: read\n",
        "      attestations: write\n",
    ),
    "producer action write authority": replace_once(
        workflow,
        "      actions: read\n      attestations: read\n",
        "      actions: write\n      attestations: read\n",
    ),
    "producer extra write scope": replace_once(
        workflow,
        "      actions: read\n      attestations: read\n",
        "      actions: read\n      attestations: read\n      checks: write\n",
    ),
    "attester content write authority": replace_once(
        workflow,
        "      attestations: write\n"
        "      contents: read\n"
        "      id-token: write\n",
        "      attestations: write\n"
        "      contents: write\n"
        "      id-token: write\n",
    ),
    "attester extra write scope": replace_once(
        workflow,
        "      contents: read\n      id-token: write\n",
        "      contents: read\n      id-token: write\n      packages: write\n",
    ),
    "unverified runner provenance": replace_once(
        workflow,
        "#|       --deny-self-hosted-runners \\\n",
        "",
    ),
    "paging candidate accepted": replace_once(
        workflow,
        '#|   "production-paging-delivery-${RELEASE_SHA}-" \\\n',
        '#|   "production-paging-delivery-candidate-${RELEASE_SHA}-" \\\n',
    ),
    "public probe relabeled availability": replace_once(
        workflow,
        '#|     observation["availabilityObservedAt"],\n',
        '#|     observation["observedAt"],\n',
    ),
    "canary verification rederived": replace_once(
        workflow,
        '#|     canary_dir.parent / "verification" / "recovery-evidence.json.json"\n',
        '#|     canary_dir / "attestation-predicate.json"\n',
    ),
    "canary Cloud runtime weakened to Core": replace_once(
        workflow,
        '#| exact(recovery["runtimeProfile"], "cloud", "canary runtime profile")\n',
        '#| exact(recovery["runtimeProfile"], "core", "canary runtime profile")\n',
    ),
    "canary endpoint binding detached": replace_once(
        workflow,
        '#|     recovery["endpointBindingSha256"],\n'
        '#|     "canary endpoint binding",\n',
        '#|     manifest["endpointBindingSha256"],\n'
        '#|     "canary endpoint binding",\n',
    ),
    "canary manifest digest accepted without canonical verification": replace_once(
        workflow,
        '#| manifest_digest = canonical_digest(manifest, "canary recovery manifest")\n',
        '#| manifest_digest = digest(manifest["digest"], "canary recovery manifest")\n',
    ),
    "canary run identifier coercion accepted": replace_once(
        workflow,
        '#|     positive_decimal(source["runId"], "canary source runId"),\n',
        '#|     int(source["runId"]),\n',
    ),
    "stale sealed canary recovery accepted": replace_once(
        workflow,
        '#| if recovered_at - prepared_at > dt.timedelta(hours=2):\n'
        '#|     fail("canary sealed recovery capability is stale")\n',
        "",
    ),
    "alarm inventory weakened": replace_once(
        workflow,
        '#|         "alarmCount": 10,\n',
        '#|         "alarmCount": alarm_inventory["alarmCount"],\n',
    ),
    "monitor no longer active": replace_once(
        workflow,
        '#|   .state == "active" and\n',
        '#|   (.state | type) == "string" and\n',
    ),
    "attester comparison removed": replace_once(
        workflow,
        "          cmp --silent \\\n"
        '            "${RUNNER_TEMP}/submission-operations-expected-facts.json" \\\n'
        '            "${RUNNER_TEMP}/submission-operations-retained-facts.json"\n',
        "",
    ),
    "archive traversal accepted": replace_once(
        workflow,
        '                      or canonical.startswith("../")\n',
        "",
    ),
    "native archive traversal accepted": replace_once(
        workflow,
        '#|             or canonical.startswith("../")\n',
        "",
    ),
    "extra archive directories accepted": replace_once(
        workflow,
        "                      if canonical not in expected_directories:\n"
        '                          raise SystemExit("unexpected archive directory")\n',
        "",
    ),
    "extra native archive directories accepted": replace_once(
        workflow,
        "#|             if canonical not in expected_directories:\n"
        '#|                 raise SystemExit("unexpected native artifact directory")\n',
        "",
    ),
    "attester can run after producer failure": replace_once(
        workflow,
        "    if: needs.produce.result == 'success'\n",
        "    if: always()\n",
    ),
}
for label, mutant in mutations.items():
    try:
        validate_workflow(mutant)
    except ContractError:
        continue
    raise AssertionError(f"operations contract accepted mutant: {label}")

print(
    json.dumps(
        {
            "schemaVersion": "archon.submission-operations-contract-test/v1",
            "inputs": list(EXPECTED_INPUTS),
            "jobs": list(EXPECTED_JOBS),
            "subjects": len(EXPECTED_FILES) - 1,
            "mutantsRejected": len(mutations),
            "result": "passed",
        },
        sort_keys=True,
    )
)
