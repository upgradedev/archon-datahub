#!/usr/bin/env python3
"""Static fail-closed contracts for the secretless GitHub posture observer."""

from __future__ import annotations

import copy
import json
import pathlib
import re
from collections.abc import Callable
from typing import Any


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_PATH = (
    REPOSITORY_ROOT
    / ".github"
    / "workflows"
    / "github-repository-posture.yml"
)
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "verify-github-repository-posture.sh"
POLICY_PATH = (
    REPOSITORY_ROOT / "contracts" / "github-repository-posture-v1.json"
)

WORKFLOW_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")
SCRIPT_TEXT = SCRIPT_PATH.read_text(encoding="utf-8")
POLICY_TEXT = POLICY_PATH.read_text(encoding="utf-8")

EXPECTED_ENVIRONMENTS = [
    "datahub-demo",
    "datahub-demo-seed",
    "governed-canary",
    "governed-canary-recovery",
    "governed-canary-rollback",
    "judge-access-production",
    "judge-access-staging",
    "production",
    "production-observer",
    "production-paging-test",
    "staging",
    "submission-bonus-feedback",
    "submission-content-review",
    "submission-devpost-confirmation",
    "submission-readiness",
]
EXPECTED_PENDING_ENVIRONMENTS = [
    "datahub-demo-seed",
    "governed-canary",
    "governed-canary-recovery",
    "governed-canary-rollback",
    "judge-access-production",
    "judge-access-staging",
    "production",
    "submission-bonus-feedback",
    "submission-content-review",
    "submission-devpost-confirmation",
    "submission-readiness",
]
EXPECTED_AUTOMATED_ENVIRONMENTS = [
    "datahub-demo",
    "production-observer",
    "production-paging-test",
    "staging",
]
EXPECTED_ACTION_PATTERNS = [
    "actions/attest@*",
    "actions/cache/*@*",
    "actions/cache@*",
    "actions/checkout@*",
    "actions/dependency-review-action@*",
    "actions/download-artifact@*",
    "actions/setup-node@*",
    "actions/upload-artifact@*",
    "aquasecurity/setup-trivy@*",
    "aquasecurity/trivy-action@*",
    "astral-sh/setup-uv@*",
    "aws-actions/configure-aws-credentials@*",
    "docker/build-push-action@*",
    "docker/setup-buildx-action@*",
    "github/codeql-action/*@*",
    "zizmorcore/zizmor-action@*",
]
EXPECTED_RECEIPT_PATH = (
    "${{ runner.temp }}/github-repository-posture/"
    "github-repository-posture.json"
)


class ContractError(AssertionError):
    """Raised when a reviewed repository-posture invariant is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def canonical_policy(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def validate_policy(policy_text: str) -> dict[str, Any]:
    try:
        policy = json.loads(policy_text)
    except json.JSONDecodeError as error:
        raise ContractError("policy must be valid JSON") from error

    require(policy_text == canonical_policy(policy), "policy must be canonical")
    require(
        set(policy) == {
            "administrationOnly",
            "environments",
            "repository",
            "schemaVersion",
        },
        "policy top-level fields must be exact",
    )
    require(
        policy["schemaVersion"]
        == "archon.github-repository-posture-policy/v1",
        "policy schema must be exact",
    )
    require(
        policy["repository"]
        == {
            "allowAutoMerge": False,
            "allowMergeCommit": False,
            "allowRebaseMerge": False,
            "allowSquashMerge": True,
            "allowUpdateBranch": True,
            "archived": False,
            "branch": {"name": "master", "protected": True},
            "defaultBranch": "master",
            "deleteBranchOnMerge": True,
            "disabled": False,
            "fullName": "upgradedev/archon-datahub",
            "hasWiki": False,
            "licenseSpdxId": "Apache-2.0",
            "private": False,
            "privateVulnerabilityReporting": True,
            "visibility": "public",
        },
        "repository identity and public master posture must be exact",
    )

    environments = policy["environments"]
    require(
        set(environments)
        == {
            "branchPolicy",
            "canAdminsBypass",
            "exactNames",
            "pendingIndependentReviewer",
            "reviewerlessByDesign",
        },
        "environment policy fields must be exact",
    )
    require(
        environments["branchPolicy"]
        == {
            "branchName": "master",
            "branchType": "branch",
            "customBranchPolicies": True,
            "protectedBranches": False,
        },
        "every environment must allow exactly the master branch",
    )
    require(
        environments["canAdminsBypass"] is False,
        "all fifteen environments must disable administrator bypass",
    )
    require(
        environments["exactNames"] == EXPECTED_ENVIRONMENTS,
        "the fifteen-environment inventory must be exact",
    )

    pending = environments["pendingIndependentReviewer"]
    require(
        set(pending)
        == {
            "exactNames",
            "expectedProtectionRuleTypes",
            "state",
        },
        "pending-reviewer policy fields must be exact",
    )
    require(
        pending["exactNames"] == EXPECTED_PENDING_ENVIRONMENTS,
        "the eleven pending-reviewer environments must be exact",
    )
    require(
        pending["state"] == "pending-independent-reviewer",
        "privileged environments must be transparently pending review",
    )
    require(
        pending["expectedProtectionRuleTypes"] == ["branch_policy"],
        "pending environments must reject unexpected reviewer rules",
    )
    automated = environments["reviewerlessByDesign"]
    require(
        set(automated)
        == {
            "exactNames",
            "expectedProtectionRuleTypes",
            "state",
        },
        "reviewerless policy fields must be exact",
    )
    require(
        automated["exactNames"] == EXPECTED_AUTOMATED_ENVIRONMENTS,
        "the four reviewerless-by-design environments must be exact",
    )
    require(
        automated["state"] == "reviewerless-by-design",
        "automated environments must be labelled reviewerless by design",
    )
    require(
        automated["expectedProtectionRuleTypes"] == ["branch_policy"],
        "automated environments must reject unexpected protection rules",
    )
    require(
        set(pending["exactNames"]).isdisjoint(automated["exactNames"]),
        "environment posture tiers must be disjoint",
    )
    require(
        sorted(pending["exactNames"] + automated["exactNames"])
        == environments["exactNames"],
        "environment tiers must cover the exact inventory",
    )

    administration = policy["administrationOnly"]
    require(
        set(administration) == {"actions", "environmentSecrets", "status"},
        "administration-only fields must be exact",
    )
    require(
        administration["status"]["value"]
        == "unverified-requires-administration-and-environments-read",
        "elevated-read controls must remain explicitly unverified",
    )
    require(
        "Administration:read" in administration["status"]["reason"]
        and "Environments:read" in administration["status"]["reason"],
        "the unverified limitation must name both missing permissions",
    )
    require(
        administration["actions"]
        == {
            "allowedActions": "selected",
            "githubOwnedAllowed": False,
            "patternsAllowed": EXPECTED_ACTION_PATTERNS,
            "shaPinningRequired": True,
            "verifiedAllowed": False,
        },
        "the sixteen observed Actions patterns must be exact expected data",
    )
    require(
        administration["environmentSecrets"]
        == {
            "expectedEmptyEnvironmentNames":
                EXPECTED_PENDING_ENVIRONMENTS,
            "requiredFineGrainedPermissions": [
                "Actions:read",
                "Administration:read",
                "Environments:read",
                "Metadata:read",
            ],
            "status": "unverified-requires-environments-read",
        },
        "secret-name expectations must stay in the unverified elevated tier",
    )
    return policy


def validate_workflow(workflow: str) -> None:
    require(
        workflow.startswith(
            "name: GitHub repository posture "
            "(admin/elevated-read controls unverified)\n"
        ),
        "workflow label must disclose every unverified elevated-read control",
    )
    require(
        "    name: Secretless posture "
        "(admin/elevated-read controls unverified)\n" in workflow,
        "job label must disclose the honest secretless tier",
    )
    require(
        (
            'on:\n'
            '  schedule:\n'
            '    - cron: "41 2 * * *"\n'
            '  workflow_dispatch:\n'
            '\n'
            'permissions:\n'
        )
        in workflow,
        "workflow triggers must be exactly schedule and manual dispatch",
    )
    for forbidden_event in (
        "push",
        "pull_request",
        "pull_request_target",
        "workflow_call",
        "workflow_run",
    ):
        require(
            re.search(
                rf"(?m)^  {re.escape(forbidden_event)}:",
                workflow,
            )
            is None,
            f"forbidden workflow trigger: {forbidden_event}",
        )
    require(
        workflow.count(
            "permissions:\n"
            "  actions: read\n"
            "  contents: read\n"
        )
        == 1,
        "top-level token permissions must be exact and read-only",
    )
    require(
        workflow.count(
            "    permissions:\n"
            "      actions: read\n"
            "      contents: read\n"
        )
        == 1,
        "job token permissions must be exact and read-only",
    )
    require(
        re.search(r"(?m)^\s+[a-z-]+:\s+write\s*$", workflow) is None,
        "workflow token must never receive write permission",
    )
    require("continue-on-error:" not in workflow, "checks must fail closed")
    require(
        "EXPECTED_REPOSITORY: upgradedev/archon-datahub" in workflow
        and 'test "${GITHUB_REPOSITORY}" = "${EXPECTED_REPOSITORY}"'
        in workflow,
        "workflow must gate the exact repository",
    )
    require(
        "EXPECTED_REF: refs/heads/master" in workflow
        and 'test "${GITHUB_REF}" = "${EXPECTED_REF}"' in workflow,
        "workflow must gate the exact master ref",
    )
    require(
        "schedule | workflow_dispatch) ;;" in workflow,
        "workflow must fail closed on every other event",
    )
    require(
        "GH_TOKEN: ${{ github.token }}" in workflow,
        "observer must use only the automatic GitHub token",
    )
    require(
        "secrets." not in workflow,
        "secretless posture must not consume repository secrets",
    )
    require(
        "bash scripts/verify-github-repository-posture.sh" in workflow,
        "workflow must invoke the reviewed verifier",
    )
    require(
        (
            "POLICY_PATH: ${{ github.workspace }}/contracts/"
            "github-repository-posture-v1.json"
        )
        in workflow,
        "workflow must bind the checked-in exact policy",
    )
    require(
        workflow.count(EXPECTED_RECEIPT_PATH) == 2,
        "only the exact RUNNER_TEMP receipt may cross the artifact boundary",
    )
    require(
        f"          path: {EXPECTED_RECEIPT_PATH}\n" in workflow,
        "artifact path must be the normalized receipt file, not a directory",
    )
    require(
        "          if-no-files-found: error\n" in workflow,
        "a missing receipt must fail artifact retention",
    )
    require(
        "          retention-days: 90\n" in workflow,
        "posture evidence must be retained for ninety days",
    )
    require(
        "          overwrite: false\n" in workflow,
        "posture evidence must not overwrite an earlier artifact",
    )

    uses = re.findall(r"(?m)^\s*-\s+uses:\s+([^\s#]+)", workflow)
    require(len(uses) == 2, "workflow action inventory must be exact")
    require(
        all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", item) for item in uses),
        "every external action must be pinned to a full commit SHA",
    )


def validate_script(script: str) -> None:
    require(
        script.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"),
        "verifier must use strict bash",
    )
    require(
        'readonly EXPECTED_REPOSITORY="upgradedev/archon-datahub"' in script,
        "verifier repository gate must be exact",
    )
    require(
        'readonly EXPECTED_BRANCH="master"' in script,
        "verifier branch gate must be exact",
    )
    require(
        'readonly EXPECTED_REF="refs/heads/${EXPECTED_BRANCH}"' in script,
        "verifier ref gate must derive from exact master",
    )
    require(
        'readonly API_VERSION="2026-03-10"' in script,
        "verifier must use the current documented GitHub REST version",
    )
    require(
        script.count(
            '-H "X-GitHub-Api-Version: ${API_VERSION}" \\'
        )
        == 1,
        "the reviewed GET helper must send the exact API version header",
    )
    for gate in (
        'test "${GITHUB_API_URL}" = "https://api.github.com"',
        'test "${GITHUB_REPOSITORY}" = "${EXPECTED_REPOSITORY}"',
        'test "${GITHUB_REF}" = "${EXPECTED_REF}"',
        '[[ "${GITHUB_SHA}" =~ ^[0-9a-f]{40}$ ]]',
        'schedule | workflow_dispatch) ;;',
    ):
        require(gate in script, f"missing exact verifier gate: {gate}")

    methods = re.findall(r"--method\s+([A-Za-z]+)", script)
    require(methods == ["GET"], "GitHub API use must be GET-only")
    require(
        len(re.findall(r"(?m)^\s*gh api\s*\\$", script)) == 1,
        "all GitHub API access must pass through one reviewed GET helper",
    )
    for forbidden in (
        "curl ",
        "wget ",
        "gh secret",
        "gh variable",
        "gh repo edit",
        "/actions/permissions",
        "/branches/${EXPECTED_BRANCH}/protection",
        "/secrets",
    ):
        require(
            forbidden not in script,
            f"forbidden mutation or admin-only API surface: {forbidden}",
        )
    for path in (
        '"/repos/${GITHUB_REPOSITORY}"',
        (
            '"/repos/${GITHUB_REPOSITORY}/git/ref/heads/'
            '${EXPECTED_BRANCH}"'
        ),
        '"/repos/${GITHUB_REPOSITORY}/branches/${EXPECTED_BRANCH}"',
        '"/repos/${GITHUB_REPOSITORY}/license"',
        (
            '"/repos/${GITHUB_REPOSITORY}/'
            'private-vulnerability-reporting"'
        ),
        '"/repos/${GITHUB_REPOSITORY}/environments?per_page=100"',
        '"/repos/${GITHUB_REPOSITORY}/environments/${environment_name}"',
        (
            '"/repos/${GITHUB_REPOSITORY}/environments/'
            '${environment_name}/deployment-branch-policies?per_page=100"'
        ),
    ):
        require(path in script, f"missing reviewed GET endpoint: {path}")

    for policy_anchor in (
        '(.administrationOnly.actions.patternsAllowed | length) == 16',
        '(.environments.exactNames | length) == 15',
        (
            '(.environments.pendingIndependentReviewer.exactNames '
            '| length) == 11'
        ),
        (
            '(.environments.reviewerlessByDesign.exactNames '
            '| length) == 4'
        ),
        (
            '.environments.pendingIndependentReviewer.'
            'expectedProtectionRuleTypes ==\n    ["branch_policy"]'
        ),
        (
            '.administrationOnly.environmentSecrets.status ==\n'
            '    "unverified-requires-environments-read"'
        ),
        (
            '.administrationOnly.status.value ==\n'
            '    "unverified-requires-administration-and-environments-read"'
        ),
    ):
        require(policy_anchor in script, f"missing policy gate: {policy_anchor}")
    require(
        (
            ".administrationOnly.environmentSecrets."
            "requiredFineGrainedPermissions == [\n"
            '    "Actions:read",\n'
            '    "Administration:read",\n'
            '    "Environments:read",\n'
            '    "Metadata:read"\n'
            "  ]"
        )
        in script,
        "future elevated observer permissions must be exact",
    )
    require(
        'test "${observed_environment_names}" = '
        '"${expected_environment_names}"' in script,
        "observed environment names must equal the policy set",
    )
    require(
        ".environments.canAdminsBypass == false" in script,
        "policy must require administrator bypass off for all environments",
    )
    require(
        ".can_admins_bypass == false" in script,
        "every environment must disable administrator bypass",
    )
    require(
        "([.protection_rules[].type] | sort) == $expectedRuleTypes"
        in script,
        "unexpected reviewers or protection rules must fail closed",
    )
    require(
        ".total_count == 1 and\n"
        "      (.branch_policies | length) == 1 and\n"
        "      .branch_policies[0].name == $branch and\n"
        '      .branch_policies[0].type == "branch"' in script,
        "each environment must allow exactly one master branch policy",
    )
    require(
        "expectedEmptyEnvironmentNames ==\n"
        "    .environments.pendingIndependentReviewer.exactNames" in script,
        "unverified empty-secret expectation must bind to all pending names",
    )
    require(
        "secret_names" not in script
        and "environment_secrets_json" not in script
        and "verified-empty" not in script,
        "automatic-token tier must not enumerate or claim environment secrets",
    )
    require(
        "canAdminsBypass: false," in script,
        "normalized receipt must retain the administrator-bypass observation",
    )

    live_repository_invariants = (
        ".full_name == $repository",
        '.visibility == "public"',
        ".private == false",
        ".allow_auto_merge == false",
        ".allow_merge_commit == false",
        ".allow_rebase_merge == false",
        ".allow_squash_merge == true",
        ".allow_update_branch == true",
        ".delete_branch_on_merge == true",
        ".has_wiki == false",
        ".archived == false",
        ".disabled == false",
        ".default_branch == $branch",
    )
    for invariant in live_repository_invariants:
        require(
            invariant in script,
            f"repository GET must enforce public invariant: {invariant}",
        )
    require(
        '.license.spdx_id == "Apache-2.0"' in script,
        "license observation must enforce Apache-2.0",
    )
    require(
        "jq -e '.enabled == true' <<<\"${private_reporting_json}\""
        in script,
        "private-vulnerability-reporting observation must require enabled",
    )
    for receipt_field in (
        "allowAutoMerge: false,",
        "allowMergeCommit: false,",
        "allowRebaseMerge: false,",
        "allowSquashMerge: true,",
        "allowUpdateBranch: true,",
        "deleteBranchOnMerge: true,",
        "hasWiki: false,",
    ):
        require(
            script.count(receipt_field) == 2,
            f"policy gate and receipt must both retain: {receipt_field}",
        )

    require(
        (
            'readonly EXPECTED_OUTPUT_PATH="${RUNNER_TEMP}/'
            'github-repository-posture/github-repository-posture.json"'
        )
        in script,
        "receipt destination must be the exact RUNNER_TEMP file",
    )
    require(
        'test "${OUTPUT_PATH}" = "${EXPECTED_OUTPUT_PATH}"' in script,
        "caller cannot redirect the receipt outside RUNNER_TEMP",
    )
    require(
        'readonly work_dir="$(mktemp -d "${RUNNER_TEMP}/'
        'github-repository-posture.XXXXXX")"' in script,
        "raw observations must stay in an isolated runner-temp directory",
    )
    require(
        "trap 'rm -rf -- \"${work_dir}\"' EXIT" in script,
        "temporary API material must be removed",
    )
    require(
        'local error_path="${work_dir}/api-error"' in script,
        "API error bodies must remain temporary",
    )
    work_files = sorted(
        re.findall(r"\$\{work_dir\}/([A-Za-z0-9.-]+)", script)
    )
    require(
        work_files
        == [
            "api-error",
            "canonical.json",
            "github-repository-posture.json",
        ],
        "verifier must not materialize raw API response bodies",
    )
    require(
        'verification: "not-performed"' in script,
        "receipt must not claim admin-only verification",
    )
    require(
        (
            "environmentSecrets: {\n"
            "          expectedEmptyEnvironmentCount: "
            "$expectedEmptyEnvironmentCount,\n"
            "          requiredFineGrainedPermissions: "
            "$environmentSecretPermissions,\n"
            "          status: $environmentSecretStatus,\n"
            '          verification: "not-performed"\n'
            "        },"
        )
        in script,
        "receipt must label secret-name inventory as unverified",
    )
    require(
        "expectedActionsPolicyDigest" in script
        and "expectedActionsPatternCount" in script,
        "receipt must identify the unverified admin-tier expectation",
    )
    for receipt_anchor in (
        'test ! -L "${temporary_output}"',
        'test "$(stat -c \'%s\' "${temporary_output}")" -le 1048576',
        'jq -cS . "${temporary_output}" >"${canonical_output}"',
        'cmp --silent "${temporary_output}" "${canonical_output}"',
        'mv -- "${temporary_output}" "${OUTPUT_PATH}"',
        'chmod 0600 "${OUTPUT_PATH}"',
        'test ! -L "${OUTPUT_PATH}"',
    ):
        require(
            receipt_anchor in script,
            f"missing normalized receipt safety gate: {receipt_anchor}",
        )


def validate(workflow: str, script: str, policy_text: str) -> None:
    validate_policy(policy_text)
    validate_workflow(workflow)
    validate_script(script)


def replace_once(source: str, old: str, new: str) -> str:
    require(source.count(old) == 1, f"mutation anchor must be unique: {old}")
    return source.replace(old, new, 1)


def mutate_policy(mutator: Callable[[dict[str, Any]], None]) -> str:
    policy = copy.deepcopy(json.loads(POLICY_TEXT))
    mutator(policy)
    return canonical_policy(policy)


def mutate_repository(field: str, value: Any) -> str:
    return mutate_policy(
        lambda policy: policy["repository"].__setitem__(field, value)
    )


validate(WORKFLOW_TEXT, SCRIPT_TEXT, POLICY_TEXT)

mutations: dict[str, tuple[str, str, str]] = {
    "api mutation verb": (
        WORKFLOW_TEXT,
        replace_once(SCRIPT_TEXT, "--method GET", "--method PUT"),
        POLICY_TEXT,
    ),
    "api version drift": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            'readonly API_VERSION="2026-03-10"',
            'readonly API_VERSION="unsupported"',
        ),
        POLICY_TEXT,
    ),
    "api version header bypass": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            '-H "X-GitHub-Api-Version: ${API_VERSION}" \\',
            '-H "X-GitHub-Api-Version: unsupported" \\',
        ),
        POLICY_TEXT,
    ),
    "repository identity predicate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            ".full_name == $repository",
            "(.full_name | type) == \"string\"",
        ),
        POLICY_TEXT,
    ),
    "public visibility predicate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            '.visibility == "public"',
            '(.visibility | type) == "string"',
        ),
        POLICY_TEXT,
    ),
    "private flag predicate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            ".private == false",
            '(.private | type) == "boolean"',
        ),
        POLICY_TEXT,
    ),
    "license predicate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            '.license.spdx_id == "Apache-2.0"',
            '(.license.spdx_id | type) == "string"',
        ),
        POLICY_TEXT,
    ),
    "private vulnerability reporting predicate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            "jq -e '.enabled == true' <<<\"${private_reporting_json}\"",
            (
                "jq -e '(.enabled | type) == \"boolean\"' "
                "<<<\"${private_reporting_json}\""
            ),
        ),
        POLICY_TEXT,
    ),
    "repository gate drift": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            'readonly EXPECTED_REPOSITORY="upgradedev/archon-datahub"',
            'readonly EXPECTED_REPOSITORY="fork/archon-datahub"',
        ),
        POLICY_TEXT,
    ),
    "master ref gate drift": (
        replace_once(
            WORKFLOW_TEXT,
            "EXPECTED_REF: refs/heads/master",
            "EXPECTED_REF: refs/heads/main",
        ),
        SCRIPT_TEXT,
        POLICY_TEXT,
    ),
    "environment inventory omission": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["environments"]["exactNames"].pop()
        ),
    ),
    "environment wildcard policy": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["environments"]["branchPolicy"].update(
                {"branchName": "*"}
            )
        ),
    ),
    "unexpected pending reviewer accepted": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["environments"][
                "pendingIndependentReviewer"
            ].update(
                {
                    "expectedProtectionRuleTypes": [
                        "branch_policy",
                        "required_reviewers",
                    ]
                }
            )
        ),
    ),
    "secret expectation leaked into automatic tier": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["environments"][
                "pendingIndependentReviewer"
            ].update({"secretInventory": "verified-empty"})
        ),
    ),
    "admin controls relabelled verified": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["administrationOnly"]["status"].update(
                {"value": "verified"}
            )
        ),
    ),
    "secret inventory relabelled verified": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["administrationOnly"][
                "environmentSecrets"
            ].update({"status": "verified-empty"})
        ),
    ),
    "environments read permission omitted": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["administrationOnly"][
                "environmentSecrets"
            ]["requiredFineGrainedPermissions"].remove(
                "Environments:read"
            )
        ),
    ),
    "actions pattern omitted": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["administrationOnly"]["actions"][
                "patternsAllowed"
            ].pop()
        ),
    ),
    "automatic token secret enumeration introduced": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            (
                '  environment_json="$(\n'
                '    api_get \\\n'
                '      "${environment_name} environment" \\\n'
                '      "/repos/${GITHUB_REPOSITORY}/environments/'
                '${environment_name}"\n'
                '  )"\n'
            ),
            (
                '  environment_json="$(\n'
                '    api_get \\\n'
                '      "${environment_name} environment" \\\n'
                '      "/repos/${GITHUB_REPOSITORY}/environments/'
                '${environment_name}"\n'
                '  )"\n'
                '  environment_secrets_json="$(\n'
                '    api_get \\\n'
                '      "${environment_name} secrets" \\\n'
                '      "/repos/${GITHUB_REPOSITORY}/environments/'
                '${environment_name}/secrets?per_page=100"\n'
                '  )"\n'
            ),
        ),
        POLICY_TEXT,
    ),
    "protection exactness weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            "([.protection_rules[].type] | sort) == $expectedRuleTypes",
            "([.protection_rules[].type] | sort) != []",
        ),
        POLICY_TEXT,
    ),
    "administrator bypass accepted": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            ".can_admins_bypass == false",
            "(.can_admins_bypass | type) == \"boolean\"",
        ),
        POLICY_TEXT,
    ),
    "administrator bypass policy enabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_policy(
            lambda policy: policy["environments"].update(
                {"canAdminsBypass": True}
            )
        ),
    ),
    "administrator bypass omitted from receipt": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            "          canAdminsBypass: false,\n",
            "",
        ),
        POLICY_TEXT,
    ),
    "secret inventory falsely verified in receipt": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            (
                "          status: $environmentSecretStatus,\n"
                '          verification: "not-performed"\n'
            ),
            (
                "          status: $environmentSecretStatus,\n"
                '          verification: "verified-empty"\n'
            ),
        ),
        POLICY_TEXT,
    ),
    "raw repository response materialized": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            (
                ')"\n'
                "jq -e \\\n"
                '  --arg repository "${EXPECTED_REPOSITORY}" \\\n'
            ),
            (
                ')"\n'
                'printf \'%s\' "${repository_json}" '
                '> "${work_dir}/raw-repository.json"\n'
                "jq -e \\\n"
                '  --arg repository "${EXPECTED_REPOSITORY}" \\\n'
            ),
        ),
        POLICY_TEXT,
    ),
    "auto merge enabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("allowAutoMerge", True),
    ),
    "merge commits enabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("allowMergeCommit", True),
    ),
    "rebase merge enabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("allowRebaseMerge", True),
    ),
    "squash merge disabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("allowSquashMerge", False),
    ),
    "update branch disabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("allowUpdateBranch", False),
    ),
    "delete branch on merge disabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("deleteBranchOnMerge", False),
    ),
    "wiki enabled": (
        WORKFLOW_TEXT,
        SCRIPT_TEXT,
        mutate_repository("hasWiki", True),
    ),
    "live merge gate weakened": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            ".allow_merge_commit == false",
            "(.allow_merge_commit | type) == \"boolean\"",
        ),
        POLICY_TEXT,
    ),
    "merge posture omitted from receipt": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            (
                "      repository: {\n"
                "        allowAutoMerge: false,\n"
            ),
            "      repository: {\n",
        ),
        POLICY_TEXT,
    ),
    "receipt redirected outside runner temp": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            (
                'readonly EXPECTED_OUTPUT_PATH="${RUNNER_TEMP}/'
                'github-repository-posture/github-repository-posture.json"'
            ),
            'readonly EXPECTED_OUTPUT_PATH="/tmp/posture.json"',
        ),
        POLICY_TEXT,
    ),
    "canonical receipt comparison removed": (
        WORKFLOW_TEXT,
        replace_once(
            SCRIPT_TEXT,
            'cmp --silent "${temporary_output}" "${canonical_output}"',
            'test -s "${canonical_output}"',
        ),
        POLICY_TEXT,
    ),
    "artifact directory uploaded": (
        replace_once(
            WORKFLOW_TEXT,
            f"          path: {EXPECTED_RECEIPT_PATH}\n",
            (
                "          path: "
                "${{ runner.temp }}/github-repository-posture\n"
            ),
        ),
        SCRIPT_TEXT,
        POLICY_TEXT,
    ),
    "artifact retention weakened": (
        replace_once(
            WORKFLOW_TEXT,
            "          retention-days: 90\n",
            "          retention-days: 30\n",
        ),
        SCRIPT_TEXT,
        POLICY_TEXT,
    ),
    "missing artifact tolerated": (
        replace_once(
            WORKFLOW_TEXT,
            "          if-no-files-found: error\n",
            "          if-no-files-found: warn\n",
        ),
        SCRIPT_TEXT,
        POLICY_TEXT,
    ),
    "admin limitation hidden": (
        replace_once(
            WORKFLOW_TEXT,
            "name: GitHub repository posture "
            "(admin/elevated-read controls unverified)\n",
            "name: GitHub repository posture\n",
        ),
        SCRIPT_TEXT,
        POLICY_TEXT,
    ),
}

for label, (workflow, script, policy_text) in mutations.items():
    require(
        (workflow, script, policy_text)
        != (WORKFLOW_TEXT, SCRIPT_TEXT, POLICY_TEXT),
        f"mutation must change source: {label}",
    )
    try:
        validate(workflow, script, policy_text)
    except ContractError:
        continue
    raise AssertionError(f"unsafe mutation was accepted: {label}")

print(
    json.dumps(
        {
            "schemaVersion":
                "archon.github-repository-posture-contract-test/v1",
            "actionsPatterns": len(EXPECTED_ACTION_PATTERNS),
            "automatedEnvironments": len(EXPECTED_AUTOMATED_ENVIRONMENTS),
            "environmentCount": len(EXPECTED_ENVIRONMENTS),
            "mutationCases": sorted(mutations),
            "pendingEnvironments": len(EXPECTED_PENDING_ENVIRONMENTS),
            "result": "passed",
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
