#!/usr/bin/env python3
"""Cross-workflow mutation contracts for post-merge dual-runtime readiness."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATHS = {
    "reconcile": "scripts/reconcile-aws-foundation.sh",
    "contract": "contracts/aws-foundation-v1.json",
    "foundation": ".github/workflows/aws-foundation.yml",
    "live": ".github/workflows/live-datahub-proof.yml",
    "deploy": ".github/workflows/deploy.yml",
    "core": ".github/workflows/datahub-core-ami.yml",
    "companion": ".github/workflows/datahub-companion-image.yml",
    "canary": ".github/workflows/governed-canary.yml",
    "recovery": ".github/workflows/governed-canary-recovery.yml",
    "credentials": "scripts/load-datahub-cloud-canary-credentials.sh",
    "docs_foundation": "docs/AWS_FOUNDATION.md",
    "docs_trial": "docs/DATAHUB_CLOUD_TRIAL.md",
    "docs_live": "docs/LIVE_DATAHUB_PROOF.md",
    "docs_core": "docs/DATAHUB_CORE.md",
    "docs_canary": "docs/GOVERNED_CANARY.md",
}
SOURCES = {
    name: (ROOT / relative).read_text(encoding="utf-8")
    for name, relative in PATHS.items()
}


class ContractError(AssertionError):
    """Raised when a release-readiness trust boundary is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_all(source: str, markers: tuple[str, ...], label: str) -> None:
    for marker in markers:
        require(marker in source, f"{label} lost contract: {marker}")


def validate(sources: dict[str, str]) -> None:
    reconcile = sources["reconcile"]
    contract = json.loads(sources["contract"])
    foundation = sources["foundation"]
    live = sources["live"]
    deploy = sources["deploy"]
    core = sources["core"]
    companion = sources["companion"]
    canary = sources["canary"]
    recovery = sources["recovery"]
    credentials = sources["credentials"]
    docs_foundation = sources["docs_foundation"]
    docs_trial = sources["docs_trial"]
    docs_live = sources["docs_live"]
    docs_core = sources["docs_core"]
    docs_canary = sources["docs_canary"]

    require(
        '(.aws.applicationStackRolePreflight | length) == 6' in reconcile,
        "foundation must validate six application stack role receipts",
    )
    require(
        reconcile.count("GitHubDataHubCloudTrialRoleArn") == 3
        and reconcile.count("GitHubDataHubCloudTrialRoleName") == 3,
        "both exact stack-output allowlists and trial verification must remain bound",
    )
    ordered_roles = """(.aws.operationalRoles | map(.kind)) == [
    "judge-staging",
    "datahub-cloud-trial-staging",
    "judge-production",
    "datahub-cloud-trial-production",
    "cloud-runtime-publisher",
    "posture-observer",
    "runtime-read",
    "paging-test"
  ]"""
    require(ordered_roles in reconcile, "the eight operational receipts changed")
    combined_trial_bindings = """    "${OPERATIONAL_ROLE_BINDING_SHA[datahub-cloud-trial-staging]}" \\
    "${OPERATIONAL_ROLE_BINDING_SHA[judge-production]}" \\
    "${OPERATIONAL_ROLE_BINDING_SHA[datahub-cloud-trial-production]}" \\
    "${OPERATIONAL_ROLE_BINDING_SHA[cloud-runtime-publisher]}" """
    require(
        combined_trial_bindings in reconcile,
        "both trial role bindings are not sealed in the combined digest",
    )
    require_all(
        reconcile,
        (
            'echo "datahub_cloud_trial_staging_role_arn=${OPERATIONAL_ROLE_ARN[datahub-cloud-trial-staging]}"',
            'echo "datahub_cloud_trial_production_role_arn=${OPERATIONAL_ROLE_ARN[datahub-cloud-trial-production]}"',
        ),
        "foundation output",
    )
    require_all(
        foundation,
        (
            "steps.reconcile.outputs.datahub_cloud_trial_staging_role_arn",
            "steps.reconcile.outputs.datahub_cloud_trial_production_role_arn",
            ": \"${DATAHUB_CLOUD_TRIAL_STAGING_ROLE_ARN:?staging Cloud trial role handoff missing}\"",
            ": \"${DATAHUB_CLOUD_TRIAL_PRODUCTION_ROLE_ARN:?production Cloud trial role handoff missing}\"",
        ),
        "foundation workflow handoff",
    )
    trial = contract["aws"]["deployRoles"]["dataHubCloudTrial"]["foundationRole"]
    require(
        trial
        == {
            "stackNameTemplate": "Archon-GitHub-<stage>-Deploy-Role",
            "stackOutputs": [
                "GitHubDataHubCloudTrialRoleArn",
                "GitHubDataHubCloudTrialRoleName",
            ],
            "workflowOutputs": {
                "staging": (
                    "steps.reconcile.outputs."
                    "datahub_cloud_trial_staging_role_arn"
                ),
                "production": (
                    "steps.reconcile.outputs."
                    "datahub_cloud_trial_production_role_arn"
                ),
            },
        },
        "trial role handoff contract changed",
    )
    core_contract = contract["aws"]["coreAmiFoundation"]
    require(
        core_contract["githubBuildRole"]["stackOutput"]
        == "GitHubCoreAmiBuildRoleArn"
        and core_contract["githubBuildRole"]["foundationWorkflowOutput"]
        == "steps.core_ami_foundation.outputs.build_role_arn"
        and core_contract["ec2Builder"]["stackOutputs"]
        == [
            "CoreAmiBuilderRoleArn",
            "CoreAmiBuilderInstanceProfileName",
            "CoreAmiBuilderInstanceProfileArn",
        ]
        and core_contract["ec2Builder"]["instanceProfileFoundationWorkflowOutput"]
        == "steps.core_ami_foundation.outputs.instance_profile",
        "Core AMI post-foundation handoff changed",
    )

    require_all(
        live,
        (
            "environment:\n      name: ${{ inputs.stage }}",
            "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
            "role-to-assume: ${{ vars.AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN }}",
            "allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}",
            "output-env-credentials: false",
            "output-credentials: true",
            "inline-session-policy: >-",
            '"Action":"cloudformation:DescribeStacks"',
            '"Action":"secretsmanager:GetSecretValue"',
            '"Action":"kms:Decrypt"',
            '"kms:ViaService":"secretsmanager.eu-west-1.amazonaws.com"',
            '--stack-name "Archon-${STAGE}-Judge"',
            "ArchonCloudReaderSecretArn",
            "--version-stage AWSCURRENT",
            'has("SecretBinary") | not',
            'archon.datahub-cloud-reader-secret/v1',
            "trap cleanup_cloud_secret EXIT",
            "::add-mask::%s",
            "credential_binding_digest=\"sha256:$(\n",
            "credentialBindingDigest:",
            '.proof.credentialBindingDigest |',
        ),
        "live Cloud proof",
    )
    require("environment: datahub-demo" not in live, "static proof environment returned")
    require(
        "secrets.DATAHUB_CLOUD_" not in live,
        "static GitHub DataHub Cloud credentials returned",
    )
    require(
        "datahub-cloud/writer-" not in live,
        "read-only live proof can access the writer secret",
    )

    require_all(
        deploy,
        (
            'r"archon-datahub-cloud-runtime-v2:cloud-v2-" + re.escape(expected)',
            'tag_suffix=":cloud-v2-${RELEASE_SHA}"',
            'repository_uri="${tagged_image_uri%"${tag_suffix}"}"',
            'test "${repository_uri}${tag_suffix}" = "${tagged_image_uri}"',
            "archon-datahub-cloud-runtime-v2@sha256:",
            ".releaseSha == $sha and .companionSourceSha == $sha and",
            ".event as $actual_event",
            "($events | index($actual_event)) != null",
            '".github/workflows/datahub-cloud-runtime-image.yml" \\\n            \'["push","workflow_dispatch"]\'',
            '".github/workflows/datahub-core-ami.yml" \\\n            \'["workflow_dispatch"]\'',
            '.status == "completed" and .conclusion == "success"',
        ),
        "deployment producer binding",
    )

    require_all(
        companion,
        (
            "github.event_name != 'pull_request' ||",
            "retention-days: ${{ github.ref == 'refs/heads/master' && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && 90 || 1 }}",
            "if: >-\n      github.ref == 'refs/heads/master' &&\n      (github.event_name == 'push' || github.event_name == 'workflow_dispatch')",
            "artifact-ids: ${{ needs.candidate.outputs.artifact_id }}",
        ),
        "qualifying companion dispatch",
    )
    require_all(
        core,
        (
            'test "${GITHUB_REF}" = "refs/heads/master"',
            'test "${GITHUB_SHA}" = "${SOURCE_SHA}"',
            'git/ref/heads/master" --jq .object.sha',
            '.name == "DataHub companion OCI"',
            '.path == ".github/workflows/datahub-companion-image.yml"',
            '(.event == "push" or .event == "workflow_dispatch") and',
            '.head_branch == "master"',
            ".head_repository.full_name == $repository",
            ".head_sha == $sourceSha",
            '.status == "completed"',
            '.conclusion == "success"',
            "gh attestation verify evidence/companion-image.tar.gz",
            "--signer-workflow",
            ".github/workflows/datahub-companion-image.yml",
            '--signer-digest "${SOURCE_SHA}"',
            '--source-digest "${SOURCE_SHA}"',
            "--source-ref refs/heads/master",
            "attestations/datahub-companion-image/v1",
            "--deny-self-hosted-runners",
            'echo "artifact_id=${artifact_id}" >>"${GITHUB_OUTPUT}"',
            "artifact-ids: ${{ steps.companion.outputs.artifact_id }}",
            "Revalidate exact signed master immediately before AWS OIDC",
            '.commit.verification.verified == true and',
        ),
        "Core companion supply chain",
    )

    require(
        core.index("Revalidate exact signed master immediately before AWS OIDC")
        < core.index("Configure staging AWS credentials through OIDC"),
        "Core master revalidation must immediately precede AWS OIDC",
    )
    for workflow, label in ((canary, "normal canary"), (recovery, "recovery")):
        require(
            workflow.count("AWS_CANARY_RECOVERY_ROLE_ARN") == 2
            and "AWS_CANARY_ROLLBACK_ROLE_ARN" not in workflow,
            f"{label} is not exactly bound to the recovery role",
        )
        require(
            "secrets.CANARY_DATAHUB_READ_TOKEN" not in workflow
            and "secrets.CANARY_DATAHUB_WRITE_TOKEN" not in workflow,
            f"{label} returned to static GitHub DataHub tokens",
        )
        require_all(
            workflow,
            (
                "AWS_CANARY_RECOVERY_ROLE_ARN",
                "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
                "allowed-account-ids: ${{ vars.AWS_ACCOUNT_ID }}",
                "output-env-credentials: false",
                "output-credentials: true",
                "source scripts/load-datahub-cloud-canary-credentials.sh",
                "trap cleanup_canary_credentials EXIT",
            ),
            label,
        )
    require(
        'name=="Deploy lean dual-runtime AWS release"' in canary
        and "Deploy immutable AWS release" not in canary,
        "canary does not bind the current deploy workflow identity",
    )
    require_all(
        credentials,
        (
            'BASH_SOURCE[0]}" == "$0',
            "Archon-staging-Judge",
            "exact_output ArchonCloudReaderSecretArn",
            "exact_output ArchonCloudWriterSecretArn",
            "--version-stage AWSCURRENT",
            'has("SecretBinary") | not',
            "archon.datahub-cloud-reader-secret/v1",
            "archon.datahub-cloud-writer-secret/v1",
            'test "${CANARY_DATAHUB_READ_TOKEN}" != "${CANARY_DATAHUB_WRITE_TOKEN}"',
            "::add-mask::%s",
            "CANARY_DATAHUB_CREDENTIAL_BINDING_SHA256",
        ),
        "canary AWS credential loader",
    )
    for forbidden in ("GITHUB_OUTPUT", "GITHUB_ENV", "mktemp", "tee "):
        require(
            forbidden not in credentials,
            f"credential loader persists or emits secret material: {forbidden}",
        )

    require_all(
        docs_foundation,
        (
            "datahub_cloud_trial_staging_role_arn",
            "datahub_cloud_trial_production_role_arn",
            "cloud_runtime_publisher_role_arn",
            "core_ami_foundation.outputs.build_role_arn",
            "core_ami_foundation.outputs.instance_profile",
            "printf '%s' \"$value\" | gh variable set",
        ),
        "Foundation runbook",
    )
    require("--body -" not in docs_foundation, "Foundation runbook persists a hyphen")
    require_all(
        docs_trial,
        (
            "datahub_cloud_trial_staging_role_arn",
            "datahub_cloud_trial_production_role_arn",
            "archon-datahub-github-<stage>-cloud-trial",
        ),
        "Cloud trial runbook",
    )
    require_all(
        " ".join(docs_live.split()),
        (
            "selected protected `staging` or",
            "reads only `AWSCURRENT`",
            "credential-binding digest",
            "submission-judge-journey.yml",
            "Stop & teardown",
            "runs in `finally`",
        ),
        "live proof runbook",
    )
    require(
        "DATAHUB_CLOUD_GMS_TOKEN" not in docs_live
        and "protected `datahub-demo` environment" not in docs_live,
        "live proof runbook returned to static credentials",
    )
    require_all(
        docs_core,
        (
            "current remote",
            "source ref `refs/heads/master`",
            "gh attestation verify",
            "denial of self-hosted runners",
        ),
        "Core runbook",
    )
    require_all(
        " ".join(docs_canary.split()),
        (
            "exactly three environments",
            "AWS_CANARY_RECOVERY_ROLE_ARN",
            "reads only `AWSCURRENT`",
            "source-only AWS loader",
        ),
        "canary runbook",
    )
    require(
        "| `governed-canary-rollback` |" not in docs_canary
        and "CANARY_DATAHUB_READ_TOKEN" not in docs_canary
        and "CANARY_DATAHUB_WRITE_TOKEN" not in docs_canary,
        "canary runbook documents a retired environment or static token",
    )


def mutate(
    sources: dict[str, str],
    file_key: str,
    old: str,
    new: str,
) -> dict[str, str]:
    require(old in sources[file_key], f"mutation anchor missing: {file_key}: {old}")
    mutant = dict(sources)
    mutant[file_key] = sources[file_key].replace(old, new, 1)
    return mutant


validate(SOURCES)

MUTATIONS = {
    "five application role receipts": (
        "reconcile",
        "(.aws.applicationStackRolePreflight | length) == 6",
        "(.aws.applicationStackRolePreflight | length) == 5",
    ),
    "trial role output removed from one allowlist": (
        "reconcile",
        '"GitHubDataHubCloudTrialRoleName",',
        '"RemovedTrialRoleName",',
    ),
    "trial staging receipt renamed": (
        "reconcile",
        '"datahub-cloud-trial-staging"',
        '"datahub-cloud-trial-stage"',
    ),
    "trial production digest member changed": (
        "reconcile",
        "${OPERATIONAL_ROLE_BINDING_SHA[datahub-cloud-trial-production]}",
        "${OPERATIONAL_ROLE_BINDING_SHA[datahub-cloud-trial-prod]}",
    ),
    "trial staging output changed": (
        "reconcile",
        "datahub_cloud_trial_staging_role_arn=${OPERATIONAL_ROLE_ARN[datahub-cloud-trial-staging]}",
        "datahub_cloud_trial_staging_role_arn=missing",
    ),
    "trial workflow handoff changed": (
        "contract",
        "steps.reconcile.outputs.datahub_cloud_trial_production_role_arn",
        "steps.reconcile.outputs.missing_trial_role_arn",
    ),
    "static live proof environment": (
        "live",
        "name: ${{ inputs.stage }}",
        "name: datahub-demo",
    ),
    "mutable AWS credential action": (
        "live",
        "aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c",
        "aws-actions/configure-aws-credentials@v6",
    ),
    "stale Cloud secret accepted": (
        "live",
        "--version-stage AWSCURRENT",
        "--version-stage AWSPREVIOUS",
    ),
    "Cloud credential binding omitted": (
        "live",
        "credentialBindingDigest:",
        "credentialBindingRemoved:",
    ),
    "Cloud image tag changed": (
        "deploy",
        'tag_suffix=":cloud-v2-${RELEASE_SHA}"',
        'tag_suffix=":latest"',
    ),
    "pull request Cloud producer accepted": (
        "deploy",
        '\'["push","workflow_dispatch"]\'',
        '\'["push","workflow_dispatch","pull_request"]\'',
    ),
    "push Core producer accepted": (
        "deploy",
        '\'["workflow_dispatch"]\'',
        '\'["push","workflow_dispatch"]\'',
    ),
    "Core companion SHA detached": (
        "deploy",
        ".releaseSha == $sha and .companionSourceSha == $sha and",
        ".releaseSha == $sha and",
    ),
    "pull request companion run accepted": (
        "core",
        '(.event == "push" or .event == "workflow_dispatch") and',
        '(.event == "push" or .event == "workflow_dispatch" or .event == "pull_request") and',
    ),
    "manual companion run rejected": (
        "core",
        '(.event == "push" or .event == "workflow_dispatch") and',
        '.event == "push" and',
    ),
    "push companion run rejected": (
        "core",
        '(.event == "push" or .event == "workflow_dispatch") and',
        '.event == "workflow_dispatch" and',
    ),
    "manual companion attestation disabled": (
        "companion",
        "if: >-\n      github.ref == 'refs/heads/master' &&\n      (github.event_name == 'push' || github.event_name == 'workflow_dispatch')",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/master'",
    ),
    "manual companion retention shortened": (
        "companion",
        "retention-days: ${{ github.ref == 'refs/heads/master' && (github.event_name == 'push' || github.event_name == 'workflow_dispatch') && 90 || 1 }}",
        "retention-days: ${{ github.event_name == 'push' && 90 || 1 }}",
    ),
    "mutable companion name download restored": (
        "core",
        "artifact-ids: ${{ steps.companion.outputs.artifact_id }}",
        "name: ${{ steps.companion.outputs.artifact_name }}",
    ),
    "pre-OIDC master revalidation removed": (
        "core",
        "Revalidate exact signed master immediately before AWS OIDC",
        "Skip exact master revalidation before AWS OIDC",
    ),
    "companion source ref changed": (
        "core",
        "--source-ref refs/heads/master",
        "--source-ref refs/heads/feature",
    ),
    "obsolete deploy identity restored": (
        "canary",
        'name=="Deploy lean dual-runtime AWS release"',
        'name=="Deploy immutable AWS release"',
    ),
    "normal rollback role changed": (
        "canary",
        "AWS_CANARY_RECOVERY_ROLE_ARN",
        "AWS_CANARY_ROLLBACK_ROLE_ARN",
    ),
    "recovery loader bypassed": (
        "recovery",
        "source scripts/load-datahub-cloud-canary-credentials.sh",
        "source scripts/load-unverified-credentials.sh",
    ),
    "credential loader accepts stale version": (
        "credentials",
        "--version-stage AWSCURRENT",
        "--version-stage AWSPREVIOUS",
    ),
    "writer credential mislabeled as reader": (
        "credentials",
        "archon.datahub-cloud-writer-secret/v1",
        "archon.datahub-cloud-reader-secret/v1",
    ),
    "Foundation runbook loses production trial handoff": (
        "docs_foundation",
        "datahub_cloud_trial_production_role_arn",
        "missing_production_trial_role_arn",
    ),
    "Cloud trial runbook loses verified staging handoff": (
        "docs_trial",
        "datahub_cloud_trial_staging_role_arn",
        "missing_staging_trial_role_arn",
    ),
    "live runbook restores a static token": (
        "docs_live",
        "No static GitHub DataHub token secret is used.",
        "Use DATAHUB_CLOUD_GMS_TOKEN.",
    ),
    "Core runbook weakens the signed source ref": (
        "docs_core",
        "source ref `refs/heads/master`",
        "source ref `refs/heads/feature`",
    ),
    "canary runbook restores four environments": (
        "docs_canary",
        "exactly three environments",
        "four intentionally distinct environments",
    ),
}

for label, (file_key, old, new) in MUTATIONS.items():
    mutant = mutate(SOURCES, file_key, old, new)
    try:
        validate(mutant)
    except (ContractError, json.JSONDecodeError):
        continue
    raise AssertionError(f"post-merge readiness contract accepted mutant: {label}")

print(
    json.dumps(
        {
            "schemaVersion": "archon.post-merge-readiness-contract-test/v1",
            "files": len(PATHS),
            "mutantsRejected": len(MUTATIONS),
            "result": "passed",
        },
        sort_keys=True,
    )
)
