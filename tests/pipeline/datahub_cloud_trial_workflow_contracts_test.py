#!/usr/bin/env python3
"""Workflow-security assertions for the DataHub Cloud trial pipeline."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "datahub-cloud-trial.yml"


class DataHubCloudTrialWorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_contract_tests_run_for_push_and_pull_request(self) -> None:
        self.assertIn("push:", self.source)
        self.assertIn("pull_request:", self.source)
        self.assertNotIn("pull_request_target:", self.source)
        self.assertIn(
            "python3 tests/pipeline/datahub_cloud_trial_contracts_test.py",
            self.source,
        )
        self.assertIn(
            "python3 tests/pipeline/datahub_cloud_trial_workflow_contracts_test.py",
            self.source,
        )
        self.assertEqual(
            self.source.count(
                '"services/datahub-companion/demo/seed_datahub.py"'
            ),
            2,
        )
        self.assertEqual(
            self.source.count(
                "python3 services/datahub-companion/demo/test_seed_datahub.py"
            ),
            2,
        )

    def test_live_operation_is_manual_default_branch_only(self) -> None:
        self.assertIn("workflow_dispatch:", self.source)
        self.assertIn(
            "github.event_name == 'workflow_dispatch'",
            self.source,
        )
        self.assertIn(
            "github.repository == 'upgradedev/archon-datahub'",
            self.source,
        )
        self.assertIn("github.ref == 'refs/heads/master'", self.source)
        self.assertIn(
            'test "${default_branch}" = "master"',
            self.source,
        )
        self.assertIn(
            'test "${GITHUB_SHA}" = "${RELEASE_SHA}"',
            self.source,
        )
        self.assertIn("workflow_success ci.yml", self.source)
        self.assertIn("workflow_success codeql.yml", self.source)
        self.assertIn(
            "workflow_success workflow-security.yml",
            self.source,
        )

    def test_all_actions_are_commit_pinned(self) -> None:
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", self.source, re.MULTILINE)
        self.assertGreaterEqual(len(uses), 5)
        for reference in uses:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[^@]+@[0-9a-f]{40}$")

    def test_checkout_never_persists_credentials(self) -> None:
        checkout_count = self.source.count("uses: actions/checkout@")
        self.assertEqual(checkout_count, 2)
        self.assertEqual(
            self.source.count("persist-credentials: false"),
            checkout_count,
        )

    def test_admin_pat_is_step_scoped_and_never_artifacted(self) -> None:
        secret_reference = (
            "DATAHUB_CLOUD_ADMIN_PAT: "
            "${{ secrets.DATAHUB_CLOUD_ADMIN_PAT }}"
        )
        self.assertEqual(self.source.count(secret_reference), 1)
        self.assertNotRegex(
            self.source,
            r"(?i)(echo|printf|cat|tee).{0,80}DATAHUB_CLOUD_ADMIN_PAT",
        )
        self.assertNotIn("::add-mask::${DATAHUB_CLOUD_ADMIN_PAT}", self.source)
        self.assertNotIn("set -x", self.source)
        upload_section = self.source.split(
            "- name: Upload only the sanitized receipt", 1
        )[1].split("- name: Attest", 1)[0]
        self.assertIn(
            "${{ runner.temp }}/datahub-cloud-trial-receipt/receipt.json",
            upload_section,
        )
        self.assertNotIn("DATAHUB_CLOUD", upload_section)

    def test_secret_manager_is_write_only_and_stdin_bound(self) -> None:
        clients = (
            ROOT / "scripts" / "datahub_cloud_trial_clients.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"put-secret-value"', clients)
        self.assertIn('"file:///dev/stdin"', clients)
        self.assertEqual(clients.count('"get-secret-value"'), 1)
        self.assertNotIn("GetSecretValue", clients)
        self.assertIn("ArchonCloudReaderSecretArn", clients)
        self.assertIn("ArchonCloudWriterSecretArn", clients)
        self.assertIn("ArchonSecretsKeyArn", clients)
        self.assertIn(
            "inputs.action != 'plan'",
            self.source,
        )
        self.assertIn(
            "arn:aws:iam::${AWS_ACCOUNT_ID}:role/"
            "archon-datahub-github-${DEPLOYMENT_ENVIRONMENT}-cloud-trial",
            self.source,
        )
        self.assertIn(
            "AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN",
            self.source,
        )
        self.assertNotIn("AWS_DEPLOY_ROLE_ARN", self.source)

    def test_oidc_is_late_and_aws_credentials_are_execute_step_scoped(self) -> None:
        setup = self.source.index("uses: astral-sh/setup-uv@")
        resolution = self.source.index("uv sync")
        oidc = self.source.index("id: cloud-trial-aws")
        execute = self.source.index("id: operate")
        upload = self.source.index("- name: Upload only the sanitized receipt")
        self.assertLess(setup, resolution)
        self.assertLess(resolution, oidc)
        self.assertLess(oidc, execute)
        self.assertLess(execute, upload)
        self.assertIn("output-env-credentials: false", self.source)
        self.assertIn("output-credentials: true", self.source)
        execute_section = self.source[execute:upload]
        for variable in (
            "AWS_ACCESS_KEY_ID:",
            "AWS_SECRET_ACCESS_KEY:",
            "AWS_SESSION_TOKEN:",
        ):
            self.assertEqual(self.source.count(variable), 1)
            self.assertIn(variable, execute_section)

    def test_minimal_permissions_and_protected_environment(self) -> None:
        self.assertIn("permissions:\n  contents: read", self.source)
        operate = self.source.split("  operate:", 1)[1]
        self.assertIn("actions: read", operate)
        self.assertIn("attestations: write", operate)
        self.assertIn("contents: read", operate)
        self.assertIn("id-token: write", operate)
        self.assertNotIn("packages: write", self.source)
        self.assertNotIn("security-events: write", self.source)
        self.assertIn(
            "name: ${{ inputs.deployment_environment }}",
            operate,
        )

    def test_runner_temp_only_and_no_local_cache(self) -> None:
        self.assertIn(
            'evidence="${RUNNER_TEMP}/datahub-cloud-trial-receipt"',
            self.source,
        )
        self.assertIn("enable-cache: false", self.source)
        self.assertIn("UV_NO_PROGRESS", self.source)
        self.assertNotIn("actions/cache", self.source)
        self.assertNotIn("Codex Security", self.source)
        self.assertNotIn("codex-security", self.source.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
