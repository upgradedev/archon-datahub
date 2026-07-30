from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "datahub-canary-fixture.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
GOVERNED_CANARY_PATH = (
    ROOT / ".github" / "workflows" / "governed-canary.yml"
)
RECOVERY_PATH = (
    ROOT / ".github" / "workflows" / "governed-canary-recovery.yml"
)
DEPLOY_PATH = ROOT / ".github" / "workflows" / "deploy.yml"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
CI = CI_PATH.read_text(encoding="utf-8")
GOVERNED_CANARY = GOVERNED_CANARY_PATH.read_text(encoding="utf-8")
RECOVERY = RECOVERY_PATH.read_text(encoding="utf-8")
DEPLOY = DEPLOY_PATH.read_text(encoding="utf-8")


def job_blocks(workflow: str) -> dict[str, str]:
    jobs = workflow.split("\njobs:\n", maxsplit=1)[1]
    matches = list(
        re.finditer(r"(?m)^  ([a-z][a-z0-9_-]*):\n", jobs)
    )
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(jobs)
        result[match.group(1)] = jobs[match.start() : end]
    return result


class DataHubCanaryFixtureWorkflowContractsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = job_blocks(WORKFLOW)
        cls.plan = cls.jobs["plan"]
        cls.apply = cls.jobs["apply"]
        cls.attest = cls.jobs["attest"]

    def test_dispatch_is_manual_with_plan_seed_and_reset(self) -> None:
        self.assertIn("  workflow_dispatch:", WORKFLOW)
        self.assertNotRegex(WORKFLOW, r"(?m)^  (push|pull_request):")
        action = re.search(
            r"(?ms)^      action:\n(?P<body>.*?)(?=^      release_sha:)",
            WORKFLOW,
        )
        self.assertIsNotNone(action)
        body = action.group("body")
        self.assertRegex(
            body,
            r"(?ms)options:\n\s+- plan\n\s+- seed\n\s+- reset\n",
        )
        self.assertIn(
            "RESET ARCHON GOVERNED CANARY FIXTURE",
            WORKFLOW,
        )
        self.assertIn(
            'test "${RESET_CONFIRMATION}" = \\\n'
            '              "RESET ARCHON GOVERNED CANARY FIXTURE"',
            self.plan,
        )

    def test_fixture_shares_the_mutation_recovery_lock(self) -> None:
        self.assertRegex(
            WORKFLOW,
            r"(?ms)^concurrency:\n"
            r"  group: archon-governed-canary-mutation-recovery\n"
            r"  cancel-in-progress: false\n",
        )

    def test_plan_precedes_every_mutation_and_is_retained(self) -> None:
        self.assertIn("environment: datahub-demo", self.plan)
        self.assertIn("scripts/datahub-canary-fixture.py plan", self.plan)
        self.assertIn("Upload the immutable fixture plan", self.plan)
        self.assertIn("retention-days: 90", self.plan)
        self.assertRegex(self.apply, r"(?m)^    needs: plan$")
        self.assertIn("inputs.action != 'plan'", self.apply)
        self.assertIn(
            "scripts/datahub-canary-fixture.py apply",
            self.apply,
        )
        self.assertIn(
            "--expected-plan-sha256",
            self.apply,
        )
        self.assertNotIn("--datahub-cli", WORKFLOW)
        self.assertIn(
            "artifact-ids: ${{ needs.plan.outputs.artifact_id }}",
            self.apply,
        )

    def test_every_locked_runtime_is_credentiallessly_validated(self) -> None:
        materialization = (
            "bash scripts/materialize-datahub-mcp-lock.sh "
            '"${RUNTIME}"'
        )
        runtime_command = (
            "scripts/datahub-canary-fixture.py validate-runtime"
        )
        runtime_schema = (
            "archon.datahub-canary-fixture-runtime-validation/v1"
        )
        sanitized_keys = re.compile(
            r'\(keys \| sort\) == \[\s*'
            r'"proposalCount",\s*'
            r'"proposalSetSha256",\s*'
            r'"schemaVersion",\s*'
            r'"stateContractSha256"\s*'
            r"\]"
        )
        self.assertEqual(WORKFLOW.count(materialization), 2)
        self.assertEqual(WORKFLOW.count(runtime_command), 2)
        self.assertEqual(WORKFLOW.count(runtime_schema), 2)
        self.assertEqual(len(sanitized_keys.findall(WORKFLOW)), 2)
        self.assertEqual(WORKFLOW.count(".proposalCount == 6"), 2)
        self.assertEqual(
            WORKFLOW.count(
                '.proposalSetSha256 | test("^[0-9a-f]{64}$")'
            ),
            2,
        )
        self.assertGreaterEqual(
            WORKFLOW.count(
                '.stateContractSha256 | test("^[0-9a-f]{64}$")'
            ),
            2,
        )
        plan_materialize = self.plan.index(
            "Materialize the exact wheel-only DataHub runtime"
        )
        plan_validate = self.plan.index(
            "Credentialless validation of the exact fixture SDK proposals"
        )
        plan_read = self.plan.index(
            "Inspect live state and author the immutable plan"
        )
        self.assertLess(plan_materialize, plan_validate)
        self.assertLess(plan_validate, plan_read)
        apply_materialize = self.apply.index(
            "Recreate the exact wheel-only DataHub runtime"
        )
        apply_validate = self.apply.index(
            "Revalidate exact fixture SDK proposals before mutation"
        )
        apply_gate = self.apply.index(
            "Final exact-SHA gate immediately before writer credentials"
        )
        self.assertLess(apply_materialize, apply_validate)
        self.assertLess(apply_validate, apply_gate)

        ci_validate = CI.index(
            "Validate governed-canary fixture proposals in the locked SDK"
        )
        self.assertLess(
            CI.index(
                'bash scripts/materialize-datahub-mcp-lock.sh "${project}"'
            ),
            ci_validate,
        )
        locked_ci = CI[ci_validate:]
        self.assertIn(runtime_command, locked_ci)
        self.assertIn(runtime_schema, locked_ci)
        self.assertRegex(locked_ci, sanitized_keys)
        self.assertIn(".proposalCount == 6", locked_ci)
        self.assertIn(
            '.stateContractSha256 | test("^[0-9a-f]{64}$")',
            locked_ci,
        )
        self.assertIn(
            '.proposalSetSha256 | test("^[0-9a-f]{64}$")',
            locked_ci,
        )

    def test_read_and_write_credentials_are_distinct_and_scoped(self) -> None:
        self.assertIn(
            "CANARY_FIXTURE_READ_GMS_URL: "
            "${{ vars.CANARY_FIXTURE_READ_GMS_URL }}",
            self.plan,
        )
        self.assertIn(
            "CANARY_FIXTURE_READ_GMS_TOKEN: "
            "${{ secrets.CANARY_FIXTURE_READ_GMS_TOKEN }}",
            self.plan,
        )
        self.assertNotIn("CANARY_FIXTURE_WRITE_GMS_TOKEN:", self.plan)
        self.assertNotIn("CANARY_FIXTURE_WRITE_GMS_URL:", self.plan)
        self.assertIn("environment: datahub-demo-seed", self.apply)
        self.assertIn(
            "CANARY_FIXTURE_WRITE_GMS_URL: "
            "${{ vars.CANARY_FIXTURE_WRITE_GMS_URL }}",
            self.apply,
        )
        self.assertIn(
            "CANARY_FIXTURE_WRITE_GMS_TOKEN: "
            "${{ secrets.CANARY_FIXTURE_WRITE_GMS_TOKEN }}",
            self.apply,
        )
        self.assertNotIn("CANARY_FIXTURE_READ_GMS_TOKEN:", self.apply)
        self.assertNotIn("CANARY_FIXTURE_READ_GMS_URL:", self.apply)
        self.assertNotIn("secrets.DATAHUB_GMS_TOKEN", WORKFLOW)
        self.assertNotIn("secrets.DATAHUB_GMS_URL", WORKFLOW)
        self.assertGreaterEqual(WORKFLOW.count("env -i \\"), 2)
        self.assertGreaterEqual(
            WORKFLOW.count(
                'DATAHUB_GMS_TOKEN="${CANARY_FIXTURE_'
            ),
            2,
        )
        self.assertGreaterEqual(
            WORKFLOW.count(
                'DATAHUB_GMS_URL="${CANARY_FIXTURE_'
            ),
            2,
        )

    def test_writer_requires_exact_solo_owner_approval(self) -> None:
        self.assertIn(
            "Solo-owner-approved fixture apply "
            "${{ needs.plan.outputs.plan_sha256 }}",
            self.apply,
        )
        self.assertIn(
            "APPROVE ARCHON CANARY FIXTURE "
            "run_id=${GITHUB_RUN_ID} "
            "run_attempt=${GITHUB_RUN_ATTEMPT} "
            "action=${ACTION} "
            "release_sha=${RELEASE_SHA} "
            "plan_sha256=${PLAN_SHA256}",
            self.apply,
        )
        self.assertIn(".prevent_self_review == false", self.apply)
        self.assertRegex(
            self.apply,
            r"reviewer\.login\s*\|\s*ascii_downcase",
        )
        self.assertIn(
            "expected exactly one matching approval",
            self.apply,
        )
        approval_position = self.apply.index(
            "Bind the exact solo-owner environment approval"
        )
        secret_position = self.apply.index(
            "CANARY_FIXTURE_WRITE_GMS_TOKEN:"
        )
        self.assertLess(approval_position, secret_position)

    def test_evidence_is_canonical_sanitized_and_content_addressed(self) -> None:
        self.assertGreaterEqual(WORKFLOW.count("jq -cS ."), 4)
        self.assertGreaterEqual(WORKFLOW.count("cmp --silent"), 4)
        self.assertGreaterEqual(WORKFLOW.count("SHA256SUMS"), 8)
        self.assertGreaterEqual(
            WORKFLOW.count("sha256sum --check --strict SHA256SUMS"),
            3,
        )
        self.assertGreaterEqual(
            WORKFLOW.count("rawAspectSnapshotSha256"),
            3,
        )
        self.assertGreaterEqual(
            WORKFLOW.count(".before.provenance"),
            3,
        )
        self.assertGreaterEqual(
            WORKFLOW.count(
                "urn:li:domain:archonGovernedCanaryFixture"
            ),
            3,
        )
        self.assertGreaterEqual(
            WORKFLOW.count('classificationState: "absent"'),
            2,
        )
        self.assertNotIn(
            "absence-proved-after-cli-error",
            WORKFLOW,
        )
        self.assertIn('.outcome == "deleted"', WORKFLOW)
        self.assertIn('.outcome == "already-absent"', WORKFLOW)
        self.assertIn(
            "archon.datahub-canary-fixture-receipt/v1",
            self.apply,
        )
        self.assertIn(
            "Upload the canonical sanitized fixture receipt",
            self.apply,
        )
        self.assertIn("retention-days: 90", self.apply)
        self.assertNotRegex(
            WORKFLOW,
            r"(?im)echo\s+.*(?:GMS_TOKEN|GMS_URL)",
        )
        self.assertGreaterEqual(
            WORKFLOW.count(">/dev/null 2>&1"),
            2,
        )

    def test_attestation_is_secretless_and_pinned(self) -> None:
        self.assertNotIn("environment:", self.attest)
        self.assertNotIn("${{ secrets.", self.attest)
        self.assertIn("attestations: write", self.attest)
        self.assertIn("id-token: write", self.attest)
        self.assertIn(
            "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
            self.attest,
        )
        self.assertIn(
            "archon.datahub-canary-fixture-attestation/v1",
            self.attest,
        )
        self.assertIn(
            "attestations/datahub-canary-fixture/v1",
            self.attest,
        )
        self.assertIn(
            "result: \"exact-fixture-ready\"",
            self.attest,
        )
        self.assertIn("subject-path: |", self.attest)
        self.assertIn("predicate-path:", self.attest)
        self.assertIn(
            "Publish exact promote-only fixture coordinates",
            self.attest,
        )
        for coordinate in (
            "fixture_coordinates=${fixture_coordinates}",
            "fixture_run_id=${GITHUB_RUN_ID}",
            "fixture_run_attempt=${GITHUB_RUN_ATTEMPT}",
            "fixture_artifact_id=${ARTIFACT_ID}",
            "fixture_artifact_digest=${ARTIFACT_DIGEST}",
            "fixture_receipt_sha256=${RECEIPT_SHA256}",
        ):
            self.assertIn(coordinate, self.attest)

    def test_fixture_receipt_is_a_required_content_addressed_canary_input(
        self,
    ) -> None:
        for input_name in (
            "fixture_run_id",
            "fixture_run_attempt",
            "fixture_artifact_id",
            "fixture_artifact_digest",
            "fixture_receipt_sha256",
        ):
            self.assertRegex(
                GOVERNED_CANARY,
                rf"(?ms)^      {input_name}:\n"
                rf".*?^        required: true\n"
                rf".*?^        type: string\n",
            )
        self.assertRegex(
            DEPLOY,
            r"(?ms)^      fixture_coordinates:\n"
            r".*?^        required: false\n"
            r".*?^        type: string\n",
        )

        fixture_verifier = GOVERNED_CANARY.index(
            "Verify exact attested governed-canary fixture binding"
        )
        aws_trust = GOVERNED_CANARY.index(
            "Assume the read-only canary evidence role"
        )
        self.assertLess(fixture_verifier, aws_trust)
        verifier = GOVERNED_CANARY[fixture_verifier:aws_trust]
        self.assertIn(
            ".github/workflows/datahub-canary-fixture.yml",
            verifier,
        )
        self.assertIn(".head_sha == $releaseSha", verifier)
        self.assertIn(".digest == $digest", verifier)
        self.assertIn(
            "contracts/datahub-canary-fixture-v1.json",
            verifier,
        )
        self.assertIn(
            "file_type not in (0, stat.S_IFREG)",
            verifier,
        )
        self.assertIn(
            "The fixture checksum inventory is not exact",
            verifier,
        )
        self.assertIn("gh attestation verify", verifier)
        self.assertIn("--deny-self-hosted-runners", verifier)
        self.assertIn("== $expectedSubjects", verifier)
        self.assertIn(
            "archon.governed-canary-fixture-binding/v1",
            verifier,
        )
        self.assertIn(
            "archon.governed-canary-recovery/v3",
            GOVERNED_CANARY,
        )
        self.assertIn(
            "archon.governed-canary-recovery/v3",
            RECOVERY,
        )
        self.assertIn(
            "fixtureBinding: $fixtureBinding",
            GOVERNED_CANARY,
        )
        self.assertIn(
            "fixtureBinding: $fixtureBinding",
            RECOVERY,
        )
        self.assertIn(
            "fixture_run_id: $fixtureRunId",
            DEPLOY,
        )
        self.assertIn(
            'canonical_fixture_coordinates="$(jq -ceS',
            DEPLOY,
        )
        self.assertIn(
            "fixtureBindingDigest:\n"
            "                    $governedCanaryFixtureBindingDigest",
            DEPLOY,
        )

    def test_all_reusable_actions_are_immutable_pins(self) -> None:
        uses = re.findall(r"(?m)^\s+-?\s*uses:\s+([^\s#]+)", WORKFLOW)
        self.assertTrue(uses)
        for value in uses:
            with self.subTest(value=value):
                self.assertRegex(value, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            uses,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            uses,
        )
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            uses,
        )

    def test_ci_executes_controller_and_workflow_contracts(self) -> None:
        controller = (
            "python3 tests/pipeline/"
            "datahub_canary_fixture_contracts_test.py"
        )
        boundary = (
            "python3 tests/pipeline/"
            "datahub_canary_fixture_workflow_contracts_test.py"
        )
        self.assertIn(controller, CI)
        self.assertIn(boundary, CI)
        self.assertLess(CI.index(controller), CI.index(boundary))


if __name__ == "__main__":
    unittest.main()
