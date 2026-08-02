#!/usr/bin/env python3
"""CI contract tests for the DataHub Cloud trial control plane."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import datahub_cloud_trial as trial
import datahub_cloud_trial_graphql as graphql
from datahub_cloud_trial_clients import (
    AwsSecretWriter,
    DataHubHttpStatusError,
    McpCallDenied,
    McpClient,
    StagedSecret,
    TrialError,
    cloud_endpoints,
)

CONTRACT = ROOT / "contracts" / "datahub-cloud-trial-v1.json"


class DataHubCloudTrialContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_official_graphql_source_is_exact(self) -> None:
        official = self.contract["officialGraphqlContract"]
        self.assertEqual(
            official["commit"],
            "53064c2d9b41f77a141736ad6eb037966174329b",
        )
        self.assertEqual(graphql.SOURCE_COMMIT, official["commit"])
        self.assertEqual(
            official["serviceAccountInput"],
            ["displayName", "description"],
        )
        self.assertEqual(
            official["accessTokenInput"]["type"],
            "SERVICE_ACCOUNT",
        )
        self.assertEqual(
            official["accessTokenInput"]["duration"],
            "ONE_MONTH",
        )
        self.assertIn(
            "createServiceAccount($input: CreateServiceAccountInput!)",
            graphql.CREATE_SERVICE_ACCOUNT,
        )
        self.assertIn(
            "createAccessToken($input: CreateAccessTokenInput!)",
            graphql.CREATE_ACCESS_TOKEN,
        )
        self.assertIn(
            "batchAssignRole($input: BatchAssignRoleInput!)",
            graphql.BATCH_ASSIGN_ROLE,
        )

    def test_exact_least_privilege_policy(self) -> None:
        writer = "urn:li:corpuser:archon-writer-test"
        policy = graphql.expected_policy_input("staging", writer)
        self.assertEqual(policy["type"], "METADATA")
        self.assertEqual(policy["state"], "ACTIVE")
        self.assertEqual(policy["privileges"], ["EDIT_DATASET_COL_TAGS"])
        self.assertEqual(policy["actors"]["users"], [writer])
        self.assertEqual(policy["actors"]["groups"], [])
        self.assertFalse(policy["actors"]["allUsers"])
        self.assertFalse(policy["actors"]["allGroups"])
        self.assertFalse(policy["actors"]["resourceOwners"])
        self.assertEqual(
            policy["resources"]["filter"]["criteria"],
            [
                {
                    "field": "URN",
                    "condition": "EQUALS",
                    "values": [
                        "urn:li:dataset:(urn:li:dataPlatform:sqlite,"
                        "archon_demo.customers,PROD)"
                    ],
                }
            ],
        )
        self.assertEqual(
            policy["resources"]["privilegeConstraints"]["criteria"],
            [
                {
                    "field": "URN",
                    "condition": "EQUALS",
                    "values": ["urn:li:tag:PII"],
                }
            ],
        )
        self.assertNotIn("policyConstraints", policy["resources"])
        self.assertNotIn("allResources", policy["resources"])

    def test_effective_writer_mutation_expansion_fails_closed(self) -> None:
        writer = "urn:li:corpuser:archon-writer-test"
        self.assertEqual(
            self.contract["identities"]["effectiveWriterPrivilegeExpansion"],
            {
                "directUser": "fail-closed",
                "allUsers": "fail-closed",
                "readerRole": "fail-closed",
            },
        )
        reader_role = "urn:li:dataHubRole:Reader"
        control = graphql.TrialControlPlane(object(), "staging")
        control.reader_role = lambda: {"urn": reader_role}
        actor_cases = {
            "direct": {
                "users": [writer],
                "roles": [],
                "allUsers": False,
            },
            "reader-role": {
                "users": [],
                "roles": [reader_role],
                "allUsers": False,
            },
            "all-users": {
                "users": [],
                "roles": [],
                "allUsers": True,
            },
        }
        for label, actors in actor_cases.items():
            with self.subTest(label=label):
                control.policies = lambda actors=actors: [
                    {
                        "urn": f"urn:li:dataHubPolicy:{label}",
                        "actors": actors,
                        "privileges": ["EDIT_DATASET_COL_TAGS"],
                    }
                ]
                with self.assertRaises(TrialError):
                    control.assert_no_effective_write_expansion(
                        writer,
                        "urn:li:dataHubPolicy:exact",
                    )
        control.policies = lambda: [
            {
                "urn": "urn:li:dataHubPolicy:reader",
                "actors": {
                    "users": [],
                    "roles": [reader_role],
                    "allUsers": False,
                },
                "privileges": ["VIEW_ENTITY_PAGE"],
            }
        ]
        control.assert_no_effective_write_expansion(
            writer,
            "urn:li:dataHubPolicy:exact",
        )
        self.assertIn("users groups roles", graphql.LIST_POLICIES)

    def test_service_accounts_and_tokens_are_stage_scoped(self) -> None:
        reader = graphql.service_account_spec("production", "reader")
        writer = graphql.service_account_spec("production", "writer")
        self.assertEqual(
            reader["displayName"],
            "Archon production DataHub reader",
        )
        self.assertEqual(
            writer["displayName"],
            "Archon production DataHub writer",
        )
        self.assertNotEqual(reader, writer)
        self.assertEqual(
            graphql.token_name("staging", "reader", "123", "2"),
            "archon-staging-reader-runtime-123-2",
        )
        main_source = (ROOT / "scripts" / "datahub_cloud_trial.py").read_text(encoding="utf-8")
        self.assertIn('"type": "SERVICE_ACCOUNT"', main_source)
        self.assertIn('"duration": "ONE_MONTH"', main_source)
        self.assertIn('"duration": "ONE_MONTH"', CONTRACT.read_text("utf-8"))

    def test_cloud_endpoint_is_derived_and_fail_closed(self) -> None:
        endpoints = cloud_endpoints("https://demo.acryl.io/gms")
        self.assertEqual(endpoints.host, "demo.acryl.io")
        self.assertEqual(endpoints.graphql_path, "/api/graphql")
        self.assertEqual(endpoints.mcp_path, "/integrations/ai/mcp")
        for invalid in (
            "http://demo.acryl.io/gms",
            "https://demo.acryl.io:444/gms",
            "https://user@demo.acryl.io/gms",
            "https://demo.acryl.io/gms?token=x",
            "https://example.com/gms",
            "https://acryl.io/gms",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(TrialError):
                    cloud_endpoints(invalid)

    def test_cloud_seed_reuses_fixture_with_exact_tenant_binding(self) -> None:
        seeder = (
            ROOT
            / "services"
            / "datahub-companion"
            / "demo"
            / "seed_datahub.py"
        ).read_text(encoding="utf-8")
        operation = (
            ROOT / "scripts" / "datahub_cloud_trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn("def _validate_emitter_target(", seeder)
        self.assertIn(
            "cloud_tenant_host: str | None = None",
            seeder,
        )
        self.assertIn(
            "cloud_tenant_host=cloud_endpoints(gms_url).host",
            operation,
        )
        self.assertNotIn(
            'emit_metadata(gms_url, Path("in-memory-token-not-read"))',
            operation,
        )
    def test_transport_failure_and_generic_errors_never_count_as_denial(self) -> None:
        client = McpClient(
            cloud_endpoints("https://demo.acryl.io/gms"),
            "reader-token-with-sufficient-length",
            "archon-contract-test",
        )
        with patch.object(
            client._http,
            "request",
            side_effect=TrialError("synthetic transient transport failure"),
        ):
            with self.assertRaises(TrialError) as transient:
                client._rpc("tools/call", {}, allow_denial=True)
        self.assertNotIsInstance(transient.exception, McpCallDenied)

        with patch.object(
            client._http,
            "request",
            side_effect=DataHubHttpStatusError(500),
        ):
            with self.assertRaises(DataHubHttpStatusError):
                client._rpc("tools/call", {}, allow_denial=True)

        with patch.object(
            client._http,
            "request",
            side_effect=DataHubHttpStatusError(403),
        ):
            with self.assertRaises(McpCallDenied):
                client._rpc("tools/call", {}, allow_denial=True)

        def response(payload: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
            return (
                200,
                {"content-type": "application/json"},
                json.dumps({"jsonrpc": "2.0", "id": 1, **payload}).encode("utf-8"),
            )

        generic_rpc = McpClient(
            cloud_endpoints("https://demo.acryl.io/gms"),
            "reader-token-with-sufficient-length",
            "archon-generic-rpc-test",
        )
        with patch.object(
            generic_rpc._http,
            "request",
            return_value=response(
                {"error": {"code": -32603, "message": "Internal error"}}
            ),
        ):
            with self.assertRaises(TrialError) as generic:
                generic_rpc._rpc("tools/call", {}, allow_denial=True)
        self.assertNotIsInstance(generic.exception, McpCallDenied)

        generic_tool = McpClient(
            cloud_endpoints("https://demo.acryl.io/gms"),
            "reader-token-with-sufficient-length",
            "archon-generic-tool-test",
        )
        with patch.object(
            generic_tool._http,
            "request",
            return_value=response(
                {
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": "upstream timed out"}],
                    }
                }
            ),
        ):
            with self.assertRaises(TrialError) as generic:
                generic_tool._rpc("tools/call", {}, allow_denial=True)
        self.assertNotIsInstance(generic.exception, McpCallDenied)

        explicit = McpClient(
            cloud_endpoints("https://demo.acryl.io/gms"),
            "reader-token-with-sufficient-length",
            "archon-explicit-denial-test",
        )
        with patch.object(
            explicit._http,
            "request",
            return_value=response(
                {"error": {"code": -32000, "message": "Permission denied"}}
            ),
        ):
            with self.assertRaises(McpCallDenied):
                explicit._rpc("tools/call", {}, allow_denial=True)

    def test_live_canary_validates_writer_before_network(self) -> None:
        with self.assertRaises(TrialError):
            trial.run_live_canary(
                object(),
                "reader-token-with-sufficient-length",
                "",
            )

    def test_official_mcp_mutation_arguments_are_exact(self) -> None:
        mcp = self.contract["officialMcpContract"]
        self.assertEqual(mcp["version"], "0.6.0")
        self.assertEqual(
            mcp["commit"],
            "9a6946daa7d30eb481c82dd8ee5e15ae6526a3c9",
        )
        self.assertEqual(mcp["tools"], ["add_tags", "remove_tags"])
        expected = {
            "tag_urns": ["urn:li:tag:PII"],
            "entity_urns": [
                "urn:li:dataset:(urn:li:dataPlatform:sqlite,"
                "archon_demo.customers,PROD)"
            ],
            "column_paths": ["customer_email"],
        }
        self.assertEqual(trial.MUTATION_ARGUMENTS, expected)
        self.assertEqual(
            self.contract["liveCanary"]["mutationArguments"],
            expected,
        )
        self.assertEqual(
            self.contract["liveCanary"]["writerRoundTrip"],
            [
                "remove_tags baseline",
                "add_tags",
                "observe PII",
                "remove_tags",
                "observe absent",
            ],
        )
        self.assertEqual(
            self.contract["liveCanary"]["finalState"],
            "PII tag absent",
        )
        denial = self.contract["liveCanary"]["readerMutationProbe"]
        self.assertFalse(denial["transportFailureCountsAsDenial"])
        self.assertEqual(denial["postProbeState"], "PII tag absent")
        self.assertIn(
            '"readerMutationStateUnchanged": True',
            (ROOT / "scripts" / "datahub_cloud_trial.py").read_text(
                encoding="utf-8"
            ),
        )

    def test_secret_values_flow_only_over_stdin_and_stage_by_version(self) -> None:
        writer = AwsSecretWriter(
            account_id="123456789012",
            region="eu-west-1",
            stage="staging",
            stack_name="Archon-staging-Judge",
        )
        token = "secret-token-value-with-sufficient-length"
        arn = (
            "arn:aws:secretsmanager:eu-west-1:123456789012:"
            "secret:archon/staging/datahub-cloud/writer-AbCdEf"
        )
        version_id = "a" * 32
        stage_label = "archon-trial-123-1"
        responses = [
            json.dumps({"ARN": arn, "VersionIdsToStages": {}}).encode(),
            json.dumps(
                {
                    "ARN": arn,
                    "VersionId": version_id,
                    "VersionStages": [stage_label],
                }
            ).encode(),
            json.dumps(
                {
                    "ARN": arn,
                    "VersionIdsToStages": {version_id: [stage_label]},
                }
            ).encode(),
        ]
        with patch.object(writer, "_run", side_effect=responses) as execute:
            staged = writer._stage_document(arn, {"token": token}, stage_label)
        arguments, stdin = execute.call_args_list[1].args
        self.assertEqual(staged.version_id, version_id)
        self.assertIn("put-secret-value", arguments)
        self.assertIn("file:///dev/stdin", arguments)
        self.assertIn("--version-stages", arguments)
        self.assertIn(stage_label, arguments)
        self.assertNotIn(token, arguments)
        self.assertEqual(json.loads(stdin), {"token": token})

    def test_reader_keys_are_stable_and_no_current_first_bootstrap_is_valid(self) -> None:
        writer = AwsSecretWriter(
            account_id="123456789012",
            region="eu-west-1",
            stage="staging",
            stack_name="Archon-staging-Judge",
        )
        first = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
        second = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
        managed = json.dumps(
            {
                "schemaVersion": writer.READER_SCHEMA,
                "gmsUrl": "https://demo.acryl.io/gms",
                "token": "runtime-token-with-sufficient-length",
                "runHandleFernetKey": first,
                "oauthMasterKey": second,
            }
        )
        with patch.object(writer, "_current_secret_string", return_value=managed):
            self.assertEqual(
                writer.reader_keys("reader-arn", "rotate"),
                (first, second),
            )
        malformed = json.dumps(
            {
                "schemaVersion": writer.READER_SCHEMA,
                "runHandleFernetKey": "bad",
                "oauthMasterKey": second,
            }
        )
        with patch.object(writer, "_current_secret_string", return_value=malformed):
            with self.assertRaises(TrialError):
                writer.reader_keys("reader-arn", "bootstrap")

        arn = (
            "arn:aws:secretsmanager:eu-west-1:123456789012:"
            "secret:archon/staging/datahub-cloud/reader-AbCdEf"
        )
        empty = json.dumps({"ARN": arn}).encode()
        with patch.object(writer, "_run", return_value=empty) as execute:
            generated = writer.reader_keys(arn, "bootstrap")
        self.assertEqual([len(value) for value in generated], [44, 44])
        self.assertNotEqual(*generated)
        self.assertEqual(execute.call_count, 1)
        self.assertIn("describe-secret", execute.call_args.args[0])
        self.assertNotIn("get-secret-value", execute.call_args.args[0])
        with patch.object(writer, "_run", return_value=empty):
            with self.assertRaises(TrialError):
                writer.reader_keys(arn, "reconcile")

    def test_runtime_secret_commit_compensates_and_revokes_generated_pair(self) -> None:
        class Control:
            def __init__(self) -> None:
                self.revoked: list[str] = []

            def revoke(self, token_id: str) -> None:
                self.revoked.append(token_id)

        staged_writer = StagedSecret(
            secret_arn="writer-arn",
            version_id="a" * 32,
            previous_current="b" * 32,
            stage_label="archon-trial-123-1",
        )

        class Aws:
            def __init__(self) -> None:
                self.rolled_back: list[StagedSecret] = []
                self.dropped: list[StagedSecret] = []

            def staging_label(self, _run_id: str, _attempt: str) -> str:
                return staged_writer.stage_label

            def stage_writer(self, *_: object, **__: object) -> StagedSecret:
                return staged_writer

            def stage_reader(self, *_: object, **__: object) -> StagedSecret:
                raise TrialError("synthetic second stage failure")

            def rollback(self, staged: StagedSecret) -> None:
                self.rolled_back.append(staged)

            def drop_stage(self, staged: StagedSecret) -> None:
                self.dropped.append(staged)

        control = Control()
        aws = Aws()
        generated = (
            graphql.GeneratedToken(
                "reader-new",
                "reader-token-with-sufficient-length",
                "reader-name",
                "reader-urn",
                1,
            ),
            graphql.GeneratedToken(
                "writer-new",
                "writer-token-with-sufficient-length",
                "writer-name",
                "writer-urn",
                1,
            ),
        )
        with self.assertRaises(TrialError):
            trial._commit_runtime_credentials(
                control,
                aws,
                endpoints=type("Endpoints", (), {"gms_url": "https://demo.acryl.io/gms"})(),
                reader={"urn": "reader-urn"},
                writer={"urn": "writer-urn"},
                generated=generated,
                read_arn="reader-arn",
                write_arn="writer-arn",
                run_handle_key="unused",
                oauth_master_key="unused",
                run_id="123",
                run_attempt="1",
                old_ids=set(),
            )
        self.assertEqual(control.revoked, ["reader-new", "writer-new"])
        self.assertEqual(aws.rolled_back, [staged_writer])
        self.assertEqual(aws.dropped, [staged_writer])

    def test_superseded_tokens_are_revoked_and_exact_inventory_is_verified(self) -> None:
        class Control:
            def __init__(self) -> None:
                self.active = {
                    "reader-urn": {"reader-old", "reader-new"},
                    "writer-urn": {"writer-old", "writer-new"},
                }

            def revoke(self, token_id: str) -> None:
                for identifiers in self.active.values():
                    identifiers.discard(token_id)

            def scoped_tokens(
                self,
                _role: str,
                actor_urn: str,
            ) -> list[dict[str, str]]:
                return [
                    {"id": token_id}
                    for token_id in sorted(self.active[actor_urn])
                ]

        control = Control()
        count = trial._revoke_superseded_and_verify(
            control,
            {"urn": "reader-urn"},
            {"urn": "writer-urn"},
            {"reader-old", "writer-old"},
            {"reader-new", "writer-new"},
        )
        self.assertEqual(count, 2)
        self.assertEqual(
            trial._scoped_token_ids(
                control,
                {"urn": "reader-urn"},
                {"urn": "writer-urn"},
            ),
            {"reader-new", "writer-new"},
        )

    def test_partial_owned_account_cleanup_is_retryable(self) -> None:
        reader = {
            "urn": "urn:li:corpuser:archon-reader",
            "description": graphql.DESCRIPTION_MARKER,
        }

        class Client:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def execute(
                self,
                operation: str,
                _query: str,
                variables: dict[str, object],
            ) -> dict[str, object]:
                self.calls.append((operation, variables))
                if operation == "batchAssignRole":
                    return {"batchAssignRole": True}
                if operation == "deleteServiceAccount":
                    return {"deleteServiceAccount": True}
                raise AssertionError(operation)

        client = Client()
        control = graphql.TrialControlPlane(client, "staging")
        control.scoped_tokens = lambda _role, _urn: []
        control.exact_policy = lambda: None
        control.find_service_account = lambda _role: None
        outcome = control.delete_owned(reader, None)
        self.assertEqual(
            outcome,
            {
                "revokedTokens": 0,
                "deletedPolicies": 0,
                "deletedServiceAccounts": 1,
            },
        )
        role_call = next(call for call in client.calls if call[0] == "batchAssignRole")
        self.assertEqual(
            role_call[1],
            {"input": {"roleUrn": None, "actors": [reader["urn"]]}},
        )

    def test_dedicated_foundation_grant_is_exact_and_writer_remains_unreadable(self) -> None:
        foundation = (
            ROOT / "infra" / "aws" / "foundation" /
            "github-actions-deploy-role.yml"
        ).read_text(encoding="utf-8")
        dedicated = foundation.split(
            "GitHubDataHubCloudTrialRole:", 1
        )[1].split("JudgeUserRole:", 1)[0]
        broad = foundation.split(
            "GitHubDeployRole:", 1
        )[1].split("GitHubDataHubCloudTrialRole:", 1)[0]
        self.assertNotIn("datahub-cloud/reader-*", broad)
        self.assertNotIn("datahub-cloud/writer-*", broad)
        self.assertIn(
            "archon-datahub-github-${DeploymentEnvironment}-cloud-trial",
            dedicated,
        )
        for action in (
            "cloudformation:DescribeStacks",
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "secretsmanager:UpdateSecretVersionStage",
            "kms:DescribeKey",
            "kms:Decrypt",
            "kms:GenerateDataKey",
        ):
            self.assertIn(action, dedicated)
        reader = dedicated.split(
            "ReadOnlyRetainedCloudReaderSecretForStableKeys", 1
        )[1].split("StageAndPromoteExactCloudRuntimeSecrets", 1)[0]
        self.assertIn("datahub-cloud/reader-*", reader)
        self.assertNotIn("datahub-cloud/writer-*", reader)
        self.assertNotIn("kms:Encrypt\\n", dedicated)
        self.assertNotIn("- iam:", dedicated)
        self.assertNotIn("iam:*", dedicated)
        self.assertNotIn("sts:AssumeRole\\n", dedicated)
        aws_contract = json.loads(
            (ROOT / "contracts" / "aws-foundation-v1.json").read_text(
                encoding="utf-8"
            )
        )
        role = aws_contract["aws"]["deployRoles"]["dataHubCloudTrial"]
        self.assertTrue(role["dedicatedRoleRequired"])
        self.assertEqual(
            role["roleVariable"],
            "AWS_DATAHUB_CLOUD_TRIAL_ROLE_ARN",
        )
        self.assertEqual(role["stackNameTemplate"], "Archon-<stage>-Judge")
        self.assertEqual(
            role["stackOutputs"],
            [
                "ArchonCloudReaderSecretArn",
                "ArchonCloudWriterSecretArn",
                "ArchonSecretsKeyArn",
            ],
        )

    def test_confirmations_and_trial_continuity_are_exact(self) -> None:
        self.assertEqual(
            trial.CONFIRMATIONS,
            {
                "plan": "",
                "bootstrap": "BOOTSTRAP DATAHUB CLOUD TRIAL 2026-08-04",
                "reconcile": "RECONCILE DATAHUB CLOUD TRIAL",
                "rotate": "ROTATE DATAHUB CLOUD TRIAL",
                "cleanup": "CLEANUP DATAHUB CLOUD TRIAL",
            },
        )
        continuity = self.contract["continuity"]
        self.assertEqual(continuity["plannedActivationDate"], "2026-08-04")
        self.assertEqual(continuity["nominalExpiryDate"], "2026-08-25")
        self.assertEqual(
            continuity["judgingAccessTargetThrough"],
            "2026-08-31",
        )
        self.assertTrue(continuity["ossCoreRemainsCanonical"])
        self.assertFalse(continuity["silentFailover"])

    def test_sources_never_serialize_credentials_to_evidence(self) -> None:
        sources = "\n".join(
            (ROOT / path).read_text(encoding="utf-8")
            for path in (
                "scripts/datahub_cloud_trial.py",
                "scripts/datahub_cloud_trial_clients.py",
                "scripts/datahub_cloud_trial_graphql.py",
            )
        )
        self.assertNotIn("traceback.print_exc", sources)
        self.assertNotIn("logger.exception", sources)
        self.assertNotIn("GetSecretValue", sources)
        self.assertEqual(sources.count("get-secret-value"), 1)
        self.assertNotIn("Codex Security", sources)
        self.assertIn("file:///dev/stdin", sources)
        self.assertIn("credential appeared in sanitized receipt", sources)


if __name__ == "__main__":
    unittest.main(verbosity=2)
