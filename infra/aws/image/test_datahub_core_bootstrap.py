from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import types
from unittest import TestCase, main, mock

SESSION = "rs_" + "A" * 43
DIGEST = "sha256:" + "a" * 64
DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
DATA_KEY = "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"
SIGNING_KEY = "arn:aws:kms:eu-west-1:123456789012:key/22222222-2222-2222-2222-222222222222"

fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: None
fake_boto3.client = lambda _name, **_kwargs: None
fake_exceptions = types.ModuleType("botocore.exceptions")
fake_exceptions.BotoCoreError = type("BotoCoreError", (Exception,), {})
fake_exceptions.ClientError = type("ClientError", (Exception,), {})
sys.modules.setdefault("boto3", fake_boto3)
sys.modules.setdefault("botocore", types.ModuleType("botocore"))
sys.modules.setdefault("botocore.exceptions", fake_exceptions)
fake_adapter = types.ModuleType("core_job_adapter")
fake_adapter.CoreJobAdapter = object
sys.modules.setdefault("core_job_adapter", fake_adapter)

os.environ.update(
    {
        "AWS_REGION": "eu-west-1",
        "ARCHON_STAGE": "staging",
        "CORE_LEASE_TABLE": "CoreLease",
        "ARCHON_RUNTIME_GENERATION": "core-20260802-1",
        "ARCHON_RUNTIME_CAPABILITY_DIGEST": DIGEST,
        "ARCHON_IMAGE_MANIFEST_DIGEST": "sha256:" + "b" * 64,
        "ARCHON_CORE_DATA_KEY_ARN": DATA_KEY,
        "ARCHON_MUTATION_SIGNING_KEY_ARN": SIGNING_KEY,
        "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN": (
            "arn:aws:iam::123456789012:role/archon-staging-core-analytics"
        ),
        "ARCHON_LLM_PROVIDER": "bedrock",
        "ARCHON_LLM_MODEL": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "ARCHON_CHART_LLM_MODEL": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "ARCHON_QUALITY_LLM_MODEL": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "ARCHON_DELIGHT_LLM_MODEL": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "ARCHON_DEMO_QUERY": DATASET,
        "ARCHON_ANALYTICS_QUESTION": (
            "Which customer segment generated the highest net revenue in Q2 2026, "
            "and is customers.customer_email governed as PII?"
        ),
    }
)

path = pathlib.Path(__file__).with_name("datahub_core_bootstrap.py")
spec = importlib.util.spec_from_file_location("datahub_core_bootstrap", path)
assert spec is not None and spec.loader is not None
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def lease() -> dict:
    return {
        "sessionId": SESSION,
        "analyticsCredentialsVersion": "acv_" + "1" * 32,
        "analyticsCredentialsCiphertext": "eA==",
        "analyticsCredentialsExpiresAt": 1_900_000_000,
        "gatewayCredentialsVersion": "gcv_" + "2" * 32,
        "gatewayCredentialsCiphertext": "eQ==",
        "gatewayCredentialsExpiresAt": 1_900_000_000,
    }


class BootstrapBoundaryTests(TestCase):
    def test_process_envs_enforce_identity_and_network_separation(self) -> None:
        def decrypted(_lease, *, field_prefix, **_kwargs):
            if field_prefix == "analytics":
                return (
                    {
                        "AWS_ACCESS_KEY_ID": "ASIA-BEDROCK",
                        "AWS_SECRET_ACCESS_KEY": "bedrock-secret",
                        "AWS_SESSION_TOKEN": "bedrock-session",
                    },
                    "acv_" + "1" * 32,
                )
            return (
                {
                    "AWS_ACCESS_KEY_ID": "ASIA-GATEWAY",
                    "AWS_SECRET_ACCESS_KEY": "gateway-secret",
                    "AWS_SESSION_TOKEN": "gateway-session",
                },
                "gcv_" + "2" * 32,
            )

        with tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            credentials = runtime / "datahub-credentials.json"
            credentials.write_text(
                json.dumps({"readToken": "read-secret", "writeToken": "write-secret"}),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            with (
                mock.patch.multiple(
                    bootstrap,
                    RUNTIME=runtime,
                    CREDENTIALS=credentials,
                    ANALYTICS_ENV=runtime / "analytics.env",
                ),
                mock.patch.object(
                    bootstrap, "_decrypt_scoped_credentials", side_effect=decrypted
                ),
            ):
                read, analytics, companion, writer, gateway, versions = (
                    bootstrap._prepare_process_env(lease())
                )
            values = {
                "read": read.read_text("utf-8"),
                "analytics": analytics.read_text("utf-8"),
                "companion": companion.read_text("utf-8"),
                "writer": writer.read_text("utf-8"),
                "gateway": gateway.read_text("utf-8"),
            }
        self.assertEqual(versions, ("acv_" + "1" * 32, "gcv_" + "2" * 32))
        self.assertIn("DATAHUB_GMS_TOKEN=read-secret", values["read"])
        self.assertNotIn("write-secret", values["read"])
        self.assertNotIn("AWS_ACCESS_KEY_ID", values["read"])
        self.assertIn("DATAHUB_GMS_TOKEN=write-secret", values["writer"])
        self.assertNotIn("read-secret", values["writer"])
        self.assertNotIn("AWS_ACCESS_KEY_ID", values["writer"])
        for consumer in ("analytics", "companion"):
            self.assertIn("AWS_ACCESS_KEY_ID=ASIA-BEDROCK", values[consumer])
            self.assertNotIn("gateway-secret", values[consumer])
            self.assertNotIn("write-secret", values[consumer])
        self.assertIn("AWS_ACCESS_KEY_ID=ASIA-GATEWAY", values["gateway"])
        self.assertNotIn("bedrock-secret", values["gateway"])
        self.assertNotIn("DATAHUB_GMS_TOKEN", values["gateway"])
        self.assertIn(
            "ARCHON_OFFICIAL_WRITER_MCP_URL=http://archon-writer-mcp:8002/mcp",
            values["gateway"],
        )
        self.assertIn("DATAHUB_GMS_URL=http://archon-writer-gms:8080", values["writer"])
        self.assertIn("TOOLS_IS_MUTATION_ENABLED=false", values["read"])
        self.assertIn("TOOLS_IS_MUTATION_ENABLED=true", values["writer"])
        oauth_lines = [
            line for line in values["analytics"].splitlines()
            if line.startswith("OAUTH_MASTER_KEY=")
        ]
        self.assertEqual(len(oauth_lines), 1)
        self.assertRegex(oauth_lines[0].split("=", 1)[1], r"^[A-Za-z0-9_-]{43}=$")
        self.assertNotIn("OAUTH_MASTER_KEY", values["companion"])
        self.assertIn(
            "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN="
            "arn:aws:iam::123456789012:role/archon-staging-core-analytics",
            values["companion"],
        )
        self.assertIn("AWS_STS_REGIONAL_ENDPOINTS=regional", values["companion"])
        self.assertNotIn("ARCHON_EXPECTED_ANALYTICS_ROLE_ARN", values["read"])
        self.assertNotIn("ARCHON_EXPECTED_ANALYTICS_ROLE_ARN", values["writer"])
        self.assertNotIn("ARCHON_EXPECTED_ANALYTICS_ROLE_ARN", values["gateway"])

    def test_analytics_oauth_key_survives_rotation_and_plaintext_pat_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            analytics = runtime / "analytics"
            analytics.mkdir()
            state = analytics / "state.sqlite"
            state.write_bytes(b"encrypted connector state")
            credentials = runtime / "datahub-credentials.json"
            credentials.write_text(
                json.dumps({"readToken": "read-secret", "writeToken": "write-secret"}),
                encoding="utf-8",
            )
            credentials.chmod(0o600)
            env = runtime / "analytics.env"
            with mock.patch.multiple(
                bootstrap,
                RUNTIME=runtime,
                ANALYTICS_DIR=analytics,
                ANALYTICS_ENV=env,
                CREDENTIALS=credentials,
            ):
                first = bootstrap._analytics_oauth_master_key()
                bootstrap._write_env(
                    env,
                    bootstrap._analytics_env_values(
                        {"AWS_ACCESS_KEY_ID": "ASIA1"}, "acv_" + "1" * 32, first
                    ),
                )
                second = bootstrap._analytics_oauth_master_key()
                bootstrap._assert_analytics_token_not_at_rest()
                proof = json.loads(
                    (runtime / "analytics-credential-at-rest-proof.json").read_text("utf-8")
                )
                (analytics / "state.sqlite-wal").write_bytes(b"prefix-read-secret-suffix")
                with self.assertRaisesRegex(RuntimeError, "plaintext DataHub read credential"):
                    bootstrap._assert_analytics_token_not_at_rest()
        self.assertEqual(first, second)
        self.assertTrue(proof["oauthMasterKeyValidated"])
        self.assertFalse(proof["plaintextReadTokenPresent"])
        supplied = proof.pop("proofDigest")
        self.assertEqual(supplied, bootstrap._digest(proof))

    def test_container_create_is_hardened_and_never_joins_compose_default(self) -> None:
        fake_process = mock.Mock()
        fake_process.poll.return_value = None
        calls = []

        def run(arguments, **_kwargs):
            calls.append(arguments)
            return types.SimpleNamespace(returncode=0, stdout="[]")

        with (
            mock.patch.object(bootstrap, "_verified_image", return_value="sealed@sha256:" + "a" * 64),
            mock.patch.object(bootstrap.subprocess, "run", side_effect=run),
            mock.patch.object(bootstrap.subprocess, "Popen", return_value=fake_process) as popen,
            mock.patch.object(bootstrap, "PROCESSES", {}),
        ):
            bootstrap._container(
                "archon-test",
                pathlib.Path("/run/archon/test.env"),
                8001,
                ((bootstrap.WRITER_NETWORK, "archon-test"),),
                ["server"],
            )
        create = next(call for call in calls if call[:2] == ["docker", "create"])
        rendered = " ".join(create)
        self.assertIn("65532:65532", rendered)
        self.assertIn("--read-only", create)
        self.assertIn("no-new-privileges", rendered)
        self.assertIn("--cap-drop", create)
        self.assertIn("127.0.0.1:8001:8001", rendered)
        self.assertNotIn("archon-core_default", rendered)
        self.assertNotIn("/var/run/docker.sock", rendered)
        self.assertEqual(popen.call_args.args[0][:3], ["docker", "start", "--attach"])

    def test_rotation_restarts_every_scoped_credential_consumer(self) -> None:
        paths = tuple(pathlib.Path(f"/{name}.env") for name in ("read", "analytics", "companion", "writer", "gateway"))
        with (
            mock.patch.object(
                bootstrap,
                "_prepare_process_env",
                return_value=(*paths, ("acv_" + "3" * 32, "gcv_" + "4" * 32)),
            ),
            mock.patch.object(bootstrap, "_start_analytics") as analytics,
            mock.patch.object(bootstrap, "_start_companion") as companion,
            mock.patch.object(bootstrap, "_start_gateway") as gateway,
        ):
            versions = bootstrap._refresh_scoped_credentials(
                lease(), ("acv_" + "1" * 32, "gcv_" + "2" * 32)
            )
        self.assertEqual(versions, ("acv_" + "3" * 32, "gcv_" + "4" * 32))
        analytics.assert_called_once_with(paths[1])
        companion.assert_called_once_with(paths[2])
        gateway.assert_called_once_with(paths[4])

    def test_rbac_preflight_is_live_negative_roundtrip_and_digest_sealed(self) -> None:
        empty = {
            "entityUrn": DATASET,
            "columnPath": "customer_email",
            "tagUrns": [],
            "stateDigest": "sha256:" + "1" * 64,
        }
        tagged = {**empty, "tagUrns": ["urn:li:tag:PII"], "stateDigest": "sha256:" + "2" * 64}
        probes = [
            {"isError": True},
            {"isError": False, "payload": {"success": True}},
            {"isError": False, "payload": {"success": True}},
            {"isError": True},
        ]
        identity = {
            "sessionId": SESSION,
            "readActorUrn": "urn:li:corpuser:reader",
            "writerActorUrn": "urn:li:corpuser:writer",
            "writerPolicyUrn": "urn:li:dataHubPolicy:exact",
            "writerPolicy": {
                "resources": {"resources": [DATASET]},
                "privileges": ["VIEW_ENTITY_PAGE", "GET_ENTITY_PRIVILEGE", "EDIT_DATASET_COL_TAGS"],
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            with (
                mock.patch.object(bootstrap, "RUNTIME", runtime),
                mock.patch.object(
                    bootstrap, "_wait_read_state", side_effect=[empty, tagged, empty]
                ),
                mock.patch.object(bootstrap, "_mcp_probe", side_effect=probes) as probe,
                mock.patch.object(bootstrap, "_assert_writer_network_boundary") as boundary,
            ):
                bootstrap._rbac_preflight(identity)
            proof = json.loads((runtime / "datahub-rbac-preflight.json").read_text("utf-8"))
        self.assertEqual(probe.call_count, 4)
        boundary.assert_called_once()
        supplied = proof.pop("proofDigest")
        self.assertEqual(supplied, bootstrap._digest(proof))
        self.assertTrue(proof["readMutationDenied"])
        self.assertTrue(proof["writerRoundTripVerified"])
        self.assertTrue(proof["gatewayUnsignedDenied"])
        self.assertTrue(proof["hostAndAgentDirectWriterDenied"])

    def test_real_bedrock_proof_uses_scoped_session_without_model_output(self) -> None:
        client = mock.Mock()
        client.converse.return_value = {
            "output": {"message": {"content": [{"text": "OK"}]}},
            "ResponseMetadata": {"RequestId": "request-123"},
        }
        scoped = {
            "AWS_ACCESS_KEY_ID": "ASIA-BEDROCK",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "AWS_SESSION_TOKEN": "session",
        }
        with tempfile.TemporaryDirectory() as directory:
            runtime = pathlib.Path(directory)
            with (
                mock.patch.object(bootstrap, "RUNTIME", runtime),
                mock.patch.object(
                    bootstrap, "_decrypt_scoped_credentials",
                    return_value=(scoped, "acv_" + "1" * 32),
                ),
                mock.patch.object(
                    bootstrap, "boto3", types.SimpleNamespace(client=lambda *_a, **_k: client)
                ),
            ):
                self.assertTrue(bootstrap._model_ready(lease()))
            proof = json.loads((runtime / "bedrock-preflight.json").read_text("utf-8"))
        supplied = proof.pop("proofDigest")
        self.assertEqual(supplied, bootstrap._digest(proof))
        self.assertEqual(proof["responseId"], "request-123")
        self.assertNotIn("OK", json.dumps(proof))
        client.converse.assert_called_once()

    def test_source_seals_service_accounts_images_and_writer_boundary(self) -> None:
        source = path.read_text("utf-8")
        for required in (
            "createServiceAccount",
            "urn:li:dataHubRole:Reader",
            "EDIT_DATASET_COL_TAGS",
            "SERVICE_ACCOUNT",
            '"type": token_type',
            '"PERSONAL"',
            "revokeAccessToken",
            ".RepoDigests",
            "hmac.compare_digest",
            'WRITER_SUBNET = "172.28.71.0/24"',
            '"OUTPUT"',
            '"archon-writer-mcp", writer_env, None',
            "gatewayUnsignedDenied",
            "def _run_handle_key",
            '"OAUTH_MASTER_KEY": oauth_master_key',
            '"ARCHON_EXPECTED_ANALYTICS_ROLE_ARN": expected_analytics_role',
            '"AWS_STS_REGIONAL_ENDPOINTS": "regional"',
            "def _assert_analytics_token_not_at_rest",
            'str(ROOT / "datahub/docker-compose.images.yml")',
        ):
            self.assertIn(required, source)
        self.assertNotIn("archon-core_default", source)
        self.assertNotIn("ARCHON_GOVERNED_GATEWAY_TOKEN", source)
        self.assertNotIn("host.docker.internal", source)


if __name__ == "__main__":
    main()
