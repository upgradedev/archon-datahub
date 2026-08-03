from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import json
import os
import pathlib
import sys
import types
from unittest import TestCase, main, mock

SESSION = "rs_" + "A" * 43
JOB = "job_" + "B" * 22
DIGEST = "sha256:" + "a" * 64
KEY_ARN = "arn:aws:kms:eu-west-1:123456789012:key/87654321-4321-4321-4321-210987654321"
DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
NOW = dt.datetime(2026, 8, 2, 8, tzinfo=dt.timezone.utc)

os.environ.update(
    {
        "AWS_REGION": "eu-west-1",
        "ARCHON_STAGE": "staging",
        "ARCHON_SESSION_ID": SESSION,
        "ARCHON_RUNTIME_GENERATION": "core-generation",
        "ARCHON_RUNTIME_CAPABILITY_DIGEST": DIGEST,
        "ARCHON_MUTATION_SIGNING_KEY_ARN": KEY_ARN,
        "ARCHON_OFFICIAL_WRITER_MCP_URL": "http://archon-writer-mcp:8002/mcp",
        "CORE_LEASE_TABLE": "core-table",
        "FASTMCP_HOST": "127.0.0.1",
        "FASTMCP_PORT": "8001",
    }
)


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code}}


class FakeTable:
    def __init__(self) -> None:
        self.consumed = False
        self.update_calls = []

    def get_item(self, **_kwargs):
        return {
            "Item": {
                "sessionId": SESSION,
                "generation": "core-generation",
                "capabilityDigest": DIGEST,
                "state": "READY",
                "hardExpiresAt": int((NOW + dt.timedelta(hours=2)).timestamp()),
            }
        }

    def update_item(self, **kwargs):
        if self.consumed:
            raise FakeClientError("ConditionalCheckFailedException")
        self.consumed = True
        self.update_calls.append(kwargs)
        return {}


TABLE = FakeTable()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _table: TABLE)
fake_boto3.client = lambda *_args, **_kwargs: mock.Mock()
fake_exceptions = types.ModuleType("botocore.exceptions")
fake_exceptions.ClientError = FakeClientError
sys.modules.setdefault("boto3", fake_boto3)
sys.modules.setdefault("botocore", types.ModuleType("botocore"))
sys.modules.setdefault("botocore.exceptions", fake_exceptions)

path = pathlib.Path(__file__).with_name("governed_datahub_gateway.py")
spec = importlib.util.spec_from_file_location("governed_gateway", path)
assert spec is not None and spec.loader is not None
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class PublicKey:
    def verify(self, *_args, **_kwargs):
        return None


def request() -> dict:
    approval = {
        "approvalId": "approval-1",
        "decision": "APPROVE",
        "approverDigest": DIGEST,
        "decidedAt": "2026-08-02T07:59:00.000Z",
        "digest": DIGEST,
    }
    envelope = {
        "schemaVersion": "archon.core-mutation-authorization/v1",
        "stage": "staging",
        "sessionId": SESSION,
        "generation": "core-generation",
        "capabilityDigest": DIGEST,
        "jobId": JOB,
        "approvalId": approval["approvalId"],
        "planDigest": DIGEST,
        "policyDigest": DIGEST,
        "target": {"entityUrn": DATASET, "columnPath": "customer_email"},
        "tool": "add_tags",
        "arguments": {
            "tag_urns": ["urn:li:tag:PII"],
            "entity_urns": [DATASET],
            "column_paths": ["customer_email"],
        },
        "issuedAt": "2026-08-02T07:59:30.000Z",
        "expiresAt": "2026-08-02T08:04:30.000Z",
    }
    signature = {
        "keyArn": KEY_ARN,
        "algorithm": "ECDSA_SHA_256",
        "canonicalization": "archon.sorted-json-utf8/v1",
        "envelopeDigest": gateway._digest(envelope),
        "signatureBase64": base64.b64encode(b"x" * 70).decode("ascii"),
    }
    value = {
        "schemaVersion": "archon.core-governed-tag-mutation/v1",
        "auditId": "b" * 64,
        "runtimeEvidenceDigest": DIGEST,
        "auditEvidenceDigest": DIGEST,
        "planDigest": DIGEST,
        "policyDigest": DIGEST,
        "approval": approval,
        "action": "ADD_TAGS",
        "arguments": {
            "tagUrns": ["urn:li:tag:PII"],
            "entityUrns": [DATASET],
            "columnPaths": ["customer_email"],
        },
        "expectedBeforeDigest": DIGEST,
        "expectedAfterDigest": DIGEST,
        "authorization": {"envelope": envelope, "signature": signature},
    }
    return {**value, "requestDigest": gateway._digest(value)}


class GovernedGatewayTests(TestCase):
    def setUp(self) -> None:
        TABLE.consumed = False
        TABLE.update_calls.clear()
        gateway._TABLE = TABLE

    def validate(self, value: dict):
        with mock.patch.object(gateway, "_public_key", return_value=PublicKey()):
            return gateway._validate_request(JOB, value, NOW)

    def test_valid_signature_binds_exact_official_mcp_arguments(self) -> None:
        envelope, signature = self.validate(request())
        self.assertEqual(envelope["tool"], "add_tags")
        self.assertEqual(
            envelope["arguments"],
            {
                "tag_urns": ["urn:li:tag:PII"],
                "entity_urns": [DATASET],
                "column_paths": ["customer_email"],
            },
        )
        self.assertEqual(signature["algorithm"], "ECDSA_SHA_256")
        self.assertEqual(
            signature["canonicalization"], "archon.sorted-json-utf8/v1"
        )

    def test_unsigned_tampered_wrong_key_generation_and_expired_are_rejected(self) -> None:
        cases = []
        unsigned = request()
        unsigned.pop("authorization")
        cases.append(unsigned)
        tampered = request()
        tampered["authorization"]["envelope"]["target"]["columnPath"] = "other"
        cases.append(tampered)
        wrong_key = request()
        wrong_key["authorization"]["signature"]["keyArn"] = (
            "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111"
        )
        cases.append(wrong_key)
        wrong_generation = request()
        wrong_generation["authorization"]["envelope"]["generation"] = "other"
        cases.append(wrong_generation)
        expired = request()
        expired["authorization"]["envelope"]["expiresAt"] = (
            "2026-08-02T07:59:59.000Z"
        )
        cases.append(expired)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(PermissionError):
                    self.validate(value)

    def test_noncanonical_target_rejects_before_official_tool(self) -> None:
        value = request()
        value["arguments"]["entityUrns"] = [
            "urn:li:dataset:(urn:li:dataPlatform:sqlite,other,PROD)"
        ]
        unsigned = dict(value)
        unsigned.pop("requestDigest")
        value["requestDigest"] = gateway._digest(unsigned)
        with mock.patch.object(gateway, "_official_call") as official:
            with self.assertRaises(PermissionError):
                self.validate(value)
            official.assert_not_called()

    def test_canonical_subset_rejects_floats_non_ascii_and_unsafe_integers(self) -> None:
        for value in (1.5, "PII-π", 2**53):
            with self.subTest(value=value):
                with self.assertRaises(PermissionError):
                    gateway._validate_signed_json(value)

    def test_cross_language_golden_signature_fixture(self) -> None:
        fixture_path = (
            pathlib.Path(__file__).resolve().parents[3]
            / "contracts"
            / "datahub-core-mutation-authorization-golden.json"
        )
        fixture = json.loads(fixture_path.read_text("utf-8"))
        self.assertEqual(
            set(fixture),
            {
                "schemaVersion",
                "canonicalization",
                "envelope",
                "canonicalJson",
                "envelopeDigest",
                "keySpec",
                "algorithm",
                "publicKeyDerBase64",
                "signatureBase64",
            },
        )
        self.assertEqual(
            fixture["schemaVersion"],
            "archon.core-mutation-authorization-golden/v1",
        )
        self.assertEqual(
            fixture["canonicalization"], "archon.sorted-json-utf8/v1"
        )
        canonical = gateway._canonical(fixture["envelope"])
        self.assertEqual(canonical.decode("utf-8"), fixture["canonicalJson"])
        self.assertEqual(gateway._digest(fixture["envelope"]), fixture["envelopeDigest"])
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        public_key = load_der_public_key(
            base64.b64decode(fixture["publicKeyDerBase64"], validate=True)
        )
        public_key.verify(
            base64.b64decode(fixture["signatureBase64"], validate=True),
            bytes.fromhex(fixture["envelopeDigest"].removeprefix("sha256:")),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )

    def test_authorization_is_consumed_once_before_tool_execution(self) -> None:
        value = request()
        before = {
            "entityUrn": DATASET,
            "columnPath": "customer_email",
            "tagUrns": [],
        }
        after = {
            "entityUrn": DATASET,
            "columnPath": "customer_email",
            "tagUrns": ["urn:li:tag:PII"],
        }
        value["expectedBeforeDigest"] = gateway._digest(before)
        value["expectedAfterDigest"] = gateway._digest(after)
        unsigned = dict(value)
        unsigned.pop("requestDigest")
        value["requestDigest"] = gateway._digest(unsigned)
        with (
            mock.patch.object(gateway, "_now", return_value=NOW),
            mock.patch.object(gateway, "_public_key", return_value=PublicKey()),
            mock.patch.object(
                gateway,
                "_read_state",
                side_effect=[
                    {**before, "stateDigest": gateway._digest(before)},
                    {**after, "stateDigest": gateway._digest(after)},
                ],
            ),
            mock.patch.object(
                gateway,
                "_official_call",
                return_value={"success": True, "message": "Tag added"},
            ) as official,
        ):
            result = gateway._execute(JOB, value)
        self.assertEqual(result["mutationExecutor"], "official-datahub-mcp")
        self.assertEqual(result["officialMcpMutation"]["tool"], "add_tags")
        self.assertEqual(
            result["authorizationEvidence"]["canonicalization"],
            "archon.sorted-json-utf8/v1",
        )
        official.assert_called_once_with(
            "add_tags",
            {
                "tag_urns": ["urn:li:tag:PII"],
                "entity_urns": [DATASET],
                "column_paths": ["customer_email"],
            },
        )
        self.assertIn(
            "attribute_not_exists(authorizationConsumedAt)",
            TABLE.update_calls[0]["ConditionExpression"],
        )
        with self.assertRaises(PermissionError):
            gateway._consume(
                JOB, value["authorization"]["envelope"], NOW
            )


if __name__ == "__main__":
    main()