from __future__ import annotations

import datetime as dt
import importlib.util
import os
import pathlib
import sys
import types
from unittest import TestCase, main, mock

SESSION = "rs_" + "A" * 43
OTHER_SESSION = "rs_" + "B" * 43
DIGEST = "sha256:" + "a" * 64
MANIFEST = "sha256:" + "b" * 64
GENERATION = "core-20260802-1"

os.environ.update(
    {
        "CORE_LEASE_TABLE": "Archon-staging-CoreLease",
        "CORE_AMI_ID": "ami-0123456789abcdef0",
        "CORE_GENERATION": GENERATION,
        "CORE_CAPABILITY_DIGEST": DIGEST,
        "CORE_IMAGE_MANIFEST_DIGEST": MANIFEST,
        "CORE_STAGE": "staging",
        "CORE_VPC_ID": "vpc-0123456789abcdef0",
        "CORE_SUBNET_ID": "subnet-0123456789abcdef0",
        "CORE_INFERENCE_SECURITY_GROUP_ID": "sg-0123456789abcdef0",
        "CORE_BEDROCK_SERVICE_NAME": (
            "com.amazonaws.eu-west-1.bedrock-runtime"
        ),
        "CORE_IDLE_SECONDS": "1800",
        "CORE_HARD_SECONDS": "7200",
        "CORE_OPERATION_SECONDS": "300",
    }
)

EVENTS: list[str] = []


class FakeClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeTable:
    def __init__(self) -> None:
        self.item = None
        self.updates = []
        self.puts = []
        self.fail_next_update = ""

    def update_item(self, **kwargs):
        EVENTS.append("ddb-update")
        self.updates.append(kwargs)
        if self.fail_next_update:
            code = self.fail_next_update
            self.fail_next_update = ""
            raise FakeClientError(code)
        return {}

    def get_item(self, **_kwargs):
        return {"Item": self.item} if self.item is not None else {}

    def put_item(self, **kwargs):
        self.puts.append(kwargs)
        return {}


class FakeEc2:
    def __init__(self) -> None:
        self.endpoints: list[dict] = []
        self.create_calls: list[dict] = []
        self.delete_calls: list[str] = []

    def describe_images(self, **_kwargs):
        return {
            "Images": [
                {
                    "State": "available",
                    "Architecture": "x86_64",
                    "RootDeviceType": "ebs",
                    "EnaSupport": True,
                    "ImdsSupport": "v2.0",
                    "Tags": [
                        {"Key": "Application", "Value": "archon-datahub"},
                        {"Key": "ArchonDataHubCore", "Value": "verified"},
                        {"Key": "ArchonGeneration", "Value": GENERATION},
                        {"Key": "ArchonCapabilityDigest", "Value": DIGEST},
                        {
                            "Key": "ArchonImageManifestDigest",
                            "Value": MANIFEST,
                        },
                        {
                            "Key": "ArchonFourComponents",
                            "Value": "mcp,ack,skills,analytics",
                        },
                        {"Key": "ManagedBy", "Value": "github-actions"},
                    ],
                }
            ]
        }

    def describe_vpc_endpoints(self, **_kwargs):
        return {"VpcEndpoints": list(self.endpoints)}

    def create_vpc_endpoint(self, **kwargs):
        EVENTS.append("endpoint-create")
        self.create_calls.append(kwargs)
        endpoint = {
            "VpcEndpointId": "vpce-0123456789abcdef0",
            "State": "available",
            "Tags": kwargs["TagSpecifications"][0]["Tags"],
        }
        self.endpoints = [endpoint]
        return {"VpcEndpoint": endpoint}

    def delete_vpc_endpoints(self, *, VpcEndpointIds):
        self.delete_calls.extend(VpcEndpointIds)
        self.endpoints = [
            endpoint
            for endpoint in self.endpoints
            if endpoint.get("VpcEndpointId") not in VpcEndpointIds
        ]
        return {}


TABLE = FakeTable()
EC2 = FakeEc2()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _table: TABLE)
fake_boto3.client = lambda name: EC2 if name == "ec2" else None
fake_exceptions = types.ModuleType("botocore.exceptions")
fake_exceptions.ClientError = FakeClientError
sys.modules.setdefault("boto3", fake_boto3)
sys.modules.setdefault("botocore", types.ModuleType("botocore"))
sys.modules.setdefault("botocore.exceptions", fake_exceptions)

path = pathlib.Path(__file__).with_name("lifecycle.py")
spec = importlib.util.spec_from_file_location("core_lifecycle", path)
assert spec is not None and spec.loader is not None
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


def instant(hour: int, minute: int = 0) -> dt.datetime:
    return dt.datetime(2026, 8, 2, hour, minute, tzinfo=dt.timezone.utc)


def binding() -> dict:
    return {
        "schemaVersion": "archon.runtime-binding/v1",
        "profileId": "core",
        "generation": GENERATION,
        "capabilityDigest": DIGEST,
        "resolution": "explicit",
        "boundAt": "2026-08-02T08:00:00.000Z",
        "leaseExpiresAt": "2026-08-02T10:00:00.000Z",
    }


def command(action: str, revision: int = 0) -> dict:
    return {
        "schema": "archon.core-runtime-command/v1",
        "action": action,
        "sessionId": SESSION,
        "expectedRevision": revision,
        "binding": binding(),
    }


class CoreLifecycleTests(TestCase):
    def setUp(self) -> None:
        EVENTS.clear()
        TABLE.item = None
        TABLE.updates.clear()
        TABLE.puts.clear()
        TABLE.fail_next_update = ""
        EC2.endpoints.clear()
        EC2.create_calls.clear()
        EC2.delete_calls.clear()

    def test_exact_canonical_contract(self) -> None:
        validated = lifecycle._validate_command(command("START"), instant(8))
        self.assertEqual(validated["binding"], binding())
        invalid = command("START")
        invalid["binding"]["extra"] = True
        with self.assertRaises(ValueError):
            lifecycle._validate_command(invalid, instant(8))
        self.assertEqual(
            lifecycle.CAPABILITIES,
            {
                "mcpRead": True,
                "mcpGovernedWrite": True,
                "agentContextKit": True,
                "dataHubSkills": True,
                "analyticsAgent": True,
            },
        )

    def test_start_reserves_before_endpoint_and_uses_exact_lease(self) -> None:
        result = lifecycle._start(command("START", revision=7), instant(8))
        self.assertEqual(result["decision"], "UPSCALE")
        self.assertEqual(result["revision"], 8)
        self.assertEqual(EVENTS[:2], ["ddb-update", "endpoint-create"])
        reserve = TABLE.updates[0]
        values = reserve["ExpressionAttributeValues"]
        self.assertEqual(values[":expected"], 7)
        self.assertEqual(values[":revision"], 8)
        self.assertEqual(values[":idle"], int(instant(8, 30).timestamp()))
        self.assertEqual(values[":hard"], int(instant(10).timestamp()))
        self.assertIn(
            "attribute_not_exists(operationId)",
            reserve["ConditionExpression"],
        )
        self.assertIn("inferenceEndpointId", TABLE.updates[1]["UpdateExpression"])

    def test_losing_start_allocates_no_endpoint(self) -> None:
        TABLE.item = {
            "sessionId": OTHER_SESSION,
            "state": "READY",
            "revision": 3,
            "generation": GENERATION,
            "capabilityDigest": DIGEST,
        }
        TABLE.fail_next_update = "ConditionalCheckFailedException"
        result = lifecycle._start(command("START", revision=3), instant(8))
        self.assertEqual(result["code"], "LEASE_CONFLICT")
        self.assertEqual(EC2.create_calls, [])

    def test_endpoint_client_token_is_retry_deterministic(self) -> None:
        first = lifecycle._endpoint_token(SESSION)
        second = lifecycle._endpoint_token(SESSION)
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_activity_is_ready_only_and_returns_exact_watchdog(self) -> None:
        result = lifecycle._activity(command("ACTIVITY", revision=8), instant(8, 20))
        self.assertTrue(result["watchdog"])
        self.assertEqual(result["revision"], 9)
        self.assertEqual(
            result["watchdogDeadline"], "2026-08-02T08:50:00.000Z"
        )
        update = TABLE.updates[-1]
        self.assertIn("#state=:ready", update["ConditionExpression"])
        self.assertEqual(update["ExpressionAttributeValues"][":ready"], "READY")

    def test_activity_conditional_conflict_has_no_endpoint_state_dependency(self) -> None:
        TABLE.item = {
            "sessionId": SESSION,
            "state": "READY",
            "revision": 9,
            "idleExpiresAt": int(instant(8, 50).timestamp()),
        }
        TABLE.fail_next_update = "ConditionalCheckFailedException"
        result = lifecycle._activity(
            command("ACTIVITY", revision=8), instant(8, 20)
        )
        self.assertEqual(result["code"], "IDEMPOTENT")
        self.assertEqual(result["revision"], 9)
        self.assertEqual(EC2.create_calls, [])
        self.assertEqual(EC2.delete_calls, [])

    def test_stale_watchdog_is_a_noop_after_activity_revision(self) -> None:
        TABLE.item = {
            "pk": "CORE#LEASE",
            "sk": "CURRENT",
            "sessionId": SESSION,
            "state": "READY",
            "revision": 9,
            "idleExpiresAt": int(instant(8, 50).timestamp()),
            "hardExpiresAt": int(instant(10).timestamp()),
        }
        stale = {
            "schema": "archon.core-runtime-command/v1",
            "action": "REAP",
            "expectedSessionId": SESSION,
            "expectedRevision": 8,
            "deadlineEpoch": int(instant(8, 30).timestamp()),
        }
        result = lifecycle._reap(stale, instant(8, 31))
        self.assertEqual(result["code"], "STALE_WATCHDOG")
        self.assertEqual(TABLE.updates, [])

    def test_exact_watchdog_drains_at_deadline(self) -> None:
        deadline = int(instant(8, 30).timestamp())
        TABLE.item = {
            "pk": "CORE#LEASE",
            "sk": "CURRENT",
            "sessionId": SESSION,
            "state": "READY",
            "revision": 8,
            "idleExpiresAt": deadline,
            "hardExpiresAt": int(instant(10).timestamp()),
        }
        exact = {
            "schema": "archon.core-runtime-command/v1",
            "action": "REAP",
            "expectedSessionId": SESSION,
            "expectedRevision": 8,
            "deadlineEpoch": deadline,
        }
        result = lifecycle._reap(exact, instant(8, 30))
        self.assertEqual(result["decision"], "DOWNSCALE")
        self.assertEqual(result["revision"], 9)
        self.assertEqual(
            TABLE.updates[-1]["ExpressionAttributeValues"][":draining"],
            "DRAINING",
        )

    def test_lifecycle_role_code_never_calls_autoscaling(self) -> None:
        source = path.read_text(encoding="utf-8").lower()
        self.assertNotIn("autoscaling", source)
        self.assertNotIn("set_desired_capacity", source)
        self.assertNotIn("update_auto_scaling_group", source)

    def test_ami_mismatch_fails_closed(self) -> None:
        bad = FakeEc2()
        bad.describe_images = mock.Mock(return_value={"Images": []})
        with mock.patch.object(lifecycle, "_EC2", bad):
            with self.assertRaises(ValueError):
                lifecycle._verify_ami()


if __name__ == "__main__":
    main()