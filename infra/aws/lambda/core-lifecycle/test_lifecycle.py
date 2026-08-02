from __future__ import annotations

import datetime as dt
import importlib.util
import json
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
DATA_KEY_ARN = "arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
MUTATION_KEY_ARN = "arn:aws:kms:eu-west-1:123456789012:key/87654321-4321-4321-4321-210987654321"
ANALYTICS_ROLE_ARN = "arn:aws:iam::123456789012:role/archon-core-analytics-staging"
INSTANCE_ROLE_ARN = "arn:aws:iam::123456789012:role/archon-core-host-staging"
PROFILE = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
BASE_MODEL = "anthropic.claude-sonnet-4-5-20250929-v1:0"
BEDROCK_RESOURCES = [
    f"arn:aws:bedrock:eu-west-1:123456789012:inference-profile/{PROFILE}",
    f"arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/{PROFILE}",
    *[
        f"arn:aws:bedrock:{region}::foundation-model/{BASE_MODEL}"
        for region in (
            "eu-central-1",
            "eu-north-1",
            "eu-south-1",
            "eu-south-2",
            "eu-west-1",
            "eu-west-3",
        )
    ],
]

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
        "CORE_INTERFACE_SECURITY_GROUP_ID": "sg-0123456789abcdef0",
        "CORE_BEDROCK_SERVICE_NAME": "com.amazonaws.eu-west-1.bedrock-runtime",
        "CORE_KMS_SERVICE_NAME": "com.amazonaws.eu-west-1.kms",
        "CORE_STS_SERVICE_NAME": "com.amazonaws.eu-west-1.sts",
        "CORE_DATA_KEY_ARN": DATA_KEY_ARN,
        "CORE_MUTATION_SIGNING_KEY_ARN": MUTATION_KEY_ARN,
        "CORE_ANALYTICS_ROLE_ARN": ANALYTICS_ROLE_ARN,
        "CORE_GATEWAY_ROLE_ARN": GATEWAY_ROLE_ARN,
        "CORE_INSTANCE_ROLE_ARN": INSTANCE_ROLE_ARN,
        "CORE_BEDROCK_RESOURCE_ARNS": json.dumps(BEDROCK_RESOURCES),
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
        self.updates: list[dict] = []
        self.puts: list[dict] = []
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
            "Images": [{
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
                    {"Key": "ArchonImageManifestDigest", "Value": MANIFEST},
                    {"Key": "ArchonFourComponents", "Value": "mcp,ack,skills,analytics"},
                    {"Key": "ManagedBy", "Value": "github-actions"},
                    {"Key": "archon:Purpose", "Value": "datahub-core-ami"},
                ],
            }]
        }

    def describe_vpc_endpoints(self, *, Filters):
        capability = next(
            (
                entry["Values"][0]
                for entry in Filters
                if entry["Name"] == "tag:ArchonCapability"
            ),
            None,
        )
        values = []
        for endpoint in self.endpoints:
            tags = {tag["Key"]: tag["Value"] for tag in endpoint["Tags"]}
            if capability is None or tags.get("ArchonCapability") == capability:
                values.append(endpoint)
        return {"VpcEndpoints": values}

    def create_vpc_endpoint(self, **kwargs):
        tags = kwargs["TagSpecifications"][0]["Tags"]
        capability = {tag["Key"]: tag["Value"] for tag in tags}["ArchonCapability"]
        EVENTS.append(f"endpoint-create:{capability}")
        self.create_calls.append(kwargs)
        endpoint = {
            "VpcEndpointId": {
                "kms": "vpce-0123456789abcdef0",
                "bedrock": "vpce-0fedcba9876543210",
                "sts": "vpce-00112233445566778",
            }[capability],
            "State": "available",
            "Tags": tags,
        }
        self.endpoints.append(endpoint)
        return {"VpcEndpoint": endpoint}

    def delete_vpc_endpoints(self, *, VpcEndpointIds):
        self.delete_calls.extend(VpcEndpointIds)
        self.endpoints = [
            endpoint
            for endpoint in self.endpoints
            if endpoint.get("VpcEndpointId") not in VpcEndpointIds
        ]
        return {}


class FakeSts:
    def __init__(self) -> None:
        self.expiration = dt.datetime(2026, 8, 2, 9, tzinfo=dt.timezone.utc)
        self.calls: list[dict] = []

    def assume_role(self, **kwargs):
        EVENTS.append("sts-assume")
        self.calls.append(kwargs)
        return {
            "Credentials": {
                "AccessKeyId": "ASIAEXAMPLESCOPED",
                "SecretAccessKey": "secret-value-never-in-ddb",
                "SessionToken": "session-value-never-in-ddb",
                "Expiration": self.expiration,
            }
        }


class FakeKms:
    def __init__(self) -> None:
        self.encrypt_calls: list[dict] = []

    def encrypt(self, **kwargs):
        EVENTS.append("kms-encrypt")
        self.encrypt_calls.append(kwargs)
        return {"CiphertextBlob": b"x" * 128}


TABLE = FakeTable()
EC2 = FakeEc2()
STS = FakeSts()
KMS = FakeKms()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = lambda _name: types.SimpleNamespace(Table=lambda _table: TABLE)
fake_boto3.client = lambda name: {
    "ec2": EC2,
    "sts": STS,
    "kms": KMS,
}[name]
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


def active_lease(now: dt.datetime, revision: int = 8, expiry_seconds: int = 600) -> dict:
    return {
        "pk": "CORE#LEASE",
        "sk": "CURRENT",
        "sessionId": SESSION,
        "state": "READY",
        "revision": revision,
        "generation": GENERATION,
        "capabilityDigest": DIGEST,
        "idleExpiresAt": int((now + dt.timedelta(minutes=10)).timestamp()),
        "hardExpiresAt": int(instant(10).timestamp()),
        "analyticsCredentialsVersion": "acv_" + "1" * 32,
        "analyticsCredentialsExpiresAt": int((now + dt.timedelta(seconds=expiry_seconds)).timestamp()),
        "analyticsCredentialsCiphertext": "eA==",
        "gatewayCredentialsVersion": "gcv_" + "2" * 32,
        "gatewayCredentialsExpiresAt": int((now + dt.timedelta(seconds=expiry_seconds)).timestamp()),
        "gatewayCredentialsCiphertext": "eQ==",
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
        STS.calls.clear()
        KMS.encrypt_calls.clear()
        STS.expiration = instant(9)

    def test_exact_canonical_contract(self) -> None:
        validated = lifecycle._validate_command(command("START"), instant(8))
        self.assertEqual(validated["binding"], binding())
        invalid = command("START")
        invalid["binding"]["extra"] = True
        with self.assertRaises(ValueError):
            lifecycle._validate_command(invalid, instant(8))

    def test_start_reserves_then_creates_three_endpoints_and_stores_only_ciphertext(self) -> None:
        result = lifecycle._start(command("START", revision=7), instant(8))
        self.assertEqual(result["decision"], "UPSCALE")
        self.assertEqual(
            EVENTS,
            [
                "ddb-update",
                "endpoint-create:kms",
                "endpoint-create:bedrock",
                "endpoint-create:sts",
                "sts-assume",
                "kms-encrypt",
                "sts-assume",
                "kms-encrypt",
                "ddb-update",
            ],
        )
        self.assertEqual([call["ServiceName"] for call in EC2.create_calls], [
            "com.amazonaws.eu-west-1.kms",
            "com.amazonaws.eu-west-1.bedrock-runtime",
            "com.amazonaws.eu-west-1.sts",
        ])
        kms_policy = EC2.create_calls[0]["PolicyDocument"]["Statement"][0]
        self.assertEqual(kms_policy["Principal"], {"AWS": INSTANCE_ROLE_ARN})
        self.assertEqual(kms_policy["Action"], "kms:Decrypt")
        self.assertEqual(kms_policy["Resource"], DATA_KEY_ARN)
        public_key_policy = EC2.create_calls[0]["PolicyDocument"]["Statement"][1]
        self.assertEqual(public_key_policy["Principal"], {"AWS": GATEWAY_ROLE_ARN})
        self.assertEqual(public_key_policy["Action"], ["kms:GetPublicKey", "kms:DescribeKey"])
        self.assertEqual(public_key_policy["Resource"], MUTATION_KEY_ARN)
        analytics_context = lifecycle._encryption_context(
            SESSION, "analytics-agent-bedrock"
        )
        gateway_context = lifecycle._encryption_context(
            SESSION, "governed-gateway-control"
        )
        expected_endpoint_context = {
            f"kms:EncryptionContext:{key}": value
            for key, value in analytics_context.items()
            if key != "capability"
        }
        expected_endpoint_context["kms:EncryptionContext:capability"] = [
            "analytics-agent-bedrock", "governed-gateway-control"
        ]
        self.assertEqual(
            kms_policy["Condition"]["StringEquals"], expected_endpoint_context
        )
        bedrock_policy = EC2.create_calls[1]["PolicyDocument"]["Statement"][0]
        self.assertEqual(bedrock_policy["Principal"], {"AWS": ANALYTICS_ROLE_ARN})
        self.assertEqual(bedrock_policy["Resource"], BEDROCK_RESOURCES)
        sts_policy = EC2.create_calls[2]["PolicyDocument"]["Statement"][0]
        self.assertEqual(sts_policy["Principal"], {"AWS": ANALYTICS_ROLE_ARN})
        self.assertEqual(sts_policy["Action"], "sts:GetCallerIdentity")
        self.assertEqual(sts_policy["Resource"], "*")
        persisted = TABLE.updates[1]["ExpressionAttributeValues"]
        serialized = json.dumps(persisted)
        self.assertNotIn("secret-value-never-in-ddb", serialized)
        self.assertNotIn("session-value-never-in-ddb", serialized)
        self.assertIn(":analyticsCiphertext", persisted)
        self.assertIn(":gatewayCiphertext", persisted)
        self.assertEqual(KMS.encrypt_calls[0]["EncryptionContext"], analytics_context)
        self.assertEqual(KMS.encrypt_calls[1]["EncryptionContext"], gateway_context)
        self.assertEqual(
            [call["RoleArn"] for call in STS.calls],
            [ANALYTICS_ROLE_ARN, GATEWAY_ROLE_ARN],
        )
        self.assertTrue(all(call["DurationSeconds"] == 3600 for call in STS.calls))

    def test_losing_start_allocates_no_billable_endpoint_or_credentials(self) -> None:
        TABLE.item = active_lease(instant(8), revision=3)
        TABLE.item["sessionId"] = OTHER_SESSION
        TABLE.fail_next_update = "ConditionalCheckFailedException"
        result = lifecycle._start(command("START", revision=3), instant(8))
        self.assertEqual(result["code"], "LEASE_CONFLICT")
        self.assertEqual(EC2.create_calls, [])
        self.assertEqual(STS.calls, [])
        self.assertEqual(KMS.encrypt_calls, [])

    def test_activity_rotates_before_expiry_when_session_extends_past_one_hour(self) -> None:
        now = instant(9, 5)
        TABLE.item = active_lease(now, revision=8, expiry_seconds=300)
        STS.expiration = instant(10, 5)
        result = lifecycle._activity(command("ACTIVITY", revision=8), now)
        self.assertEqual(result["code"], "ACTIVITY_RECORDED_CREDENTIALS_ROTATED")
        values = TABLE.updates[-1]["ExpressionAttributeValues"]
        self.assertIn(":analyticsCiphertext", values)
        self.assertIn(":gatewayCiphertext", values)
        self.assertNotEqual(
            values[":analyticsVersion"], TABLE.item["analyticsCredentialsVersion"]
        )
        self.assertNotEqual(
            values[":gatewayVersion"], TABLE.item["gatewayCredentialsVersion"]
        )
        self.assertEqual(
            [call["RoleArn"] for call in STS.calls],
            [ANALYTICS_ROLE_ARN, GATEWAY_ROLE_ARN],
        )
        self.assertEqual(len(KMS.encrypt_calls), 2)
        self.assertEqual(
            {call["EncryptionContext"]["capability"] for call in KMS.encrypt_calls},
            {"analytics-agent-bedrock", "governed-gateway-control"},
        )

    def test_activity_reuses_scoped_credentials_when_expiry_is_not_near(self) -> None:
        now = instant(8, 10)
        TABLE.item = active_lease(now, revision=8, expiry_seconds=2400)
        result = lifecycle._activity(command("ACTIVITY", revision=8), now)
        self.assertEqual(result["code"], "ACTIVITY_RECORDED")
        values = TABLE.updates[-1]["ExpressionAttributeValues"]
        self.assertNotIn(":analyticsCiphertext", values)
        self.assertNotIn(":gatewayCiphertext", values)
        self.assertEqual(STS.calls, [])
        self.assertEqual(KMS.encrypt_calls, [])

    def test_finalize_down_removes_ciphertext_and_all_three_endpoints(self) -> None:
        EC2.endpoints = [
            {
                "VpcEndpointId": "vpce-0123456789abcdef0",
                "State": "available",
                "Tags": [
                    {"Key": "ArchonSessionId", "Value": SESSION},
                    {"Key": "ArchonCapability", "Value": "kms"},
                ],
            },
            {
                "VpcEndpointId": "vpce-0fedcba9876543210",
                "State": "available",
                "Tags": [
                    {"Key": "ArchonSessionId", "Value": SESSION},
                    {"Key": "ArchonCapability", "Value": "bedrock"},
                ],
            },
            {
                "VpcEndpointId": "vpce-00112233445566778",
                "State": "available",
                "Tags": [
                    {"Key": "ArchonSessionId", "Value": SESSION},
                    {"Key": "ArchonCapability", "Value": "sts"},
                ],
            },
        ]
        TABLE.item = {
            **active_lease(instant(8)),
            "state": "DRAINING",
            "operationId": "1" * 32,
            "inferenceEndpointId": "vpce-0fedcba9876543210",
            "kmsEndpointId": "vpce-0123456789abcdef0",
            "stsEndpointId": "vpce-00112233445566778",
        }
        final = {
            "schema": "archon.core-runtime-command/v1",
            "action": "FINALIZE",
            "decision": "DOWNSCALE",
            "operationId": "1" * 32,
            "sessionId": SESSION,
            "expectedRevision": 8,
        }
        result = lifecycle._finalize(final, instant(8, 30))
        self.assertEqual(result["code"], "STOPPED_COMMITTED")
        update = TABLE.updates[-1]["UpdateExpression"]
        self.assertIn("analyticsCredentialsCiphertext", update)
        self.assertIn("gatewayCredentialsCiphertext", update)
        self.assertIn("kmsEndpointId", update)
        self.assertIn("stsEndpointId", update)
        self.assertEqual(
            sorted(EC2.delete_calls),
            sorted(["vpce-0123456789abcdef0", "vpce-0fedcba9876543210", "vpce-00112233445566778"]),
        )

    def test_lifecycle_has_no_autoscaling_or_direct_bedrock_authority(self) -> None:
        source = path.read_text(encoding="utf-8").lower()
        self.assertNotIn("autoscaling", source)
        self.assertNotIn('boto3.client("bedrock-runtime")', source)
        self.assertIn("_sts.assume_role", source)
        self.assertIn("_kms.encrypt", source)


if __name__ == "__main__":
    main()