"""Authoritative lease/CAS gate for the ephemeral DataHub Core runtime.

The function never receives DataHub or model credentials and is deliberately
not permitted to mutate Auto Scaling. Step Functions is the only scaling owner.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import os
import re
import time
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger("archon.core_lifecycle")

SCHEMA = "archon.core-runtime-command/v1"
SESSION_RE = re.compile(r"^rs_[A-Za-z0-9_-]{43}$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
BINDING_KEYS = {
    "schemaVersion",
    "profileId",
    "generation",
    "capabilityDigest",
    "resolution",
    "boundAt",
    "leaseExpiresAt",
}
COMMAND_KEYS = {
    "START": {"schema", "action", "sessionId", "expectedRevision", "binding"},
    "ACTIVITY": {"schema", "action", "sessionId", "expectedRevision", "binding"},
    "STOP": {"schema", "action", "sessionId", "expectedRevision", "binding"},
    "REAP": {"schema", "action"},
    "FINALIZE": {
        "schema",
        "action",
        "decision",
        "operationId",
        "sessionId",
        "expectedRevision",
    },
}
REAP_KEYS = (
    {"schema", "action"},
    {
        "schema",
        "action",
        "expectedSessionId",
        "expectedRevision",
        "deadlineEpoch",
    },
)
ACTIVE_STATES = {"STARTING", "READY", "FAILED"}
TERMINAL_STATES = {"STOPPED", "EXPIRED"}
CAPABILITIES = {
    "mcpRead": True,
    "mcpGovernedWrite": True,
    "agentContextKit": True,
    "dataHubSkills": True,
    "analyticsAgent": True,
}


def _required_env(name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = os.environ.get(name, "")
    if not value or (pattern is not None and pattern.fullmatch(value) is None):
        raise RuntimeError(f"{name} is missing or invalid")
    return value


TABLE_NAME = _required_env("CORE_LEASE_TABLE")
AMI_ID = _required_env("CORE_AMI_ID", re.compile(r"^ami-[0-9a-f]{8,17}$"))
GENERATION = _required_env("CORE_GENERATION", GENERATION_RE)
CAPABILITY_DIGEST = _required_env("CORE_CAPABILITY_DIGEST", DIGEST_RE)
IMAGE_MANIFEST_DIGEST = _required_env("CORE_IMAGE_MANIFEST_DIGEST", DIGEST_RE)
STAGE = _required_env("CORE_STAGE", re.compile(r"^(staging|production)$"))
VPC_ID = _required_env("CORE_VPC_ID", re.compile(r"^vpc-[0-9a-f]{8,17}$"))
SUBNET_ID = _required_env("CORE_SUBNET_ID", re.compile(r"^subnet-[0-9a-f]{8,17}$"))
INFERENCE_SECURITY_GROUP_ID = _required_env(
    "CORE_INFERENCE_SECURITY_GROUP_ID", re.compile(r"^sg-[0-9a-f]{8,17}$")
)
BEDROCK_SERVICE_NAME = _required_env(
    "CORE_BEDROCK_SERVICE_NAME",
    re.compile(r"^com\.amazonaws\.eu-west-1\.bedrock-runtime$"),
)
KMS_SERVICE_NAME = _required_env(
    "CORE_KMS_SERVICE_NAME", re.compile(r"^com\.amazonaws\.eu-west-1\.kms$")
)
STS_SERVICE_NAME = _required_env(
    "CORE_STS_SERVICE_NAME", re.compile(r"^com\.amazonaws\.eu-west-1\.sts$")
)
INTERFACE_SECURITY_GROUP_ID = _required_env(
    "CORE_INTERFACE_SECURITY_GROUP_ID", re.compile(r"^sg-[0-9a-f]{8,17}$")
)
DATA_KEY_ARN = _required_env(
    "CORE_DATA_KEY_ARN",
    re.compile(r"^arn:(aws|aws-us-gov|aws-cn):kms:eu-west-1:\d{12}:key/[0-9a-f-]{36}$"),
)
MUTATION_SIGNING_KEY_ARN = _required_env(
    "CORE_MUTATION_SIGNING_KEY_ARN",
    re.compile(r"^arn:(aws|aws-us-gov|aws-cn):kms:eu-west-1:\d{12}:key/[0-9a-f-]{36}$"),
)
if MUTATION_SIGNING_KEY_ARN == DATA_KEY_ARN:
    raise RuntimeError("mutation signing and data-encryption keys must be distinct")
ANALYTICS_ROLE_ARN = _required_env(
    "CORE_ANALYTICS_ROLE_ARN",
    re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$"),
)GATEWAY_ROLE_ARN = _required_env(
    "CORE_GATEWAY_ROLE_ARN",
    re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$"),
)
INSTANCE_ROLE_ARN = _required_env(
    "CORE_INSTANCE_ROLE_ARN",
    re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$"),
)
try:
    _resources = json.loads(_required_env("CORE_BEDROCK_RESOURCE_ARNS"))
except json.JSONDecodeError as error:
    raise RuntimeError("CORE_BEDROCK_RESOURCE_ARNS is invalid") from error
if (
    not isinstance(_resources, list)
    or len(_resources) != 8
    or len(set(_resources)) != 8
    or not all(
        isinstance(value, str)
        and re.fullmatch(
            r"^arn:(aws|aws-us-gov|aws-cn):bedrock:"
            r"(eu-central-1|eu-north-1|eu-south-1|eu-south-2|eu-west-1|eu-west-3):"
            r"(?:\d{12})?:(?:inference-profile|application-inference-profile|foundation-model)/"
            r"[A-Za-z0-9._:-]{1,256}$",
            value,
        )
        for value in _resources
    )
):
    raise RuntimeError("CORE_BEDROCK_RESOURCE_ARNS must contain the exact eight resources")
BEDROCK_RESOURCES = tuple(_resources)
IDLE_SECONDS = int(_required_env("CORE_IDLE_SECONDS", re.compile(r"^[1-9]\d{2,4}$")))
HARD_SECONDS = int(_required_env("CORE_HARD_SECONDS", re.compile(r"^[1-9]\d{3,5}$")))
OPERATION_SECONDS = int(
    _required_env("CORE_OPERATION_SECONDS", re.compile(r"^[1-9]\d{1,3}$"))
)
if IDLE_SECONDS != 1800 or HARD_SECONDS != 7200 or OPERATION_SECONDS != 300:
    raise RuntimeError("Core lease durations must remain exactly 30m/2h/5m")

_DYNAMODB = boto3.resource("dynamodb")
_TABLE = _DYNAMODB.Table(TABLE_NAME)
_EC2 = boto3.client("ec2")
_STS = boto3.client("sts")
_KMS = boto3.client("kms")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _epoch(value: dt.datetime) -> int:
    return int(value.timestamp())


def _iso(value: dt.datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or ISO_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical millisecond UTC instant")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if _iso(parsed) != value:
        raise ValueError(f"{label} is not canonical")
    return parsed


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} must use the exact allowlisted schema")
    return value


def _validate_binding(value: Any, now: dt.datetime) -> dict[str, Any]:
    binding = _exact_object(value, BINDING_KEYS, "binding")
    if binding["schemaVersion"] != "archon.runtime-binding/v1":
        raise ValueError("binding schema is invalid")
    if binding["profileId"] != "core":
        raise ValueError("Core lifecycle accepts only profileId=core")
    if not isinstance(binding["generation"], str) or not GENERATION_RE.fullmatch(
        binding["generation"]
    ):
        raise ValueError("binding generation is invalid")
    if binding["generation"] != GENERATION:
        raise ValueError("binding generation does not match configured Core")
    if (
        not isinstance(binding["capabilityDigest"], str)
        or not DIGEST_RE.fullmatch(binding["capabilityDigest"])
        or binding["capabilityDigest"] != CAPABILITY_DIGEST
    ):
        raise ValueError("binding capability digest does not match configured Core")
    if binding["resolution"] not in {"auto", "explicit"}:
        raise ValueError("binding resolution is invalid")
    bound_at = _parse_iso(binding["boundAt"], "binding.boundAt")
    lease_expires = _parse_iso(binding["leaseExpiresAt"], "binding.leaseExpiresAt")
    if lease_expires <= bound_at or lease_expires - bound_at > dt.timedelta(
        seconds=HARD_SECONDS
    ):
        raise ValueError("binding lease must be positive and at most two hours")
    if lease_expires <= now:
        raise ValueError("binding lease is expired")
    return dict(binding)


def _validate_command(event: Any, now: dt.datetime) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("command must be an object")
    action = event.get("action")
    if action not in COMMAND_KEYS:
        raise ValueError("command action is invalid")
    if action == "REAP":
        if set(event) not in REAP_KEYS:
            raise ValueError("reap command must use an exact allowlisted schema")
        command = dict(event)
    else:
        command = _exact_object(event, COMMAND_KEYS[action], "command")
    if command["schema"] != SCHEMA:
        raise ValueError("command schema is invalid")
    if action in {"START", "ACTIVITY", "STOP"}:
        if (
            not isinstance(command["sessionId"], str)
            or SESSION_RE.fullmatch(command["sessionId"]) is None
        ):
            raise ValueError("sessionId is invalid")
        if (
            not isinstance(command["expectedRevision"], int)
            or isinstance(command["expectedRevision"], bool)
            or command["expectedRevision"] < 0
        ):
            raise ValueError("expectedRevision is invalid")
        command = dict(command)
        command["binding"] = _validate_binding(command["binding"], now)
    elif action == "REAP" and "expectedSessionId" in command:
        if (
            not isinstance(command["expectedSessionId"], str)
            or SESSION_RE.fullmatch(command["expectedSessionId"]) is None
        ):
            raise ValueError("expectedSessionId is invalid")
        if (
            not isinstance(command["expectedRevision"], int)
            or isinstance(command["expectedRevision"], bool)
            or command["expectedRevision"] < 1
        ):
            raise ValueError("expectedRevision is invalid")
        if (
            not isinstance(command["deadlineEpoch"], int)
            or isinstance(command["deadlineEpoch"], bool)
            or command["deadlineEpoch"] < 1
        ):
            raise ValueError("deadlineEpoch is invalid")
    elif action == "FINALIZE":
        if command["decision"] not in {"UPSCALE", "DOWNSCALE"}:
            raise ValueError("finalize decision is invalid")
        if (
            not isinstance(command["operationId"], str)
            or re.fullmatch(r"^[0-9a-f]{32}$", command["operationId"]) is None
        ):
            raise ValueError("operationId is invalid")
        if (
            not isinstance(command["sessionId"], str)
            or SESSION_RE.fullmatch(command["sessionId"]) is None
        ):
            raise ValueError("sessionId is invalid")
        if (
            not isinstance(command["expectedRevision"], int)
            or isinstance(command["expectedRevision"], bool)
            or command["expectedRevision"] < 1
        ):
            raise ValueError("expectedRevision is invalid")
    return command


def _lease() -> dict[str, Any] | None:
    response = _TABLE.get_item(
        Key={"pk": "CORE#LEASE", "sk": "CURRENT"}, ConsistentRead=True
    )
    item = response.get("Item")
    return item if isinstance(item, dict) else None


def _decision(
    value: str,
    *,
    operation_id: str = "",
    session_id: str = "",
    revision: int = 0,
    code: str = "OK",
    watchdog_deadline: dt.datetime | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": "archon.core-runtime-decision/v1",
        "decision": value,
        "code": code,
    }
    if operation_id:
        result["operationId"] = operation_id
        result["sessionId"] = session_id
        result["revision"] = revision
    if watchdog_deadline is not None:
        result["watchdog"] = True
        result["watchdogDeadline"] = _iso(watchdog_deadline)
        result["watchdogDeadlineEpoch"] = _epoch(watchdog_deadline)
        result["sessionId"] = session_id
        result["revision"] = revision
    return result


def _conditional_failure(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") in {
        "ConditionalCheckFailedException",
        "TransactionCanceledException",
    }


def _verify_ami() -> None:
    response = _EC2.describe_images(ImageIds=[AMI_ID], Owners=["self"])
    images = response.get("Images", [])
    if len(images) != 1:
        raise ValueError("configured Core AMI is not uniquely owned by this account")
    image = images[0]
    tags = {
        tag.get("Key"): tag.get("Value")
        for tag in image.get("Tags", [])
        if isinstance(tag, dict)
    }
    required = {
        "Application": "archon-datahub",
        "ArchonDataHubCore": "verified",
        "ArchonGeneration": GENERATION,
        "ArchonCapabilityDigest": CAPABILITY_DIGEST,
        "ArchonImageManifestDigest": IMAGE_MANIFEST_DIGEST,
        "ArchonFourComponents": "mcp,ack,skills,analytics",
        "ManagedBy": "github-actions",
        "archon:Purpose": "datahub-core-ami",
    }
    valid = (
        image.get("State") == "available"
        and image.get("Architecture") == "x86_64"
        and image.get("RootDeviceType") == "ebs"
        and image.get("EnaSupport") is True
        and image.get("ImdsSupport") == "v2.0"
        and all(tags.get(key) == value for key, value in required.items())
    )
    if not valid:
        raise ValueError("configured Core AMI failed the immutable provenance gate")


def _runtime_endpoints(capability: str | None = None) -> list[dict[str, Any]]:
    filters = [
        {"Name": "vpc-id", "Values": [VPC_ID]},
        {"Name": "tag:Application", "Values": ["archon-datahub"]},
        {"Name": "tag:ManagedBy", "Values": ["archon-core-lifecycle"]},
        {"Name": "tag:Environment", "Values": [STAGE]},
    ]
    if capability is not None:
        if capability not in {"bedrock", "kms", "sts"}:
            raise ValueError("endpoint capability is invalid")
        filters.append({"Name": "tag:ArchonCapability", "Values": [capability]})
    response = _EC2.describe_vpc_endpoints(Filters=filters)
    return [
        endpoint
        for endpoint in response.get("VpcEndpoints", [])
        if endpoint.get("State") not in {"deleted", "failed", "rejected"}
    ]


def _endpoint_session(endpoint: dict[str, Any]) -> str:
    tags = {
        tag.get("Key"): tag.get("Value")
        for tag in endpoint.get("Tags", [])
        if isinstance(tag, dict)
    }
    return str(tags.get("ArchonSessionId", ""))


def _endpoint_token(session_id: str, capability: str) -> str:
    material = f"{STAGE}\0{GENERATION}\0{session_id}\0{capability}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _encryption_context(session_id: str, capability: str) -> dict[str, str]:
    if capability not in {"analytics-agent-bedrock", "governed-gateway-control"}:
        raise ValueError("credential capability is invalid")
    return {
        "stage": STAGE,
        "sessionId": session_id,
        "generation": GENERATION,
        "capabilityDigest": CAPABILITY_DIGEST,
        "capability": capability,
    }


def _endpoint_policy(capability: str, session_id: str) -> dict[str, Any]:
    if capability == "kms":
        context: dict[str, Any] = {
            f"kms:EncryptionContext:{key}": value
            for key, value in _encryption_context(
                session_id, "analytics-agent-bedrock"
            ).items()
            if key != "capability"
        }
        context["kms:EncryptionContext:capability"] = [
            "analytics-agent-bedrock", "governed-gateway-control"
        ]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "OnlyActiveCoreHostDecrypt",
                    "Effect": "Allow",
                    "Principal": {"AWS": INSTANCE_ROLE_ARN},
                    "Action": "kms:Decrypt",
                    "Resource": DATA_KEY_ARN,
                    "Condition": {"StringEquals": context},
                },
                {
                    "Sid": "OnlyGovernedGatewayVerificationKey",
                    "Effect": "Allow",
                    "Principal": {"AWS": GATEWAY_ROLE_ARN},
                    "Action": ["kms:GetPublicKey", "kms:DescribeKey"],
                    "Resource": MUTATION_SIGNING_KEY_ARN,
                },
            ],
        }
    if capability == "bedrock":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "OnlyScopedAnalyticsSession",
                "Effect": "Allow",
                "Principal": {"AWS": ANALYTICS_ROLE_ARN},
                "Action": [
                    "bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
                ],
                "Resource": list(BEDROCK_RESOURCES),
            }],
        }
    if capability == "sts":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "OnlyScopedAnalyticsIdentityProof",
                "Effect": "Allow",
                "Principal": {"AWS": ANALYTICS_ROLE_ARN},
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            }],
        }
    raise ValueError("endpoint capability is invalid")

def _delete_endpoint(endpoint_id: Any) -> None:
    if not isinstance(endpoint_id, str) or re.fullmatch(
        r"^vpce-[0-9a-f]{8,17}$", endpoint_id
    ) is None:
        return
    _EC2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id])


def _cleanup_orphan_endpoints(active_endpoint_ids: set[str] | None = None) -> None:
    active = active_endpoint_ids or set()
    for endpoint in _runtime_endpoints():
        endpoint_id = endpoint.get("VpcEndpointId", "")
        if endpoint_id not in active and endpoint.get("State") != "deleting":
            _delete_endpoint(endpoint_id)


def _cleanup_session_endpoints(
    session_id: str, endpoint_ids: tuple[str, ...] = ()
) -> None:
    owned = {
        value
        for value in endpoint_ids
        if isinstance(value, str)
        and re.fullmatch(r"^vpce-[0-9a-f]{8,17}$", value)
    }
    try:
        for endpoint in _runtime_endpoints():
            candidate = endpoint.get("VpcEndpointId")
            if (
                _endpoint_session(endpoint) == session_id
                and endpoint.get("State") != "deleting"
                and isinstance(candidate, str)
                and re.fullmatch(r"^vpce-[0-9a-f]{8,17}$", candidate)
            ):
                owned.add(candidate)
    except ClientError as error:
        LOGGER.warning(
            "Could not enumerate session-owned endpoints during rollback",
            exc_info=error,
        )
    for candidate in sorted(owned):
        try:
            _delete_endpoint(candidate)
        except ClientError as error:
            LOGGER.warning(
                "Could not delete exact session-owned endpoint %s",
                candidate,
                exc_info=error,
            )


def _abandon_start(
    session_id: str,
    revision: int,
    operation_id: str,
    endpoint_ids: tuple[str, ...] = (),
) -> None:
    for attempt in range(3):
        try:
            _TABLE.update_item(
                Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
                UpdateExpression=(
                    "SET #state=:failed, updatedAt=:updated "
                    "REMOVE operationId, operationExpiresAt, inferenceEndpointId, "
                    "kmsEndpointId, stsEndpointId, analyticsCredentialsCiphertext, "
                    "analyticsCredentialsExpiresAt, analyticsCredentialsVersion, "
                    "gatewayCredentialsCiphertext, gatewayCredentialsExpiresAt, "
                    "gatewayCredentialsVersion"
                ),
                ConditionExpression=(
                    "sessionId=:session AND #state=:starting "
                    "AND revision=:revision AND operationId=:operation "
                    "AND generation=:generation AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":failed": "FAILED",
                    ":updated": _iso(_now()),
                    ":session": session_id,
                    ":starting": "STARTING",
                    ":revision": revision,
                    ":operation": operation_id,
                    ":generation": GENERATION,
                    ":digest": CAPABILITY_DIGEST,
                },
            )
            break
        except ClientError as error:
            if _conditional_failure(error):
                break
            if attempt < 2:
                time.sleep(0.2 * (2**attempt))
    _cleanup_session_endpoints(session_id, endpoint_ids)


def _ensure_endpoint(
    capability: str, session_id: str, operation_expires_at: int
) -> tuple[str, bool]:
    service_name = {
        "bedrock": BEDROCK_SERVICE_NAME,
        "kms": KMS_SERVICE_NAME,
        "sts": STS_SERVICE_NAME,
    }.get(capability)
    if service_name is None:
        raise ValueError("endpoint capability is invalid")
    remaining = max(1, operation_expires_at - int(time.time()) - 5)
    deadline = time.monotonic() + min(210, remaining)
    retryable_codes = {
        "ConflictingDomainExists",
        "InvalidParameter",
        "InvalidState",
        "InvalidVpcEndpoint.DuplicateSubnets",
    }
    while True:
        endpoints = _runtime_endpoints(capability)
        for endpoint in endpoints:
            if (
                _endpoint_session(endpoint) == session_id
                and endpoint.get("State") != "deleting"
            ):
                endpoint_id = endpoint.get("VpcEndpointId")
                if isinstance(endpoint_id, str) and re.fullmatch(
                    r"^vpce-[0-9a-f]{8,17}$", endpoint_id
                ):
                    return endpoint_id, False
        for endpoint in endpoints:
            if endpoint.get("State") != "deleting":
                _delete_endpoint(endpoint.get("VpcEndpointId"))
        if endpoints:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{capability} endpoint release timed out")
            time.sleep(3)
            continue
        try:
            response = _EC2.create_vpc_endpoint(
                VpcEndpointType="Interface",
                VpcId=VPC_ID,
                ServiceName=service_name,
                SubnetIds=[SUBNET_ID],
                SecurityGroupIds=[INTERFACE_SECURITY_GROUP_ID],
                PrivateDnsEnabled=True,
                ClientToken=_endpoint_token(session_id, capability),
                PolicyDocument=_endpoint_policy(capability, session_id),
                TagSpecifications=[{
                    "ResourceType": "vpc-endpoint",
                    "Tags": [
                        {"Key": "Application", "Value": "archon-datahub"},
                        {"Key": "Environment", "Value": STAGE},
                        {"Key": "ManagedBy", "Value": "archon-core-lifecycle"},
                        {"Key": "ArchonSessionId", "Value": session_id},
                        {"Key": "ArchonCapability", "Value": capability},
                    ],
                }],
            )
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in retryable_codes and not str(code).startswith("InvalidVpcEndpoint"):
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"{capability} endpoint creation did not converge"
                ) from error
            time.sleep(3)
            continue
        endpoint_id = response.get("VpcEndpoint", {}).get("VpcEndpointId")
        if not isinstance(endpoint_id, str) or re.fullmatch(
            r"^vpce-[0-9a-f]{8,17}$", endpoint_id
        ) is None:
            raise ValueError(f"{capability} endpoint creation returned no exact ID")
        return endpoint_id, True


def _mint_scoped_credentials(
    session_id: str,
    now: dt.datetime,
    *,
    role_arn: str,
    capability: str,
    version_prefix: str,
    session_label: str,
) -> dict[str, Any]:
    if version_prefix not in {"acv_", "gcv_"} or session_label not in {"analytics", "gateway"}:
        raise ValueError("scoped credential contract is invalid")
    suffix = hashlib.sha256(session_id.encode("ascii")).hexdigest()[:16]
    response = _STS.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"archon-{session_label}-{suffix}",
        DurationSeconds=3600,
    )
    credentials = response.get("Credentials", {})
    expiration = credentials.get("Expiration")
    if not isinstance(expiration, dt.datetime):
        raise RuntimeError("STS returned no credential expiration")
    expiration_epoch = _epoch(expiration)
    if expiration_epoch < _epoch(now) + 3300 or expiration_epoch > _epoch(now) + 3660:
        raise RuntimeError("STS credential duration is outside the one-hour bound")
    plaintext = {
        "accessKeyId": credentials.get("AccessKeyId"),
        "secretAccessKey": credentials.get("SecretAccessKey"),
        "sessionToken": credentials.get("SessionToken"),
        "expirationEpoch": expiration_epoch,
    }
    if (
        not all(
            isinstance(plaintext[key], str) and 1 <= len(plaintext[key]) <= 4096
            for key in ("accessKeyId", "secretAccessKey", "sessionToken")
        )
        or not str(plaintext["accessKeyId"]).startswith("ASIA")
    ):
        raise RuntimeError("STS returned invalid scoped credentials")
    encrypted = _KMS.encrypt(
        KeyId=DATA_KEY_ARN,
        Plaintext=json.dumps(
            plaintext, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8"),
        EncryptionContext=_encryption_context(session_id, capability),
    )
    ciphertext = encrypted.get("CiphertextBlob")
    if not isinstance(ciphertext, bytes) or not 64 <= len(ciphertext) <= 16384:
        raise RuntimeError("KMS returned invalid credential ciphertext")
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "expiresAt": expiration_epoch,
        "version": version_prefix + uuid.uuid4().hex,
    }


def _mint_analytics_credentials(session_id: str, now: dt.datetime) -> dict[str, Any]:
    return _mint_scoped_credentials(
        session_id, now, role_arn=ANALYTICS_ROLE_ARN,
        capability="analytics-agent-bedrock", version_prefix="acv_",
        session_label="analytics",
    )


def _mint_gateway_credentials(session_id: str, now: dt.datetime) -> dict[str, Any]:
    return _mint_scoped_credentials(
        session_id, now, role_arn=GATEWAY_ROLE_ARN,
        capability="governed-gateway-control", version_prefix="gcv_",
        session_label="gateway",
    )

def _start(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    _verify_ami()
    binding = command["binding"]
    session_id = command["sessionId"]
    expected = command["expectedRevision"]
    hard = _parse_iso(binding["leaseExpiresAt"], "binding.leaseExpiresAt")
    idle = min(now + dt.timedelta(seconds=IDLE_SECONDS), hard)
    revision = expected + 1
    operation_id = uuid.uuid4().hex
    operation_expires_at = _epoch(now) + OPERATION_SECONDS
    values = {
        ":session": session_id,
        ":starting": "STARTING",
        ":stopped": "STOPPED",
        ":expired": "EXPIRED",
        ":failed": "FAILED",
        ":expected": expected,
        ":revision": revision,
        ":generation": GENERATION,
        ":digest": CAPABILITY_DIGEST,
        ":resolution": binding["resolution"],
        ":bound": binding["boundAt"],
        ":idle": _epoch(idle),
        ":hard": _epoch(hard),
        ":updated": _iso(now),
        ":operation": operation_id,
        ":operationExpiry": operation_expires_at,
        ":ttl": _epoch(hard) + 86400,
    }

    # Win authoritative ownership before creating any billable/network resource.
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=(
                "SET sessionId=:session, #state=:starting, revision=:revision, "
                "generation=:generation, capabilityDigest=:digest, "
                "resolution=:resolution, boundAt=:bound, "
                "idleExpiresAt=:idle, hardExpiresAt=:hard, updatedAt=:updated, "
                "operationId=:operation, operationExpiresAt=:operationExpiry, "
                "expiresAt=:ttl REMOVE stoppedAt, inferenceEndpointId, kmsEndpointId, stsEndpointId, "
                "analyticsCredentialsCiphertext, analyticsCredentialsExpiresAt, "
                "analyticsCredentialsVersion, gatewayCredentialsCiphertext, "
                "gatewayCredentialsExpiresAt, gatewayCredentialsVersion"
            ),
            ConditionExpression=(
                "(attribute_not_exists(pk) OR "
                "(#state IN (:stopped,:expired,:failed) AND revision=:expected)) "
                "AND attribute_not_exists(operationId)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues=values,
        )
    except ClientError as error:
        if not _conditional_failure(error):
            raise
        current = _lease()
        same_reservation = (
            current
            and current.get("sessionId") == session_id
            and current.get("generation") == GENERATION
            and current.get("capabilityDigest") == CAPABILITY_DIGEST
            and current.get("state") == "STARTING"
            and current.get("revision") == revision
            and current.get("resolution") == binding["resolution"]
            and current.get("boundAt") == binding["boundAt"]
            and int(current.get("hardExpiresAt", 0)) == _epoch(hard)
            and isinstance(current.get("operationId"), str)
            and int(current.get("operationExpiresAt", 0)) > _epoch(now)
        )
        if same_reservation:
            operation_id = str(current["operationId"])
            operation_expires_at = int(current["operationExpiresAt"])
        elif (
            current
            and current.get("sessionId") == session_id
            and current.get("generation") == GENERATION
            and current.get("capabilityDigest") == CAPABILITY_DIGEST
            and current.get("state") == "READY"
            and int(current.get("revision", -1)) >= revision
        ):
            return _decision("NONE", code="IDEMPOTENT")
        else:
            return _decision("REJECT", code="LEASE_CONFLICT")

    endpoint_ids: list[str] = []
    try:
        kms_endpoint_id, _ = _ensure_endpoint(
            "kms", session_id, operation_expires_at
        )
        endpoint_ids.append(kms_endpoint_id)
        inference_endpoint_id, _ = _ensure_endpoint(
            "bedrock", session_id, operation_expires_at
        )
        endpoint_ids.append(inference_endpoint_id)
        sts_endpoint_id, _ = _ensure_endpoint(
            "sts", session_id, operation_expires_at
        )
        endpoint_ids.append(sts_endpoint_id)
        analytics_credential = _mint_analytics_credentials(session_id, now)
        gateway_credential = _mint_gateway_credentials(session_id, now)
        try:
            _TABLE.update_item(
                Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
                UpdateExpression=(
                    "SET inferenceEndpointId=:inferenceEndpoint, "
                    "kmsEndpointId=:kmsEndpoint, stsEndpointId=:stsEndpoint, "
                    "updatedAt=:updated, "
                    "analyticsCredentialsCiphertext=:analyticsCiphertext, "
                    "analyticsCredentialsExpiresAt=:analyticsExpiry, "
                    "analyticsCredentialsVersion=:analyticsVersion, "
                    "gatewayCredentialsCiphertext=:gatewayCiphertext, "
                    "gatewayCredentialsExpiresAt=:gatewayExpiry, "
                    "gatewayCredentialsVersion=:gatewayVersion"
                ),
                ConditionExpression=(
                    "sessionId=:session AND #state=:starting "
                    "AND revision=:revision AND operationId=:operation "
                    "AND generation=:generation AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":inferenceEndpoint": inference_endpoint_id,
                    ":kmsEndpoint": kms_endpoint_id,
                    ":stsEndpoint": sts_endpoint_id,
                    ":analyticsCiphertext": analytics_credential["ciphertext"],
                    ":analyticsExpiry": analytics_credential["expiresAt"],
                    ":analyticsVersion": analytics_credential["version"],
                    ":gatewayCiphertext": gateway_credential["ciphertext"],
                    ":gatewayExpiry": gateway_credential["expiresAt"],
                    ":gatewayVersion": gateway_credential["version"],
                    ":updated": _iso(now),
                    ":session": session_id,
                    ":starting": "STARTING",
                    ":revision": revision,
                    ":operation": operation_id,
                    ":generation": GENERATION,
                    ":digest": CAPABILITY_DIGEST,
                },
            )
        except ClientError as error:
            if not _conditional_failure(error):
                raise
            current = _lease()
            if not (
                current
                and current.get("sessionId") == session_id
                and current.get("revision") == revision
                and current.get("operationId") == operation_id
                and current.get("inferenceEndpointId") == inference_endpoint_id
                and current.get("kmsEndpointId") == kms_endpoint_id
                and current.get("stsEndpointId") == sts_endpoint_id
                and isinstance(current.get("analyticsCredentialsCiphertext"), str)
                and isinstance(current.get("analyticsCredentialsVersion"), str)
                and int(current.get("analyticsCredentialsExpiresAt", 0)) > _epoch(now) + 900
                and isinstance(current.get("gatewayCredentialsCiphertext"), str)
                and isinstance(current.get("gatewayCredentialsVersion"), str)
                and int(current.get("gatewayCredentialsExpiresAt", 0)) > _epoch(now) + 900
            ):
                _abandon_start(
                    session_id, revision, operation_id, tuple(endpoint_ids)
                )
                return _decision("REJECT", code="LEASE_CONFLICT")
    except Exception:
        _abandon_start(session_id, revision, operation_id, tuple(endpoint_ids))
        raise
    return _decision(
        "UPSCALE",
        operation_id=operation_id,
        session_id=session_id,
        revision=revision,
    )

def _activity(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    binding = command["binding"]
    session_id = command["sessionId"]
    expected = command["expectedRevision"]
    hard = _parse_iso(binding["leaseExpiresAt"], "binding.leaseExpiresAt")
    idle = min(now + dt.timedelta(seconds=IDLE_SECONDS), hard)
    revision = expected + 1
    current = _lease()
    if (
        not current
        or current.get("sessionId") != session_id
        or current.get("state") != "READY"
        or current.get("revision") != expected
        or current.get("generation") != GENERATION
        or current.get("capabilityDigest") != CAPABILITY_DIGEST
        or int(current.get("hardExpiresAt", 0)) != _epoch(hard)
        or int(current.get("hardExpiresAt", 0)) <= _epoch(now)
    ):
        if (
            current
            and current.get("sessionId") == session_id
            and int(current.get("revision", -1)) == revision
            and int(current.get("idleExpiresAt", 0)) >= _epoch(now)
        ):
            return _decision(
                "NONE",
                session_id=session_id,
                revision=revision,
                code="IDEMPOTENT",
                watchdog_deadline=dt.datetime.fromtimestamp(
                    int(current["idleExpiresAt"]), tz=dt.timezone.utc
                ),
            )
        return _decision("REJECT", code="STALE_ACTIVITY")
    previous_analytics_version = current.get("analyticsCredentialsVersion")
    previous_gateway_version = current.get("gatewayCredentialsVersion")
    analytics_expiry = current.get("analyticsCredentialsExpiresAt")
    gateway_expiry = current.get("gatewayCredentialsExpiresAt")
    if (
        not isinstance(previous_analytics_version, str)
        or re.fullmatch(r"^acv_[0-9a-f]{32}$", previous_analytics_version) is None
        or not isinstance(previous_gateway_version, str)
        or re.fullmatch(r"^gcv_[0-9a-f]{32}$", previous_gateway_version) is None
        or not isinstance(analytics_expiry, int)
        or isinstance(analytics_expiry, bool)
        or not isinstance(gateway_expiry, int)
        or isinstance(gateway_expiry, bool)
    ):
        return _decision("REJECT", code="INVALID_CREDENTIAL_BINDING")
    rotate_analytics = analytics_expiry <= _epoch(now) + 1200
    rotate_gateway = gateway_expiry <= _epoch(now) + 1200
    analytics_credential = (
        _mint_analytics_credentials(session_id, now) if rotate_analytics else None
    )
    gateway_credential = (
        _mint_gateway_credentials(session_id, now) if rotate_gateway else None
    )
    update = "SET idleExpiresAt=:idle, updatedAt=:updated, revision=:next"
    values: dict[str, Any] = {
        ":idle": _epoch(idle),
        ":updated": _iso(now),
        ":next": revision,
        ":session": session_id,
        ":ready": "READY",
        ":expected": expected,
        ":generation": GENERATION,
        ":digest": CAPABILITY_DIGEST,
        ":hard": _epoch(hard),
        ":now": _epoch(now),
        ":previousAnalyticsVersion": previous_analytics_version,
        ":previousGatewayVersion": previous_gateway_version,
    }
    if analytics_credential is not None:
        update += (
            ", analyticsCredentialsCiphertext=:analyticsCiphertext, "
            "analyticsCredentialsExpiresAt=:analyticsExpiry, "
            "analyticsCredentialsVersion=:analyticsVersion"
        )
        values.update({
            ":analyticsCiphertext": analytics_credential["ciphertext"],
            ":analyticsExpiry": analytics_credential["expiresAt"],
            ":analyticsVersion": analytics_credential["version"],
        })
    if gateway_credential is not None:
        update += (
            ", gatewayCredentialsCiphertext=:gatewayCiphertext, "
            "gatewayCredentialsExpiresAt=:gatewayExpiry, "
            "gatewayCredentialsVersion=:gatewayVersion"
        )
        values.update({
            ":gatewayCiphertext": gateway_credential["ciphertext"],
            ":gatewayExpiry": gateway_credential["expiresAt"],
            ":gatewayVersion": gateway_credential["version"],
        })
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=update,
            ConditionExpression=(
                "sessionId=:session AND #state=:ready AND revision=:expected "
                "AND generation=:generation AND capabilityDigest=:digest "
                "AND hardExpiresAt=:hard AND hardExpiresAt>:now "
                "AND analyticsCredentialsVersion=:previousAnalyticsVersion "
                "AND gatewayCredentialsVersion=:previousGatewayVersion "
                "AND attribute_not_exists(operationId)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues=values,
        )
        return _decision(
            "NONE",
            session_id=session_id,
            revision=revision,
            code=(
                "ACTIVITY_RECORDED_CREDENTIALS_ROTATED"
                if analytics_credential is not None or gateway_credential is not None
                else "ACTIVITY_RECORDED"
            ),
            watchdog_deadline=idle,
        )    except ClientError as error:
        if not _conditional_failure(error):
            raise
    current = _lease()
    if (
        current
        and current.get("sessionId") == session_id
        and int(current.get("revision", -1)) == revision
        and int(current.get("idleExpiresAt", 0)) >= _epoch(now)
    ):
        return _decision(
            "NONE",
            session_id=session_id,
            revision=revision,
            code="IDEMPOTENT",
            watchdog_deadline=dt.datetime.fromtimestamp(
                int(current["idleExpiresAt"]), tz=dt.timezone.utc
            ),
        )
    return _decision("REJECT", code="STALE_ACTIVITY")

def _begin_down(
    current: dict[str, Any],
    now: dt.datetime,
    *,
    expected: int,
    code: str,
) -> dict[str, Any]:
    session_id = current.get("sessionId")
    if not isinstance(session_id, str) or SESSION_RE.fullmatch(session_id) is None:
        return _decision("REJECT", code="INVALID_STORED_SESSION")
    operation_id = uuid.uuid4().hex
    revision = expected + 1
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=(
                "SET #state=:draining, revision=:next, updatedAt=:updated, "
                "operationId=:operation, operationExpiresAt=:operationExpiry"
            ),
            ConditionExpression=(
                "sessionId=:session AND revision=:expected "
                "AND #state IN (:starting,:ready,:failed) "
                "AND (attribute_not_exists(operationId) "
                "OR operationExpiresAt<=:now)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":draining": "DRAINING",
                ":next": revision,
                ":updated": _iso(now),
                ":operation": operation_id,
                ":operationExpiry": _epoch(now) + OPERATION_SECONDS,
                ":session": session_id,
                ":expected": expected,
                ":starting": "STARTING",
                ":ready": "READY",
                ":failed": "FAILED",
                ":now": _epoch(now),
            },
        )
        return _decision(
            "DOWNSCALE",
            operation_id=operation_id,
            session_id=session_id,
            revision=revision,
            code=code,
        )
    except ClientError as error:
        if not _conditional_failure(error):
            raise
    return _decision("REJECT", code="LEASE_CONFLICT")


def _stop(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    current = _lease()
    if current is None:
        return _decision("NONE", code="ALREADY_STOPPED")
    if (
        current.get("sessionId") != command["sessionId"]
        or current.get("generation") != GENERATION
        or current.get("capabilityDigest") != CAPABILITY_DIGEST
    ):
        return _decision("REJECT", code="BINDING_MISMATCH")
    if current.get("state") in TERMINAL_STATES:
        return _decision("NONE", code="IDEMPOTENT")
    if int(current.get("revision", -1)) != command["expectedRevision"]:
        return _decision("REJECT", code="STALE_REVISION")
    return _begin_down(
        current,
        now,
        expected=command["expectedRevision"],
        code="EXPLICIT_STOP",
    )


def _reap(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    current = _lease()
    if current is None or current.get("state") in TERMINAL_STATES:
        _cleanup_orphan_endpoints()
        return _decision("NONE", code="NO_ACTIVE_LEASE")
    if "expectedSessionId" in command:
        if (
            current.get("sessionId") != command["expectedSessionId"]
            or current.get("revision") != command["expectedRevision"]
            or command["deadlineEpoch"] > _epoch(now)
            or int(current.get("idleExpiresAt", 0) or 0)
            != command["deadlineEpoch"]
        ):
            return _decision("NONE", code="STALE_WATCHDOG")
    revision = current.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool):
        return _decision("REJECT", code="INVALID_STORED_REVISION")
    operation_expiry = int(current.get("operationExpiresAt", 0) or 0)
    expired = (
        int(current.get("hardExpiresAt", 0) or 0) <= _epoch(now)
        or int(current.get("idleExpiresAt", 0) or 0) <= _epoch(now)
        or (bool(current.get("operationId")) and operation_expiry <= _epoch(now))
    )
    if not expired:
        return _decision("NONE", code="LEASE_CURRENT")
    return _begin_down(current, now, expected=revision, code="LEASE_EXPIRED")


def _finalize(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    decision = command["decision"]
    final_state = "STARTING" if decision == "UPSCALE" else "STOPPED"
    before = _lease()
    endpoint_ids = (
        (
            str(before.get("inferenceEndpointId", "")),
            str(before.get("kmsEndpointId", "")),
            str(before.get("stsEndpointId", "")),
        )
        if before
        else ()
    )
    update = (
        "SET #state=:state, updatedAt=:updated"
        + (", stoppedAt=:updated" if final_state == "STOPPED" else "")
        + (
            " REMOVE operationId, operationExpiresAt, inferenceEndpointId, "
            "kmsEndpointId, stsEndpointId, analyticsCredentialsCiphertext, "
            "analyticsCredentialsExpiresAt, analyticsCredentialsVersion, "
                    "gatewayCredentialsCiphertext, gatewayCredentialsExpiresAt, "
                    "gatewayCredentialsVersion"
            if final_state == "STOPPED"
            else " REMOVE operationId, operationExpiresAt"
        )
    )
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=update,
            ConditionExpression=(
                "sessionId=:session AND revision=:revision "
                "AND operationId=:operation"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":state": final_state,
                ":updated": _iso(now),
                ":session": command["sessionId"],
                ":revision": command["expectedRevision"],
                ":operation": command["operationId"],
            },
        )
    except ClientError as error:
        if not _conditional_failure(error):
            raise
        current = _lease()
        if (
            current
            and current.get("sessionId") == command["sessionId"]
            and current.get("state") == final_state
            and "operationId" not in current
        ):
            if final_state == "STARTING":
                return _decision(
                    "NONE",
                    session_id=command["sessionId"],
                    revision=command["expectedRevision"],
                    code="IDEMPOTENT",
                    watchdog_deadline=dt.datetime.fromtimestamp(
                        int(current["idleExpiresAt"]), tz=dt.timezone.utc
                    ),
                )
            return _decision("NONE", code="IDEMPOTENT")
        return _decision("REJECT", code="FINALIZE_CONFLICT")

    if final_state == "STOPPED":
        for endpoint_id in endpoint_ids:
            _delete_endpoint(endpoint_id)
        _cleanup_orphan_endpoints()
        _TABLE.put_item(
            Item={
                "pk": "RUNTIME#core",
                "sk": "HEALTH",
                "generation": GENERATION,
                "status": "STOPPED",
                "checkedAt": _iso(now),
                "capabilities": CAPABILITIES,
                "capabilityDigest": CAPABILITY_DIGEST,
                "sessionId": command["sessionId"],
                "endpoint": f"dynamodb://core-session/{command['sessionId']}",
                "transport": "dynamodb",
                "expiresAt": _epoch(now) + 86400,
            }
        )
    if final_state == "STARTING":
        current = _lease()
        if current is None:
            return _decision("REJECT", code="FINALIZE_READ_FAILED")
        return _decision(
            "NONE",
            session_id=command["sessionId"],
            revision=command["expectedRevision"],
            code="STARTING_COMMITTED",
            watchdog_deadline=dt.datetime.fromtimestamp(
                int(current["idleExpiresAt"]), tz=dt.timezone.utc
            ),
        )
    return _decision("NONE", code="STOPPED_COMMITTED")


def handler(event: Any, _context: Any) -> dict[str, Any]:
    now = _now()
    try:
        command = _validate_command(event, now)
        action = command["action"]
        if action == "START":
            return _start(command, now)
        if action == "ACTIVITY":
            return _activity(command, now)
        if action == "STOP":
            return _stop(command, now)
        if action == "REAP":
            return _reap(command, now)
        if action == "FINALIZE":
            return _finalize(command, now)
        raise AssertionError("unreachable action")
    except ValueError:
        return _decision("REJECT", code="INVALID_COMMAND")