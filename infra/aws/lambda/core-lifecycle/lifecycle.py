"""Authoritative lease/CAS gate for the ephemeral DataHub Core runtime.

The function never receives DataHub or model credentials and is deliberately
not permitted to mutate Auto Scaling. Step Functions is the only scaling owner.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import uuid
from typing import Any

import boto3
from botocore.exceptions import ClientError

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
ACTIVE_STATES = {"STARTING", "ACTIVE", "UNHEALTHY", "FAILED"}
TERMINAL_STATES = {"STOPPED", "EXPIRED"}
CAPABILITIES = {
    "dataHubMcpServer": True,
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


def _start(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    _verify_ami()
    binding = command["binding"]
    session_id = command["sessionId"]
    expected = command["expectedRevision"]
    operation_id = uuid.uuid4().hex
    hard = _parse_iso(binding["leaseExpiresAt"], "binding.leaseExpiresAt")
    idle = min(now + dt.timedelta(seconds=IDLE_SECONDS), hard)
    revision = expected + 1
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
        ":operationExpiry": _epoch(now) + OPERATION_SECONDS,
        ":ttl": _epoch(hard) + 86400,
    }
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=(
                "SET sessionId=:session, #state=:starting, revision=:revision, "
                "generation=:generation, capabilityDigest=:digest, "
                "resolution=:resolution, boundAt=:bound, "
                "idleExpiresAt=:idle, hardExpiresAt=:hard, updatedAt=:updated, "
                "operationId=:operation, operationExpiresAt=:operationExpiry, "
                "expiresAt=:ttl REMOVE stoppedAt"
            ),
            ConditionExpression=(
                "(attribute_not_exists(pk) OR "
                "(#state IN (:stopped,:expired,:failed) AND revision=:expected)) "
                "AND attribute_not_exists(operationId)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues=values,
        )
        return _decision(
            "UPSCALE",
            operation_id=operation_id,
            session_id=session_id,
            revision=revision,
        )
    except ClientError as error:
        if not _conditional_failure(error):
            raise
    current = _lease()
    if (
        current
        and current.get("sessionId") == session_id
        and current.get("generation") == GENERATION
        and current.get("capabilityDigest") == CAPABILITY_DIGEST
        and current.get("state") in {"STARTING", "ACTIVE"}
        and int(current.get("revision", -1)) >= revision
    ):
        return _decision("NONE", code="IDEMPOTENT")
    return _decision("REJECT", code="LEASE_CONFLICT")


def _activity(command: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    binding = command["binding"]
    session_id = command["sessionId"]
    expected = command["expectedRevision"]
    hard = _parse_iso(binding["leaseExpiresAt"], "binding.leaseExpiresAt")
    idle = min(now + dt.timedelta(seconds=IDLE_SECONDS), hard)
    revision = expected + 1
    try:
        _TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression=(
                "SET idleExpiresAt=:idle, updatedAt=:updated, revision=:next"
            ),
            ConditionExpression=(
                "sessionId=:session AND #state=:active AND revision=:expected "
                "AND generation=:generation AND capabilityDigest=:digest "
                "AND hardExpiresAt=:hard AND hardExpiresAt>:now "
                "AND attribute_not_exists(operationId)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":idle": _epoch(idle),
                ":updated": _iso(now),
                ":next": revision,
                ":session": session_id,
                ":active": "ACTIVE",
                ":expected": expected,
                ":generation": GENERATION,
                ":digest": CAPABILITY_DIGEST,
                ":hard": _epoch(hard),
                ":now": _epoch(now),
            },
        )
        return _decision(
            "NONE",
            session_id=session_id,
            revision=revision,
            code="ACTIVITY_RECORDED",
            watchdog_deadline=idle,
        )
    except ClientError as error:
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
                "SET #state=:stopping, revision=:next, updatedAt=:updated, "
                "operationId=:operation, operationExpiresAt=:operationExpiry"
            ),
            ConditionExpression=(
                "sessionId=:session AND revision=:expected "
                "AND #state IN (:starting,:active,:unhealthy,:failed) "
                "AND (attribute_not_exists(operationId) "
                "OR operationExpiresAt<=:now)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":stopping": "STOPPING",
                ":next": revision,
                ":updated": _iso(now),
                ":operation": operation_id,
                ":operationExpiry": _epoch(now) + OPERATION_SECONDS,
                ":session": session_id,
                ":expected": expected,
                ":starting": "STARTING",
                ":active": "ACTIVE",
                ":unhealthy": "UNHEALTHY",
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
    update = (
        "SET #state=:state, updatedAt=:updated"
        + (", stoppedAt=:updated" if final_state == "STOPPED" else "")
        + " REMOVE operationId, operationExpiresAt"
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
