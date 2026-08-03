"""Strict contracts shared by the DataHub Cloud v2 Lambda handlers."""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import re
from decimal import Decimal
from typing import Any, Literal

from boto3.dynamodb.types import TypeDeserializer

SCHEMA_JOB = "archon.runtime-bound-job/v2"
SCHEMA_RECEIPT = "archon.runtime-bound-job-receipt/v2"
SCHEMA_BINDING = "archon.runtime-binding/v1"
PROFILE = "cloud"
MUTATION_CANONICALIZATION = "archon.sorted-json-utf8/v1"
MUTATION_ALGORITHM = "ECDSA_SHA_256"
PII_TAG = "urn:li:tag:PII"
DATASET_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
)
COLUMN_PATH = "customer_email"
QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)

DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
AUDIT_RE = re.compile(r"^[a-f0-9]{64}$")
SESSION_RE = re.compile(r"^rs_[A-Za-z0-9_-]{43}$")
JOB_RE = re.compile(r"^job_[A-Za-z0-9_-]{22}$")
GENERATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
STAGE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
KMS_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:"
    r"key/[0-9a-f-]{36}$"
)
TAG_RE = re.compile(r"^urn:li:tag:[A-Za-z0-9_.:-]{1,220}$")
CREDENTIAL_RE = re.compile(
    rb"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    rb"Bearer\s+[A-Za-z0-9._~+/=-]{12,}|"
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,}"
)

READ_OPERATIONS = frozenset(
    {"ANALYZE", "READ_TAGS", "IMPROVE_CONTEXT", "POST_ANALYZE", "POST_READ_TAGS"}
)
MUTATION_OPERATIONS = frozenset({"GOVERNED_TAG_MUTATION"})
ALL_OPERATIONS = READ_OPERATIONS | MUTATION_OPERATIONS
CAPABILITY_KEYS = (
    "mcpRead",
    "mcpGovernedWrite",
    "agentContextKit",
    "dataHubSkills",
    "analyticsAgent",
)
_JOB_KEYS = frozenset(
    {
        "pk", "sk", "schema", "profileId", "jobId", "auditId",
        "runtimeEvidenceDigest", "sessionId", "generation", "capabilityDigest",
        "state", "operation", "request", "submittedAt", "expiresAt",
    }
)


class ContractError(ValueError):
    """A terminal, sanitized contract rejection."""


class RetryableFailure(RuntimeError):
    """An infrastructure failure for DynamoDB partial-batch retry."""


@dataclasses.dataclass(frozen=True)
class RuntimeJob:
    event_id: str
    pk: str
    sk: str
    job_id: str
    audit_id: str
    runtime_evidence_digest: str
    session_id: str
    generation: str
    capability_digest: str
    operation: str
    request: dict[str, Any]
    submitted_at: str
    expires_at: int

    def identity(self) -> dict[str, str]:
        return {
            "profileId": PROFILE,
            "jobId": self.job_id,
            "auditId": self.audit_id,
            "runtimeEvidenceDigest": self.runtime_evidence_digest,
            "sessionId": self.session_id,
            "generation": self.generation,
            "capabilityDigest": self.capability_digest,
            "operation": self.operation,
        }


def is_record(value: Any) -> bool:
    return isinstance(value, dict)


def exact_keys(value: Any, required: set[str] | frozenset[str]) -> bool:
    return is_record(value) and set(value) == set(required)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (OverflowError, TypeError, ValueError) as error:
        raise ContractError("canonical_json_invalid") from error


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def without(value: dict[str, Any], *keys: str) -> dict[str, Any]:
    omitted = set(keys)
    return {key: item for key, item in value.items() if key not in omitted}


def verify_digest_object(value: Any, field: str = "digest") -> bool:
    return (
        is_record(value)
        and DIGEST_RE.fullmatch(str(value.get(field))) is not None
        and hmac.compare_digest(value[field], digest(without(value, field)))
    )


def parse_instant(value: Any) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise ContractError("timestamp_invalid")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError("timestamp_invalid") from error
    if parsed.tzinfo is None:
        raise ContractError("timestamp_invalid")
    return parsed.astimezone(dt.UTC)


def instant() -> str:
    return (
        dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def validate_binding(value: Any) -> dict[str, Any]:
    expected = {
        "schemaVersion", "profileId", "generation", "capabilityDigest",
        "resolution", "boundAt", "leaseExpiresAt",
    }
    if (
        not exact_keys(value, expected)
        or value.get("schemaVersion") != SCHEMA_BINDING
        or value.get("profileId") != PROFILE
        or GENERATION_RE.fullmatch(str(value.get("generation"))) is None
        or DIGEST_RE.fullmatch(str(value.get("capabilityDigest"))) is None
        or value.get("resolution") not in {"auto", "explicit"}
    ):
        raise ContractError("runtime_binding_invalid")
    bound = parse_instant(value["boundAt"])
    expires = parse_instant(value["leaseExpiresAt"])
    if expires <= bound or expires - bound > dt.timedelta(hours=2):
        raise ContractError("runtime_binding_invalid")
    return dict(value)


def capability_digest(generation: str, capabilities: Any) -> str:
    if (
        not exact_keys(capabilities, set(CAPABILITY_KEYS))
        or any(type(capabilities[key]) is not bool for key in CAPABILITY_KEYS)
    ):
        raise ContractError("runtime_capabilities_invalid")
    return digest(
        {
            "schemaVersion": "archon.runtime-capabilities/v1",
            "profileId": PROFILE,
            "generation": generation,
            "capabilities": {key: capabilities[key] for key in CAPABILITY_KEYS},
        }
    )


def normalize_ddb(value: Any, depth: int = 0) -> Any:
    if depth > 16:
        raise ContractError("ddb_value_too_deep")
    if isinstance(value, Decimal):
        if not value.is_finite() or value != value.to_integral_value():
            raise ContractError("ddb_number_invalid")
        integer = int(value)
        if not -(2**63) <= integer <= 2**63 - 1:
            raise ContractError("ddb_number_invalid")
        return integer
    if isinstance(value, list):
        return [normalize_ddb(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {
            str(key): normalize_ddb(item, depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (str, bytes, bool, type(None), int)):
        return value
    raise ContractError("ddb_value_invalid")


def deserialize_image(value: Any) -> dict[str, Any]:
    if not is_record(value) or len(value) > 64:
        raise ContractError("stream_image_invalid")
    deserializer = TypeDeserializer()
    try:
        return normalize_ddb({
            str(key): deserializer.deserialize(item)
            for key, item in value.items()
        })
    except ContractError:
        raise
    except Exception as error:
        raise ContractError("stream_image_invalid") from error


def parse_job_record(
    stream_record: Any, *, operations: frozenset[str],
) -> RuntimeJob | None:
    if not is_record(stream_record):
        raise ContractError("stream_record_invalid")
    event_id = stream_record.get("eventID")
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 256:
        raise ContractError("stream_record_invalid")
    if stream_record.get("eventSource") not in {None, "aws:dynamodb"}:
        raise ContractError("stream_source_invalid")
    if stream_record.get("eventName") not in {"INSERT", "MODIFY"}:
        return None
    dynamodb = stream_record.get("dynamodb")
    if not is_record(dynamodb) or not is_record(dynamodb.get("NewImage")):
        raise ContractError("stream_record_invalid")
    image = deserialize_image(dynamodb["NewImage"])
    if image.get("state") != "QUEUED":
        return None
    if image.get("schema") != SCHEMA_JOB or image.get("profileId") != PROFILE:
        return None
    if image.get("operation") not in operations:
        return None
    if set(image) != _JOB_KEYS:
        raise ContractError("job_top_level_contract_invalid")

    session_id = image.get("sessionId")
    job_id = image.get("jobId")
    partition = (
        "MUTATION#" + str(session_id)
        if image["operation"] in MUTATION_OPERATIONS
        else "SESSION#" + str(session_id)
    )
    if (
        SESSION_RE.fullmatch(str(session_id)) is None
        or JOB_RE.fullmatch(str(job_id)) is None
        or image.get("pk") != partition
        or image.get("sk") != "JOB#" + str(job_id)
        or AUDIT_RE.fullmatch(str(image.get("auditId"))) is None
        or DIGEST_RE.fullmatch(str(image.get("runtimeEvidenceDigest"))) is None
        or GENERATION_RE.fullmatch(str(image.get("generation"))) is None
        or DIGEST_RE.fullmatch(str(image.get("capabilityDigest"))) is None
        or not is_record(image.get("request"))
        or len(canonical_json(image["request"])) > 96 * 1024
        or not isinstance(image.get("submittedAt"), str)
        or not isinstance(image.get("expiresAt"), int)
        or isinstance(image.get("expiresAt"), bool)
    ):
        raise ContractError("job_identity_invalid")
    parse_instant(image["submittedAt"])
    return RuntimeJob(
        event_id=event_id, pk=image["pk"], sk=image["sk"], job_id=job_id,
        audit_id=image["auditId"],
        runtime_evidence_digest=image["runtimeEvidenceDigest"],
        session_id=session_id, generation=image["generation"],
        capability_digest=image["capabilityDigest"],
        operation=image["operation"], request=dict(image["request"]),
        submitted_at=image["submittedAt"], expires_at=image["expiresAt"],
    )


def validate_session_payload(
    value: Any,
    job: RuntimeJob,
    now: dt.datetime,
) -> dict[str, Any]:
    expected = {
        "schemaVersion", "sessionId", "requestedProfile", "binding", "state",
        "createdAt", "updatedAt", "lastActivityAt", "idleExpiresAt",
        "hardExpiresAt", "revision", "endReason", "failureCode",
    }
    if (
        not exact_keys(value, expected)
        or value.get("schemaVersion") != "archon.runtime-session/v1"
        or value.get("sessionId") != job.session_id
        or value.get("requestedProfile") not in {"auto", "cloud"}
        or value.get("state") != "ACTIVE"
        or type(value.get("revision")) is not int
        or value["revision"] < 1
        or value.get("endReason") is not None
        or value.get("failureCode") is not None
    ):
        raise ContractError("runtime_session_inactive")
    binding = validate_binding(value["binding"])
    created = parse_instant(value["createdAt"])
    updated = parse_instant(value["updatedAt"])
    activity = parse_instant(value["lastActivityAt"])
    idle = parse_instant(value["idleExpiresAt"])
    hard = parse_instant(value["hardExpiresAt"])
    if (
        binding["generation"] != job.generation
        or binding["capabilityDigest"] != job.capability_digest
        or not created <= activity <= updated <= now
        or not updated < idle <= hard
        or idle <= now
        or hard <= now
        or parse_instant(binding["leaseExpiresAt"]) <= now
        or value["hardExpiresAt"] != binding["leaseExpiresAt"]
    ):
        raise ContractError("runtime_session_binding_mismatch")
    return {**value, "binding": binding}


def validate_cloud_lease(value: Any, job: RuntimeJob, now: dt.datetime) -> dict[str, Any]:
    expected = {
        "schemaVersion", "profileId", "state", "sessionId", "generation",
        "capabilityDigest", "leaseExpiresAt", "revision",
    }
    if (
        not exact_keys(value, expected)
        or value.get("schemaVersion") != "archon.cloud-runtime-lease/v1"
        or value.get("profileId") != PROFILE
        or value.get("state") != "ACTIVE"
        or value.get("sessionId") != job.session_id
        or value.get("generation") != job.generation
        or value.get("capabilityDigest") != job.capability_digest
        or type(value.get("revision")) is not int
        or value["revision"] < 1
        or parse_instant(value.get("leaseExpiresAt")) <= now
    ):
        raise ContractError("cloud_runtime_lease_mismatch")
    return dict(value)


def validate_registry(value: Any, job: RuntimeJob, now: dt.datetime) -> dict[str, Any]:
    expected = {
        "pk", "sk", "status", "generation", "capabilityDigest",
        "capabilities", "checkedAt",
    }
    if (
        not exact_keys(value, expected)
        or value.get("pk") != "RUNTIME#cloud"
        or value.get("sk") != "HEALTH"
        or value.get("status") != "READY"
        or value.get("generation") != job.generation
        or value.get("capabilityDigest") != job.capability_digest
    ):
        raise ContractError("cloud_runtime_registry_mismatch")
    checked = parse_instant(value.get("checkedAt"))
    if checked > now or now - checked > dt.timedelta(minutes=2):
        raise ContractError("cloud_runtime_registry_stale")
    capabilities = value["capabilities"]
    if (
        any(capabilities.get(key) is not True for key in CAPABILITY_KEYS)
        or capability_digest(job.generation, capabilities) != job.capability_digest
    ):
        raise ContractError("cloud_runtime_registry_incomplete")
    return dict(value)


def validate_mutation_canonical_value(value: Any, depth: int = 0) -> None:
    if depth > 12:
        raise ContractError("mutation_authorization_too_deep")
    if value is None or type(value) is bool:
        return
    if isinstance(value, str):
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ContractError("mutation_authorization_non_ascii")
        return
    if type(value) is int:
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise ContractError("mutation_authorization_number_invalid")
        return
    if isinstance(value, list):
        for item in value:
            validate_mutation_canonical_value(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if (
                not isinstance(key, str) or not key
                or any(ord(character) < 0x20 or ord(character) > 0x7E for character in key)
            ):
                raise ContractError("mutation_authorization_key_invalid")
            validate_mutation_canonical_value(item, depth + 1)
        return
    raise ContractError("mutation_authorization_non_json")


def canonical_mutation_json(value: Any) -> bytes:
    validate_mutation_canonical_value(value)
    return canonical_json(value)


def strict_base64(value: Any, *, minimum: int = 8, maximum: int = 256) -> bytes:
    if (
        not isinstance(value, str) or not 8 <= len(value) <= 512
        or len(value) % 4
        or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value) is None
    ):
        raise ContractError("signature_malformed")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ContractError("signature_malformed") from error
    if not minimum <= len(decoded) <= maximum:
        raise ContractError("signature_malformed")
    return decoded


def safe_error(error: BaseException) -> dict[str, Any]:
    if isinstance(error, ContractError):
        code = str(error) if re.fullmatch(r"[a-z0-9_]{1,64}", str(error)) else "contract_rejected"
    elif isinstance(error, TimeoutError):
        code = "operation_timeout"
    else:
        code = "runtime_unavailable"
    payload = {
        "schemaVersion": "archon.runtime-job-error/v1",
        "code": code,
        "retryable": isinstance(error, RetryableFailure),
        "providerPayloadStored": False,
        "detailsStored": False,
    }
    return {**payload, "digest": digest(payload)}


def job_receipt(
    job: RuntimeJob, *, state: Literal["SUCCEEDED", "FAILED"],
    started_at: str, completed_at: str,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    execution_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (state == "SUCCEEDED") != (result is not None) or (state == "FAILED") != (error is not None):
        raise ContractError("receipt_terminal_state_invalid")
    payload: dict[str, Any] = {
        "schema": SCHEMA_RECEIPT, "profileId": PROFILE,
        "jobId": job.job_id, "auditId": job.audit_id,
        "runtimeEvidenceDigest": job.runtime_evidence_digest,
        "sessionId": job.session_id, "generation": job.generation,
        "capabilityDigest": job.capability_digest,
        "operation": job.operation, "state": state,
        "request": job.request, "requestDigest": digest(job.request),
        "startedAt": started_at, "completedAt": completed_at,
        "providerPayloadStored": False,
    }
    if execution_evidence is not None:
        if (
            not verify_digest_object(execution_evidence)
            or len(canonical_json(execution_evidence)) > 32 * 1024
        ):
            raise ContractError("execution_evidence_invalid")
        payload["executionEvidence"] = execution_evidence
    if result is not None:
        payload["result"] = result
    if error is not None:
        payload["error"] = error
    if len(canonical_json(payload)) > 350 * 1024:
        raise ContractError("receipt_payload_too_large")
    return {**payload, "receiptDigest": digest(payload)}


def checkpoint_contains_credentials(parts: list[bytes], forbidden: list[bytes]) -> bool:
    for part in parts:
        if len(part) > 16 * 1024 * 1024 or CREDENTIAL_RE.search(part):
            return True
        for secret in forbidden:
            if secret and secret in part:
                return True
    return False
