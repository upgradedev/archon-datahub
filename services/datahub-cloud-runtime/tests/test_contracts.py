from __future__ import annotations

import datetime as dt
from decimal import Decimal

import pytest
from boto3.dynamodb.types import TypeSerializer

import contracts


def _stream(job: contracts.RuntimeJob, *, schema: str = contracts.SCHEMA_JOB, profile: str = "cloud"):
    image = {
        "pk": job.pk,
        "sk": job.sk,
        "schema": schema,
        "profileId": profile,
        "jobId": job.job_id,
        "auditId": job.audit_id,
        "runtimeEvidenceDigest": job.runtime_evidence_digest,
        "sessionId": job.session_id,
        "generation": job.generation,
        "capabilityDigest": job.capability_digest,
        "state": "QUEUED",
        "operation": job.operation,
        "request": job.request,
        "submittedAt": job.submitted_at,
        "expiresAt": job.expires_at,
    }
    serializer = TypeSerializer()
    return {
        "eventID": job.event_id,
        "eventName": "INSERT",
        "eventSource": "aws:dynamodb",
        "eventSourceARN": (
            "arn:aws:dynamodb:eu-west-1:123456789012:"
            "table/archon-jobs/stream/2026-08-02T00:00:00.000"
        ),
        "dynamodb": {
            "NewImage": {
                key: serializer.serialize(value)
                for key, value in image.items()
            }
        },
    }


def test_job_v2_is_exact_and_legacy_or_core_is_ignored(runtime_job):
    parsed = contracts.parse_job_record(
        _stream(runtime_job), operations=contracts.READ_OPERATIONS
    )
    assert parsed == runtime_job
    assert contracts.parse_job_record(
        _stream(runtime_job, schema="archon.runtime-bound-job/v1"),
        operations=contracts.READ_OPERATIONS,
    ) is None
    assert contracts.parse_job_record(
        _stream(runtime_job, profile="core"),
        operations=contracts.READ_OPERATIONS,
    ) is None


def test_job_rejects_extra_fields_and_wrong_partition(runtime_job):
    record = _stream(runtime_job)
    serializer = TypeSerializer()
    record["dynamodb"]["NewImage"]["unexpected"] = serializer.serialize(True)
    with pytest.raises(contracts.ContractError, match="job_top_level_contract_invalid"):
        contracts.parse_job_record(record, operations=contracts.READ_OPERATIONS)

    record = _stream(runtime_job)
    record["dynamodb"]["NewImage"]["pk"] = serializer.serialize("SESSION#wrong")
    with pytest.raises(contracts.ContractError, match="job_identity_invalid"):
        contracts.parse_job_record(record, operations=contracts.READ_OPERATIONS)


def test_ddb_decimal_normalization_is_bounded_and_lossless():
    assert contracts.normalize_ddb(
        {"count": Decimal("7"), "items": [Decimal("-2"), True]}
    ) == {"count": 7, "items": [-2, True]}
    for invalid in (Decimal("1.5"), Decimal("NaN"), {1, 2}):
        with pytest.raises(contracts.ContractError):
            contracts.normalize_ddb(invalid)


def test_runtime_binding_checks_exact_capability_digest(runtime_job):
    now = dt.datetime(2026, 8, 2, 12, 1, tzinfo=dt.UTC)
    capabilities = {key: True for key in contracts.CAPABILITY_KEYS}
    capability = contracts.capability_digest(runtime_job.generation, capabilities)
    job = contracts.dataclasses.replace(
        runtime_job, capability_digest=capability
    )
    lease_expires = "2026-08-02T13:00:00.000Z"
    binding = {
        "schemaVersion": contracts.SCHEMA_BINDING,
        "profileId": "cloud",
        "generation": job.generation,
        "capabilityDigest": capability,
        "resolution": "auto",
        "boundAt": "2026-08-02T12:00:00.000Z",
        "leaseExpiresAt": lease_expires,
    }
    session = {
        "schemaVersion": "archon.runtime-session/v1",
        "sessionId": job.session_id,
        "requestedProfile": "auto",
        "binding": binding,
        "state": "ACTIVE",
        "createdAt": "2026-08-02T12:00:00.000Z",
        "updatedAt": "2026-08-02T12:00:30.000Z",
        "lastActivityAt": "2026-08-02T12:00:20.000Z",
        "idleExpiresAt": "2026-08-02T12:30:00.000Z",
        "hardExpiresAt": lease_expires,
        "revision": 1,
        "endReason": None,
        "failureCode": None,
    }
    assert contracts.validate_session_payload(session, job, now)["binding"] == binding
    lease = {
        "schemaVersion": "archon.cloud-runtime-lease/v1",
        "profileId": "cloud",
        "state": "ACTIVE",
        "sessionId": job.session_id,
        "generation": job.generation,
        "capabilityDigest": capability,
        "leaseExpiresAt": lease_expires,
        "revision": 1,
    }
    assert contracts.validate_cloud_lease(lease, job, now) == lease
    registry = {
        "pk": "RUNTIME#cloud",
        "sk": "HEALTH",
        "status": "READY",
        "generation": job.generation,
        "capabilityDigest": capability,
        "capabilities": capabilities,
        "checkedAt": "2026-08-02T12:00:30.000Z",
    }
    assert contracts.validate_registry(registry, job, now) == registry
    registry["checkedAt"] = "2026-08-02T11:58:00.000Z"
    with pytest.raises(contracts.ContractError, match="cloud_runtime_registry_stale"):
        contracts.validate_registry(registry, job, now)


def test_v2_receipt_preserves_exact_request_and_self_digest(runtime_job):
    result = {"schemaVersion": "example/v1", "ok": True}
    receipt = contracts.job_receipt(
        runtime_job,
        state="SUCCEEDED",
        started_at="2026-08-02T12:00:01.000Z",
        completed_at="2026-08-02T12:00:02.000Z",
        result=result,
    )
    assert receipt["schema"] == contracts.SCHEMA_RECEIPT
    assert receipt["profileId"] == "cloud"
    assert receipt["request"] == runtime_job.request
    assert receipt["requestDigest"] == contracts.digest(runtime_job.request)
    assert receipt["receiptDigest"] == contracts.digest(
        contracts.without(receipt, "receiptDigest")
    )
    assert receipt["providerPayloadStored"] is False


def test_safe_error_never_contains_exception_message():
    secret = "Bearer super-secret-provider-token"
    payload = contracts.safe_error(RuntimeError(secret))
    encoded = contracts.canonical_json(payload)
    assert secret.encode() not in encoded
    assert payload["code"] == "runtime_unavailable"
    assert payload["providerPayloadStored"] is False
    assert payload["detailsStored"] is False


def test_checkpoint_credential_scan_detects_all_secret_classes():
    synthetic_aws_key = b"ASIA" + b"ABCDEFGHIJKLMNOP"
    assert contracts.checkpoint_contains_credentials(
        [b"safe", synthetic_aws_key],
        [],
    )
    assert contracts.checkpoint_contains_credentials(
        [b"opaque-token-value"],
        [b"opaque-token-value"],
    )
    assert not contracts.checkpoint_contains_credentials([b"ordinary state"], [])


def test_non_json_binary_payload_is_a_sanitized_contract_rejection():
    with pytest.raises(contracts.ContractError, match="canonical_json_invalid"):
        contracts.canonical_json({"binary": b"not-json"})
