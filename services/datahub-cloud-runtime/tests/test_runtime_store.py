from __future__ import annotations

import base64
from io import BytesIO
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

import contracts
import runtime_store


class Body:
    def __init__(self, value):
        self.value = value
        self.closed = False

    def read(self, maximum):
        assert maximum == runtime_store.MAX_CHECKPOINT_BYTES + 1
        return self.value

    def close(self):
        self.closed = True


def test_retryable_claim_release_uses_exact_identity_cas(runtime_job):
    calls = []

    class Jobs:
        def update_item(self, **kwargs):
            calls.append(kwargs)
            return {}

    store = object.__new__(runtime_store.RuntimeStore)
    store.jobs = Jobs()
    store.release(runtime_job, "execution-1")
    call = calls[0]
    assert call["Key"] == {"pk": runtime_job.pk, "sk": runtime_job.sk}
    assert "executionId=:execution" in call["ConditionExpression"]
    assert "requestDigest=:request" in call["ConditionExpression"]
    assert call["ExpressionAttributeValues"][":request"] == contracts.digest(
        runtime_job.request
    )
    assert "REMOVE startedAt, executionId, executionLeaseExpiresAt" in (
        call["UpdateExpression"]
    )


def test_claim_returns_none_only_for_exact_terminal_job(runtime_job, monkeypatch):
    class Jobs:
        def update_item(self, **_kwargs):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "conditional",
                    }
                },
                "UpdateItem",
            )

        def get_item(self, **_kwargs):
            return {
                "Item": {
                    "schema": contracts.SCHEMA_JOB,
                    "profileId": "cloud",
                    "jobId": runtime_job.job_id,
                    "auditId": runtime_job.audit_id,
                    "runtimeEvidenceDigest": runtime_job.runtime_evidence_digest,
                    "sessionId": runtime_job.session_id,
                    "generation": runtime_job.generation,
                    "capabilityDigest": runtime_job.capability_digest,
                    "operation": runtime_job.operation,
                    "request": runtime_job.request,
                    "state": "SUCCEEDED",
                }
            }

    store = object.__new__(runtime_store.RuntimeStore)
    store.jobs = Jobs()
    assert store.claim(runtime_job, "execution-1") is None


def test_checkpoint_is_versioned_kms_encrypted_checksummed_and_cas(
    runtime_job, monkeypatch, tmp_path
):
    state = b"SQLite format 3\x00" + b"x" * 128
    checksum = base64.b64encode(
        bytes.fromhex(contracts.digest_bytes(state).removeprefix("sha256:"))
    ).decode("ascii")
    s3_calls = []
    table_calls = []

    class S3:
        def put_object(self, **kwargs):
            s3_calls.append(("put", kwargs))
            return {
                "VersionId": "version-1",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KEY_ARN,
                "ChecksumSHA256": checksum,
            }

        def get_object(self, **kwargs):
            s3_calls.append(("get", kwargs))
            return {
                "Body": Body(state),
                "VersionId": "version-1",
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": KEY_ARN,
                "ChecksumSHA256": checksum,
            }

        def delete_object(self, **kwargs):
            s3_calls.append(("delete", kwargs))

    class Table:
        marker = None

        def put_item(self, **kwargs):
            table_calls.append(kwargs)
            self.marker = kwargs["Item"]

        def get_item(self, **kwargs):
            return {"Item": self.marker}

    monkeypatch.setenv("CLOUD_CHECKPOINT_BUCKET", "archon-cloud-checkpoints")
    monkeypatch.setenv("CLOUD_CHECKPOINT_KMS_KEY_ARN", KEY_ARN)
    monkeypatch.setattr(runtime_store.boto3, "client", lambda name: S3())
    table = Table()
    checkpoint = runtime_store.CheckpointStore(table)
    receipt = checkpoint.save(
        runtime_job,
        state,
        expected_revision=0,
        oauth_key_digest="sha256:" + "1" * 64,
        run_handle_key_digest="sha256:" + "2" * 64,
    )
    put = s3_calls[0][1]
    assert put["ServerSideEncryption"] == "aws:kms"
    assert put["SSEKMSKeyId"] == KEY_ARN
    assert put["ChecksumAlgorithm"] == "SHA256"
    assert put["ChecksumSHA256"] == checksum
    assert table_calls[0]["ConditionExpression"] == (
        "attribute_not_exists(pk) AND attribute_not_exists(sk)"
    )
    assert receipt["encryptedAtRest"] is True
    destination = tmp_path / "state.sqlite"
    revision = checkpoint.restore(
        runtime_job,
        destination,
        oauth_key_digest="sha256:" + "1" * 64,
        run_handle_key_digest="sha256:" + "2" * 64,
    )
    assert revision == 1
    assert destination.read_bytes() == state
    assert s3_calls[-1][1]["VersionId"] == "version-1"
    destination.unlink()


def test_mutation_ledger_never_reauthorizes_existing_phase(runtime_job):
    class Jobs:
        def update_item(self, **_kwargs):
            raise ClientError(
                {
                    "Error": {
                        "Code": "ConditionalCheckFailedException",
                        "Message": "conditional",
                    }
                },
                "UpdateItem",
            )

        def get_item(self, **_kwargs):
            return {
                "Item": {
                    "mutationPhase": "AUTHORIZED",
                    "mutationEnvelopeDigest": "sha256:" + "1" * 64,
                    "mutationConsumedAt": "2026-08-02T12:00:00.000Z",
                }
            }

    store = object.__new__(runtime_store.RuntimeStore)
    store.jobs = Jobs()
    ledger = store.begin_mutation_once(
        runtime_job,
        "execution-1",
        envelope_digest="sha256:" + "1" * 64,
        consumed_at="2026-08-02T12:00:00.000Z",
    )
    assert ledger["phase"] == "AUTHORIZED"
    assert ledger["replayed"] is True


KEY_ARN = (
    "arn:aws:kms:eu-west-1:123456789012:"
    "key/00000000-0000-4000-8000-000000000001"
)
