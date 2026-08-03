from __future__ import annotations

import asyncio
import dataclasses

import pytest

import contracts
import handlers


STREAM_ARN = (
    "arn:aws:dynamodb:eu-west-1:123456789012:"
    "table/archon-jobs/stream/2026-08-02T00:00:00.000"
)


def test_stream_source_is_exact_and_dedicated(monkeypatch):
    monkeypatch.setenv("RUNTIME_JOB_STREAM_ARN", STREAM_ARN)
    event = {
        "Records": [
            {
                "eventID": "evt-1",
                "eventSource": "aws:dynamodb",
                "eventSourceARN": STREAM_ARN,
            }
        ]
    }
    assert handlers._valid_records(event) == event["Records"]
    event["Records"][0]["eventSourceARN"] = STREAM_ARN + "-other"
    with pytest.raises(contracts.ContractError, match="stream_event_invalid"):
        handlers._valid_records(event)


class FakeStore:
    instances = []
    context_error = None

    def __init__(self):
        self.released = []
        self.receipts = []
        FakeStore.instances.append(self)

    def validate_runtime_context(self, _job):
        if self.context_error is not None:
            raise self.context_error
        return {"session": {}, "lease": {}, "registry": {}}

    def claim(self, _job, _execution):
        return "2026-08-02T12:00:01.000Z"

    def release(self, job, execution):
        self.released.append((job.job_id, execution))

    def terminal(self, _job, _execution, receipt):
        self.receipts.append(receipt)


def _event():
    return {
        "Records": [
            {
                "eventID": "evt-1",
                "eventSource": "aws:dynamodb",
                "eventSourceARN": STREAM_ARN,
            }
        ]
    }


def test_retryable_execution_is_partial_batch_failure_and_releases_claim(
    runtime_job, lambda_context, monkeypatch
):
    FakeStore.instances.clear()
    FakeStore.context_error = None
    monkeypatch.setenv("RUNTIME_JOB_STREAM_ARN", STREAM_ARN)
    monkeypatch.setattr(handlers, "RuntimeStore", FakeStore)
    monkeypatch.setattr(
        handlers,
        "parse_job_record",
        lambda record, operations: runtime_job,
    )
    monkeypatch.setattr(handlers, "_load_secret", lambda purpose: object())

    def retry(*_args):
        raise contracts.RetryableFailure("temporary")

    result = handlers._process(
        _event(),
        lambda_context,
        operations=contracts.READ_OPERATIONS,
        purpose="reader",
        executor=retry,
    )
    store = FakeStore.instances[-1]
    assert result == {"batchItemFailures": [{"itemIdentifier": "evt-1"}]}
    assert store.released == [(runtime_job.job_id, lambda_context.aws_request_id)]
    assert store.receipts == []


def test_contract_failure_is_sanitized_terminal_receipt_without_secret(
    runtime_job, lambda_context, monkeypatch
):
    FakeStore.instances.clear()
    FakeStore.context_error = contracts.ContractError(
        "runtime_session_binding_mismatch"
    )
    monkeypatch.setenv("RUNTIME_JOB_STREAM_ARN", STREAM_ARN)
    monkeypatch.setattr(handlers, "RuntimeStore", FakeStore)
    monkeypatch.setattr(
        handlers,
        "parse_job_record",
        lambda record, operations: runtime_job,
    )
    monkeypatch.setattr(
        handlers,
        "_load_secret",
        lambda purpose: (_ for _ in ()).throw(AssertionError("secret loaded")),
    )
    result = handlers._process(
        _event(),
        lambda_context,
        operations=contracts.READ_OPERATIONS,
        purpose="reader",
        executor=lambda *_args: ({}, None),
    )
    receipt = FakeStore.instances[-1].receipts[0]
    assert result == {"batchItemFailures": []}
    assert receipt["state"] == "FAILED"
    assert receipt["error"]["code"] == "runtime_session_binding_mismatch"
    assert receipt["request"] == runtime_job.request


def test_success_receipt_preserves_request_and_execution_evidence(
    runtime_job, lambda_context, monkeypatch
):
    FakeStore.instances.clear()
    FakeStore.context_error = None
    monkeypatch.setenv("RUNTIME_JOB_STREAM_ARN", STREAM_ARN)
    monkeypatch.setattr(handlers, "RuntimeStore", FakeStore)
    monkeypatch.setattr(
        handlers,
        "parse_job_record",
        lambda record, operations: runtime_job,
    )
    monkeypatch.setattr(handlers, "_load_secret", lambda purpose: object())
    evidence = {
        "schemaVersion": "archon.test-evidence/v1",
        "providerPayloadStored": False,
    }
    evidence["digest"] = contracts.digest(evidence)
    result = handlers._process(
        _event(),
        lambda_context,
        operations=contracts.READ_OPERATIONS,
        purpose="reader",
        executor=lambda *_args: (
            {"schemaVersion": "archon.test-result/v1", "ok": True},
            evidence,
        ),
    )
    receipt = FakeStore.instances[-1].receipts[0]
    assert result == {"batchItemFailures": []}
    assert receipt["state"] == "SUCCEEDED"
    assert receipt["request"] == runtime_job.request
    assert receipt["executionEvidence"] == evidence


def test_post_read_wrapper_is_exact_and_requires_expected_pii(
    runtime_job, monkeypatch
):
    expected_state = {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrns": [contracts.PII_TAG],
    }
    expected = {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **expected_state,
        "stateDigest": contracts.digest(expected_state),
    }
    request = {
        "schemaVersion": "archon.core-post-mutation-tag-read/v1",
        "originalRequest": runtime_job.request,
        "sourceMutationAuditId": runtime_job.audit_id,
        "sourceMutationReceiptDigest": "sha256:" + "9" * 64,
        "postMutationExpectedTagState": expected,
    }
    job = dataclasses.replace(
        runtime_job, operation="POST_READ_TAGS", request=request
    )

    async def read(_credential):
        proof = {
            "schemaVersion": "archon.test-proof/v1",
            "providerPayloadStored": False,
        }
        proof["digest"] = contracts.digest(proof)
        return {**expected, "_proof": proof}

    monkeypatch.setattr(handlers, "read_column_tags", read)
    result, proof = handlers._read_executor(
        job, object(), object(), "execution", {}
    )
    assert result == {
        "schemaVersion": "archon.core-post-mutation-tag-read-result/v1",
        "sourceMutationAuditId": runtime_job.audit_id,
        "sourceMutationReceiptDigest": "sha256:" + "9" * 64,
        "postMutationExpectedTagState": expected,
        "postMutationResult": expected,
        "postMutationResultDigest": contracts.digest(expected),
    }
    assert proof["providerPayloadStored"] is False
