from __future__ import annotations

import asyncio
import json

import pytest
from boto3.dynamodb.types import TypeSerializer

import contracts
import fixture_reset
import handlers


SESSION_STREAM = (
    "arn:aws:dynamodb:eu-west-1:123456789012:"
    "table/archon-sessions/stream/2026-08-02T00:00:00.000"
)


def _typed(value):
    serializer = TypeSerializer()
    return {key: serializer.serialize(item) for key, item in value.items()}


def _session_record(runtime_job, *, old_state="ACTIVE", new_state="EXPIRED"):
    def image(state, revision):
        payload = {
            "schemaVersion": "archon.runtime-session/v1",
            "sessionId": runtime_job.session_id,
            "state": state,
            "revision": revision,
        }
        return {
            "pk": "SESSION#" + runtime_job.session_id,
            "sk": "RUNTIME",
            "payload": json.dumps(payload, separators=(",", ":")),
            "revision": revision,
        }

    return {
        "eventID": "evt-reset",
        "eventName": "MODIFY",
        "eventSource": "aws:dynamodb",
        "eventSourceARN": SESSION_STREAM,
        "dynamodb": {
            "OldImage": _typed(image(old_state, 1)),
            "NewImage": _typed(image(new_state, 2)),
        },
    }


def _state(tags):
    values = {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrns": sorted(tags),
    }
    return {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **values,
        "stateDigest": contracts.digest(values),
        "_proof": {"digest": "sha256:" + "1" * 64},
    }


def test_reset_transition_accepts_only_configured_expired_or_draining(
    runtime_job
):
    record = _session_record(runtime_job)
    transition = fixture_reset._transition(record, frozenset({SESSION_STREAM}))
    assert transition["triggerState"] == "EXPIRED"
    assert transition["sessionId"] == runtime_job.session_id
    assert transition["digest"] == contracts.digest(
        contracts.without(transition, "digest")
    )
    assert fixture_reset._transition(
        record, frozenset({SESSION_STREAM + "-wrong"})
    ) is None
    assert fixture_reset._transition(
        _session_record(runtime_job, old_state="EXPIRED"),
        frozenset({SESSION_STREAM}),
    ) is None


def test_fixture_reset_uses_remove_tags_only_and_emits_non_human_receipt(
    runtime_job, lambda_context, monkeypatch
):
    receipts = []

    class Table:
        def put_item(self, **_kwargs):
            return {}

        def update_item(self, **kwargs):
            receipts.append(kwargs["ExpressionAttributeValues"][":receipt"])
            return {}

    monkeypatch.setattr(fixture_reset, "_ledger_table", lambda: Table())
    monkeypatch.setattr(handlers, "_load_secret", lambda purpose: object())
    observations = iter([
        _state([contracts.PII_TAG]),
        _state([]),
    ])

    async def read(_credential):
        return next(observations)

    calls = []

    async def mutate(_credential, *, tool):
        calls.append(tool)
        return {
            "argumentsDigest": "sha256:" + "2" * 64,
            "responseDigest": "sha256:" + "3" * 64,
        }

    monkeypatch.setattr(fixture_reset, "read_column_tags", read)
    monkeypatch.setattr(fixture_reset, "mutate_tags", mutate)
    transition = fixture_reset._transition(
        _session_record(runtime_job), frozenset({SESSION_STREAM})
    )
    fixture_reset._reset_one(transition, lambda_context.aws_request_id)
    assert calls == ["remove_tags"]
    receipt = receipts[0]
    assert receipt["verified"] is True
    assert receipt["humanApprovalUsed"] is False
    assert receipt["authority"] == "system-lifecycle-only"
    assert receipt["target"] == {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrn": contracts.PII_TAG,
    }
    assert receipt["officialMcpMutation"]["tool"] == "remove_tags"


def test_baseline_reset_is_idempotent_when_pii_is_already_absent(
    runtime_job, lambda_context, monkeypatch
):
    class Table:
        def put_item(self, **_kwargs):
            return {}

        def update_item(self, **_kwargs):
            return {}

    monkeypatch.setattr(fixture_reset, "_ledger_table", lambda: Table())
    monkeypatch.setattr(handlers, "_load_secret", lambda purpose: object())

    async def read(_credential):
        return _state([])

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("remove_tags called for clean baseline")

    monkeypatch.setattr(fixture_reset, "read_column_tags", read)
    monkeypatch.setattr(fixture_reset, "mutate_tags", forbidden)
    transition = fixture_reset._transition(
        _session_record(runtime_job), frozenset({SESSION_STREAM})
    )
    fixture_reset._reset_one(transition, lambda_context.aws_request_id)


def test_handler_returns_partial_batch_failure_only_for_retryable(
    runtime_job, lambda_context, monkeypatch
):
    monkeypatch.setenv(
        "FIXTURE_RESET_SOURCE_STREAM_ARNS", json.dumps([SESSION_STREAM])
    )
    monkeypatch.setattr(
        fixture_reset,
        "_reset_one",
        lambda *_args: (_ for _ in ()).throw(
            contracts.RetryableFailure("temporary")
        ),
    )
    result = fixture_reset.handle_fixture_reset(
        {"Records": [_session_record(runtime_job)]},
        lambda_context,
    )
    assert result == {
        "batchItemFailures": [{"itemIdentifier": "evt-reset"}]
    }


def test_fixture_baseline_requires_exact_self_digest():
    state = _state([])
    state["stateDigest"] = "sha256:" + "0" * 64
    with pytest.raises(
        contracts.ContractError, match="fixture_reset_baseline_invalid"
    ):
        fixture_reset._clean_state(state)
