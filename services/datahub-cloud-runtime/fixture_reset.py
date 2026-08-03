"""System-lifecycle-only canonical DataHub fixture reset."""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from contracts import (
    COLUMN_PATH,
    ContractError,
    DATASET_URN,
    DIGEST_RE,
    PII_TAG,
    RetryableFailure,
    SESSION_RE,
    TAG_RE,
    deserialize_image,
    digest,
    exact_keys,
    instant,
    normalize_ddb,
)
from managed_mcp import mutate_tags, read_column_tags
from runtime_store import required_env

STREAM_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):dynamodb:[a-z0-9-]+:"
    r"\d{12}:table/[A-Za-z0-9_.-]{3,255}/stream/.{10,64}$"
)
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
RETENTION_SECONDS = 90 * 24 * 60 * 60


def _source_arns() -> frozenset[str]:
    raw = required_env("FIXTURE_RESET_SOURCE_STREAM_ARNS", maximum=4096)
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractError("fixture_reset_sources_invalid") from error
    if (
        not isinstance(values, list)
        or not 1 <= len(values) <= 2
        or len(set(values)) != len(values)
        or any(
            not isinstance(value, str)
            or STREAM_ARN_RE.fullmatch(value) is None
            for value in values
        )
    ):
        raise ContractError("fixture_reset_sources_invalid")
    return frozenset(values)


def _session_state(image: dict[str, Any]) -> tuple[str, str, int] | None:
    pk = image.get("pk")
    if (
        not isinstance(pk, str)
        or not pk.startswith("SESSION#")
        or image.get("sk") != "RUNTIME"
        or not isinstance(image.get("payload"), str)
        or len(image["payload"].encode("utf-8")) > 32 * 1024
    ):
        return None
    try:
        payload = json.loads(image["payload"])
    except json.JSONDecodeError as error:
        raise ContractError("fixture_reset_session_invalid") from error
    session_id = pk.removeprefix("SESSION#")
    if (
        SESSION_RE.fullmatch(session_id) is None
        or not isinstance(payload, dict)
        or payload.get("schemaVersion") != "archon.runtime-session/v1"
        or payload.get("sessionId") != session_id
        or payload.get("state") != "EXPIRED"
        or type(payload.get("revision")) is not int
        or payload["revision"] < 1
        or image.get("revision") != payload["revision"]
    ):
        return None
    return session_id, "EXPIRED", payload["revision"]


def _draining_state(image: dict[str, Any]) -> tuple[str, str, int] | None:
    session_id = image.get("sessionId")
    if (
        image.get("pk") != "CORE#LEASE"
        or image.get("sk") != "CURRENT"
        or image.get("state") != "DRAINING"
        or SESSION_RE.fullmatch(str(session_id)) is None
        or type(image.get("revision")) is not int
        or image["revision"] < 2
        or not isinstance(image.get("generation"), str)
        or DIGEST_RE.fullmatch(str(image.get("capabilityDigest"))) is None
        or not isinstance(image.get("operationId"), str)
        or re.fullmatch(r"[a-f0-9]{32}", image["operationId"]) is None
    ):
        return None
    return session_id, "DRAINING", image["revision"]


def _transition(record: dict[str, Any], source_arns: frozenset[str]) -> dict[str, Any] | None:
    if (
        record.get("eventName") != "MODIFY"
        or record.get("eventSource") not in {None, "aws:dynamodb"}
        or record.get("eventSourceARN") not in source_arns
        or not isinstance(record.get("dynamodb"), dict)
        or not isinstance(record["dynamodb"].get("NewImage"), dict)
        or not isinstance(record["dynamodb"].get("OldImage"), dict)
    ):
        return None
    new = deserialize_image(record["dynamodb"]["NewImage"])
    old = deserialize_image(record["dynamodb"]["OldImage"])
    state = _session_state(new) or _draining_state(new)
    if state is None:
        return None
    session_id, trigger_state, revision = state
    if (
        (trigger_state == "EXPIRED" and (_session_state(old) is not None))
        or (
            trigger_state == "DRAINING"
            and old.get("state") == "DRAINING"
        )
    ):
        return None
    payload = {
        "schemaVersion": "archon.fixture-reset-transition/v1",
        "sessionId": session_id,
        "triggerState": trigger_state,
        "revision": revision,
        "sourceStreamDigest": digest({
            "schemaVersion": "archon.fixture-reset-source/v1",
            "sourceArn": record["eventSourceARN"],
        }),
    }
    return {**payload, "digest": digest(payload)}


def _clean_state(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("_proof", None)
    tags = result.get("tagUrns")
    state = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": tags,
    }
    if (
        not exact_keys(
            result,
            {"schemaVersion", "entityUrn", "columnPath", "tagUrns", "stateDigest"},
        )
        or result.get("schemaVersion") != "archon.core-tag-read-result/v1"
        or result.get("entityUrn") != DATASET_URN
        or result.get("columnPath") != COLUMN_PATH
        or not isinstance(tags, list)
        or len(tags) > 256
        or tags != sorted(set(tags))
        or any(
            not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None
            for tag in tags
        )
        or result.get("stateDigest") != digest(state)
    ):
        raise ContractError("fixture_reset_baseline_invalid")
    return result


def _ledger_table() -> Any:
    return boto3.resource("dynamodb").Table(
        required_env("FIXTURE_RESET_TABLE", maximum=255)
    )


def _begin(
    table: Any,
    transition: dict[str, Any],
    execution_id: str,
) -> tuple[str, dict[str, Any] | None]:
    key = {
        "pk": "FIXTURE#DATAHUB",
        "sk": "RESET#" + transition["digest"].removeprefix("sha256:"),
    }
    now_epoch = int(time.time())
    item = {
        **key,
        "schemaVersion": "archon.fixture-reset-execution/v1",
        "phase": "EXECUTING",
        "sessionId": transition["sessionId"],
        "triggerState": transition["triggerState"],
        "transitionDigest": transition["digest"],
        "executionId": execution_id,
        "startedAt": instant(),
        "expiresAt": now_epoch + RETENTION_SECONDS,
    }
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
        )
        return "NEW", item
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != (
            "ConditionalCheckFailedException"
        ):
            raise RetryableFailure("fixture_reset_ledger_failed") from error
    except BotoCoreError as error:
        raise RetryableFailure("fixture_reset_ledger_failed") from error
    try:
        response = table.get_item(Key=key, ConsistentRead=True)
    except (BotoCoreError, ClientError) as error:
        raise RetryableFailure("fixture_reset_ledger_failed") from error
    existing = normalize_ddb(response.get("Item"))
    if (
        not isinstance(existing, dict)
        or existing.get("schemaVersion")
            != "archon.fixture-reset-execution/v1"
        or existing.get("sessionId") != transition["sessionId"]
        or existing.get("triggerState") != transition["triggerState"]
        or existing.get("transitionDigest") != transition["digest"]
        or existing.get("phase") not in {"EXECUTING", "COMPLETE"}
    ):
        raise ContractError("fixture_reset_ledger_invalid")
    return existing["phase"], existing


def _complete(
    table: Any,
    transition: dict[str, Any],
    *,
    started_at: str,
    baseline: dict[str, Any],
    mutation: dict[str, Any] | None,
    recovered: bool,
) -> None:
    payload = {
        "schemaVersion": "archon.fixture-baseline-reset-receipt/v1",
        "sessionId": transition["sessionId"],
        "triggerState": transition["triggerState"],
        "transitionDigest": transition["digest"],
        "target": {
            "entityUrn": DATASET_URN,
            "columnPath": COLUMN_PATH,
            "tagUrn": PII_TAG,
        },
        "officialMcpMutation": (
            {
                "tool": "remove_tags",
                "argumentsDigest": mutation["argumentsDigest"],
                "responseDigest": mutation["responseDigest"],
            }
            if mutation is not None
            else None
        ),
        "baselineState": baseline,
        "baselineStateDigest": baseline["stateDigest"],
        "verified": True,
        "humanApprovalUsed": False,
        "authority": "system-lifecycle-only",
        "recoveredAfterInterruptedExecution": recovered,
        "providerPayloadStored": False,
        "startedAt": started_at,
        "completedAt": instant(),
    }
    receipt = {**payload, "digest": digest(payload)}
    key = {
        "pk": "FIXTURE#DATAHUB",
        "sk": "RESET#" + transition["digest"].removeprefix("sha256:"),
    }
    try:
        table.update_item(
            Key=key,
            UpdateExpression="SET #phase=:complete, receipt=:receipt",
            ConditionExpression=(
                "#phase=:executing AND transitionDigest=:transition"
            ),
            ExpressionAttributeNames={"#phase": "phase"},
            ExpressionAttributeValues={
                ":complete": "COMPLETE",
                ":executing": "EXECUTING",
                ":transition": transition["digest"],
                ":receipt": receipt,
            },
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == (
            "ConditionalCheckFailedException"
        ):
            response = table.get_item(Key=key, ConsistentRead=True)
            existing = normalize_ddb(response.get("Item"))
            if (
                isinstance(existing, dict)
                and existing.get("phase") == "COMPLETE"
                and isinstance(existing.get("receipt"), dict)
                and existing["receipt"].get("digest") == receipt["digest"]
            ):
                return
        raise RetryableFailure("fixture_reset_receipt_failed") from error
    except BotoCoreError as error:
        raise RetryableFailure("fixture_reset_receipt_failed") from error


def _reset_one(
    transition: dict[str, Any],
    execution_id: str,
) -> None:
    from handlers import _load_secret

    table = _ledger_table()
    phase, ledger = _begin(table, transition, execution_id)
    if phase == "COMPLETE":
        return
    if ledger is None:
        raise ContractError("fixture_reset_ledger_invalid")
    credential = _load_secret("writer")
    before = _clean_state(asyncio.run(read_column_tags(credential)))
    mutation: dict[str, Any] | None = None
    if PII_TAG in before["tagUrns"]:
        mutation = asyncio.run(mutate_tags(credential, tool="remove_tags"))
    baseline = _clean_state(asyncio.run(read_column_tags(credential)))
    if PII_TAG in baseline["tagUrns"]:
        raise ContractError("fixture_reset_postcondition_failed")
    _complete(
        table,
        transition,
        started_at=ledger["startedAt"],
        baseline=baseline,
        mutation=mutation,
        recovered=phase == "EXECUTING"
            and ledger.get("executionId") != execution_id,
    )


def handle_fixture_reset(event: Any, context: Any) -> dict[str, Any]:
    if (
        not isinstance(event, dict)
        or not exact_keys(event, {"Records"})
        or not isinstance(event.get("Records"), list)
        or not 1 <= len(event["Records"]) <= 2
    ):
        raise ContractError("fixture_reset_event_invalid")
    execution_id = getattr(context, "aws_request_id", None)
    if (
        not isinstance(execution_id, str)
        or REQUEST_ID_RE.fullmatch(execution_id) is None
    ):
        raise ContractError("lambda_execution_id_invalid")
    sources = _source_arns()
    failures: list[dict[str, str]] = []
    for record in event["Records"]:
        event_id = record.get("eventID") if isinstance(record, dict) else None
        if not isinstance(event_id, str) or not 1 <= len(event_id) <= 256:
            continue
        try:
            transition = _transition(record, sources)
            if transition is None:
                continue
            _reset_one(transition, execution_id)
        except RetryableFailure:
            failures.append({"itemIdentifier": event_id})
        except ContractError:
            continue
        except Exception:
            failures.append({"itemIdentifier": event_id})
    return {"batchItemFailures": failures}
