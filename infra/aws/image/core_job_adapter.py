"""DynamoDB-to-loopback adapter for the non-networked Core companion."""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.error
import urllib.request
import uuid
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

SESSION_RE = re.compile(r"^rs_[A-Za-z0-9_-]{43}$")
JOB_RE = re.compile(r"^job_[A-Za-z0-9_-]{22}$")
MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 384 * 1024
ALLOWED_OPERATIONS = {
    "ANALYZE": "/v2/analyze",
    "IMPROVE_CONTEXT": "/v2/improve-context",
}


def _iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class CoreJobAdapter:
    def __init__(
        self,
        *,
        table_name: str,
        session_id: str,
        generation: str,
        capability_digest: str,
        companion_url: str = "http://127.0.0.1:8080",
    ) -> None:
        if SESSION_RE.fullmatch(session_id) is None:
            raise ValueError("invalid session")
        if companion_url != "http://127.0.0.1:8080":
            raise ValueError("companion must remain loopback-only")
        self._table = boto3.resource("dynamodb").Table(table_name)
        self._session_id = session_id
        self._generation = generation
        self._capability_digest = capability_digest
        self._base = companion_url

    def process_once(self) -> int:
        response = self._table.query(
            KeyConditionExpression=Key("pk").eq(f"SESSION#{self._session_id}")
            & Key("sk").begins_with("JOB#"),
            ConsistentRead=True,
            Limit=20,
        )
        processed = 0
        for item in response.get("Items", []):
            if self._claim(item):
                self._execute(item)
                processed += 1
        return processed

    def _valid(self, item: Any) -> bool:
        if not isinstance(item, dict):
            return False
        request = item.get("request")
        request_bytes = json.dumps(
            request, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return (
            item.get("schema") == "archon.core-runtime-job/v1"
            and item.get("sessionId") == self._session_id
            and item.get("generation") == self._generation
            and item.get("capabilityDigest") == self._capability_digest
            and item.get("state") == "QUEUED"
            and item.get("operation") in ALLOWED_OPERATIONS
            and isinstance(item.get("jobId"), str)
            and JOB_RE.fullmatch(item["jobId"]) is not None
            and isinstance(request, dict)
            and len(request_bytes) <= MAX_REQUEST_BYTES
        )

    def _claim(self, item: Any) -> bool:
        if not self._valid(item):
            return False
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET #state=:running, startedAt=:started, "
                    "attemptId=:attempt"
                ),
                ConditionExpression=(
                    "#state=:queued AND sessionId=:session "
                    "AND generation=:generation "
                    "AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":running": "RUNNING",
                    ":started": _iso(),
                    ":attempt": uuid.uuid4().hex,
                    ":queued": "QUEUED",
                    ":session": self._session_id,
                    ":generation": self._generation,
                    ":digest": self._capability_digest,
                },
            )
            return True
        except ClientError as error:
            if (
                error.response.get("Error", {}).get("Code")
                == "ConditionalCheckFailedException"
            ):
                return False
            raise

    def _execute(self, item: dict[str, Any]) -> None:
        path = ALLOWED_OPERATIONS[item["operation"]]
        body = json.dumps(
            item["request"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = urllib.request.Request(
            self._base + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=185) as response:
                if response.status != 200:
                    raise RuntimeError("companion returned a non-success status")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("companion response exceeded its bound")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise RuntimeError("companion response was not an object")
            self._complete(item, "SUCCEEDED", result=result)
        except (OSError, ValueError, RuntimeError, urllib.error.HTTPError):
            self._complete(
                item,
                "FAILED",
                error={"code": "CORE_JOB_FAILED", "retryable": True},
            )

    def _complete(
        self,
        item: dict[str, Any],
        state: str,
        *,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        receipt: dict[str, Any] = {
            "schema": "archon.core-runtime-job-receipt/v1",
            "jobId": item["jobId"],
            "sessionId": self._session_id,
            "generation": self._generation,
            "capabilityDigest": self._capability_digest,
            "state": state,
            "completedAt": _iso(),
        }
        if result is not None:
            receipt["result"] = result
        if error is not None:
            receipt["error"] = error
        self._table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression=(
                "SET #state=:state, completedAt=:completed, receipt=:receipt "
                "REMOVE request"
            ),
            ConditionExpression="#state=:running",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":state": state,
                ":completed": receipt["completedAt"],
                ":receipt": receipt,
                ":running": "RUNNING",
            },
        )
