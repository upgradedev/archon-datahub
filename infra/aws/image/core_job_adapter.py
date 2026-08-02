"""Durable DynamoDB-to-loopback adapter for the isolated Core runtime."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import math
import re
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

SESSION_RE = re.compile(r"^rs_[A-Za-z0-9_-]{43}$")
JOB_RE = re.compile(r"^job_[A-Za-z0-9_-]{22}$")
AUDIT_RE = re.compile(r"^[a-f0-9]{64}$")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
DATASET_RE = re.compile(r"^urn:li:dataset:\(.{1,900}\)$")
APPROVAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
)
MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 300 * 1024
MAX_RECEIPT_BYTES = 340 * 1024
MAX_JSON_DEPTH = 12
QUERY_PAGE_LIMIT = 50
MAX_QUERY_PAGES = 8
ATTEMPT_SECONDS = 240
MAX_ATTEMPTS = 3
PII_TAG = "urn:li:tag:PII"
READ_OPERATIONS = {
    "ANALYZE": "/v2/analyze",
    "IMPROVE_CONTEXT": "/v2/improve-context",
    "READ_TAGS": None,
}
MUTATION_OPERATION = "GOVERNED_TAG_MUTATION"


def _iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _json_value(value: Any, depth: int = 0) -> bool:
    if depth > MAX_JSON_DEPTH:
        return False
    if value is None or isinstance(value, (bool, str, int)):
        return not isinstance(value, int) or -(2**53) < value < 2**53
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return len(value) <= 256 and all(
            _json_value(item, depth + 1) for item in value
        )
    if isinstance(value, dict):
        return (
            len(value) <= 256
            and all(
                isinstance(key, str)
                and len(key) <= 256
                and _json_value(item, depth + 1)
                for key, item in value.items()
            )
        )
    return False


def _bounded_request(value: Any) -> bool:
    if not isinstance(value, dict) or not _json_value(value):
        return False
    try:
        return len(_canonical(value)) <= MAX_REQUEST_BYTES
    except (TypeError, ValueError, RecursionError):
        return False


def _exact(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _valid_column(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 512
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _valid_read_request(request: Any) -> bool:
    return (
        _exact(
            request,
            {
                "schemaVersion",
                "auditId",
                "runtimeEvidenceDigest",
                "entityUrn",
                "columnPath",
            },
        )
        and request["schemaVersion"] == "archon.core-tag-read/v1"
        and isinstance(request["auditId"], str)
        and AUDIT_RE.fullmatch(request["auditId"]) is not None
        and isinstance(request["runtimeEvidenceDigest"], str)
        and DIGEST_RE.fullmatch(request["runtimeEvidenceDigest"]) is not None
        and isinstance(request["entityUrn"], str)
        and DATASET_RE.fullmatch(request["entityUrn"]) is not None
        and _valid_column(request["columnPath"])
    )


def _valid_governed_request(request: Any) -> bool:
    if not _exact(
        request,
        {
            "schemaVersion",
            "auditId",
            "runtimeEvidenceDigest",
            "auditEvidenceDigest",
            "planDigest",
            "approval",
            "action",
            "arguments",
            "expectedBeforeDigest",
            "expectedAfterDigest",
            "requestDigest",
        },
    ):
        return False
    approval = request["approval"]
    arguments = request["arguments"]
    if not _exact(
        approval,
        {
            "approvalId",
            "decision",
            "approverDigest",
            "decidedAt",
            "digest",
        },
    ) or not _exact(arguments, {"tagUrns", "entityUrns", "columnPaths"}):
        return False
    digests = (
        request["runtimeEvidenceDigest"],
        request["auditEvidenceDigest"],
        request["planDigest"],
        request["expectedBeforeDigest"],
        request["expectedAfterDigest"],
        request["requestDigest"],
        approval["approverDigest"],
        approval["digest"],
    )
    if not all(
        isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None
        for value in digests
    ):
        return False
    if (
        request["schemaVersion"] != "archon.core-governed-tag-mutation/v1"
        or not isinstance(request["auditId"], str)
        or AUDIT_RE.fullmatch(request["auditId"]) is None
        or request["action"] not in {"ADD_TAGS", "REMOVE_TAGS"}
        or approval["decision"] != "APPROVE"
        or not isinstance(approval["approvalId"], str)
        or APPROVAL_ID_RE.fullmatch(approval["approvalId"]) is None
        or not isinstance(approval["decidedAt"], str)
        or RFC3339_RE.fullmatch(approval["decidedAt"]) is None
        or arguments["tagUrns"] != [PII_TAG]
        or not isinstance(arguments["entityUrns"], list)
        or len(arguments["entityUrns"]) != 1
        or not isinstance(arguments["entityUrns"][0], str)
        or DATASET_RE.fullmatch(arguments["entityUrns"][0]) is None
        or not isinstance(arguments["columnPaths"], list)
        or len(arguments["columnPaths"]) != 1
        or not _valid_column(arguments["columnPaths"][0])
    ):
        return False
    unsigned = dict(request)
    supplied = unsigned.pop("requestDigest")
    return hmac.compare_digest(supplied, _digest(unsigned))


def _request_valid(operation: Any, request: Any) -> bool:
    if not _bounded_request(request):
        return False
    if operation in {"ANALYZE", "IMPROVE_CONTEXT"}:
        return True
    if operation == "READ_TAGS":
        return _valid_read_request(request)
    if operation == MUTATION_OPERATION:
        return _valid_governed_request(request)
    return False


class CoreJobAdapter:
    def __init__(
        self,
        *,
        table_name: str,
        session_id: str,
        generation: str,
        capability_digest: str,
        companion_url: str = "http://127.0.0.1:8080",
        governed_mcp_url: str = "http://127.0.0.1:8001/mcp",
    ) -> None:
        if SESSION_RE.fullmatch(session_id) is None:
            raise ValueError("invalid session")
        if companion_url != "http://127.0.0.1:8080":
            raise ValueError("companion must remain loopback-only")
        if governed_mcp_url != "http://127.0.0.1:8001/mcp":
            raise ValueError("governed MCP must remain loopback-only")
        self._table = boto3.resource("dynamodb").Table(table_name)
        self._session_id = session_id
        self._generation = generation
        self._capability_digest = capability_digest
        self._base = companion_url
        self._governed_mcp_url = governed_mcp_url
        self._cursors: dict[str, Any] = {}

    def process_once(self) -> int:
        processed = 0
        for partition in (
            f"SESSION#{self._session_id}",
            f"MUTATION#{self._session_id}",
        ):
            processed += self._process_partition(partition)
        return processed

    def _process_partition(self, partition: str) -> int:
        processed = 0
        cursor = self._cursors.get(partition)
        for _page in range(MAX_QUERY_PAGES):
            query: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(partition)
                & Key("sk").begins_with("JOB#"),
                "ConsistentRead": True,
                "Limit": QUERY_PAGE_LIMIT,
            }
            if cursor is not None:
                query["ExclusiveStartKey"] = cursor
            response = self._table.query(**query)
            for item in response.get("Items", []):
                try:
                    if not self._valid(item, partition):
                        self._reject_invalid(item)
                        continue
                    if item.get("state") == "RUNNING":
                        self._recover_expired(item)
                        continue
                    attempt_id = self._claim(item)
                    if attempt_id is not None:
                        self._execute(item, attempt_id)
                        processed += 1
                except Exception:
                    # A malformed or contended item is isolated from host health.
                    self._reject_invalid(item)
            cursor = response.get("LastEvaluatedKey")
            if cursor is None:
                self._cursors.pop(partition, None)
                break
            self._cursors[partition] = cursor
        return processed

    def _valid(self, item: Any, partition: str) -> bool:
        if not isinstance(item, dict):
            return False
        operation = item.get("operation")
        expected_partition = (
            f"MUTATION#{self._session_id}"
            if operation == MUTATION_OPERATION
            else f"SESSION#{self._session_id}"
        )
        job_id = item.get("jobId")
        return (
            partition == expected_partition
            and item.get("pk") == partition
            and isinstance(job_id, str)
            and JOB_RE.fullmatch(job_id) is not None
            and item.get("sk") == f"JOB#{job_id}"
            and item.get("schema") == "archon.core-runtime-job/v1"
            and item.get("sessionId") == self._session_id
            and item.get("generation") == self._generation
            and item.get("capabilityDigest") == self._capability_digest
            and item.get("state") in {"QUEUED", "RUNNING"}
            and _request_valid(operation, item.get("request"))
        )

    def _claim(self, item: dict[str, Any]) -> str | None:
        if item.get("state") != "QUEUED":
            return None
        attempt_id = uuid.uuid4().hex
        started = _iso()
        deadline = int(time.time()) + ATTEMPT_SECONDS
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET #state=:running, startedAt=:started, "
                    "attemptId=:attempt, attemptDeadlineEpoch=:deadline, "
                    "attemptCount=if_not_exists(attemptCount,:zero)+:one"
                ),
                ConditionExpression=(
                    "#state=:queued AND sessionId=:session "
                    "AND generation=:generation "
                    "AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":running": "RUNNING",
                    ":started": started,
                    ":attempt": attempt_id,
                    ":deadline": deadline,
                    ":zero": 0,
                    ":one": 1,
                    ":queued": "QUEUED",
                    ":session": self._session_id,
                    ":generation": self._generation,
                    ":digest": self._capability_digest,
                },
            )
            return attempt_id
        except ClientError as error:
            if _conditional_failure(error):
                return None
            raise

    def _recover_expired(self, item: dict[str, Any]) -> bool:
        deadline = item.get("attemptDeadlineEpoch")
        attempt_id = item.get("attemptId")
        attempts = item.get("attemptCount")
        if (
            not isinstance(deadline, int)
            or isinstance(deadline, bool)
            or not isinstance(attempt_id, str)
            or re.fullmatch(r"^[0-9a-f]{32}$", attempt_id) is None
            or not isinstance(attempts, int)
            or isinstance(attempts, bool)
        ):
            self._reject_invalid(item)
            return False
        if deadline > int(time.time()):
            return False
        if attempts >= MAX_ATTEMPTS:
            return self._complete(
                item,
                attempt_id,
                "FAILED",
                error={"code": "CORE_JOB_ATTEMPTS_EXHAUSTED", "retryable": False},
            )
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET #state=:queued, recoveredAt=:recovered "
                    "REMOVE attemptId, attemptDeadlineEpoch"
                ),
                ConditionExpression=(
                    "#state=:running AND attemptId=:attempt "
                    "AND attemptDeadlineEpoch=:deadline"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":queued": "QUEUED",
                    ":recovered": _iso(),
                    ":running": "RUNNING",
                    ":attempt": attempt_id,
                    ":deadline": deadline,
                },
            )
            return True
        except ClientError as error:
            if _conditional_failure(error):
                return False
            raise

    def _execute(self, item: dict[str, Any], attempt_id: str) -> None:
        try:
            operation = item["operation"]
            if operation in {"ANALYZE", "IMPROVE_CONTEXT"}:
                result = self._companion(
                    READ_OPERATIONS[operation], item["request"]
                )
            elif operation == "READ_TAGS":
                result = self._read_tags(item["request"])
            elif operation == MUTATION_OPERATION:
                result = self._governed_mutation(item["request"])
            else:
                raise RuntimeError("operation is not allowlisted")
            self._complete(item, attempt_id, "SUCCEEDED", result=result)
        except (Exception, RecursionError):
            self._complete(
                item,
                attempt_id,
                "FAILED",
                error={"code": "CORE_JOB_FAILED", "retryable": True},
            )

    def _companion(self, path: str | None, body_value: dict[str, Any]) -> dict[str, Any]:
        if path not in {"/v2/analyze", "/v2/improve-context"}:
            raise RuntimeError("companion path is not allowlisted")
        body = _canonical(body_value)
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
        except urllib.error.HTTPError as error:
            raise RuntimeError("companion rejected the bounded request") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("companion response exceeded its bound")
        result = json.loads(raw)
        if not isinstance(result, dict) or not _json_value(result):
            raise RuntimeError("companion response was not a bounded object")
        return result

    def _mcp_call(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if tool_name not in {"get_entities", "add_tags", "remove_tags"}:
            raise RuntimeError("MCP tool is not allowlisted")

        async def invoke() -> Any:
            from fastmcp import Client

            async with Client(self._governed_mcp_url) as client:
                response = await client.call_tool(tool_name, arguments)
            if getattr(response, "is_error", False):
                raise RuntimeError("governed MCP tool failed")
            data = getattr(response, "data", None)
            if data is not None:
                return data
            structured = getattr(response, "structured_content", None)
            if structured is not None:
                return structured
            blocks = getattr(response, "content", [])
            texts = [
                block.text
                for block in blocks
                if isinstance(getattr(block, "text", None), str)
            ]
            if len(texts) != 1:
                raise RuntimeError("governed MCP result schema drift")
            return json.loads(texts[0])

        return asyncio.run(invoke())

    def _read_tags(self, request: dict[str, Any]) -> dict[str, Any]:
        entity = request["entityUrn"]
        column = request["columnPath"]
        raw = self._mcp_call("get_entities", {"urns": [entity]})
        found, tags = _column_tags(raw, column)
        if not found:
            raise RuntimeError("bound DataHub column was not found")
        state = {
            "entityUrn": entity,
            "columnPath": column,
            "tagUrns": sorted(tags),
        }
        return {
            "schemaVersion": "archon.core-tag-read-result/v1",
            **state,
            "stateDigest": _digest(state),
        }

    def _governed_mutation(self, request: dict[str, Any]) -> dict[str, Any]:
        if not _valid_governed_request(request):
            raise RuntimeError("governed mutation envelope is invalid")
        arguments = request["arguments"]
        read_request = {
            "entityUrn": arguments["entityUrns"][0],
            "columnPath": arguments["columnPaths"][0],
        }
        before = self._read_tags(read_request)
        if not hmac.compare_digest(
            before["stateDigest"], request["expectedBeforeDigest"]
        ):
            raise RuntimeError("governed mutation before-state drift")
        tool = "add_tags" if request["action"] == "ADD_TAGS" else "remove_tags"
        mutation_result = self._mcp_call(
            tool,
            {
                "tag_urns": arguments["tagUrns"],
                "entity_urns": arguments["entityUrns"],
                "column_paths": arguments["columnPaths"],
            },
        )
        if not isinstance(mutation_result, dict) or mutation_result.get("success") is not True:
            raise RuntimeError("governed MCP mutation was not confirmed")
        after = self._read_tags(read_request)
        if not hmac.compare_digest(
            after["stateDigest"], request["expectedAfterDigest"]
        ):
            raise RuntimeError("governed mutation after-state drift")
        result = {
            "schemaVersion": "archon.core-governed-tag-result/v1",
            "requestDigest": request["requestDigest"],
            "beforeDigest": before["stateDigest"],
            "afterDigest": after["stateDigest"],
            "verified": True,
        }
        return {**result, "responseDigest": _digest(result)}

    def _reject_invalid(self, item: Any) -> None:
        if not isinstance(item, dict):
            return
        pk = item.get("pk")
        sk = item.get("sk")
        if (
            not isinstance(pk, str)
            or pk
            not in {
                f"SESSION#{self._session_id}",
                f"MUTATION#{self._session_id}",
            }
            or not isinstance(sk, str)
            or re.fullmatch(r"^JOB#job_[A-Za-z0-9_-]{22}$", sk) is None
            or item.get("state") not in {"QUEUED", "RUNNING"}
        ):
            return
        job_id = item.get("jobId")
        if not isinstance(job_id, str) or JOB_RE.fullmatch(job_id) is None:
            job_id = sk.removeprefix("JOB#")
        receipt = {
            "schema": "archon.core-runtime-job-receipt/v1",
            "jobId": job_id,
            "sessionId": self._session_id,
            "generation": self._generation,
            "capabilityDigest": self._capability_digest,
            "state": "FAILED",
            "completedAt": _iso(),
            "error": {"code": "INVALID_CORE_JOB", "retryable": False},
        }
        try:
            self._table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=(
                    "SET #state=:failed, completedAt=:completed, receipt=:receipt "
                    "REMOVE request, attemptId, attemptDeadlineEpoch"
                ),
                ConditionExpression="#state IN (:queued,:running)",
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":failed": "FAILED",
                    ":completed": receipt["completedAt"],
                    ":receipt": receipt,
                    ":queued": "QUEUED",
                    ":running": "RUNNING",
                },
            )
        except ClientError as error:
            if not _conditional_failure(error):
                raise

    def _complete(
        self,
        item: dict[str, Any],
        attempt_id: str,
        state: str,
        *,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> bool:
        receipt: dict[str, Any] = {
            "schema": "archon.core-runtime-job-receipt/v1",
            "jobId": item["jobId"],
            "sessionId": self._session_id,
            "generation": self._generation,
            "capabilityDigest": self._capability_digest,
            "state": state,
            "completedAt": _iso(),
            "attemptId": attempt_id,
        }
        if result is not None:
            receipt["result"] = result
        if error is not None:
            receipt["error"] = error
        try:
            if len(_canonical(receipt)) > MAX_RECEIPT_BYTES:
                receipt.pop("result", None)
                receipt["state"] = "FAILED"
                receipt["error"] = {
                    "code": "CORE_JOB_RECEIPT_TOO_LARGE",
                    "retryable": False,
                }
        except (TypeError, ValueError, RecursionError):
            receipt.pop("result", None)
            receipt["state"] = "FAILED"
            receipt["error"] = {
                "code": "CORE_JOB_RECEIPT_INVALID",
                "retryable": False,
            }
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET #state=:state, completedAt=:completed, receipt=:receipt "
                    "REMOVE request, attemptId, attemptDeadlineEpoch"
                ),
                ConditionExpression=(
                    "#state=:running AND attemptId=:attempt"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":state": receipt["state"],
                    ":completed": receipt["completedAt"],
                    ":receipt": receipt,
                    ":running": "RUNNING",
                    ":attempt": attempt_id,
                },
            )
            return True
        except ClientError as error:
            if _conditional_failure(error):
                return False
            raise


def _conditional_failure(error: ClientError) -> bool:
    return (
        error.response.get("Error", {}).get("Code")
        == "ConditionalCheckFailedException"
    )


def _column_tags(value: Any, column_path: str) -> tuple[bool, set[str]]:
    found = False
    tags: set[str] = set()

    def walk(node: Any, within_column: bool = False) -> None:
        nonlocal found
        if isinstance(node, list):
            for entry in node:
                walk(entry, within_column)
            return
        if not isinstance(node, dict):
            return
        matches = any(
            node.get(key) == column_path
            for key in ("fieldPath", "columnPath", "path")
        )
        if matches:
            found = True
            within_column = True
        for child in node.values():
            if (
                within_column
                and isinstance(child, str)
                and child.startswith("urn:li:tag:")
                and len(child) <= 256
            ):
                tags.add(child)
            else:
                walk(child, within_column)

    walk(value)
    return found, tags