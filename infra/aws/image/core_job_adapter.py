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
POST_OPERATIONS = {"POST_ANALYZE", "POST_READ_TAGS"}
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


def _seal_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Bind every durable receipt to its exact canonical content."""
    if "receiptDigest" in receipt:
        raise ValueError("receipt is already sealed")
    return {**receipt, "receiptDigest": _digest(receipt)}


def _receipt_context(item: dict[str, Any]) -> dict[str, str]:
    context: dict[str, str] = {}
    operation = item.get("operation")
    if operation in {*READ_OPERATIONS, *POST_OPERATIONS, MUTATION_OPERATION}:
        context["operation"] = operation
    request = item.get("request")
    if isinstance(request, dict):
        audit_id = request.get("auditId")
        evidence_digest = request.get("runtimeEvidenceDigest")
        if isinstance(audit_id, str) and AUDIT_RE.fullmatch(audit_id):
            context["auditId"] = audit_id
        if (
            isinstance(evidence_digest, str)
            and DIGEST_RE.fullmatch(evidence_digest)
        ):
            context["runtimeEvidenceDigest"] = evidence_digest
        source_audit = request.get("sourceMutationAuditId")
        source_receipt = request.get("sourceMutationReceiptDigest")
        if isinstance(source_audit, str) and AUDIT_RE.fullmatch(source_audit):
            context["sourceMutationAuditId"] = source_audit
        if (
            isinstance(source_receipt, str)
            and DIGEST_RE.fullmatch(source_receipt)
        ):
            context["sourceMutationReceiptDigest"] = source_receipt
    return context


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


def _valid_post_request(operation: str, request: Any) -> bool:
    if not _exact(
        request,
        {
            "schemaVersion",
            "originalRequest",
            "sourceMutationAuditId",
            "sourceMutationReceiptDigest",
            "postMutationExpectedTagState",
        },
    ):
        return False
    expected_schema = {
        "POST_ANALYZE": "archon.datahub-post-mutation-analysis/v1",
        "POST_READ_TAGS": "archon.core-post-mutation-tag-read/v1",
    }.get(operation)
    state = request["postMutationExpectedTagState"]
    if (
        request["schemaVersion"] != expected_schema
        or not isinstance(request["sourceMutationAuditId"], str)
        or AUDIT_RE.fullmatch(request["sourceMutationAuditId"]) is None
        or not isinstance(request["sourceMutationReceiptDigest"], str)
        or DIGEST_RE.fullmatch(request["sourceMutationReceiptDigest"]) is None
        or not _exact(
            state, {"entityUrn", "columnPath", "tagUrns", "stateDigest"}
        )
        or not isinstance(state["entityUrn"], str)
        or DATASET_RE.fullmatch(state["entityUrn"]) is None
        or not _valid_column(state["columnPath"])
        or state["tagUrns"] not in ([], [PII_TAG])
    ):
        return False
    unsigned_state = {
        "entityUrn": state["entityUrn"],
        "columnPath": state["columnPath"],
        "tagUrns": state["tagUrns"],
    }
    if (
        not isinstance(state["stateDigest"], str)
        or not hmac.compare_digest(state["stateDigest"], _digest(unsigned_state))
    ):
        return False
    original = request["originalRequest"]
    if operation == "POST_READ_TAGS":
        return _valid_read_request(original)
    return _bounded_request(original)

def _valid_governed_request(request: Any) -> bool:
    if not _exact(
        request,
        {
            "schemaVersion",
            "auditId",
            "runtimeEvidenceDigest",
            "auditEvidenceDigest",
            "planDigest",
            "policyDigest",
            "approval",
            "action",
            "arguments",
            "expectedBeforeDigest",
            "expectedAfterDigest",
            "authorization",
            "requestDigest",
        },
    ):
        return False
    approval = request["approval"]
    arguments = request["arguments"]
    authorization = request["authorization"]
    if not _exact(
        approval,
        {
            "approvalId",
            "decision",
            "approverDigest",
            "decidedAt",
            "digest",
        },
    ) or not _exact(arguments, {"tagUrns", "entityUrns", "columnPaths"}) or not _exact(
        authorization, {"envelope", "signature"}
    ):
        return False
    digests = (
        request["runtimeEvidenceDigest"],
        request["auditEvidenceDigest"],
        request["planDigest"],
        request["policyDigest"],
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
    if operation in POST_OPERATIONS:
        return _valid_post_request(operation, request)
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
        read_mcp_url: str = "http://127.0.0.1:8000/mcp",
        governed_mcp_url: str = "http://127.0.0.1:8001/mcp",
    ) -> None:
        if SESSION_RE.fullmatch(session_id) is None:
            raise ValueError("invalid session")
        if companion_url != "http://127.0.0.1:8080":
            raise ValueError("companion must remain loopback-only")
        if read_mcp_url != "http://127.0.0.1:8000/mcp":
            raise ValueError("read MCP must remain loopback-only")
        if governed_mcp_url != "http://127.0.0.1:8001/mcp":
            raise ValueError("governed gateway must remain loopback-only")
        self._table = boto3.resource("dynamodb").Table(table_name)
        self._session_id = session_id
        self._generation = generation
        self._capability_digest = capability_digest
        self._base = companion_url
        self._read_mcp_url = read_mcp_url
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
                    # This consumer never mutates or reports jobs bound to another runtime.
                    if (
                        not isinstance(item, dict)
                        or item.get("profileId") != "core"
                        or item.get("schema") != "archon.runtime-bound-job/v2"
                    ):
                        continue
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
            and item.get("schema") == "archon.runtime-bound-job/v2"
            and item.get("profileId") == "core"
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
                    "#state=:queued AND #schema=:schema AND profileId=:profile "
                    "AND sessionId=:session AND generation=:generation "
                    "AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state", "#schema": "schema"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": "core",
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
                    "AND attemptDeadlineEpoch=:deadline AND #schema=:schema "
                    "AND profileId=:profile AND sessionId=:session "
                    "AND generation=:generation AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state", "#schema": "schema"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": "core",
                    ":session": self._session_id,
                    ":generation": self._generation,
                    ":digest": self._capability_digest,
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
            elif operation in POST_OPERATIONS:
                result = self._post_mutation(operation, item["request"])
            elif operation == MUTATION_OPERATION:
                result = self._governed_mutation(item)
            else:
                raise RuntimeError("operation is not allowlisted")
            self._complete(item, attempt_id, "SUCCEEDED", result=result)
        except Exception:
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

    def _mcp_call(
        self, url: str, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        if (
            url not in {self._read_mcp_url, self._governed_mcp_url}
            or tool_name not in {"get_entities", "execute_governed_mutation"}
            or (
                tool_name == "execute_governed_mutation"
                and url != self._governed_mcp_url
            )
            or (tool_name == "get_entities" and url != self._read_mcp_url)
        ):
            raise RuntimeError("MCP authority or tool is not allowlisted")

        async def invoke() -> Any:
            from fastmcp import Client

            async with Client(url) as client:
                response = await client.call_tool(tool_name, arguments)
            if getattr(response, "is_error", False):
                raise RuntimeError("bounded MCP call failed")
            data = getattr(response, "data", None)
            if data is not None:
                return data
            structured = getattr(response, "structured_content", None)
            if structured is not None:
                return structured
            texts = [
                block.text
                for block in getattr(response, "content", [])
                if isinstance(getattr(block, "text", None), str)
            ]
            if len(texts) != 1:
                raise RuntimeError("bounded MCP result schema drift")
            return json.loads(texts[0])

        return asyncio.run(invoke())

    def _read_tags(self, request: dict[str, Any]) -> dict[str, Any]:
        entity = request["entityUrn"]
        column = request["columnPath"]
        raw = self._mcp_call(
            self._read_mcp_url, "get_entities", {"urns": [entity]}
        )
        if not _json_value(raw):
            raise RuntimeError("read MCP result exceeded policy")
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

    def _post_mutation(
        self, operation: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        if not _valid_post_request(operation, request):
            raise RuntimeError("post-mutation request is invalid")
        expected = request["postMutationExpectedTagState"]
        live = self._read_tags(
            {
                "entityUrn": expected["entityUrn"],
                "columnPath": expected["columnPath"],
            }
        )
        if not hmac.compare_digest(live["stateDigest"], expected["stateDigest"]):
            raise RuntimeError("post-mutation live tag state drifted")
        if operation == "POST_ANALYZE":
            post_result = self._companion(
                "/v2/analyze", request["originalRequest"]
            )
            schema = "archon.datahub-post-mutation-analysis-result/v1"
        else:
            post_result = live
            schema = "archon.core-post-mutation-tag-read-result/v1"
        result = {
            "schemaVersion": schema,
            "sourceMutationAuditId": request["sourceMutationAuditId"],
            "sourceMutationReceiptDigest": request[
                "sourceMutationReceiptDigest"
            ],
            "postMutationExpectedTagState": expected,
            "postMutationResult": post_result,
            "postMutationResultDigest": _digest(post_result),
        }
        return result

    def _governed_mutation(self, item: dict[str, Any]) -> dict[str, Any]:
        request = item["request"]
        if not _valid_governed_request(request):
            raise RuntimeError("governed mutation envelope is invalid")
        gateway_result = self._mcp_call(
            self._governed_mcp_url,
            "execute_governed_mutation",
            {"job_id": item["jobId"], "request": request},
        )
        expected_keys = {
            "schemaVersion",
            "success",
            "action",
            "requestDigest",
            "policyDigest",
            "approvalDigest",
            "beforeDigest",
            "afterDigest",
            "changed",
            "verified",
            "mutationExecutor",
            "officialMcpMutation",
            "authorizationEvidence",
            "receiptDigest",
        }
        if not isinstance(gateway_result, dict) or set(gateway_result) != expected_keys:
            raise RuntimeError("governed gateway result schema drift")
        unsigned = dict(gateway_result)
        receipt_digest = unsigned.pop("receiptDigest")
        official = gateway_result.get("officialMcpMutation")
        authorization_evidence = gateway_result.get("authorizationEvidence")
        signature = request["authorization"]["signature"]
        expected_tool = "add_tags" if request["action"] == "ADD_TAGS" else "remove_tags"
        nested_evidence_valid = (
            _exact(
                official,
                {"tool", "policyDigest", "approvalDigest", "requestDigest", "responseDigest"},
            )
            and official["tool"] == expected_tool
            and official["policyDigest"] == request["policyDigest"]
            and official["approvalDigest"] == request["approval"]["digest"]
            and official["requestDigest"] == request["requestDigest"]
            and isinstance(official["responseDigest"], str)
            and DIGEST_RE.fullmatch(official["responseDigest"]) is not None
            and _exact(
                authorization_evidence,
                {
                    "keyArn", "algorithm", "canonicalization", "envelopeDigest",
                    "signatureDigest", "consumedAt",
                },
            )
            and authorization_evidence["keyArn"] == signature["keyArn"]
            and authorization_evidence["algorithm"] == "ECDSA_SHA_256"
            and authorization_evidence["canonicalization"]
            == "archon.sorted-json-utf8/v1"
            and authorization_evidence["envelopeDigest"] == signature["envelopeDigest"]
            and isinstance(authorization_evidence["signatureDigest"], str)
            and DIGEST_RE.fullmatch(authorization_evidence["signatureDigest"])
            is not None
            and isinstance(authorization_evidence["consumedAt"], str)
            and ISO_RE.fullmatch(authorization_evidence["consumedAt"]) is not None
        )
        if (
            gateway_result["schemaVersion"]
            != "archon.core-governed-gateway-result/v2"
            or gateway_result["success"] is not True
            or gateway_result["verified"] is not True
            or gateway_result["mutationExecutor"] != "official-datahub-mcp"
            or gateway_result["action"] != request["action"]
            or gateway_result["requestDigest"] != request["requestDigest"]
            or gateway_result["policyDigest"] != request["policyDigest"]
            or gateway_result["approvalDigest"] != request["approval"]["digest"]
            or gateway_result["beforeDigest"] != request["expectedBeforeDigest"]
            or gateway_result["afterDigest"] != request["expectedAfterDigest"]
            or not isinstance(gateway_result["changed"], bool)
            or not nested_evidence_valid
            or not isinstance(receipt_digest, str)
            or not hmac.compare_digest(receipt_digest, _digest(unsigned))
        ):
            raise RuntimeError("governed gateway receipt verification failed")
        result = {
            "schemaVersion": "archon.core-governed-tag-result/v1",
            "requestDigest": request["requestDigest"],
            "policyDigest": request["policyDigest"],
            "beforeDigest": gateway_result["beforeDigest"],
            "afterDigest": gateway_result["afterDigest"],
            "verified": True,
            "mutationExecutor": "official-datahub-mcp",
            "officialMcpMutation": gateway_result["officialMcpMutation"],
            "authorizationEvidence": gateway_result["authorizationEvidence"],
        }
        return {**result, "responseDigest": _digest(result)}
    def _reject_invalid(self, item: Any) -> None:
        if not isinstance(item, dict):
            return
        pk = item.get("pk")
        sk = item.get("sk")
        if (
            item.get("profileId") != "core"
            or item.get("schema") != "archon.runtime-bound-job/v2"
            or item.get("sessionId") != self._session_id
            or item.get("generation") != self._generation
            or item.get("capabilityDigest") != self._capability_digest
            or not isinstance(pk, str)
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
            "schema": "archon.runtime-bound-job-receipt/v2",
            "profileId": "core",
            "jobId": job_id,
            "sessionId": self._session_id,
            "generation": self._generation,
            "capabilityDigest": self._capability_digest,
            "state": "FAILED",
            "completedAt": _iso(),
            **_receipt_context(item),
            "error": {"code": "INVALID_CORE_JOB", "retryable": False},
        }
        receipt = _seal_receipt(receipt)
        try:
            self._table.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression=(
                    "SET #state=:failed, completedAt=:completed, receipt=:receipt "
                    "REMOVE attemptId, attemptDeadlineEpoch"
                ),
                ConditionExpression=(
                    "#state IN (:queued,:running) AND #schema=:schema "
                    "AND profileId=:profile AND sessionId=:session "
                    "AND generation=:generation AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state", "#schema": "schema"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": "core",
                    ":session": self._session_id,
                    ":generation": self._generation,
                    ":digest": self._capability_digest,
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
            "schema": "archon.runtime-bound-job-receipt/v2",
            "profileId": "core",
            "jobId": item["jobId"],
            "sessionId": self._session_id,
            "generation": self._generation,
            "capabilityDigest": self._capability_digest,
            "state": state,
            "completedAt": _iso(),
            "attemptId": attempt_id,
            **_receipt_context(item),
        }
        if result is not None:
            receipt["result"] = result
        if error is not None:
            receipt["error"] = error
        try:
            if len(_canonical(_seal_receipt(receipt))) > MAX_RECEIPT_BYTES:
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
        receipt = _seal_receipt(receipt)
        try:
            self._table.update_item(
                Key={"pk": item["pk"], "sk": item["sk"]},
                UpdateExpression=(
                    "SET #state=:state, completedAt=:completed, receipt=:receipt "
                    "REMOVE attemptId, attemptDeadlineEpoch"
                ),
                ConditionExpression=(
                    "#state=:running AND attemptId=:attempt "
                    "AND #schema=:schema AND profileId=:profile "
                    "AND sessionId=:session AND generation=:generation "
                    "AND capabilityDigest=:digest"
                ),
                ExpressionAttributeNames={"#state": "state", "#schema": "schema"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": "core",
                    ":session": self._session_id,
                    ":generation": self._generation,
                    ":digest": self._capability_digest,
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