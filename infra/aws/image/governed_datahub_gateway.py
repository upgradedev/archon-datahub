"""Loopback-only asymmetric authorization firewall for official DataHub MCP writes."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import threading
from typing import Any

import boto3
from botocore.exceptions import ClientError

DATASET_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
)
COLUMN_PATH = "customer_email"
PII_TAG = "urn:li:tag:PII"
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
AUDIT_RE = re.compile(r"^[a-f0-9]{64}$")
SESSION_RE = re.compile(r"^rs_[A-Za-z0-9_-]{43}$")
JOB_RE = re.compile(r"^job_[A-Za-z0-9_-]{22}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
KEY_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):kms:eu-west-1:\d{12}:key/[0-9a-f-]{36}$"
)
REQUEST_KEYS = {
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
}
ENVELOPE_KEYS = {
    "schemaVersion",
    "stage",
    "sessionId",
    "generation",
    "capabilityDigest",
    "jobId",
    "approvalId",
    "planDigest",
    "policyDigest",
    "target",
    "tool",
    "arguments",
    "issuedAt",
    "expiresAt",
}
SIGNATURE_KEYS = {
    "keyArn",
    "algorithm",
    "canonicalization",
    "envelopeDigest",
    "signatureBase64",
}
APPROVAL_KEYS = {
    "approvalId",
    "decision",
    "approverDigest",
    "decidedAt",
    "digest",
}
ARGUMENT_KEYS = {"tagUrns", "entityUrns", "columnPaths"}
SIGNED_ARGUMENT_KEYS = {"tag_urns", "entity_urns", "column_paths"}
TARGET_KEYS = {"entityUrn", "columnPath"}
_LOCK = threading.Lock()
_PUBLIC_KEY: Any = None
_KMS: Any = None
_TABLE: Any = None


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


def _validate_signed_json(value: Any, path: str = "$") -> None:
    """Enforce the cross-language sorted-JSON subset before signature verification."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise PermissionError(f"signed integer at {path} is not interoperable")
        return
    if isinstance(value, str):
        if not value or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise PermissionError(f"signed string at {path} is outside printable ASCII")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_signed_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key or any(
                ord(character) < 0x20 or ord(character) > 0x7E for character in key
            ):
                raise PermissionError(f"signed key at {path} is outside printable ASCII")
            _validate_signed_json(item, f"{path}.{key}")
        return
    raise PermissionError(f"signed value at {path} is outside the canonical subset")


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


def _exact(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _parse_instant(value: Any) -> dt.datetime:
    if not isinstance(value, str) or ISO_RE.fullmatch(value) is None:
        raise PermissionError("authorization instant is invalid")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    canonical = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if canonical != value:
        raise PermissionError("authorization instant is not canonical")
    return parsed


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _table() -> Any:
    global _TABLE
    if _TABLE is None:
        _TABLE = boto3.resource("dynamodb").Table(_required("CORE_LEASE_TABLE"))
    return _TABLE


def _public_key() -> Any:
    global _KMS, _PUBLIC_KEY
    if _PUBLIC_KEY is None:
        if _KMS is None:
            _KMS = boto3.client("kms", region_name=_required("AWS_REGION"))
        key_arn = _required("ARCHON_MUTATION_SIGNING_KEY_ARN")
        if KEY_ARN_RE.fullmatch(key_arn) is None:
            raise RuntimeError("mutation verification key ARN is invalid")
        response = _KMS.get_public_key(KeyId=key_arn)
        if (
            response.get("KeySpec") != "ECC_NIST_P256"
            or response.get("KeyUsage") != "SIGN_VERIFY"
            or "ECDSA_SHA_256" not in response.get("SigningAlgorithms", [])
            or not isinstance(response.get("PublicKey"), bytes)
        ):
            raise RuntimeError("KMS mutation verification key contract drifted")
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        _PUBLIC_KEY = load_der_public_key(response["PublicKey"])
    return _PUBLIC_KEY


def _validate_request(job_id: str, request: Any, now: dt.datetime) -> tuple[dict, dict]:
    if JOB_RE.fullmatch(job_id) is None or not _exact(request, REQUEST_KEYS):
        raise PermissionError("governed mutation envelope is invalid")
    approval = request["approval"]
    arguments = request["arguments"]
    authorization = request["authorization"]
    if (
        request["schemaVersion"] != "archon.core-governed-tag-mutation/v1"
        or not isinstance(request["auditId"], str)
        or AUDIT_RE.fullmatch(request["auditId"]) is None
        or request["action"] not in {"ADD_TAGS", "REMOVE_TAGS"}
        or not _exact(approval, APPROVAL_KEYS)
        or approval["decision"] != "APPROVE"
        or not _exact(arguments, ARGUMENT_KEYS)
        or arguments
        != {
            "tagUrns": [PII_TAG],
            "entityUrns": [DATASET_URN],
            "columnPaths": [COLUMN_PATH],
        }
        or not _exact(authorization, {"envelope", "signature"})
    ):
        raise PermissionError("governed mutation request is outside policy")
    for value in (
        request["runtimeEvidenceDigest"],
        request["auditEvidenceDigest"],
        request["planDigest"],
        request["policyDigest"],
        request["expectedBeforeDigest"],
        request["expectedAfterDigest"],
        request["requestDigest"],
        approval["approverDigest"],
        approval["digest"],
    ):
        if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
            raise PermissionError("governed mutation digest is invalid")
    if (
        not isinstance(approval["approvalId"], str)
        or ID_RE.fullmatch(approval["approvalId"]) is None
        or not isinstance(approval["decidedAt"], str)
        or ISO_RE.fullmatch(approval["decidedAt"]) is None
    ):
        raise PermissionError("approval binding is invalid")
    unsigned = dict(request)
    supplied_request_digest = unsigned.pop("requestDigest")
    if not hmac.compare_digest(supplied_request_digest, _digest(unsigned)):
        raise PermissionError("governed request digest mismatch")

    envelope = authorization["envelope"]
    signature = authorization["signature"]
    _validate_signed_json(envelope)
    if not _exact(envelope, ENVELOPE_KEYS) or not _exact(signature, SIGNATURE_KEYS):
        raise PermissionError("signed authorization schema is invalid")
    expected_tool = "add_tags" if request["action"] == "ADD_TAGS" else "remove_tags"
    expected_signed_arguments = {
        "tag_urns": arguments["tagUrns"],
        "entity_urns": arguments["entityUrns"],
        "column_paths": arguments["columnPaths"],
    }
    if (
        envelope["schemaVersion"] != "archon.core-mutation-authorization/v1"
        or envelope["stage"] != _required("ARCHON_STAGE")
        or envelope["sessionId"] != _required("ARCHON_SESSION_ID")
        or envelope["generation"] != _required("ARCHON_RUNTIME_GENERATION")
        or envelope["capabilityDigest"]
        != _required("ARCHON_RUNTIME_CAPABILITY_DIGEST")
        or envelope["jobId"] != job_id
        or envelope["approvalId"] != approval["approvalId"]
        or envelope["planDigest"] != request["planDigest"]
        or envelope["policyDigest"] != request["policyDigest"]
        or envelope["target"]
        != {"entityUrn": DATASET_URN, "columnPath": COLUMN_PATH}
        or envelope["tool"] != expected_tool
        or not _exact(envelope["arguments"], SIGNED_ARGUMENT_KEYS)
        or envelope["arguments"] != expected_signed_arguments
    ):
        raise PermissionError("signed authorization binding mismatch")
    issued_at = _parse_instant(envelope["issuedAt"])
    expires_at = _parse_instant(envelope["expiresAt"])
    if (
        issued_at > now + dt.timedelta(seconds=30)
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > dt.timedelta(minutes=5)
    ):
        raise PermissionError("signed authorization is expired or overlong")

    key_arn = _required("ARCHON_MUTATION_SIGNING_KEY_ARN")
    envelope_digest = _digest(envelope)
    if (
        signature["keyArn"] != key_arn
        or signature["algorithm"] != "ECDSA_SHA_256"
        or signature["canonicalization"] != "archon.sorted-json-utf8/v1"
        or not isinstance(signature["envelopeDigest"], str)
        or not hmac.compare_digest(signature["envelopeDigest"], envelope_digest)
        or not isinstance(signature["signatureBase64"], str)
        or len(signature["signatureBase64"]) > 256
    ):
        raise PermissionError("mutation signature metadata is invalid")
    try:
        signature_bytes = base64.b64decode(
            signature["signatureBase64"], validate=True
        )
    except (ValueError, TypeError) as error:
        raise PermissionError("mutation signature encoding is invalid") from error
    if not 64 <= len(signature_bytes) <= 80:
        raise PermissionError("mutation signature length is invalid")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        _public_key().verify(
            signature_bytes,
            bytes.fromhex(envelope_digest.removeprefix("sha256:")),
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature as error:
        raise PermissionError("mutation signature verification failed") from error

    lease = _table().get_item(
        Key={"pk": "CORE#LEASE", "sk": "CURRENT"}, ConsistentRead=True
    ).get("Item")
    if (
        not isinstance(lease, dict)
        or lease.get("sessionId") != envelope["sessionId"]
        or lease.get("generation") != envelope["generation"]
        or lease.get("capabilityDigest") != envelope["capabilityDigest"]
        or lease.get("state") != "READY"
        or int(lease.get("hardExpiresAt", 0)) < int(expires_at.timestamp())
    ):
        raise PermissionError("mutation authorization is outside the active lease")
    return envelope, signature


def _consume(job_id: str, envelope: dict[str, Any], now: dt.datetime) -> str:
    consumed_at = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        _table().update_item(
            Key={
                "pk": f"MUTATION#{envelope['sessionId']}",
                "sk": f"JOB#{job_id}",
            },
            UpdateExpression=(
                "SET authorizationConsumedAt=:consumed, "
                "authorizationEnvelopeDigest=:envelopeDigest"
            ),
            ConditionExpression=(
                "#state=:running AND jobId=:job AND sessionId=:session "
                "AND generation=:generation AND capabilityDigest=:capability "
                "AND attribute_not_exists(authorizationConsumedAt)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":consumed": consumed_at,
                ":envelopeDigest": _digest(envelope),
                ":running": "RUNNING",
                ":job": job_id,
                ":session": envelope["sessionId"],
                ":generation": envelope["generation"],
                ":capability": envelope["capabilityDigest"],
            },
        )
    except ClientError as error:
        if (
            error.response.get("Error", {}).get("Code")
            == "ConditionalCheckFailedException"
        ):
            raise PermissionError("mutation authorization was already consumed") from error
        raise
    return consumed_at


def _official_call(tool_name: str, arguments: dict[str, Any]) -> Any:
    if tool_name not in {"get_entities", "add_tags", "remove_tags"}:
        raise RuntimeError("official MCP tool is not allowlisted")

    async def invoke() -> Any:
        from fastmcp import Client

        async with Client(_required("ARCHON_OFFICIAL_WRITER_MCP_URL")) as client:
            response = await client.call_tool(tool_name, arguments)
        if getattr(response, "is_error", False):
            raise RuntimeError("official DataHub MCP tool failed")
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
            raise RuntimeError("official DataHub MCP result schema drift")
        return json.loads(texts[0])

    return asyncio.run(invoke())


def _column_tags(value: Any) -> tuple[bool, set[str]]:
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
        if any(node.get(key) == COLUMN_PATH for key in ("fieldPath", "columnPath", "path")):
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


def _read_state() -> dict[str, Any]:
    raw = _official_call("get_entities", {"urns": [DATASET_URN]})
    found, tags = _column_tags(raw)
    if not found:
        raise RuntimeError("canonical DataHub column was not found")
    state = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": sorted(tags),
    }
    return {**state, "stateDigest": _digest(state)}


def _execute(job_id: str, request: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    envelope, signature = _validate_request(job_id, request, now)
    consumed_at = _consume(job_id, envelope, now)
    with _LOCK:
        before = _read_state()
        if not hmac.compare_digest(
            before["stateDigest"], request["expectedBeforeDigest"]
        ):
            raise RuntimeError("governed mutation before-state drift")
        official_result = _official_call(
            envelope["tool"],
            envelope["arguments"],
        )
        if (
            not isinstance(official_result, dict)
            or official_result.get("success") is not True
        ):
            raise RuntimeError("official DataHub MCP mutation was not confirmed")
        sanitized_official = {
            "success": True,
            "message": str(official_result.get("message", ""))[:512],
        }
        after = _read_state()
        if not hmac.compare_digest(
            after["stateDigest"], request["expectedAfterDigest"]
        ):
            raise RuntimeError("governed mutation after-state drift")
    official_evidence = {
        "tool": envelope["tool"],
        "policyDigest": request["policyDigest"],
        "approvalDigest": request["approval"]["digest"],
        "requestDigest": request["requestDigest"],
        "responseDigest": _digest(sanitized_official),
    }
    authorization_evidence = {
        "keyArn": signature["keyArn"],
        "algorithm": signature["algorithm"],
        "canonicalization": signature["canonicalization"],
        "envelopeDigest": signature["envelopeDigest"],
        "signatureDigest": "sha256:"
        + hashlib.sha256(
            base64.b64decode(signature["signatureBase64"], validate=True)
        ).hexdigest(),
        "consumedAt": consumed_at,
    }
    result = {
        "schemaVersion": "archon.core-governed-gateway-result/v2",
        "success": True,
        "action": request["action"],
        "requestDigest": request["requestDigest"],
        "policyDigest": request["policyDigest"],
        "approvalDigest": request["approval"]["digest"],
        "beforeDigest": before["stateDigest"],
        "afterDigest": after["stateDigest"],
        "changed": before["stateDigest"] != after["stateDigest"],
        "verified": True,
        "mutationExecutor": "official-datahub-mcp",
        "officialMcpMutation": official_evidence,
        "authorizationEvidence": authorization_evidence,
    }
    return {**result, "receiptDigest": _digest(result)}


def build_server() -> Any:
    from fastmcp import FastMCP
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    server = FastMCP("Archon governed official DataHub MCP firewall")

    @server.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @server.tool()
    def execute_governed_mutation(
        job_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        """Verify and consume one off-host KMS-signed mutation authorization."""
        return _execute(job_id, request)

    return server


def main() -> None:
    if os.environ.get("FASTMCP_HOST") != "127.0.0.1":
        raise RuntimeError("governed gateway must bind to loopback")
    if os.environ.get("FASTMCP_PORT") != "8001":
        raise RuntimeError("governed gateway must use its isolated port")
    if os.environ.get("ARCHON_OFFICIAL_WRITER_MCP_URL") != "http://127.0.0.1:8002/mcp":
        raise RuntimeError("official writer MCP must remain on its isolated loopback port")
    _public_key()
    build_server().run(transport="http", host="127.0.0.1", port=8001)


if __name__ == "__main__":
    main()