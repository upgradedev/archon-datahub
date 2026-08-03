"""Bounded Streamable HTTP client for the managed DataHub Cloud MCP server."""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet

from contracts import (
    COLUMN_PATH,
    ContractError,
    DATASET_URN,
    PII_TAG,
    TAG_RE,
    canonical_json,
    digest,
)

MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_PATH = "/integrations/ai/mcp"
TENANT_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.acryl\.io$"
)
SESSION_RE = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")
TOOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
READ_TOOLS = frozenset({"get_entities", "list_schema_fields"})
WRITE_TOOLS = frozenset({"add_tags", "remove_tags"})
MAX_RESPONSE = 512 * 1024
MAX_TOOLS = 128
MAX_PAGES = 4


@dataclasses.dataclass(frozen=True)
class ManagedCredential:
    gms_url: str
    endpoint: str
    token: str
    run_handle_key: str | None = None
    oauth_master_key: str | None = None


def derive_endpoint(gms_url: Any) -> str:
    if not isinstance(gms_url, str) or not 1 <= len(gms_url) <= 2048:
        raise ContractError("cloud_tenant_url_invalid")
    try:
        parsed = urlparse(gms_url)
        port = parsed.port
    except ValueError as error:
        raise ContractError("cloud_tenant_url_invalid") from error
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or port not in {None, 443}
        or not isinstance(host, str)
        or TENANT_RE.fullmatch(host) is None
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/", "/gms"}
    ):
        raise ContractError("cloud_tenant_url_invalid")
    return f"https://{host}{MCP_PATH}"


def _fernet(value: Any, code: str) -> str:
    if not isinstance(value, str) or len(value) != 44:
        raise ContractError(code)
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii"))
        Fernet(value.encode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise ContractError(code) from error
    if len(decoded) != 32:
        raise ContractError(code)
    return value


def parse_managed_secret(payload: Any, *, purpose: Literal["reader", "writer"]) -> ManagedCredential:
    if not isinstance(payload, dict):
        raise ContractError("cloud_secret_invalid")
    reader_keys = {
        "schemaVersion", "gmsUrl", "token", "runHandleFernetKey",
        "oauthMasterKey",
    }
    writer_keys = {"schemaVersion", "gmsUrl", "token"}
    expected = reader_keys if purpose == "reader" else writer_keys
    schema = (
        "archon.datahub-cloud-reader-secret/v1"
        if purpose == "reader"
        else "archon.datahub-cloud-writer-secret/v1"
    )
    token = payload.get("token")
    if (
        set(payload) != expected
        or payload.get("schemaVersion") != schema
        or not isinstance(token, str)
        or not 16 <= len(token) <= 8192
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in token)
    ):
        raise ContractError("cloud_secret_invalid")
    endpoint = derive_endpoint(payload["gmsUrl"])
    if purpose == "reader":
        return ManagedCredential(
            gms_url=payload["gmsUrl"],
            endpoint=endpoint,
            token=token,
            run_handle_key=_fernet(
                payload["runHandleFernetKey"], "run_handle_key_invalid"
            ),
            oauth_master_key=_fernet(
                payload["oauthMasterKey"], "oauth_master_key_invalid"
            ),
        )
    return ManagedCredential(
        gms_url=payload["gmsUrl"], endpoint=endpoint, token=token
    )


def _decode_response(data: bytes, media_type: str, request_id: int) -> Any:
    if media_type == "application/json":
        try:
            message = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ContractError("mcp_response_invalid") from error
    elif media_type == "text/event-stream":
        try:
            text = data.decode("utf-8", errors="strict").replace("\r\n", "\n")
        except UnicodeDecodeError as error:
            raise ContractError("mcp_response_invalid") from error
        if "\r" in text or not (text.endswith("\n\n") or not text):
            raise ContractError("mcp_response_invalid")
        messages: list[Any] = []
        for block in text.split("\n\n"):
            if not block:
                continue
            payloads: list[str] = []
            for line in block.split("\n"):
                if line.startswith(":"):
                    continue
                field, separator, value = line.partition(":")
                if separator and value.startswith(" "):
                    value = value[1:]
                if field == "event" and value != "message":
                    raise ContractError("mcp_response_invalid")
                if field == "data":
                    payloads.append(value)
                elif field != "event":
                    raise ContractError("mcp_response_invalid")
            if payloads:
                try:
                    messages.append(json.loads("\n".join(payloads)))
                except json.JSONDecodeError as error:
                    raise ContractError("mcp_response_invalid") from error
        if len(messages) != 1:
            raise ContractError("mcp_response_invalid")
        message = messages[0]
    else:
        raise ContractError("mcp_media_type_invalid")
    if (
        not isinstance(message, dict)
        or message.get("jsonrpc") != "2.0"
        or type(message.get("id")) is not int
        or message.get("id") != request_id
        or "error" in message
        or "result" not in message
    ):
        raise ContractError("mcp_rpc_failed")
    return message["result"]


class ManagedMcpClient:
    def __init__(self, credential: ManagedCredential, *, timeout_seconds: float = 30.0):
        self.credential = credential
        self._parsed = urlparse(credential.endpoint)
        self._timeout = httpx.Timeout(timeout_seconds, connect=3.0)
        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._next_id = 1
        self._inventory: dict[str, dict[str, Any]] = {}

    async def __aenter__(self) -> "ManagedMcpClient":
        self._client = httpx.AsyncClient(
            base_url=f"https://{self._parsed.hostname}",
            headers={"Authorization": f"Bearer {self.credential.token}"},
            timeout=self._timeout,
            trust_env=False,
            follow_redirects=False,
        )
        try:
            initialized = await self._rpc(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "archon-datahub-cloud-runtime",
                        "version": "2.0.0",
                    },
                },
            )
            if (
                not isinstance(initialized, dict)
                or initialized.get("protocolVersion") != MCP_PROTOCOL_VERSION
                or not isinstance(initialized.get("capabilities"), dict)
                or not isinstance(initialized["capabilities"].get("tools"), dict)
            ):
                raise ContractError("mcp_initialize_invalid")
            await self._initialized()
            await self._load_inventory()
            return self
        except BaseException:
            await self._client.aclose()
            self._client = None
            self._session_id = None
            self._inventory = {}
            raise

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        close_error: BaseException | None = None
        try:
            if self._client is not None and self._session_id is not None:
                request = self._client.build_request(
                    "DELETE",
                    MCP_PATH,
                    headers={
                        "Mcp-Session-Id": self._session_id,
                        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                    },
                )
                response = await self._client.send(request, stream=True)
                try:
                    await self._bounded(response)
                    if response.status_code not in {200, 202, 204, 404, 405}:
                        raise ContractError("mcp_session_close_failed")
                finally:
                    await response.aclose()
        except BaseException as error:
            close_error = error
        finally:
            if self._client is not None:
                await self._client.aclose()
            self._client = None
            self._session_id = None
            self._inventory = {}
        if close_error is not None and exc_type is None:
            raise close_error

    def _headers(
        self,
        *,
        method: str | None = None,
        notification: bool = False,
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if method != "initialize" and (self._next_id > 1 or notification):
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    async def _bounded(self, response: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE:
                raise ContractError("mcp_response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _rpc(self, method: str, params: dict[str, Any]) -> Any:
        if self._client is None or method not in {"initialize", "tools/list", "tools/call"}:
            raise ContractError("mcp_rpc_invalid")
        request_id = self._next_id
        self._next_id += 1
        request = self._client.build_request(
            "POST",
            MCP_PATH,
            headers=self._headers(method=method),
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
        )
        response = await self._client.send(request, stream=True)
        try:
            data = await self._bounded(response)
            if not 200 <= response.status_code < 300:
                raise ContractError("mcp_non_success")
            assigned = response.headers.get("mcp-session-id")
            if assigned is not None and SESSION_RE.fullmatch(assigned) is None:
                raise ContractError("mcp_session_invalid")
            if method == "initialize":
                self._session_id = assigned
            elif assigned is not None and assigned != self._session_id:
                raise ContractError("mcp_session_mismatch")
            media = response.headers.get("content-type", "").split(";", 1)[0]
            return _decode_response(data, media, request_id)
        finally:
            await response.aclose()

    async def _initialized(self) -> None:
        if self._client is None:
            raise ContractError("mcp_rpc_invalid")
        request = self._client.build_request(
            "POST",
            MCP_PATH,
            headers=self._headers(notification=True),
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        response = await self._client.send(request, stream=True)
        try:
            data = await self._bounded(response)
            if response.status_code not in {202, 204} or data:
                raise ContractError("mcp_initialized_invalid")
        finally:
            await response.aclose()

    async def _load_inventory(self) -> None:
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            result = await self._rpc(
                "tools/list", {} if cursor is None else {"cursor": cursor}
            )
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise ContractError("mcp_inventory_invalid")
            for tool in result["tools"]:
                if not isinstance(tool, dict):
                    raise ContractError("mcp_inventory_invalid")
                name = tool.get("name")
                annotations = tool.get("annotations")
                if (
                    not isinstance(name, str)
                    or TOOL_RE.fullmatch(name) is None
                    or name in self._inventory
                    or not isinstance(annotations, dict)
                ):
                    raise ContractError("mcp_inventory_invalid")
                self._inventory[name] = {
                    "readOnlyHint": annotations.get("readOnlyHint"),
                    "destructiveHint": annotations.get("destructiveHint"),
                }
                if len(self._inventory) > MAX_TOOLS:
                    raise ContractError("mcp_inventory_too_large")
            cursor = result.get("nextCursor")
            if cursor is None:
                return
            if (
                not isinstance(cursor, str)
                or not 1 <= len(cursor) <= 512
                or cursor in seen
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in cursor)
            ):
                raise ContractError("mcp_inventory_invalid")
            seen.add(cursor)
        raise ContractError("mcp_inventory_too_large")

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool not in READ_TOOLS | WRITE_TOOLS or not isinstance(arguments, dict):
            raise ContractError("mcp_tool_denied")
        annotation = self._inventory.get(tool)
        if not isinstance(annotation, dict):
            raise ContractError("mcp_tool_unavailable")
        if tool in READ_TOOLS and (
            annotation.get("readOnlyHint") is not True
            or annotation.get("destructiveHint") is not False
        ):
            raise ContractError("mcp_read_annotation_invalid")
        if tool in WRITE_TOOLS and annotation.get("readOnlyHint") is not False:
            raise ContractError("mcp_write_annotation_invalid")
        result = await self._rpc(
            "tools/call", {"name": tool, "arguments": arguments}
        )
        if (
            not isinstance(result, dict)
            or result.get("isError", False) is not False
            or not isinstance(result.get("content"), list)
            or not 1 <= len(result["content"]) <= 64
            or len(canonical_json(result)) > MAX_RESPONSE
        ):
            raise ContractError("mcp_tool_result_invalid")
        for item in result["content"]:
            if (
                not isinstance(item, dict)
                or item.get("type") != "text"
                or not isinstance(item.get("text"), str)
            ):
                raise ContractError("mcp_tool_result_invalid")
        return result


def _structured_payloads(result: dict[str, Any]) -> list[Any]:
    payloads: list[Any] = []
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        payloads.append(structured)
    for item in result["content"]:
        try:
            payloads.append(json.loads(item["text"]))
        except (json.JSONDecodeError, TypeError):
            continue
    if not payloads:
        raise ContractError("mcp_structured_result_required")
    return payloads


def _subtree_strings(value: Any, *, limit: list[int]) -> set[str]:
    limit[0] += 1
    if limit[0] > 20_000:
        raise ContractError("mcp_tag_result_too_large")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        values: set[str] = set()
        for item in value:
            values.update(_subtree_strings(item, limit=limit))
        return values
    if isinstance(value, dict):
        values = set()
        for key, item in value.items():
            values.add(str(key))
            values.update(_subtree_strings(item, limit=limit))
        return values
    return set()


def _column_scopes(value: Any, *, visited: list[int]) -> list[Any]:
    visited[0] += 1
    if visited[0] > 20_000:
        raise ContractError("mcp_tag_result_too_large")
    scopes: list[Any] = []
    if isinstance(value, list):
        for item in value:
            scopes.extend(_column_scopes(item, visited=visited))
        return scopes
    if not isinstance(value, dict):
        return scopes
    direct_match = any(
        key in {"fieldPath", "field_path", "path", "name"}
        and item == COLUMN_PATH
        for key, item in value.items()
    )
    for key, item in value.items():
        if key == COLUMN_PATH:
            scopes.append(item)
        scopes.extend(_column_scopes(item, visited=visited))
    if direct_match:
        scopes.append(value)
    return scopes


def extract_column_tags(result: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    for payload in _structured_payloads(result):
        for scope in _column_scopes(payload, visited=[0]):
            found.update(
                item
                for item in _subtree_strings(scope, limit=[0])
                if TAG_RE.fullmatch(item)
            )
    return sorted(found)


async def read_column_tags(credential: ManagedCredential) -> dict[str, Any]:
    entity_args = {"urns": [DATASET_URN]}
    field_args = {
        "urn": DATASET_URN,
        "keywords": [COLUMN_PATH],
        "limit": 50,
        "offset": 0,
    }
    async with ManagedMcpClient(credential) as client:
        entity_result = await client.call("get_entities", entity_args)
        field_result = await client.call("list_schema_fields", field_args)
    tags = extract_column_tags(field_result)
    state = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": tags,
    }
    result = {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **state,
        "stateDigest": digest(state),
    }
    proof = {
        "schemaVersion": "archon.datahub-cloud-tag-read-proof/v1",
        "tools": ["get_entities", "list_schema_fields"],
        "argumentsDigests": [digest(entity_args), digest(field_args)],
        "responseDigests": [digest(entity_result), digest(field_result)],
        "providerPayloadStored": False,
    }
    return {**result, "_proof": {**proof, "digest": digest(proof)}}


async def mutate_tags(
    credential: ManagedCredential,
    *,
    tool: Literal["add_tags", "remove_tags"],
) -> dict[str, Any]:
    if tool not in WRITE_TOOLS:
        raise ContractError("mcp_tool_denied")
    arguments = {
        "tag_urns": [PII_TAG],
        "entity_urns": [DATASET_URN],
        "column_paths": [COLUMN_PATH],
    }
    async with ManagedMcpClient(credential) as client:
        result = await client.call(tool, arguments)
    receipt = {
        "schemaVersion": "archon.official-datahub-mcp-mutation/v1",
        "tool": tool,
        "argumentsDigest": digest(arguments),
        "responseDigest": digest(result),
        "providerPayloadStored": False,
    }
    return {**receipt, "digest": digest(receipt)}
