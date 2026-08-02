"""Hardened, read-only bridge for the complete DataHub agent stack.

The API accepts one configured demo scope and an immutable runtime binding. Analytics
conversation identifiers never leave this process; continuation uses a short-lived
encrypted handle bound to the runtime and evidence digests.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlparse

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from datahub.sdk.main_client import DataHubClient
from datahub_agent_context.context import DataHubContext
from datahub_agent_context.mcp_tools.assertions import get_dataset_assertions
from datahub_agent_context.mcp_tools.entities import get_entities, list_schema_fields
from datahub_agent_context.mcp_tools.lineage import get_lineage
from datahub_agent_context.mcp_tools.search import search

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DATASET_URN = re.compile(r"^urn:li:dataset:.{1,900}$")
RUN_HANDLE = re.compile(r"^run_[A-Za-z0-9_-]{80,2048}$")
FORBIDDEN_KEY = re.compile(
    r"(?:authorization|credential|password|secret|token|endpoint|private.?key)",
    re.IGNORECASE,
)
OFFICIAL_SKILLS = (
    "datahub-search", "datahub-lineage", "datahub-quality",
    "datahub-enrich", "using-datahub",
)
CUSTOM_SKILL = "datahub-audit"
MUTATION_TOOLS = frozenset({
    "publish_analysis", "save_correction", "add_tags", "add_owners",
    "set_domains", "update_description",
})
READ_ONLY_TOOLS = frozenset({
    "execute_sql", "list_tables", "get_schema", "preview_table", "create_chart",
    "search_documents", "grep_documents", "search", "get_entities",
    "list_schema_fields", "get_lineage", "get_dataset_queries",
    "search_business_context",
})
EVENT_TYPES = frozenset({
    "TEXT", "TOOL_CALL", "TOOL_RESULT", "SQL", "CHART", "USAGE", "COMPLETE",
})
MAX_RESPONSE_BYTES = 1_000_000
MAX_EVENTS = 200
MAX_LINES = 1_000
MAX_LINE_BYTES = 65_536
MAX_JSON_BYTES = 262_144
MAX_PROMPT_BYTES = 65_536
MAX_PROMPT_CONTEXT_BYTES = 48_000
QUALITY_ATTEMPTS = 8
QUALITY_DELAY_SECONDS = 0.5


class RuntimeBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schemaVersion: Literal["archon.runtime-binding/v1"]
    profileId: Literal["cloud", "core"]
    generation: str = Field(min_length=1, max_length=128)
    capabilityDigest: str
    resolution: Literal["auto", "explicit"]
    boundAt: datetime
    leaseExpiresAt: datetime


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal["archon.datahub-companion-request/v2"]
    query: str = Field(min_length=1, max_length=256)
    question: str = Field(min_length=1, max_length=512)
    runtimeBinding: RuntimeBinding


class ImproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal["archon.datahub-companion-improve/v2"]
    runHandle: str = Field(min_length=84, max_length=2052)
    runtimeBinding: RuntimeBinding


app = FastAPI(
    title="Archon DataHub Companion", version="0.2.0",
    docs_url=None, redoc_url=None, openapi_url=None,
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def git_blob(data: bytes) -> str:
    payload = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def read_regular(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"{path.name} is not a regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def sanitized(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[depth-limit]"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[non-finite]"
    if isinstance(value, str):
        return value[:2048]
    if isinstance(value, (list, tuple)):
        return [sanitized(item, depth + 1) for item in value[:50]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key in sorted(value, key=str)[:100]:
            key = str(raw_key)[:128]
            if not FORBIDDEN_KEY.search(key):
                result[key] = sanitized(value[raw_key], depth + 1)
        return result
    return str(value)[:512]


def binding_value(binding: RuntimeBinding) -> dict[str, Any]:
    return binding.model_dump(mode="json")


def binding_digest(binding: RuntimeBinding) -> str:
    return digest(binding_value(binding))


def configured_runtime_identity() -> dict[str, str]:
    identity = {
        "profileId": os.environ.get("ARCHON_RUNTIME_PROFILE_ID", ""),
        "generation": os.environ.get("ARCHON_RUNTIME_GENERATION", ""),
        "capabilityDigest": os.environ.get("ARCHON_RUNTIME_CAPABILITY_DIGEST", ""),
    }
    if identity["profileId"] not in {"cloud", "core"}:
        raise RuntimeError("runtime profile is not configured")
    if not GENERATION.fullmatch(identity["generation"]):
        raise RuntimeError("runtime generation is not configured")
    if not DIGEST.fullmatch(identity["capabilityDigest"]):
        raise RuntimeError("runtime capability digest is not configured")
    return identity


def validate_binding(binding: RuntimeBinding) -> None:
    if not GENERATION.fullmatch(binding.generation):
        raise HTTPException(400, "invalid runtime generation")
    if not DIGEST.fullmatch(binding.capabilityDigest):
        raise HTTPException(400, "invalid runtime capability digest")
    if binding.boundAt.tzinfo is None or binding.leaseExpiresAt.tzinfo is None:
        raise HTTPException(400, "runtime instants must be timezone-aware")
    bound = binding.boundAt.astimezone(UTC)
    expires = binding.leaseExpiresAt.astimezone(UTC)
    now = utc_now()
    if bound > now or expires <= now:
        raise HTTPException(409, "runtime binding is not active")
    lease_seconds = (expires - bound).total_seconds()
    if lease_seconds <= 0 or lease_seconds > 7200:
        raise HTTPException(400, "runtime lease is outside policy")
    configured = configured_runtime_identity()
    supplied = {
        "profileId": binding.profileId,
        "generation": binding.generation,
        "capabilityDigest": binding.capabilityDigest,
    }
    if any(
        not hmac.compare_digest(supplied[key], configured[key])
        for key in configured
    ):
        raise HTTPException(409, "runtime binding does not match this isolated runtime")


def exact_public_input(request: AnalyzeRequest) -> None:
    validate_binding(request.runtimeBinding)
    expected_query = os.environ.get("ARCHON_DEMO_QUERY", "")
    expected_question = os.environ.get("ARCHON_ANALYTICS_QUESTION", "")
    if not expected_query or not hmac.compare_digest(request.query, expected_query):
        raise HTTPException(400, "query is outside the configured demo scope")
    if not expected_question or not hmac.compare_digest(
        request.question, expected_question
    ):
        raise HTTPException(400, "question is outside the configured analytics scope")


def datahub_client() -> DataHubClient:
    server = os.environ.get("DATAHUB_GMS_URL", "")
    token = os.environ.get("DATAHUB_GMS_TOKEN", "")
    parsed = urlparse(server)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/", "/gms")
        or parsed.port not in (None, 443, 9443)
    ):
        raise RuntimeError("DATAHUB_GMS_URL is outside the server policy")
    if not token or len(token) > 8192:
        raise RuntimeError("a bounded server-owned DataHub token is required")
    return DataHubClient(server=server.rstrip("/"), token=token)


def test_datahub_connection() -> None:
    result = datahub_client()._graph.test_connection()
    if result is False:
        raise RuntimeError("DataHub connection check failed")


def dataset_urns(search_result: Any) -> list[str]:
    if not isinstance(search_result, dict):
        return []
    selected: set[str] = set()
    results = search_result.get("searchResults")
    if not isinstance(results, list):
        return []
    for entry in results[:50]:
        if not isinstance(entry, dict):
            continue
        entity = entry.get("entity")
        if not isinstance(entity, dict):
            continue
        entity_type = entity.get("type")
        urn = entity.get("urn")
        if (
            isinstance(entity_type, str)
            and entity_type.upper() == "DATASET"
            and isinstance(urn, str)
            and DATASET_URN.fullmatch(urn)
        ):
            selected.add(urn)
    return sorted(selected)[:5]


def tool_receipt(
    name: str,
    arguments: dict[str, Any],
    result: Any,
    status_value: Literal["verified", "unknown"] = "verified",
) -> dict[str, Any]:
    safe_result = sanitized(result)
    return {
        "tool": name,
        "provider": "datahub-agent-context",
        "status": status_value,
        "argumentsDigest": digest(arguments),
        "resultDigest": digest(safe_result),
        "result": safe_result,
    }


def guarded_tool(
    name: str,
    arguments: dict[str, Any],
    operation: Any,
) -> dict[str, Any]:
    try:
        return tool_receipt(name, arguments, operation(**arguments))
    except Exception as error:
        return tool_receipt(
            name,
            arguments,
            {"reason": "tool unavailable", "errorType": type(error).__name__},
            "unknown",
        )


def collect_ack_context(query: str) -> dict[str, Any]:
    receipts: list[dict[str, Any]] = []
    with DataHubContext(datahub_client()):
        search_args = {
            "query": query,
            "filter": "entity_type = dataset",
            "num_results": 5,
        }
        search_result = search(**search_args)
        receipts.append(tool_receipt("search", search_args, search_result))
        selected = dataset_urns(search_result)
        if not selected:
            for name in (
                "get_entities", "list_schema_fields", "get_lineage_upstream",
                "get_lineage_downstream", "get_dataset_assertions",
            ):
                receipts.append(tool_receipt(
                    name, {}, {"reason": "no resolved dataset"}, "unknown",
                ))
        else:
            entity_args = {"urns": selected}
            receipts.append(guarded_tool("get_entities", entity_args, get_entities))
            root = selected[0]
            schema_args = {"urn": root, "limit": 50, "offset": 0}
            receipts.append(
                guarded_tool("list_schema_fields", schema_args, list_schema_fields)
            )
            for upstream, label in (
                (True, "get_lineage_upstream"),
                (False, "get_lineage_downstream"),
            ):
                lineage_args = {
                    "urn": root,
                    "upstream": upstream,
                    "max_hops": 2,
                    "max_results": 30,
                }
                receipts.append(guarded_tool(label, lineage_args, get_lineage))
            quality_args = {"urn": root, "start": 0, "count": 20}
            receipts.append(guarded_tool(
                "get_dataset_assertions", quality_args, get_dataset_assertions,
            ))
    envelope = {
        "schemaVersion": "archon.datahub-context/v2",
        "query": query,
        "entityUrns": selected,
        "receipts": receipts,
        "unknownPreserved": any(r["status"] == "unknown" for r in receipts),
    }
    return {**envelope, "digest": digest(envelope)}


def verify_locked_file(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    data = read_regular(path)
    if (
        len(data) != expected["size"]
        or git_blob(data) != expected["gitBlob"]
        or (
            "sha256" in expected
            and hashlib.sha256(data).hexdigest() != expected["sha256"]
        )
    ):
        raise RuntimeError(f"DataHub Skill drift: {path.name}")
    return {
        "artifactDigest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "gitBlob": expected["gitBlob"],
        "bytes": expected["size"],
    }


def load_skill_receipt() -> dict[str, Any]:
    lock_path = Path(os.environ.get(
        "ARCHON_AGENT_STACK_LOCK",
        "/opt/archon/.github/locks/datahub-agent-stack.json",
    ))
    skills_root = Path(os.environ.get(
        "ARCHON_DATAHUB_SKILLS_DIR", "/opt/archon/datahub-skills",
    ))
    custom_root = Path(os.environ.get(
        "ARCHON_CUSTOM_SKILLS_DIR", "/opt/archon/contrib",
    ))
    lock = json.loads(read_regular(lock_path))
    if lock.get("schemaVersion") != "archon.datahub-agent-stack-lock/v1":
        raise RuntimeError("agent stack lock schema drift")
    component = lock["components"]["dataHubSkills"]
    official: list[dict[str, Any]] = []
    for skill in OFFICIAL_SKILLS:
        relative = f"skills/{skill}/SKILL.md"
        verified = verify_locked_file(
            skills_root / relative, component["files"][relative],
        )
        official.append({"skill": skill, **verified})
    custom_relative = "contrib/datahub-audit/SKILL.md"
    custom = verify_locked_file(
        custom_root / "datahub-audit" / "SKILL.md",
        component["customFiles"][custom_relative],
    )
    receipt = {
        "schemaVersion": "archon.datahub-skills-receipt/v2",
        "sourceCommit": component["source"]["commit"],
        "official": official,
        "custom": [{"skill": CUSTOM_SKILL, **custom}],
        "workflow": [
            "datahub-search", "datahub-lineage", "datahub-quality",
            "datahub-audit", "datahub-enrich",
        ],
        "mutationAuthority": "archon-remediation-worker",
    }
    return {**receipt, "digest": digest(receipt)}


def ground_skills(
    skills: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    receipt_digests = {
        receipt["tool"]: receipt["resultDigest"] for receipt in context["receipts"]
    }
    by_skill = {
        "datahub-search": ("search", "get_entities", "list_schema_fields"),
        "datahub-lineage": ("get_lineage_upstream", "get_lineage_downstream"),
        "datahub-quality": ("get_dataset_assertions",),
        "datahub-audit": tuple(receipt_digests),
        "datahub-enrich": tuple(receipt_digests),
        "using-datahub": tuple(receipt_digests),
    }
    artifacts = {
        item["skill"]: item["artifactDigest"]
        for item in skills["official"] + skills["custom"]
    }
    grounding = [{
        "skill": name,
        "sourceArtifactDigest": artifacts[name],
        "ackReceiptDigests": [
            receipt_digests[tool] for tool in by_skill[name]
            if tool in receipt_digests
        ],
        "mode": "read-only" if name != "datahub-enrich" else "preview-only",
    } for name in (*OFFICIAL_SKILLS, CUSTOM_SKILL)]
    envelope = {
        "schemaVersion": "archon.datahub-skill-grounding/v1",
        "contextDigest": context["digest"],
        "receipts": grounding,
    }
    return {**envelope, "digest": digest(envelope)}


def analytics_url() -> str:
    configured = os.environ.get(
        "ARCHON_ANALYTICS_AGENT_URL", "http://analytics-agent:8100",
    )
    parsed = urlparse(configured)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"analytics-agent", "127.0.0.1", "localhost"}
        or parsed.port != 8100
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("Analytics Agent URL is outside the private allowlist")
    return configured.rstrip("/")


def analytics_client(timeout: httpx.Timeout) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=analytics_url(),
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    )


async def bounded_json(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
) -> Any:
    request = client.build_request(method, path, json=body)
    response = await client.send(request, stream=True)
    try:
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError("Analytics Agent returned a non-success status")
        media_type = response.headers.get("content-type", "").split(";", 1)[0]
        if media_type != "application/json":
            raise RuntimeError("Analytics Agent returned an unexpected media type")
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise RuntimeError("Analytics Agent JSON exceeded policy")
            chunks.append(chunk)
        return json.loads(b"".join(chunks))
    finally:
        await response.aclose()


def validate_connections(
    connections: Any,
    engine_name: str,
) -> dict[str, Any]:
    if not isinstance(connections, list) or len(connections) > 100:
        raise RuntimeError("Analytics Agent connection inventory drift")
    active_datahub: list[str] = []
    engine_connected = False
    for item in connections:
        if not isinstance(item, dict):
            raise RuntimeError("Analytics Agent connection schema drift")
        name = item.get("name")
        connection_type = item.get("type")
        active = item.get("status") == "connected" and item.get("disabled") is False
        if name == engine_name and active:
            engine_connected = True
        if connection_type not in {"datahub", "datahub-mcp"} or not active:
            continue
        tools = item.get("tools")
        if not isinstance(tools, list):
            raise RuntimeError("DataHub mutation policy is not observable")
        toggles: dict[str, bool] = {}
        for tool in tools:
            if not isinstance(tool, dict):
                raise RuntimeError("DataHub tool policy schema drift")
            tool_name = tool.get("name")
            enabled = tool.get("enabled")
            if isinstance(tool_name, str) and isinstance(enabled, bool):
                toggles[tool_name] = enabled
        for mutation in ("publish_analysis", "save_correction"):
            if mutation not in toggles or toggles[mutation] is not False:
                raise RuntimeError("Analytics Agent mutation tools are not disabled")
        active_datahub.append(str(name))
    if not active_datahub:
        raise RuntimeError("no connected DataHub context platform")
    if not engine_connected:
        raise RuntimeError("configured Analytics engine is not connected")
    return {
        "activeDataHubConnections": sorted(active_datahub),
        "engineName": engine_name,
        "mutationTools": {
            "publish_analysis": False,
            "save_correction": False,
        },
    }


async def analytics_preflight() -> dict[str, Any]:
    engine_name = os.environ.get("ARCHON_ANALYTICS_ENGINE", "")
    if not GENERATION.fullmatch(engine_name):
        raise RuntimeError("Analytics engine is not configured")
    async with analytics_client(httpx.Timeout(10.0, connect=3.0)) as client:
        health, engines, connections = await asyncio.gather(
            bounded_json(client, "GET", "/health"),
            bounded_json(client, "GET", "/api/engines"),
            bounded_json(client, "GET", "/api/settings/connections"),
        )
    if health != {"status": "ok"}:
        raise RuntimeError("Analytics Agent health contract drift")
    if not isinstance(engines, list) or len(engines) > 100:
        raise RuntimeError("Analytics Agent engine inventory drift")
    matching = [
        item for item in engines
        if isinstance(item, dict)
        and item.get("name") == engine_name
        and isinstance(item.get("type"), str)
        and item["type"]
    ]
    if len(matching) != 1:
        raise RuntimeError("configured Analytics engine is unavailable")
    policy = validate_connections(connections, engine_name)
    receipt = {
        "schemaVersion": "archon.analytics-agent-preflight/v1",
        "status": "verified",
        "health": "ok",
        "engine": {"name": engine_name, "type": matching[0]["type"]},
        **policy,
    }
    return {**receipt, "digest": digest(receipt)}


def canonical_conversation_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise RuntimeError("Analytics Agent returned an invalid conversation id")
    try:
        canonical_id = str(uuid.UUID(value))
    except ValueError as error:
        raise RuntimeError(
            "Analytics Agent returned an invalid conversation id"
        ) from error
    if canonical_id != value:
        raise RuntimeError("Analytics Agent conversation id is not canonical")
    return canonical_id


def safe_conversation_path(conversation_id: str, suffix: str) -> str:
    canonical_id = canonical_conversation_id(conversation_id)
    return f"/api/conversations/{quote(canonical_id, safe='')}/{suffix}"


def project_event(
    event: Any,
    conversation_id: str,
    *,
    complete_seen: bool,
) -> tuple[dict[str, Any] | None, bool]:
    if not isinstance(event, dict) or not set(event).issubset(
        {"event", "conversation_id", "message_id", "payload"}
    ):
        raise RuntimeError("Analytics Agent event schema drift")
    event_type = event.get("event")
    if event_type == "KEEPALIVE":
        if set(event) != {"event"}:
            raise RuntimeError("Analytics Agent keepalive schema drift")
        return None, complete_seen
    if event_type == "ERROR":
        raise RuntimeError("Analytics Agent reported an error")
    if event_type not in EVENT_TYPES or complete_seen:
        raise RuntimeError("Analytics Agent emitted an unexpected event")
    if event.get("conversation_id") != conversation_id:
        raise RuntimeError("Analytics Agent conversation binding drift")
    payload = event.get("payload")
    if not isinstance(payload, dict):
        raise RuntimeError("Analytics Agent event payload drift")
    if event_type in {"TOOL_CALL", "TOOL_RESULT"}:
        tool_name = payload.get("tool_name")
        if tool_name in MUTATION_TOOLS:
            raise RuntimeError("Analytics Agent attempted a mutation")
        if tool_name not in READ_ONLY_TOOLS:
            raise RuntimeError("Analytics Agent invoked an unreviewed tool")
    return {
        "event": event_type,
        "payload": sanitized(payload),
    }, event_type == "COMPLETE"


# __ARCHON_APPEND__
