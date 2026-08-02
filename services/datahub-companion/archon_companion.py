"""Private bridge joining ACK, official Skills, and Analytics Agent.

The bridge accepts only the single server-configured judge query and question. It never
accepts endpoints, credentials, mutation tools, or an unbound runtime from a caller.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from datahub.sdk.main_client import DataHubClient
from datahub_agent_context.context import DataHubContext
from datahub_agent_context.mcp_tools.assertions import get_dataset_assertions
from datahub_agent_context.mcp_tools.entities import get_entities, list_schema_fields
from datahub_agent_context.mcp_tools.lineage import get_lineage
from datahub_agent_context.mcp_tools.search import search

DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
FORBIDDEN_KEY = re.compile(
    r"(?:authorization|credential|password|secret|token|endpoint|private.?key)",
    re.IGNORECASE,
)
URN = re.compile(r"^urn:li:[A-Za-z0-9_-]+:.{1,900}$")
REQUIRED_SKILLS = (
    "datahub-search",
    "datahub-lineage",
    "datahub-quality",
    "datahub-enrich",
    "using-datahub",
)
MAX_RESPONSE_BYTES = 1_000_000
MAX_EVENTS = 200


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

    schemaVersion: Literal["archon.datahub-companion-request/v1"]
    query: str = Field(min_length=1, max_length=256)
    question: str = Field(min_length=1, max_length=512)
    runtimeBinding: RuntimeBinding


class ImproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["archon.datahub-companion-improve/v1"]
    conversationId: str = Field(pattern=r"^[0-9a-f-]{36}$")
    runtimeBinding: RuntimeBinding


app = FastAPI(
    title="Archon DataHub Companion",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def git_blob(data: bytes) -> str:
    payload = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def sanitized(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "[depth-limit]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2048]
    if isinstance(value, list):
        return [sanitized(item, depth + 1) for item in value[:50]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key in sorted(value, key=str)[:100]:
            key = str(raw_key)
            if FORBIDDEN_KEY.search(key):
                continue
            result[key[:128]] = sanitized(value[raw_key], depth + 1)
        return result
    return str(value)[:512]


def validate_binding(binding: RuntimeBinding) -> None:
    if not GENERATION.fullmatch(binding.generation):
        raise HTTPException(400, "invalid runtime generation")
    if not DIGEST.fullmatch(binding.capabilityDigest):
        raise HTTPException(400, "invalid runtime capability digest")
    now = datetime.now(UTC)
    if binding.boundAt.tzinfo is None or binding.leaseExpiresAt.tzinfo is None:
        raise HTTPException(400, "runtime instants must be timezone-aware")
    if binding.boundAt > now or binding.leaseExpiresAt <= now:
        raise HTTPException(409, "runtime binding is not active")
    if (binding.leaseExpiresAt - binding.boundAt).total_seconds() > 7200:
        raise HTTPException(400, "runtime lease exceeds the two-hour ceiling")


def exact_public_input(request: AnalyzeRequest) -> None:
    validate_binding(request.runtimeBinding)
    expected_query = os.environ.get("ARCHON_DEMO_QUERY", "")
    expected_question = os.environ.get("ARCHON_ANALYTICS_QUESTION", "")
    if not expected_query or request.query != expected_query:
        raise HTTPException(400, "query is outside the configured demo scope")
    if not expected_question or request.question != expected_question:
        raise HTTPException(400, "question is outside the configured analytics scope")


def datahub_client() -> DataHubClient:
    server = os.environ.get("DATAHUB_GMS_URL", "")
    token = os.environ.get("DATAHUB_GMS_TOKEN", "")
    parsed = urlparse(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeError("DATAHUB_GMS_URL must be a server-owned HTTPS endpoint")
    if not token or len(token) > 8192:
        raise RuntimeError("a bounded server-owned DataHub token is required")
    return DataHubClient(server=server, token=token)


def collect_urns(value: Any, output: set[str]) -> None:
    if isinstance(value, str) and URN.fullmatch(value):
        output.add(value)
    elif isinstance(value, list):
        for item in value[:100]:
            collect_urns(item, output)
    elif isinstance(value, dict):
        for item in list(value.values())[:200]:
            collect_urns(item, output)


def tool_receipt(
    name: str,
    arguments: dict[str, Any],
    result: Any,
    status: Literal["verified", "unknown"] = "verified",
) -> dict[str, Any]:
    safe_result = sanitized(result)
    return {
        "tool": name,
        "provider": "datahub-agent-context",
        "status": status,
        "argumentsDigest": digest(arguments),
        "resultDigest": digest(safe_result),
        "result": safe_result,
    }


def collect_ack_context(query: str) -> dict[str, Any]:
    receipts: list[dict[str, Any]] = []
    with DataHubContext(datahub_client()):
        search_args = {"query": query, "num_results": 5}
        search_result = search(**search_args)
        receipts.append(tool_receipt("search", search_args, search_result))
        urns: set[str] = set()
        collect_urns(search_result, urns)
        selected = sorted(urns)[:5]
        if not selected:
            for name in (
                "get_entities",
                "list_schema_fields",
                "get_lineage_upstream",
                "get_lineage_downstream",
                "get_dataset_assertions",
            ):
                receipts.append(
                    tool_receipt(name, {}, {"reason": "no resolved dataset"}, "unknown")
                )
        else:
            entity_args = {"urns": selected}
            receipts.append(
                tool_receipt(
                    "get_entities",
                    entity_args,
                    get_entities(**entity_args),
                )
            )
            root = selected[0]
            schema_args = {"urn": root, "limit": 50, "offset": 0}
            receipts.append(
                tool_receipt(
                    "list_schema_fields",
                    schema_args,
                    list_schema_fields(**schema_args),
                )
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
                receipts.append(
                    tool_receipt(
                        label,
                        lineage_args,
                        get_lineage(**lineage_args),
                    )
                )
            quality_args = {"urn": root, "start": 0, "count": 20}
            receipts.append(
                tool_receipt(
                    "get_dataset_assertions",
                    quality_args,
                    get_dataset_assertions(**quality_args),
                )
            )
    envelope = {
        "schemaVersion": "archon.datahub-context/v1",
        "query": query,
        "entityUrns": sorted(urns)[:20],
        "receipts": receipts,
        "unknownPreserved": any(
            receipt["status"] == "unknown" for receipt in receipts
        ),
    }
    return {**envelope, "digest": digest(envelope)}


def load_skill_receipt() -> dict[str, Any]:
    lock_path = Path(
        os.environ.get(
            "ARCHON_AGENT_STACK_LOCK",
            "/opt/archon/.github/locks/datahub-agent-stack.json",
        )
    )
    skills_root = Path(
        os.environ.get("ARCHON_DATAHUB_SKILLS_DIR", "/opt/archon/datahub-skills")
    )
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    component = lock["components"]["dataHubSkills"]
    loaded: list[dict[str, Any]] = []
    for skill in REQUIRED_SKILLS:
        path = skills_root / "skills" / skill / "SKILL.md"
        data = path.read_bytes()
        relative = f"skills/{skill}/SKILL.md"
        expected = component["files"][relative]
        if len(data) != expected["size"] or git_blob(data) != expected["gitBlob"]:
            raise RuntimeError(f"official DataHub Skill drift: {skill}")
        loaded.append(
            {
                "skill": skill,
                "gitBlob": expected["gitBlob"],
                "bytes": expected["size"],
            }
        )
    receipt = {
        "schemaVersion": "archon.datahub-skills-receipt/v1",
        "sourceCommit": component["source"]["commit"],
        "skills": loaded,
        "workflow": [
            "datahub-search",
            "datahub-lineage",
            "datahub-quality",
            "datahub-audit",
            "datahub-enrich",
        ],
        "mutationAuthority": "archon-remediation-worker",
    }
    return {**receipt, "digest": digest(receipt)}


def analytics_url() -> str:
    configured = os.environ.get(
        "ARCHON_ANALYTICS_AGENT_URL",
        "http://analytics-agent:8100",
    )
    parsed = urlparse(configured)
    allowed_hosts = {"analytics-agent", "127.0.0.1", "localhost"}
    if (
        parsed.scheme != "http"
        or parsed.hostname not in allowed_hosts
        or parsed.port != 8100
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
    ):
        raise RuntimeError("Analytics Agent URL is outside the private allowlist")
    return configured.rstrip("/")


async def analytics_turn(conversation_id: str, text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    byte_count = 0
    timeout = httpx.Timeout(180.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream(
            "POST",
            f"{analytics_url()}/api/conversations/{conversation_id}/messages",
            json={"text": text},
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                byte_count += len(line.encode("utf-8"))
                if byte_count > MAX_RESPONSE_BYTES or len(events) >= MAX_EVENTS:
                    raise RuntimeError("Analytics Agent response exceeded policy")
                if not line.startswith("data:"):
                    continue
                raw = line[5:].strip()
                if not raw:
                    continue
                event = json.loads(raw)
                safe = sanitized(event)
                if isinstance(safe, dict):
                    events.append(safe)
                if event.get("event") == "COMPLETE":
                    break
    if not events or events[-1].get("event") != "COMPLETE":
        raise RuntimeError("Analytics Agent did not complete")
    return events


async def run_analytics(question: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as client:
        created = await client.post(
            f"{analytics_url()}/api/conversations",
            json={
                "title": "Archon governed judge analysis",
                "engine_name": os.environ.get(
                    "ARCHON_ANALYTICS_ENGINE",
                    "archon-judge",
                ),
            },
        )
        created.raise_for_status()
        conversation = created.json()
    conversation_id = str(conversation["id"])
    events = await analytics_turn(conversation_id, question)
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0)) as client:
        quality_response = await client.get(
            f"{analytics_url()}/api/conversations/{conversation_id}/quality"
        )
        quality_response.raise_for_status()
        quality = sanitized(quality_response.json())
    projection = {
        "schemaVersion": "archon.analytics-agent-result/v1",
        "conversationId": conversation_id,
        "events": events,
        "contextQuality": quality,
        "mutationsEnabled": False,
        "improveContextCommandAvailable": True,
    }
    return {**projection, "digest": digest(projection)}


@app.get("/healthz")
async def health() -> dict[str, Any]:
    try:
        skills = load_skill_receipt()
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{analytics_url()}/health")
            analytics_ready = response.status_code == 200
    except Exception:
        analytics_ready = False
        skills = None
    return {
        "status": "ready" if analytics_ready and skills else "starting",
        "components": {
            "agentContextKit": True,
            "dataHubSkills": skills is not None,
            "analyticsAgent": analytics_ready,
        },
    }


@app.post("/v1/analyze")
async def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    exact_public_input(request)
    try:
        context, skills = await asyncio.gather(
            asyncio.to_thread(collect_ack_context, request.query),
            asyncio.to_thread(load_skill_receipt),
        )
        analytics = await run_analytics(request.question)
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as error:
        raise HTTPException(503, "DataHub companion is not ready") from error
    result = {
        "schemaVersion": "archon.datahub-agent-stack-result/v1",
        "runtimeBinding": request.runtimeBinding.model_dump(mode="json"),
        "context": context,
        "skills": skills,
        "analytics": analytics,
        "enrichment": {
            "status": "preview-only",
            "writeAuthority": "archon-remediation-worker",
            "requiresFreshDigestBoundApproval": True,
        },
    }
    return {**result, "digest": digest(result)}


@app.post("/v1/improve-context")
async def improve_context(request: ImproveRequest) -> dict[str, Any]:
    validate_binding(request.runtimeBinding)
    try:
        events = await analytics_turn(request.conversationId, "/improve-context")
    except (httpx.HTTPError, OSError, RuntimeError, ValueError) as error:
        raise HTTPException(503, "Analytics Agent is not ready") from error
    result = {
        "schemaVersion": "archon.datahub-improve-context/v1",
        "runtimeBinding": request.runtimeBinding.model_dump(mode="json"),
        "conversationId": request.conversationId,
        "events": events,
        "status": "proposal-only",
        "writeAuthority": "archon-remediation-worker",
        "requiresFreshDigestBoundApproval": True,
    }
    return {**result, "digest": digest(result)}
