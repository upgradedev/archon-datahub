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


# __ARCHON_APPEND__
