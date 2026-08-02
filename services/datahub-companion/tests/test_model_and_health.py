from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

import archon_companion as companion


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
CAPABILITY = "sha256:" + "a" * 64
CONTEXT = "sha256:" + "b" * 64
GROUNDING = "sha256:" + "c" * 64
CONVERSATION = "12345678-1234-4234-8234-123456789abc"
MODEL = "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)


def official_mcp_reads() -> dict:
    receipts = [
        {
            "tool": name,
            "status": "verified",
            "digest": companion.digest({"tool": name, "status": "verified"}),
        }
        for name in companion.MCP_CANONICAL_READ_TOOLS
    ]
    envelope = {
        "schemaVersion": "archon.official-datahub-mcp-read-receipts/v1",
        "status": "verified",
        "sequence": list(companion.MCP_CANONICAL_READ_TOOLS),
        "receipts": receipts,
        "providerPayloadStored": False,
        "mutationsEnabled": False,
    }
    return {**envelope, "digest": companion.digest(envelope)}


def runtime_binding() -> companion.RuntimeBinding:
    return companion.RuntimeBinding(
        schemaVersion="archon.runtime-binding/v1",
        profileId="core",
        generation="generation-1",
        capabilityDigest=CAPABILITY,
        resolution="explicit",
        boundAt=NOW - timedelta(minutes=1),
        leaseExpiresAt=NOW + timedelta(hours=1),
    )


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.setattr(companion, "utc_now", lambda: NOW)
    monkeypatch.setenv("ARCHON_RUNTIME_PROFILE_ID", "core")
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setenv("ARCHON_RUNTIME_CAPABILITY_DIGEST", CAPABILITY)
    monkeypatch.setenv("ARCHON_ANALYTICS_LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("ARCHON_ANALYTICS_LLM_MODEL", MODEL)
    monkeypatch.setenv("ARCHON_ANALYTICS_AWS_REGION", "eu-west-1")
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    monkeypatch.setenv(
        "ARCHON_RUN_HANDLE_FERNET_KEY",
        Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(companion, "_model_probe_state", companion._ModelProbeState())



@pytest.mark.parametrize(
    "variable,value,match",
    [
        ("ARCHON_RUNTIME_PROFILE_ID", "other", "profile"),
        ("ARCHON_RUNTIME_GENERATION", "../escape", "generation"),
        ("ARCHON_RUNTIME_CAPABILITY_DIGEST", "sha256:no", "capability"),
    ],
)
def test_runtime_identity_is_fail_closed(
    runtime,
    monkeypatch,
    variable,
    value,
    match,
):
    monkeypatch.setenv(variable, value)
    with pytest.raises(RuntimeError, match=match):
        companion.configured_runtime_identity()


def test_binding_rejects_malformed_and_naive_claims(runtime):
    current = runtime_binding()
    invalid_generation = current.model_copy(update={"generation": "../bad"})
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(invalid_generation)
    assert raised.value.status_code == 400

    invalid_digest = current.model_copy(update={"capabilityDigest": "bad"})
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(invalid_digest)
    assert raised.value.status_code == 400

    naive = current.model_copy(update={
        "boundAt": NOW.replace(tzinfo=None),
        "leaseExpiresAt": (NOW + timedelta(minutes=5)).replace(tzinfo=None),
    })
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(naive)
    assert raised.value.status_code == 400

    future = current.model_copy(update={"boundAt": NOW + timedelta(seconds=1)})
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(future)
    assert raised.value.status_code == 409


def test_exact_public_input_rejects_query_scope(runtime, monkeypatch):
    monkeypatch.setenv("ARCHON_DEMO_QUERY", DATASET)
    monkeypatch.setenv("ARCHON_ANALYTICS_QUESTION", QUESTION)
    request = companion.AnalyzeRequest(
        schemaVersion="archon.datahub-companion-request/v2",
        query="urn:li:dataset:(urn:li:dataPlatform:sqlite,other,PROD)",
        question=QUESTION,
        runtimeBinding=runtime_binding(),
    )
    with pytest.raises(HTTPException) as raised:
        companion.exact_public_input(request)
    assert raised.value.status_code == 400


@pytest.mark.parametrize(
    "provider,model,region",
    [
        ("openai", MODEL, "eu-west-1"),
        ("bedrock", "../model", "eu-west-1"),
        ("bedrock", MODEL, "not-a-region"),
    ],
)
def test_model_identity_rejects_provider_model_or_region_drift(
    runtime,
    monkeypatch,
    provider,
    model,
    region,
):
    monkeypatch.setenv("ARCHON_ANALYTICS_LLM_PROVIDER", provider)
    monkeypatch.setenv("ARCHON_ANALYTICS_LLM_MODEL", model)
    monkeypatch.setenv("ARCHON_ANALYTICS_AWS_REGION", region)
    with pytest.raises(RuntimeError):
        companion.analytics_model_identity()


@pytest.mark.asyncio
async def test_model_probe_proves_bedrock_reachability_without_keys_or_errors(
    runtime,
    monkeypatch,
):
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/api/settings/llm":
            return httpx.Response(200, json={
                "provider": "bedrock",
                "model": MODEL,
                "has_key": True,
                "has_aws_keys": False,
                "aws_region": "eu-west-1",
            })
        if request.url.path == "/api/settings/llm/test":
            body = json.loads(request.content)
            assert body == {
                "provider": "bedrock",
                "model": MODEL,
                "aws_region": "eu-west-1",
            }
            return httpx.Response(
                200,
                json={"ok": True, "message": "provider-internal-secret"},
            )
        raise AssertionError(request.url.path)

    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=httpx.MockTransport(handler),
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(companion, "analytics_client", factory)
    receipt = await companion.probe_analytics_model(
        companion.analytics_model_identity(),
    )
    encoded = json.dumps(receipt)
    assert receipt["status"] == "verified"
    assert receipt["usesIamRoleCredentials"] is True
    assert receipt["usesStaticAwsKeys"] is False
    assert receipt["probeAttempts"] == 1
    assert "provider-internal-secret" not in encoded
    assert all("aws_access_key" not in request.content.decode() for request in requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["config", "connectivity"])
async def test_model_probe_fails_closed_without_echoing_provider_error(
    runtime,
    monkeypatch,
    mode,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/settings/llm":
            return httpx.Response(200, json={
                "provider": "bedrock",
                "model": MODEL if mode != "config" else "wrong-model",
                "has_key": True,
                "has_aws_keys": False,
                "aws_region": "eu-west-1",
            })
        return httpx.Response(
            200,
            json={"ok": False, "message": "sensitive provider traceback"},
        )

    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=httpx.MockTransport(handler),
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(companion, "analytics_client", factory)
    with pytest.raises(RuntimeError) as raised:
        await companion.probe_analytics_model(
            companion.analytics_model_identity(),
        )
    assert "sensitive provider traceback" not in str(raised.value)


def model_receipt(identity: dict) -> dict:
    return {
        "schemaVersion": "archon.analytics-model-connectivity/v1",
        "status": "verified",
        "provider": identity["provider"],
        "model": identity["model"],
        "region": identity["region"],
        "usesIamRoleCredentials": True,
        "usesStaticAwsKeys": False,
        "credentialModeDigest": identity["credentialModeDigest"],
        "runtimeIdentityDigest": companion.digest(
            companion.configured_runtime_identity(),
        ),
        "probeAttempts": 1,
        "providerResponseStored": False,
        "verifiedAt": NOW.isoformat(),
        "validUntil": (
            NOW + timedelta(seconds=companion.MODEL_PROBE_SUCCESS_TTL_SECONDS)
        ).isoformat(),
        "probeDigest": "sha256:" + "d" * 64,
    }


@pytest.mark.asyncio
async def test_model_probe_cache_age_and_runtime_generation_binding(
    runtime,
    monkeypatch,
):
    clock = [100.0]
    calls = []

    monkeypatch.setattr(companion.time, "monotonic", lambda: clock[0])

    async def probe(identity):
        calls.append(identity)
        return model_receipt(identity)

    monkeypatch.setattr(companion, "probe_analytics_model", probe)
    first = await companion.analytics_model_preflight()
    clock[0] += 7
    second = await companion.analytics_model_preflight()
    assert len(calls) == 1
    assert first["cacheAgeSeconds"] == 0
    assert second["cacheAgeSeconds"] == 7

    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-2")
    third = await companion.analytics_model_preflight()
    assert len(calls) == 2
    assert third["cacheAgeSeconds"] == 0


@pytest.mark.asyncio
async def test_model_probe_accepts_job_scoped_state_without_global_mutation(
    runtime,
    monkeypatch,
):
    global_state = companion._model_probe_state
    job_state = companion._ModelProbeState()

    async def probe(identity):
        return model_receipt(identity)

    monkeypatch.setattr(companion, "probe_analytics_model", probe)
    receipt = await companion.analytics_model_preflight(job_state)
    assert receipt["status"] == "verified"
    assert job_state.success is not None
    assert job_state.failure is None
    assert global_state.success is None
    assert global_state.failure is None


@pytest.mark.asyncio
async def test_model_probe_failure_cache_is_short_and_generic(
    runtime,
    monkeypatch,
):
    clock = [100.0]
    calls = 0
    monkeypatch.setattr(companion.time, "monotonic", lambda: clock[0])

    async def failing(_):
        nonlocal calls
        calls += 1
        raise RuntimeError("provider secret failure")

    monkeypatch.setattr(companion, "probe_analytics_model", failing)
    for _ in range(2):
        with pytest.raises(RuntimeError) as raised:
            await companion.analytics_model_preflight()
        assert str(raised.value) == (
            "Analytics model connectivity probe is unavailable"
        )
    assert calls == 1
    clock[0] += companion.MODEL_PROBE_FAILURE_TTL_SECONDS + 1
    with pytest.raises(RuntimeError):
        await companion.analytics_model_preflight()
    assert calls == 2


@pytest.mark.asyncio
async def test_combined_preflight_binds_mcp_process_and_model(
    runtime,
    monkeypatch,
):
    async def mcp():
        return {
            "digest": "sha256:" + "1" * 64,
            "toolSurfaceDigest": "sha256:" + "2" * 64,
            "officialMcpReadReceipts": official_mcp_reads(),
        }

    async def process():
        return {
            "digest": "sha256:" + "3" * 64,
            "engine": {"name": "archon-judge", "type": "duckdb"},
            "activeDataHubConnections": ["archon-datahub-mcp"],
            "mcpConnectionName": "archon-datahub-mcp",
            "mcpToolSurfaceDigest": "sha256:" + "2" * 64,
            "mutationTools": {
                "publish_analysis": False,
                "save_correction": False,
            },
        }

    async def model():
        return {
            "digest": "sha256:" + "4" * 64,
            "provider": "bedrock",
            "model": MODEL,
            "region": "eu-west-1",
            "usesIamRoleCredentials": True,
            "credentialModeDigest": "sha256:" + "5" * 64,
            "cacheAgeSeconds": 4,
        }

    monkeypatch.setattr(companion, "mcp_preflight", mcp)
    monkeypatch.setattr(companion, "analytics_contract_preflight", process)
    monkeypatch.setattr(companion, "analytics_model_preflight", model)
    receipt = await companion.analytics_preflight(runtime_binding())
    assert receipt["runtimeBindingDigest"] == companion.binding_digest(
        runtime_binding(),
    )
    assert receipt["schemaVersion"] == "archon.analytics-agent-preflight/v2"
    assert receipt["dataHubMcpServer"]["status"] == "verified"
    assert receipt["dataHubMcpServer"]["officialMcpReadReceiptsDigest"] == (
        official_mcp_reads()["digest"]
    )
    assert receipt["analyticsAgentProcess"]["status"] == "verified"
    assert receipt["analyticsModelConnectivity"]["provider"] == "bedrock"
    assert receipt["mutationTools"]["publish_analysis"] is False


@pytest.mark.asyncio
async def test_component_health_separates_process_from_model_connectivity(
    runtime,
    monkeypatch,
):
    monkeypatch.setattr(
        companion,
        "test_datahub_connection",
        lambda: {"digest": "sha256:" + "0" * 64},
    )
    monkeypatch.setattr(
        companion,
        "load_skill_receipt",
        lambda: {
            "digest": "sha256:" + "1" * 64,
            "sourceCommit": "f" * 40,
        },
    )

    async def mcp():
        return {
            "digest": "sha256:" + "2" * 64,
            "package": companion.MCP_PACKAGE,
            "version": companion.MCP_VERSION,
            "sourceCommit": companion.MCP_SOURCE_COMMIT,
            "toolSurfaceDigest": "sha256:" + "3" * 64,
            "officialMcpReadReceipts": official_mcp_reads(),
        }

    async def process():
        return {
            "digest": "sha256:" + "4" * 64,
            "engine": {"name": "archon-judge", "type": "duckdb"},
        }

    async def model():
        raise RuntimeError("bedrock unreachable")

    monkeypatch.setattr(companion, "mcp_preflight", mcp)
    monkeypatch.setattr(companion, "analytics_contract_preflight", process)
    monkeypatch.setattr(companion, "analytics_model_preflight", model)
    components, evidence, ready = await companion.component_health()
    assert components["analyticsAgentProcess"] is True
    assert components["analyticsModelConnectivity"] is False
    assert components["analyticsAgent"] is False
    assert evidence["analyticsAgentProcess"]["status"] == "verified"
    assert evidence["dataHubMcpServer"]["officialMcpReadsVerified"] == len(
        companion.MCP_CANONICAL_READ_TOOLS
    )
    assert evidence["analyticsModelConnectivity"] == {"status": "unknown"}
    assert ready is False


@pytest.mark.asyncio
async def test_component_health_ready_evidence_is_sanitized(
    runtime,
    monkeypatch,
):
    monkeypatch.setattr(
        companion,
        "test_datahub_connection",
        lambda: {"digest": "sha256:" + "0" * 64},
    )
    monkeypatch.setattr(
        companion,
        "load_skill_receipt",
        lambda: {"digest": "x", "sourceCommit": "f" * 40},
    )

    async def mcp():
        return {
            "digest": "sha256:" + "2" * 64,
            "package": companion.MCP_PACKAGE,
            "version": companion.MCP_VERSION,
            "sourceCommit": companion.MCP_SOURCE_COMMIT,
            "toolSurfaceDigest": "sha256:" + "3" * 64,
            "officialMcpReadReceipts": official_mcp_reads(),
        }

    async def process():
        return {
            "digest": "sha256:" + "4" * 64,
            "engine": {"name": "archon-judge", "type": "duckdb"},
        }

    async def model():
        return {
            "digest": "sha256:" + "5" * 64,
            "provider": "bedrock",
            "model": MODEL,
            "region": "eu-west-1",
            "usesIamRoleCredentials": True,
            "credentialModeDigest": "sha256:" + "6" * 64,
            "cacheAgeSeconds": 2,
        }

    monkeypatch.setattr(companion, "mcp_preflight", mcp)
    monkeypatch.setattr(companion, "analytics_contract_preflight", process)
    monkeypatch.setattr(companion, "analytics_model_preflight", model)
    components, evidence, ready = await companion.component_health()
    assert ready is True
    assert all(components.values())
    assert evidence["dataHubMcpServer"]["officialMcpReadReceiptsDigest"] == (
        official_mcp_reads()["digest"]
    )
    assert evidence["analyticsModelConnectivity"] == {
        "status": "verified",
        "provider": "bedrock",
        "model": MODEL,
        "region": "eu-west-1",
        "usesIamRoleCredentials": True,
        "credentialModeDigest": "sha256:" + "6" * 64,
        "cacheAgeSeconds": 2,
        "receiptDigest": "sha256:" + "5" * 64,
    }
    assert "token" not in json.dumps(evidence).lower()


@pytest.mark.parametrize(
    "event,match",
    [
        ([], "schema"),
        ({"event": "KEEPALIVE", "payload": {}}, "keepalive"),
        (
            {
                "event": "TEXT",
                "conversation_id": "wrong",
                "payload": {},
            },
            "binding",
        ),
        (
            {
                "event": "TEXT",
                "conversation_id": CONVERSATION,
                "payload": "bad",
            },
            "payload",
        ),
        (
            {
                "event": "TOOL_CALL",
                "conversation_id": CONVERSATION,
                "payload": {"tool_name": "unreviewed"},
            },
            "unreviewed",
        ),
    ],
)
def test_event_projection_rejects_schema_and_tool_drift(event, match):
    with pytest.raises(RuntimeError, match=match):
        companion.project_event(
            event,
            CONVERSATION,
            complete_seen=False,
        )


def projected_mcp_call(name: str) -> dict:
    return {
        "event": "TOOL_CALL",
        "payload": {
            "tool_name": name,
            "toolInputDigest": companion.digest({"fixture": name}),
            "tracePayloadStored": False,
        },
    }


def projected_mcp_result(name: str, *, is_error: bool = False) -> dict:
    return {
        "event": "TOOL_RESULT",
        "payload": {
            "tool_name": name,
            "isError": is_error,
            "resultDigest": companion.digest({"fixture": name}),
            "resultBytes": 10,
            "tracePayloadStored": False,
        },
    }


def test_analytics_mcp_trace_requires_ordered_matched_pairs():
    events = [
        projected_mcp_call("search"),
        projected_mcp_result("search"),
        {"event": "COMPLETE", "payload": {"text": "done"}},
    ]
    receipt = companion.analytics_mcp_trace_receipt(events)
    assert receipt["status"] == "verified"
    assert receipt["tools"] == ["search"]
    assert receipt["matchedPairs"] == 1
    assert receipt["tracePayloadStored"] is False
    assert receipt["rawProviderPayloadStored"] is False
    assert receipt["pairs"][0]["tool"] == "search"
    assert "fixture" not in json.dumps(receipt)


@pytest.mark.parametrize(
    "events",
    [
        [projected_mcp_result("search")],
        [projected_mcp_call("search")],
        [
            projected_mcp_call("search"),
            projected_mcp_result("search"),
            projected_mcp_result("search"),
        ],
        [
            projected_mcp_call("search"),
            projected_mcp_call("get_entities"),
            projected_mcp_result("get_entities"),
            projected_mcp_result("search"),
        ],
        [
            projected_mcp_call("search"),
            projected_mcp_call("search"),
            projected_mcp_result("search"),
        ],
        [
            projected_mcp_call("search"),
            projected_mcp_result("search", is_error=True),
        ],
    ],
)
def test_analytics_mcp_trace_rejects_duplicate_unmatched_or_failed_events(
    events,
):
    with pytest.raises(RuntimeError, match="MCP"):
        companion.analytics_mcp_trace_receipt(events)


def sse(event_type: str, payload: dict) -> str:
    return "data: " + json.dumps({
        "event": event_type,
        "conversation_id": CONVERSATION,
        "payload": payload,
    }) + "\n\n"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,match",
    [
        ("status", "turn failed"),
        ("media", "media type"),
        ("framing", "framing drift"),
        ("empty", "empty event"),
        ("incomplete", "incomplete frame"),
        ("no-complete", "exactly once"),
    ],
)
async def test_analytics_stream_fails_closed_on_framing_drift(
    monkeypatch,
    mode,
    match,
):
    def handler(_: httpx.Request) -> httpx.Response:
        if mode == "status":
            return httpx.Response(502, json={"error": "private"})
        if mode == "media":
            return httpx.Response(200, json={"event": "COMPLETE"})
        bodies = {
            "framing": "event: TEXT\n\n",
            "empty": "data:\n\n",
            "incomplete": "data: {",
            "no-complete": sse("TEXT", {"text": "partial"}),
        }
        return httpx.Response(
            200,
            text=bodies[mode],
            headers={"content-type": "text/event-stream"},
        )

    transport = httpx.MockTransport(handler)

    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(companion, "analytics_client", factory)
    with pytest.raises(RuntimeError, match=match):
        await companion.analytics_turn(CONVERSATION, "question")


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"score": True, "label": "Good", "breakdown": {"reason": "x"}},
        {"score": 6, "label": "Good", "breakdown": {"reason": "x"}},
        {"score": 3, "label": "", "breakdown": {"reason": "x"}},
        {"score": 3, "label": "Good", "breakdown": {}},
    ],
)
def test_verified_quality_rejects_schema_drift(value):
    with pytest.raises(RuntimeError, match="quality schema"):
        companion.verified_quality(value)


def test_prompt_context_omits_oversized_untrusted_result(monkeypatch):
    monkeypatch.setattr(companion, "MAX_PROMPT_CONTEXT_BYTES", 200)
    receipt = {
        "tool": "search",
        "status": "verified",
        "resultDigest": "sha256:" + "d" * 64,
        "result": {"large": "x" * 1000},
    }
    context = {
        "digest": CONTEXT,
        "entityUrns": [],
        "receipts": [receipt],
    }
    projected = companion.prompt_context(context)
    assert projected["evidence"][0]["resultOmittedFromPrompt"] is True
    assert "large" not in projected["evidence"][0]


def test_grounded_prompt_enforces_total_byte_ceiling(
    runtime,
    monkeypatch,
):
    monkeypatch.setattr(companion, "MAX_PROMPT_BYTES", 10)
    with pytest.raises(RuntimeError, match="exceeded policy"):
        companion.grounded_prompt(
            "question",
            runtime_binding(),
            {
                "digest": CONTEXT,
                "entityUrns": [],
                "receipts": [],
            },
            {"digest": GROUNDING, "receipts": []},
        )


@pytest.mark.parametrize("value", [None, "not-a-uuid", CONVERSATION.upper()])
def test_conversation_id_is_canonical(value):
    with pytest.raises(RuntimeError, match="conversation id"):
        companion.canonical_conversation_id(value)


@pytest.mark.asyncio
async def test_create_conversation_and_run_projection(
    runtime,
    monkeypatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/conversations"
        return httpx.Response(201, json={
            "id": CONVERSATION,
            "engine_name": "archon-judge",
        })

    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=httpx.MockTransport(handler),
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(companion, "analytics_client", factory)
    assert await companion.create_conversation() == CONVERSATION

    async def create():
        return CONVERSATION

    async def turn(conversation_id, prompt):
        assert conversation_id == CONVERSATION
        assert "ARCHON_GOVERNED_ANALYTICS_INPUT" in prompt
        return [
            projected_mcp_call("search"),
            projected_mcp_result("search"),
            {"event": "COMPLETE", "payload": {"text": "done"}},
        ]

    async def quality(conversation_id):
        assert conversation_id == CONVERSATION
        return {"status": "verified", "score": 5}

    monkeypatch.setattr(companion, "create_conversation", create)
    monkeypatch.setattr(companion, "analytics_turn", turn)
    monkeypatch.setattr(companion, "context_quality", quality)
    result = await companion.run_analytics(
        QUESTION,
        runtime_binding(),
        {
            "digest": CONTEXT,
            "entityUrns": [],
            "receipts": [],
        },
        {"digest": GROUNDING, "receipts": []},
        {
            "digest": "sha256:" + "e" * 64,
            "dataHubMcpServer": {
                "officialMcpReadReceiptsDigest": official_mcp_reads()["digest"],
            },
        },
    )
    assert result["preflightDigest"] == "sha256:" + "e" * 64
    assert result["officialMcpReadReceiptsDigest"] == (
        official_mcp_reads()["digest"]
    )
    assert result["analyticsMcpTrace"]["matchedPairs"] == 1
    assert result["runHandle"].startswith("run_")
    assert result["digest"].startswith("sha256:")


@pytest.mark.asyncio
async def test_create_conversation_rejects_contract_drift(
    runtime,
    monkeypatch,
):
    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=httpx.MockTransport(
                lambda _: httpx.Response(201, json={
                    "id": CONVERSATION,
                    "engine_name": "wrong-engine",
                }),
            ),
            trust_env=False,
            follow_redirects=False,
        )

    monkeypatch.setattr(companion, "analytics_client", factory)
    with pytest.raises(RuntimeError, match="conversation contract"):
        await companion.create_conversation()


def test_handle_cipher_requires_valid_key(monkeypatch):
    monkeypatch.delenv("ARCHON_RUN_HANDLE_FERNET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="not configured"):
        companion.handle_cipher()
    monkeypatch.setenv("ARCHON_RUN_HANDLE_FERNET_KEY", "not-a-fernet-key")
    with pytest.raises(RuntimeError, match="invalid"):
        companion.handle_cipher()
