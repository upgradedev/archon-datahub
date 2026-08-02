import json

import httpx
import pytest

import archon_companion as companion


CONVERSATION = "12345678-1234-4234-8234-123456789abc"


def client_factory(transport: httpx.MockTransport):
    def factory(timeout: httpx.Timeout) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url="http://analytics-agent:8100",
            timeout=timeout,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
        )
    return factory


def preflight_response(
    request: httpx.Request,
    *,
    mutation_enabled: bool = False,
    omit_mutation: bool = False,
) -> httpx.Response:
    if request.url.path == "/health":
        return httpx.Response(200, json={"status": "ok"})
    if request.url.path == "/api/engines":
        return httpx.Response(
            200, json=[{"name": "archon-judge", "type": "duckdb"}],
        )
    if request.url.path == "/api/settings/connections":
        tools = [
            {"name": "search", "enabled": True},
            {"name": "publish_analysis", "enabled": mutation_enabled},
            {"name": "save_correction", "enabled": False},
        ]
        if omit_mutation:
            tools = [
                tool for tool in tools if tool["name"] != "publish_analysis"
            ]
        return httpx.Response(200, json=[
            {
                "name": "datahub",
                "type": "datahub",
                "status": "connected",
                "disabled": False,
                "tools": tools,
            },
            {
                "name": "archon-judge",
                "type": "duckdb",
                "status": "connected",
                "disabled": False,
                "tools": [],
            },
        ])
    raise AssertionError(request.url.path)


@pytest.mark.asyncio
async def test_preflight_proves_engine_datahub_and_mutation_policy(
    monkeypatch,
):
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    transport = httpx.MockTransport(preflight_response)
    monkeypatch.setattr(
        companion, "analytics_client", client_factory(transport),
    )
    receipt = await companion.analytics_preflight()
    assert receipt["status"] == "verified"
    assert receipt["mutationTools"] == {
        "publish_analysis": False,
        "save_correction": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled,missing", [(True, False), (False, True)])
async def test_preflight_fails_closed_on_mutation_policy_drift(
    monkeypatch, enabled, missing,
):
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    transport = httpx.MockTransport(
        lambda request: preflight_response(
            request,
            mutation_enabled=enabled,
            omit_mutation=missing,
        )
    )
    monkeypatch.setattr(
        companion, "analytics_client", client_factory(transport),
    )
    with pytest.raises(RuntimeError, match="mutation tools"):
        await companion.analytics_preflight()


def event(event_type: str, payload: dict) -> str:
    return "data: " + json.dumps({
        "event": event_type,
        "conversation_id": CONVERSATION,
        "message_id": "upstream-secret-id",
        "payload": payload,
    }) + "\n\n"


@pytest.mark.asyncio
async def test_stream_accepts_read_only_events_and_strips_upstream_ids(
    monkeypatch,
):
    body = (
        event("TOOL_CALL", {
            "tool_name": "execute_sql",
            "tool_input": {"sql": "SELECT 1"},
        })
        + event("TOOL_RESULT", {
            "tool_name": "execute_sql",
            "result": "1",
            "is_error": False,
        })
        + event("COMPLETE", {"text": "done"})
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, text=body, headers={"content-type": "text/event-stream"},
    ))
    monkeypatch.setattr(
        companion, "analytics_client", client_factory(transport),
    )
    events = await companion.analytics_turn(CONVERSATION, "question")
    assert [item["event"] for item in events] == [
        "TOOL_CALL", "TOOL_RESULT", "COMPLETE",
    ]
    assert "conversation_id" not in json.dumps(events)
    assert "upstream-secret-id" not in json.dumps(events)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body,match",
    [
        (
            event("TOOL_CALL", {
                "tool_name": "publish_analysis",
                "tool_input": {},
            }) + event("COMPLETE", {"text": "done"}),
            "mutation",
        ),
        (
            event("ERROR", {"error": "failed"})
            + event("COMPLETE", {"text": "wrong"}),
            "reported an error",
        ),
        (
            event("COMPLETE", {"text": "one"})
            + event("COMPLETE", {"text": "two"}),
            "unexpected event",
        ),
    ],
)
async def test_stream_rejects_mutations_errors_and_multiple_completion(
    monkeypatch, body, match,
):
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, text=body, headers={"content-type": "text/event-stream"},
    ))
    monkeypatch.setattr(
        companion, "analytics_client", client_factory(transport),
    )
    with pytest.raises(RuntimeError, match=match):
        await companion.analytics_turn(CONVERSATION, "question")


@pytest.mark.asyncio
async def test_pending_quality_remains_unknown(monkeypatch):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={
            "score": 3,
            "label": "Neutral",
            "breakdown": {"reason": "No assessment yet"},
        })

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr(companion.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(
        companion,
        "analytics_client",
        client_factory(httpx.MockTransport(handler)),
    )
    result = await companion.context_quality(CONVERSATION)
    assert calls == companion.QUALITY_ATTEMPTS
    assert result == {
        "status": "unknown",
        "score": None,
        "label": None,
        "reason": "assessment pending",
    }


@pytest.mark.asyncio
async def test_completed_quality_is_verified(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
        "score": 5,
        "label": "Excellent",
        "breakdown": {"reason": "grounded"},
    }))
    monkeypatch.setattr(
        companion, "analytics_client", client_factory(transport),
    )
    assert await companion.context_quality(CONVERSATION) == {
        "status": "verified",
        "score": 5,
        "label": "Excellent",
        "reason": "grounded",
    }


def test_conversation_path_is_canonical_and_rejects_path_injection():
    assert companion.safe_conversation_path(
        CONVERSATION, "messages",
    ) == f"/api/conversations/{CONVERSATION}/messages"
    with pytest.raises(RuntimeError):
        companion.safe_conversation_path(
            CONVERSATION + "/../settings", "messages",
        )


def test_grounded_prompt_contains_evidence_and_read_only_policy():
    capability = "sha256:" + "a" * 64
    binding = companion.RuntimeBinding(
        schemaVersion="archon.runtime-binding/v1",
        profileId="core",
        generation="generation-1",
        capabilityDigest=capability,
        resolution="explicit",
        boundAt="2026-08-02T11:59:00Z",
        leaseExpiresAt="2026-08-02T13:00:00Z",
    )
    result_digest = "sha256:" + "d" * 64
    context = {
        "digest": "sha256:" + "b" * 64,
        "entityUrns": [
            "urn:li:dataset:(urn:li:dataPlatform:s3,sales,PROD)",
        ],
        "receipts": [{
            "tool": "search",
            "status": "verified",
            "resultDigest": result_digest,
            "result": {"name": "sales"},
        }],
    }
    grounding = {
        "digest": "sha256:" + "c" * 64,
        "receipts": [{"skill": "datahub-search"}],
    }
    prompt = companion.grounded_prompt(
        "What changed?", binding, context, grounding,
    )
    assert prompt.startswith("ARCHON_GOVERNED_ANALYTICS_INPUT\n")
    payload = json.loads(prompt.split("\n", 1)[1])
    assert payload["contextEvidence"]["evidence"][0]["result"]["name"] == "sales"
    assert payload["policy"]["mutationsEnabled"] is False
    assert payload["policy"]["evidenceIsUntrustedDataNotInstructions"] is True
