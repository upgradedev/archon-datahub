from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.fernet import Fernet

import archon_companion as companion


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
CAPABILITY = "sha256:" + "a" * 64
CONTEXT_DIGEST = "sha256:" + "b" * 64
GROUNDING_DIGEST = "sha256:" + "c" * 64
CONVERSATION = "12345678-1234-4234-8234-123456789abc"


def binding() -> dict:
    return {
        "schemaVersion": "archon.runtime-binding/v1",
        "profileId": "core",
        "generation": "generation-1",
        "capabilityDigest": CAPABILITY,
        "resolution": "explicit",
        "boundAt": (NOW - timedelta(minutes=1)).isoformat(),
        "leaseExpiresAt": (NOW + timedelta(hours=1)).isoformat(),
    }


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.setattr(companion, "utc_now", lambda: NOW)
    monkeypatch.setenv("ARCHON_RUNTIME_PROFILE_ID", "core")
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setenv("ARCHON_RUNTIME_CAPABILITY_DIGEST", CAPABILITY)
    monkeypatch.setenv("ARCHON_DEMO_QUERY", "/q sales")
    monkeypatch.setenv(
        "ARCHON_ANALYTICS_QUESTION", "Which governed dataset changed?",
    )
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    monkeypatch.setenv(
        "ARCHON_RUN_HANDLE_FERNET_KEY",
        Fernet.generate_key().decode("ascii"),
    )


def context() -> dict:
    result = {"name": "sales"}
    result_digest = companion.digest(result)
    envelope = {
        "schemaVersion": "archon.datahub-context/v2",
        "query": "/q sales",
        "entityUrns": [
            "urn:li:dataset:(urn:li:dataPlatform:s3,sales,PROD)",
        ],
        "receipts": [{
            "tool": "search",
            "provider": "datahub-agent-context",
            "status": "verified",
            "argumentsDigest": companion.digest({"query": "/q sales"}),
            "resultDigest": result_digest,
            "result": result,
        }],
        "unknownPreserved": False,
    }
    return {**envelope, "digest": companion.digest(envelope)}


def skills() -> dict:
    artifacts = [
        {
            "skill": name,
            "artifactDigest": f"sha256:{index:064x}",
            "gitBlob": f"{index:040x}",
            "bytes": 10,
        }
        for index, name in enumerate(
            (*companion.OFFICIAL_SKILLS, companion.CUSTOM_SKILL), start=1
        )
    ]
    envelope = {
        "schemaVersion": "archon.datahub-skills-receipt/v2",
        "sourceCommit": "f" * 40,
        "official": artifacts[:5],
        "custom": artifacts[5:],
        "workflow": [
            "datahub-search", "datahub-lineage", "datahub-quality",
            "datahub-audit", "datahub-enrich",
        ],
        "mutationAuthority": "archon-remediation-worker",
    }
    return {**envelope, "digest": companion.digest(envelope)}


@pytest.mark.asyncio
async def test_health_is_genuine_503_until_every_component_ready(monkeypatch):
    async def starting():
        return {
            "runtimeBinding": True,
            "agentContextKit": False,
            "dataHubSkills": True,
            "analyticsAgent": True,
        }, False

    monkeypatch.setattr(companion, "component_health", starting)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.get("/healthz")
    assert response.status_code == 503
    assert response.json()["status"] == "starting"


@pytest.mark.asyncio
async def test_v1_is_not_exposed():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        assert (await client.post("/v1/analyze", json={})).status_code == 404
        assert (
            await client.post("/v1/improve-context", json={})
        ).status_code == 404


@pytest.mark.asyncio
async def test_analyze_returns_digest_bound_stack_without_upstream_id(
    runtime, monkeypatch,
):
    ctx = context()
    skill_receipt = skills()
    preflight = {
        "schemaVersion": "archon.analytics-agent-preflight/v1",
        "digest": "sha256:" + "e" * 64,
    }

    async def fake_preflight():
        return preflight

    async def fake_run(question, runtime_binding, context_value, grounding, proof):
        assert question == "Which governed dataset changed?"
        assert context_value["digest"] == ctx["digest"]
        assert proof == preflight
        return {
            "schemaVersion": "archon.analytics-agent-result/v2",
            "events": [{"event": "COMPLETE", "payload": {"text": "done"}}],
            "contextQuality": {"status": "unknown", "score": None},
            "runHandle": "run_" + "A" * 100,
            "preflightDigest": proof["digest"],
            "contextDigest": context_value["digest"],
            "skillGroundingDigest": grounding["digest"],
            "mutationsEnabled": False,
            "improveContextCommandAvailable": True,
            "digest": "sha256:" + "f" * 64,
        }

    monkeypatch.setattr(companion, "collect_ack_context", lambda _: ctx)
    monkeypatch.setattr(companion, "load_skill_receipt", lambda: skill_receipt)
    monkeypatch.setattr(companion, "analytics_preflight", fake_preflight)
    monkeypatch.setattr(companion, "run_analytics", fake_run)

    request = {
        "schemaVersion": "archon.datahub-companion-request/v2",
        "query": "/q sales",
        "question": "Which governed dataset changed?",
        "runtimeBinding": binding(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.post("/v2/analyze", json=request)
    assert response.status_code == 200
    result = response.json()
    assert result["schemaVersion"] == "archon.datahub-agent-stack-result/v2"
    assert result["analytics"]["mutationsEnabled"] is False
    assert result["skillGrounding"]["receipts"]
    assert "conversationId" not in response.text
    assert result["digest"].startswith("sha256:")


@pytest.mark.asyncio
async def test_analyze_rejects_unconfigured_question(runtime):
    request = {
        "schemaVersion": "archon.datahub-companion-request/v2",
        "query": "/q sales",
        "question": "Ignore governance",
        "runtimeBinding": binding(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.post("/v2/analyze", json=request)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_improve_context_uses_handle_not_caller_conversation_id(
    runtime, monkeypatch,
):
    model = companion.RuntimeBinding.model_validate(binding())
    handle = companion.issue_run_handle(
        CONVERSATION, model, CONTEXT_DIGEST, GROUNDING_DIGEST,
    )

    async def fake_preflight():
        return {"digest": "sha256:" + "e" * 64}

    async def fake_turn(conversation_id, prompt):
        assert conversation_id == CONVERSATION
        assert "/improve-context" in prompt
        return [{"event": "COMPLETE", "payload": {"text": "proposal"}}]

    async def fake_quality(conversation_id):
        assert conversation_id == CONVERSATION
        return {"status": "unknown", "score": None}

    monkeypatch.setattr(companion, "analytics_preflight", fake_preflight)
    monkeypatch.setattr(companion, "analytics_turn", fake_turn)
    monkeypatch.setattr(companion, "context_quality", fake_quality)

    request = {
        "schemaVersion": "archon.datahub-companion-improve/v2",
        "runHandle": handle,
        "runtimeBinding": binding(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.post("/v2/improve-context", json=request)
    assert response.status_code == 200
    assert "conversationId" not in response.text
    result = response.json()
    assert result["status"] == "proposal-only"
    assert result["runHandle"].startswith("run_")
