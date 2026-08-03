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
DATASET = "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)
DOWNSTREAM_DATASET = "archon_demo.customer_segment_revenue"
GOVERNED_COLUMN = "customer_email"


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
    monkeypatch.setenv("ARCHON_DEMO_QUERY", DATASET)
    monkeypatch.setenv(
        "ARCHON_ANALYTICS_QUESTION", QUESTION,
    )
    monkeypatch.setenv("ARCHON_ANALYTICS_ENGINE", "archon-judge")
    monkeypatch.setenv(
        "ARCHON_RUN_HANDLE_FERNET_KEY",
        Fernet.generate_key().decode("ascii"),
    )


def context() -> dict:
    governed_result = {
        "name": "archon_demo.customers",
        "governedColumn": GOVERNED_COLUMN,
        "downstreamDataset": DOWNSTREAM_DATASET,
    }
    receipts = []
    for index, name in enumerate(
        companion.ACK_CANONICAL_READ_TOOLS,
        start=1,
    ):
        result = governed_result if name == "search" else {"fixture": name}
        body = {
            "tool": name,
            "provider": "datahub-agent-context",
            "status": "verified",
            "argumentsDigest": f"sha256:{index:064x}",
            "resultDigest": companion.digest(result),
            "result": result,
        }
        receipts.append({**body, "digest": companion.digest(body)})
    envelope = {
        "schemaVersion": "archon.datahub-context/v2",
        "query": DATASET,
        "entityUrns": [DATASET],
        "receipts": receipts,
        "unknownPreserved": False,
    }
    return {**envelope, "digest": companion.digest(envelope)}


def skills() -> dict:
    artifacts = []
    for index, name in enumerate(
        (*companion.OFFICIAL_SKILLS, companion.CUSTOM_SKILL),
        start=1,
    ):
        artifact_digest = f"sha256:{index:064x}"
        artifacts.append({
            "skill": name,
            "artifactDigest": artifact_digest,
            "gitBlob": f"{index:040x}",
            "bytes": 10,
            "reviewedExecution": companion.reviewed_skill_execution(
                name, artifact_digest,
            ),
        })
    envelope = {
        "schemaVersion": "archon.datahub-skills-receipt/v2",
        "sourceCommit": companion.SKILLS_SOURCE_COMMIT,
        "official": artifacts[:5],
        "custom": artifacts[5:],
        "workflow": list(companion.SKILL_WORKFLOW),
        "reviewedSkillCount": 6,
        "mutationAuthority": "archon-remediation-worker",
    }
    return {**envelope, "digest": companion.digest(envelope)}


def official_mcp_reads() -> dict:
    receipts = []
    for index, name in enumerate(
        companion.MCP_CANONICAL_READ_TOOLS,
        start=20,
    ):
        body = {
            "schemaVersion": "archon.official-datahub-mcp-read-receipt/v1",
            "provider": "official-datahub-mcp",
            "tool": name,
            "status": "verified",
            "argumentsDigest": f"sha256:{index:064x}",
            "resultDigest": f"sha256:{index + 20:064x}",
            "providerPayloadStored": False,
            "mutationsEnabled": False,
        }
        receipts.append({**body, "digest": companion.digest(body)})
    envelope = {
        "schemaVersion": "archon.official-datahub-mcp-read-receipts/v1",
        "status": "verified",
        "sequence": list(companion.MCP_CANONICAL_READ_TOOLS),
        "receipts": receipts,
        "providerPayloadStored": False,
        "mutationsEnabled": False,
    }
    return {**envelope, "digest": companion.digest(envelope)}


@pytest.mark.asyncio
async def test_health_is_genuine_503_until_every_component_ready(monkeypatch):
    async def starting():
        return {
            "runtimeBinding": True,
            "dataHubMcpServer": True,
            "agentContextKit": False,
            "dataHubSkills": True,
            "analyticsAgentProcess": True,
            "analyticsModelConnectivity": False,
            "analyticsAgent": False,
        }, {
            "analyticsModelConnectivity": {"status": "unknown"},
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
    mcp_reads = official_mcp_reads()
    preflight = {
        "schemaVersion": "archon.analytics-agent-preflight/v2",
        "dataHubMcpServer": {
            "officialMcpReadReceipts": mcp_reads,
            "officialMcpReadReceiptsDigest": mcp_reads["digest"],
        },
        "digest": "sha256:" + "e" * 64,
    }

    async def fake_preflight(*_):
        return preflight

    async def fake_run(question, runtime_binding, context_value, grounding, proof):
        assert question == QUESTION
        assert context_value["digest"] == ctx["digest"]
        assert proof == preflight
        assert grounding["officialMcpReadReceiptsDigest"] == mcp_reads["digest"]
        assert grounding["ackContextDigest"] == ctx["digest"]
        enrich = next(
            item for item in grounding["receipts"]
            if item["skill"] == "datahub-enrich"
        )
        assert enrich["status"] == "previewed"
        assert enrich["requiredCallsSatisfied"] is True
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
        "query": DATASET,
        "question": QUESTION,
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
        "query": DATASET,
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

    async def fake_preflight(*_):
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


@pytest.mark.asyncio
async def test_analyze_internal_failure_is_one_generic_503(
    runtime,
    monkeypatch,
):
    def failing(_):
        raise RuntimeError("private ACK error")

    async def preflight(*_):
        return {"digest": "sha256:" + "e" * 64}

    monkeypatch.setattr(companion, "collect_ack_context", failing)
    monkeypatch.setattr(companion, "load_skill_receipt", skills)
    monkeypatch.setattr(companion, "analytics_preflight", preflight)
    request = {
        "schemaVersion": "archon.datahub-companion-request/v2",
        "query": DATASET,
        "question": QUESTION,
        "runtimeBinding": binding(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.post("/v2/analyze", json=request)
    assert response.status_code == 503
    assert response.json() == {
        "detail": "DataHub companion is not ready",
    }
    assert "private ACK error" not in response.text


@pytest.mark.asyncio
async def test_improve_internal_failure_is_one_generic_503(
    runtime,
    monkeypatch,
):
    model = companion.RuntimeBinding.model_validate(binding())
    handle = companion.issue_run_handle(
        CONVERSATION,
        model,
        CONTEXT_DIGEST,
        GROUNDING_DIGEST,
    )

    async def failing(*_):
        raise RuntimeError("private model error")

    monkeypatch.setattr(companion, "analytics_preflight", failing)
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
    assert response.status_code == 503
    assert response.json() == {
        "detail": "Analytics Agent is not ready",
    }
    assert "private model error" not in response.text


@pytest.mark.asyncio
async def test_health_ready_exposes_separate_model_signal(monkeypatch):
    async def ready():
        components = {
            "runtimeBinding": True,
            "dataHubMcpServer": True,
            "agentContextKit": True,
            "dataHubSkills": True,
            "analyticsAgentProcess": True,
            "analyticsModelConnectivity": True,
            "analyticsAgent": True,
        }
        evidence = {
            "analyticsAgentProcess": {"status": "verified"},
            "analyticsModelConnectivity": {
                "status": "verified",
                "provider": "bedrock",
                "cacheAgeSeconds": 1,
            },
        }
        return components, evidence, True

    monkeypatch.setattr(companion, "component_health", ready)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["components"]["analyticsModelConnectivity"] is True


@pytest.mark.asyncio
async def test_liveness_does_not_claim_dependency_readiness():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=companion.app),
        base_url="http://companion",
    ) as client:
        response = await client.get("/livez")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert "components" not in response.json()
