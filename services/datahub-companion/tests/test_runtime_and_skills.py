from datetime import UTC, datetime, timedelta
import hashlib
import json

import pytest
from cryptography.fernet import Fernet
from fastapi import HTTPException

import archon_companion as companion


NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
CAPABILITY = "sha256:" + "a" * 64
CONTEXT = "sha256:" + "b" * 64
GROUNDING = "sha256:" + "c" * 64
CONVERSATION = "12345678-1234-4234-8234-123456789abc"


def binding(
    *,
    profile: str = "core",
    generation: str = "generation-1",
    expires: datetime | None = None,
) -> companion.RuntimeBinding:
    return companion.RuntimeBinding(
        schemaVersion="archon.runtime-binding/v1",
        profileId=profile,
        generation=generation,
        capabilityDigest=CAPABILITY,
        resolution="explicit",
        boundAt=NOW - timedelta(minutes=1),
        leaseExpiresAt=expires or NOW + timedelta(hours=1),
    )


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.setattr(companion, "utc_now", lambda: NOW)
    monkeypatch.setenv("ARCHON_RUNTIME_PROFILE_ID", "core")
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setenv("ARCHON_RUNTIME_CAPABILITY_DIGEST", CAPABILITY)
    monkeypatch.setenv(
        "ARCHON_RUN_HANDLE_FERNET_KEY",
        Fernet.generate_key().decode("ascii"),
    )


def test_binding_requires_exact_isolated_runtime(runtime, monkeypatch):
    companion.validate_binding(binding())
    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-2")
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(binding())
    assert raised.value.status_code == 409


def test_binding_rejects_inactive_and_oversized_lease(runtime):
    with pytest.raises(HTTPException) as expired:
        companion.validate_binding(binding(expires=NOW))
    assert expired.value.status_code == 409
    oversized = binding().model_copy(update={
        "boundAt": NOW - timedelta(minutes=1),
        "leaseExpiresAt": NOW + timedelta(hours=2),
    })
    with pytest.raises(HTTPException) as raised:
        companion.validate_binding(oversized)
    assert raised.value.status_code == 400


def test_run_handle_failures_share_one_generic_not_found(runtime, monkeypatch):
    current = binding()
    handle = companion.issue_run_handle(
        CONVERSATION, current, CONTEXT, GROUNDING,
    )
    assert handle.startswith("run_")
    assert CONVERSATION not in handle
    payload = companion.resolve_run_handle(handle, current)
    assert payload["conversationId"] == CONVERSATION

    invalid_handles = [
        handle[:-1] + ("A" if handle[-1] != "A" else "B"),
        "run_" + "A" * 80,
    ]
    for invalid in invalid_handles:
        with pytest.raises(HTTPException) as raised:
            companion.resolve_run_handle(invalid, current)
        assert (raised.value.status_code, raised.value.detail) == (
            404, "run handle not found",
        )

    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-2")
    with pytest.raises(HTTPException) as rebound:
        companion.resolve_run_handle(
            handle, binding(generation="generation-2"),
        )
    assert (rebound.value.status_code, rebound.value.detail) == (
        404, "run handle not found",
    )

    monkeypatch.setenv("ARCHON_RUNTIME_GENERATION", "generation-1")
    monkeypatch.setattr(
        companion, "utc_now", lambda: NOW + timedelta(minutes=31),
    )
    with pytest.raises(HTTPException) as expired:
        companion.resolve_run_handle(handle, current)
    assert (expired.value.status_code, expired.value.detail) == (
        404, "run handle not found",
    )


def test_unknown_ack_receipt_has_no_exception_fingerprint():
    class SensitiveInternalFailure(Exception):
        pass

    def failing(**_):
        raise SensitiveInternalFailure("do not expose")

    receipt = companion.guarded_tool("search", {"query": "x"}, failing)
    assert receipt["status"] == "unknown"
    assert receipt["result"] == {"reason": "tool unavailable"}
    assert "SensitiveInternalFailure" not in json.dumps(receipt)

def test_dataset_selection_rejects_non_dataset_and_malformed_urns():
    result = {
        "searchResults": [
            {"entity": {
                "type": "DATASET",
                "urn": "urn:li:dataset:(urn:li:dataPlatform:s3,a,PROD)",
            }},
            {"entity": {"type": "TAG", "urn": "urn:li:tag:PII"}},
            {"entity": {"type": "DATASET", "urn": "urn:li:corpuser:admin"}},
            {"entity": {
                "type": "dataset",
                "urn": "urn:li:dataset:(urn:li:dataPlatform:s3,b,PROD)",
            }},
        ]
    }
    assert companion.dataset_urns(result) == [
        "urn:li:dataset:(urn:li:dataPlatform:s3,a,PROD)",
        "urn:li:dataset:(urn:li:dataPlatform:s3,b,PROD)",
    ]


def locked(data: bytes) -> dict:
    return {
        "gitBlob": companion.git_blob(data),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def test_skill_receipt_verifies_official_and_custom_files(tmp_path, monkeypatch):
    skills_root = tmp_path / "official"
    custom_root = tmp_path / "contrib"
    lock_path = tmp_path / "lock.json"
    files = {}
    for skill in companion.OFFICIAL_SKILLS:
        data = f"---\nname: {skill}\n---\n".encode()
        path = skills_root / "skills" / skill / "SKILL.md"
        path.parent.mkdir(parents=True)
        path.write_bytes(data)
        files[f"skills/{skill}/SKILL.md"] = locked(data)
    custom_data = b"---\nname: datahub-audit\n---\n"
    custom_path = custom_root / "datahub-audit" / "SKILL.md"
    custom_path.parent.mkdir(parents=True)
    custom_path.write_bytes(custom_data)
    lock_path.write_text(json.dumps({
        "schemaVersion": "archon.datahub-agent-stack-lock/v1",
        "components": {"dataHubSkills": {
            "name": "datahub-skills",
            "version": companion.SKILLS_VERSION,
            "source": {"commit": companion.SKILLS_SOURCE_COMMIT},
            "files": files,
            "customFiles": {
                "contrib/datahub-audit/SKILL.md": locked(custom_data),
            },
        }},
    }))
    monkeypatch.setenv("ARCHON_AGENT_STACK_LOCK", str(lock_path))
    monkeypatch.setenv("ARCHON_DATAHUB_SKILLS_DIR", str(skills_root))
    monkeypatch.setenv("ARCHON_CUSTOM_SKILLS_DIR", str(custom_root))

    receipt = companion.load_skill_receipt()
    assert receipt["schemaVersion"] == "archon.datahub-skills-receipt/v2"
    assert len(receipt["official"]) == 5
    assert receipt["custom"][0]["skill"] == "datahub-audit"
    assert receipt["sourceCommit"] == companion.SKILLS_SOURCE_COMMIT
    assert receipt["reviewedSkillCount"] == 6
    assert all(
        item["reviewedExecution"]["executionPlanDigest"].startswith("sha256:")
        for item in receipt["official"] + receipt["custom"]
    )
    enrich = next(
        item for item in receipt["official"]
        if item["skill"] == "datahub-enrich"
    )
    assert enrich["reviewedExecution"]["executionPlan"]["phase"] == (
        "governed-enrichment-preview"
    )
    assert receipt["digest"].startswith("sha256:")


def skill_stack_receipt() -> dict:
    artifacts = []
    for index, name in enumerate(
        (*companion.OFFICIAL_SKILLS, companion.CUSTOM_SKILL),
        start=1,
    ):
        artifact_digest = f"sha256:{index:064x}"
        artifacts.append({
            "skill": name,
            "artifactDigest": artifact_digest,
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


def ack_context_receipt() -> dict:
    receipts = []
    for index, name in enumerate(
        companion.ACK_CANONICAL_READ_TOOLS,
        start=20,
    ):
        body = {
            "tool": name,
            "provider": "datahub-agent-context",
            "status": "verified",
            "argumentsDigest": f"sha256:{index:064x}",
            "resultDigest": f"sha256:{index + 20:064x}",
            "result": {"fixture": name},
        }
        receipts.append({**body, "digest": companion.digest(body)})
    return {"digest": CONTEXT, "receipts": receipts}


def official_mcp_read_receipt() -> dict:
    receipts = []
    for index, name in enumerate(
        companion.MCP_CANONICAL_READ_TOOLS,
        start=50,
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


def test_skill_grounding_executes_artifact_bound_reviewed_plans():
    skills = skill_stack_receipt()
    context = ack_context_receipt()
    mcp = official_mcp_read_receipt()
    result = companion.ground_skills(skills, context, mcp)
    assert result["schemaVersion"] == "archon.datahub-skill-grounding/v2"
    assert result["skillsReceiptDigest"] == skills["digest"]
    assert result["ackContextDigest"] == CONTEXT
    assert result["officialMcpReadReceiptsDigest"] == mcp["digest"]
    assert result["allRequiredCallsSatisfied"] is True
    assert len(result["receipts"]) == 6
    assert all(
        item["requiredCallsSatisfied"] is True
        and item["sourceArtifactDigest"].startswith("sha256:")
        and item["digest"] == companion.digest({
            key: value for key, value in item.items() if key != "digest"
        })
        for item in result["receipts"]
    )
    enrich = next(
        item for item in result["receipts"]
        if item["skill"] == "datahub-enrich"
    )
    assert enrich["status"] == "previewed"
    assert enrich["mode"] == "preview-only"
    assert enrich["executionPlan"]["phase"] == "governed-enrichment-preview"
    assert enrich["executionPlanDigest"] == next(
        item["reviewedExecution"]["executionPlanDigest"]
        for item in skills["official"]
        if item["skill"] == "datahub-enrich"
    )
    assert [item["tool"] for item in enrich["satisfiedAckCalls"]] == list(
        companion.ACK_CANONICAL_READ_TOOLS
    )
    assert [
        item["tool"] for item in enrich["satisfiedOfficialMcpCalls"]
    ] == list(companion.MCP_CANONICAL_READ_TOOLS)
    assert all(
        item["status"] == "executed"
        for item in result["receipts"]
        if item["skill"] != "datahub-enrich"
    )


def test_skill_grounding_keeps_ack_and_official_mcp_receipts_distinct():
    result = companion.ground_skills(
        skill_stack_receipt(),
        ack_context_receipt(),
        official_mcp_read_receipt(),
    )
    search_grounding = next(
        item for item in result["receipts"]
        if item["skill"] == "datahub-search"
    )
    assert len(search_grounding["ackReceiptDigests"]) == 3
    assert len(search_grounding["officialMcpReadReceiptDigests"]) == 3
    assert not set(search_grounding["ackReceiptDigests"]) & set(
        search_grounding["officialMcpReadReceiptDigests"]
    )


def test_skill_grounding_rejects_changed_artifact_binding():
    skills = skill_stack_receipt()
    skills["official"][0]["artifactDigest"] = "sha256:" + "f" * 64
    with pytest.raises(RuntimeError, match="digest drift"):
        companion.ground_skills(
            skills,
            ack_context_receipt(),
            official_mcp_read_receipt(),
        )


def test_skill_grounding_rejects_changed_required_call_policy():
    skills = skill_stack_receipt()
    search = skills["official"][0]
    search["reviewedExecution"]["executionPlan"]["requiredCalls"]["ack"].pop()
    body = {key: value for key, value in skills.items() if key != "digest"}
    skills["digest"] = companion.digest(body)
    with pytest.raises(RuntimeError, match="artifact binding drift"):
        companion.ground_skills(
            skills,
            ack_context_receipt(),
            official_mcp_read_receipt(),
        )


@pytest.mark.parametrize("mechanism", ["ack", "official-mcp"])
def test_skill_grounding_fails_closed_when_required_call_is_missing(mechanism):
    context = ack_context_receipt()
    mcp = official_mcp_read_receipt()
    if mechanism == "ack":
        context["receipts"].pop()
        match = "required calls missing"
    else:
        mcp["receipts"].pop()
        body = {key: value for key, value in mcp.items() if key != "digest"}
        mcp["digest"] = companion.digest(body)
        match = "read sequence drift"
    with pytest.raises(RuntimeError, match=match):
        companion.ground_skills(skill_stack_receipt(), context, mcp)
