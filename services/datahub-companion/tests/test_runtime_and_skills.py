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
            "source": {"commit": "f" * 40},
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
    assert receipt["digest"].startswith("sha256:")


def test_skill_grounding_links_artifacts_to_ack_receipts():
    artifacts = [
        {"skill": name, "artifactDigest": f"sha256:{index:064x}"}
        for index, name in enumerate(
            (*companion.OFFICIAL_SKILLS, companion.CUSTOM_SKILL), start=1
        )
    ]
    context = {
        "digest": CONTEXT,
        "receipts": [
            {"tool": "search", "resultDigest": "sha256:" + "d" * 64},
            {
                "tool": "get_dataset_assertions",
                "resultDigest": "sha256:" + "e" * 64,
            },
        ],
    }
    result = companion.ground_skills(
        {"official": artifacts[:5], "custom": artifacts[5:]},
        context,
    )
    assert len(result["receipts"]) == 6
    assert all(item["sourceArtifactDigest"].startswith("sha256:") for item in result["receipts"])
    audit = next(item for item in result["receipts"] if item["skill"] == "datahub-audit")
    assert len(audit["ackReceiptDigests"]) == 2
