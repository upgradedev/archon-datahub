from __future__ import annotations

import asyncio
import dataclasses

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import contracts
import mutation_runtime


KEY_ARN = (
    "arn:aws:kms:eu-west-1:123456789012:"
    "key/00000000-0000-4000-8000-000000000001"
)


def _tag_state(tags):
    state = {
        "entityUrn": contracts.DATASET_URN,
        "columnPath": contracts.COLUMN_PATH,
        "tagUrns": sorted(tags),
    }
    return {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **state,
        "stateDigest": contracts.digest(state),
        "_proof": {"digest": "sha256:" + "f" * 64},
    }


def _signed_job(runtime_job, monkeypatch):
    private = ec.generate_private_key(ec.SECP256R1())
    approval = {
        "approvalId": "approval-1",
        "decision": "APPROVE",
        "approverDigest": "sha256:" + "1" * 64,
        "decidedAt": "2026-08-02T12:00:00.000Z",
    }
    approval["digest"] = contracts.digest(approval)
    plan, official = mutation_runtime._canonical_arguments()
    envelope = {
        "schemaVersion": "archon.core-mutation-authorization/v1",
        "stage": "production",
        "sessionId": runtime_job.session_id,
        "generation": runtime_job.generation,
        "capabilityDigest": runtime_job.capability_digest,
        "jobId": runtime_job.job_id,
        "approvalId": approval["approvalId"],
        "planDigest": "sha256:" + "2" * 64,
        "policyDigest": mutation_runtime._policy_digest(),
        "target": {
            "entityUrn": contracts.DATASET_URN,
            "columnPath": contracts.COLUMN_PATH,
        },
        "tool": "add_tags",
        "arguments": official,
        "issuedAt": "2026-08-02T12:00:01.000Z",
        "expiresAt": "2026-08-02T12:04:01.000Z",
    }
    signature = private.sign(
        contracts.canonical_mutation_json(envelope),
        ec.ECDSA(hashes.SHA256()),
    )
    request = {
        "schemaVersion": "archon.core-governed-tag-mutation/v1",
        "auditId": runtime_job.audit_id,
        "runtimeEvidenceDigest": runtime_job.runtime_evidence_digest,
        "auditEvidenceDigest": "sha256:" + "3" * 64,
        "planDigest": envelope["planDigest"],
        "policyDigest": envelope["policyDigest"],
        "approval": approval,
        "action": "ADD_TAGS",
        "arguments": plan,
        "expectedBeforeDigest": "sha256:" + "4" * 64,
        "expectedAfterDigest": "sha256:" + "5" * 64,
        "authorization": {
            "envelope": envelope,
            "signature": {
                "keyArn": KEY_ARN,
                "algorithm": contracts.MUTATION_ALGORITHM,
                "canonicalization": contracts.MUTATION_CANONICALIZATION,
                "envelopeDigest": contracts.digest_bytes(
                    contracts.canonical_mutation_json(envelope)
                ),
                "signatureBase64": __import__("base64").b64encode(
                    signature
                ).decode(),
            },
        },
    }
    request["requestDigest"] = contracts.digest(request)
    job = dataclasses.replace(
        runtime_job,
        pk="MUTATION#" + runtime_job.session_id,
        operation="GOVERNED_TAG_MUTATION",
        request=request,
    )
    monkeypatch.setenv("ARCHON_STAGE", "production")
    monkeypatch.setenv("MUTATION_SIGNING_KEY_ARN", KEY_ARN)
    monkeypatch.setattr(mutation_runtime, "verify_golden_contract", lambda: "ok")
    monkeypatch.setattr(mutation_runtime, "_kms_public_key", lambda arn: private.public_key())
    monkeypatch.setattr(
        mutation_runtime,
        "instant",
        lambda: "2026-08-02T12:02:00.000Z",
    )
    context = {
        "session": {
            "binding": {"leaseExpiresAt": "2026-08-02T13:00:00.000Z"}
        }
    }
    return job, context


def test_embedded_golden_vector_is_verified():
    assert mutation_runtime.verify_golden_contract() == (
        mutation_runtime.GOLDEN_ENVELOPE_DIGEST
    )


def test_local_p256_authorization_is_exact_and_bound(runtime_job, monkeypatch):
    job, context = _signed_job(runtime_job, monkeypatch)
    evidence = mutation_runtime.verify_mutation_request(job, context)
    assert evidence["keyArn"] == KEY_ARN
    assert evidence["algorithm"] == "ECDSA_SHA_256"
    assert evidence["envelopeDigest"] == (
        job.request["authorization"]["signature"]["envelopeDigest"]
    )

    wrong = dataclasses.replace(job, generation="wrong-generation")
    with pytest.raises(
        contracts.ContractError, match="mutation_authorization_invalid"
    ):
        mutation_runtime.verify_mutation_request(wrong, context)

    job.request["authorization"]["signature"]["signatureBase64"] = "AA=="
    with pytest.raises(contracts.ContractError):
        mutation_runtime.verify_mutation_request(job, context)


def test_fresh_mutation_calls_official_add_tags_exactly_once(runtime_job, monkeypatch):
    before = _tag_state([])
    after = _tag_state([contracts.PII_TAG])
    job = dataclasses.replace(
        runtime_job,
        operation="GOVERNED_TAG_MUTATION",
        request={
            "requestDigest": "sha256:" + "1" * 64,
            "policyDigest": "sha256:" + "2" * 64,
            "expectedBeforeDigest": before["stateDigest"],
            "expectedAfterDigest": after["stateDigest"],
        },
    )
    authorization = {
        "keyArn": KEY_ARN,
        "algorithm": "ECDSA_SHA_256",
        "canonicalization": contracts.MUTATION_CANONICALIZATION,
        "envelopeDigest": "sha256:" + "3" * 64,
        "signatureDigest": "sha256:" + "4" * 64,
        "issuedAt": "2026-08-02T12:00:00.000Z",
        "expiresAt": "2026-08-02T12:05:00.000Z",
        "approvalDigest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        mutation_runtime, "verify_mutation_request", lambda *args: authorization
    )
    observations = iter([before, after])

    async def read(_credential):
        return next(observations)

    calls = []

    async def mutate(_credential, *, tool):
        calls.append(tool)
        return {"responseDigest": "sha256:" + "6" * 64}

    monkeypatch.setattr(mutation_runtime, "read_column_tags", read)
    monkeypatch.setattr(mutation_runtime, "mutate_tags", mutate)

    class Store:
        def __init__(self):
            self.ack = []
            self.verified = []

        def mutation_execution(self, _job):
            return None

        def begin_mutation_once(self, *_args, **_kwargs):
            return {
                "phase": "AUTHORIZED",
                "envelopeDigest": authorization["envelopeDigest"],
                "consumedAt": "2026-08-02T12:01:00.000Z",
                "responseDigest": None,
                "beforeDigest": None,
                "afterDigest": None,
                "replayed": False,
            }

        def acknowledge_mutation(self, *_args, **kwargs):
            self.ack.append(kwargs)

        def verify_mutation(self, *_args, **kwargs):
            self.verified.append(kwargs)

    store = Store()
    result = mutation_runtime.execute_mutation(
        job, object(), store, "execution-1", {}
    )
    assert calls == ["add_tags"]
    assert len(store.ack) == 1
    assert len(store.verified) == 1
    assert result["verified"] is True
    assert result["mutationExecutor"] == "official-datahub-mcp"
    assert result["responseDigest"] == contracts.digest(
        contracts.without(result, "responseDigest")
    )


def test_acknowledged_retry_recovers_without_second_mutation(runtime_job, monkeypatch):
    after = _tag_state([contracts.PII_TAG])
    job = dataclasses.replace(
        runtime_job,
        operation="GOVERNED_TAG_MUTATION",
        request={
            "requestDigest": "sha256:" + "1" * 64,
            "policyDigest": "sha256:" + "2" * 64,
            "expectedBeforeDigest": "sha256:" + "7" * 64,
            "expectedAfterDigest": after["stateDigest"],
        },
    )
    authorization = {
        "keyArn": KEY_ARN,
        "algorithm": "ECDSA_SHA_256",
        "canonicalization": contracts.MUTATION_CANONICALIZATION,
        "envelopeDigest": "sha256:" + "3" * 64,
        "signatureDigest": "sha256:" + "4" * 64,
        "issuedAt": "2026-08-02T12:00:00.000Z",
        "expiresAt": "2026-08-02T12:05:00.000Z",
        "approvalDigest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        mutation_runtime, "verify_mutation_request", lambda *args: authorization
    )

    async def read(_credential):
        return after

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("mutation replayed")

    monkeypatch.setattr(mutation_runtime, "read_column_tags", read)
    monkeypatch.setattr(mutation_runtime, "mutate_tags", forbidden)

    class Store:
        verified = 0

        def mutation_execution(self, _job):
            return {
                "phase": "PROVIDER_ACKNOWLEDGED",
                "envelopeDigest": authorization["envelopeDigest"],
                "consumedAt": "2026-08-02T12:01:00.000Z",
                "responseDigest": "sha256:" + "6" * 64,
                "beforeDigest": None,
                "afterDigest": None,
            }

        def verify_mutation(self, *_args, **_kwargs):
            self.verified += 1

    store = Store()
    result = mutation_runtime.execute_mutation(
        job, object(), store, "execution-2", {}
    )
    assert store.verified == 1
    assert result["afterDigest"] == after["stateDigest"]


def test_authorized_only_replay_is_rejected_without_provider_call(
    runtime_job, monkeypatch
):
    job = dataclasses.replace(
        runtime_job,
        operation="GOVERNED_TAG_MUTATION",
        request={
            "requestDigest": "sha256:" + "1" * 64,
            "policyDigest": "sha256:" + "2" * 64,
            "expectedBeforeDigest": "sha256:" + "7" * 64,
            "expectedAfterDigest": "sha256:" + "8" * 64,
        },
    )
    authorization = {
        "envelopeDigest": "sha256:" + "3" * 64,
        "issuedAt": "2026-08-02T12:00:00.000Z",
        "expiresAt": "2026-08-02T12:05:00.000Z",
    }
    monkeypatch.setattr(
        mutation_runtime, "verify_mutation_request", lambda *args: authorization
    )

    class Store:
        def mutation_execution(self, _job):
            return {
                "phase": "AUTHORIZED",
                "envelopeDigest": authorization["envelopeDigest"],
                "consumedAt": "2026-08-02T12:01:00.000Z",
                "responseDigest": None,
            }

    async def read(_credential):
        return _tag_state([])

    monkeypatch.setattr(mutation_runtime, "read_column_tags", read)
    with pytest.raises(
        contracts.ContractError, match="mutation_outcome_indeterminate"
    ):
        mutation_runtime.execute_mutation(
            job, object(), Store(), "execution-3", {}
        )
