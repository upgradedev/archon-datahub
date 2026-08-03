"""Locally verified, replay-safe governed DataHub Cloud tag mutation."""

from __future__ import annotations

import asyncio
import functools
import json
import os
import stat
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from contracts import (
    COLUMN_PATH,
    ContractError,
    DATASET_URN,
    DIGEST_RE,
    KMS_ARN_RE,
    MUTATION_ALGORITHM,
    MUTATION_CANONICALIZATION,
    PII_TAG,
    RuntimeJob,
    canonical_mutation_json,
    digest,
    digest_bytes,
    exact_keys,
    instant,
    parse_instant,
    strict_base64,
    verify_digest_object,
    without,
)
from managed_mcp import ManagedCredential, mutate_tags, read_column_tags
from runtime_store import RuntimeStore, required_env

GOLDEN_PATH = Path(
    "/opt/archon/contracts/core-mutation-authorization-golden.json"
)
GOLDEN_ENVELOPE_DIGEST = (
    "sha256:16aeefe29cea76b19af4270dbe0453b3fbdaa72d425abd18ea969affc066c935"
)
GOLDEN_PUBLIC_KEY = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw8Cjm2/B/bJHY1SXSWUzaDxp2+7p"
    "5keuTDwOJQ+yKkdxryCXVn1Yn3bdSZtn89HuvKnJ6p7bsS2CnP4wnx56mg=="
)
GOLDEN_SIGNATURE = (
    "MEQCIE/UUoYswGVf70htGLE2e0hNoLQ/r9/sN2ECqPHR0ZsFAiAtY0kR+mwS0oxG"
    "O2tnc+K4nfudaXZCx5VXsN94c02l1g=="
)
AUTHORIZATION_KEYS = {
    "schemaVersion", "stage", "sessionId", "generation", "capabilityDigest",
    "jobId", "approvalId", "planDigest", "policyDigest", "target", "tool",
    "arguments", "issuedAt", "expiresAt",
}
OUTER_KEYS = {
    "schemaVersion", "auditId", "runtimeEvidenceDigest",
    "auditEvidenceDigest", "planDigest", "policyDigest", "approval",
    "action", "arguments", "expectedBeforeDigest", "expectedAfterDigest",
    "authorization", "requestDigest",
}


def _regular_json(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or not 1 <= file_stat.st_size <= 32 * 1024:
            raise ContractError("mutation_golden_fixture_invalid")
        data = os.read(descriptor, file_stat.st_size + 1)
    finally:
        os.close(descriptor)
    if len(data) != file_stat.st_size:
        raise ContractError("mutation_golden_fixture_invalid")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("mutation_golden_fixture_invalid") from error
    if not isinstance(value, dict):
        raise ContractError("mutation_golden_fixture_invalid")
    return value


def _p256_public_key(value: bytes) -> ec.EllipticCurvePublicKey:
    if not 80 <= len(value) <= 256:
        raise ContractError("mutation_public_key_invalid")
    try:
        public_key = serialization.load_der_public_key(value)
    except (TypeError, ValueError) as error:
        raise ContractError("mutation_public_key_invalid") from error
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
        or public_key.key_size != 256
    ):
        raise ContractError("mutation_public_key_invalid")
    return public_key


def _verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    envelope: dict[str, Any],
    signature: bytes,
) -> None:
    envelope_hash = hashes.Hash(hashes.SHA256())
    envelope_hash.update(canonical_mutation_json(envelope))
    value = envelope_hash.finalize()
    try:
        r_value, s_value = utils.decode_dss_signature(signature)
        if r_value <= 0 or s_value <= 0:
            raise ValueError("non-positive ECDSA coordinate")
        public_key.verify(
            signature,
            value,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (InvalidSignature, ValueError) as error:
        raise ContractError("mutation_signature_invalid") from error


@functools.lru_cache(maxsize=1)
def verify_golden_contract() -> str:
    fixture = _regular_json(GOLDEN_PATH)
    expected = {
        "schemaVersion", "canonicalization", "envelope", "canonicalJson",
        "envelopeDigest", "keySpec", "algorithm", "publicKeyDerBase64",
        "signatureBase64",
    }
    if (
        not exact_keys(fixture, expected)
        or fixture.get("schemaVersion")
            != "archon.core-mutation-authorization-golden/v1"
        or fixture.get("canonicalization") != MUTATION_CANONICALIZATION
        or fixture.get("keySpec") != "ECC_NIST_P256"
        or fixture.get("algorithm") != MUTATION_ALGORITHM
        or fixture.get("envelopeDigest") != GOLDEN_ENVELOPE_DIGEST
        or fixture.get("publicKeyDerBase64") != GOLDEN_PUBLIC_KEY
        or fixture.get("signatureBase64") != GOLDEN_SIGNATURE
        or not isinstance(fixture.get("envelope"), dict)
    ):
        raise ContractError("mutation_golden_fixture_invalid")
    canonical = canonical_mutation_json(fixture["envelope"])
    if (
        fixture["canonicalJson"] != canonical.decode("ascii")
        or digest_bytes(canonical) != fixture["envelopeDigest"]
    ):
        raise ContractError("mutation_golden_fixture_invalid")
    public_der = strict_base64(
        fixture["publicKeyDerBase64"], minimum=80, maximum=256
    )
    signature = strict_base64(
        fixture["signatureBase64"], minimum=8, maximum=256
    )
    _verify_signature(_p256_public_key(public_der), fixture["envelope"], signature)
    return fixture["envelopeDigest"]


@functools.lru_cache(maxsize=1)
def _kms_public_key(key_arn: str) -> ec.EllipticCurvePublicKey:
    try:
        response = boto3.client("kms").get_public_key(KeyId=key_arn)
    except (BotoCoreError, ClientError) as error:
        raise ContractError("mutation_public_key_unavailable") from error
    algorithms = response.get("SigningAlgorithms")
    public_value = response.get("PublicKey")
    if (
        response.get("KeyId") != key_arn
        or response.get("KeySpec") != "ECC_NIST_P256"
        or response.get("KeyUsage") != "SIGN_VERIFY"
        or not isinstance(algorithms, list)
        or MUTATION_ALGORITHM not in algorithms
        or not isinstance(public_value, bytes)
    ):
        raise ContractError("mutation_public_key_invalid")
    return _p256_public_key(public_value)


def _canonical_arguments() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    plan = {
        "tagUrns": [PII_TAG],
        "entityUrns": [DATASET_URN],
        "columnPaths": [COLUMN_PATH],
    }
    official = {
        "tag_urns": [PII_TAG],
        "entity_urns": [DATASET_URN],
        "column_paths": [COLUMN_PATH],
    }
    return plan, official


def _policy_digest() -> str:
    return digest({
        "schemaVersion": "archon.governed-mcp-mutation-policy/v1",
        "action": "ADD_TAGS",
        "tool": "add_tags",
        "tagUrns": [PII_TAG],
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "writeAuthority": "archon-remediation-worker",
    })


def verify_mutation_request(
    job: RuntimeJob,
    runtime_context: dict[str, Any],
) -> dict[str, Any]:
    verify_golden_contract()
    request = job.request
    plan_arguments, official_arguments = _canonical_arguments()
    approval = request.get("approval")
    authorization = request.get("authorization")
    if (
        not exact_keys(request, OUTER_KEYS)
        or request.get("schemaVersion")
            != "archon.core-governed-tag-mutation/v1"
        or request.get("auditId") != job.audit_id
        or request.get("runtimeEvidenceDigest")
            != job.runtime_evidence_digest
        or DIGEST_RE.fullmatch(str(request.get("auditEvidenceDigest"))) is None
        or DIGEST_RE.fullmatch(str(request.get("planDigest"))) is None
        or request.get("policyDigest") != _policy_digest()
        or request.get("action") != "ADD_TAGS"
        or request.get("arguments") != plan_arguments
        or DIGEST_RE.fullmatch(str(request.get("expectedBeforeDigest"))) is None
        or DIGEST_RE.fullmatch(str(request.get("expectedAfterDigest"))) is None
        or request["expectedBeforeDigest"] == request["expectedAfterDigest"]
        or request.get("requestDigest") != digest(without(request, "requestDigest"))
        or not exact_keys(
            approval,
            {"approvalId", "decision", "approverDigest", "decidedAt", "digest"},
        )
        or approval.get("decision") != "APPROVE"
        or DIGEST_RE.fullmatch(str(approval.get("approverDigest"))) is None
        or not verify_digest_object(approval)
        or not exact_keys(authorization, {"envelope", "signature"})
    ):
        raise ContractError("governed_mutation_request_invalid")

    envelope = authorization["envelope"]
    signature = authorization["signature"]
    stage = required_env("ARCHON_STAGE", maximum=32)
    key_arn = required_env("MUTATION_SIGNING_KEY_ARN")
    if KMS_ARN_RE.fullmatch(key_arn) is None:
        raise ContractError("mutation_signing_key_invalid")
    if (
        not exact_keys(envelope, AUTHORIZATION_KEYS)
        or envelope.get("schemaVersion")
            != "archon.core-mutation-authorization/v1"
        or envelope.get("stage") != stage
        or envelope.get("sessionId") != job.session_id
        or envelope.get("generation") != job.generation
        or envelope.get("capabilityDigest") != job.capability_digest
        or envelope.get("jobId") != job.job_id
        or envelope.get("approvalId") != approval["approvalId"]
        or envelope.get("planDigest") != request["planDigest"]
        or envelope.get("policyDigest") != request["policyDigest"]
        or envelope.get("target")
            != {"entityUrn": DATASET_URN, "columnPath": COLUMN_PATH}
        or envelope.get("tool") != "add_tags"
        or envelope.get("arguments") != official_arguments
        or not exact_keys(
            signature,
            {
                "keyArn", "algorithm", "canonicalization",
                "envelopeDigest", "signatureBase64",
            },
        )
        or signature.get("keyArn") != key_arn
        or signature.get("algorithm") != MUTATION_ALGORITHM
        or signature.get("canonicalization") != MUTATION_CANONICALIZATION
        or signature.get("envelopeDigest") != digest_bytes(
            canonical_mutation_json(envelope)
        )
    ):
        raise ContractError("mutation_authorization_invalid")

    issued_at = parse_instant(envelope["issuedAt"])
    expires_at = parse_instant(envelope["expiresAt"])
    decided_at = parse_instant(approval["decidedAt"])
    observed = parse_instant(instant())
    lease_expires = parse_instant(
        runtime_context["session"]["binding"]["leaseExpiresAt"]
    )
    if issued_at < decided_at or expires_at <= issued_at:
        raise ContractError("mutation_authorization_invalid")
    if (
        (expires_at - issued_at).total_seconds() > 300
        or expires_at > lease_expires
        or observed < issued_at
        or observed > expires_at
    ):
        raise ContractError("mutation_authorization_expired")
    signature_bytes = strict_base64(
        signature["signatureBase64"], minimum=8, maximum=256
    )
    _verify_signature(_kms_public_key(key_arn), envelope, signature_bytes)
    return {
        "keyArn": key_arn,
        "algorithm": MUTATION_ALGORITHM,
        "canonicalization": MUTATION_CANONICALIZATION,
        "envelopeDigest": signature["envelopeDigest"],
        "signatureDigest": digest_bytes(signature_bytes),
        "issuedAt": envelope["issuedAt"],
        "expiresAt": envelope["expiresAt"],
        "approvalDigest": approval["digest"],
    }


def _clean_tag_result(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("_proof", None)
    return result


def _expected_after(before: dict[str, Any]) -> dict[str, Any]:
    tags = sorted(set(before["tagUrns"]) | {PII_TAG})
    state = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": tags,
    }
    return {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **state,
        "stateDigest": digest(state),
    }


def _result(
    job: RuntimeJob,
    authorization: dict[str, Any],
    *,
    response_digest: str,
    before_digest: str,
    after_digest: str,
    consumed_at: str,
) -> dict[str, Any]:
    result = {
        "schemaVersion": "archon.core-governed-tag-result/v1",
        "requestDigest": job.request["requestDigest"],
        "policyDigest": job.request["policyDigest"],
        "beforeDigest": before_digest,
        "afterDigest": after_digest,
        "verified": True,
        "mutationExecutor": "official-datahub-mcp",
        "officialMcpMutation": {
            "tool": "add_tags",
            "policyDigest": job.request["policyDigest"],
            "approvalDigest": authorization["approvalDigest"],
            "requestDigest": job.request["requestDigest"],
            "responseDigest": response_digest,
        },
        "authorizationEvidence": {
            "keyArn": authorization["keyArn"],
            "algorithm": authorization["algorithm"],
            "canonicalization": authorization["canonicalization"],
            "envelopeDigest": authorization["envelopeDigest"],
            "signatureDigest": authorization["signatureDigest"],
            "consumedAt": consumed_at,
        },
    }
    return {**result, "responseDigest": digest(result)}


def _validate_ledger(
    ledger: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    if (
        ledger["envelopeDigest"] != authorization["envelopeDigest"]
        or parse_instant(ledger["consumedAt"])
            < parse_instant(authorization["issuedAt"])
        or parse_instant(ledger["consumedAt"])
            > parse_instant(authorization["expiresAt"])
    ):
        raise ContractError("mutation_replay_binding_mismatch")


def _recover_mutation(
    job: RuntimeJob,
    credential: ManagedCredential,
    store: RuntimeStore,
    execution_id: str,
    authorization: dict[str, Any],
    ledger: dict[str, Any],
) -> dict[str, Any]:
    _validate_ledger(ledger, authorization)
    observed = _clean_tag_result(asyncio.run(read_column_tags(credential)))
    if ledger["phase"] == "AUTHORIZED":
        # The authorization is consumed, but an exact provider response was not
        # durably acknowledged. Never replay the side effect.
        raise ContractError("mutation_outcome_indeterminate")
    if (
        ledger["phase"] not in {"PROVIDER_ACKNOWLEDGED", "VERIFIED"}
        or observed["stateDigest"] != job.request["expectedAfterDigest"]
        or DIGEST_RE.fullmatch(str(ledger.get("responseDigest"))) is None
    ):
        raise ContractError("mutation_recovery_state_mismatch")
    if ledger["phase"] == "PROVIDER_ACKNOWLEDGED":
        store.verify_mutation(
            job,
            execution_id,
            envelope_digest=authorization["envelopeDigest"],
            before_digest=job.request["expectedBeforeDigest"],
            after_digest=observed["stateDigest"],
        )
    return _result(
        job,
        authorization,
        response_digest=ledger["responseDigest"],
        before_digest=job.request["expectedBeforeDigest"],
        after_digest=observed["stateDigest"],
        consumed_at=ledger["consumedAt"],
    )


def execute_mutation(
    job: RuntimeJob,
    credential: ManagedCredential,
    store: RuntimeStore,
    execution_id: str,
    runtime_context: dict[str, Any],
) -> dict[str, Any]:
    authorization = verify_mutation_request(job, runtime_context)

    existing = store.mutation_execution(job)
    if existing is not None:
        return _recover_mutation(
            job,
            credential,
            store,
            execution_id,
            authorization,
            existing,
        )

    before = _clean_tag_result(asyncio.run(read_column_tags(credential)))
    if before["stateDigest"] != job.request["expectedBeforeDigest"]:
        raise ContractError("mutation_compare_and_swap_failed")
    expected_after = _expected_after(before)
    if (
        expected_after["stateDigest"] != job.request["expectedAfterDigest"]
        or PII_TAG in before["tagUrns"]
    ):
        raise ContractError("mutation_expected_state_invalid")

    consumed_at = instant()
    ledger = store.begin_mutation_once(
        job,
        execution_id,
        envelope_digest=authorization["envelopeDigest"],
        consumed_at=consumed_at,
    )
    if ledger.get("replayed") is True:
        return _recover_mutation(
            job,
            credential,
            store,
            execution_id,
            authorization,
            ledger,
        )
    _validate_ledger(ledger, authorization)

    mutation = asyncio.run(mutate_tags(credential, tool="add_tags"))
    response_digest = mutation["responseDigest"]
    store.acknowledge_mutation(
        job,
        execution_id,
        envelope_digest=authorization["envelopeDigest"],
        response_digest=response_digest,
    )
    after = _clean_tag_result(asyncio.run(read_column_tags(credential)))
    if after["stateDigest"] != job.request["expectedAfterDigest"]:
        raise ContractError("mutation_postcondition_failed")
    store.verify_mutation(
        job,
        execution_id,
        envelope_digest=authorization["envelopeDigest"],
        before_digest=before["stateDigest"],
        after_digest=after["stateDigest"],
    )
    return _result(
        job,
        authorization,
        response_digest=response_digest,
        before_digest=before["stateDigest"],
        after_digest=after["stateDigest"],
        consumed_at=ledger["consumedAt"],
    )
