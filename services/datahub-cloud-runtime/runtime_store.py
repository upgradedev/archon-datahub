"""DynamoDB job CAS, runtime binding, and encrypted S3 checkpoint storage."""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from contracts import (
    ContractError,
    DIGEST_RE,
    KMS_ARN_RE,
    PROFILE,
    RetryableFailure,
    RuntimeJob,
    canonical_json,
    digest,
    digest_bytes,
    instant,
    normalize_ddb,
    parse_instant,
    validate_cloud_lease,
    validate_registry,
    validate_session_payload,
)

VERSION_RE = re.compile(r"^[A-Za-z0-9._~-]{1,1024}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
BUCKET_RE = re.compile(
    r"^(?!xn--)(?!.*\.\.)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
)
MAX_CHECKPOINT_BYTES = 12 * 1024 * 1024
CLAIM_SECONDS = 12 * 60


def required_env(name: str, *, maximum: int = 2048) -> str:
    value = os.environ.get(name, "")
    if (
        not value
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ContractError("runtime_configuration_invalid")
    return value


class RuntimeStore:
    def __init__(self) -> None:
        self.jobs = boto3.resource("dynamodb").Table(
            required_env("RUNTIME_JOB_TABLE", maximum=255)
        )
        self.sessions = boto3.resource("dynamodb").Table(
            required_env("RUNTIME_SESSION_TABLE", maximum=255)
        )
        self.leases = boto3.resource("dynamodb").Table(
            required_env("CLOUD_RUNTIME_LEASE_TABLE", maximum=255)
        )

    @staticmethod
    def _item(table: Any, key: dict[str, str]) -> dict[str, Any]:
        try:
            response = table.get_item(Key=key, ConsistentRead=True)
        except (BotoCoreError, ClientError) as error:
            raise RetryableFailure("ddb_read_failed") from error
        item = response.get("Item")
        if not isinstance(item, dict):
            raise ContractError("runtime_binding_not_found")
        return normalize_ddb(item)

    def validate_runtime_context(
        self, job: RuntimeJob, *, now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        observed = now or dt.datetime.now(dt.UTC)
        session_item = self._item(
            self.sessions,
            {"pk": "SESSION#" + job.session_id, "sk": "RUNTIME"},
        )
        payload_text = session_item.get("payload")
        if (
            not isinstance(payload_text, str)
            or len(payload_text.encode("utf-8")) > 32 * 1024
        ):
            raise ContractError("runtime_session_invalid")
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as error:
            raise ContractError("runtime_session_invalid") from error
        session = validate_session_payload(payload, job, observed)
        if (
            session_item.get("pk") != "SESSION#" + job.session_id
            or session_item.get("sk") != "RUNTIME"
            or session_item.get("revision") != session["revision"]
            or job.expires_at <= int(observed.timestamp())
            or parse_instant(job.submitted_at) < parse_instant(session["createdAt"])
            or parse_instant(job.submitted_at) > observed
        ):
            raise ContractError("runtime_session_binding_mismatch")

        lease = validate_cloud_lease(
            self._item(
                self.leases,
                {"pk": "CLOUD#LEASE", "sk": "CURRENT"},
            ),
            job,
            observed,
        )
        registry = validate_registry(
            self._item(
                self.sessions,
                {"pk": "RUNTIME#cloud", "sk": "HEALTH"},
            ),
            job,
            observed,
        )
        if session["binding"]["leaseExpiresAt"] != lease["leaseExpiresAt"]:
            raise ContractError("cloud_runtime_lease_mismatch")
        return {"session": session, "lease": lease, "registry": registry}

    def claim(self, job: RuntimeJob, execution_id: str) -> str | None:
        if REQUEST_ID_RE.fullmatch(execution_id) is None:
            raise ContractError("lambda_execution_id_invalid")
        started = instant()
        now_epoch = int(time.time())
        lease_epoch = now_epoch + CLAIM_SECONDS
        names = {"#schema": "schema", "#state": "state"}
        values = {
            ":schema": "archon.runtime-bound-job/v2",
            ":profile": PROFILE,
            ":job": job.job_id,
            ":audit": job.audit_id,
            ":evidence": job.runtime_evidence_digest,
            ":session": job.session_id,
            ":generation": job.generation,
            ":capability": job.capability_digest,
            ":operation": job.operation,
            ":requestDigest": digest(job.request),
            ":queued": "QUEUED",
            ":running": "RUNNING",
            ":now": now_epoch,
            ":lease": lease_epoch,
            ":started": started,
            ":execution": execution_id,
            ":zero": 0,
            ":one": 1,
        }
        condition = (
            "#schema = :schema AND profileId = :profile AND jobId = :job "
            "AND auditId = :audit AND runtimeEvidenceDigest = :evidence "
            "AND sessionId = :session AND generation = :generation "
            "AND capabilityDigest = :capability AND operation = :operation "
            "AND (#state = :queued OR "
            "(#state = :running AND executionLeaseExpiresAt < :now))"
        )
        update = (
            "SET #state = :running, startedAt = :started, "
            "executionId = :execution, executionLeaseExpiresAt = :lease, "
            "requestDigest = :requestDigest, "
            "attempt = if_not_exists(attempt, :zero) + :one"
        )
        try:
            response = self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=update,
                ConditionExpression=condition,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise RetryableFailure("ddb_claim_failed") from error
            current = self._item(self.jobs, {"pk": job.pk, "sk": job.sk})
            exact_identity = (
                current.get("schema") == "archon.runtime-bound-job/v2"
                and current.get("profileId") == PROFILE
                and current.get("jobId") == job.job_id
                and current.get("auditId") == job.audit_id
                and current.get("runtimeEvidenceDigest")
                    == job.runtime_evidence_digest
                and current.get("sessionId") == job.session_id
                and current.get("generation") == job.generation
                and current.get("capabilityDigest") == job.capability_digest
                and current.get("operation") == job.operation
                and current.get("request") == job.request
            )
            if not exact_identity:
                raise ContractError("runtime_job_binding_drift") from error
            if current.get("state") in {"SUCCEEDED", "FAILED"}:
                return None
            if (
                current.get("state") == "RUNNING"
                and type(current.get("executionLeaseExpiresAt")) is int
                and current["executionLeaseExpiresAt"] >= now_epoch
            ):
                raise RetryableFailure("ddb_job_already_running") from error
            raise RetryableFailure("ddb_claim_race") from error
        except BotoCoreError as error:
            raise RetryableFailure("ddb_claim_failed") from error
        attributes = response.get("Attributes")
        if (
            not isinstance(attributes, dict)
            or attributes.get("request") != job.request
            or attributes.get("requestDigest") != digest(job.request)
        ):
            raise RetryableFailure("ddb_claim_result_invalid")
        return started

    def release(self, job: RuntimeJob, execution_id: str) -> None:
        """Release a safely retryable claim back to QUEUED using exact CAS."""
        if REQUEST_ID_RE.fullmatch(execution_id) is None:
            raise ContractError("lambda_execution_id_invalid")
        try:
            self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=(
                    "SET #state=:queued "
                    "REMOVE startedAt, executionId, executionLeaseExpiresAt"
                ),
                ConditionExpression=(
                    "#schema=:schema AND profileId=:profile "
                    "AND jobId=:job AND auditId=:audit "
                    "AND runtimeEvidenceDigest=:evidence "
                    "AND sessionId=:session AND generation=:generation "
                    "AND capabilityDigest=:capability AND operation=:operation "
                    "AND #state=:running AND executionId=:execution "
                    "AND requestDigest=:request"
                ),
                ExpressionAttributeNames={"#schema": "schema", "#state": "state"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": PROFILE,
                    ":job": job.job_id,
                    ":audit": job.audit_id,
                    ":evidence": job.runtime_evidence_digest,
                    ":session": job.session_id,
                    ":generation": job.generation,
                    ":capability": job.capability_digest,
                    ":operation": job.operation,
                    ":running": "RUNNING",
                    ":queued": "QUEUED",
                    ":execution": execution_id,
                    ":request": digest(job.request),
                },
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == (
                "ConditionalCheckFailedException"
            ):
                current = self._item(self.jobs, {"pk": job.pk, "sk": job.sk})
                if current.get("state") in {"SUCCEEDED", "FAILED", "QUEUED"}:
                    return
            raise RetryableFailure("ddb_claim_release_failed") from error
        except BotoCoreError as error:
            raise RetryableFailure("ddb_claim_release_failed") from error

    def mutation_execution(self, job: RuntimeJob) -> dict[str, Any] | None:
        item = self._item(self.jobs, {"pk": job.pk, "sk": job.sk})
        phase = item.get("mutationPhase")
        if phase is None:
            return None
        expected = {
            "phase": phase,
            "envelopeDigest": item.get("mutationEnvelopeDigest"),
            "consumedAt": item.get("mutationConsumedAt"),
            "responseDigest": item.get("mutationResponseDigest"),
            "beforeDigest": item.get("mutationBeforeDigest"),
            "afterDigest": item.get("mutationAfterDigest"),
        }
        if (
            phase not in {"AUTHORIZED", "PROVIDER_ACKNOWLEDGED", "VERIFIED"}
            or DIGEST_RE.fullmatch(str(expected["envelopeDigest"])) is None
            or not isinstance(expected["consumedAt"], str)
            or (
                phase in {"PROVIDER_ACKNOWLEDGED", "VERIFIED"}
                and DIGEST_RE.fullmatch(str(expected["responseDigest"])) is None
            )
            or (
                phase == "VERIFIED"
                and (
                    DIGEST_RE.fullmatch(str(expected["beforeDigest"])) is None
                    or DIGEST_RE.fullmatch(str(expected["afterDigest"])) is None
                )
            )
        ):
            raise ContractError("mutation_execution_ledger_invalid")
        return expected

    def begin_mutation_once(
        self,
        job: RuntimeJob,
        execution_id: str,
        *,
        envelope_digest: str,
        consumed_at: str,
    ) -> dict[str, Any]:
        if (
            DIGEST_RE.fullmatch(envelope_digest) is None
            or REQUEST_ID_RE.fullmatch(execution_id) is None
        ):
            raise ContractError("mutation_execution_binding_invalid")
        parse_instant(consumed_at)
        try:
            self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=(
                    "SET mutationPhase=:authorized, "
                    "mutationEnvelopeDigest=:envelope, "
                    "mutationConsumedAt=:consumed"
                ),
                ConditionExpression=(
                    "#state=:running AND executionId=:execution "
                    "AND requestDigest=:request "
                    "AND attribute_not_exists(mutationPhase)"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":authorized": "AUTHORIZED",
                    ":envelope": envelope_digest,
                    ":consumed": consumed_at,
                    ":running": "RUNNING",
                    ":execution": execution_id,
                    ":request": digest(job.request),
                },
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != (
                "ConditionalCheckFailedException"
            ):
                raise RetryableFailure("mutation_ledger_write_failed") from error
            existing = self.mutation_execution(job)
            if existing is None:
                raise RetryableFailure("mutation_ledger_race") from error
            return {**existing, "replayed": True}
        except BotoCoreError as error:
            raise RetryableFailure("mutation_ledger_write_failed") from error
        return {
            "phase": "AUTHORIZED",
            "envelopeDigest": envelope_digest,
            "consumedAt": consumed_at,
            "responseDigest": None,
            "beforeDigest": None,
            "afterDigest": None,
            "replayed": False,
        }

    def acknowledge_mutation(
        self,
        job: RuntimeJob,
        execution_id: str,
        *,
        envelope_digest: str,
        response_digest: str,
    ) -> None:
        if (
            DIGEST_RE.fullmatch(envelope_digest) is None
            or DIGEST_RE.fullmatch(response_digest) is None
        ):
            raise ContractError("mutation_execution_binding_invalid")
        try:
            self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=(
                    "SET mutationPhase=:ack, "
                    "mutationResponseDigest=:response"
                ),
                ConditionExpression=(
                    "#state=:running AND executionId=:execution "
                    "AND mutationPhase=:authorized "
                    "AND mutationEnvelopeDigest=:envelope"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":ack": "PROVIDER_ACKNOWLEDGED",
                    ":response": response_digest,
                    ":running": "RUNNING",
                    ":execution": execution_id,
                    ":authorized": "AUTHORIZED",
                    ":envelope": envelope_digest,
                },
            )
        except (BotoCoreError, ClientError) as error:
            try:
                existing = self.mutation_execution(job)
            except (ContractError, RetryableFailure):
                raise RetryableFailure("mutation_ledger_ack_failed") from error
            if (
                existing is not None
                and existing["phase"] in {"PROVIDER_ACKNOWLEDGED", "VERIFIED"}
                and existing["envelopeDigest"] == envelope_digest
                and existing["responseDigest"] == response_digest
            ):
                return
            raise RetryableFailure("mutation_ledger_ack_failed") from error

    def verify_mutation(
        self,
        job: RuntimeJob,
        execution_id: str,
        *,
        envelope_digest: str,
        before_digest: str,
        after_digest: str,
    ) -> None:
        if any(
            DIGEST_RE.fullmatch(value) is None
            for value in (envelope_digest, before_digest, after_digest)
        ):
            raise ContractError("mutation_execution_binding_invalid")
        try:
            self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=(
                    "SET mutationPhase=:verified, "
                    "mutationBeforeDigest=:before, "
                    "mutationAfterDigest=:after"
                ),
                ConditionExpression=(
                    "#state=:running AND executionId=:execution "
                    "AND mutationPhase=:ack "
                    "AND mutationEnvelopeDigest=:envelope "
                    "AND attribute_exists(mutationResponseDigest)"
                ),
                ExpressionAttributeNames={"#state": "state"},
                ExpressionAttributeValues={
                    ":verified": "VERIFIED",
                    ":before": before_digest,
                    ":after": after_digest,
                    ":running": "RUNNING",
                    ":execution": execution_id,
                    ":ack": "PROVIDER_ACKNOWLEDGED",
                    ":envelope": envelope_digest,
                },
            )
        except (BotoCoreError, ClientError) as error:
            try:
                existing = self.mutation_execution(job)
            except (ContractError, RetryableFailure):
                raise RetryableFailure("mutation_ledger_verify_failed") from error
            if (
                existing is not None
                and existing["phase"] == "VERIFIED"
                and existing["envelopeDigest"] == envelope_digest
                and existing["beforeDigest"] == before_digest
                and existing["afterDigest"] == after_digest
            ):
                return
            raise RetryableFailure("mutation_ledger_verify_failed") from error

    def terminal(
        self,
        job: RuntimeJob,
        execution_id: str,
        receipt: dict[str, Any],
    ) -> None:
        state = receipt.get("state")
        if state not in {"SUCCEEDED", "FAILED"}:
            raise ContractError("receipt_terminal_state_invalid")
        try:
            self.jobs.update_item(
                Key={"pk": job.pk, "sk": job.sk},
                UpdateExpression=(
                    "SET #state = :state, completedAt = :completed, "
                    "receipt = :receipt REMOVE executionLeaseExpiresAt"
                ),
                ConditionExpression=(
                    "#schema = :schema AND profileId = :profile "
                    "AND jobId = :job AND auditId = :audit "
                    "AND runtimeEvidenceDigest = :evidence "
                    "AND sessionId = :session "
                    "AND generation = :generation "
                    "AND capabilityDigest = :capability "
                    "AND operation = :operation AND #state = :running "
                    "AND executionId = :execution "
                    "AND requestDigest = :requestDigest"
                ),
                ExpressionAttributeNames={"#schema": "schema", "#state": "state"},
                ExpressionAttributeValues={
                    ":schema": "archon.runtime-bound-job/v2",
                    ":profile": PROFILE,
                    ":job": job.job_id,
                    ":audit": job.audit_id,
                    ":evidence": job.runtime_evidence_digest,
                    ":session": job.session_id,
                    ":generation": job.generation,
                    ":capability": job.capability_digest,
                    ":operation": job.operation,
                    ":running": "RUNNING",
                    ":execution": execution_id,
                    ":requestDigest": digest(job.request),
                    ":state": state,
                    ":completed": receipt["completedAt"],
                    ":receipt": receipt,
                },
            )
        except (BotoCoreError, ClientError) as error:
            raise RetryableFailure("ddb_terminal_write_failed") from error


class CheckpointStore:
    def __init__(self, sessions_table: Any) -> None:
        self.table = sessions_table
        self.s3 = boto3.client("s3")
        self.bucket = required_env("CLOUD_CHECKPOINT_BUCKET", maximum=63)
        self.kms_key_arn = required_env("CLOUD_CHECKPOINT_KMS_KEY_ARN")
        if BUCKET_RE.fullmatch(self.bucket) is None:
            raise ContractError("checkpoint_bucket_invalid")
        if KMS_ARN_RE.fullmatch(self.kms_key_arn) is None:
            raise ContractError("checkpoint_kms_key_invalid")

    @staticmethod
    def _key(job: RuntimeJob) -> str:
        return (
            "cloud-runtime/v2/"
            + job.session_id
            + "/"
            + job.generation
            + "/analytics-state.sqlite"
        )

    def restore(
        self,
        job: RuntimeJob,
        destination: Path,
        *,
        oauth_key_digest: str,
        run_handle_key_digest: str,
    ) -> int:
        try:
            response = self.table.get_item(
                Key={"pk": "CHECKPOINT#" + job.session_id, "sk": "STATE"},
                ConsistentRead=True,
            )
        except (BotoCoreError, ClientError) as error:
            raise RetryableFailure("checkpoint_registry_read_failed") from error
        marker = response.get("Item")
        if marker is None:
            return 0
        marker = normalize_ddb(marker)
        expected = {
            "pk", "sk", "schemaVersion", "profileId", "sessionId", "generation",
            "capabilityDigest", "revision", "s3Key", "versionId", "stateDigest",
            "bytes", "oauthKeyDigest", "runHandleKeyDigest", "updatedAt",
        }
        if (
            not isinstance(marker, dict)
            or set(marker) != expected
            or marker.get("schemaVersion") != "archon.analytics-checkpoint/v1"
            or marker.get("profileId") != PROFILE
            or marker.get("sessionId") != job.session_id
            or marker.get("generation") != job.generation
            or marker.get("capabilityDigest") != job.capability_digest
            or marker.get("s3Key") != self._key(job)
            or not isinstance(marker.get("revision"), int)
            or marker["revision"] < 1
            or not isinstance(marker.get("bytes"), int)
            or not 1 <= marker["bytes"] <= MAX_CHECKPOINT_BYTES
            or DIGEST_RE.fullmatch(str(marker.get("stateDigest"))) is None
            or VERSION_RE.fullmatch(str(marker.get("versionId"))) is None
            or marker.get("oauthKeyDigest") != oauth_key_digest
            or marker.get("runHandleKeyDigest") != run_handle_key_digest
        ):
            raise ContractError("checkpoint_registry_invalid")
        try:
            stored = self.s3.get_object(
                Bucket=self.bucket,
                Key=marker["s3Key"],
                VersionId=marker["versionId"],
                ChecksumMode="ENABLED",
            )
            stream = stored["Body"]
            try:
                body = stream.read(MAX_CHECKPOINT_BYTES + 1)
            finally:
                stream.close()
        except (BotoCoreError, ClientError, KeyError) as error:
            raise RetryableFailure("checkpoint_restore_failed") from error
        expected_checksum = base64.b64encode(
            bytes.fromhex(marker["stateDigest"].removeprefix("sha256:"))
        ).decode("ascii")
        if (
            len(body) != marker["bytes"]
            or len(body) > MAX_CHECKPOINT_BYTES
            or stored.get("VersionId") != marker["versionId"]
            or stored.get("ServerSideEncryption") != "aws:kms"
            or stored.get("SSEKMSKeyId") != self.kms_key_arn
            or stored.get("ChecksumSHA256") != expected_checksum
            or digest_bytes(body) != marker["stateDigest"]
        ):
            raise ContractError("checkpoint_object_invalid")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return marker["revision"]

    def save(
        self,
        job: RuntimeJob,
        state: bytes,
        *,
        expected_revision: int,
        oauth_key_digest: str,
        run_handle_key_digest: str,
    ) -> dict[str, Any]:
        if not 1 <= len(state) <= MAX_CHECKPOINT_BYTES:
            raise ContractError("checkpoint_size_invalid")
        next_revision = expected_revision + 1
        state_digest = digest_bytes(state)
        key = self._key(job)
        checksum = base64.b64encode(
            bytes.fromhex(state_digest.removeprefix("sha256:"))
        ).decode("ascii")
        try:
            uploaded = self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=state,
                ContentType="application/vnd.sqlite3",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self.kms_key_arn,
                ChecksumAlgorithm="SHA256",
                ChecksumSHA256=checksum,
                Metadata={
                    "schema": "archon-analytics-checkpoint-v1",
                    "session": job.session_id,
                    "generation": job.generation,
                    "revision": str(next_revision),
                    "sha256": state_digest.removeprefix("sha256:"),
                },
            )
        except (BotoCoreError, ClientError) as error:
            raise RetryableFailure("checkpoint_upload_failed") from error
        version_id = uploaded.get("VersionId")
        if (
            VERSION_RE.fullmatch(str(version_id)) is None
            or uploaded.get("ServerSideEncryption") != "aws:kms"
            or uploaded.get("SSEKMSKeyId") != self.kms_key_arn
            or uploaded.get("ChecksumSHA256") != checksum
        ):
            if VERSION_RE.fullmatch(str(version_id)) is not None:
                try:
                    self.s3.delete_object(
                        Bucket=self.bucket,
                        Key=key,
                        VersionId=version_id,
                    )
                except (BotoCoreError, ClientError):
                    pass
            raise RetryableFailure("checkpoint_upload_unversioned")
        marker = {
            "pk": "CHECKPOINT#" + job.session_id,
            "sk": "STATE",
            "schemaVersion": "archon.analytics-checkpoint/v1",
            "profileId": PROFILE,
            "sessionId": job.session_id,
            "generation": job.generation,
            "capabilityDigest": job.capability_digest,
            "revision": next_revision,
            "s3Key": key,
            "versionId": version_id,
            "stateDigest": state_digest,
            "bytes": len(state),
            "oauthKeyDigest": oauth_key_digest,
            "runHandleKeyDigest": run_handle_key_digest,
            "updatedAt": instant(),
        }
        try:
            if expected_revision == 0:
                self.table.put_item(
                    Item=marker,
                    ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)",
                )
            else:
                self.table.put_item(
                    Item=marker,
                    ConditionExpression="revision = :expected",
                    ExpressionAttributeValues={":expected": expected_revision},
                )
        except (BotoCoreError, ClientError) as error:
            try:
                self.s3.delete_object(
                    Bucket=self.bucket, Key=key, VersionId=version_id
                )
            except (BotoCoreError, ClientError):
                pass
            raise RetryableFailure("checkpoint_registry_cas_failed") from error
        return {
            "schemaVersion": "archon.analytics-checkpoint-receipt/v1",
            "revision": next_revision,
            "stateDigest": state_digest,
            "objectVersionDigest": digest({"versionId": version_id}),
            "encryptedAtRest": True,
            "providerPayloadStored": False,
        }
