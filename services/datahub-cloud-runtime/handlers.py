"""DynamoDB stream entry points for the isolated DataHub Cloud v2 roles."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from contracts import (
    COLUMN_PATH,
    ContractError,
    DATASET_URN,
    DIGEST_RE,
    MUTATION_OPERATIONS,
    PII_TAG,
    READ_OPERATIONS,
    RetryableFailure,
    RuntimeJob,
    TAG_RE,
    digest,
    exact_keys,
    instant,
    job_receipt,
    parse_job_record,
    safe_error,
)
from managed_mcp import (
    ManagedCredential,
    parse_managed_secret,
    read_column_tags,
)
from runtime_store import CheckpointStore, RuntimeStore, required_env


DDB_STREAM_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):dynamodb:[a-z0-9-]+:"
    r"\d{12}:table/[A-Za-z0-9_.-]{3,255}/stream/.{10,64}$"
)
SECRET_ARN_RE = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:"
    r"\d{12}:secret:[A-Za-z0-9/_+=.@-]{7,512}$"
)


Executor = Callable[
    [RuntimeJob, ManagedCredential, RuntimeStore, str, dict[str, Any]],
    tuple[dict[str, Any], dict[str, Any] | None],
]


def _load_secret(purpose: str) -> ManagedCredential:
    variable = (
        "DATAHUB_CLOUD_READER_SECRET_ARN"
        if purpose == "reader"
        else "DATAHUB_CLOUD_WRITER_SECRET_ARN"
    )
    secret_arn = required_env(variable)
    if SECRET_ARN_RE.fullmatch(secret_arn) is None:
        raise ContractError("cloud_secret_reference_invalid")
    try:
        response = boto3.client("secretsmanager").get_secret_value(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
        )
    except (BotoCoreError, ClientError) as error:
        raise RetryableFailure("cloud_secret_unavailable") from error
    value = response.get("SecretString")
    stages = response.get("VersionStages")
    if (
        response.get("ARN") != secret_arn
        or not isinstance(stages, list)
        or "AWSCURRENT" not in stages
        or not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= 16 * 1024
        or response.get("SecretBinary") is not None
    ):
        raise ContractError("cloud_secret_invalid")
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as error:
        raise ContractError("cloud_secret_invalid") from error
    return parse_managed_secret(payload, purpose=purpose)


def _tag_state(value: Any, *, require_pii: bool = False) -> dict[str, Any]:
    tag_urns = value.get("tagUrns") if isinstance(value, dict) else None
    state = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": tag_urns,
    }
    if (
        not exact_keys(
            value,
            {"schemaVersion", "entityUrn", "columnPath", "tagUrns", "stateDigest"},
        )
        or value.get("schemaVersion")
            != "archon.core-tag-read-result/v1"
        or value.get("entityUrn") != DATASET_URN
        or value.get("columnPath") != COLUMN_PATH
        or not isinstance(tag_urns, list)
        or len(tag_urns) > 256
        or tag_urns != sorted(set(tag_urns))
        or any(
            not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None
            for tag in tag_urns
        )
        or value.get("stateDigest") != digest(state)
        or (require_pii and PII_TAG not in tag_urns)
    ):
        raise ContractError("post_mutation_expected_state_invalid")
    return dict(value)


def _read_request(job: RuntimeJob) -> dict[str, Any]:
    request = job.request
    if (
        not exact_keys(
            request,
            {
                "schemaVersion", "auditId", "runtimeEvidenceDigest",
                "entityUrn", "columnPath",
            },
        )
        or request.get("schemaVersion") != "archon.core-tag-read/v1"
        or request.get("auditId") != job.audit_id
        or request.get("runtimeEvidenceDigest")
            != job.runtime_evidence_digest
        or request.get("entityUrn") != DATASET_URN
        or request.get("columnPath") != COLUMN_PATH
    ):
        raise ContractError("tag_read_request_invalid")
    return request


def _post_read_request(
    job: RuntimeJob,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = job.request
    if (
        not exact_keys(
            request,
            {
                "schemaVersion", "originalRequest",
                "sourceMutationAuditId", "sourceMutationReceiptDigest",
                "postMutationExpectedTagState",
            },
        )
        or request.get("schemaVersion")
            != "archon.core-post-mutation-tag-read/v1"
        or request.get("sourceMutationAuditId") != job.audit_id
        or DIGEST_RE.fullmatch(
            str(request.get("sourceMutationReceiptDigest"))
        ) is None
        or not isinstance(request.get("originalRequest"), dict)
    ):
        raise ContractError("post_tag_read_request_invalid")
    original_job = RuntimeJob(
        event_id=job.event_id,
        pk=job.pk,
        sk=job.sk,
        job_id=job.job_id,
        audit_id=job.audit_id,
        runtime_evidence_digest=job.runtime_evidence_digest,
        session_id=job.session_id,
        generation=job.generation,
        capability_digest=job.capability_digest,
        operation="READ_TAGS",
        request=request["originalRequest"],
        submitted_at=job.submitted_at,
        expires_at=job.expires_at,
    )
    _read_request(original_job)
    expected = _tag_state(
        request["postMutationExpectedTagState"],
        require_pii=True,
    )
    return request, expected


def _clean_tag_result(
    value: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    proof = value.get("_proof")
    result = dict(value)
    result.pop("_proof", None)
    if (
        not isinstance(proof, dict)
        or not DIGEST_RE.fullmatch(str(proof.get("digest")))
    ):
        raise ContractError("tag_read_proof_invalid")
    return result, proof


def _read_executor(
    job: RuntimeJob,
    credential: ManagedCredential,
    store: RuntimeStore,
    execution_id: str,
    runtime_context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    del execution_id, runtime_context
    if job.operation in {"ANALYZE", "IMPROVE_CONTEXT", "POST_ANALYZE"}:
        from analytics_runtime import execute_analytics_operation

        checkpoint = CheckpointStore(store.sessions)
        return execute_analytics_operation(job, credential, checkpoint)

    post_request: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    if job.operation == "READ_TAGS":
        _read_request(job)
    elif job.operation == "POST_READ_TAGS":
        post_request, expected = _post_read_request(job)
    else:
        raise ContractError("read_operation_invalid")
    result, proof = _clean_tag_result(
        asyncio.run(read_column_tags(credential))
    )
    if expected is not None and result != {
        "schemaVersion": "archon.core-tag-read-result/v1",
        **expected,
    }:
        raise ContractError("post_mutation_tag_state_mismatch")
    if post_request is not None:
        result = {
            "schemaVersion":
                "archon.core-post-mutation-tag-read-result/v1",
            "sourceMutationAuditId":
                post_request["sourceMutationAuditId"],
            "sourceMutationReceiptDigest":
                post_request["sourceMutationReceiptDigest"],
            "postMutationExpectedTagState":
                post_request["postMutationExpectedTagState"],
            "postMutationResult": result,
            "postMutationResultDigest": digest(result),
        }
    return result, proof


def _mutation_executor(
    job: RuntimeJob,
    credential: ManagedCredential,
    store: RuntimeStore,
    execution_id: str,
    runtime_context: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    from mutation_runtime import execute_mutation

    return (
        execute_mutation(
            job,
            credential,
            store,
            execution_id,
            runtime_context,
        ),
        None,
    )


def _valid_records(event: Any) -> list[dict[str, Any]]:
    source_arn = required_env("RUNTIME_JOB_STREAM_ARN", maximum=512)
    if (
        DDB_STREAM_ARN_RE.fullmatch(source_arn) is None
        or not isinstance(event, dict)
        or not exact_keys(event, {"Records"})
        or not isinstance(event.get("Records"), list)
        or not 1 <= len(event["Records"]) <= 10
        or any(
            not isinstance(record, dict)
            or record.get("eventSource") != "aws:dynamodb"
            or record.get("eventSourceARN") != source_arn
            for record in event["Records"]
        )
    ):
        raise ContractError("stream_event_invalid")
    return event["Records"]


def _request_id(context: Any) -> str:
    value = getattr(context, "aws_request_id", None)
    if not isinstance(value, str):
        raise ContractError("lambda_execution_id_invalid")
    return value


def _write_failure(
    store: RuntimeStore,
    job: RuntimeJob,
    execution_id: str,
    started_at: str,
    error: BaseException,
) -> None:
    receipt = job_receipt(
        job,
        state="FAILED",
        started_at=started_at,
        completed_at=instant(),
        error=safe_error(error),
    )
    store.terminal(job, execution_id, receipt)


def _process(
    event: Any,
    context: Any,
    *,
    operations: frozenset[str],
    purpose: str,
    executor: Executor,
) -> dict[str, list[dict[str, str]]]:
    records = _valid_records(event)
    execution_id = _request_id(context)
    store = RuntimeStore()
    failures: list[dict[str, str]] = []
    for record in records:
        try:
            job = parse_job_record(record, operations=operations)
        except ContractError:
            continue
        if job is None:
            continue

        runtime_context: dict[str, Any] | None = None
        context_error: ContractError | None = None
        try:
            runtime_context = store.validate_runtime_context(job)
        except RetryableFailure:
            failures.append({"itemIdentifier": job.event_id})
            continue
        except ContractError as error:
            context_error = error

        try:
            started_at = store.claim(job, execution_id)
        except RetryableFailure:
            failures.append({"itemIdentifier": job.event_id})
            continue
        except ContractError:
            continue
        if started_at is None:
            continue

        if context_error is not None:
            try:
                _write_failure(
                    store,
                    job,
                    execution_id,
                    started_at,
                    context_error,
                )
            except RetryableFailure:
                failures.append({"itemIdentifier": job.event_id})
            continue
        if runtime_context is None:
            failures.append({"itemIdentifier": job.event_id})
            continue

        try:
            credential = _load_secret(purpose)
            result, evidence = executor(
                job,
                credential,
                store,
                execution_id,
                runtime_context,
            )
            receipt = job_receipt(
                job,
                state="SUCCEEDED",
                started_at=started_at,
                completed_at=instant(),
                result=result,
                execution_evidence=evidence,
            )
            store.terminal(job, execution_id, receipt)
        except RetryableFailure:
            try:
                store.release(job, execution_id)
            except RetryableFailure:
                pass
            failures.append({"itemIdentifier": job.event_id})
        except Exception as error:
            try:
                _write_failure(
                    store,
                    job,
                    execution_id,
                    started_at,
                    error,
                )
            except RetryableFailure:
                failures.append({"itemIdentifier": job.event_id})
    return {"batchItemFailures": failures}


def read_handler(event: Any, context: Any) -> dict[str, Any]:
    return _process(
        event,
        context,
        operations=READ_OPERATIONS,
        purpose="reader",
        executor=_read_executor,
    )


def mutation_handler(event: Any, context: Any) -> dict[str, Any]:
    return _process(
        event,
        context,
        operations=MUTATION_OPERATIONS,
        purpose="writer",
        executor=_mutation_executor,
    )


def fixture_reset_handler(event: Any, context: Any) -> dict[str, Any]:
    from fixture_reset import handle_fixture_reset

    return handle_fixture_reset(event, context)
