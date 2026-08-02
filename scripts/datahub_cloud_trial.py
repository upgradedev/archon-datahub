#!/usr/bin/env python3
"""CI-only DataHub Cloud trial bootstrap, rotation, canary, and cleanup."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from datahub_cloud_trial_clients import (
    AwsSecretWriter,
    GraphQLClient,
    McpCallDenied,
    McpClient,
    StagedSecret,
    TrialError,
    canonical_bytes,
    cloud_endpoints,
    contains_exact,
    sha256,
    validate_credential,
)
from datahub_cloud_trial_graphql import (
    CANONICAL_DATASET_URN,
    COLUMN,
    DESCRIPTION_MARKER,
    PII_TAG_URN,
    PRIVILEGE,
    SOURCE_COMMIT,
    GeneratedToken,
    TrialControlPlane,
    expected_policy_input,
    policy_name,
)

MUTATION_ARGUMENTS = {
    "tag_urns": [PII_TAG_URN],
    "entity_urns": [CANONICAL_DATASET_URN],
    "column_paths": [COLUMN],
}
SEARCH_ARGUMENTS = {
    "query": "/q archon_demo+customers",
    "filter": "entity_type = dataset",
    "num_results": 5,
    "offset": 0,
}
FIELD_ARGUMENTS = {
    "urn": CANONICAL_DATASET_URN,
    "keywords": [COLUMN],
    "limit": 50,
    "offset": 0,
}
CONFIRMATIONS = {
    "plan": "",
    "bootstrap": "BOOTSTRAP DATAHUB CLOUD TRIAL 2026-08-04",
    "reconcile": "RECONCILE DATAHUB CLOUD TRIAL",
    "rotate": "ROTATE DATAHUB CLOUD TRIAL",
    "cleanup": "CLEANUP DATAHUB CLOUD TRIAL",
}


def _owned_account_digest(account: dict[str, Any] | None) -> str | None:
    if account is None:
        return None
    urn = account.get("urn")
    if not isinstance(urn, str):
        raise TrialError("service account digest input failed")
    return sha256(urn)


def seed_canonical_fixture(gms_url: str, admin_token: str) -> int:
    """Reuse the canonical seeder without writing a plaintext credential file."""
    validate_credential(admin_token, "admin seeder")
    root = Path(__file__).resolve().parent.parent
    path = root / "services" / "datahub-companion" / "demo" / "seed_datahub.py"
    if not path.is_file() or path.is_symlink():
        raise TrialError("canonical DataHub seeder is unavailable")
    specification = importlib.util.spec_from_file_location(
        "archon_cloud_trial_seed",
        path,
    )
    if specification is None or specification.loader is None:
        raise TrialError("canonical DataHub seeder import failed")
    module = importlib.util.module_from_spec(specification)
    try:
        specification.loader.exec_module(module)
    except Exception:
        raise TrialError("canonical DataHub seeder load failed") from None
    if (
        getattr(module, "SOURCE_URN", None) != CANONICAL_DATASET_URN
        or getattr(module, "PII_TAG_URN", None) != PII_TAG_URN
        or getattr(module, "COLUMN", None) != COLUMN
        or not callable(getattr(module, "emit_metadata", None))
        or not callable(getattr(module, "_validate_emitter_target", None))
        or not callable(getattr(module, "_token", None))
    ):
        raise TrialError("canonical DataHub seeder contract drift")
    original = module._token
    previous_disable = logging.root.manager.disable
    try:
        module._token = lambda _path: admin_token
        logging.disable(logging.CRITICAL)
        count = module.emit_metadata(
            gms_url,
            Path("in-memory-token-not-read"),
            cloud_tenant_host=cloud_endpoints(gms_url).host,
        )
    except Exception:
        raise TrialError("canonical DataHub Cloud seed failed") from None
    finally:
        module._token = original
        logging.disable(previous_disable)
    if not isinstance(count, int) or count < 10:
        raise TrialError("canonical DataHub seed receipt failed")
    return count


def _tool_is_read_only(definition: Any) -> bool:
    if not isinstance(definition, dict):
        return False
    annotations = definition.get("annotations")
    return (
        isinstance(annotations, dict)
        and annotations.get("readOnlyHint") is True
        and annotations.get("destructiveHint") is False
    )


def _field_has_pii(reader: McpClient) -> bool:
    result = reader.call("list_schema_fields", FIELD_ARGUMENTS)
    return contains_exact(result, PII_TAG_URN)


def _wait_for_field_state(reader: McpClient, expected: bool) -> int:
    for attempt in range(1, 11):
        if _field_has_pii(reader) is expected:
            return attempt
        time.sleep(1)
    raise TrialError("DataHub Cloud field-tag state did not converge")


def run_live_canary(
    endpoints: Any,
    reader_token: str,
    writer_token: str,
) -> dict[str, Any]:
    """Prove read health, reader denial, writer add, and exact rollback."""
    validate_credential(reader_token, "reader")
    validate_credential(writer_token, "writer")
    reader_denied = False
    reader_denial_proof = ""
    add_visible_attempt = 0
    remove_visible_attempt = 0
    writer_added = False
    with McpClient(
        endpoints,
        writer_token,
        "archon-cloud-trial-writer-canary",
    ) as writer:
        writer_tools = writer.tools()
        for name in ("add_tags", "remove_tags"):
            if name not in writer_tools:
                raise TrialError("writer MCP mutation surface is incomplete")
        writer.call("remove_tags", MUTATION_ARGUMENTS)
        with McpClient(
            endpoints,
            reader_token,
            "archon-cloud-trial-reader-canary",
        ) as reader:
            reader_tools = reader.tools()
            for name in ("search", "list_schema_fields"):
                if not _tool_is_read_only(reader_tools.get(name)):
                    raise TrialError("reader MCP read-only surface failed")
            search = reader.call("search", SEARCH_ARGUMENTS)
            if not contains_exact(search, CANONICAL_DATASET_URN):
                raise TrialError("reader health canary did not resolve canonical dataset")
            if _field_has_pii(reader):
                raise TrialError("canonical field was not clean before denial probe")
            if "add_tags" not in reader_tools:
                reader_denied = True
                reader_denial_proof = "tool-absent-from-reader-inventory"
            else:
                try:
                    reader.call(
                        "add_tags",
                        MUTATION_ARGUMENTS,
                        allow_denial=True,
                    )
                except McpCallDenied:
                    reader_denied = True
                    reader_denial_proof = (
                        "explicit-provider-authorization-denial"
                    )
            if not reader_denied:
                try:
                    writer.call("remove_tags", MUTATION_ARGUMENTS)
                finally:
                    raise TrialError("reader unexpectedly performed a mutation")
            if _field_has_pii(reader):
                writer.call("remove_tags", MUTATION_ARGUMENTS)
                _wait_for_field_state(reader, False)
                raise TrialError("reader denial probe changed canonical field state")
            try:
                writer.call("add_tags", MUTATION_ARGUMENTS)
                writer_added = True
                add_visible_attempt = _wait_for_field_state(reader, True)
                writer.call("remove_tags", MUTATION_ARGUMENTS)
                remove_visible_attempt = _wait_for_field_state(reader, False)
                writer_added = False
            finally:
                if writer_added:
                    try:
                        writer.call("remove_tags", MUTATION_ARGUMENTS)
                        _wait_for_field_state(reader, False)
                    except Exception:
                        raise TrialError("writer rollback compensation failed") from None
    return {
        "schemaVersion": "archon.datahub-cloud-live-canary/v1",
        "managedMcpProtocolVersion": "2025-06-18",
        "canonicalDatasetResolved": True,
        "canonicalDatasetUrnDigest": sha256(CANONICAL_DATASET_URN),
        "readerMutationDenied": reader_denied,
        "readerMutationDenialProof": reader_denial_proof,
        "readerMutationStateUnchanged": True,
        "writerAddObservedAttempt": add_visible_attempt,
        "writerRemoveObservedAttempt": remove_visible_attempt,
        "writerAddRemoveRollback": True,
        "mutationArgumentsDigest": sha256(MUTATION_ARGUMENTS),
        "finalPiiTagState": "absent",
        "providerPayloadStored": False,
    }


def _create_pair(
    control: TrialControlPlane,
    reader: dict[str, Any],
    writer: dict[str, Any],
    run_id: str,
    run_attempt: str,
) -> tuple[GeneratedToken, GeneratedToken]:
    reader_token = control.create_token(
        "reader", reader["urn"], run_id, run_attempt
    )
    try:
        writer_token = control.create_token(
            "writer", writer["urn"], run_id, run_attempt
        )
    except Exception:
        try:
            control.revoke(reader_token.token_id)
        finally:
            raise
    if reader_token.raw == writer_token.raw:
        for generated in (reader_token, writer_token):
            try:
                control.revoke(generated.token_id)
            except Exception:
                pass
        raise TrialError("reader and writer tokens were not distinct")
    return reader_token, writer_token


def _revoke_generated(
    control: TrialControlPlane,
    generated: tuple[GeneratedToken, GeneratedToken],
) -> None:
    failed = False
    for token in generated:
        try:
            control.revoke(token.token_id)
        except Exception:
            failed = True
    if failed:
        raise TrialError("failed to revoke an uncommitted generated token")


def _scoped_token_ids(
    control: TrialControlPlane,
    reader: dict[str, Any],
    writer: dict[str, Any],
) -> set[str]:
    identifiers: list[str] = []
    for role, account in (("reader", reader), ("writer", writer)):
        for token in control.scoped_tokens(role, account["urn"]):
            token_id = token.get("id")
            if not isinstance(token_id, str) or not token_id:
                raise TrialError("scoped token inventory failed")
            identifiers.append(token_id)
    if len(identifiers) != len(set(identifiers)):
        raise TrialError("scoped token inventory contained duplicate identifiers")
    return set(identifiers)


def _revoke_superseded_and_verify(
    control: TrialControlPlane,
    reader: dict[str, Any],
    writer: dict[str, Any],
    old_ids: set[str],
    generated_ids: set[str],
) -> int:
    if old_ids & generated_ids or len(generated_ids) != 2:
        raise TrialError("credential inventory sets failed policy")
    allowed = old_ids | generated_ids
    remaining = set(old_ids)
    for attempt in range(1, 6):
        for token_id in sorted(remaining):
            try:
                control.revoke(token_id)
            except Exception:
                pass
        observed = _scoped_token_ids(control, reader, writer)
        if observed - allowed:
            raise TrialError("unexpected scoped token appeared during commit")
        remaining = old_ids & observed
        if not remaining and observed == generated_ids:
            return len(old_ids)
        if attempt < 5:
            time.sleep(1)
    raise TrialError("superseded token revocation did not verify")


def _compensate_secret_commit(
    control: TrialControlPlane,
    aws: AwsSecretWriter,
    generated: tuple[GeneratedToken, GeneratedToken],
    staged: list[StagedSecret],
) -> None:
    failed = False
    try:
        _revoke_generated(control, generated)
    except Exception:
        failed = True
    for secret in reversed(staged):
        try:
            aws.rollback(secret)
        except Exception:
            failed = True
    for secret in staged:
        try:
            aws.drop_stage(secret)
        except Exception:
            failed = True
    if failed:
        raise TrialError("runtime credential commit compensation was incomplete")


def _commit_runtime_credentials(
    control: TrialControlPlane,
    aws: AwsSecretWriter,
    *,
    endpoints: Any,
    reader: dict[str, Any],
    writer: dict[str, Any],
    generated: tuple[GeneratedToken, GeneratedToken],
    read_arn: str,
    write_arn: str,
    run_handle_key: str,
    oauth_master_key: str,
    run_id: str,
    run_attempt: str,
    old_ids: set[str],
) -> int:
    staged: list[StagedSecret] = []
    try:
        stage_label = aws.staging_label(run_id, run_attempt)
        staged.append(
            aws.stage_writer(
                write_arn,
                gms_url=endpoints.gms_url,
                token=generated[1].raw,
                stage_label=stage_label,
            )
        )
        staged.append(
            aws.stage_reader(
                read_arn,
                gms_url=endpoints.gms_url,
                token=generated[0].raw,
                run_handle_key=run_handle_key,
                oauth_master_key=oauth_master_key,
                stage_label=stage_label,
            )
        )
        for secret in staged:
            aws.promote(secret)
        for secret in staged:
            aws.verify_current(secret)
        for secret in staged:
            aws.drop_stage(secret)
        for secret in staged:
            aws.verify_current(secret)
        revoked = _revoke_superseded_and_verify(
            control,
            reader,
            writer,
            old_ids,
            {generated[0].token_id, generated[1].token_id},
        )
    except Exception:
        _compensate_secret_commit(control, aws, generated, staged)
        raise TrialError(
            "runtime credential commit failed and was compensated"
        ) from None
    return revoked


def plan_receipt(
    control: TrialControlPlane,
    stage: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, Any]:
    reader = control.find_service_account("reader")
    writer = control.find_service_account("writer")
    policy = control.exact_policy()
    if policy is not None and DESCRIPTION_MARKER not in str(
        policy.get("description", "")
    ):
        raise TrialError("plan found an unowned exact-name policy")
    reader_tokens = (
        [] if reader is None else control.scoped_tokens("reader", reader["urn"])
    )
    writer_tokens = (
        [] if writer is None else control.scoped_tokens("writer", writer["urn"])
    )
    return {
        "schemaVersion": "archon.datahub-cloud-trial-receipt/v1",
        "action": "plan",
        "stage": stage,
        "workflowRunId": run_id,
        "workflowRunAttempt": run_attempt,
        "officialGraphqlSourceCommit": SOURCE_COMMIT,
        "desired": {
            "readerServiceAccount": "present",
            "writerServiceAccount": "present",
            "readerRoleForBoth": "Reader",
            "writerPolicy": policy_name(stage),
            "tokenDuration": "ONE_MONTH",
        },
        "observed": {
            "readerServiceAccountUrnDigest": _owned_account_digest(reader),
            "writerServiceAccountUrnDigest": _owned_account_digest(writer),
            "exactWriterPolicyPresent": policy is not None,
            "scopedReaderTokenCount": len(reader_tokens),
            "scopedWriterTokenCount": len(writer_tokens),
        },
        "mutationPerformed": False,
        "providerPayloadStored": False,
    }


def reconcile(
    control: TrialControlPlane,
    endpoints: Any,
    aws: AwsSecretWriter,
    *,
    admin_pat: str,
    action: str,
    stage: str,
    run_id: str,
    run_attempt: str,
) -> tuple[dict[str, Any], tuple[str, str, str, str]]:
    reader = control.ensure_service_account("reader")
    writer = control.ensure_service_account("writer")
    actors = [reader["urn"], writer["urn"]]
    control.assign_reader_role(actors)
    policy = control.ensure_policy(writer["urn"])
    old_reader = control.scoped_tokens("reader", reader["urn"])
    old_writer = control.scoped_tokens("writer", writer["urn"])
    old = old_reader + old_writer
    if action == "bootstrap" and old:
        raise TrialError("bootstrap requires no existing scoped runtime tokens")
    if action == "rotate" and not old:
        raise TrialError("rotate requires an existing scoped runtime token")
    read_arn, write_arn, key_arn = aws.bindings()
    run_handle_key, oauth_master_key = aws.reader_keys(read_arn, action)
    generated = _create_pair(control, reader, writer, run_id, run_attempt)
    try:
        proposal_count = seed_canonical_fixture(endpoints.gms_url, admin_pat)
        canary = run_live_canary(
            endpoints,
            generated[0].raw,
            generated[1].raw,
        )
    except Exception:
        _revoke_generated(control, generated)
        raise
    # Values flow only over AWS CLI stdin. Both documents are stored under a
    # run-bound staging label, promoted with verified version IDs, and rolled
    # back with generated-token revocation if any commit or inventory check fails.
    old_ids = {
        token.get("id")
        for token in old
        if isinstance(token.get("id"), str)
    }
    if len(old_ids) != len(old):
        _revoke_generated(control, generated)
        raise TrialError("superseded token inventory failed")
    old_ids.discard(generated[0].token_id)
    old_ids.discard(generated[1].token_id)
    revoked_count = _commit_runtime_credentials(
        control,
        aws,
        endpoints=endpoints,
        reader=reader,
        writer=writer,
        generated=generated,
        read_arn=read_arn,
        write_arn=write_arn,
        run_handle_key=run_handle_key,
        oauth_master_key=oauth_master_key,
        run_id=run_id,
        run_attempt=run_attempt,
        old_ids=old_ids,
    )
    policy_input = expected_policy_input(stage, writer["urn"])
    receipt = {
        "schemaVersion": "archon.datahub-cloud-trial-receipt/v1",
        "action": action,
        "stage": stage,
        "workflowRunId": run_id,
        "workflowRunAttempt": run_attempt,
        "officialGraphqlSourceCommit": SOURCE_COMMIT,
        "identities": {
            "readerServiceAccountUrnDigest": sha256(reader["urn"]),
            "writerServiceAccountUrnDigest": sha256(writer["urn"]),
            "readerRoleAssignedToBoth": True,
        },
        "authorization": {
            "policyUrnDigest": sha256(policy["urn"]),
            "policyName": policy_name(stage),
            "privileges": [PRIVILEGE],
            "resourceDatasetUrnDigest": sha256(CANONICAL_DATASET_URN),
            "privilegeConstraintTagUrnDigest": sha256(PII_TAG_URN),
            "policyInputDigest": sha256(policy_input),
            "effectiveWriterPrivilegeExpansionAbsent": True,
        },
        "credentials": {
            "type": "SERVICE_ACCOUNT",
            "duration": "ONE_MONTH",
            "readerAndWriterDistinct": True,
            "storedInSeparateAwsSecrets": True,
            "readSecretArnDigest": sha256(read_arn),
            "writeSecretArnDigest": sha256(write_arn),
            "supersededTokensRevoked": revoked_count,
            "stagedVersionCommitVerified": True,
            "finalScopedTokenInventoryVerified": True,
            "rawCredentialsRetainedInEvidence": False,
        },
        "fixture": {
            "canonicalDatasetUrnDigest": sha256(CANONICAL_DATASET_URN),
            "proposalCount": proposal_count,
            "customerEmailStartsWithoutPii": True,
        },
        "canary": canary,
        "nominalTrialWindow": {
            "activationDate": "2026-08-04",
            "nominalExpiryDate": "2026-08-25",
            "ossCoreRemainsCanonical": True,
        },
        "providerPayloadStored": False,
    }
    return receipt, (
        generated[0].raw,
        generated[1].raw,
        run_handle_key,
        oauth_master_key,
    )


def cleanup(
    control: TrialControlPlane,
    aws: AwsSecretWriter,
    *,
    stage: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, Any]:
    reader = control.find_service_account("reader")
    writer = control.find_service_account("writer")
    outcome = control.delete_owned(reader, writer)
    read_arn, write_arn, _key_arn = aws.bindings()
    aws.put_revoked_marker(write_arn, run_id)
    aws.put_revoked_marker(read_arn, run_id)
    return {
        "schemaVersion": "archon.datahub-cloud-trial-receipt/v1",
        "action": "cleanup",
        "stage": stage,
        "workflowRunId": run_id,
        "workflowRunAttempt": run_attempt,
        "officialGraphqlSourceCommit": SOURCE_COMMIT,
        "outcome": outcome,
        "runtimeSecretsFailClosed": True,
        "canonicalMetadataPreserved": True,
        "rawCredentialsRetainedInEvidence": False,
        "providerPayloadStored": False,
    }


def write_receipt(
    path: Path,
    receipt: dict[str, Any],
    forbidden: tuple[str, ...],
) -> None:
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
    resolved = path.resolve()
    if (
        not runner_temp.is_dir()
        or runner_temp == resolved
        or runner_temp not in resolved.parents
        or path.exists()
        or path.is_symlink()
    ):
        raise TrialError("receipt path failed runner-temporary policy")
    data = canonical_bytes(receipt) + b"\n"
    for value in forbidden:
        if value and value.encode("utf-8") in data:
            raise TrialError("credential appeared in sanitized receipt")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        os.write(descriptor, data)
    finally:
        os.close(descriptor)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=tuple(CONFIRMATIONS), required=True)
    parser.add_argument(
        "--stage", choices=("staging", "production"), required=True
    )
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--confirmation", default="")
    parser.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if (
        len(arguments.release_sha) != 40
        or any(character not in "0123456789abcdef" for character in arguments.release_sha)
        or arguments.confirmation != CONFIRMATIONS[arguments.action]
    ):
        raise TrialError("release or confirmation binding failed")
    admin_pat = os.environ.get("DATAHUB_CLOUD_ADMIN_PAT", "")
    validate_credential(admin_pat, "admin")
    endpoints = cloud_endpoints(os.environ.get("DATAHUB_CLOUD_GMS_URL", ""))
    control = TrialControlPlane(GraphQLClient(endpoints, admin_pat), arguments.stage)
    forbidden: list[str] = [admin_pat]
    if arguments.action == "plan":
        receipt = plan_receipt(
            control,
            arguments.stage,
            arguments.run_id,
            arguments.run_attempt,
        )
    else:
        aws = AwsSecretWriter(
            account_id=os.environ.get("AWS_ACCOUNT_ID", ""),
            region=os.environ.get("AWS_REGION", ""),
            stage=arguments.stage,
            stack_name=f"Archon-{arguments.stage}-Judge",
        )
        if arguments.action == "cleanup":
            receipt = cleanup(
                control,
                aws,
                stage=arguments.stage,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
            )
        else:
            receipt, generated = reconcile(
                control,
                endpoints,
                aws,
                admin_pat=admin_pat,
                action=arguments.action,
                stage=arguments.stage,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
            )
            forbidden.extend(generated)
    receipt["releaseSha"] = arguments.release_sha
    receipt["repository"] = os.environ.get("GITHUB_REPOSITORY", "")
    receipt["receiptDigest"] = sha256(receipt)
    write_receipt(arguments.receipt, receipt, tuple(forbidden))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TrialError as error:
        print(f"::error::DataHub Cloud trial operation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
    except Exception:
        print(
            "::error::DataHub Cloud trial operation failed with a sanitized internal error",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
