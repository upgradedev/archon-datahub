#!/usr/bin/env python3
"""Fail-closed CI/CD controller for Archon's reproducible DataHub demo state.

This file is intentionally not a workstation bootstrapper.  It is executed by protected
GitHub jobs with environment-scoped DataHub credentials and no cloud/OIDC credentials.
Only a separate, secretless downstream job receives GitHub OIDC for attestation.  Plans
and receipts contain no credentials or raw provider responses.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NoReturn

MAX_CONTRACT_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
DATASET_PREFIX = "urn:li:dataset:(urn:li:dataPlatform:"
DATAHUB_CLI_ENVIRONMENT_KEYS = frozenset(
    {
        "DATAHUB_GMS_TOKEN",
        "DATAHUB_GMS_URL",
    }
)


class RejectDataHubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


DATAHUB_API_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    RejectDataHubRedirects(),
)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_obj(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def git_blob_sha1(value: bytes) -> str:
    """Return Git's SHA-1 object identity, not a general-purpose security digest."""

    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"blob {len(value)}\0".encode("ascii"))
    digest.update(value)
    return digest.hexdigest()


def regular_file(path: pathlib.Path, maximum: int | None = None) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"expected one regular file: {path}")
    if maximum is not None and path.stat().st_size > maximum:
        fail(f"file exceeds the {maximum}-byte safety bound: {path}")


def read_json(path: pathlib.Path, maximum: int = MAX_CONTRACT_BYTES) -> Any:
    regular_file(path, maximum)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON file {path}: {exc}")


def write_exclusive(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value))
    except Exception:
        path.unlink(missing_ok=True)
        raise
    regular_file(path)


def exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        fail(f"{context} keys differ from the reviewed contract")


def validate_urn(value: Any, entity_type: str | None = None) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not value.startswith("urn:li:")
        or re.search(r"[\x00-\x20\x7f]", value)
    ):
        fail("contract contains an invalid URN")
    if entity_type is not None and not value.startswith(f"urn:li:{entity_type}:"):
        fail(f"contract URN is not a {entity_type}: {value}")
    return value


def validate_contract(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("state contract must be an object")
    exact_keys(
        raw,
        {
            "schemaVersion",
            "owner",
            "officialBaseline",
            "binding",
            "state",
            "resetConfirmation",
        },
        "state contract",
    )
    if raw["schemaVersion"] != "archon.datahub-demo-state/v1":
        fail("unsupported state contract schema")
    if raw["owner"] != "https://github.com/upgradedev/archon-datahub":
        fail("state contract owner changed")

    baseline = raw["officialBaseline"]
    if not isinstance(baseline, dict):
        fail("officialBaseline must be an object")
    exact_keys(
        baseline,
        {
            "anchors",
            "commit",
            "commitSignatureVerified",
            "description",
            "expectedMcpCount",
            "expectedUniqueEntityUrnCount",
            "files",
            "indexVersion",
            "name",
            "packFormatVersion",
            "referenceTimestamp",
            "repository",
            "tree",
        },
        "official baseline",
    )
    if (
        baseline.get("name") != "showcase-ecommerce"
        or not isinstance(baseline.get("description"), str)
        or not baseline["description"]
        or baseline.get("repository")
        != "https://github.com/datahub-project/static-assets"
        or not HEX_40.fullmatch(str(baseline.get("commit", "")))
        or not HEX_40.fullmatch(str(baseline.get("tree", "")))
        or baseline.get("commitSignatureVerified") is not True
        or baseline.get("packFormatVersion") != "1"
        or baseline.get("indexVersion") != "4"
        or baseline.get("referenceTimestamp") != 1769615173327
        or baseline.get("expectedMcpCount") != 3873
        or baseline.get("expectedUniqueEntityUrnCount") != 1088
    ):
        fail("official showcase-ecommerce provenance changed")
    files = baseline.get("files")
    if not isinstance(files, list) or len(files) != 4:
        fail("official baseline must bind exactly four files")
    expected_paths = [
        "index.json",
        "01-definitions.json",
        "02-data.json",
        "03-context.json",
    ]
    if not all(isinstance(item, dict) for item in files) or [
        item.get("path") for item in files
    ] != expected_paths:
        fail("official baseline file order changed")
    wait_for_completion = [None, True, False, False]
    for index, item in enumerate(files):
        if (
            not isinstance(item, dict)
            or set(item)
            != (
                {"gitBlob", "path", "sha256", "size"}
                if index == 0
                else {
                    "gitBlob",
                    "path",
                    "sha256",
                    "size",
                    "waitForCompletion",
                }
            )
            or not isinstance(item.get("size"), int)
            or isinstance(item.get("size"), bool)
            or item["size"] <= 0
            or item["size"] > MAX_RESPONSE_BYTES
            or not HEX_40.fullmatch(str(item.get("gitBlob", "")))
            or not HEX_64.fullmatch(str(item.get("sha256", "")))
            or item.get("waitForCompletion") is not wait_for_completion[index]
        ):
            fail("official baseline file binding is invalid")
    anchors = baseline.get("anchors")
    if not isinstance(anchors, list) or len(anchors) != 11:
        fail("official baseline anchor coverage is incomplete")
    for anchor in anchors:
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"entityType", "urn", "aspect"}
            or not isinstance(anchor["entityType"], str)
            or not isinstance(anchor["aspect"], str)
        ):
            fail("official baseline anchor is invalid")
        validate_urn(anchor["urn"], anchor["entityType"])

    binding = raw["binding"]
    if not isinstance(binding, dict):
        fail("binding must be an object")
    exact_keys(
        binding,
        {
            "query",
            "targetUrn",
            "domainUrn",
            "danglingUpstreamUrn",
            "sensitiveFieldPath",
            "ownedUrns",
        },
        "binding",
    )
    target = validate_urn(binding["targetUrn"], "dataset")
    if binding["query"] != target or not target.startswith(DATASET_PREFIX):
        fail("the live query must equal the exact target dataset URN")
    domain = validate_urn(binding["domainUrn"], "domain")
    dangling = validate_urn(binding["danglingUpstreamUrn"], "dataset")
    if dangling == target:
        fail("dangling upstream must differ from the target")
    if binding["sensitiveFieldPath"] != "email":
        fail("the reviewed G6 gap must remain the email field")
    if binding["ownedUrns"] != [target, domain]:
        fail("hard-delete allowlist must contain only target then domain")

    state = raw["state"]
    if not isinstance(state, dict) or set(state) != {
        "domain",
        "dataset",
        "ownershipHistory",
    }:
        fail("state shape changed")
    domain_state = state["domain"]
    dataset_state = state["dataset"]
    if not isinstance(domain_state, dict) or set(domain_state) != {
        "description",
        "name",
    }:
        fail("domain state shape changed")
    if not isinstance(dataset_state, dict) or set(dataset_state) != {
        "description",
        "fields",
        "name",
        "qualifiedName",
        "schemaName",
    }:
        fail("dataset state shape changed")
    if not all(
        isinstance(domain_state[key], str) and domain_state[key]
        for key in ("description", "name")
    ) or not all(
        isinstance(dataset_state[key], str) and dataset_state[key]
        for key in ("description", "name", "qualifiedName", "schemaName")
    ):
        fail("domain or dataset state contains an invalid value")
    fields = dataset_state["fields"]
    expected_fields = [
        {
            "path": "order_id",
            "nativeType": "VARCHAR",
            "logicalType": "string",
            "nullable": False,
            "isPartOfKey": True,
        },
        {
            "path": "email",
            "nativeType": "VARCHAR",
            "logicalType": "string",
            "nullable": False,
            "isPartOfKey": False,
        },
        {
            "path": "amount",
            "nativeType": "NUMBER",
            "logicalType": "number",
            "nullable": False,
            "isPartOfKey": False,
        },
    ]
    if fields != expected_fields:
        fail("reviewed schema fields changed")
    history = state["ownershipHistory"]
    expected_history = [
        {
            "owner": "urn:li:corpGroup:b2fd91.BusinessIntelligence",
            "ownershipType": "DATAOWNER",
            "pipelineName": "snowflake-prod",
            "runId": "snowflake-connector-2026-06-01",
            "lastObserved": 1780304400000,
        },
        {
            "owner": "urn:li:corpGroup:b2fd91.data-governance",
            "ownershipType": "DATAOWNER",
            "pipelineName": "dbt-prod",
            "runId": "dbt-manifest-2026-07-01",
            "lastObserved": 1782896400000,
        },
    ]
    if (
        not isinstance(history, list)
        or history != expected_history
    ):
        fail("retained-history contradiction binding changed")
    for item in history:
        validate_urn(item.get("owner"), "corpGroup")
        if (
            item.get("ownershipType") != "DATAOWNER"
            or not isinstance(item.get("lastObserved"), int)
            or item["lastObserved"] <= 0
        ):
            fail("ownership history entry is invalid")
    if raw["resetConfirmation"] != "RESET ARCHON DATAHUB DEMO":
        fail("reset confirmation phrase changed")
    return raw


def load_contract(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    contract = validate_contract(read_json(path))
    return contract, digest_obj(contract)


def validate_endpoint(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        fail("DataHub GMS URL must be one credential-free HTTPS origin/base path")
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError:
        fail("DataHub GMS URL must be one credential-free HTTPS origin/base path")
    hostname = parsed.hostname
    decoded_path = urllib.parse.unquote(parsed.path)
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in raw
        or "#" in raw
        or "\\" in raw
        or re.search(r"[\x00-\x20\x7f]", raw)
        or re.search(r"[\x00-\x20\x7f\\]", decoded_path)
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
        or (port is not None and not 1 <= port <= 65535)
    ):
        fail("DataHub GMS URL must be one credential-free HTTPS origin/base path")
    normalized_host = hostname.lower().rstrip(".")
    if (
        not normalized_host
        or "%" in normalized_host
        or (
            ":" not in normalized_host
            and not re.fullmatch(r"[a-z0-9._-]+", normalized_host)
        )
    ):
        fail("DataHub GMS URL must be one credential-free HTTPS origin/base path")
    authority = (
        f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    )
    if port is not None and port != 443:
        authority = f"{authority}:{port}"
    return urllib.parse.urlunsplit(
        ("https", authority, parsed.path.rstrip("/"), "", "")
    )


def validate_token(raw: str) -> str:
    if not raw or len(raw) > 16_384 or re.search(r"[\r\n\x00]", raw):
        fail("DATAHUB_GMS_TOKEN is missing or invalid")
    return raw


def live_config() -> tuple[str, str]:
    gms = os.environ.get("DATAHUB_GMS_URL", "")
    token = os.environ.get("DATAHUB_GMS_TOKEN", "")
    return validate_endpoint(gms), validate_token(token)


def gms_endpoint_fingerprint(gms: str) -> str:
    """Bind plans to a normalized endpoint without retaining the endpoint itself."""

    return digest_bytes(validate_endpoint(gms).encode("utf-8"))


def assert_datahub_cli_environment(environment: dict[str, str]) -> None:
    if set(environment) != DATAHUB_CLI_ENVIRONMENT_KEYS:
        fail("DataHub CLI environment differs from the two-key allowlist")
    if validate_endpoint(environment["DATAHUB_GMS_URL"]) != environment[
        "DATAHUB_GMS_URL"
    ]:
        fail("DataHub CLI URL must already be normalized")
    validate_token(environment["DATAHUB_GMS_TOKEN"])


def datahub_cli_environment(gms: str, token: str) -> dict[str, str]:
    environment = {
        "DATAHUB_GMS_URL": validate_endpoint(gms),
        "DATAHUB_GMS_TOKEN": validate_token(token),
    }
    assert_datahub_cli_environment(environment)
    return environment


def validate_github_login(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or re.search(r"[\x00-\x20\x7f]", value)
    ):
        fail(f"{context} is invalid")
    return value


def approval_comment(
    run_id: str,
    run_attempt: str,
    action: str,
    release_sha: str,
    plan_sha256: str,
) -> str:
    if (
        not run_id.isdigit()
        or int(run_id) <= 0
        or not run_attempt.isdigit()
        or int(run_attempt) <= 0
        or action not in {"seed", "reset"}
        or not HEX_40.fullmatch(release_sha)
        or not HEX_64.fullmatch(plan_sha256)
    ):
        fail("approval binding inputs are invalid")
    return (
        "APPROVE ARCHON DATAHUB DEMO "
        f"run_id={run_id} "
        f"run_attempt={run_attempt} "
        f"action={action} "
        f"release_sha={release_sha} "
        f"plan_sha256={plan_sha256}"
    )


def load_approval_receipt(
    path: pathlib.Path,
    *,
    repository: str,
    run_id: str,
    run_attempt: str,
    action: str,
    release_sha: str,
    plan_sha256: str,
    actor: str,
    triggering_actor: str,
) -> tuple[dict[str, Any], str]:
    receipt = read_json(path)
    if not isinstance(receipt, dict):
        fail("approval receipt must be an object")
    exact_keys(
        receipt,
        {
            "action",
            "approval",
            "configuredReviewerIds",
            "environment",
            "initiators",
            "planSha256",
            "releaseSha",
            "repository",
            "schemaVersion",
            "workflowRunAttempt",
            "workflowRunId",
        },
        "approval receipt",
    )
    if path.read_bytes() != canonical_bytes(receipt):
        fail("approval receipt must use canonical JSON")
    if (
        receipt["schemaVersion"] != "archon.datahub-demo-approval/v1"
        or receipt["repository"] != repository
        or repository != "upgradedev/archon-datahub"
        or receipt["workflowRunId"] != run_id
        or receipt["workflowRunAttempt"] != run_attempt
        or receipt["action"] != action
        or receipt["releaseSha"] != release_sha
        or receipt["planSha256"] != plan_sha256
    ):
        fail("approval receipt differs from the exact workflow/plan binding")

    expected_actor = validate_github_login(actor, "workflow actor")
    expected_triggering_actor = validate_github_login(
        triggering_actor,
        "workflow triggering actor",
    )
    initiators = receipt["initiators"]
    if (
        not isinstance(initiators, dict)
        or set(initiators) != {"actor", "triggeringActor"}
        or initiators["actor"] != expected_actor
        or initiators["triggeringActor"] != expected_triggering_actor
    ):
        fail("approval receipt initiator binding changed")

    environment = receipt["environment"]
    if (
        not isinstance(environment, dict)
        or set(environment) != {"id", "name"}
        or environment["name"] != "datahub-demo-seed"
        or not isinstance(environment["id"], int)
        or isinstance(environment["id"], bool)
        or environment["id"] <= 0
    ):
        fail("approval receipt environment binding is invalid")

    reviewer_ids = receipt["configuredReviewerIds"]
    if (
        not isinstance(reviewer_ids, list)
        or not reviewer_ids
        or any(
            not isinstance(identifier, int)
            or isinstance(identifier, bool)
            or identifier <= 0
            for identifier in reviewer_ids
        )
        or reviewer_ids != sorted(set(reviewer_ids))
    ):
        fail("approval receipt reviewer allowlist is invalid")

    approval = receipt["approval"]
    if (
        not isinstance(approval, dict)
        or set(approval) != {"comment", "state", "user"}
        or approval["state"] != "approved"
        or approval["comment"]
        != approval_comment(
            run_id,
            run_attempt,
            action,
            release_sha,
            plan_sha256,
        )
    ):
        fail("approval receipt decision/comment binding is invalid")
    user = approval["user"]
    if (
        not isinstance(user, dict)
        or set(user) != {"id", "login"}
        or not isinstance(user["id"], int)
        or isinstance(user["id"], bool)
        or user["id"] not in reviewer_ids
    ):
        fail("approval receipt user is not a configured reviewer")
    approved_login = validate_github_login(user["login"], "approval user login")
    if approved_login.casefold() in {
        expected_actor.casefold(),
        expected_triggering_actor.casefold(),
    }:
        fail("approval user must differ from actor and triggering actor")
    return receipt, digest_obj(receipt)


def request_json(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: Any | None = None,
    absent_ok: bool = False,
) -> Any | None:
    payload = None if body is None else canonical_bytes(body)
    request = urllib.request.Request(
        url,
        data=payload,
        method=method,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Content-Type": "application/json"} if payload is not None else {}),
        },
    )
    try:
        with DATAHUB_API_OPENER.open(request, timeout=20) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                fail("DataHub response exceeded the safety bound")
            if response.status < 200 or response.status >= 300:
                fail(f"DataHub returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        if absent_ok and exc.code == 404:
            return None
        fail(f"DataHub read failed with HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"DataHub read failed: {type(exc).__name__}")
    try:
        return json.loads(content)
    except (UnicodeError, json.JSONDecodeError):
        fail("DataHub returned malformed JSON")


def aspect_url(
    gms: str, entity_type: str, urn: str, aspect: str, version: int = 0
) -> str:
    return (
        f"{gms}/openapi/v3/entity/{urllib.parse.quote(entity_type, safe='')}/"
        f"{urllib.parse.quote(urn, safe='')}/{urllib.parse.quote(aspect, safe='')}"
        f"?systemMetadata=true&version={version}"
    )


def read_aspect(
    gms: str,
    token: str,
    entity_type: str,
    urn: str,
    aspect: str,
    version: int = 0,
) -> dict[str, Any] | None:
    result = request_json(
        aspect_url(gms, entity_type, urn, aspect, version),
        token,
        absent_ok=True,
    )
    if result is None:
        return None
    if (
        not isinstance(result, dict)
        or "value" not in result
        or (
            result["value"] is not None
            and not isinstance(result["value"], dict)
        )
        or (
            result.get("systemMetadata") is not None
            and not isinstance(result["systemMetadata"], dict)
        )
    ):
        fail("DataHub returned an invalid versioned-aspect envelope")
    return result


def baseline_anchor_state(
    contract: dict[str, Any], gms: str, token: str
) -> dict[str, Any]:
    present: list[str] = []
    missing: list[str] = []
    for anchor in contract["officialBaseline"]["anchors"]:
        value = read_aspect(
            gms,
            token,
            anchor["entityType"],
            anchor["urn"],
            anchor["aspect"],
        )
        identifier = f'{anchor["entityType"]}:{anchor["urn"]}#{anchor["aspect"]}'
        (present if value is not None and value["value"] is not None else missing).append(
            identifier
        )
    return {
        "expected": len(contract["officialBaseline"]["anchors"]),
        "present": len(present),
        "complete": not missing,
        "missingDigest": digest_obj(sorted(missing)),
    }


def expected_custom_properties(
    contract: dict[str, Any], contract_digest: str
) -> dict[str, str]:
    baseline = contract["officialBaseline"]
    index = baseline["files"][0]
    return {
        "archonStateContractSha256": contract_digest,
        "archonBaselineCommit": baseline["commit"],
        "archonBaselineIndexSha256": index["sha256"],
        "archonIntentionalGap": "retained-history+g6-email+dangling-lineage",
    }


def owner_projection(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if entry is None or entry.get("value") is None:
        return None
    value = entry["value"]
    owners = value.get("owners")
    metadata = entry.get("systemMetadata") or {}
    if not isinstance(owners, list) or len(owners) != 1:
        return {"invalid": True}
    owner = owners[0]
    if not isinstance(owner, dict):
        return {"invalid": True}
    return {
        "owner": owner.get("owner"),
        "ownershipType": owner.get("type"),
        "pipelineName": metadata.get("pipelineName"),
        "runId": metadata.get("runId"),
        "lastObserved": metadata.get("lastObserved"),
    }


def aspect_is_present(entry: dict[str, Any] | None) -> bool:
    return entry is not None and entry.get("value") is not None


def schema_field_logical_type(field: dict[str, Any]) -> str | None:
    """Project the exact DataHub SchemaFieldDataType union discriminator."""

    field_type = field.get("type")
    if not isinstance(field_type, dict) or set(field_type) != {"type"}:
        return None
    logical_union = field_type["type"]
    if not isinstance(logical_union, dict) or len(logical_union) != 1:
        return None
    discriminator, payload = next(iter(logical_union.items()))
    if payload != {}:
        return None
    return {
        "com.linkedin.schema.StringType": "string",
        "com.linkedin.schema.NumberType": "number",
    }.get(discriminator)


def validate_owned_urn_presence(
    value: Any, owned_urns: list[str]
) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or len(value) != len(owned_urns)
        or [item.get("urn") for item in value if isinstance(item, dict)]
        != owned_urns
    ):
        fail("owned-URN presence projection differs from the two-URN allowlist")
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"present", "urn"}
            or not isinstance(item["present"], bool)
        ):
            fail("owned-URN presence projection is invalid")
    return value


def reset_delete_candidates(value: Any, owned_urns: list[str]) -> list[str]:
    presence = validate_owned_urn_presence(value, owned_urns)
    return [item["urn"] for item in presence if item["present"]]


def owned_urn_is_present(state: dict[str, Any], urn: str) -> bool:
    presence = state.get("ownedUrnPresence")
    if not isinstance(presence, list):
        fail("inspected state omitted the owned-URN presence projection")
    matching = [
        item
        for item in presence
        if isinstance(item, dict) and item.get("urn") == urn
    ]
    if len(matching) != 1 or not isinstance(matching[0].get("present"), bool):
        fail("inspected state has an invalid owned-URN presence projection")
    return matching[0]["present"]


def inspect_state(
    contract: dict[str, Any], contract_digest: str, gms: str, token: str
) -> dict[str, Any]:
    binding = contract["binding"]
    target = binding["targetUrn"]
    domain = binding["domainUrn"]
    dataset_key = read_aspect(gms, token, "dataset", target, "datasetKey")
    aspects = {
        name: read_aspect(gms, token, "dataset", target, name)
        for name in (
            "datasetProperties",
            "schemaMetadata",
            "ownership",
            "domains",
            "upstreamLineage",
            "editableSchemaMetadata",
        )
    }
    historical = read_aspect(gms, token, "dataset", target, "ownership", 1)
    unexpected_history = read_aspect(gms, token, "dataset", target, "ownership", 2)
    domain_properties = read_aspect(
        gms, token, "domain", domain, "domainProperties"
    )
    domain_key = read_aspect(gms, token, "domain", domain, "domainKey")
    dangling_exists = (
        read_aspect(
            gms,
            token,
            "dataset",
            binding["danglingUpstreamUrn"],
            "datasetKey",
        )
        is not None
    )

    dataset_present = aspect_is_present(dataset_key) or any(
        aspect_is_present(item)
        for item in [*aspects.values(), historical, unexpected_history]
    )
    domain_present = aspect_is_present(domain_key) or aspect_is_present(
        domain_properties
    )
    owned_urn_presence = validate_owned_urn_presence(
        [
            {"urn": target, "present": dataset_present},
            {"urn": domain, "present": domain_present},
        ],
        binding["ownedUrns"],
    )
    if not dataset_present and not domain_present:
        classification = "absent" if not dangling_exists else "drift"
        projection = {
            "classification": classification,
            "danglingUpstreamAbsent": not dangling_exists,
            "ownedUrnPresence": owned_urn_presence,
        }
        return {
            **projection,
            "digest": digest_obj(projection),
            "mismatches": [] if classification == "absent" else ["dangling-upstream-exists"],
            "history": [],
        }

    mismatches: list[str] = []
    dataset = contract["state"]["dataset"]
    domain_expected = contract["state"]["domain"]
    props = (aspects["datasetProperties"] or {}).get("value") or {}
    if (
        props.get("name") != dataset["name"]
        or props.get("description") != dataset["description"]
        or props.get("qualifiedName") != dataset["qualifiedName"]
        or props.get("customProperties")
        != expected_custom_properties(contract, contract_digest)
    ):
        mismatches.append("dataset-properties")

    domain_value = (domain_properties or {}).get("value") or {}
    if (
        domain_value.get("name") != domain_expected["name"]
        or domain_value.get("description") != domain_expected["description"]
    ):
        mismatches.append("domain-properties")

    schema = (aspects["schemaMetadata"] or {}).get("value") or {}
    actual_fields = schema.get("fields")
    projected_fields: list[dict[str, Any]] = []
    if isinstance(actual_fields, list):
        for field in actual_fields:
            if not isinstance(field, dict):
                projected_fields.append({"invalid": True})
                continue
            projected_fields.append(
                {
                    "path": field.get("fieldPath"),
                    "nativeType": field.get("nativeDataType"),
                    "logicalType": schema_field_logical_type(field),
                    "nullable": field.get("nullable"),
                    "isPartOfKey": field.get("isPartOfKey", False),
                    "classified": bool(
                        (field.get("globalTags") or {}).get("tags")
                        if isinstance(field.get("globalTags"), dict)
                        else field.get("tags")
                    )
                    or bool(
                        (field.get("glossaryTerms") or {}).get("terms")
                        if isinstance(field.get("glossaryTerms"), dict)
                        else field.get("glossaryTerms")
                    ),
                }
            )
    expected_fields = [
        {
            "path": field["path"],
            "nativeType": field["nativeType"],
            "logicalType": field["logicalType"],
            "nullable": field["nullable"],
            "isPartOfKey": field["isPartOfKey"],
            "classified": False,
        }
        for field in dataset["fields"]
    ]
    if (
        schema.get("schemaName") != dataset["schemaName"]
        or schema.get("platform") != "urn:li:dataPlatform:snowflake"
        or projected_fields != expected_fields
    ):
        mismatches.append("schema-or-g6-gap")

    editable = (aspects["editableSchemaMetadata"] or {}).get("value") or {}
    editable_fields = editable.get("editableSchemaFieldInfo", [])
    if not isinstance(editable_fields, list):
        mismatches.append("editable-schema")
    else:
        for field in editable_fields:
            if (
                isinstance(field, dict)
                and field.get("fieldPath") == binding["sensitiveFieldPath"]
                and (
                    bool((field.get("globalTags") or {}).get("tags"))
                    or bool((field.get("glossaryTerms") or {}).get("terms"))
                )
            ):
                mismatches.append("g6-gap-classified")

    domains = ((aspects["domains"] or {}).get("value") or {}).get("domains")
    if domains != [domain]:
        mismatches.append("domain-association")
    upstreams = ((aspects["upstreamLineage"] or {}).get("value") or {}).get(
        "upstreams"
    )
    if not isinstance(upstreams, list) or len(upstreams) != 1:
        mismatches.append("dangling-lineage")
    else:
        upstream = upstreams[0]
        if (
            not isinstance(upstream, dict)
            or upstream.get("dataset") != binding["danglingUpstreamUrn"]
            or upstream.get("type") != "TRANSFORMED"
        ):
            mismatches.append("dangling-lineage")
    if dangling_exists:
        mismatches.append("dangling-upstream-exists")

    history_expected = contract["state"]["ownershipHistory"]
    history_projection = [
        owner_projection(historical),
        owner_projection(aspects["ownership"]),
    ]
    if history_projection != history_expected or unexpected_history is not None:
        mismatches.append("retained-ownership-history")

    projection = {
        "classification": "exact" if not mismatches else "drift",
        "datasetProperties": {
            "name": props.get("name"),
            "description": props.get("description"),
            "qualifiedName": props.get("qualifiedName"),
            "customProperties": props.get("customProperties"),
        },
        "domain": domain_value,
        "fields": projected_fields,
        "domainAssociation": domains,
        "declaredUpstreams": upstreams,
        "danglingUpstreamAbsent": not dangling_exists,
        "ownedUrnPresence": owned_urn_presence,
        "ownershipHistory": history_projection,
    }
    return {
        "classification": projection["classification"],
        "digest": digest_obj(projection),
        "mismatches": sorted(set(mismatches)),
        "history": history_projection,
        "danglingUpstreamAbsent": not dangling_exists,
        "ownedUrnPresence": owned_urn_presence,
    }


def download_exact(
    url: str,
    destination: pathlib.Path,
    size: int,
    digest: str,
    git_blob: str,
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com":
        fail("baseline download origin changed")
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read(size + 1)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"baseline download failed: {type(exc).__name__}")
    if (
        len(payload) != size
        or digest_bytes(payload) != digest
        or git_blob_sha1(payload) != git_blob
    ):
        fail("baseline file size, SHA-256, or Git blob differs from the contract")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    regular_file(destination, size)


def materialize_baseline(
    contract: dict[str, Any], contract_digest: str, output: pathlib.Path
) -> dict[str, Any]:
    if not output.is_absolute() or output.exists():
        fail("baseline output must be a new absolute runner-temporary directory")
    output.mkdir(parents=True, mode=0o700)
    baseline = contract["officialBaseline"]
    commit = baseline["commit"]
    base = (
        "https://raw.githubusercontent.com/datahub-project/static-assets/"
        f"{commit}/datapacks/showcase-ecommerce"
    )
    for item in baseline["files"]:
        download_exact(
            f'{base}/{item["path"]}',
            output / item["path"],
            item["size"],
            item["sha256"],
            item["gitBlob"],
        )
    index = read_json(output / "index.json")
    expected_index = {
        "version": baseline["indexVersion"],
        "files": [
            {"path": "01-definitions.json", "wait_for_completion": True},
            {"path": "02-data.json"},
            {"path": "03-context.json"},
        ],
    }
    if index != expected_index:
        fail("official baseline index content changed")

    mcps: list[Any] = []
    for path in ("01-definitions.json", "02-data.json", "03-context.json"):
        value = read_json(output / path, MAX_RESPONSE_BYTES)
        if not isinstance(value, list):
            fail("baseline data file is not an MCP array")
        mcps.extend(value)
    urns = {
        item.get("entityUrn")
        for item in mcps
        if isinstance(item, dict) and isinstance(item.get("entityUrn"), str)
    }
    if (
        len(mcps) != baseline["expectedMcpCount"]
        or len(urns) != baseline["expectedUniqueEntityUrnCount"]
    ):
        fail("official baseline MCP/entity count differs from the contract")
    manifest = {
        "schemaVersion": "archon.datahub-demo-baseline/v1",
        "stateContractSha256": contract_digest,
        "name": baseline["name"],
        "repository": baseline["repository"],
        "commit": commit,
        "tree": baseline["tree"],
        "commitSignatureVerified": True,
        "indexVersion": baseline["indexVersion"],
        "mcpCount": len(mcps),
        "uniqueEntityUrnCount": len(urns),
        "files": [
            {
                "path": item["path"],
                "size": item["size"],
                "sha256": item["sha256"],
                "gitBlob": item["gitBlob"],
            }
            for item in baseline["files"]
        ],
    }
    manifest["contentDigest"] = digest_obj(manifest)
    write_exclusive(output / "baseline-manifest.json", manifest)
    return manifest


def load_baseline_manifest(
    path: pathlib.Path, contract: dict[str, Any], contract_digest: str
) -> tuple[dict[str, Any], str]:
    manifest = read_json(path)
    if not isinstance(manifest, dict):
        fail("baseline manifest must be an object")
    exact_keys(
        manifest,
        {
            "commit",
            "commitSignatureVerified",
            "contentDigest",
            "files",
            "indexVersion",
            "mcpCount",
            "name",
            "repository",
            "schemaVersion",
            "stateContractSha256",
            "tree",
            "uniqueEntityUrnCount",
        },
        "baseline manifest",
    )
    baseline = contract["officialBaseline"]
    expected = {
        "schemaVersion": "archon.datahub-demo-baseline/v1",
        "stateContractSha256": contract_digest,
        "name": baseline["name"],
        "repository": baseline["repository"],
        "commit": baseline["commit"],
        "tree": baseline["tree"],
        "commitSignatureVerified": True,
        "indexVersion": baseline["indexVersion"],
        "mcpCount": baseline["expectedMcpCount"],
        "uniqueEntityUrnCount": baseline["expectedUniqueEntityUrnCount"],
        "files": [
            {
                "path": item["path"],
                "size": item["size"],
                "sha256": item["sha256"],
                "gitBlob": item["gitBlob"],
            }
            for item in baseline["files"]
        ],
    }
    expected["contentDigest"] = digest_obj(expected)
    if manifest != expected or path.read_bytes() != canonical_bytes(manifest):
        fail("baseline manifest is not bound to the reviewed contract")
    return manifest, digest_obj(manifest)


def command_plan(args: argparse.Namespace) -> None:
    contract_path = pathlib.Path(args.contract).resolve()
    contract, contract_digest = load_contract(contract_path)
    if args.repository != "upgradedev/archon-datahub":
        fail("workflow repository differs from the reviewed owner")
    if not HEX_40.fullmatch(args.release_sha):
        fail("release SHA must be a full lowercase Git commit")
    if args.query != contract["binding"]["query"]:
        fail("dispatch query differs from the exact contract query/URN")
    if args.action == "reset" and args.confirmation != contract["resetConfirmation"]:
        fail(f'reset requires exact confirmation: {contract["resetConfirmation"]}')
    if args.action == "seed" and args.confirmation:
        fail("seed does not accept a reset confirmation")
    manifest, manifest_digest = load_baseline_manifest(
        pathlib.Path(args.baseline_manifest).resolve(), contract, contract_digest
    )
    gms, token = live_config()
    before = inspect_state(contract, contract_digest, gms, token)
    anchors = baseline_anchor_state(contract, gms, token)
    if not before["danglingUpstreamAbsent"]:
        fail("the intentionally missing upstream URN exists; it is outside the delete allowlist")

    if args.action == "seed":
        if before["classification"] == "exact" and anchors["complete"]:
            required = False
            operation = "noop"
        elif before["classification"] == "absent":
            required = True
            operation = "seed"
        else:
            detail = ",".join(before["mismatches"]) or "baseline-anchor-drift"
            fail(f"demo state is not empty or exact ({detail}); dispatch an approved reset")
    else:
        required = True
        operation = "reset"

    plan = {
        "schemaVersion": "archon.datahub-demo-plan/v1",
        "repository": args.repository,
        "releaseSha": args.release_sha,
        "gmsEndpointFingerprint": gms_endpoint_fingerprint(gms),
        "action": args.action,
        "operation": operation,
        "mutationRequired": required,
        "stateContractSha256": contract_digest,
        "baselineManifestSha256": manifest_digest,
        "baselineContentDigest": manifest["contentDigest"],
        "baselineBefore": anchors,
        "queryBinding": {
            "query": contract["binding"]["query"],
            "targetUrn": contract["binding"]["targetUrn"],
        },
        "ownedUrns": contract["binding"]["ownedUrns"],
        "before": {
            "classification": before["classification"],
            "digest": before["digest"],
            "ownedUrnPresence": before["ownedUrnPresence"],
        },
        "resetConfirmationSha256": (
            digest_bytes(contract["resetConfirmation"].encode("utf-8"))
            if args.action == "reset"
            else None
        ),
    }
    write_exclusive(pathlib.Path(args.output).resolve(), plan)
    print(
        json.dumps(
            {
                "mutationRequired": required,
                "operation": operation,
                "planSha256": digest_obj(plan),
                "beforeStateSha256": before["digest"],
                "baselineManifestSha256": manifest_digest,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def build_demo_proposals(
    contract: dict[str, Any], contract_digest: str
) -> tuple[list[Any], Any, Any]:
    """Build and validate every SDK object without contacting DataHub."""

    try:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.emitter.rest_emitter import DatahubRestEmitter, EmitMode
        from datahub.metadata.schema_classes import (
            AuditStampClass,
            DatasetLineageTypeClass,
            DatasetPropertiesClass,
            DomainPropertiesClass,
            DomainsClass,
            NumberTypeClass,
            OtherSchemaClass,
            OwnerClass,
            OwnershipClass,
            OwnershipTypeClass,
            SchemaFieldClass,
            SchemaFieldDataTypeClass,
            SchemaMetadataClass,
            StringTypeClass,
            SystemMetadataClass,
            UpstreamClass,
            UpstreamLineageClass,
        )
    except ImportError:
        fail("the exact locked acryl-datahub runtime is unavailable")

    try:
        binding = contract["binding"]
        state = contract["state"]
        actor = "urn:li:corpuser:__datahub_system"
        stamp = AuditStampClass(
            time=state["ownershipHistory"][1]["lastObserved"],
            actor=actor,
        )
        common_metadata = SystemMetadataClass(
            lastObserved=state["ownershipHistory"][1]["lastObserved"],
            runId="archon-demo-state-v1",
            pipelineName="archon-demo-seed",
            properties={"stateContractSha256": contract_digest},
        )
        logical_classes = {
            "string": StringTypeClass,
            "number": NumberTypeClass,
        }
        schema_fields = []
        for field in state["dataset"]["fields"]:
            logical = logical_classes.get(field["logicalType"])
            if logical is None:
                fail("unsupported logical field type in reviewed contract")
            schema_fields.append(
                SchemaFieldClass(
                    fieldPath=field["path"],
                    type=SchemaFieldDataTypeClass(type=logical()),
                    nativeDataType=field["nativeType"],
                    nullable=field["nullable"],
                    recursive=False,
                    isPartOfKey=field["isPartOfKey"],
                )
            )
        aspects: list[tuple[str, Any, Any]] = [
            (
                binding["domainUrn"],
                DomainPropertiesClass(
                    name=state["domain"]["name"],
                    description=state["domain"]["description"],
                ),
                common_metadata,
            ),
            (
                binding["targetUrn"],
                DatasetPropertiesClass(
                    name=state["dataset"]["name"],
                    description=state["dataset"]["description"],
                    qualifiedName=state["dataset"]["qualifiedName"],
                    customProperties=expected_custom_properties(
                        contract,
                        contract_digest,
                    ),
                ),
                common_metadata,
            ),
            (
                binding["targetUrn"],
                SchemaMetadataClass(
                    schemaName=state["dataset"]["schemaName"],
                    platform="urn:li:dataPlatform:snowflake",
                    version=0,
                    hash="archon-datahub-demo-state-v1",
                    platformSchema=OtherSchemaClass(
                        rawSchema=json.dumps(
                            {
                                "type": "object",
                                "required": ["order_id", "email", "amount"],
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                    ),
                    fields=schema_fields,
                ),
                common_metadata,
            ),
            (
                binding["targetUrn"],
                DomainsClass(domains=[binding["domainUrn"]]),
                common_metadata,
            ),
            (
                binding["targetUrn"],
                UpstreamLineageClass(
                    upstreams=[
                        UpstreamClass(
                            dataset=binding["danglingUpstreamUrn"],
                            type=DatasetLineageTypeClass.TRANSFORMED,
                            auditStamp=stamp,
                        )
                    ]
                ),
                common_metadata,
            ),
        ]
        for item in state["ownershipHistory"]:
            aspects.append(
                (
                    binding["targetUrn"],
                    OwnershipClass(
                        owners=[
                            OwnerClass(
                                owner=item["owner"],
                                type=OwnershipTypeClass.DATAOWNER,
                            )
                        ],
                        lastModified=AuditStampClass(
                            time=item["lastObserved"],
                            actor=actor,
                        ),
                    ),
                    SystemMetadataClass(
                        lastObserved=item["lastObserved"],
                        runId=item["runId"],
                        pipelineName=item["pipelineName"],
                        properties={"stateContractSha256": contract_digest},
                    ),
                )
            )
        proposals = []
        for urn, aspect, metadata in aspects:
            proposal = MetadataChangeProposalWrapper(
                entityUrn=urn,
                aspect=aspect,
                systemMetadata=metadata,
            )
            if not proposal.validate() or not proposal.make_mcp().validate():
                fail("reviewed demo MCP failed local DataHub model validation")
            proposals.append(proposal)
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"DataHub SDK model preparation failed: {type(exc).__name__}")
    return proposals, DatahubRestEmitter, EmitMode


def prepare_demo_emission(
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
) -> dict[str, Any]:
    """Validate the pinned SDK/model and connection before any mutation."""

    proposals, emitter_class, emit_mode = build_demo_proposals(
        contract,
        contract_digest,
    )
    try:
        emitter = emitter_class(
            gms_server=gms,
            token=token,
            openapi_ingestion=True,
        )
    except Exception as exc:
        fail(f"DataHub SDK initialization failed: {type(exc).__name__}")
    try:
        emitter.test_connection()
    except Exception as exc:
        with contextlib.suppress(Exception):
            emitter.close()
        fail(f"DataHub SDK connection failed: {type(exc).__name__}")
    return {
        "emitter": emitter,
        "emitMode": emit_mode.SYNC_PRIMARY,
        "proposals": proposals,
    }


def emit_prepared_demo_state(prepared: dict[str, Any]) -> None:
    """Emit only objects that passed the pre-mutation SDK/model preflight."""

    emitter = prepared["emitter"]
    for proposal in prepared["proposals"]:
        try:
            emitter.emit_mcp(proposal, emit_mode=prepared["emitMode"])
        except Exception as exc:
            fail(f"DataHub SDK emission failed: {type(exc).__name__}")


def close_prepared_demo_emission(prepared: dict[str, Any]) -> None:
    try:
        prepared["emitter"].close()
    except Exception as exc:
        fail(f"DataHub SDK close failed: {type(exc).__name__}")


def emit_demo_state(
    contract: dict[str, Any], contract_digest: str, gms: str, token: str
) -> None:
    """Compatibility wrapper used by functional contracts and non-mutating callers."""

    prepared = prepare_demo_emission(contract, contract_digest, gms, token)
    operation_failure: Exception | SystemExit | None = None
    try:
        emit_prepared_demo_state(prepared)
    except (Exception, SystemExit) as exc:
        operation_failure = exc
    finally:
        try:
            close_prepared_demo_emission(prepared)
        except (Exception, SystemExit) as exc:
            if operation_failure is None:
                operation_failure = exc
    if operation_failure is not None:
        raise operation_failure


def run_datahub_cli(
    argv: list[str], environment: dict[str, str]
) -> subprocess.CompletedProcess[Any]:
    assert_datahub_cli_environment(environment)
    try:
        return subprocess.run(
            argv,
            check=False,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
    except OSError as exc:
        fail(f"reviewed DataHub CLI could not start: {type(exc).__name__}")


def run_exact(argv: list[str], environment: dict[str, str]) -> None:
    completed = run_datahub_cli(argv, environment)
    if completed.returncode != 0:
        fail(f"reviewed DataHub CLI operation failed ({argv[1]})")


def delete_owned_urn(
    cli: pathlib.Path,
    urn: str,
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
    environment: dict[str, str],
) -> str:
    if urn not in contract["binding"]["ownedUrns"]:
        fail("hard delete attempted outside the two-URN allowlist")
    completed = run_datahub_cli(
        [str(cli), "delete", "--urn", urn, "--hard", "--force"],
        environment,
    )
    readback = inspect_state(contract, contract_digest, gms, token)
    if owned_urn_is_present(readback, urn):
        if completed.returncode == 0:
            fail("hard delete reported success but exact live readback found the URN")
        fail("hard delete failed and exact live readback still found the URN")
    return (
        "deleted"
        if completed.returncode == 0
        else "absence-proved-after-cli-error"
    )


def wait_for_anchors(
    contract: dict[str, Any], gms: str, token: str, seconds: int = 180
) -> dict[str, Any]:
    deadline = time.monotonic() + seconds
    while True:
        state = baseline_anchor_state(contract, gms, token)
        if state["complete"]:
            return state
        if time.monotonic() >= deadline:
            fail("official baseline anchors did not become readable before the deadline")
        time.sleep(5)


def command_apply(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    plan_path = pathlib.Path(args.plan).resolve()
    regular_file(plan_path, MAX_CONTRACT_BYTES)
    plan_bytes = plan_path.read_bytes()
    if (
        not HEX_64.fullmatch(args.expected_plan_sha256)
        or digest_bytes(plan_bytes) != args.expected_plan_sha256
    ):
        fail("plan artifact digest differs from the pre-mutation receipt")
    try:
        plan = json.loads(plan_bytes)
    except (UnicodeError, json.JSONDecodeError):
        fail("plan artifact is malformed")
    if not isinstance(plan, dict):
        fail("plan artifact must be an object")
    exact_keys(
        plan,
        {
            "action",
            "baselineBefore",
            "baselineContentDigest",
            "baselineManifestSha256",
            "before",
            "gmsEndpointFingerprint",
            "mutationRequired",
            "operation",
            "ownedUrns",
            "queryBinding",
            "releaseSha",
            "repository",
            "resetConfirmationSha256",
            "schemaVersion",
            "stateContractSha256",
        },
        "plan artifact",
    )
    if plan_bytes != canonical_bytes(plan):
        fail("plan artifact must use canonical JSON")
    baseline_before = plan["baselineBefore"]
    query_binding = plan["queryBinding"]
    if (
        plan.get("schemaVersion") != "archon.datahub-demo-plan/v1"
        or plan.get("repository") != "upgradedev/archon-datahub"
        or plan.get("stateContractSha256") != contract_digest
        or not HEX_64.fullmatch(str(plan.get("gmsEndpointFingerprint", "")))
        or not HEX_64.fullmatch(str(plan.get("baselineManifestSha256", "")))
        or not HEX_64.fullmatch(str(plan.get("baselineContentDigest", "")))
        or plan.get("releaseSha") != args.release_sha
        or not isinstance(query_binding, dict)
        or set(query_binding) != {"query", "targetUrn"}
        or query_binding.get("query") != contract["binding"]["query"]
        or query_binding.get("targetUrn") != contract["binding"]["targetUrn"]
        or plan.get("ownedUrns") != contract["binding"]["ownedUrns"]
        or plan.get("action") not in {"seed", "reset"}
        or (
            plan.get("action") == "seed"
            and plan.get("resetConfirmationSha256") is not None
        )
        or (
            plan.get("action") == "reset"
            and not HEX_64.fullmatch(
                str(plan.get("resetConfirmationSha256", ""))
            )
        )
        or not isinstance(plan.get("mutationRequired"), bool)
        or not isinstance(baseline_before, dict)
        or set(baseline_before)
        != {"complete", "expected", "missingDigest", "present"}
        or baseline_before.get("expected")
        != len(contract["officialBaseline"]["anchors"])
        or not isinstance(baseline_before.get("present"), int)
        or isinstance(baseline_before.get("present"), bool)
        or baseline_before["present"] < 0
        or baseline_before["present"] > baseline_before["expected"]
        or not isinstance(baseline_before.get("complete"), bool)
        or baseline_before["complete"]
        != (baseline_before["present"] == baseline_before["expected"])
        or not HEX_64.fullmatch(str(baseline_before.get("missingDigest", "")))
        or not isinstance(plan.get("before"), dict)
        or set(plan["before"]) != {
            "classification",
            "digest",
            "ownedUrnPresence",
        }
        or plan["before"].get("classification") not in {"absent", "drift", "exact"}
        or not HEX_64.fullmatch(str(plan["before"].get("digest", "")))
    ):
        fail("plan is not bound to the reviewed release/state contract")
    plan_owned_urn_presence = validate_owned_urn_presence(
        plan["before"]["ownedUrnPresence"],
        contract["binding"]["ownedUrns"],
    )
    valid_operation = (
        plan["action"] == "seed"
        and (
            (
                plan.get("operation") == "seed"
                and plan["mutationRequired"]
                and plan["before"]["classification"] == "absent"
                and not any(item["present"] for item in plan_owned_urn_presence)
            )
            or (
                plan.get("operation") == "noop"
                and not plan["mutationRequired"]
                and plan["before"]["classification"] == "exact"
                and baseline_before["complete"]
                and all(item["present"] for item in plan_owned_urn_presence)
            )
        )
    ) or (
        plan["action"] == "reset"
        and plan.get("operation") == "reset"
        and plan["mutationRequired"]
    )
    if not valid_operation:
        fail("plan action/operation/mutation tuple is invalid")
    approval, approval_digest = load_approval_receipt(
        pathlib.Path(args.approval_receipt).resolve(),
        repository=plan["repository"],
        run_id=args.workflow_run_id,
        run_attempt=args.workflow_run_attempt,
        action=plan["action"],
        release_sha=args.release_sha,
        plan_sha256=args.expected_plan_sha256,
        actor=args.actor,
        triggering_actor=args.triggering_actor,
    )
    baseline_path = pathlib.Path(args.baseline_manifest).resolve()
    manifest, manifest_digest = load_baseline_manifest(
        baseline_path, contract, contract_digest
    )
    if (
        plan.get("baselineManifestSha256") != manifest_digest
        or plan.get("baselineContentDigest") != manifest["contentDigest"]
    ):
        fail("apply baseline differs from the dry-run plan")

    gms, token = live_config()
    if gms_endpoint_fingerprint(gms) != plan["gmsEndpointFingerprint"]:
        fail("apply DataHub endpoint differs from the reviewed plan")
    before = inspect_state(contract, contract_digest, gms, token)
    anchors_before = baseline_anchor_state(contract, gms, token)
    if (
        before["classification"] != plan["before"]["classification"]
        or before["digest"] != plan["before"]["digest"]
        or before["ownedUrnPresence"] != plan_owned_urn_presence
        or anchors_before != plan["baselineBefore"]
    ):
        fail("live DataHub state changed after the reviewed plan was sealed")
    if not before["danglingUpstreamAbsent"]:
        fail("unowned dangling-upstream URN now exists")

    cli = pathlib.Path(args.datahub_cli).resolve()
    regular_file(cli)
    if not os.access(cli, os.X_OK):
        fail("reviewed DataHub CLI is not executable")
    index = baseline_path.parent / "index.json"
    regular_file(index, MAX_CONTRACT_BYTES)
    environment = datahub_cli_environment(gms, token)
    reset_deletions: list[dict[str, str]] = []
    delete_candidates: set[str] = set()

    if plan["operation"] == "reset":
        if (
            plan.get("resetConfirmationSha256")
            != digest_bytes(contract["resetConfirmation"].encode("utf-8"))
        ):
            fail("reset confirmation digest is absent")
        delete_candidates = set(
            reset_delete_candidates(
                before["ownedUrnPresence"],
                contract["binding"]["ownedUrns"],
            )
        )

    if plan["mutationRequired"]:
        prepared = prepare_demo_emission(contract, contract_digest, gms, token)
        mutation_failure: Exception | SystemExit | None = None
        try:
            if plan["operation"] == "reset":
                for presence in before["ownedUrnPresence"]:
                    urn = presence["urn"]
                    outcome = (
                        delete_owned_urn(
                            cli,
                            urn,
                            contract,
                            contract_digest,
                            gms,
                            token,
                            environment,
                        )
                        if urn in delete_candidates
                        else "already-absent"
                    )
                    reset_deletions.append({"urn": urn, "outcome": outcome})
            run_exact(
                [
                    str(cli),
                    "datapack",
                    "load",
                    contract["officialBaseline"]["name"],
                    "--url",
                    index.as_uri(),
                    "--trust-custom",
                    "--no-cache",
                    "--no-time-shift",
                ],
                environment,
            )
            anchors_after_load = wait_for_anchors(contract, gms, token)
            emit_prepared_demo_state(prepared)
        except (Exception, SystemExit) as exc:
            mutation_failure = exc
        finally:
            try:
                close_prepared_demo_emission(prepared)
            except (Exception, SystemExit) as exc:
                if mutation_failure is None:
                    mutation_failure = exc
        if mutation_failure is not None:
            raise mutation_failure
    else:
        anchors_after_load = anchors_before

    post = inspect_state(contract, contract_digest, gms, token)
    anchors_after = wait_for_anchors(contract, gms, token)
    if (
        post["classification"] != "exact"
        or not post["danglingUpstreamAbsent"]
        or not anchors_after["complete"]
    ):
        fail("post-mutation state did not match the exact reviewed contract")
    receipt = {
        "schemaVersion": "archon.datahub-demo-receipt/v1",
        "repository": plan["repository"],
        "releaseSha": args.release_sha,
        "gmsEndpointFingerprint": plan["gmsEndpointFingerprint"],
        "workflowRunId": args.workflow_run_id,
        "workflowRunAttempt": args.workflow_run_attempt,
        "action": plan["action"],
        "outcome": (
            "unchanged"
            if not plan["mutationRequired"]
            else "reset"
            if plan["operation"] == "reset"
            else "seeded"
        ),
        "planSha256": args.expected_plan_sha256,
        "approvalReceiptSha256": approval_digest,
        "approval": {
            "environment": approval["environment"],
            "state": approval["approval"]["state"],
            "user": approval["approval"]["user"],
        },
        "stateContractSha256": contract_digest,
        "baselineManifestSha256": manifest_digest,
        "baselineContentDigest": manifest["contentDigest"],
        "baselineCommit": contract["officialBaseline"]["commit"],
        "baselineAnchors": anchors_after,
        "queryBinding": plan["queryBinding"],
        "ownedUrns": contract["binding"]["ownedUrns"],
        "resetDeletes": reset_deletions,
        "postStateSha256": post["digest"],
        "retainedOwnershipHistory": post["history"],
        "g6Gap": {
            "fieldPath": contract["binding"]["sensitiveFieldPath"],
            "classificationAbsent": True,
        },
        "danglingLineage": {
            "upstreamUrn": contract["binding"]["danglingUpstreamUrn"],
            "upstreamAbsent": True,
        },
        "baselineReloaded": bool(plan["mutationRequired"]),
        "baselineAnchorsAfterLoad": anchors_after_load,
        "observedAt": dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    write_exclusive(pathlib.Path(args.receipt).resolve(), receipt)
    print(
        json.dumps(
            {
                "outcome": receipt["outcome"],
                "postStateSha256": receipt["postStateSha256"],
                "receiptSha256": digest_obj(receipt),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def command_materialize(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    manifest = materialize_baseline(
        contract, contract_digest, pathlib.Path(args.output_dir).resolve()
    )
    print(
        json.dumps(
            {
                "contentDigest": manifest["contentDigest"],
                "manifestSha256": digest_obj(manifest),
                "mcpCount": manifest["mcpCount"],
                "uniqueEntityUrnCount": manifest["uniqueEntityUrnCount"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def command_validate_config(args: argparse.Namespace) -> None:
    gms, _ = live_config()
    fingerprint = gms_endpoint_fingerprint(gms)
    if args.expected_fingerprint is not None and (
        not HEX_64.fullmatch(args.expected_fingerprint)
        or fingerprint != args.expected_fingerprint
    ):
        fail("DataHub endpoint differs from the reviewed endpoint fingerprint")
    print(
        json.dumps(
            {
                "gmsEndpointFingerprint": fingerprint,
                "schemaVersion": "archon.datahub-demo-config/v1",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def command_validate_runtime(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    proposals, _, _ = build_demo_proposals(contract, contract_digest)
    target = contract["binding"]["targetUrn"]
    domain = contract["binding"]["domainUrn"]
    history = contract["state"]["ownershipHistory"]
    expected = [
        (domain, "domainProperties", "archon-demo-seed", "archon-demo-state-v1"),
        (target, "datasetProperties", "archon-demo-seed", "archon-demo-state-v1"),
        (target, "schemaMetadata", "archon-demo-seed", "archon-demo-state-v1"),
        (target, "domains", "archon-demo-seed", "archon-demo-state-v1"),
        (target, "upstreamLineage", "archon-demo-seed", "archon-demo-state-v1"),
        (
            target,
            "ownership",
            history[0]["pipelineName"],
            history[0]["runId"],
        ),
        (
            target,
            "ownership",
            history[1]["pipelineName"],
            history[1]["runId"],
        ),
    ]
    actual = [
        (
            proposal.entityUrn,
            proposal.aspectName,
            proposal.systemMetadata.pipelineName,
            proposal.systemMetadata.runId,
        )
        for proposal in proposals
    ]
    if actual != expected:
        fail("pinned DataHub runtime produced an unexpected demo MCP projection")
    print(
        json.dumps(
            {
                "proposalCount": len(proposals),
                "runtimeContract": "archon.datahub-demo-runtime/v1",
                "stateContractSha256": contract_digest,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    materialize = commands.add_parser("materialize-baseline")
    materialize.add_argument("--contract", required=True)
    materialize.add_argument("--output-dir", required=True)
    materialize.set_defaults(handler=command_materialize)

    validate_config = commands.add_parser("validate-config")
    validate_config.add_argument("--expected-fingerprint")
    validate_config.set_defaults(handler=command_validate_config)

    validate_runtime = commands.add_parser("validate-runtime")
    validate_runtime.add_argument("--contract", required=True)
    validate_runtime.set_defaults(handler=command_validate_runtime)

    plan = commands.add_parser("plan")
    plan.add_argument("--contract", required=True)
    plan.add_argument("--baseline-manifest", required=True)
    plan.add_argument("--action", choices=["seed", "reset"], required=True)
    plan.add_argument("--confirmation", default="")
    plan.add_argument("--query", required=True)
    plan.add_argument("--release-sha", required=True)
    plan.add_argument("--repository", required=True)
    plan.add_argument("--output", required=True)
    plan.set_defaults(handler=command_plan)

    apply = commands.add_parser("apply")
    apply.add_argument("--contract", required=True)
    apply.add_argument("--baseline-manifest", required=True)
    apply.add_argument("--plan", required=True)
    apply.add_argument("--approval-receipt", required=True)
    apply.add_argument("--expected-plan-sha256", required=True)
    apply.add_argument("--release-sha", required=True)
    apply.add_argument("--workflow-run-id", required=True)
    apply.add_argument("--workflow-run-attempt", required=True)
    apply.add_argument("--actor", required=True)
    apply.add_argument("--triggering-actor", required=True)
    apply.add_argument("--datahub-cli", required=True)
    apply.add_argument("--receipt", required=True)
    apply.set_defaults(handler=command_apply)
    return root


def main() -> None:
    arguments = parser().parse_args()
    arguments.handler(arguments)


if __name__ == "__main__":
    main()
