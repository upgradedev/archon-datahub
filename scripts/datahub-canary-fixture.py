#!/usr/bin/env python3
"""Pipeline-only controller for Archon's isolated governed-canary fixture.

The controller has two mutation-aware phases. ``plan`` reads and seals the exact
live state without credentials or endpoint material in its output. ``apply``
accepts only that canonical plan, re-reads the state, and either creates the
absent fixture, performs a no-op for the exact fixture, or executes an explicitly
confirmed reset. The only hard-delete targets are the two URNs embedded in the
reviewed contract.
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
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NoReturn

MAX_JSON_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TARGET_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:snowflake,"
    "archon_governed_canary_fixture,TEST)"
)
DOMAIN_URN = "urn:li:domain:archonGovernedCanaryFixture"
QUERY = "archon_governed_canary_fixture"
PII_TAG_URN = "urn:li:tag:PII"
REPOSITORY = "upgradedev/archon-datahub"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]{0,19}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{6,61}[a-z0-9])$")
GRAPHQL_SEARCH = """
query ArchonCanaryFixtureSearch($input: SearchAcrossEntitiesInput!) {
  searchAcrossEntities(input: $input) {
    start
    count
    total
    searchResults {
      entity {
        urn
        type
      }
    }
  }
}"""


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


DATAHUB_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    RejectDataHubRedirects(),
)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_obj(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        fail(f"{context} keys differ from the reviewed contract")


def regular_file(path: pathlib.Path, maximum: int = MAX_JSON_BYTES) -> None:
    if not path.is_file() or path.is_symlink():
        fail(f"expected one regular file: {path}")
    if path.stat().st_size > maximum:
        fail(f"file exceeds the {maximum}-byte safety bound: {path}")


def read_json(path: pathlib.Path) -> Any:
    regular_file(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON file {path}: {exc}")


def write_exclusive(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(canonical_bytes(value))
    except Exception:
        path.unlink(missing_ok=True)
        raise
    regular_file(path)


def require_ci_output(path: pathlib.Path) -> pathlib.Path:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        fail(
            "fixture plans, mutations, and receipts are supported only in GitHub Actions"
        )
    runner_raw = os.environ.get("RUNNER_TEMP", "")
    if not runner_raw:
        fail("RUNNER_TEMP is required")
    runner = pathlib.Path(runner_raw).resolve()
    if not runner.is_dir() or runner.is_symlink():
        fail("RUNNER_TEMP must be one regular directory")
    resolved = path.resolve()
    try:
        resolved.relative_to(runner)
    except ValueError:
        fail("pipeline output must remain below RUNNER_TEMP")
    if resolved.exists():
        fail("pipeline output already exists")
    return resolved


def require_ci_input(
    path: pathlib.Path,
    maximum: int = MAX_JSON_BYTES,
) -> pathlib.Path:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        fail(
            "fixture plans, mutations, and receipts are supported only in GitHub Actions"
        )
    runner_raw = os.environ.get("RUNNER_TEMP", "")
    if not runner_raw:
        fail("RUNNER_TEMP is required")
    runner = pathlib.Path(runner_raw).resolve()
    if not runner.is_dir() or runner.is_symlink():
        fail("RUNNER_TEMP must be one regular directory")
    resolved = path.resolve()
    try:
        resolved.relative_to(runner)
    except ValueError:
        fail("pipeline input must remain below RUNNER_TEMP")
    regular_file(resolved, maximum)
    return resolved


def validate_contract(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail("fixture contract must be an object")
    exact_keys(
        raw,
        {
            "schemaVersion",
            "owner",
            "binding",
            "provenance",
            "state",
            "resetConfirmation",
        },
        "fixture contract",
    )
    if (
        raw["schemaVersion"] != "archon.datahub-canary-fixture/v1"
        or raw["owner"] != "https://github.com/upgradedev/archon-datahub"
        or raw["resetConfirmation"] != "RESET ARCHON GOVERNED CANARY FIXTURE"
    ):
        fail("fixture contract identity changed")

    binding = raw["binding"]
    if not isinstance(binding, dict):
        fail("fixture binding must be an object")
    exact_keys(
        binding,
        {
            "query",
            "targetUrn",
            "domainUrn",
            "platformUrn",
            "ownerUrn",
            "sensitiveFieldPath",
            "piiTagUrn",
            "piiTermUrns",
            "ownedUrns",
        },
        "fixture binding",
    )
    if (
        binding["query"] != QUERY
        or binding["targetUrn"] != TARGET_URN
        or binding["domainUrn"] != DOMAIN_URN
        or binding["platformUrn"] != "urn:li:dataPlatform:snowflake"
        or binding["ownerUrn"] != "urn:li:corpuser:upgradedev"
        or binding["sensitiveFieldPath"] != "email"
        or binding["piiTagUrn"] != PII_TAG_URN
        or binding["piiTermUrns"]
        != ["urn:li:glossaryTerm:Classification.PII"]
        or binding["ownedUrns"] != [TARGET_URN, DOMAIN_URN]
    ):
        fail("fixture binding changed from the exact TEST canary allowlist")

    provenance = raw["provenance"]
    if not isinstance(provenance, dict):
        fail("fixture provenance must be an object")
    exact_keys(
        provenance,
        {"contractSha256Property", "customProperties"},
        "fixture provenance",
    )
    if (
        provenance["contractSha256Property"] != "archonFixtureContractSha256"
        or provenance["customProperties"]
        != {
            "archonFixtureOwner": "https://github.com/upgradedev/archon-datahub",
            "archonFixturePurpose": "governed-canary-write-rollback",
            "archonFixtureSchema": "archon.datahub-canary-fixture/v1",
        }
    ):
        fail("fixture provenance marker changed")

    state = raw["state"]
    if not isinstance(state, dict):
        fail("fixture state must be an object")
    exact_keys(state, {"domain", "dataset", "ownerType"}, "fixture state")
    if state["ownerType"] != "DATAOWNER":
        fail("fixture owner type changed")
    domain = state["domain"]
    dataset = state["dataset"]
    if not isinstance(domain, dict) or set(domain) != {"name", "description"}:
        fail("fixture domain state changed")
    if not isinstance(dataset, dict) or set(dataset) != {
        "name",
        "description",
        "qualifiedName",
        "schemaName",
        "fields",
    }:
        fail("fixture dataset state changed")
    if (
        domain
        != {
            "name": "Archon Governed Canary",
            "description": (
                "Archon-owned non-production domain for the governed "
                "write-and-rollback canary."
            ),
        }
        or dataset["name"] != QUERY
        or dataset["qualifiedName"] != QUERY
        or dataset["schemaName"] != QUERY
        or not isinstance(dataset["description"], str)
        or not dataset["description"]
    ):
        fail("fixture dataset or domain metadata changed")
    expected_fields = [
        {
            "path": "customer_id",
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
    if dataset["fields"] != expected_fields:
        fail("fixture typed schema changed")
    return raw


def load_contract(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    contract = validate_contract(read_json(path))
    return contract, digest_obj(contract)


def validate_endpoint(raw: str, isolation_marker: str) -> str:
    marker = isolation_marker.lower()
    if not DNS_LABEL.fullmatch(marker):
        fail("canary isolation marker must be one DNS-safe label")
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError:
        fail("DataHub GMS URL must be one credential-free HTTPS base URL")
    hostname = parsed.hostname
    decoded_path = urllib.parse.unquote(parsed.path)
    if (
        not raw
        or parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in raw
        or re.search(r"[\x00-\x20\x7f]", raw)
        or re.search(r"[\x00-\x20\x7f\\]", decoded_path)
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
        or (port is not None and not 1 <= port <= 65535)
    ):
        fail("DataHub GMS URL must be one credential-free HTTPS base URL")
    normalized_host = hostname.lower().rstrip(".")
    if (
        marker not in normalized_host.split(".")
        or "%" in normalized_host
        or (
            ":" not in normalized_host
            and not re.fullmatch(r"[a-z0-9._-]+", normalized_host)
        )
    ):
        fail("DataHub GMS URL is outside the dedicated canary tenant")
    authority = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    if port is not None and port != 443:
        authority = f"{authority}:{port}"
    return urllib.parse.urlunsplit(
        ("https", authority, parsed.path.rstrip("/"), "", "")
    )


def live_config() -> tuple[str, str, str]:
    marker = os.environ.get("CANARY_ISOLATION_MARKER", "")
    gms = validate_endpoint(os.environ.get("DATAHUB_GMS_URL", ""), marker)
    token = os.environ.get("DATAHUB_GMS_TOKEN", "")
    if not token or len(token) > 16_384 or re.search(r"[\r\n\x00]", token):
        fail("DATAHUB_GMS_TOKEN is missing or invalid")
    return gms, token, marker.lower()


def endpoint_fingerprint(gms: str) -> str:
    return digest_bytes(gms.encode("utf-8"))


def request_json(
    url: str,
    token: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    absent_ok: bool = False,
    restli: bool = False,
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
            **({"X-RestLi-Protocol-Version": "2.0.0"} if restli else {}),
        },
    )
    try:
        with DATAHUB_OPENER.open(request, timeout=30) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                fail("DataHub response exceeded the safety bound")
            if response.status < 200 or response.status >= 300:
                fail(f"DataHub returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        if absent_ok and exc.code == 404:
            return None
        fail(f"DataHub request failed with HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"DataHub request failed: {type(exc).__name__}")
    try:
        return json.loads(content)
    except (UnicodeError, json.JSONDecodeError):
        fail("DataHub returned malformed JSON")


def aspect_url(
    gms: str,
    entity_type: str,
    urn: str,
    aspect: str,
) -> str:
    allowed_types = {"dataset", "domain", "tag"}
    allowed_aspects = {
        "datasetKey",
        "datasetProperties",
        "schemaMetadata",
        "ownership",
        "domains",
        "deprecation",
        "editableSchemaMetadata",
        "domainKey",
        "domainProperties",
        "tagProperties",
    }
    if entity_type not in allowed_types or aspect not in allowed_aspects:
        fail("versioned-aspect read is outside the endpoint allowlist")
    allowed_urns = {
        TARGET_URN,
        DOMAIN_URN,
        PII_TAG_URN,
    }
    if urn not in allowed_urns:
        fail("versioned-aspect read is outside the URN allowlist")
    return (
        f"{gms}/openapi/v3/entity/{urllib.parse.quote(entity_type, safe='')}/"
        f"{urllib.parse.quote(urn, safe='')}/{urllib.parse.quote(aspect, safe='')}"
        "?systemMetadata=true&version=0"
    )


def read_aspect(
    gms: str,
    token: str,
    entity_type: str,
    urn: str,
    aspect: str,
) -> dict[str, Any] | None:
    value = request_json(
        aspect_url(gms, entity_type, urn, aspect),
        token,
        absent_ok=True,
    )
    if value is None:
        return None
    if (
        not isinstance(value, dict)
        or "value" not in value
        or (value["value"] is not None and not isinstance(value["value"], dict))
    ):
        fail("DataHub returned an invalid versioned-aspect envelope")
    return value


def exact_query(gms: str, token: str, query: str) -> dict[str, Any]:
    if query != QUERY:
        fail("DataHub search query is outside the exact fixture allowlist")
    body = {
        "query": GRAPHQL_SEARCH,
        "variables": {
            "input": {
                "query": QUERY,
                "types": ["DATASET"],
                "start": 0,
                "count": 2,
            }
        },
    }
    response = request_json(f"{gms}/api/graphql", token, method="POST", body=body)
    if not isinstance(response, dict) or response.get("errors"):
        fail("DataHub fixture query failed")
    data = response.get("data")
    search = data.get("searchAcrossEntities") if isinstance(data, dict) else None
    if (
        not isinstance(search, dict)
        or not isinstance(search.get("total"), int)
        or isinstance(search.get("total"), bool)
        or search["total"] < 0
        or not isinstance(search.get("searchResults"), list)
    ):
        fail("DataHub fixture query returned an invalid envelope")
    urns: list[str] = []
    for item in search["searchResults"]:
        entity = item.get("entity") if isinstance(item, dict) else None
        if (
            not isinstance(entity, dict)
            or entity.get("type") != "DATASET"
            or not isinstance(entity.get("urn"), str)
        ):
            fail("DataHub fixture query returned an invalid entity")
        urns.append(entity["urn"])
    if len(urns) != len(set(urns)) or len(urns) > 2:
        fail("DataHub fixture query returned duplicate or excessive entities")
    return {"total": search["total"], "urns": urns}


def aspect_value(entry: dict[str, Any] | None) -> dict[str, Any]:
    if entry is None or entry.get("value") is None:
        return {}
    return entry["value"]


def aspect_present(entry: dict[str, Any] | None) -> bool:
    return entry is not None and entry.get("value") is not None


def schema_field_logical_type(field: dict[str, Any]) -> str | None:
    field_type = field.get("type")
    if not isinstance(field_type, dict) or set(field_type) != {"type"}:
        return None
    union = field_type["type"]
    if not isinstance(union, dict) or len(union) != 1:
        return None
    discriminator, payload = next(iter(union.items()))
    if payload != {}:
        return None
    return {
        "com.linkedin.schema.StringType": "string",
        "com.linkedin.schema.NumberType": "number",
    }.get(discriminator)


def reference_urns(
    container: Any,
    collection_name: str,
    reference_name: str,
) -> tuple[bool, list[str]]:
    if container is None:
        return True, []
    if not isinstance(container, dict):
        return False, []
    if collection_name not in container:
        return False, []
    collection = container[collection_name]
    if not isinstance(collection, list):
        return False, []
    values: list[str] = []
    for item in collection:
        reference = item.get(reference_name) if isinstance(item, dict) else None
        if not isinstance(reference, str) or not reference.startswith("urn:li:"):
            return False, []
        values.append(reference)
    return True, sorted(set(values))


def pii_classification_state(
    contract: dict[str, Any],
    schema_fields: Any,
    editable_fields: Any,
) -> str:
    email = contract["binding"]["sensitiveFieldPath"]
    pii_tags = {contract["binding"]["piiTagUrn"]}
    pii_terms = set(contract["binding"]["piiTermUrns"])
    if not isinstance(schema_fields, list) or not isinstance(editable_fields, list):
        return "unknown"
    matching: list[dict[str, Any]] = []
    invalid_evidence = False
    for field in [*schema_fields, *editable_fields]:
        if not isinstance(field, dict) or not isinstance(field.get("fieldPath"), str):
            invalid_evidence = True
            continue
        if field["fieldPath"] == email:
            matching.append(field)
    if not matching:
        return "unknown"
    for field in matching:
        tags_valid, tags = reference_urns(
            field.get("globalTags"),
            "tags",
            "tag",
        )
        terms_valid, terms = reference_urns(
            field.get("glossaryTerms"),
            "terms",
            "term",
        )
        if set(tags) & pii_tags or set(terms) & pii_terms:
            return "present"
        if not tags_valid or not terms_valid:
            invalid_evidence = True
    return "unknown" if invalid_evidence else "absent"


def owner_projection(entry: dict[str, Any] | None) -> list[dict[str, Any]]:
    owners = aspect_value(entry).get("owners", [])
    if not isinstance(owners, list):
        return [{"invalid": True}]
    projected: list[dict[str, Any]] = []
    for owner in owners:
        if not isinstance(owner, dict):
            return [{"invalid": True}]
        projected.append({"owner": owner.get("owner"), "type": owner.get("type")})
    return projected


def expected_custom_properties(
    contract: dict[str, Any],
    contract_digest: str,
) -> dict[str, str]:
    return {
        **contract["provenance"]["customProperties"],
        contract["provenance"]["contractSha256Property"]: contract_digest,
    }


def inspect_state(
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
) -> dict[str, Any]:
    search = exact_query(gms, token, contract["binding"]["query"])
    dataset_aspects = {
        name: read_aspect(gms, token, "dataset", TARGET_URN, name)
        for name in (
            "datasetKey",
            "datasetProperties",
            "schemaMetadata",
            "ownership",
            "domains",
            "deprecation",
            "editableSchemaMetadata",
        )
    }
    domain_aspects = {
        name: read_aspect(gms, token, "domain", DOMAIN_URN, name)
        for name in ("domainKey", "domainProperties", "ownership")
    }
    tag_properties = read_aspect(
        gms,
        token,
        "tag",
        PII_TAG_URN,
        "tagProperties",
    )
    dataset_present = any(aspect_present(value) for value in dataset_aspects.values())
    domain_present = any(aspect_present(value) for value in domain_aspects.values())
    tag_present = aspect_present(tag_properties)
    owned_presence = [
        {"urn": TARGET_URN, "present": dataset_present},
        {"urn": DOMAIN_URN, "present": domain_present},
    ]
    mismatches: list[str] = []
    if not tag_present:
        mismatches.append("pii-tag-absent")

    props = aspect_value(dataset_aspects["datasetProperties"])
    raw_domain_props = aspect_value(domain_aspects["domainProperties"])
    domain_props = {
        "name": raw_domain_props.get("name"),
        "description": raw_domain_props.get("description"),
    }
    schema = aspect_value(dataset_aspects["schemaMetadata"])
    schema_fields = schema.get("fields", [])
    editable = aspect_value(dataset_aspects["editableSchemaMetadata"])
    editable_fields = editable.get("editableSchemaFieldInfo", [])
    email_classification = pii_classification_state(
        contract,
        schema_fields,
        editable_fields,
    )
    if not isinstance(schema_fields, list):
        schema_fields = [{"invalid": True}]
    projected_fields: list[dict[str, Any]] = []
    for field in schema_fields:
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
            }
        )
    expected_fields = contract["state"]["dataset"]["fields"]
    expected_provenance = expected_custom_properties(contract, contract_digest)
    dataset_provenance_exact = (
        dataset_present
        and props.get("customProperties") == expected_provenance
    )
    domain_provenance_exact = (
        domain_present
        and raw_domain_props.get("customProperties") == expected_provenance
    )
    expected_owner = [
        {
            "owner": contract["binding"]["ownerUrn"],
            "type": contract["state"]["ownerType"],
        }
    ]
    domains = aspect_value(dataset_aspects["domains"]).get("domains")
    deprecated = aspect_value(dataset_aspects["deprecation"]).get(
        "deprecated",
        False,
    )

    if dataset_present:
        expected_dataset = contract["state"]["dataset"]
        if (
            props.get("name") != expected_dataset["name"]
            or props.get("description") != expected_dataset["description"]
            or props.get("qualifiedName") != expected_dataset["qualifiedName"]
        ):
            mismatches.append("dataset-properties")
        if not dataset_provenance_exact:
            mismatches.append("dataset-provenance")
        if (
            schema.get("schemaName") != expected_dataset["schemaName"]
            or schema.get("platform") != contract["binding"]["platformUrn"]
            or projected_fields != expected_fields
        ):
            mismatches.append("typed-schema")
        if owner_projection(dataset_aspects["ownership"]) != expected_owner:
            mismatches.append("dataset-owner")
        if domains != [DOMAIN_URN]:
            mismatches.append("dataset-domain")
        if deprecated is not False:
            mismatches.append("deprecated")
        if email_classification == "present":
            mismatches.append("email-pii-classification-present")
        elif email_classification == "unknown":
            mismatches.append("email-pii-classification-unknown")
    if domain_present:
        expected_domain = contract["state"]["domain"]
        if domain_props != expected_domain:
            mismatches.append("domain-properties")
        if not domain_provenance_exact:
            mismatches.append("domain-provenance")
        if owner_projection(domain_aspects["ownership"]) != expected_owner:
            mismatches.append("domain-owner")

    exact_query_match = search == {"total": 1, "urns": [TARGET_URN]}
    if (
        search["total"] > 1
        or any(urn != TARGET_URN for urn in search["urns"])
        or search["total"] != len(search["urns"])
    ):
        mismatches.append("query-outside-target")
    if dataset_present and not exact_query_match:
        mismatches.append("exact-one-query-readback")
    if not dataset_present and search != {"total": 0, "urns": []}:
        mismatches.append("query-found-unowned-result")

    if not dataset_present and not domain_present and not mismatches:
        classification = "absent"
    elif dataset_present and domain_present and not mismatches:
        classification = "exact"
    else:
        classification = "drift"
    raw_aspect_snapshot = {
        "dataset": dataset_aspects,
        "domain": domain_aspects,
        "piiTag": {"tagProperties": tag_properties},
        "query": search,
    }
    provenance = [
        {
            "urn": TARGET_URN,
            "present": dataset_present,
            "markerExact": dataset_provenance_exact,
        },
        {
            "urn": DOMAIN_URN,
            "present": domain_present,
            "markerExact": domain_provenance_exact,
        },
    ]
    projection = {
        "classification": classification,
        "query": search,
        "ownedUrnPresence": owned_presence,
        "piiTagPresent": tag_present,
        "datasetProperties": props,
        "domainProperties": domain_props,
        "datasetOwner": owner_projection(dataset_aspects["ownership"]),
        "domainOwner": owner_projection(domain_aspects["ownership"]),
        "domains": domains,
        "deprecated": deprecated,
        "schemaFields": projected_fields,
        "emailPiiClassificationState": email_classification,
        "provenance": provenance,
    }
    return {
        "classification": classification,
        "digest": digest_obj(projection),
        "rawAspectSnapshotSha256": digest_obj(raw_aspect_snapshot),
        "exactQueryMatchCount": sum(urn == TARGET_URN for urn in search["urns"]),
        "mismatches": sorted(set(mismatches)),
        "ownedUrnPresence": owned_presence,
        "provenance": provenance,
        "piiTagPresent": tag_present,
        "g1ToG5": {
            "G1": owner_projection(dataset_aspects["ownership"]) == expected_owner,
            "G2": domains == [DOMAIN_URN],
            "G3": props.get("description")
            == contract["state"]["dataset"]["description"],
            "G4": deprecated is False,
            "G5": projected_fields == expected_fields,
        },
        "g6Gap": {
            "fieldPath": contract["binding"]["sensitiveFieldPath"],
            "classificationState": email_classification,
            "piiClassificationAbsent": email_classification == "absent",
        },
    }


def before_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "classification": state["classification"],
        "digest": state["digest"],
        "rawAspectSnapshotSha256": state["rawAspectSnapshotSha256"],
        "exactQueryMatchCount": state["exactQueryMatchCount"],
        "mismatches": state["mismatches"],
        "ownedUrnPresence": state["ownedUrnPresence"],
        "provenance": state["provenance"],
        "piiTagPresent": state["piiTagPresent"],
    }


def require_reset_provenance(state: dict[str, Any]) -> None:
    provenance = state.get("provenance")
    expected_urns = (TARGET_URN, DOMAIN_URN)
    if (
        not isinstance(provenance, list)
        or len(provenance) != len(expected_urns)
    ):
        fail("reset provenance evidence is malformed")
    for item, expected_urn in zip(provenance, expected_urns, strict=True):
        if (
            not isinstance(item, dict)
            or set(item) != {"urn", "present", "markerExact"}
            or item["urn"] != expected_urn
            or not isinstance(item["present"], bool)
            or not isinstance(item["markerExact"], bool)
        ):
            fail("reset provenance evidence is malformed")
        if item["present"] and not item["markerExact"]:
            fail(
                "reset refuses a present URN without the exact Archon provenance marker"
            )


def validate_release(value: str) -> str:
    if not HEX_40.fullmatch(value):
        fail("release SHA must be one full lowercase commit SHA")
    return value


def command_plan(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    if args.repository != REPOSITORY:
        fail("repository differs from the reviewed fixture owner")
    release_sha = validate_release(args.release_sha)
    if args.query != QUERY:
        fail("plan query differs from the exact fixture query")
    if args.action == "seed":
        if args.confirmation:
            fail("seed does not accept reset confirmation")
    elif (
        args.action != "reset"
        or args.confirmation != contract["resetConfirmation"]
    ):
        fail("reset requires the exact reviewed confirmation phrase")
    output = require_ci_output(pathlib.Path(args.output))
    gms, token, marker = live_config()
    before = inspect_state(contract, contract_digest, gms, token)
    if not before["piiTagPresent"]:
        fail("the pre-existing PII tag prerequisite is absent")
    if args.action == "seed":
        if before["classification"] == "absent":
            operation = "seed"
        elif before["classification"] == "exact":
            operation = "noop"
        else:
            fail("fixture drift requires an explicitly confirmed reset")
    else:
        if "query-outside-target" in before["mismatches"]:
            fail("reset cannot repair a query result outside the two-URN allowlist")
        require_reset_provenance(before)
        operation = "reset"
    plan = {
        "schemaVersion": "archon.datahub-canary-fixture-plan/v1",
        "repository": REPOSITORY,
        "releaseSha": release_sha,
        "stateContractSha256": contract_digest,
        "gmsEndpointFingerprint": endpoint_fingerprint(gms),
        "isolationMarkerSha256": digest_bytes(marker.encode("utf-8")),
        "queryBinding": {"query": QUERY, "targetUrn": TARGET_URN},
        "ownedUrns": contract["binding"]["ownedUrns"],
        "action": args.action,
        "operation": operation,
        "mutationRequired": operation != "noop",
        "resetConfirmationSha256": (
            digest_bytes(contract["resetConfirmation"].encode("utf-8"))
            if args.action == "reset"
            else None
        ),
        "before": before_summary(before),
    }
    write_exclusive(output, plan)
    print(
        json.dumps(
            {
                "classification": before["classification"],
                "mutationRequired": plan["mutationRequired"],
                "operation": operation,
                "planSha256": digest_obj(plan),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def build_proposals(
    contract: dict[str, Any],
    contract_digest: str,
) -> tuple[list[Any], Any, Any]:
    try:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper
        from datahub.emitter.rest_emitter import DatahubRestEmitter, EmitMode
        from datahub.metadata.schema_classes import (
            AuditStampClass,
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
        )
    except ImportError:
        fail("the exact locked acryl-datahub runtime is unavailable")
    try:
        stamp = AuditStampClass(
            time=1767225600000,
            actor="urn:li:corpuser:__datahub_system",
        )
        metadata = SystemMetadataClass(
            lastObserved=1767225600000,
            runId="archon-datahub-canary-fixture-v1",
            pipelineName="archon-canary-fixture-seed",
            properties={"stateContractSha256": contract_digest},
        )
        logical_classes = {"string": StringTypeClass, "number": NumberTypeClass}
        fields = []
        for field in contract["state"]["dataset"]["fields"]:
            logical = logical_classes.get(field["logicalType"])
            if logical is None:
                fail("unsupported logical type in fixture contract")
            fields.append(
                SchemaFieldClass(
                    fieldPath=field["path"],
                    type=SchemaFieldDataTypeClass(type=logical()),
                    nativeDataType=field["nativeType"],
                    nullable=field["nullable"],
                    recursive=False,
                    isPartOfKey=field["isPartOfKey"],
                )
            )
        owner = OwnerClass(
            owner=contract["binding"]["ownerUrn"],
            type=OwnershipTypeClass.DATAOWNER,
        )
        ownership = OwnershipClass(owners=[owner], lastModified=stamp)
        aspects = [
            (
                DOMAIN_URN,
                DomainPropertiesClass(
                    **contract["state"]["domain"],
                    customProperties=expected_custom_properties(
                        contract,
                        contract_digest,
                    ),
                ),
            ),
            (DOMAIN_URN, ownership),
            (
                TARGET_URN,
                DatasetPropertiesClass(
                    name=contract["state"]["dataset"]["name"],
                    description=contract["state"]["dataset"]["description"],
                    qualifiedName=contract["state"]["dataset"]["qualifiedName"],
                    customProperties=expected_custom_properties(
                        contract,
                        contract_digest,
                    ),
                ),
            ),
            (
                TARGET_URN,
                SchemaMetadataClass(
                    schemaName=contract["state"]["dataset"]["schemaName"],
                    platform=contract["binding"]["platformUrn"],
                    version=0,
                    hash=f"sha256:{contract_digest}",
                    platformSchema=OtherSchemaClass(
                        rawSchema=json.dumps(
                            {
                                "type": "object",
                                "required": [
                                    field["path"]
                                    for field in contract["state"]["dataset"]["fields"]
                                ],
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                    ),
                    fields=fields,
                ),
            ),
            (TARGET_URN, DomainsClass(domains=[DOMAIN_URN])),
            (TARGET_URN, ownership),
        ]
        proposals = []
        for urn, aspect in aspects:
            proposal = MetadataChangeProposalWrapper(
                entityUrn=urn,
                aspect=aspect,
                systemMetadata=metadata,
            )
            if not proposal.validate() or not proposal.make_mcp().validate():
                fail("fixture MCP failed DataHub model validation")
            proposals.append(proposal)
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"DataHub SDK model preparation failed: {type(exc).__name__}")
    return proposals, DatahubRestEmitter, EmitMode


def prepare_emission(
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
) -> dict[str, Any]:
    proposals, emitter_class, emit_mode = build_proposals(contract, contract_digest)
    emitter: Any | None = None
    try:
        emitter = emitter_class(
            gms_server=gms,
            token=token,
            openapi_ingestion=True,
        )
        emitter.test_connection()
    except Exception as exc:
        with contextlib.suppress(Exception):
            if emitter is not None:
                emitter.close()
        fail(f"DataHub SDK connection preflight failed: {type(exc).__name__}")
    return {
        "emitter": emitter,
        "emitMode": emit_mode.SYNC_PRIMARY,
        "proposals": proposals,
    }


def emit_prepared(prepared: dict[str, Any]) -> None:
    for proposal in prepared["proposals"]:
        try:
            prepared["emitter"].emit_mcp(
                proposal,
                emit_mode=prepared["emitMode"],
            )
        except Exception as exc:
            fail(f"DataHub SDK emission failed: {type(exc).__name__}")


def close_prepared(prepared: dict[str, Any]) -> None:
    try:
        prepared["emitter"].close()
    except Exception as exc:
        fail(f"DataHub SDK close failed: {type(exc).__name__}")


def authoritative_entity_present(gms: str, token: str, urn: str) -> bool:
    if urn == TARGET_URN:
        entity_type = "dataset"
        key_aspect = "datasetKey"
    elif urn == DOMAIN_URN:
        entity_type = "domain"
        key_aspect = "domainKey"
    else:
        fail("entity existence read is outside the owned-URN allowlist")
    # DataHub 1.6.x DataHubGraph.exists uses the current key aspect as the
    # authoritative entity-existence read.
    return aspect_present(
        read_aspect(gms, token, entity_type, urn, key_aspect)
    )


def require_owned_urns_absent(gms: str, token: str) -> None:
    for urn in (TARGET_URN, DOMAIN_URN):
        if authoritative_entity_present(gms, token, urn):
            fail("fixture reseed requires both authoritative entity keys to be absent")


def require_live_delete_provenance(
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
    urn: str,
) -> None:
    if urn == TARGET_URN:
        entity_type = "dataset"
        properties_aspect = "datasetProperties"
    elif urn == DOMAIN_URN:
        entity_type = "domain"
        properties_aspect = "domainProperties"
    else:
        fail("delete provenance read is outside the owned-URN allowlist")
    properties = read_aspect(
        gms,
        token,
        entity_type,
        urn,
        properties_aspect,
    )
    if (
        not aspect_present(properties)
        or aspect_value(properties).get("customProperties")
        != expected_custom_properties(contract, contract_digest)
    ):
        fail("hard delete refuses a live URN without exact Archon provenance")


def delete_owned_urn(
    contract: dict[str, Any],
    contract_digest: str,
    urn: str,
    gms: str,
    token: str,
) -> str:
    if urn not in (TARGET_URN, DOMAIN_URN):
        fail("hard delete attempted outside the two-URN allowlist")
    require_live_delete_provenance(
        contract,
        contract_digest,
        gms,
        token,
        urn,
    )
    response = request_json(
        f"{gms}/entities?action=delete",
        token,
        method="POST",
        body={"urn": urn},
        restli=True,
    )
    summary = response.get("value") if isinstance(response, dict) else None
    if not isinstance(summary, dict):
        fail("DataHub hard-delete response was malformed")
    rows = summary.get("rows")
    timeseries_rows = summary.get("timeseriesRows", 0)
    if (
        not isinstance(rows, int)
        or isinstance(rows, bool)
        or rows <= 0
        or not isinstance(timeseries_rows, int)
        or isinstance(timeseries_rows, bool)
        or timeseries_rows < 0
    ):
        fail("DataHub hard delete did not prove removal of the exact entity")
    deadline = time.monotonic() + 120
    while authoritative_entity_present(gms, token, urn):
        if time.monotonic() >= deadline:
            fail("hard delete did not produce an absent authoritative key readback")
        time.sleep(5)
    return "deleted"


def wait_for_exact(
    contract: dict[str, Any],
    contract_digest: str,
    gms: str,
    token: str,
) -> dict[str, Any]:
    deadline = time.monotonic() + 180
    while True:
        observed = inspect_state(contract, contract_digest, gms, token)
        if observed["classification"] == "exact":
            return observed
        if time.monotonic() >= deadline:
            fail("fixture did not reach exact-one contract state before the deadline")
        time.sleep(5)


def validate_plan(
    value: Any,
    raw: bytes,
    contract: dict[str, Any],
    contract_digest: str,
    args: argparse.Namespace,
) -> dict[str, Any]:
    if not isinstance(value, dict) or raw != canonical_bytes(value):
        fail("fixture plan must be one canonical JSON object")
    exact_keys(
        value,
        {
            "schemaVersion",
            "repository",
            "releaseSha",
            "stateContractSha256",
            "gmsEndpointFingerprint",
            "isolationMarkerSha256",
            "queryBinding",
            "ownedUrns",
            "action",
            "operation",
            "mutationRequired",
            "resetConfirmationSha256",
            "before",
        },
        "fixture plan",
    )
    before = value["before"]
    owned_presence = (
        before.get("ownedUrnPresence") if isinstance(before, dict) else None
    )
    valid_owned_presence = (
        isinstance(owned_presence, list)
        and len(owned_presence) == 2
        and all(
            isinstance(item, dict) and set(item) == {"urn", "present"}
            for item in owned_presence
        )
        and owned_presence
        == [
            {"urn": TARGET_URN, "present": owned_presence[0]["present"]},
            {"urn": DOMAIN_URN, "present": owned_presence[1]["present"]},
        ]
        and all(isinstance(item["present"], bool) for item in owned_presence)
    )
    provenance = before.get("provenance") if isinstance(before, dict) else None
    valid_provenance = (
        isinstance(provenance, list)
        and len(provenance) == 2
        and all(
            isinstance(item, dict)
            and set(item) == {"urn", "present", "markerExact"}
            for item in provenance
        )
        and provenance
        == [
            {
                "urn": TARGET_URN,
                "present": provenance[0]["present"],
                "markerExact": provenance[0]["markerExact"],
            },
            {
                "urn": DOMAIN_URN,
                "present": provenance[1]["present"],
                "markerExact": provenance[1]["markerExact"],
            },
        ]
        and all(
            isinstance(item["present"], bool)
            and isinstance(item["markerExact"], bool)
            for item in provenance
        )
    )
    if (
        value["schemaVersion"] != "archon.datahub-canary-fixture-plan/v1"
        or value["repository"] != REPOSITORY
        or value["releaseSha"] != args.release_sha
        or value["stateContractSha256"] != contract_digest
        or not HEX_64.fullmatch(str(value["gmsEndpointFingerprint"]))
        or not HEX_64.fullmatch(str(value["isolationMarkerSha256"]))
        or value["queryBinding"] != {"query": QUERY, "targetUrn": TARGET_URN}
        or value["ownedUrns"] != [TARGET_URN, DOMAIN_URN]
        or value["action"] not in {"seed", "reset"}
        or not isinstance(before, dict)
        or set(before)
        != {
            "classification",
            "digest",
            "rawAspectSnapshotSha256",
            "exactQueryMatchCount",
            "mismatches",
            "ownedUrnPresence",
            "provenance",
            "piiTagPresent",
        }
        or before["classification"] not in {"absent", "drift", "exact"}
        or not HEX_64.fullmatch(str(before["digest"]))
        or not HEX_64.fullmatch(str(before["rawAspectSnapshotSha256"]))
        or not isinstance(before["exactQueryMatchCount"], int)
        or isinstance(before["exactQueryMatchCount"], bool)
        or before["exactQueryMatchCount"] < 0
        or before["exactQueryMatchCount"] > 1
        or not isinstance(before["mismatches"], list)
        or not all(isinstance(item, str) for item in before["mismatches"])
        or before["mismatches"] != sorted(set(before["mismatches"]))
        or not valid_owned_presence
        or not valid_provenance
        or not isinstance(before["piiTagPresent"], bool)
    ):
        fail("fixture plan differs from the reviewed contract")
    valid_operation = (
        value["action"] == "seed"
        and (
            (
                value["operation"] == "seed"
                and value["mutationRequired"] is True
                and before["classification"] == "absent"
            )
            or (
                value["operation"] == "noop"
                and value["mutationRequired"] is False
                and before["classification"] == "exact"
            )
        )
        and value["resetConfirmationSha256"] is None
    ) or (
        value["action"] == "reset"
        and value["operation"] == "reset"
        and value["mutationRequired"] is True
        and value["resetConfirmationSha256"]
        == digest_bytes(contract["resetConfirmation"].encode("utf-8"))
    )
    if not valid_operation or before["piiTagPresent"] is not True:
        fail("fixture plan action/operation tuple is invalid")
    if value["action"] == "reset":
        require_reset_provenance(before)
    return value


def command_apply(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    release_sha = validate_release(args.release_sha)
    if args.repository != REPOSITORY:
        fail("repository differs from the reviewed fixture owner")
    if (
        not POSITIVE_INTEGER.fullmatch(args.workflow_run_id)
        or not POSITIVE_INTEGER.fullmatch(args.workflow_run_attempt)
    ):
        fail("workflow run coordinates must be positive integers")
    plan_path = require_ci_input(pathlib.Path(args.plan))
    raw_plan = plan_path.read_bytes()
    if (
        not HEX_64.fullmatch(args.expected_plan_sha256)
        or digest_bytes(raw_plan) != args.expected_plan_sha256
    ):
        fail("fixture plan digest differs from the approved handoff")
    try:
        parsed_plan = json.loads(raw_plan)
    except (UnicodeError, json.JSONDecodeError):
        fail("fixture plan is malformed")
    plan = validate_plan(
        parsed_plan,
        raw_plan,
        contract,
        contract_digest,
        args,
    )
    if plan["action"] == "reset":
        if args.confirmation != contract["resetConfirmation"]:
            fail("apply requires the exact reviewed reset confirmation phrase")
    elif args.confirmation:
        fail("seed apply does not accept reset confirmation")
    receipt_path = require_ci_output(pathlib.Path(args.receipt))
    gms, token, marker = live_config()
    if (
        endpoint_fingerprint(gms) != plan["gmsEndpointFingerprint"]
        or digest_bytes(marker.encode("utf-8"))
        != plan["isolationMarkerSha256"]
    ):
        fail("live endpoint binding differs from the reviewed plan")
    before = inspect_state(contract, contract_digest, gms, token)
    if before_summary(before) != plan["before"]:
        fail("live fixture state changed after the reviewed plan was sealed")
    if plan["operation"] == "reset":
        require_reset_provenance(before)

    reset_deletes: list[dict[str, str]] = []
    prepared: dict[str, Any] | None = None
    if plan["mutationRequired"]:
        prepared = prepare_emission(contract, contract_digest, gms, token)
        failure: Exception | SystemExit | None = None
        try:
            mutation_before = inspect_state(contract, contract_digest, gms, token)
            if before_summary(mutation_before) != plan["before"]:
                fail("live fixture state changed immediately before mutation")
            before = mutation_before
            if plan["operation"] == "reset":
                require_reset_provenance(before)
                for item in before["ownedUrnPresence"]:
                    outcome = (
                        delete_owned_urn(
                            contract,
                            contract_digest,
                            item["urn"],
                            gms,
                            token,
                        )
                        if item["present"]
                        else "already-absent"
                    )
                    reset_deletes.append({"urn": item["urn"], "outcome": outcome})
            require_owned_urns_absent(gms, token)
            emit_prepared(prepared)
        except (Exception, SystemExit) as exc:
            failure = exc
        finally:
            try:
                close_prepared(prepared)
            except (Exception, SystemExit) as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure

    post = (
        wait_for_exact(contract, contract_digest, gms, token)
        if plan["mutationRequired"]
        else before
    )
    if (
        post["classification"] != "exact"
        or post["exactQueryMatchCount"] != 1
        or not all(post["g1ToG5"].values())
        or post["g6Gap"]["classificationState"] != "absent"
        or post["g6Gap"]["piiClassificationAbsent"] is not True
    ):
        fail("post-apply readback differs from the governed-canary contract")
    receipt = {
        "schemaVersion": "archon.datahub-canary-fixture-receipt/v1",
        "repository": REPOSITORY,
        "releaseSha": release_sha,
        "workflowRunId": args.workflow_run_id,
        "workflowRunAttempt": args.workflow_run_attempt,
        "stateContractSha256": contract_digest,
        "planSha256": args.expected_plan_sha256,
        "gmsEndpointFingerprint": plan["gmsEndpointFingerprint"],
        "queryBinding": plan["queryBinding"],
        "ownedUrns": plan["ownedUrns"],
        "action": plan["action"],
        "outcome": (
            "unchanged"
            if plan["operation"] == "noop"
            else "reset"
            if plan["operation"] == "reset"
            else "seeded"
        ),
        "beforeStateSha256": before["digest"],
        "postStateSha256": post["digest"],
        "exactQueryMatchCount": post["exactQueryMatchCount"],
        "g1ToG5": post["g1ToG5"],
        "g6Gap": post["g6Gap"],
        "resetDeletes": reset_deletes,
        "observedAt": dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    write_exclusive(receipt_path, receipt)
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


def command_validate_contract(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    print(
        json.dumps(
            {
                "query": contract["binding"]["query"],
                "schemaVersion": contract["schemaVersion"],
                "stateContractSha256": contract_digest,
                "targetUrn": contract["binding"]["targetUrn"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def command_validate_runtime(args: argparse.Namespace) -> None:
    contract, contract_digest = load_contract(pathlib.Path(args.contract).resolve())
    proposals, _, _ = build_proposals(contract, contract_digest)
    proposal_projection = sorted(
        (
            {
                "aspectName": proposal.aspect.get_aspect_name(),
                "aspectSha256": digest_obj(proposal.aspect.to_obj()),
                "entityUrn": proposal.entityUrn,
            }
            for proposal in proposals
        ),
        key=lambda item: (item["entityUrn"], item["aspectName"]),
    )
    print(
        json.dumps(
            {
                "schemaVersion": (
                    "archon.datahub-canary-fixture-runtime-validation/v1"
                ),
                "stateContractSha256": contract_digest,
                "proposalCount": len(proposal_projection),
                "proposalSetSha256": digest_obj(proposal_projection),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-contract")
    validate.add_argument("--contract", required=True)
    validate.set_defaults(handler=command_validate_contract)

    validate_runtime = commands.add_parser("validate-runtime")
    validate_runtime.add_argument("--contract", required=True)
    validate_runtime.set_defaults(handler=command_validate_runtime)

    plan = commands.add_parser("plan")
    plan.add_argument("--contract", required=True)
    plan.add_argument("--action", required=True, choices=("seed", "reset"))
    plan.add_argument("--confirmation", default="")
    plan.add_argument("--query", required=True)
    plan.add_argument("--release-sha", required=True)
    plan.add_argument("--repository", default=REPOSITORY)
    plan.add_argument("--output", required=True)
    plan.set_defaults(handler=command_plan)

    apply = commands.add_parser("apply")
    apply.add_argument("--contract", required=True)
    apply.add_argument("--plan", required=True)
    apply.add_argument("--expected-plan-sha256", required=True)
    apply.add_argument("--confirmation", default="")
    apply.add_argument("--release-sha", required=True)
    apply.add_argument("--repository", default=REPOSITORY)
    apply.add_argument("--workflow-run-id", required=True)
    apply.add_argument("--workflow-run-attempt", required=True)
    apply.add_argument("--receipt", required=True)
    apply.set_defaults(handler=command_apply)
    return root


def main() -> None:
    args = parser().parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
