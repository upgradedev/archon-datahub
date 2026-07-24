#!/usr/bin/env python3
"""Fail-closed CI disposition gate for the locked DataHub MCP runtime.

The raw uv SARIF is always copied to the actionable output before validation.
Only an exact, current, runtime-scoped OpenVEX match may replace that copy with
an otherwise identical SARIF document whose results are empty.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, NoReturn


CONTRACT_SCHEMA = "archon.datahub-mcp-lock/v5"
POLICY_SCHEMA = "archon.openvex-policy/v1"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
SMOKE_SCHEMA = "archon.datahub-mcp-runtime-smoke/v1"
RECEIPT_SCHEMA = "archon.datahub-mcp-audit-disposition/v1"
SELF_TEST_SCHEMA = "archon.datahub-mcp-audit-validator-self-test/v1"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/"
    "schemas/sarif-schema-2.1.0.json"
)

MCP_NAME = "mcp-server-datahub"
MCP_VERSION = "0.6.0"
MCP_PURL = "pkg:pypi/mcp-server-datahub@0.6.0"
MCP_REQUIREMENT = "mcp-server-datahub==0.6.0"
VIRTUAL_ROOT_NAME = "archon-datahub-mcp-runtime"
VIRTUAL_ROOT_VERSION = "0.6.0"
MCP_WHEEL = {
    "filename": "mcp_server_datahub-0.6.0-py3-none-any.whl",
    "url": (
        "https://files.pythonhosted.org/packages/fb/5a/"
        "5573927ea69ff2a93b1957d6f128b9aacbee50df0b35e6410678d3b62d0b/"
        "mcp_server_datahub-0.6.0-py3-none-any.whl"
    ),
    "sha256": "2679dcfafc0ae12724efbf0fc6a73014f9085a4e1303cba9b1e41776dab8f001",
    "size": 119_016,
}
MCP_WHEEL_SHA256 = MCP_WHEEL["sha256"]

ACRYL_NAME = "acryl-datahub"
ACRYL_VERSION = "1.6.0.15"
ACRYL_WHEEL = {
    "filename": "acryl_datahub-1.6.0.15-py3-none-any.whl",
    "url": (
        "https://files.pythonhosted.org/packages/c1/81/"
        "32a1e7a9b7bd75c4930ba27edad498cde2e4032464df8ad7577776038341/"
        "acryl_datahub-1.6.0.15-py3-none-any.whl"
    ),
    "sha256": "18263b60c52c333dda3091578dead0a238e606c92c0561fe7b52c905e7b00cbf",
    "size": 4_725_320,
}

SETUPTOOLS_NAME = "setuptools"
SETUPTOOLS_VERSION = "81.0.0"
SETUPTOOLS_PURL = "pkg:pypi/setuptools@81.0.0"
SETUPTOOLS_WHEEL = {
    "filename": "setuptools-81.0.0-py3-none-any.whl",
    "url": (
        "https://files.pythonhosted.org/packages/e1/e3/"
        "c164c88b2e5ce7b24d667b9bd83589cf4f3520d97cad01534cd3c4f55fdb/"
        "setuptools-81.0.0-py3-none-any.whl"
    ),
    "sha256": "fdd925d5c5d9f62e4b74b30d6dd7828ce236fd6ed998a08d81de62ce5a6310d6",
    "size": 1_062_021,
}

UV_VERSION = "0.11.31"
PYTHON_VERSION = "3.11.15"
CANONICAL_ID = "CVE-2026-59890"
ADVISORY_ALIASES = [
    "BIT-setuptools-2026-59890",
    "GHSA-h35f-9h28-mq5c",
    "PYSEC-2026-3447",
]
SCANNER_RULE_IDS = [
    "GHSA-h35f-9h28-mq5c",
    "PYSEC-2026-3447",
]
ADVISORY_CLOSURE = frozenset([CANONICAL_ID, *ADVISORY_ALIASES])
EXPECTED_RESULT_ALIASES = {
    "GHSA-h35f-9h28-mq5c": [
        "BIT-setuptools-2026-59890",
        "CVE-2026-59890",
        "PYSEC-2026-3447",
    ],
    "PYSEC-2026-3447": [
        "BIT-setuptools-2026-59890",
        "CVE-2026-59890",
        "GHSA-h35f-9h28-mq5c",
    ],
}

EXPECTED_TOOLS = [
    "get_dataset_queries",
    "get_entities",
    "get_lineage",
    "get_lineage_paths_between",
    "list_schema_fields",
    "search",
]
EXPECTED_VEX_PATH = (
    ".github/security/openvex/datahub-mcp-setuptools-81.0.0.openvex.json"
)
EXPECTED_VEX_SHA256 = (
    "9432452a9fd4b602ec6509b059d7e45d5fd48cfa3ccb3fcbdfa561451d3b8dbc"
)
EXPECTED_CONDITIONS = {
    "runnerOs": "Linux",
    "pythonPlatform": "linux",
    "sourceBuilds": "deny",
    "sourceDistributionCreation": "forbidden",
    "installation": "hash-bound-wheels-only",
}
EXPECTED_CONSTRAINTS = [
    "acryl-datahub==1.6.0.15",
    "setuptools==81.0.0",
]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:[-+][0-9A-Za-z.-]+)?$"
)


class ValidationError(RuntimeError):
    """A policy or evidence mismatch."""


def fail(message: str) -> NoReturn:
    raise ValidationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_dict(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def require_exact_keys(
    value: dict[str, Any], expected: set[str], label: str
) -> None:
    observed = set(value)
    require(
        observed == expected,
        f"{label} keys changed: expected {sorted(expected)}, observed {sorted(observed)}",
    )


def require_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value), f"{label} must be a non-empty string")
    return value


def require_int(value: Any, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} must be an integer",
    )
    return value


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{label} is not UTF-8: {exc}") from exc
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValidationError(f"{label} is not canonical JSON input: {exc}") from exc


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_timestamp(value: Any, label: str) -> datetime:
    text = require_string(value, label)
    require(TIMESTAMP_RE.fullmatch(text) is not None, f"{label} must be UTC RFC3339")
    parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return parsed


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def validate_contract(
    contract: dict[str, Any],
    vex_sha256: str,
    now: datetime,
    *,
    enforce_static_vex: bool,
) -> dict[str, Any]:
    require(contract.get("schemaVersion") == CONTRACT_SCHEMA, "contract schema changed")

    package = require_dict(contract.get("package"), "contract.package")
    require(package.get("name") == MCP_NAME, "contract MCP package changed")
    require(package.get("version") == MCP_VERSION, "contract MCP version changed")
    mcp_wheel = require_dict(package.get("wheel"), "contract.package.wheel")
    require(
        mcp_wheel == MCP_WHEEL,
        "contract MCP wheel binding changed",
    )

    runtime = require_dict(contract.get("runtime"), "contract.runtime")
    require(runtime.get("pythonVersion") == PYTHON_VERSION, "Python pin changed")
    require(runtime.get("uvVersion") == UV_VERSION, "uv pin changed")

    resolution = require_dict(contract.get("resolution"), "contract.resolution")
    require(
        resolution.get("constraints") == EXPECTED_CONSTRAINTS,
        "runtime compatibility constraints changed",
    )
    require(resolution.get("sourceBuilds") == "deny", "source builds are not denied")
    require(
        resolution.get("projectMode") == "virtual-static-metadata",
        "runtime project mode changed",
    )
    require(
        resolution.get("virtualRootName") == VIRTUAL_ROOT_NAME,
        "virtual runtime root name changed",
    )
    require(
        resolution.get("virtualRootVersion") == VIRTUAL_ROOT_VERSION,
        "virtual runtime root version changed",
    )
    require(
        resolution.get("mcpDependency") == MCP_REQUIREMENT,
        "audited MCP registry dependency changed",
    )
    resolved_sha = require_string(
        resolution.get("resolvedLockSha256"),
        "contract.resolution.resolvedLockSha256",
    )
    require(SHA256_RE.fullmatch(resolved_sha) is not None, "invalid resolved-lock digest")

    compatibility = require_dict(
        contract.get("runtimeCompatibility"), "contract.runtimeCompatibility"
    )
    acryl = require_dict(
        compatibility.get("acrylDatahub"), "runtimeCompatibility.acrylDatahub"
    )
    require(acryl.get("name") == ACRYL_NAME, "acryl-datahub package name changed")
    require(acryl.get("version") == ACRYL_VERSION, "acryl-datahub version changed")
    require(
        acryl.get("setuptoolsRequirement") == "setuptools<82.0.0",
        "acryl-datahub setuptools compatibility bound changed",
    )
    require(acryl.get("wheel") == ACRYL_WHEEL, "acryl-datahub wheel binding changed")

    setuptools = require_dict(
        compatibility.get("setuptools"), "runtimeCompatibility.setuptools"
    )
    require(setuptools.get("name") == SETUPTOOLS_NAME, "setuptools package name changed")
    require(
        setuptools.get("version") == SETUPTOOLS_VERSION,
        "setuptools compatibility pin changed",
    )
    require(
        setuptools.get("wheel") == SETUPTOOLS_WHEEL,
        "setuptools wheel binding changed",
    )

    policy = require_dict(
        contract.get("advisoryDisposition"), "contract.advisoryDisposition"
    )
    require(policy.get("schemaVersion") == POLICY_SCHEMA, "policy schema changed")
    require(policy.get("canonicalId") == CANONICAL_ID, "canonical advisory changed")
    require(policy.get("aliases") == ADVISORY_ALIASES, "advisory aliases changed")
    require(
        policy.get("scannerRuleIds") == SCANNER_RULE_IDS,
        "approved scanner primary IDs changed",
    )
    require(
        policy.get("product")
        == {"name": MCP_NAME, "version": MCP_VERSION, "purl": MCP_PURL},
        "VEX product identity changed",
    )
    require(
        policy.get("package")
        == {
            "name": SETUPTOOLS_NAME,
            "version": SETUPTOOLS_VERSION,
            "purl": SETUPTOOLS_PURL,
        },
        "VEX subcomponent identity changed",
    )
    require(policy.get("status") == "not_affected", "VEX status is not not_affected")
    require(
        policy.get("justification") == "vulnerable_code_not_in_execute_path",
        "VEX justification changed",
    )
    require_string(policy.get("impactStatement"), "policy.impactStatement")
    require(policy.get("conditions") == EXPECTED_CONDITIONS, "VEX conditions changed")

    vex_policy = require_dict(policy.get("vex"), "policy.vex")
    require(
        vex_policy
        == {
            "path": EXPECTED_VEX_PATH,
            "sha256": vex_policy.get("sha256"),
            "issuedAt": vex_policy.get("issuedAt"),
            "expiresAt": vex_policy.get("expiresAt"),
            "maxValidityDays": 30,
        },
        "VEX policy shape changed",
    )
    declared_vex_sha = require_string(vex_policy.get("sha256"), "policy.vex.sha256")
    require(SHA256_RE.fullmatch(declared_vex_sha) is not None, "invalid VEX digest")
    require(declared_vex_sha == vex_sha256, "committed OpenVEX digest mismatch")
    if enforce_static_vex:
        require(
            declared_vex_sha == EXPECTED_VEX_SHA256,
            "repository OpenVEX digest changed without validator review",
        )

    issued = parse_timestamp(vex_policy.get("issuedAt"), "policy.vex.issuedAt")
    expires = parse_timestamp(vex_policy.get("expiresAt"), "policy.vex.expiresAt")
    validity = expires - issued
    require(validity > timedelta(0), "VEX expiry must follow issuance")
    require(
        validity <= timedelta(days=30),
        "VEX validity exceeds the 30-day policy maximum",
    )
    require(issued <= now, "VEX policy is not active yet")
    require(now < expires, "VEX policy has expired")

    return policy


def validate_openvex(
    vex: dict[str, Any],
    contract: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    require_exact_keys(
        vex,
        {"@context", "@id", "author", "role", "timestamp", "version", "statements"},
        "OpenVEX document",
    )
    require(vex.get("@context") == OPENVEX_CONTEXT, "OpenVEX context changed")
    document_id = require_string(vex.get("@id"), "OpenVEX @id")
    require(document_id.endswith(f"/{CANONICAL_ID}"), "OpenVEX document ID changed")
    require_string(vex.get("author"), "OpenVEX author")
    require(vex.get("role") == "Document Creator", "OpenVEX role changed")
    require(vex.get("timestamp") == policy["vex"]["issuedAt"], "VEX timestamp drift")
    require(vex.get("version") == 1, "OpenVEX version changed")

    statements = require_list(vex.get("statements"), "OpenVEX statements")
    require(len(statements) == 1, "OpenVEX must contain exactly one statement")
    statement = require_dict(statements[0], "OpenVEX statement")
    require_exact_keys(
        statement,
        {
            "vulnerability",
            "products",
            "status",
            "justification",
            "impact_statement",
        },
        "OpenVEX statement",
    )

    vulnerability = require_dict(
        statement.get("vulnerability"), "OpenVEX vulnerability"
    )
    require_exact_keys(
        vulnerability, {"@id", "name", "aliases"}, "OpenVEX vulnerability"
    )
    require(
        vulnerability.get("@id")
        == "https://nvd.nist.gov/vuln/detail/CVE-2026-59890",
        "OpenVEX vulnerability IRI changed",
    )
    require(vulnerability.get("name") == CANONICAL_ID, "OpenVEX canonical ID changed")
    require(
        vulnerability.get("aliases") == ADVISORY_ALIASES,
        "OpenVEX alias closure changed",
    )

    products = require_list(statement.get("products"), "OpenVEX products")
    require(len(products) == 1, "OpenVEX must bind exactly one product")
    product = require_dict(products[0], "OpenVEX product")
    require_exact_keys(
        product, {"@id", "hashes", "subcomponents"}, "OpenVEX product"
    )
    require(product.get("@id") == MCP_PURL, "OpenVEX product purl changed")
    require(
        product.get("hashes") == {"sha-256": MCP_WHEEL_SHA256},
        "OpenVEX product digest changed",
    )
    subcomponents = require_list(
        product.get("subcomponents"), "OpenVEX subcomponents"
    )
    require(len(subcomponents) == 1, "OpenVEX must bind one subcomponent")
    subcomponent = require_dict(subcomponents[0], "OpenVEX subcomponent")
    require_exact_keys(
        subcomponent, {"@id", "hashes"}, "OpenVEX subcomponent"
    )
    require(subcomponent.get("@id") == SETUPTOOLS_PURL, "OpenVEX package purl changed")
    require(
        subcomponent.get("hashes") == {"sha-256": SETUPTOOLS_WHEEL["sha256"]},
        "OpenVEX package digest changed",
    )
    require(statement.get("status") == policy["status"], "OpenVEX status drift")
    require(
        statement.get("justification") == policy["justification"],
        "OpenVEX justification drift",
    )
    require(
        statement.get("impact_statement") == policy["impactStatement"],
        "contract and OpenVEX impact statements differ",
    )
    require(
        contract["runtimeCompatibility"]["setuptools"]["wheel"]["sha256"]
        == SETUPTOOLS_WHEEL["sha256"],
        "OpenVEX subcomponent is not the runtime compatibility artifact",
    )


def validate_installed(installed: Any) -> None:
    packages = require_list(installed, "installed package inventory")
    require(len(packages) > 10, "installed package inventory is incomplete")
    selected: dict[str, list[dict[str, Any]]] = {
        MCP_NAME: [],
        ACRYL_NAME: [],
        SETUPTOOLS_NAME: [],
    }
    for index, raw_package in enumerate(packages):
        package = require_dict(raw_package, f"installed[{index}]")
        name = require_string(package.get("name"), f"installed[{index}].name")
        version = require_string(package.get("version"), f"installed[{index}].version")
        normalized = normalized_name(name)
        if normalized in selected:
            selected[normalized].append(package)
        require(version.strip() == version, f"installed[{index}] version is not trimmed")

    expected = {
        MCP_NAME: MCP_VERSION,
        ACRYL_NAME: ACRYL_VERSION,
        SETUPTOOLS_NAME: SETUPTOOLS_VERSION,
    }
    for name, version in expected.items():
        matches = selected[name]
        require(len(matches) == 1, f"installed inventory must contain one {name}")
        require(matches[0].get("version") == version, f"installed {name} version changed")
        require(
            "editable_project_location" not in matches[0],
            f"installed {name} must not be editable",
        )


def validate_wheel_graph(graph: dict[str, Any]) -> None:
    require(
        graph.get("schemaVersion") == "archon.datahub-mcp-wheel-only-graph/v1",
        "wheel graph schema changed",
    )
    packages = require_list(graph.get("packages"), "wheel graph packages")
    package_count = require_int(graph.get("packageCount"), "wheel graph packageCount")
    require(package_count == len(packages), "wheel graph package count mismatch")
    require(package_count > 10, "wheel graph is incomplete")

    selected: dict[str, list[dict[str, Any]]] = {
        MCP_NAME: [],
        ACRYL_NAME: [],
        SETUPTOOLS_NAME: [],
    }
    for index, raw_package in enumerate(packages):
        package = require_dict(raw_package, f"wheel graph package[{index}]")
        name = require_string(package.get("name"), f"wheel graph package[{index}].name")
        require_string(
            package.get("version"), f"wheel graph package[{index}].version"
        )
        wheels = require_list(
            package.get("wheels"), f"wheel graph package[{index}].wheels"
        )
        require(bool(wheels), f"wheel graph package {name} is wheel-less")
        for wheel_index, raw_wheel in enumerate(wheels):
            wheel = require_dict(
                raw_wheel, f"wheel graph package[{index}].wheels[{wheel_index}]"
            )
            require_exact_keys(
                wheel,
                {"hash", "size", "url"},
                f"wheel graph package[{index}].wheels[{wheel_index}]",
            )
            wheel_hash = require_string(
                wheel.get("hash"), f"wheel graph package[{index}] wheel hash"
            )
            require(
                SHA256_RE.fullmatch(wheel_hash) is not None,
                f"wheel graph package {name} has invalid wheel digest",
            )
            require(
                require_int(
                    wheel.get("size"), f"wheel graph package[{index}] wheel size"
                )
                > 0,
                f"wheel graph package {name} has invalid wheel size",
            )
            wheel_url = require_string(
                wheel.get("url"), f"wheel graph package[{index}] wheel URL"
            )
            require(
                wheel_url.startswith("https://files.pythonhosted.org/"),
                f"wheel graph package {name} has an untrusted wheel origin",
            )
        normalized = normalized_name(name)
        if normalized in selected:
            selected[normalized].append(package)

    for name, version, artifact in (
        (MCP_NAME, MCP_VERSION, MCP_WHEEL),
        (ACRYL_NAME, ACRYL_VERSION, ACRYL_WHEEL),
        (SETUPTOOLS_NAME, SETUPTOOLS_VERSION, SETUPTOOLS_WHEEL),
    ):
        matches = selected[name]
        require(len(matches) == 1, f"wheel graph must contain one {name}")
        package = matches[0]
        require(package.get("version") == version, f"wheel graph {name} version changed")
        expected_wheel = {
            "hash": artifact["sha256"],
            "size": artifact["size"],
            "url": artifact["url"],
        }
        require(
            package.get("wheels") == [expected_wheel],
            f"wheel graph {name} artifact set changed",
        )


def validate_runtime_smoke(smoke: dict[str, Any]) -> None:
    required_keys = {
        "credentialsUsed",
        "fastMcpVersion",
        "initialized",
        "loopbackConfigRequests",
        "networkToolCalls",
        "packageVersion",
        "pinged",
        "protocol",
        "readOnlyHints",
        "schemaVersion",
        "serverInfoVersion",
        "stderrBytes",
        "stderrSha256",
        "tools",
        "unexpectedHttpRequests",
    }
    require_exact_keys(smoke, required_keys, "runtime smoke")
    require(smoke.get("schemaVersion") == SMOKE_SCHEMA, "runtime smoke schema changed")
    require(smoke.get("protocol") == "mcp-stdio", "runtime smoke protocol changed")
    require(smoke.get("packageVersion") == MCP_VERSION, "smoke package version changed")
    fastmcp_version = require_string(
        smoke.get("fastMcpVersion"), "smoke.fastMcpVersion"
    )
    require(
        SEMVER_RE.fullmatch(fastmcp_version) is not None,
        "smoke FastMCP version is not semver",
    )
    require(
        smoke.get("serverInfoVersion") == fastmcp_version,
        "MCP serverInfo version differs from the installed FastMCP runtime",
    )
    require(smoke.get("initialized") is True, "MCP initialize did not succeed")
    require(smoke.get("pinged") is True, "MCP ping did not succeed")
    require(
        smoke.get("credentialsUsed") is False,
        "runtime smoke used DataHub credentials",
    )
    require(
        require_int(smoke.get("networkToolCalls"), "smoke.networkToolCalls") == 0,
        "runtime smoke invoked a network-backed MCP tool",
    )
    require(
        require_int(
            smoke.get("loopbackConfigRequests"), "smoke.loopbackConfigRequests"
        )
        == 1,
        "runtime smoke did not prove the exact loopback config request",
    )
    require(
        require_int(
            smoke.get("unexpectedHttpRequests"), "smoke.unexpectedHttpRequests"
        )
        == 0,
        "runtime smoke observed an unexpected HTTP request",
    )
    require(
        smoke.get("readOnlyHints") is True,
        "runtime smoke did not prove all tool readOnlyHint annotations",
    )
    require(smoke.get("tools") == EXPECTED_TOOLS, "runtime MCP tool profile changed")
    require(
        require_int(smoke.get("stderrBytes"), "smoke.stderrBytes") >= 0,
        "runtime smoke stderr byte count is invalid",
    )
    stderr_sha = require_string(smoke.get("stderrSha256"), "smoke.stderrSha256")
    require(SHA256_RE.fullmatch(stderr_sha) is not None, "invalid smoke stderr digest")


def validate_rule_descriptors(driver: dict[str, Any]) -> None:
    rules = require_list(driver.get("rules"), "SARIF driver rules")
    require(len(rules) == 2, "SARIF must contain exactly two vulnerability rules")
    observed_ids: list[str] = []
    for index, raw_rule in enumerate(rules):
        rule = require_dict(raw_rule, f"SARIF rule[{index}]")
        rule_id = require_string(rule.get("id"), f"SARIF rule[{index}].id")
        observed_ids.append(rule_id)
        require(rule_id in SCANNER_RULE_IDS, "SARIF contains an unapproved rule")
        name = require_string(rule.get("name"), f"SARIF rule[{index}].name")
        require(name in ADVISORY_CLOSURE, "SARIF rule display ID is outside VEX")
        properties = require_dict(
            rule.get("properties"), f"SARIF rule[{index}].properties"
        )
        require(
            properties.get("tags") == ["security", "vulnerability"],
            "SARIF rule is not a vulnerability descriptor",
        )
    require(
        sorted(observed_ids) == sorted(SCANNER_RULE_IDS),
        "SARIF rule primary-ID set changed",
    )


def validate_result(result: dict[str, Any], index: int) -> str:
    label = f"SARIF result[{index}]"
    require(result.get("kind") == "fail", f"{label} kind changed")
    require(result.get("level") == "error", f"{label} is not a vulnerability error")
    rule_id = require_string(result.get("ruleId"), f"{label}.ruleId")
    require(rule_id in SCANNER_RULE_IDS, f"{label} primary ID is unapproved")

    properties = require_dict(result.get("properties"), f"{label}.properties")
    required_properties = {
        "uv/aliases",
        "uv/displayId",
        "uv/fixVersions",
        "uv/id",
        "uv/package",
        "uv/version",
    }
    optional_properties = {"uv/modified", "uv/published"}
    require(
        required_properties.issubset(properties),
        f"{label} is missing uv vulnerability identity fields",
    )
    require(
        set(properties).issubset(required_properties | optional_properties),
        f"{label} contains unexpected uv properties",
    )
    require(properties.get("uv/id") == rule_id, f"{label} rule and uv/id differ")
    require(
        properties.get("uv/package") == SETUPTOOLS_NAME,
        f"{label} package is not setuptools",
    )
    require(
        properties.get("uv/version") == SETUPTOOLS_VERSION,
        f"{label} setuptools version changed",
    )
    aliases = require_list(properties.get("uv/aliases"), f"{label} uv/aliases")
    require(
        aliases == EXPECTED_RESULT_ALIASES[rule_id],
        f"{label} alias set changed",
    )
    require(
        frozenset([rule_id, *aliases]) == ADVISORY_CLOSURE,
        f"{label} does not map exactly to the approved VEX closure",
    )
    require(
        properties.get("uv/fixVersions") == ["83.0.0"],
        f"{label} fixed-version evidence changed",
    )
    require(
        properties.get("uv/displayId") in ADVISORY_CLOSURE,
        f"{label} display ID is outside the VEX closure",
    )
    for optional in optional_properties:
        if optional in properties:
            require_string(properties[optional], f"{label} {optional}")

    fingerprints = require_dict(
        result.get("partialFingerprints"), f"{label}.partialFingerprints"
    )
    require(
        fingerprints
        == {
            "uv/vulnerability": (
                f"{rule_id}:{SETUPTOOLS_NAME}:{SETUPTOOLS_VERSION}"
            )
        },
        f"{label} semantic fingerprint changed",
    )

    message = require_dict(result.get("message"), f"{label}.message")
    message_text = require_string(message.get("text"), f"{label}.message.text")
    require(
        f"{SETUPTOOLS_NAME} {SETUPTOOLS_VERSION}" in message_text,
        f"{label} message package identity changed",
    )

    locations = require_list(result.get("locations"), f"{label}.locations")
    require(len(locations) == 1, f"{label} must have one package location")
    location = require_dict(locations[0], f"{label}.locations[0]")
    logical = require_list(
        location.get("logicalLocations"), f"{label}.logicalLocations"
    )
    require(len(logical) == 1, f"{label} must have one logical package location")
    logical_location = require_dict(logical[0], f"{label}.logicalLocations[0]")
    require(
        logical_location.get("kind") == "package"
        and logical_location.get("name") == SETUPTOOLS_NAME
        and logical_location.get("fullyQualifiedName")
        == f"{SETUPTOOLS_NAME}@{SETUPTOOLS_VERSION}",
        f"{label} logical package location changed",
    )
    physical = require_dict(
        location.get("physicalLocation"), f"{label}.physicalLocation"
    )
    artifact = require_dict(
        physical.get("artifactLocation"), f"{label}.artifactLocation"
    )
    artifact_uri = require_string(artifact.get("uri"), f"{label}.artifact URI")
    require(artifact_uri.endswith("uv.lock"), f"{label} is not bound to uv.lock")
    region = require_dict(physical.get("region"), f"{label}.region")
    require(region.get("startLine") == 1, f"{label} lock location changed")

    return rule_id


def validate_sarif(sarif: dict[str, Any], audit_exit: int) -> tuple[int, int]:
    require(audit_exit == 1, "active VEX requires raw uv audit exit code 1")
    require(sarif.get("$schema") == SARIF_SCHEMA, "SARIF schema URI changed")
    require(sarif.get("version") == "2.1.0", "SARIF version changed")
    runs = require_list(sarif.get("runs"), "SARIF runs")
    require(len(runs) == 1, "SARIF must contain exactly one run")
    run = require_dict(runs[0], "SARIF run")

    invocations = require_list(run.get("invocations"), "SARIF invocations")
    require(len(invocations) == 1, "SARIF must contain exactly one invocation")
    invocation = require_dict(invocations[0], "SARIF invocation")
    require(
        invocation.get("executionSuccessful") is True,
        "uv SARIF invocation did not complete successfully",
    )

    tool = require_dict(run.get("tool"), "SARIF tool")
    driver = require_dict(tool.get("driver"), "SARIF driver")
    require(driver.get("name") == "uv", "SARIF was not produced by uv")
    require(driver.get("version") == UV_VERSION, "SARIF uv version changed")
    require(
        driver.get("semanticVersion") == UV_VERSION,
        "SARIF uv semantic version changed",
    )
    validate_rule_descriptors(driver)

    results = require_list(run.get("results"), "SARIF results")
    require(
        len(results) == 2,
        "active VEX requires exactly two raw setuptools vulnerability records",
    )
    observed: list[str] = []
    for index, raw_result in enumerate(results):
        result = require_dict(raw_result, f"SARIF result[{index}]")
        observed.append(validate_result(result, index))
    require(
        sorted(observed) == sorted(SCANNER_RULE_IDS),
        "raw SARIF primary-ID set changed",
    )
    require(len(set(observed)) == 2, "raw SARIF contains a duplicate primary record")
    return len(results), len(observed)


def validate_bundle(
    *,
    contract: dict[str, Any],
    vex: dict[str, Any],
    sarif: dict[str, Any],
    installed: Any,
    wheel_graph: dict[str, Any],
    runtime_smoke: dict[str, Any],
    audit_exit: int,
    input_hashes: dict[str, str],
    now: datetime,
    runner_os: str,
    enforce_static_vex: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    require(runner_os == "Linux", "MCP VEX disposition is Linux-only")
    require(now.tzinfo is not None, "validation clock must be timezone-aware")
    vex_sha256 = input_hashes["openVexSha256"]
    policy = validate_contract(
        contract,
        vex_sha256,
        now,
        enforce_static_vex=enforce_static_vex,
    )
    validate_openvex(vex, contract, policy)
    validate_installed(installed)
    validate_wheel_graph(wheel_graph)
    validate_runtime_smoke(runtime_smoke)
    raw_count, approved_count = validate_sarif(sarif, audit_exit)

    actionable = copy.deepcopy(sarif)
    actionable["runs"][0]["results"] = []
    actionable_raw = canonical_json_bytes(actionable)
    receipt = {
        "schemaVersion": RECEIPT_SCHEMA,
        "decision": "approved",
        "evaluatedAt": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": {
            "runnerOs": runner_os,
            "pythonPlatform": "linux",
        },
        "scanner": {
            "name": "uv",
            "version": UV_VERSION,
            "exitCode": audit_exit,
        },
        "policy": {
            "canonicalId": CANONICAL_ID,
            "scannerRuleIds": SCANNER_RULE_IDS,
            "status": "not_affected",
            "expiresAt": policy["vex"]["expiresAt"],
        },
        "findings": {
            "raw": raw_count,
            "approved": approved_count,
            "unapproved": raw_count - approved_count,
            "actionable": 0,
        },
        "runtimeSmoke": {
            "protocol": "mcp-stdio",
            "initialized": True,
            "pinged": True,
            "credentialsUsed": False,
            "loopbackConfigRequests": 1,
            "unexpectedHttpRequests": 0,
            "readOnlyHints": True,
            "toolCount": len(EXPECTED_TOOLS),
            "serverInfoVersion": runtime_smoke["serverInfoVersion"],
        },
        "hashes": {
            **input_hashes,
            "actionableSarifSha256": digest(actionable_raw),
        },
    }
    require(receipt["findings"]["unapproved"] == 0, "unapproved findings remain")
    return actionable, receipt


def read_regular_file(path_text: str, label: str) -> bytes:
    path = Path(path_text)
    require(path.is_file(), f"{label} is not one regular file")
    require(not path.is_symlink(), f"{label} must not be a symlink")
    return path.read_bytes()


def prepare_output(path: Path, label: str) -> None:
    if path.exists():
        require(path.is_file(), f"{label} exists but is not a regular file")
        require(not path.is_symlink(), f"{label} must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    require(path.parent.is_dir(), f"{label} parent is not a directory")


def atomic_write(path: Path, raw: bytes) -> None:
    prepare_output(path, str(path))
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def rejected_receipt(error: str, hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "decision": "rejected",
        "error": error,
        "findings": {
            "approved": 0,
            "unapproved": None,
            "actionable": "raw-sarif-preserved",
        },
        "hashes": hashes,
    }


def fixture_sarif_result(rule_id: str) -> dict[str, Any]:
    return {
        "kind": "fail",
        "level": "error",
        "locations": [
            {
                "logicalLocations": [
                    {
                        "fullyQualifiedName": "setuptools@81.0.0",
                        "kind": "package",
                        "name": "setuptools",
                    }
                ],
                "physicalLocation": {
                    "artifactLocation": {"uri": "uv.lock"},
                    "region": {"startLine": 1},
                },
            }
        ],
        "message": {"text": f"setuptools 81.0.0 is vulnerable to {rule_id}"},
        "partialFingerprints": {
            "uv/vulnerability": f"{rule_id}:setuptools:81.0.0"
        },
        "properties": {
            "uv/aliases": EXPECTED_RESULT_ALIASES[rule_id],
            "uv/displayId": rule_id,
            "uv/fixVersions": ["83.0.0"],
            "uv/id": rule_id,
            "uv/package": "setuptools",
            "uv/version": "81.0.0",
        },
        "ruleId": rule_id,
    }


def build_self_test_fixture() -> dict[str, Any]:
    issued = "2026-07-23T11:30:00Z"
    impact = (
        "DataHub requires setuptools below 82 at runtime. This sealed Linux graph "
        "installs only hash-bound wheels with source builds and source-distribution "
        "creation forbidden. The affected macOS APFS/HFS+ MANIFEST.in "
        "source-distribution path cannot execute in this Linux wheel-only runtime, "
        "regardless of DataHub authentication. CI separately imports the MCP "
        "runtime and completes an uncredentialed stdio initialize/ping/tools-list "
        "smoke exposing only the exact read-only tool set."
    )
    vex = {
        "@context": OPENVEX_CONTEXT,
        "@id": (
            "https://github.com/upgradedev/archon-datahub/security/vex/"
            "datahub-mcp-v0.6.0/setuptools-81.0.0/CVE-2026-59890"
        ),
        "author": "https://github.com/upgradedev/archon-datahub",
        "role": "Document Creator",
        "timestamp": issued,
        "version": 1,
        "statements": [
            {
                "vulnerability": {
                    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2026-59890",
                    "name": CANONICAL_ID,
                    "aliases": ADVISORY_ALIASES,
                },
                "products": [
                    {
                        "@id": MCP_PURL,
                        "hashes": {"sha-256": MCP_WHEEL_SHA256},
                        "subcomponents": [
                            {
                                "@id": SETUPTOOLS_PURL,
                                "hashes": {
                                    "sha-256": SETUPTOOLS_WHEEL["sha256"]
                                },
                            }
                        ],
                    }
                ],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": impact,
            }
        ],
    }
    vex_raw = canonical_json_bytes(vex)
    contract = {
        "schemaVersion": CONTRACT_SCHEMA,
        "package": {
            "name": MCP_NAME,
            "version": MCP_VERSION,
            "wheel": MCP_WHEEL,
        },
        "runtime": {
            "pythonVersion": PYTHON_VERSION,
            "uvVersion": UV_VERSION,
        },
        "resolution": {
            "constraints": EXPECTED_CONSTRAINTS,
            "sourceBuilds": "deny",
            "projectMode": "virtual-static-metadata",
            "virtualRootName": VIRTUAL_ROOT_NAME,
            "virtualRootVersion": VIRTUAL_ROOT_VERSION,
            "mcpDependency": MCP_REQUIREMENT,
            "resolvedLockSha256": "1" * 64,
        },
        "runtimeCompatibility": {
            "acrylDatahub": {
                "name": ACRYL_NAME,
                "version": ACRYL_VERSION,
                "setuptoolsRequirement": "setuptools<82.0.0",
                "wheel": ACRYL_WHEEL,
            },
            "setuptools": {
                "name": SETUPTOOLS_NAME,
                "version": SETUPTOOLS_VERSION,
                "wheel": SETUPTOOLS_WHEEL,
            },
        },
        "advisoryDisposition": {
            "schemaVersion": POLICY_SCHEMA,
            "vex": {
                "path": EXPECTED_VEX_PATH,
                "sha256": digest(vex_raw),
                "issuedAt": issued,
                "expiresAt": "2026-08-22T11:30:00Z",
                "maxValidityDays": 30,
            },
            "canonicalId": CANONICAL_ID,
            "aliases": ADVISORY_ALIASES,
            "scannerRuleIds": SCANNER_RULE_IDS,
            "product": {
                "name": MCP_NAME,
                "version": MCP_VERSION,
                "purl": MCP_PURL,
            },
            "package": {
                "name": SETUPTOOLS_NAME,
                "version": SETUPTOOLS_VERSION,
                "purl": SETUPTOOLS_PURL,
            },
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
            "impactStatement": impact,
            "conditions": EXPECTED_CONDITIONS,
        },
    }
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "properties": {"tags": ["security", "vulnerability"]},
        }
        for rule_id in SCANNER_RULE_IDS
    ]
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    fixture_sarif_result(rule_id) for rule_id in SCANNER_RULE_IDS
                ],
                "tool": {
                    "driver": {
                        "name": "uv",
                        "version": UV_VERSION,
                        "semanticVersion": UV_VERSION,
                        "rules": rules,
                    }
                },
            }
        ],
    }
    installed = [
        {"name": MCP_NAME, "version": MCP_VERSION},
        {"name": ACRYL_NAME, "version": ACRYL_VERSION},
        {"name": SETUPTOOLS_NAME, "version": SETUPTOOLS_VERSION},
        *[
            {"name": f"fixture-package-{index}", "version": "1.0.0"}
            for index in range(10)
        ],
    ]
    wheel_graph_packages = [
        {
            "name": MCP_NAME,
            "version": MCP_VERSION,
            "wheels": [
                {
                    "hash": MCP_WHEEL["sha256"],
                    "size": MCP_WHEEL["size"],
                    "url": MCP_WHEEL["url"],
                }
            ],
        },
        {
            "name": ACRYL_NAME,
            "version": ACRYL_VERSION,
            "wheels": [
                {
                    "hash": ACRYL_WHEEL["sha256"],
                    "size": ACRYL_WHEEL["size"],
                    "url": ACRYL_WHEEL["url"],
                }
            ],
        },
        {
            "name": SETUPTOOLS_NAME,
            "version": SETUPTOOLS_VERSION,
            "wheels": [
                {
                    "hash": SETUPTOOLS_WHEEL["sha256"],
                    "size": SETUPTOOLS_WHEEL["size"],
                    "url": SETUPTOOLS_WHEEL["url"],
                }
            ],
        },
        *[
            {
                "name": f"fixture-package-{index}",
                "version": "1.0.0",
                "wheels": [
                    {
                        "hash": f"{index + 2:064x}",
                        "size": 1,
                        "url": (
                            "https://files.pythonhosted.org/packages/fixture/"
                            f"fixture-package-{index}.whl"
                        ),
                    }
                ],
            }
            for index in range(10)
        ],
    ]
    wheel_graph = {
        "schemaVersion": "archon.datahub-mcp-wheel-only-graph/v1",
        "packageCount": len(wheel_graph_packages),
        "packages": wheel_graph_packages,
    }
    smoke = {
        "schemaVersion": SMOKE_SCHEMA,
        "protocol": "mcp-stdio",
        "packageVersion": MCP_VERSION,
        "fastMcpVersion": "2.14.5",
        "serverInfoVersion": "2.14.5",
        "initialized": True,
        "pinged": True,
        "credentialsUsed": False,
        "networkToolCalls": 0,
        "loopbackConfigRequests": 1,
        "unexpectedHttpRequests": 0,
        "readOnlyHints": True,
        "tools": EXPECTED_TOOLS,
        "stderrBytes": 0,
        "stderrSha256": hashlib.sha256(b"").hexdigest(),
    }
    return {
        "contract": contract,
        "vex": vex,
        "sarif": sarif,
        "installed": installed,
        "wheel_graph": wheel_graph,
        "runtime_smoke": smoke,
        "audit_exit": 1,
        "input_hashes": {
            "contractSha256": digest(canonical_json_bytes(contract)),
            "openVexSha256": digest(vex_raw),
            "rawSarifSha256": digest(canonical_json_bytes(sarif)),
            "installedPackagesSha256": digest(canonical_json_bytes(installed)),
            "wheelGraphSha256": digest(canonical_json_bytes(wheel_graph)),
            "runtimeSmokeSha256": digest(canonical_json_bytes(smoke)),
        },
        "now": datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc),
        "runner_os": "Linux",
        "enforce_static_vex": False,
    }


def run_self_test() -> None:
    cases: list[dict[str, Any]] = []

    def expect_pass(name: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        fixture = build_self_test_fixture()
        mutate(fixture)
        validate_bundle(**fixture)
        cases.append({"name": name, "result": "pass"})

    def expect_rejection(name: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        fixture = build_self_test_fixture()
        mutate(fixture)
        try:
            validate_bundle(**fixture)
        except ValidationError:
            cases.append({"name": name, "result": "pass"})
            return
        fail(f"self-test canary {name!r} was incorrectly approved")

    expect_pass("exact-approved-pair", lambda fixture: None)
    expect_rejection(
        "extra-unrelated-result",
        lambda fixture: fixture["sarif"]["runs"][0]["results"].append(
            {
                **fixture_sarif_result("GHSA-h35f-9h28-mq5c"),
                "ruleId": "GHSA-unapproved",
            }
        ),
    )
    expect_rejection(
        "wrong-setuptools-version",
        lambda fixture: fixture["sarif"]["runs"][0]["results"][0]["properties"].update(
            {"uv/version": "80.9.0"}
        ),
    )
    expect_rejection(
        "wrong-mcp-wheel",
        lambda fixture: fixture["wheel_graph"]["packages"][0]["wheels"][0].update(
            {"hash": "0" * 64}
        ),
    )
    expect_rejection(
        "expired-vex",
        lambda fixture: fixture.update(
            {"now": datetime(2026, 8, 22, 11, 30, tzinfo=timezone.utc)}
        ),
    )
    expect_rejection(
        "malformed-sarif",
        lambda fixture: fixture["sarif"].update({"runs": "not-an-array"}),
    )
    expect_rejection(
        "unused-vex-empty-results",
        lambda fixture: (
            fixture["sarif"]["runs"][0].update({"results": []}),
            fixture.update({"audit_exit": 0}),
        ),
    )
    expect_rejection(
        "missing-pysec-primary",
        lambda fixture: fixture["sarif"]["runs"][0].update(
            {"results": [fixture["sarif"]["runs"][0]["results"][0]]}
        ),
    )
    expect_rejection(
        "third-alias-primary",
        lambda fixture: fixture["sarif"]["runs"][0]["results"].append(
            {
                **fixture_sarif_result("GHSA-h35f-9h28-mq5c"),
                "ruleId": "CVE-2026-59890",
                "properties": {
                    **fixture_sarif_result("GHSA-h35f-9h28-mq5c")["properties"],
                    "uv/id": "CVE-2026-59890",
                },
                "partialFingerprints": {
                    "uv/vulnerability": "CVE-2026-59890:setuptools:81.0.0"
                },
            }
        ),
    )
    expect_rejection(
        "audit-exit-zero-with-results",
        lambda fixture: fixture.update({"audit_exit": 0}),
    )
    expect_rejection(
        "audit-operational-failure",
        lambda fixture: fixture.update({"audit_exit": 2}),
    )
    expect_rejection(
        "extra-runtime-tool",
        lambda fixture: fixture["runtime_smoke"].update(
            {"tools": [*EXPECTED_TOOLS, "add_tags"]}
        ),
    )
    expect_rejection(
        "server-info-version-mismatch",
        lambda fixture: fixture["runtime_smoke"].update(
            {"serverInfoVersion": "2.14.4"}
        ),
    )
    expect_rejection(
        "wrong-loopback-config-count",
        lambda fixture: fixture["runtime_smoke"].update(
            {"loopbackConfigRequests": 0}
        ),
    )
    expect_rejection(
        "unexpected-runtime-http",
        lambda fixture: fixture["runtime_smoke"].update(
            {"unexpectedHttpRequests": 1}
        ),
    )

    print(
        json.dumps(
            {
                "schemaVersion": SELF_TEST_SCHEMA,
                "passed": True,
                "cases": cases,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Validate and apply the exact DataHub MCP OpenVEX disposition."
    )
    result.add_argument("--self-test", action="store_true")
    result.add_argument("--contract")
    result.add_argument("--vex")
    result.add_argument("--sarif")
    result.add_argument("--installed")
    result.add_argument("--wheel-graph")
    result.add_argument("--runtime-smoke")
    result.add_argument("--audit-exit", type=int)
    result.add_argument("--actionable-sarif")
    result.add_argument("--disposition-receipt")
    return result


def require_real_arguments(arguments: argparse.Namespace) -> None:
    names = [
        "contract",
        "vex",
        "sarif",
        "installed",
        "wheel_graph",
        "runtime_smoke",
        "audit_exit",
        "actionable_sarif",
        "disposition_receipt",
    ]
    missing = [name.replace("_", "-") for name in names if getattr(arguments, name) is None]
    require(not missing, f"real mode is missing arguments: {', '.join(missing)}")


def run_real(arguments: argparse.Namespace) -> None:
    require_real_arguments(arguments)
    actionable_path = Path(arguments.actionable_sarif)
    receipt_path = Path(arguments.disposition_receipt)
    require(
        actionable_path.resolve(strict=False) != receipt_path.resolve(strict=False),
        "actionable SARIF and receipt outputs must differ",
    )

    raw_sarif_bytes = read_regular_file(arguments.sarif, "raw SARIF")
    atomic_write(actionable_path, raw_sarif_bytes)
    hashes = {"rawSarifSha256": digest(raw_sarif_bytes)}
    atomic_write(
        receipt_path,
        canonical_json_bytes(rejected_receipt("validation incomplete", hashes)),
    )

    try:
        require(
            os.environ.get("CI") == "true"
            and os.environ.get("GITHUB_ACTIONS") == "true",
            "real disposition mode is restricted to GitHub Actions CI",
        )
        require(platform.system() == "Linux", "real disposition mode is Linux-only")

        raw_inputs = {
            "contract": read_regular_file(arguments.contract, "contract"),
            "vex": read_regular_file(arguments.vex, "OpenVEX"),
            "sarif": raw_sarif_bytes,
            "installed": read_regular_file(arguments.installed, "installed inventory"),
            "wheel_graph": read_regular_file(arguments.wheel_graph, "wheel graph"),
            "runtime_smoke": read_regular_file(
                arguments.runtime_smoke, "runtime smoke"
            ),
        }
        hashes = {
            "contractSha256": digest(raw_inputs["contract"]),
            "openVexSha256": digest(raw_inputs["vex"]),
            "rawSarifSha256": digest(raw_inputs["sarif"]),
            "installedPackagesSha256": digest(raw_inputs["installed"]),
            "wheelGraphSha256": digest(raw_inputs["wheel_graph"]),
            "runtimeSmokeSha256": digest(raw_inputs["runtime_smoke"]),
        }
        parsed = {
            label: parse_json_bytes(raw, label)
            for label, raw in raw_inputs.items()
        }
        for label in ("contract", "vex", "sarif", "wheel_graph", "runtime_smoke"):
            parsed[label] = require_dict(parsed[label], label)

        actionable, disposition = validate_bundle(
            contract=parsed["contract"],
            vex=parsed["vex"],
            sarif=parsed["sarif"],
            installed=parsed["installed"],
            wheel_graph=parsed["wheel_graph"],
            runtime_smoke=parsed["runtime_smoke"],
            audit_exit=arguments.audit_exit,
            input_hashes=hashes,
            now=datetime.now(timezone.utc),
            runner_os=platform.system(),
            enforce_static_vex=True,
        )
        actionable_bytes = canonical_json_bytes(actionable)
        require(
            disposition["hashes"]["actionableSarifSha256"]
            == digest(actionable_bytes),
            "actionable SARIF digest binding failed",
        )
        atomic_write(receipt_path, canonical_json_bytes(disposition))
        atomic_write(actionable_path, actionable_bytes)
    except (OSError, ValidationError, ValueError) as exc:
        try:
            atomic_write(
                receipt_path,
                canonical_json_bytes(rejected_receipt(str(exc), hashes)),
            )
        except OSError:
            pass
        raise ValidationError(str(exc)) from exc


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.self_test:
            supplied_real = any(
                getattr(arguments, name) is not None
                for name in (
                    "contract",
                    "vex",
                    "sarif",
                    "installed",
                    "wheel_graph",
                    "runtime_smoke",
                    "audit_exit",
                    "actionable_sarif",
                    "disposition_receipt",
                )
            )
            require(not supplied_real, "--self-test cannot be combined with real inputs")
            run_self_test()
        else:
            run_real(arguments)
    except ValidationError as exc:
        print(f"DataHub MCP audit disposition rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
