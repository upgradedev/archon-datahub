#!/usr/bin/env python3
"""Fail-closed CI evaluator for the exact DataHub agent stack OpenVEX statement."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

EXPECTED_RULES = {
    "GHSA-h35f-9h28-mq5c",
    "PYSEC-2026-3447",
}
EXPECTED_CVE = "CVE-2026-59890"
EXPECTED_PACKAGE = "setuptools"
EXPECTED_VERSION = "81.0.0"
EXPECTED_PURL = "pkg:pypi/setuptools@81.0.0"
EXPECTED_PRODUCT = (
    "pkg:github/upgradedev/archon-datahub?path=services/datahub-companion"
)
EXPECTED_VEX_ID = (
    "https://github.com/upgradedev/archon-datahub/security/vex/"
    "setuptools-cve-2026-59890/v1"
)


def regular_bytes(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AssertionError(f"{path} must be a regular file")
        if metadata.st_size > maximum:
            raise AssertionError(f"{path} exceeds the reviewed size ceiling")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return stream.read(maximum + 1)
    finally:
        os.close(descriptor)


def parse_time(value: str) -> datetime:
    assert isinstance(value, str) and value.endswith("Z")
    parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    assert parsed.tzinfo == timezone.utc
    return parsed


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise AssertionError(f"{label} must remain below {root}") from error
    return resolved


def write_json_output(
    path: Path,
    runner_temp: Path,
    payload: dict[str, Any],
) -> None:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(runner_temp)
    except ValueError as error:
        raise AssertionError("CI output must remain below RUNNER_TEMP") from error
    if resolved.parent != runner_temp:
        raise AssertionError("CI output must be directly below RUNNER_TEMP")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags, 0o600)
    try:
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


def validate_environment(workspace: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    lock = json.loads(
        regular_bytes(
            workspace / ".github/locks/datahub-agent-stack.json",
            1_048_576,
        )
    )
    assert lock["runtime"]["platform"] == "linux-x86_64"
    assert lock["runtime"]["sourceBuilds"] == "deny"

    project = tomllib.loads(
        regular_bytes(
            workspace / "services/datahub-companion/pyproject.toml",
            131_072,
        ).decode("utf-8")
    )
    assert project["tool"]["uv"]["constraint-dependencies"] == [
        "setuptools==81.0.0"
    ]

    frozen = tomllib.loads(
        regular_bytes(
            workspace / "services/datahub-companion/uv.lock",
            2_097_152,
        ).decode("utf-8")
    )
    setuptools = [
        package
        for package in frozen["package"]
        if package["name"] == EXPECTED_PACKAGE
    ]
    assert len(setuptools) == 1
    assert setuptools[0]["version"] == EXPECTED_VERSION
    assert "sdist" in setuptools[0] and "wheels" in setuptools[0]

    workflow = regular_bytes(
        workspace / ".github/workflows/datahub-agent-stack.yml",
        262_144,
    ).decode("utf-8")
    normalized = " ".join(workflow.split())
    assert "runs-on: ubuntu-24.04" in workflow
    assert (
        "uv sync --project services/datahub-companion --python 3.11.15 "
        "--frozen --no-dev --no-build"
    ) in normalized
    assert 'UV_PYTHON_DOWNLOADS: "manual"' in workflow

    main_ci = regular_bytes(
        workspace / ".github/workflows/ci.yml",
        524_288,
    ).decode("utf-8")
    expected_allowlist = (
        "allow-ghsas: GHSA-mh99-v99m-4gvg, GHSA-h35f-9h28-mq5c"
    )
    assert expected_allowlist in main_ci
    assert main_ci.count("allow-ghsas:") == 1
    return lock, frozen


def validate_vex(vex: dict[str, Any]) -> tuple[dict[str, Any], datetime]:
    assert set(vex) == {
        "@context",
        "@id",
        "author",
        "role",
        "timestamp",
        "last_updated",
        "version",
        "x-archon-expires-at",
        "statements",
    }
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert vex["@id"] == EXPECTED_VEX_ID
    assert vex["author"] == "https://github.com/upgradedev/archon-datahub"
    assert vex["role"] == "Document Creator"
    assert vex["version"] == 1
    assert vex["timestamp"] == vex["last_updated"]

    issued = parse_time(vex["timestamp"])
    expires = parse_time(vex["x-archon-expires-at"])
    now = datetime.now(timezone.utc)
    assert issued <= now < expires
    assert timedelta(0) < expires - issued <= timedelta(days=32)

    assert isinstance(vex["statements"], list) and len(vex["statements"]) == 1
    statement = vex["statements"][0]
    assert set(statement) == {
        "vulnerability",
        "products",
        "status",
        "justification",
        "impact_statement",
    }
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    impact = statement["impact_statement"]
    for required in (
        "MANIFEST.in",
        "macOS APFS/HFS+",
        "Linux",
        "prebuilt wheels",
        "source builds denied",
        "uv sync --no-build",
    ):
        assert required in impact

    vulnerability = statement["vulnerability"]
    assert vulnerability == {
        "@id": "https://github.com/advisories/GHSA-h35f-9h28-mq5c",
        "name": EXPECTED_CVE,
        "aliases": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-59890",
            "https://osv.dev/vulnerability/PYSEC-2026-3447",
        ],
    }
    assert statement["products"] == [
        {
            "@id": EXPECTED_PRODUCT,
            "subcomponents": [{"@id": EXPECTED_PURL}],
        }
    ]
    return statement, expires


def validate_sarif(sarif: dict[str, Any]) -> tuple[str, list[str]]:
    assert sarif["version"] == "2.1.0"
    assert isinstance(sarif["runs"], list) and sarif["runs"]
    results = [
        result
        for run in sarif["runs"]
        for result in (run.get("results") or [])
    ]
    if not results:
        return "approved-no-findings", []

    assert 1 <= len(results) <= len(EXPECTED_RULES)
    seen: set[str] = set()
    for result in results:
        rule_id = result["ruleId"]
        assert rule_id in EXPECTED_RULES
        assert rule_id not in seen
        seen.add(rule_id)
        assert result["kind"] == "fail"
        assert result["level"] == "error"
        properties = result["properties"]
        assert properties["uv/package"] == EXPECTED_PACKAGE
        assert properties["uv/version"] == EXPECTED_VERSION
        assert properties["uv/id"] == rule_id
        aliases = set(properties["uv/aliases"])
        assert EXPECTED_CVE in aliases
        assert (EXPECTED_RULES - {rule_id}) <= aliases
        location = result["locations"][0]["logicalLocations"][0]
        assert location["fullyQualifiedName"] == "setuptools@81.0.0"
        assert location["kind"] == "package"
    return "approved-by-exact-openvex", sorted(seen)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--vex", required=True)
    parser.add_argument("--decision", required=True)
    parser.add_argument("--projection", required=True)
    args = parser.parse_args()

    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("OpenVEX evaluation is CI/CD-only")

    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    try:
        runner_temp.relative_to(workspace)
    except ValueError:
        pass
    else:
        raise AssertionError("RUNNER_TEMP must be outside the repository")

    validate_environment(workspace)
    sarif_path = require_under(Path(args.sarif), runner_temp, "SARIF")
    vex_path = require_under(Path(args.vex), workspace, "OpenVEX")
    sarif = json.loads(regular_bytes(sarif_path, 8_388_608))
    vex = json.loads(regular_bytes(vex_path, 262_144))
    _, expires = validate_vex(vex)
    disposition, rules = validate_sarif(sarif)

    projection = json.loads(json.dumps(sarif))
    if rules:
        for run in projection["runs"]:
            run["results"] = []
            properties = run.setdefault("properties", {})
            properties["archon/vexDecision"] = "not_affected"
            properties["archon/vexId"] = EXPECTED_VEX_ID
            properties["archon/vexExpiresAt"] = (
                expires.isoformat().replace("+00:00", "Z")
            )
            properties["archon/rawSarifRetained"] = True

    decision = {
        "schemaVersion": "archon.datahub-agent-stack-audit-decision/v1",
        "decision": disposition,
        "advisoryIds": rules,
        "cve": EXPECTED_CVE if rules else None,
        "component": EXPECTED_PURL if rules else None,
        "environment": {
            "platform": "linux-x86_64",
            "sourceBuilds": "deny",
            "installation": "uv-sync-frozen-no-build",
        },
        "vexId": EXPECTED_VEX_ID if rules else None,
        "vexExpiresAt": expires.isoformat().replace("+00:00", "Z"),
    }
    write_json_output(Path(args.projection), runner_temp, projection)
    write_json_output(Path(args.decision), runner_temp, decision)
    print(json.dumps(decision, sort_keys=True))


if __name__ == "__main__":
    main()
