#!/usr/bin/env python3
"""Fail-closed CI verifier for the complete official DataHub agent stack."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import urllib.parse
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

SCHEMA = "archon.datahub-agent-stack-lock/v1"
SHA256 = re.compile(r"^[a-f0-9]{64}$")
GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
ALLOWED_DOWNLOAD_HOSTS = {
    "api.github.com",
    "raw.githubusercontent.com",
    "files.pythonhosted.org",
}


def regular_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        stat = os.fstat(descriptor)
        if not stat.st_mode & 0o100000:
            raise AssertionError(f"{path} must be a regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(data: bytes) -> str:
    payload = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def expect_artifact(value: dict[str, Any], suffix: str) -> None:
    assert set(value) == {"filename", "url", "size", "sha256"}
    assert value["filename"].endswith(suffix)
    parsed = urllib.parse.urlparse(value["url"])
    assert parsed.scheme == "https"
    assert parsed.hostname == "files.pythonhosted.org"
    assert isinstance(value["size"], int) and 1 <= value["size"] <= 10_000_000
    assert SHA256.fullmatch(value["sha256"])


def request_bytes(url: str, token: str | None = None) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise AssertionError(f"unreviewed download origin: {parsed.hostname}")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "archon-datahub-agent-stack-verifier/1.0",
    }
    if token and parsed.hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        final = urllib.parse.urlparse(response.geturl())
        if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
            raise AssertionError(f"download redirected to unreviewed origin: {final.hostname}")
        data = response.read(12_000_001)
    if len(data) > 12_000_000:
        raise AssertionError("download exceeded the reviewed in-memory ceiling")
    return data


def verify_download(value: dict[str, Any]) -> bytes:
    data = request_bytes(value["url"])
    assert len(data) == value["size"], value["filename"]
    assert sha256(data) == value["sha256"], value["filename"]
    return data


def github_json(path: str, token: str | None) -> dict[str, Any]:
    raw = request_bytes(f"https://api.github.com/{path}", token)
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    return parsed


def verify_source(
    source: dict[str, Any],
    owner_repo: str,
    token: str | None,
    *,
    package_path: str | None = None,
) -> None:
    assert GIT_SHA.fullmatch(source["commit"])
    assert GIT_SHA.fullmatch(source["tree"])
    commit = github_json(
        f"repos/{owner_repo}/commits/{source['commit']}",
        token,
    )
    assert commit["sha"] == source["commit"]
    assert commit["commit"]["tree"]["sha"] == source["tree"]
    assert commit["commit"]["verification"]["verified"] is True
    assert source["githubCommitSignatureVerified"] is True
    if "tag" in source:
        ref = github_json(
            f"repos/{owner_repo}/git/ref/tags/{source['tag']}",
            token,
        )
        assert ref["object"]["sha"] == source["commit"]
    if package_path is not None:
        tree = github_json(
            f"repos/{owner_repo}/git/trees/{source['tree']}",
            token,
        )
        package = next(
            entry for entry in tree["tree"] if entry["path"] == package_path
        )
        assert package["type"] == "tree"
        assert package["sha"] == source["packageTree"]


def raw_source(
    owner_repo: str,
    commit: str,
    path: str,
) -> bytes:
    quoted = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    return request_bytes(
        f"https://raw.githubusercontent.com/{owner_repo}/{commit}/{quoted}"
    )


def verify_source_files(
    files: dict[str, Any],
    owner_repo: str,
    commit: str,
    wheel: zipfile.ZipFile | None = None,
) -> None:
    for path, expected in files.items():
        assert set(expected).issubset({"gitBlob", "size", "sha256", "wheelPath"})
        assert GIT_SHA.fullmatch(expected["gitBlob"])
        assert isinstance(expected["size"], int) and expected["size"] > 0
        data = raw_source(owner_repo, commit, path)
        assert len(data) == expected["size"], path
        assert git_blob(data) == expected["gitBlob"], path
        if "sha256" in expected:
            assert SHA256.fullmatch(expected["sha256"])
            assert sha256(data) == expected["sha256"], path
        if "wheelPath" in expected:
            assert wheel is not None
            assert wheel.read(expected["wheelPath"]) == data, path


def wheel_metadata(
    archive: zipfile.ZipFile,
    distribution: str,
    version: str,
) -> Any:
    matches = [
        name
        for name in archive.namelist()
        if name.endswith(".dist-info/METADATA")
    ]
    assert len(matches) == 1
    metadata = BytesParser().parsebytes(archive.read(matches[0]))
    assert metadata["Name"] == distribution
    assert metadata["Version"] == version
    assert "Apache" in (metadata["License"] or "")
    return metadata


def verify_static(lock: dict[str, Any], workspace: Path) -> None:
    assert lock["schemaVersion"] == SCHEMA
    assert set(lock["components"]) == {
        "mcpServer",
        "agentContextKit",
        "dataHubSkills",
        "analyticsAgent",
    }
    assert lock["runtime"] == {
        "pythonVersion": "3.11.15",
        "uvVersion": "0.11.31",
        "sourceBuilds": "deny",
        "platform": "linux-x86_64",
        "excludeNewer": "2026-08-02T00:00:00Z",
    }

    mcp = lock["components"]["mcpServer"]
    delegated = mcp["delegatedLock"]
    delegated_path = workspace / delegated["path"]
    delegated_bytes = regular_bytes(delegated_path)
    assert len(delegated_bytes) == delegated["size"]
    assert sha256(delegated_bytes) == delegated["sha256"]
    delegated_lock = json.loads(delegated_bytes)
    assert delegated_lock["package"]["name"] == "mcp-server-datahub"
    assert delegated_lock["package"]["version"] == "0.6.0"

    ack = lock["components"]["agentContextKit"]
    assert ack["requirement"] == "datahub-agent-context[langchain]==1.6.0.17"
    assert ack["compatibility"]["acrylDatahubRequirement"] == (
        "acryl-datahub[datahub-rest]==1.6.0.6"
    )
    expect_artifact(ack["wheel"], ".whl")
    expect_artifact(ack["sdist"], ".tar.gz")
    assert ack["pypiProvenance"]["trustedPublisherAttestation"] is False

    analytics = lock["components"]["analyticsAgent"]
    assert analytics["requirement"] == "datahub-analytics-agent==0.4.0"
    expect_artifact(analytics["wheel"], ".whl")
    assert analytics["pypiProvenance"]["trustedPublisherAttestation"] is False

    skills = lock["components"]["dataHubSkills"]
    assert skills["source"]["tag"] == "v1.4.1"
    assert set(skills["files"]) == {
        "LICENSE",
        "skills/datahub-search/SKILL.md",
        "skills/datahub-lineage/SKILL.md",
        "skills/datahub-quality/SKILL.md",
        "skills/datahub-enrich/SKILL.md",
        "skills/using-datahub/SKILL.md",
    }

    assert lock["executionPolicy"] == {
        "requiredForReady": [
            "mcpServer",
            "agentContextKit",
            "dataHubSkills",
            "analyticsAgent",
        ],
        "skillWorkflow": [
            "datahub-search",
            "datahub-lineage",
            "datahub-quality",
            "datahub-audit",
            "datahub-enrich",
        ],
        "agentContextKitIncludeMutations": False,
        "analyticsAgentMutationToolsEnabled": False,
        "writeAuthority": "archon-remediation-worker",
        "writeRequiresFreshDigestBoundHumanApproval": True,
        "runtimeProfiles": ["cloud", "core"],
        "runtimeBindingImmutableAfterStart": True,
        "silentMutationFailover": False,
    }


def verify_network(lock: dict[str, Any]) -> None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    ack = lock["components"]["agentContextKit"]
    analytics = lock["components"]["analyticsAgent"]
    skills = lock["components"]["dataHubSkills"]

    verify_source(
        ack["source"],
        "datahub-project/datahub",
        token,
        package_path="datahub-agent-context",
    )
    verify_source(
        analytics["source"],
        "datahub-project/analytics-agent",
        token,
    )
    verify_source(
        skills["source"],
        "datahub-project/datahub-skills",
        token,
    )

    ack_wheel_bytes = verify_download(ack["wheel"])
    ack_sdist_bytes = verify_download(ack["sdist"])
    with zipfile.ZipFile(io.BytesIO(ack_wheel_bytes)) as wheel:
        metadata = wheel_metadata(
            wheel,
            "datahub-agent-context",
            ack["version"],
        )
        requirements = metadata.get_all("Requires-Dist") or []
        assert any(
            requirement.startswith("acryl-datahub[datahub-rest]==1.6.0.6")
            for requirement in requirements
        )
        verify_source_files(
            ack["files"],
            "datahub-project/datahub",
            ack["source"]["commit"],
            wheel,
        )
        with tarfile.open(fileobj=io.BytesIO(ack_sdist_bytes), mode="r:gz") as sdist:
            members = {member.name: member for member in sdist.getmembers()}
            prefix = f"datahub_agent_context-{ack['version']}/"
            for source_path, expected in ack["files"].items():
                wheel_path = expected.get("wheelPath")
                if wheel_path is None:
                    continue
                source_relative = source_path.removeprefix(
                    "datahub-agent-context/"
                )
                member = members[prefix + source_relative]
                stream = sdist.extractfile(member)
                assert stream is not None
                assert stream.read() == wheel.read(wheel_path)

    analytics_wheel_bytes = verify_download(analytics["wheel"])
    with zipfile.ZipFile(io.BytesIO(analytics_wheel_bytes)) as wheel:
        metadata = wheel_metadata(
            wheel,
            "datahub-analytics-agent",
            analytics["version"],
        )
        requirements = metadata.get_all("Requires-Dist") or []
        assert any(
            requirement.startswith("datahub-agent-context[langchain]>=1.5.0")
            for requirement in requirements
        )
        assert any(
            requirement.startswith("langchain-aws>=1.4.0")
            for requirement in requirements
        )
        verify_source_files(
            analytics["files"],
            "datahub-project/analytics-agent",
            analytics["source"]["commit"],
            wheel,
        )

    verify_source_files(
        skills["files"],
        "datahub-project/datahub-skills",
        skills["source"]["commit"],
    )
    for path in skills["files"]:
        if not path.endswith("/SKILL.md"):
            continue
        body = raw_source(
            "datahub-project/datahub-skills",
            skills["source"]["commit"],
            path,
        ).decode("utf-8")
        assert body.startswith("---\n")
        assert "\nname:" in body[:1000]
        assert "\ndescription:" in body[:2000]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", action="store_true")
    args = parser.parse_args()
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("DataHub agent stack verification is CI/CD-only")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    lock_path = workspace / ".github/locks/datahub-agent-stack.json"
    lock = json.loads(regular_bytes(lock_path))
    verify_static(lock, workspace)
    if args.network:
        verify_network(lock)
    print(
        json.dumps(
            {
                "schemaVersion": "archon.datahub-agent-stack-verification/v1",
                "decision": "approved",
                "networkVerified": args.network,
                "components": list(lock["components"]),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
