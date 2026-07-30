#!/usr/bin/env python3
"""Collect fail-closed BONUS-OSS facts from CI and public upstream state."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


REPOSITORY = "upgradedev/archon-datahub"
UPSTREAM_REPOSITORY = "acryldata/mcp-server-datahub"
UPSTREAM_REPOSITORY_URL = "https://github.com/acryldata/mcp-server-datahub"
UPSTREAM_GIT_URL = f"{UPSTREAM_REPOSITORY_URL}.git"
UPSTREAM_BRANCH = "main"
UPSTREAM_LICENSE = "Apache-2.0"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
CI_PREDICATE_TYPE = (
    "https://github.com/upgradedev/archon-datahub/attestations/ci-release/v1"
)
CI_PREDICATE_SCHEMA = "archon.ci-release/v1"
RECEIPT_SCHEMA = "archon.oss-validation-receipt/v1"
CANDIDATE_SCHEMA = "archon.oss-candidate-binding/v1"
SUBMISSION_START = dt.datetime(2026, 7, 6, 13, 0, 0, tzinfo=dt.timezone.utc)
SUBMISSION_DEADLINE = dt.datetime(2026, 8, 10, 21, 0, 0, tzinfo=dt.timezone.utc)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
BARE_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_PATHS = (
    "src/mcp_server_datahub/mcp_server.py",
    "src/mcp_server_datahub/tools/__init__.py",
    "src/mcp_server_datahub/tools/aspect_history.py",
    "tests/test_mcp/test_get_aspect_history.py",
)
EXPECTED_FILE_STATUS = {
    "src/mcp_server_datahub/mcp_server.py": "modified",
    "src/mcp_server_datahub/tools/__init__.py": "modified",
    "src/mcp_server_datahub/tools/aspect_history.py": "added",
    "tests/test_mcp/test_get_aspect_history.py": "added",
}
STAGED_SOURCE_BY_DESTINATION = {
    "src/mcp_server_datahub/tools/aspect_history.py": (
        "contrib/mcp-get-aspect-history/upstream/"
        "src/mcp_server_datahub/tools/aspect_history.py"
    ),
    "tests/test_mcp/test_get_aspect_history.py": (
        "contrib/mcp-get-aspect-history/upstream/"
        "tests/test_mcp/test_get_aspect_history.py"
    ),
}
RECEIPT_FILES = {
    "SHA256SUMS",
    "applied.diff",
    "manifest.json",
    "receipt.json",
}
LAMBDA_FILES = {
    "archon-lambdas.tar.gz",
    "archon-lambdas.tar.gz.sha256",
}
CI_GATE_KEYS = {
    "buildTest",
    "container",
    "contribution",
    "dataHubBenchmark",
    "dataHubMcpDependency",
    "infrastructure",
    "judgeEvidence",
    "load",
    "readiness",
    "secretScan",
    "security",
    "web",
}
CI_CAPABILITY_KEYS = {
    "dataHubBenchmarkArtifactDigest",
    "judgeEvidenceArtifactDigest",
    "ossContributionValidationArtifactDigest",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(value: bytes, *, prefixed: bool = True) -> str:
    digest = hashlib.sha256(value).hexdigest()
    return f"sha256:{digest}" if prefixed else digest


def sha256_file(path: Path, *, prefixed: bool = True) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    value = digest.hexdigest()
    return f"sha256:{value}" if prefixed else value


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def parse_json_bytes(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{label} is not strict UTF-8: {error}")
    try:
        return json.loads(
            text,
            object_pairs_hook=no_duplicate_object,
            parse_constant=lambda value: fail(
                f"{label} contains invalid JSON constant {value}"
            ),
        )
    except json.JSONDecodeError as error:
        fail(f"{label} is not valid JSON: {error}")


def read_json(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file")
    return parse_json_bytes(path.read_bytes(), label)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected, f"{label} fields are not exact")
    return value


def positive_int(value: Any, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value > 0,
        f"{label} must be a positive integer",
    )
    return value


def require_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA_RE.fullmatch(value) is not None, f"{label} is invalid")
    return value


def require_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None,
        f"{label} is invalid",
    )
    return value


def parse_utc(value: Any, label: str) -> dt.datetime:
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value)
        is not None,
        f"{label} must be canonical UTC RFC3339",
    )
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        fail(f"{label} is invalid: {error}")


def write_json(path: Path, value: Any) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to overwrite {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            f"redirect rejected: {newurl}",
            headers,
            fp,
        )


class GitHubApi:
    def __init__(self, *, token: str | None) -> None:
        self.token = token
        self.opener = urllib.request.build_opener(RejectRedirects())

    def get(
        self,
        url: str,
        *,
        accept: str = "application/vnd.github+json",
        maximum_bytes: int = 16 * 1024 * 1024,
    ) -> tuple[bytes, dict[str, str]]:
        parsed = urllib.parse.urlparse(url)
        require(
            parsed.scheme == "https"
            and parsed.hostname == "api.github.com"
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None,
            "GitHub API URL escaped the exact HTTPS API origin",
        )
        headers = {
            "Accept": accept,
            "User-Agent": "archon-datahub-bonus-oss-evidence/1",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(url, headers=headers, method="GET")
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with self.opener.open(request, timeout=30) as response:
                    require(response.status == 200, f"GitHub API returned {response.status}")
                    content_length = response.headers.get("Content-Length")
                    if content_length is not None:
                        require(
                            content_length.isdigit()
                            and int(content_length) <= maximum_bytes,
                            "GitHub API response exceeds its byte limit",
                        )
                    raw = response.read(maximum_bytes + 1)
                    require(
                        len(raw) <= maximum_bytes,
                        "GitHub API response exceeds its byte limit",
                    )
                    return raw, {key.lower(): value for key, value in response.headers.items()}
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in {403, 429, 500, 502, 503, 504}:
                    break
            except (TimeoutError, urllib.error.URLError) as error:
                last_error = error
            if attempt < 2:
                time.sleep(2**attempt)
        fail(f"GitHub API request failed: {last_error}")

    def json(self, path_or_url: str, *, maximum_bytes: int = 16 * 1024 * 1024) -> Any:
        url = (
            path_or_url
            if path_or_url.startswith("https://")
            else f"https://api.github.com{path_or_url}"
        )
        raw, _ = self.get(url, maximum_bytes=maximum_bytes)
        return parse_json_bytes(raw, f"GitHub API {url}")

    def pages(self, path: str, *, maximum_pages: int = 10) -> list[Any]:
        separator = "&" if "?" in path else "?"
        next_url = f"https://api.github.com{path}{separator}per_page=100"
        pages: list[Any] = []
        for _ in range(maximum_pages):
            raw, headers = self.get(next_url)
            pages.append(parse_json_bytes(raw, f"GitHub API {next_url}"))
            next_url = parse_next_link(headers.get("link"))
            if next_url is None:
                return pages
        fail("GitHub API pagination exceeded its page limit")


def parse_next_link(value: str | None) -> str | None:
    if value is None:
        return None
    next_urls = []
    for item in value.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([^"]+)"\s*', item)
        require(match is not None, "GitHub pagination Link header is malformed")
        if match.group(2) == "next":
            next_urls.append(match.group(1))
    require(len(next_urls) <= 1, "GitHub pagination has ambiguous next links")
    return next_urls[0] if next_urls else None


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    credentialless: bool = False,
    maximum_stdout: int = 32 * 1024 * 1024,
) -> bytes:
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    if credentialless:
        for key in tuple(environment):
            if key in {
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_ASKPASS",
                "GIT_CEILING_DIRECTORIES",
                "GIT_COMMON_DIR",
                "GIT_CONFIG_PARAMETERS",
                "GIT_CURL_VERBOSE",
                "GIT_DIR",
                "GIT_EXEC_PATH",
                "GIT_EXTERNAL_DIFF",
                "GIT_GRAFT_FILE",
                "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_PAGER",
                "GIT_REPLACE_REF_BASE",
                "GIT_SSH",
                "GIT_SSH_COMMAND",
                "GIT_SSH_VARIANT",
                "GIT_TEMPLATE_DIR",
                "GIT_WORK_TREE",
                "SSH_ASKPASS",
                "SSH_AUTH_SOCK",
            } or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                environment.pop(key, None)
        environment.pop("GIT_CONFIG_COUNT", None)
        environment["GIT_CONFIG_GLOBAL"] = os.devnull
        environment["GIT_CONFIG_NOSYSTEM"] = "1"
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        result.returncode == 0,
        (
            f"command failed ({' '.join(command)}): "
            f"{result.stderr.decode('utf-8', errors='replace')[:4096]}"
        ),
    )
    require(len(result.stdout) <= maximum_stdout, "command output exceeds its byte limit")
    return result.stdout


def public_git(repository: Path, *arguments: str, maximum_stdout: int = 32 * 1024 * 1024) -> bytes:
    return run_command(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "http.extraHeader=",
            "-c",
            "http.https://github.com/.extraHeader=",
            "-c",
            "http.followRedirects=false",
            *arguments,
        ],
        cwd=repository,
        credentialless=True,
        maximum_stdout=maximum_stdout,
    )


def download_artifact(
    artifact_id: int,
    expected_digest: str,
    output: Path,
    *,
    maximum_bytes: int,
) -> None:
    require(not output.exists() and not output.is_symlink(), "artifact archive already exists")
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "GH_TOKEN is required for the source repository artifact API")
    with output.open("xb") as target:
        result = subprocess.run(
            [
                "gh",
                "api",
                "-H",
                "Accept: application/vnd.github+json",
                "-H",
                "X-GitHub-Api-Version: 2026-03-10",
                f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip",
            ],
            env={**os.environ, "GH_TOKEN": token},
            stdin=subprocess.DEVNULL,
            stdout=target,
            stderr=subprocess.PIPE,
            check=False,
        )
    require(
        result.returncode == 0,
        f"artifact download failed: {result.stderr.decode('utf-8', errors='replace')[:4096]}",
    )
    require(
        output.is_file()
        and not output.is_symlink()
        and 0 < output.stat().st_size <= maximum_bytes,
        "artifact archive size is invalid",
    )
    require(
        sha256_file(output) == expected_digest,
        "artifact archive bytes do not match the Actions API digest",
    )


def safe_extract_zip(
    archive: Path,
    output: Path,
    *,
    expected_files: set[str],
    maximum_total: int,
) -> None:
    require(not output.exists() and not output.is_symlink(), "ZIP output already exists")
    output.mkdir(mode=0o700)
    allowed_directories = {
        str(parent)
        for name in expected_files
        for parent in PurePosixPath(name).parents
        if str(parent) != "."
    }
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    total = 0
    try:
        bundle = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"artifact is not a valid ZIP: {error}")
    with bundle:
        entries = bundle.infolist()
        require(0 < len(entries) <= 64, "ZIP entry count is unsafe")
        for entry in entries:
            raw = entry.filename
            require(
                bool(raw)
                and not raw.startswith("/")
                and "\\" not in raw
                and "\x00" not in raw,
                f"unsafe ZIP path {raw!r}",
            )
            directory = entry.is_dir()
            canonical = str(PurePosixPath(raw.rstrip("/")))
            required_raw = f"{canonical}/" if directory else canonical
            require(
                canonical not in {"", ".", ".."}
                and raw == required_raw
                and not canonical.startswith("../"),
                f"non-canonical ZIP path {raw!r}",
            )
            mode_type = stat.S_IFMT(entry.external_attr >> 16)
            if directory:
                require(
                    canonical in allowed_directories
                    and canonical not in seen_directories
                    and mode_type in {0, stat.S_IFDIR},
                    f"unsafe ZIP directory {raw!r}",
                )
                seen_directories.add(canonical)
                continue
            require(
                canonical in expected_files
                and canonical not in seen_files
                and mode_type in {0, stat.S_IFREG}
                and not entry.flag_bits & 0x1
                and 0 < entry.file_size <= maximum_total,
                f"unsafe ZIP entry {raw!r}",
            )
            total += entry.file_size
            require(total <= maximum_total, "ZIP expands beyond its total byte limit")
            destination = output / canonical
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with bundle.open(entry) as source, destination.open("xb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            require(
                destination.stat().st_size == entry.file_size
                and destination.is_file()
                and not destination.is_symlink(),
                f"ZIP entry extraction failed for {canonical}",
            )
            seen_files.add(canonical)
    require(seen_files == expected_files, "ZIP file inventory is not exact")


def flatten_pages(pages: list[Any], key: str) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for page in pages:
        require(isinstance(page, dict) and isinstance(page.get(key), list), f"{key} page is invalid")
        for value in page[key]:
            require(isinstance(value, dict), f"{key} entry is invalid")
            values.append(value)
    return values


def resolve_ci(
    api: GitHubApi,
    *,
    release: str,
    ci_run_id: int,
) -> dict[str, Any]:
    run = api.json(f"/repos/{REPOSITORY}/actions/runs/{ci_run_id}")
    require(isinstance(run, dict), "CI run response is invalid")
    require(
        run.get("id") == ci_run_id
        and run.get("path") == CI_WORKFLOW_PATH
        and run.get("event") == "push"
        and run.get("head_sha") == release
        and run.get("head_branch") == "master"
        and isinstance(run.get("head_repository"), dict)
        and run["head_repository"].get("full_name") == REPOSITORY
        and isinstance(run.get("repository"), dict)
        and run["repository"].get("full_name") == REPOSITORY
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "CI run is not the exact successful current-release push",
    )
    current_attempt = positive_int(run.get("run_attempt"), "CI run attempt")
    require(current_attempt <= 20, "CI run attempt exceeds the bounded history")

    latest_runs = flatten_pages(
        api.pages(
            f"/repos/{REPOSITORY}/actions/workflows/ci.yml/runs"
            "?branch=master&event=push"
        ),
        "workflow_runs",
    )
    eligible_runs = [
        value
        for value in latest_runs
        if value.get("path") == CI_WORKFLOW_PATH
        and value.get("event") == "push"
        and value.get("head_sha") == release
        and value.get("head_branch") == "master"
        and isinstance(value.get("head_repository"), dict)
        and value["head_repository"].get("full_name") == REPOSITORY
        and value.get("status") == "completed"
        and value.get("conclusion") == "success"
    ]
    require(bool(eligible_runs), "no successful current-release CI run exists")
    latest = max(
        eligible_runs,
        key=lambda value: (
            positive_int(value.get("id"), "CI run ID"),
            positive_int(value.get("run_attempt"), "CI run attempt"),
        ),
    )
    require(latest.get("id") == ci_run_id, "CI run is not the latest successful release run")

    jobs: list[dict[str, Any]] = []
    for attempt in range(1, current_attempt + 1):
        attempt_jobs = flatten_pages(
            api.pages(
                f"/repos/{REPOSITORY}/actions/runs/{ci_run_id}"
                f"/attempts/{attempt}/jobs"
            ),
            "jobs",
        )
        jobs.extend({**job, "observedRunAttempt": attempt} for job in attempt_jobs)

    def successful_job(name: str, *, current: bool) -> dict[str, Any]:
        eligible = [
            job
            for job in jobs
            if job.get("name") == name
            and job.get("status") == "completed"
            and job.get("conclusion") == "success"
            and isinstance(job.get("started_at"), str)
            and isinstance(job.get("completed_at"), str)
            and (
                job["observedRunAttempt"] == current_attempt
                if current
                else job["observedRunAttempt"] <= current_attempt
            )
        ]
        require(bool(eligible), f"missing successful CI job {name}")
        selected_attempt = (
            current_attempt
            if current
            else max(job["observedRunAttempt"] for job in eligible)
        )
        selected = [
            job
            for job in eligible
            if job["observedRunAttempt"] == selected_attempt
        ]
        require(len(selected) == 1, f"CI job {name} is ambiguous")
        return selected[0]

    contribution_job = successful_job("DataHub ecosystem contribution", current=False)
    lambda_job = successful_job("AWS CDK build, test, synth, IaC gate", current=False)
    attestation_job = successful_job("Sign exact CI release candidates", current=True)
    for producer in (contribution_job, lambda_job):
        require(
            parse_utc(producer["completed_at"], "producer completion")
            <= parse_utc(attestation_job["started_at"], "attestation start"),
            "CI release attestation did not follow its producer",
        )

    artifacts = flatten_pages(
        api.pages(f"/repos/{REPOSITORY}/actions/runs/{ci_run_id}/artifacts"),
        "artifacts",
    )

    def artifact_for(
        name: str,
        job: dict[str, Any],
        maximum_size: int,
    ) -> dict[str, Any]:
        started = parse_utc(job["started_at"], f"{name} producer start")
        completed = parse_utc(job["completed_at"], f"{name} producer completion")
        eligible = [
            artifact
            for artifact in artifacts
            if artifact.get("name") == name
            and artifact.get("expired") is False
            and isinstance(artifact.get("id"), int)
            and not isinstance(artifact.get("id"), bool)
            and artifact["id"] > 0
            and isinstance(artifact.get("digest"), str)
            and DIGEST_RE.fullmatch(artifact["digest"]) is not None
            and isinstance(artifact.get("size_in_bytes"), int)
            and not isinstance(artifact.get("size_in_bytes"), bool)
            and 0 < artifact["size_in_bytes"] <= maximum_size
            and isinstance(artifact.get("workflow_run"), dict)
            and artifact["workflow_run"].get("id") == ci_run_id
            and artifact["workflow_run"].get("head_sha") == release
            and started
            <= parse_utc(artifact.get("created_at"), f"{name} creation")
            <= completed
        ]
        require(len(eligible) == 1, f"artifact {name} is missing or ambiguous")
        return eligible[0]

    receipt = artifact_for(
        f"oss-validation-receipt-{release}",
        contribution_job,
        50 * 1024 * 1024,
    )
    lambdas = artifact_for(
        f"lambdas-{release}",
        lambda_job,
        512 * 1024 * 1024,
    )
    return {
        "run": run,
        "runAttempt": current_attempt,
        "contributionJob": contribution_job,
        "lambdaJob": lambda_job,
        "attestationJob": attestation_job,
        "receiptArtifact": receipt,
        "lambdaArtifact": lambdas,
    }


def validate_manifest(
    manifest: dict[str, Any],
    *,
    upstream_pr_number: int,
) -> dict[str, Any]:
    require(manifest.get("schemaVersion") == 2, "contribution manifest schema is not v2")
    target = manifest.get("target")
    require(
        isinstance(target, dict)
        and target.get("repository") == UPSTREAM_REPOSITORY_URL
        and target.get("branch") == UPSTREAM_BRANCH
        and target.get("license") == UPSTREAM_LICENSE,
        "contribution manifest target is invalid",
    )
    require_sha(target.get("baseCommit"), "manifest target base commit")
    status = exact_keys(
        manifest.get("status"),
        {
            "state",
            "pullRequestOpened",
            "appliedToUpstream",
            "pullRequestNumber",
            "url",
            "headSha",
            "mergeCommitSha",
            "mergedAt",
            "localBuildRun",
            "localTestsRun",
            "localSecurityScanRun",
        },
        "manifest status",
    )
    require(
        status == {
            "state": "merged-upstream",
            "pullRequestOpened": True,
            "appliedToUpstream": True,
            "pullRequestNumber": upstream_pr_number,
            "url": f"{UPSTREAM_REPOSITORY_URL}/pull/{upstream_pr_number}",
            "headSha": status.get("headSha"),
            "mergeCommitSha": status.get("mergeCommitSha"),
            "mergedAt": status.get("mergedAt"),
            "localBuildRun": False,
            "localTestsRun": False,
            "localSecurityScanRun": False,
        },
        "manifest does not truthfully record the exact merged upstream PR",
    )
    require_sha(status["headSha"], "manifest status head SHA")
    require_sha(status["mergeCommitSha"], "manifest status merge commit SHA")
    merged_at = parse_utc(status["mergedAt"], "manifest status mergedAt")
    require(
        SUBMISSION_START <= merged_at <= SUBMISSION_DEADLINE,
        "manifest mergedAt is outside the submission period",
    )
    return target


def validate_receipt(
    root: Path,
    *,
    workspace: Path,
    release: str,
    manifest_bytes: bytes,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    sums = root / "SHA256SUMS"
    lines = sums.read_text(encoding="utf-8").splitlines()
    require(len(lines) == 3, "OSS receipt SHA256SUMS inventory is not exact")
    expected_sum_names = ["applied.diff", "manifest.json", "receipt.json"]
    observed_names: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "OSS receipt SHA256SUMS line is invalid")
        name = match.group(2)
        observed_names.append(name)
        require(
            name in expected_sum_names
            and sha256_file(root / name, prefixed=False) == match.group(1),
            f"OSS receipt checksum failed for {name}",
        )
    require(observed_names == expected_sum_names, "OSS receipt SHA256SUMS order drifted")
    require(
        (root / "manifest.json").read_bytes() == manifest_bytes,
        "CI receipt manifest bytes differ from the exact release",
    )

    receipt = read_json(root / "receipt.json", "OSS validation receipt")
    exact_keys(
        receipt,
        {
            "candidate",
            "dataHandling",
            "schemaVersion",
            "source",
            "target",
            "validation",
        },
        "OSS validation receipt",
    )
    require(receipt["schemaVersion"] == RECEIPT_SCHEMA, "OSS receipt schema is invalid")
    require(
        receipt["source"]
        == {
            "eventName": "push",
            "headSha": release,
            "pullRequestHeadSha": None,
            "repository": REPOSITORY,
        },
        "OSS receipt source is not the exact release push",
    )
    require(
        receipt["target"]
        == {
            "baseCommit": manifest["target"]["baseCommit"],
            "baseCommitUrl": manifest["target"]["baseCommitUrl"],
            "branch": UPSTREAM_BRANCH,
            "license": UPSTREAM_LICENSE,
            "repository": UPSTREAM_REPOSITORY_URL,
        },
        "OSS receipt target differs from the release manifest",
    )
    require(
        receipt["dataHandling"]
        == {
            "credentialsIncluded": False,
            "payload": (
                "public source metadata, digests, commands, and pass results only"
            ),
        },
        "OSS receipt data-handling boundary is invalid",
    )
    candidate = exact_keys(
        receipt["candidate"],
        {
            "appliedDiff",
            "files",
            "integrationPatch",
            "manifest",
            "name",
        },
        "OSS receipt candidate",
    )
    require(candidate["name"] == "get-aspect-history", "OSS candidate name is invalid")
    require(
        candidate["manifest"]
        == {
            "path": "manifest.json",
            "sha256": sha256_bytes(manifest_bytes, prefixed=False),
        },
        "OSS receipt manifest digest is invalid",
    )
    integration_path = workspace / "contrib/mcp-get-aspect-history/integration.patch"
    require(
        candidate["integrationPatch"]
        == {
            "path": "integration.patch",
            "sha256": sha256_file(integration_path, prefixed=False),
        },
        "OSS receipt integration patch digest is invalid",
    )
    applied_diff = root / "applied.diff"
    require(
        candidate["appliedDiff"]
        == {
            "format": "git-diff-binary-full-index",
            "path": "applied.diff",
            "sha256": sha256_file(applied_diff, prefixed=False),
        },
        "OSS receipt applied diff digest is invalid",
    )
    expected_files = [
        {
            "destination": destination,
            "kind": (
                "source"
                if destination.startswith("src/")
                else "test"
            ),
            "path": source,
            "sha256": sha256_file(workspace / source, prefixed=False),
        }
        for destination, source in STAGED_SOURCE_BY_DESTINATION.items()
    ]
    require(candidate["files"] == expected_files, "OSS receipt candidate files are detached")
    validation = exact_keys(
        receipt["validation"],
        {"commands", "environment", "result"},
        "OSS receipt validation",
    )
    require(validation["result"] == "pass", "OSS CI validation did not pass")
    require(
        validation["environment"]
        == {
            **manifest["ciEnvironment"],
            "setupResult": "pass",
        },
        "OSS CI environment differs from the manifest",
    )
    require(
        validation["commands"]
        == [
            {**entry, "result": "pass"}
            for entry in manifest["requiredCi"]
        ],
        "OSS CI commands differ from the exact manifest",
    )
    return {
        "receipt": receipt,
        "receiptDigest": sha256_file(root / "receipt.json"),
        "appliedDiff": applied_diff.read_bytes(),
        "appliedDiffDigest": sha256_file(applied_diff),
    }


def initialize_base_repository(root: Path, base_commit: str) -> None:
    root.mkdir(mode=0o700)
    public_git(root, "init", "--quiet")
    public_git(root, "config", "core.autocrlf", "false")
    public_git(root, "config", "core.filemode", "true")
    public_git(root, "remote", "add", "origin", UPSTREAM_GIT_URL)
    public_git(root, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", base_commit)
    fetched = public_git(root, "rev-parse", "FETCH_HEAD").decode().strip()
    require(fetched == base_commit, "credentialless Git fetch returned the wrong base commit")
    public_git(root, "checkout", "--quiet", "--detach", base_commit)


def diff_bytes(repository: Path) -> bytes:
    return public_git(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "HEAD",
        "--",
        *EXPECTED_PATHS,
    )


def tree_entry(repository: Path, tree: str, path: str) -> tuple[str, str, bytes]:
    raw = public_git(repository, "ls-tree", tree, "--", path).decode("utf-8")
    match = re.fullmatch(r"([0-7]{6}) blob ([0-9a-f]{40})\t([^\n]+)\n", raw)
    require(match is not None and match.group(3) == path, f"tree entry is invalid for {path}")
    content = public_git(
        repository,
        "show",
        f"{tree}:{path}",
        maximum_stdout=8 * 1024 * 1024,
    )
    return match.group(1), match.group(2), content


def reconstruct_candidate(
    *,
    workspace: Path,
    applied_diff: bytes,
    base_commit: str,
    pr_number: int,
    head_sha: str,
    merge_commit_sha: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="archon-bonus-oss-git-") as temporary:
        repository = Path(temporary) / "upstream"
        initialize_base_repository(repository, base_commit)
        applied_path = Path(temporary) / "applied.diff"
        applied_path.write_bytes(applied_diff)
        public_git(repository, "apply", "--binary", "--index", str(applied_path))
        changed = public_git(
            repository,
            "diff",
            "--cached",
            "--name-only",
            "HEAD",
        ).decode("utf-8").splitlines()
        require(tuple(changed) == EXPECTED_PATHS, "CI applied diff path inventory is not exact")
        require(diff_bytes(repository) == applied_diff, "CI applied diff is not reproducible")
        candidate_tree = public_git(repository, "write-tree").decode().strip()
        require_sha(candidate_tree, "reconstructed candidate tree")

        public_git(repository, "reset", "--hard", "--quiet", base_commit)
        public_git(
            repository,
            "clean",
            "-fdx",
            "--",
            *EXPECTED_PATHS,
        )
        for destination, source in STAGED_SOURCE_BY_DESTINATION.items():
            target = repository / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(workspace / source, target)
        public_git(
            repository,
            "apply",
            "--check",
            str(workspace / "contrib/mcp-get-aspect-history/integration.patch"),
        )
        public_git(
            repository,
            "apply",
            str(workspace / "contrib/mcp-get-aspect-history/integration.patch"),
        )
        public_git(
            repository,
            "add",
            "--intent-to-add",
            *STAGED_SOURCE_BY_DESTINATION,
        )
        require(
            diff_bytes(repository) == applied_diff,
            "release candidate files and integration patch differ from the CI receipt",
        )
        public_git(repository, "add", "--", *EXPECTED_PATHS)
        release_tree = public_git(repository, "write-tree").decode().strip()
        require(release_tree == candidate_tree, "release candidate tree differs from CI")

        public_git(
            repository,
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            f"refs/pull/{pr_number}/head",
        )
        fetched_head = public_git(repository, "rev-parse", "FETCH_HEAD").decode().strip()
        require(fetched_head == head_sha, "public pull-request head ref changed")
        head_tree = public_git(
            repository,
            "rev-parse",
            f"{head_sha}^{{tree}}",
        ).decode().strip()
        require(head_tree == candidate_tree, "public PR head tree differs from the CI candidate")

        public_git(
            repository,
            "fetch",
            "--quiet",
            "--no-tags",
            "--depth=1",
            "origin",
            merge_commit_sha,
        )
        fetched_merge = public_git(repository, "rev-parse", "FETCH_HEAD").decode().strip()
        require(fetched_merge == merge_commit_sha, "public merge commit changed")
        merge_tree = public_git(
            repository,
            "rev-parse",
            f"{merge_commit_sha}^{{tree}}",
        ).decode().strip()
        require_sha(merge_tree, "merge tree")

        files = []
        for path in EXPECTED_PATHS:
            candidate_mode, candidate_blob, candidate_bytes = tree_entry(
                repository, candidate_tree, path
            )
            head_mode, head_blob, head_bytes = tree_entry(repository, head_tree, path)
            merge_mode, _, merge_bytes = tree_entry(repository, merge_tree, path)
            require(
                (candidate_mode, candidate_blob, candidate_bytes)
                == (head_mode, head_blob, head_bytes),
                f"PR head bytes differ for {path}",
            )
            require(
                (candidate_mode, candidate_bytes) == (merge_mode, merge_bytes),
                f"merged upstream path bytes differ for {path}",
            )
            files.append(
                {
                    "path": path,
                    "mode": candidate_mode,
                    "gitBlobSha": candidate_blob,
                    "sha256": sha256_bytes(candidate_bytes),
                }
            )

        candidate_manifest = {
            "schemaVersion": CANDIDATE_SCHEMA,
            "upstreamRepository": UPSTREAM_REPOSITORY,
            "baseCommit": base_commit,
            "appliedDiffDigest": sha256_bytes(applied_diff),
            "reconstructedTreeSha": candidate_tree,
            "files": files,
        }
        candidate_digest = sha256_bytes(canonical_json_bytes(candidate_manifest))
        return {
            "baseCommit": base_commit,
            "appliedDiffDigest": sha256_bytes(applied_diff),
            "reconstructedTreeSha": candidate_tree,
            "canonicalFileManifestDigest": candidate_digest,
            "files": files,
            "exactHeadTreeMatch": True,
            "exactMergedPathBytesMatch": True,
            "headTreeSha": head_tree,
            "mergeTreeSha": merge_tree,
            "validatedCandidateDigest": candidate_digest,
        }


def collect_public_pr(
    public_api: GitHubApi,
    *,
    pr_number: int,
    manifest_status: dict[str, Any],
    base_commit: str,
) -> dict[str, Any]:
    repository = public_api.json(f"/repos/{UPSTREAM_REPOSITORY}")
    require(
        repository.get("full_name") == UPSTREAM_REPOSITORY
        and repository.get("html_url") == UPSTREAM_REPOSITORY_URL
        and repository.get("private") is False
        and repository.get("visibility") == "public"
        and repository.get("default_branch") == UPSTREAM_BRANCH
        and repository.get("archived") is False
        and repository.get("disabled") is False
        and isinstance(repository.get("license"), dict)
        and repository["license"].get("spdx_id") == UPSTREAM_LICENSE,
        "credentialless upstream repository metadata is invalid",
    )
    pull = public_api.json(f"/repos/{UPSTREAM_REPOSITORY}/pulls/{pr_number}")
    require(
        pull.get("number") == pr_number
        and pull.get("html_url") == f"{UPSTREAM_REPOSITORY_URL}/pull/{pr_number}"
        and pull.get("state") == "closed"
        and pull.get("merged") is True
        and pull.get("draft") is False
        and isinstance(pull.get("base"), dict)
        and pull["base"].get("ref") == UPSTREAM_BRANCH
        and pull["base"].get("sha") == base_commit
        and isinstance(pull["base"].get("repo"), dict)
        and pull["base"]["repo"].get("full_name") == UPSTREAM_REPOSITORY
        and isinstance(pull.get("head"), dict)
        and pull["head"].get("sha") == manifest_status["headSha"]
        and pull.get("merge_commit_sha") == manifest_status["mergeCommitSha"]
        and pull.get("merged_at") == manifest_status["mergedAt"]
        and pull.get("changed_files") == len(EXPECTED_PATHS),
        "public pull request is not the exact merged contribution",
    )
    head_sha = require_sha(pull["head"]["sha"], "public PR head SHA")
    merge_commit = require_sha(pull["merge_commit_sha"], "public PR merge commit")
    merged_at = parse_utc(pull["merged_at"], "public PR mergedAt")
    require(
        SUBMISSION_START <= merged_at <= SUBMISSION_DEADLINE
        and merged_at <= dt.datetime.now(dt.timezone.utc),
        "public PR merge is outside the official period or in the future",
    )
    author = pull.get("user")
    merger = pull.get("merged_by")
    require(
        isinstance(author, dict)
        and isinstance(merger, dict)
        and positive_int(author.get("id"), "PR author ID")
        != positive_int(merger.get("id"), "PR merger ID")
        and isinstance(author.get("login"), str)
        and bool(author["login"])
        and isinstance(merger.get("login"), str)
        and bool(merger["login"]),
        "public PR lacks independent maintainer acceptance",
    )

    files: list[dict[str, Any]] = []
    file_pages = public_api.pages(
        f"/repos/{UPSTREAM_REPOSITORY}/pulls/{pr_number}/files"
    )
    for page in file_pages:
        require(isinstance(page, list), "public PR files response is invalid")
        for file in page:
            require(isinstance(file, dict), "public PR file entry is invalid")
            files.append(file)
    require(
        len(files) == len(EXPECTED_PATHS)
        and tuple(sorted(file.get("filename") for file in files)) == EXPECTED_PATHS,
        "public PR changed path inventory is not exact",
    )
    for file in files:
        require(
            set(file).issuperset({"filename", "status"})
            and file.get("status") == EXPECTED_FILE_STATUS[file["filename"]]
            and "previous_filename" not in file,
            f"public PR path status is invalid for {file.get('filename')}",
        )

    diff_raw, _ = public_api.get(
        f"https://api.github.com/repos/{UPSTREAM_REPOSITORY}/pulls/{pr_number}",
        accept="application/vnd.github.v3.diff",
        maximum_bytes=8 * 1024 * 1024,
    )
    require(bool(diff_raw) and b"diff --git " in diff_raw, "public PR diff is empty")
    return {
        "number": pr_number,
        "baseRef": UPSTREAM_BRANCH,
        "baseSha": base_commit,
        "headSha": head_sha,
        "mergeCommitSha": merge_commit,
        "changedPaths": list(EXPECTED_PATHS),
        "authorId": author["id"],
        "authorLogin": author["login"],
        "mergedById": merger["id"],
        "mergedByLogin": merger["login"],
        "mergedAt": pull["merged_at"],
        "patchDigest": sha256_bytes(diff_raw),
    }


def verify_ci_attestation(
    *,
    lambda_root: Path,
    release: str,
    ci_run_id: int,
    ci_attempt: int,
    receipt_artifact_digest: str,
) -> dict[str, str]:
    sums = (lambda_root / "archon-lambdas.tar.gz.sha256").read_text(
        encoding="utf-8"
    )
    match = re.fullmatch(
        r"([0-9a-f]{64})  archon-lambdas\.tar\.gz\n?",
        sums,
    )
    require(match is not None, "Lambda subject checksum file is invalid")
    lambda_subject = lambda_root / "archon-lambdas.tar.gz"
    require(
        sha256_file(lambda_subject, prefixed=False) == match.group(1),
        "Lambda subject checksum is invalid",
    )
    raw = run_command(
        [
            "gh",
            "attestation",
            "verify",
            str(lambda_subject),
            "--repo",
            REPOSITORY,
            "--signer-workflow",
            f"github.com/{REPOSITORY}/.github/workflows/ci.yml",
            "--signer-digest",
            release,
            "--source-digest",
            release,
            "--source-ref",
            "refs/heads/master",
            "--predicate-type",
            CI_PREDICATE_TYPE,
            "--deny-self-hosted-runners",
            "--format",
            "json",
        ],
        maximum_stdout=32 * 1024 * 1024,
    )
    attestations = parse_json_bytes(raw, "CI attestation verification")
    require(isinstance(attestations, list), "CI attestation output is not a list")
    run_url = f"https://github.com/{REPOSITORY}/actions/runs/{ci_run_id}"
    matching = []
    for result in attestations:
        if not isinstance(result, dict):
            continue
        verification = result.get("verificationResult")
        statement = (
            verification.get("statement")
            if isinstance(verification, dict)
            else None
        )
        if not isinstance(statement, dict):
            continue
        predicate = statement.get("predicate")
        if not isinstance(predicate, dict):
            continue
        if statement.get("predicateType") != CI_PREDICATE_TYPE:
            continue
        if set(predicate) != {
            "capabilityEvidence",
            "dependencyEvidence",
            "gates",
            "releaseArtifacts",
            "schemaVersion",
            "source",
        }:
            continue
        if predicate.get("schemaVersion") != CI_PREDICATE_SCHEMA:
            continue
        if predicate.get("source") != {
            "repository": REPOSITORY,
            "commit": release,
            "ref": "refs/heads/master",
            "event": "push",
            "workflowRun": run_url,
            "runAttempt": ci_attempt,
        }:
            continue
        gates = predicate.get("gates")
        if (
            not isinstance(gates, dict)
            or set(gates) != CI_GATE_KEYS
            or any(value != "success" for value in gates.values())
        ):
            continue
        capability = predicate.get("capabilityEvidence")
        if (
            not isinstance(capability, dict)
            or set(capability) != CI_CAPABILITY_KEYS
            or capability.get("ossContributionValidationArtifactDigest")
            != receipt_artifact_digest
            or any(
                not isinstance(value, str)
                or DIGEST_RE.fullmatch(value) is None
                for value in capability.values()
            )
        ):
            continue
        dependency = predicate.get("dependencyEvidence")
        if (
            not isinstance(dependency, dict)
            or set(dependency) != {"dataHubMcpSecurityArtifactDigest"}
            or not isinstance(dependency["dataHubMcpSecurityArtifactDigest"], str)
            or DIGEST_RE.fullmatch(dependency["dataHubMcpSecurityArtifactDigest"])
            is None
        ):
            continue
        release_artifacts = predicate.get("releaseArtifacts")
        if (
            not isinstance(release_artifacts, dict)
            or set(release_artifacts) != {"container", "judgeEvidence"}
        ):
            continue
        valid_release_artifacts = True
        for key, expected_name in (
            ("container", f"container-{release}"),
            ("judgeEvidence", None),
        ):
            artifact = release_artifacts.get(key)
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"digest", "id", "name", "producerAttempt"}
                or not isinstance(artifact.get("id"), int)
                or isinstance(artifact.get("id"), bool)
                or artifact["id"] <= 0
                or not isinstance(artifact.get("producerAttempt"), int)
                or isinstance(artifact.get("producerAttempt"), bool)
                or not 0 < artifact["producerAttempt"] <= ci_attempt
                or not isinstance(artifact.get("digest"), str)
                or DIGEST_RE.fullmatch(artifact["digest"]) is None
                or (
                    artifact.get("name") != expected_name
                    if expected_name is not None
                    else artifact.get("name")
                    != f"judge-evidence-{release}-{artifact['producerAttempt']}"
                )
            ):
                valid_release_artifacts = False
                break
        if not valid_release_artifacts:
            continue
        if (
            release_artifacts["judgeEvidence"]["digest"]
            != capability["judgeEvidenceArtifactDigest"]
        ):
            continue
        subjects = statement.get("subject")
        if (
            not isinstance(subjects, list)
            or sorted(item.get("name") for item in subjects if isinstance(item, dict))
            != [
                "archon-image.tar.gz",
                "archon-lambdas.tar.gz",
                "archon-web.tar.gz",
            ]
        ):
            continue
        valid_subjects = True
        lambda_bound = False
        for subject in subjects:
            digest = subject.get("digest") if isinstance(subject, dict) else None
            if (
                not isinstance(digest, dict)
                or set(digest) != {"sha256"}
                or not isinstance(digest["sha256"], str)
                or BARE_DIGEST_RE.fullmatch(digest["sha256"]) is None
            ):
                valid_subjects = False
                break
            if (
                subject.get("name") == "archon-lambdas.tar.gz"
                and digest["sha256"] == match.group(1)
            ):
                lambda_bound = True
        if valid_subjects and lambda_bound:
            matching.append(statement)
    require(
        len(matching) == 1,
        "exactly one signed CI statement must bind the OSS validation artifact",
    )
    predicate_bytes = canonical_json_bytes(matching[0]["predicate"])
    return {
        "predicateDigest": sha256_bytes(predicate_bytes),
        "attestedSubjectName": "archon-lambdas.tar.gz",
        "attestedSubjectDigest": f"sha256:{match.group(1)}",
    }


def collect(args: argparse.Namespace) -> None:
    release = require_sha(args.release_sha, "release SHA")
    ci_run_id = positive_int(args.ci_run_id, "CI run ID")
    pr_number = positive_int(
        args.upstream_pull_request_number,
        "upstream pull request number",
    )
    require(args.repository == REPOSITORY, "source repository is not canonical")
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    require(
        workspace.is_dir() and not workspace.is_symlink(),
        "workspace is not a regular directory",
    )
    require(not output.exists() and not output.is_symlink(), "collection output exists")
    output.mkdir(mode=0o700, parents=True)
    head = run_command(["git", "rev-parse", "HEAD"], cwd=workspace).decode().strip()
    require(head == release, "workspace is not checked out at the exact release")
    require(
        run_command(["git", "status", "--porcelain"], cwd=workspace) == b"",
        "workspace is not clean",
    )
    manifest_path = workspace / "contrib/mcp-get-aspect-history/manifest.json"
    require(
        manifest_path.is_file() and not manifest_path.is_symlink(),
        "contribution manifest is not a regular file",
    )
    manifest_bytes = manifest_path.read_bytes()
    manifest = parse_json_bytes(manifest_bytes, "contribution manifest")
    require(isinstance(manifest, dict), "contribution manifest must be an object")
    target = validate_manifest(manifest, upstream_pr_number=pr_number)
    status = manifest["status"]

    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "GH_TOKEN is required for source repository evidence")
    own_api = GitHubApi(token=token)
    public_api = GitHubApi(token=None)
    current_ref = own_api.json(f"/repos/{REPOSITORY}/git/ref/heads/master")
    require(
        isinstance(current_ref.get("object"), dict)
        and current_ref["object"].get("sha") == release,
        "release is no longer current master",
    )
    ci = resolve_ci(own_api, release=release, ci_run_id=ci_run_id)
    public_pr = collect_public_pr(
        public_api,
        pr_number=pr_number,
        manifest_status=status,
        base_commit=target["baseCommit"],
    )

    receipt_archive = output / "receipt.zip"
    lambda_archive = output / "lambdas.zip"
    receipt_artifact = ci["receiptArtifact"]
    lambda_artifact = ci["lambdaArtifact"]
    download_artifact(
        receipt_artifact["id"],
        receipt_artifact["digest"],
        receipt_archive,
        maximum_bytes=50 * 1024 * 1024,
    )
    download_artifact(
        lambda_artifact["id"],
        lambda_artifact["digest"],
        lambda_archive,
        maximum_bytes=512 * 1024 * 1024,
    )
    receipt_root = output / "receipt"
    lambda_root = output / "lambdas"
    safe_extract_zip(
        receipt_archive,
        receipt_root,
        expected_files=RECEIPT_FILES,
        maximum_total=50 * 1024 * 1024,
    )
    safe_extract_zip(
        lambda_archive,
        lambda_root,
        expected_files=LAMBDA_FILES,
        maximum_total=512 * 1024 * 1024,
    )
    receipt_archive.unlink()
    lambda_archive.unlink()

    receipt = validate_receipt(
        receipt_root,
        workspace=workspace,
        release=release,
        manifest_bytes=manifest_bytes,
        manifest=manifest,
    )
    binding = reconstruct_candidate(
        workspace=workspace,
        applied_diff=receipt["appliedDiff"],
        base_commit=target["baseCommit"],
        pr_number=pr_number,
        head_sha=public_pr["headSha"],
        merge_commit_sha=public_pr["mergeCommitSha"],
    )
    require(
        binding["headTreeSha"] == binding["reconstructedTreeSha"],
        "PR head tree binding is invalid",
    )
    attestation = verify_ci_attestation(
        lambda_root=lambda_root,
        release=release,
        ci_run_id=ci_run_id,
        ci_attempt=ci["runAttempt"],
        receipt_artifact_digest=receipt_artifact["digest"],
    )
    for temporary_evidence in (receipt_root, lambda_root):
        require(
            temporary_evidence.parent == output
            and temporary_evidence.is_dir()
            and not temporary_evidence.is_symlink(),
            "temporary evidence cleanup escaped its collection root",
        )
        shutil.rmtree(temporary_evidence)
    require(
        not any(output.iterdir()),
        "collection root retained unexpected intermediate evidence",
    )

    upstream_pull_request = {
        "number": pr_number,
        "baseRef": public_pr["baseRef"],
        "baseSha": public_pr["baseSha"],
        "headSha": public_pr["headSha"],
        "headTreeSha": binding["headTreeSha"],
        "mergeCommitSha": public_pr["mergeCommitSha"],
        "mergeTreeSha": binding["mergeTreeSha"],
        "changedPaths": public_pr["changedPaths"],
        "authorId": public_pr["authorId"],
        "authorLogin": public_pr["authorLogin"],
        "mergedById": public_pr["mergedById"],
        "mergedByLogin": public_pr["mergedByLogin"],
        "mergedAt": public_pr["mergedAt"],
    }
    candidate_binding = {
        key: binding[key]
        for key in (
            "baseCommit",
            "appliedDiffDigest",
            "reconstructedTreeSha",
            "canonicalFileManifestDigest",
            "files",
            "exactHeadTreeMatch",
            "exactMergedPathBytesMatch",
        )
    }
    ci_validation = {
        "workflowPath": CI_WORKFLOW_PATH,
        "runId": ci_run_id,
        "runAttempt": ci["runAttempt"],
        "artifactId": receipt_artifact["id"],
        "artifactName": receipt_artifact["name"],
        "artifactDigest": receipt_artifact["digest"],
        "artifactProducerAttempt": ci["contributionJob"]["observedRunAttempt"],
        "receiptDigest": receipt["receiptDigest"],
        "predicateType": CI_PREDICATE_TYPE,
        "predicateDigest": attestation["predicateDigest"],
        "attestedSubjectName": attestation["attestedSubjectName"],
        "attestedSubjectDigest": attestation["attestedSubjectDigest"],
    }
    facts = {
        "upstreamRepositoryUrl": UPSTREAM_REPOSITORY_URL,
        "pullRequestUrl": f"{UPSTREAM_REPOSITORY_URL}/pull/{pr_number}",
        "state": "merged",
        "publiclyAccessible": True,
        "acceptedByMaintainer": True,
        "acceptedAt": public_pr["mergedAt"],
        "patchDigest": public_pr["patchDigest"],
        "validatedCandidateDigest": binding["validatedCandidateDigest"],
        "upstreamPullRequest": upstream_pull_request,
        "candidateBinding": candidate_binding,
        "ciValidation": ci_validation,
    }
    require(
        facts["acceptedAt"] == upstream_pull_request["mergedAt"]
        and candidate_binding["baseCommit"] == upstream_pull_request["baseSha"]
        and candidate_binding["reconstructedTreeSha"]
        == upstream_pull_request["headTreeSha"]
        and facts["validatedCandidateDigest"]
        == candidate_binding["canonicalFileManifestDigest"]
        and ci_validation["artifactProducerAttempt"] <= ci_validation["runAttempt"],
        "BONUS-OSS cross-binding is invalid",
    )
    write_json(output / "facts/BONUS-OSS.json", facts)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("collect")
    command.add_argument("--repository", required=True)
    command.add_argument("--release-sha", required=True)
    command.add_argument("--ci-run-id", type=int, required=True)
    command.add_argument("--upstream-pull-request-number", type=int, required=True)
    command.add_argument("--workspace", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    return value


def main() -> None:
    args = parser().parse_args()
    if args.command == "collect":
        collect(args)
        return
    fail(f"unsupported command {args.command}")


if __name__ == "__main__":
    main()
