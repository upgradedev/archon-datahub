"""In-process companion orchestration and durable Analytics Agent continuity."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sqlite3
import stat as stat_module
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator

import httpx

import archon_companion as companion
from contracts import (
    COLUMN_PATH,
    ContractError,
    DATASET_URN,
    DIGEST_RE,
    PII_TAG,
    QUESTION,
    RuntimeJob,
    TAG_RE,
    canonical_json,
    checkpoint_contains_credentials,
    digest,
    exact_keys,
)
from managed_mcp import ManagedCredential
from runtime_store import CheckpointStore, required_env

ROOT = Path("/tmp/archon-cloud-runtime-v2")
DEMO_SQL = Path("/opt/archon/demo/archon_demo.sql")
MAX_STATE_PART = 12 * 1024 * 1024
PROXY_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)


def _regular_bytes(
    path: Path,
    maximum: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if (
            not stat_module.S_ISREG(file_stat.st_mode)
            or file_stat.st_size < 0
            or file_stat.st_size > maximum
            or (file_stat.st_size == 0 and not allow_empty)
        ):
            raise ContractError("analytics_state_file_invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ContractError("analytics_state_file_too_large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_demo_scope() -> None:
    if (
        os.environ.get("ARCHON_DEMO_QUERY", DATASET_URN) != DATASET_URN
        or os.environ.get("ARCHON_ANALYTICS_QUESTION", QUESTION) != QUESTION
    ):
        raise ContractError("canonical_demo_scope_invalid")
    if not DEMO_SQL.is_file() or DEMO_SQL.is_symlink():
        raise ContractError("canonical_demo_sql_missing")


def _materialize_demo(database: Path) -> None:
    _validate_demo_scope()
    script = _regular_bytes(DEMO_SQL, 512 * 1024).decode("utf-8", errors="strict")
    if database.exists():
        raise ContractError("demo_database_already_exists")
    connection = sqlite3.connect(database)
    try:
        connection.executescript(script)
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)


def _analytics_config(endpoint: str, demo_database: Path) -> str:
    if not endpoint.startswith("https://") or not endpoint.endswith(
        "/integrations/ai/mcp"
    ):
        raise ContractError("cloud_tenant_url_invalid")
    return (
        "context_platforms:\n"
        "  - type: datahub-mcp\n"
        "    name: archon-datahub-mcp\n"
        "    label: Archon managed DataHub MCP\n"
        "    transport: http\n"
        "    url: \"${ARCHON_CLOUD_MCP_ENDPOINT}\"\n"
        "    headers:\n"
        "      Authorization: \"Bearer ${DATAHUB_GMS_TOKEN}\"\n"
        "engines:\n"
        "  - type: sqlite\n"
        "    name: archon_demo\n"
        "    connection:\n"
        "      dialect: sqlite\n"
        f"      database: {demo_database}\n"
    )


@contextlib.contextmanager
def _temporary_environment(values: dict[str, str]) -> Iterator[None]:
    if any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or "\x00" in value
        or "\n" in value
        or "\r" in value
        for key, value in values.items()
    ):
        raise ContractError("analytics_environment_invalid")
    names = set(values) | set(PROXY_NAMES) | {"ARCHON_DATAHUB_MCP_URL"}
    previous = {name: os.environ.get(name) for name in names}
    try:
        for name in PROXY_NAMES:
            os.environ.pop(name, None)
        os.environ.pop("ARCHON_DATAHUB_MCP_URL", None)
        os.environ.update(values)
        yield
    finally:
        for name, prior in previous.items():
            if prior is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = prior


class AnalyticsSession:
    def __init__(
        self,
        job: RuntimeJob,
        credential: ManagedCredential,
        checkpoint: CheckpointStore,
    ) -> None:
        if not credential.run_handle_key or not credential.oauth_master_key:
            raise ContractError("reader_secret_incomplete")
        self.job = job
        self.credential = credential
        self.checkpoint = checkpoint
        self.root = ROOT / job.session_id / job.job_id
        self.state = self.root / "state.sqlite"
        self.demo = self.root / "archon-demo.sqlite"
        self.config = self.root / "config.yaml"
        self.process: subprocess.Popen[bytes] | None = None
        self.revision = 0
        self.checkpoint_receipt: dict[str, Any] | None = None
        self.oauth_digest = digest(
            {"schemaVersion": "archon.analytics-oauth-key/v1", "key": credential.oauth_master_key}
        )
        self.run_handle_digest = digest(
            {"schemaVersion": "archon.analytics-run-handle-key/v1", "key": credential.run_handle_key}
        )
        model = required_env("ARCHON_BEDROCK_MODEL", maximum=256)
        region = required_env("AWS_REGION", maximum=32)
        expected_role = required_env(
            "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN",
            maximum=512,
        )
        self.environment = {
            "HOME": str(self.root),
            "ANALYTICS_AGENT_CONFIG_DIR": str(self.root),
            "ENGINES_CONFIG": str(self.config),
            "DATABASE_URL": f"sqlite+aiosqlite:///{self.state}",
            "OAUTH_MASTER_KEY": credential.oauth_master_key,
            "LLM_PROVIDER": "bedrock",
            "LLM_MODEL": model,
            "CHART_LLM_MODEL": model,
            "QUALITY_LLM_MODEL": model,
            "DELIGHT_LLM_MODEL": model,
            "AWS_REGION": region,
            "AWS_DEFAULT_REGION": region,
            "AWS_STS_REGIONAL_ENDPOINTS": "regional",
            "ARCHON_EXPECTED_ANALYTICS_ROLE_ARN": expected_role,
            "DATAHUB_TELEMETRY_ENABLED": "false",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "",
            "ARCHON_RUNTIME_PROFILE_ID": "cloud",
            "ARCHON_RUNTIME_GENERATION": job.generation,
            "ARCHON_RUNTIME_CAPABILITY_DIGEST": job.capability_digest,
            "ARCHON_RUN_HANDLE_FERNET_KEY": credential.run_handle_key,
            "ARCHON_ANALYTICS_AGENT_URL": "http://127.0.0.1:8100",
            "ARCHON_ANALYTICS_ENGINE": "archon_demo",
            "ARCHON_ANALYTICS_LLM_PROVIDER": "bedrock",
            "ARCHON_ANALYTICS_LLM_MODEL": model,
            "ARCHON_ANALYTICS_AWS_REGION": region,
            "ARCHON_DATAHUB_MCP_CONNECTION": "archon-datahub-mcp",
            "ARCHON_CLOUD_MCP_ENDPOINT": credential.endpoint,
            "ARCHON_AGENT_STACK_LOCK": "/opt/archon/.github/locks/datahub-agent-stack.json",
            "ARCHON_DATAHUB_MCP_LOCK": "/opt/archon/.github/locks/datahub-mcp-v0.6.0.json",
            "ARCHON_DATAHUB_SKILLS_DIR": "/opt/archon/datahub-skills",
            "ARCHON_CUSTOM_SKILLS_DIR": "/opt/archon/contrib",
            "ARCHON_DEMO_QUERY": DATASET_URN,
            "ARCHON_ANALYTICS_QUESTION": QUESTION,
            "DATAHUB_GMS_URL": credential.gms_url,
            "DATAHUB_GMS_TOKEN": credential.token,
        }

    def __enter__(self) -> "AnalyticsSession":
        try:
            if self.root.exists():
                shutil.rmtree(self.root)
            self.root.mkdir(mode=0o700, parents=True)
            self.revision = self.checkpoint.restore(
                self.job,
                self.state,
                oauth_key_digest=self.oauth_digest,
                run_handle_key_digest=self.run_handle_digest,
            )
            _materialize_demo(self.demo)
            self.config.write_text(
                _analytics_config(self.credential.endpoint, self.demo),
                encoding="utf-8",
            )
            self.config.chmod(0o600)
            child_env = dict(os.environ)
            for name in PROXY_NAMES:
                child_env.pop(name, None)
            child_env.pop("ARCHON_DATAHUB_MCP_URL", None)
            child_env.update(self.environment)
            bootstrap = subprocess.run(
                [sys.executable, "-m", "analytics_agent.cli", "bootstrap"],
                cwd=self.root,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=120,
                check=False,
            )
            if bootstrap.returncode != 0:
                raise ContractError("analytics_bootstrap_failed")
            self.process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "analytics_agent.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8100",
                    "--no-access-log",
                    "--log-level",
                    "warning",
                ],
                cwd=self.root,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            deadline = time.monotonic() + 30
            with httpx.Client(
                base_url="http://127.0.0.1:8100",
                timeout=httpx.Timeout(2.0),
                trust_env=False,
                follow_redirects=False,
            ) as client:
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        raise ContractError("analytics_process_failed")
                    try:
                        response = client.get("/health")
                        if (
                            response.status_code == 200
                            and response.json() == {"status": "ok"}
                        ):
                            break
                    except (httpx.HTTPError, ValueError):
                        pass
                    time.sleep(0.25)
                else:
                    raise ContractError("analytics_process_timeout")
            return self
        except BaseException:
            self._stop()
            if self.root.exists():
                shutil.rmtree(self.root)
            raise

    def _stop(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def _checkpoint(self) -> None:
        if not self.state.is_file() or self.state.is_symlink():
            raise ContractError("analytics_state_missing")
        connection = sqlite3.connect(self.state)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            connection.commit()
        finally:
            connection.close()
        paths = [self.state, Path(str(self.state) + "-wal"), Path(str(self.state) + "-shm")]
        parts: list[bytes] = []
        sidecars: list[bytes] = []
        for path in paths:
            if path.exists():
                data = _regular_bytes(
                    path,
                    MAX_STATE_PART,
                    allow_empty=path != self.state,
                )
                parts.append(data)
                if path != self.state:
                    sidecars.append(data)
        forbidden = [
            self.credential.token.encode("utf-8"),
            self.credential.oauth_master_key.encode("ascii"),
            self.credential.run_handle_key.encode("ascii"),
            ("Bearer " + self.credential.token).encode("utf-8"),
        ]
        if checkpoint_contains_credentials(parts, forbidden):
            raise ContractError("analytics_checkpoint_contains_credential")
        if any(sidecars):
            raise ContractError("analytics_checkpoint_wal_not_drained")
        state = _regular_bytes(self.state, MAX_STATE_PART)
        receipt = self.checkpoint.save(
            self.job,
            state,
            expected_revision=self.revision,
            oauth_key_digest=self.oauth_digest,
            run_handle_key_digest=self.run_handle_digest,
        )
        proof = {
            **receipt,
            "plaintextCredentialScan": "verified-absent",
            "sqliteWalCheckpoint": "truncated",
        }
        self.checkpoint_receipt = {**proof, "digest": digest(proof)}

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            self._stop()
            if exc_type is None:
                self._checkpoint()
        finally:
            if self.root.exists():
                shutil.rmtree(self.root)


async def _analyze(request_value: dict[str, Any]) -> dict[str, Any]:
    request = companion.AnalyzeRequest.model_validate(request_value)
    companion.exact_public_input(request)
    probe_state = companion._ModelProbeState()
    context, skills, preflight = await asyncio.gather(
        asyncio.to_thread(companion.collect_ack_context, request.query),
        asyncio.to_thread(companion.load_skill_receipt),
        companion.analytics_preflight(
            request.runtimeBinding, model_probe_state=probe_state,
        ),
    )
    grounding = companion.ground_skills(
        skills,
        context,
        preflight["dataHubMcpServer"]["officialMcpReadReceipts"],
    )
    analytics = await companion.run_analytics(
        request.question,
        request.runtimeBinding,
        context,
        grounding,
        preflight,
    )
    payload = {
        "schemaVersion": "archon.datahub-agent-stack-result/v2",
        "runtimeBinding": companion.binding_value(request.runtimeBinding),
        "context": context,
        "skills": skills,
        "skillGrounding": grounding,
        "analytics": analytics,
        "enrichment": {
            "status": "preview-only",
            "writeAuthority": "archon-remediation-worker",
            "requiresFreshDigestBoundApproval": True,
        },
    }
    return {**payload, "digest": companion.digest(payload)}


async def _improve(request_value: dict[str, Any]) -> dict[str, Any]:
    request = companion.ImproveRequest.model_validate(request_value)
    handle = companion.resolve_run_handle(request.runHandle, request.runtimeBinding)
    probe_state = companion._ModelProbeState()
    preflight = await companion.analytics_preflight(
        request.runtimeBinding, model_probe_state=probe_state,
    )
    prompt = companion.canonical(
        {
            "schemaVersion": "archon.analytics-improve-context/v1",
            "command": "/improve-context",
            "runtimeBindingDigest": handle["bindingDigest"],
            "contextDigest": handle["contextDigest"],
            "skillGroundingDigest": handle["skillGroundingDigest"],
            "policy": {
                "mode": "proposal-only",
                "mutationsEnabled": False,
                "requiresFreshDigestBoundApproval": True,
            },
        }
    ).decode("utf-8")
    events = await companion.analytics_turn(handle["conversationId"], prompt)
    quality = await companion.context_quality(handle["conversationId"])
    rotated = companion.issue_run_handle(
        handle["conversationId"],
        request.runtimeBinding,
        handle["contextDigest"],
        handle["skillGroundingDigest"],
    )
    payload = {
        "schemaVersion": "archon.datahub-improve-context/v2",
        "runtimeBinding": companion.binding_value(request.runtimeBinding),
        "events": events,
        "contextQuality": quality,
        "runHandle": rotated,
        "preflightDigest": preflight["digest"],
        "contextDigest": handle["contextDigest"],
        "skillGroundingDigest": handle["skillGroundingDigest"],
        "status": "proposal-only",
        "writeAuthority": "archon-remediation-worker",
        "requiresFreshDigestBoundApproval": True,
    }
    return {**payload, "digest": companion.digest(payload)}


def validate_post_analysis(
    value: Any,
    job: RuntimeJob,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = {
        "schemaVersion", "originalRequest", "sourceMutationAuditId",
        "sourceMutationReceiptDigest", "postMutationExpectedTagState",
    }
    tag_state = value.get("postMutationExpectedTagState") if isinstance(
        value, dict
    ) else None
    tag_urns = tag_state.get("tagUrns") if isinstance(
        tag_state, dict
    ) else None
    tag_values = {
        "entityUrn": DATASET_URN,
        "columnPath": COLUMN_PATH,
        "tagUrns": tag_urns,
    }
    if (
        not exact_keys(value, expected)
        or value.get("schemaVersion")
            != "archon.datahub-post-mutation-analysis/v1"
        or not isinstance(value.get("originalRequest"), dict)
        or value.get("sourceMutationAuditId") != job.audit_id
        or DIGEST_RE.fullmatch(
            str(value.get("sourceMutationReceiptDigest"))
        ) is None
        or not exact_keys(
            tag_state,
            {"schemaVersion", "entityUrn", "columnPath", "tagUrns", "stateDigest"},
        )
        or tag_state.get("schemaVersion")
            != "archon.core-tag-read-result/v1"
        or tag_state.get("entityUrn") != DATASET_URN
        or tag_state.get("columnPath") != COLUMN_PATH
        or not isinstance(tag_urns, list)
        or not 1 <= len(tag_urns) <= 256
        or tag_urns != sorted(set(tag_urns))
        or PII_TAG not in tag_urns
        or any(
            not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None
            for tag in tag_urns
        )
        or tag_state.get("stateDigest") != digest(tag_values)
    ):
        raise ContractError("post_analysis_request_invalid")
    return value["originalRequest"], {
        "sourceMutationAuditId": value["sourceMutationAuditId"],
        "sourceMutationReceiptDigest": value["sourceMutationReceiptDigest"],
        "postMutationExpectedTagState": tag_state,
    }


def execute_analytics_operation(
    job: RuntimeJob,
    credential: ManagedCredential,
    checkpoint: CheckpointStore,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = job.request
    post_metadata: dict[str, Any] | None = None
    if job.operation == "POST_ANALYZE":
        request, post_metadata = validate_post_analysis(request, job)
    if job.operation not in {"ANALYZE", "POST_ANALYZE", "IMPROVE_CONTEXT"}:
        raise ContractError("analytics_operation_invalid")
    with AnalyticsSession(job, credential, checkpoint) as session:
        with _temporary_environment(session.environment):
            raw_result = asyncio.run(
                _improve(request)
                if job.operation == "IMPROVE_CONTEXT"
                else _analyze(request)
            )
    if session.checkpoint_receipt is None:
        raise ContractError("analytics_checkpoint_missing")
    result = raw_result
    if post_metadata is not None:
        result = {
            "schemaVersion":
                "archon.datahub-post-mutation-analysis-result/v1",
            **post_metadata,
            "postMutationResult": raw_result,
            "postMutationResultDigest": digest(raw_result),
        }
    if len(canonical_json(result)) > 300 * 1024:
        raise ContractError("analytics_result_too_large")
    return result, session.checkpoint_receipt
