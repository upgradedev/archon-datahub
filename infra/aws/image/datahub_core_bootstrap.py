"""Boot and supervise the four-component DataHub Core runtime.

The host has no ingress route and exchanges requests through DynamoDB. Secrets
are generated per boot, kept in /run, and never written to the AMI or logs.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError
from cryptography.fernet import Fernet

from core_job_adapter import CoreJobAdapter

CAPABILITIES = {
    "mcpRead": True,
    "mcpGovernedWrite": True,
    "agentContextKit": True,
    "dataHubSkills": True,
    "analyticsAgent": True,
}
REQUIRED = (
    "AWS_REGION",
    "ARCHON_STAGE",
    "CORE_LEASE_TABLE",
    "ARCHON_RUNTIME_GENERATION",
    "ARCHON_RUNTIME_CAPABILITY_DIGEST",
    "ARCHON_IMAGE_MANIFEST_DIGEST",
    "ARCHON_LLM_PROVIDER",
    "ARCHON_LLM_MODEL",
)
ROOT = Path("/opt/archon")
RUNTIME = Path("/run/archon")
VENV = ROOT / ".venv/bin"
TABLE = None
PROCESSES: list[subprocess.Popen[bytes]] = []


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is missing")
    return value


def _iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _epoch() -> int:
    return int(time.time())


def _request(url: str, timeout: int = 5) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(256 * 1024)
    except (OSError, urllib.error.HTTPError):
        return 0, b""


def _lease() -> dict[str, Any] | None:
    response = TABLE.get_item(
        Key={"pk": "CORE#LEASE", "sk": "CURRENT"}, ConsistentRead=True
    )
    value = response.get("Item")
    return value if isinstance(value, dict) else None


def _runtime_env(session_id: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": "/opt/archon/runtime-home",
            "PATH": f"{VENV}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
            "ARCHON_RUNTIME_PROFILE_ID": "core",
            "ARCHON_RUNTIME_GENERATION": _required(
                "ARCHON_RUNTIME_GENERATION"
            ),
            "ARCHON_RUNTIME_CAPABILITY_DIGEST": _required(
                "ARCHON_RUNTIME_CAPABILITY_DIGEST"
            ),
            "ARCHON_RUN_HANDLE_FERNET_KEY": Fernet.generate_key().decode("ascii"),
            "ARCHON_ANALYTICS_AGENT_URL": "http://127.0.0.1:8100",
            "ARCHON_ANALYTICS_ENGINE": "archon_demo",
            "ARCHON_AGENT_STACK_LOCK": (
                "/opt/archon/.github/locks/datahub-agent-stack.json"
            ),
            "ARCHON_DATAHUB_SKILLS_DIR": "/opt/archon/datahub-skills",
            "ARCHON_CUSTOM_SKILLS_DIR": "/opt/archon/contrib",
            "DATAHUB_GMS_URL": "https://127.0.0.1:9443/gms",
            "DATAHUB_GMS_TOKEN": "core-loopback-readonly",
            "REQUESTS_CA_BUNDLE": "/opt/archon/runtime/tls/ca.pem",
            "SSL_CERT_FILE": "/opt/archon/runtime/tls/ca.pem",
            "ENGINES_CONFIG": "/opt/archon/runtime/analytics-config.yaml",
            "DATABASE_URL": (
                "sqlite+aiosqlite:////opt/archon/runtime-home/analytics.db"
            ),
            "LLM_PROVIDER": _required("ARCHON_LLM_PROVIDER"),
            "LLM_MODEL": _required("ARCHON_LLM_MODEL"),
            "CHART_LLM_MODEL": os.environ.get(
                "ARCHON_CHART_LLM_MODEL", _required("ARCHON_LLM_MODEL")
            ),
            "AWS_DEFAULT_REGION": _required("AWS_REGION"),
            "ARCHON_CORE_SESSION_ID": session_id,
            "OTEL_EXPORTER_OTLP_ENDPOINT": "",
        }
    )
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    env_path = RUNTIME / "runtime.env"
    allowed = {
        key: value
        for key, value in environment.items()
        if key.startswith(("ARCHON_", "DATAHUB_", "LLM_", "CHART_"))
        or key
        in {
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "DATABASE_URL",
            "ENGINES_CONFIG",
            "REQUESTS_CA_BUNDLE",
            "SSL_CERT_FILE",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
        }
    }
    env_path.write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(allowed.items())),
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    return environment


def _spawn(command: list[str], environment: dict[str, str]) -> None:
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    PROCESSES.append(process)


def _start_components(environment: dict[str, str]) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/opt/archon/datahub/.env",
            "-f",
            "/opt/archon/datahub/docker-compose.yml",
            "up",
            "-d",
            "--no-build",
            "--remove-orphans",
        ],
        check=True,
        timeout=600,
    )
    subprocess.run(
        [str(VENV / "analytics-agent"), "bootstrap"],
        cwd=ROOT / "runtime-home",
        env=environment,
        check=True,
        timeout=180,
    )
    _spawn(
        [
            str(VENV / "uvicorn"),
            "analytics_agent.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8100",
        ],
        environment,
    )

    read_mcp = dict(environment)
    read_mcp.update(
        {
            "FASTMCP_HOST": "127.0.0.1",
            "FASTMCP_PORT": "8000",
            "TOOLS_IS_MUTATION_ENABLED": "false",
            "TOOLS_IS_USER_ENABLED": "false",
            "DATA_QUALITY_TOOLS_ENABLED": "true",
        }
    )
    _spawn(
        [str(VENV / "mcp-server-datahub"), "--transport", "http"],
        read_mcp,
    )

    governed_mcp = dict(read_mcp)
    governed_mcp.update(
        {
            "FASTMCP_PORT": "8001",
            "TOOLS_IS_MUTATION_ENABLED": "true",
            "SAVE_DOCUMENT_TOOL_ENABLED": "false",
        }
    )
    _spawn(
        [str(VENV / "mcp-server-datahub"), "--transport", "http"],
        governed_mcp,
    )

    _spawn(
        [
            str(VENV / "uvicorn"),
            "archon_companion:app",
            "--app-dir",
            "/opt/archon/services/datahub-companion",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        environment,
    )


def _components_ready() -> bool:
    checks = (
        ("http://127.0.0.1:18080/health", None),
        ("http://127.0.0.1:8000/health", "ok"),
        ("http://127.0.0.1:8001/health", "ok"),
        ("http://127.0.0.1:8100/health", None),
        ("http://127.0.0.1:8080/healthz", None),
    )
    for url, required_status in checks:
        status, raw = _request(url)
        if status != 200:
            return False
        if required_status is not None:
            try:
                body = json.loads(raw)
            except ValueError:
                return False
            if body.get("status") != required_status:
                return False
    return all(process.poll() is None for process in PROCESSES)



def _model_ready() -> bool:
    """Require a real, schema-bounded Bedrock round trip before READY."""
    if _required("ARCHON_LLM_PROVIDER") != "bedrock":
        return False
    try:
        response = boto3.client(
            "bedrock-runtime", region_name=_required("AWS_REGION")
        ).converse(
            modelId=_required("ARCHON_LLM_MODEL"),
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                "Connectivity probe. Reply with the single token OK."
                            )
                        }
                    ],
                }
            ],
            inferenceConfig={"maxTokens": 4, "temperature": 0},
        )
        content = (
            response.get("output", {})
            .get("message", {})
            .get("content", [])
        )
        return any(
            isinstance(block, dict)
            and isinstance(block.get("text"), str)
            and bool(block["text"].strip())
            for block in content
        )
    except (BotoCoreError, OSError, TypeError, ValueError):
        return False
def _publish_health(
    lease: dict[str, Any],
    status: str,
    *,
    transition_ready: bool = False,
) -> None:
    now = _iso()
    session_id = lease["sessionId"]
    if transition_ready:
        TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression="SET #state=:ready, readyAt=:now, updatedAt=:now",
            ConditionExpression=(
                "sessionId=:session AND #state=:starting "
                "AND generation=:generation "
                "AND capabilityDigest=:digest "
                "AND attribute_not_exists(operationId)"
            ),
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":ready": "READY",
                ":now": now,
                ":session": session_id,
                ":starting": "STARTING",
                ":generation": _required("ARCHON_RUNTIME_GENERATION"),
                ":digest": _required("ARCHON_RUNTIME_CAPABILITY_DIGEST"),
            },
        )
    TABLE.put_item(
        Item={
            "pk": "RUNTIME#core",
            "sk": "HEALTH",
            "generation": _required("ARCHON_RUNTIME_GENERATION"),
            "status": status,
            "checkedAt": now,
            "capabilities": CAPABILITIES,
            "capabilityDigest": _required(
                "ARCHON_RUNTIME_CAPABILITY_DIGEST"
            ),
            "sessionId": session_id,
            "instanceId": _instance_id(),
            "endpoint": f"dynamodb://core-session/{session_id}",
            "transport": "dynamodb",
            "expiresAt": int(lease["hardExpiresAt"]) + 86400,
        }
    )


def _instance_id() -> str:
    token_request = urllib.request.Request(
        "http://169.254.169.254/latest/api/token",
        data=b"",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    try:
        with urllib.request.urlopen(token_request, timeout=2) as response:
            token = response.read(1024).decode("ascii")
        request = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            value = response.read(128).decode("ascii")
        if value.startswith("i-") and len(value) <= 32:
            return value
    except OSError:
        # IMDS is best-effort metadata; health remains bound to the lease.
        pass
    return "unknown"


def _mark_failed(lease: dict[str, Any]) -> None:
    now = _iso()
    try:
        TABLE.update_item(
            Key={"pk": "CORE#LEASE", "sk": "CURRENT"},
            UpdateExpression="SET #state=:failed, updatedAt=:now",
            ConditionExpression="sessionId=:session AND #state=:starting",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":failed": "FAILED",
                ":now": now,
                ":session": lease["sessionId"],
                ":starting": "STARTING",
            },
        )
    finally:
        _publish_health(lease, "UNHEALTHY")


def _stop_components() -> None:
    for process in PROCESSES:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                # The child already exited between poll and signal.
                pass
    deadline = time.monotonic() + 20
    for process in PROCESSES:
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/opt/archon/datahub/.env",
            "-f",
            "/opt/archon/datahub/docker-compose.yml",
            "down",
            "--remove-orphans",
        ],
        check=False,
        timeout=180,
    )


def main() -> int:
    global TABLE
    for name in REQUIRED:
        _required(name)
    TABLE = boto3.resource("dynamodb").Table(_required("CORE_LEASE_TABLE"))
    lease = _lease()
    if (
        lease is None
        or lease.get("state") != "STARTING"
        or lease.get("generation") != _required("ARCHON_RUNTIME_GENERATION")
        or lease.get("capabilityDigest")
        != _required("ARCHON_RUNTIME_CAPABILITY_DIGEST")
    ):
        return 20

    environment = _runtime_env(lease["sessionId"])
    try:
        _start_components(environment)
        ready_deadline = min(
            time.monotonic() + 20 * 60,
            time.monotonic() + max(1, int(lease["hardExpiresAt"]) - _epoch()),
        )
        model_ready = False
        next_model_probe = 0.0
        while time.monotonic() < ready_deadline:
            components_ready = _components_ready()
            if components_ready and time.monotonic() >= next_model_probe:
                model_ready = _model_ready()
                next_model_probe = time.monotonic() + 15
            if components_ready and model_ready:
                _publish_health(lease, "READY", transition_ready=True)
                break
            time.sleep(10)
        else:
            _mark_failed(lease)
            return 21

        adapter = CoreJobAdapter(
            table_name=_required("CORE_LEASE_TABLE"),
            session_id=lease["sessionId"],
            generation=_required("ARCHON_RUNTIME_GENERATION"),
            capability_digest=_required(
                "ARCHON_RUNTIME_CAPABILITY_DIGEST"
            ),
        )
        next_health = 0.0
        next_model_health = 0.0
        model_healthy = True
        while True:
            current = _lease()
            if (
                current is None
                or current.get("sessionId") != lease["sessionId"]
                or current.get("state") in {"DRAINING", "STOPPED", "EXPIRED"}
                or _epoch() >= int(lease["hardExpiresAt"])
            ):
                return 0
            adapter.process_once()
            if time.monotonic() >= next_health:
                if time.monotonic() >= next_model_health:
                    model_healthy = _model_ready()
                    next_model_health = time.monotonic() + 300
                healthy = _components_ready() and model_healthy
                _publish_health(
                    current, "READY" if healthy else "UNHEALTHY"
                )
                next_health = time.monotonic() + 30
            time.sleep(2)
    except Exception:
        _mark_failed(lease)
        return 22
    finally:
        _stop_components()


if __name__ == "__main__":
    sys.exit(main())
