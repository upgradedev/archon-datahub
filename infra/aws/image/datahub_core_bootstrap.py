"""Boot and supervise the isolated four-component DataHub Core runtime.

The AMI contains images and verified executables only. Each fresh runtime
session generates its SQLite database, DataHub service secrets, and two distinct
PATs under /run. No credential is baked into the image or shared with the wrong
process boundary.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import http.cookiejar
import json
import logging
import os
import re
import secrets
import socket
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from core_job_adapter import CoreJobAdapter

LOGGER = logging.getLogger("archon.datahub_core_bootstrap")

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
    "ARCHON_CORE_DATA_KEY_ARN",
    "ARCHON_MUTATION_SIGNING_KEY_ARN",
    "ARCHON_LLM_PROVIDER",
    "ARCHON_LLM_MODEL",
    "ARCHON_CHART_LLM_MODEL",
    "ARCHON_QUALITY_LLM_MODEL",
    "ARCHON_DELIGHT_LLM_MODEL",
    "ARCHON_DEMO_QUERY",
    "ARCHON_ANALYTICS_QUESTION",
)
ROOT = Path("/opt/archon")
RUNTIME = Path("/run/archon")
CREDENTIALS = RUNTIME / "datahub-credentials.json"
COMPOSE_ENV = RUNTIME / "datahub-compose.env"
ANALYTICS_DIR = RUNTIME / "analytics"
ANALYTICS_ENV = RUNTIME / "analytics.env"
DEMO_DIR = RUNTIME / "demo"
IMAGE_ID = ROOT / "image/companion-image.id"
DATAHUB_IMAGE_INVENTORY = ROOT / "image/datahub-images.txt"
IMAGE_REF = "archon/datahub-companion:sealed"
REPO_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[a-f0-9]{64}$")
GMS_URL = "http://127.0.0.1:18080"
FRONTEND_URL = "http://127.0.0.1:19002"
READ_MCP_URL = "http://127.0.0.1:8000/mcp"
WRITER_MCP_URL = "http://archon-writer-mcp:8002/mcp"
CONTAINER_GMS_URL = "http://archon-gms:8080"
WRITER_GMS_URL = "http://archon-writer-gms:8080"
CONTAINER_READ_MCP_URL = "http://archon-read-mcp:8000/mcp"
CONTAINER_ANALYTICS_URL = "http://archon-analytics:8100"
GOVERNED_MCP_URL = "http://127.0.0.1:8001/mcp"
COMPANION_URL = "http://127.0.0.1:8080"
ANALYTICS_URL = "http://127.0.0.1:8100"
READ_NETWORK = "archon-agent-read"
WRITER_NETWORK = "archon-writer"
BEDROCK_EGRESS_NETWORK = "archon-bedrock-egress"
GATEWAY_EGRESS_NETWORK = "archon-gateway-egress"
WRITER_SUBNET = "172.28.71.0/24"
SOURCE_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)"
)
EXPECTED_QUESTION = (
    "Which customer segment generated the highest net revenue in Q2 2026, "
    "and is customers.customer_email governed as PII?"
)
TABLE = None
PROCESSES: dict[str, subprocess.Popen[bytes]] = {}
CONTAINER_NAMES = (
    "archon-read-mcp",
    "archon-analytics",
    "archon-companion",
    "archon-writer-mcp",
    "archon-governed-gateway",
)


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


def _iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _epoch() -> int:
    return int(time.time())


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise RuntimeError(f"{path.name} is not one regular file")
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, path)
    path.chmod(0o600)


def _write_env(path: Path, values: dict[str, str]) -> None:
    for key, value in values.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
            raise RuntimeError("environment key is invalid")
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise RuntimeError(f"environment value for {key} is invalid")
    _write_private(
        path,
        "".join(f"{key}={values[key]}\n" for key in sorted(values)),
    )


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


def _prepare_runtime() -> None:
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in (ANALYTICS_DIR, DEMO_DIR):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(directory, 65532, 65532)
    _write_private(
        RUNTIME / "runtime.json",
        json.dumps(
            {
                "schemaVersion": "archon.datahub-core-runtime/v1",
                "profileId": "core",
                "generation": _required("ARCHON_RUNTIME_GENERATION"),
                "capabilityDigest": _required(
                    "ARCHON_RUNTIME_CAPABILITY_DIGEST"
                ),
                "imageManifestDigest": _required(
                    "ARCHON_IMAGE_MANIFEST_DIGEST"
                ),
                "demoQuery": _required("ARCHON_DEMO_QUERY"),
                "analyticsQuestion": _required("ARCHON_ANALYTICS_QUESTION"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )


def _prepare_compose_env() -> None:
    _write_env(
        COMPOSE_ENV,
        {
            "HOME": str(RUNTIME / "datahub-home"),
            "DATAHUB_VERSION": "v1.6.0",
            "DATAHUB_CONFLUENT_VERSION": "7.9.2",
            "DATAHUB_SEARCH_TAG": "7.16.1",
            "DATAHUB_MYSQL_VERSION": "8.2",
            "DATAHUB_TELEMETRY_ENABLED": "false",
            "AUTH_POLICIES_ENABLED": "true",
            "REST_API_AUTHORIZATION_ENABLED": "true",
            "MCP_VALIDATION_PRIVILEGE_CONSTRAINTS": "true",
            "POLICY_CACHE_REFRESH_INTERVAL_SECONDS": "5",
            "METADATA_SERVICE_AUTH_ENABLED": "true",
            "METADATA_SERVICE_AUTHENTICATOR_EXCEPTIONS_ENABLED": "true",
            "DATAHUB_SYSTEM_CLIENT_SECRET": secrets.token_urlsafe(48),
            "DATAHUB_TOKEN_SERVICE_SIGNING_KEY": secrets.token_urlsafe(48),
            "DATAHUB_TOKEN_SERVICE_SALT": secrets.token_urlsafe(32),
            "DATAHUB_SECRET": secrets.token_hex(32),
            "ARCHON_MYSQL_PASSWORD": secrets.token_urlsafe(32),
            "ARCHON_MYSQL_ROOT_PASSWORD": secrets.token_urlsafe(32),
            "ARCHON_NEO4J_PASSWORD": secrets.token_urlsafe(32),
            "DATAHUB_MAPPED_KAFKA_BROKER_PORT": "127.0.0.1:19092",
            "DATAHUB_MAPPED_FRONTEND_PORT": "127.0.0.1:19002",
            "DATAHUB_MAPPED_GMS_PORT": "127.0.0.1:18080",
            "DATAHUB_MAPPED_ELASTIC_PORT": "127.0.0.1:19200",
            "DATAHUB_MAPPED_MYSQL_PORT": "127.0.0.1:13306",
            "DATAHUB_MAPPED_NEO4J_HTTP_PORT": "127.0.0.1:17474",
            "DATAHUB_MAPPED_NEO4J_BOLT_PORT": "127.0.0.1:17687",
            "DATAHUB_MAPPED_SCHEMA_REGISTRY_PORT": "127.0.0.1:18081",
            "DATAHUB_MAPPED_ZK_PORT": "127.0.0.1:12181",
        },
    )


def _compose(*arguments: str, check: bool = True, timeout: int = 900) -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            "archon-core",
            "--env-file",
            str(COMPOSE_ENV),
            "-f",
            str(ROOT / "datahub/docker-compose.yml"),
            "-f",
            str(ROOT / "datahub/docker-compose.archon.yml"),
            "-f",
            str(ROOT / "datahub/docker-compose.images.yml"),
            *arguments,
        ],
        check=check,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def _ensure_network(name: str, subnet: str, *, internal: bool) -> None:
    inspected = subprocess.run(
        ["docker", "network", "inspect", name], check=False,
        capture_output=True, text=True, timeout=20,
    )
    if inspected.returncode != 0:
        command = ["docker", "network", "create", "--driver", "bridge", "--subnet", subnet]
        if internal:
            command.append("--internal")
        command.append(name)
        subprocess.run(command, check=True, timeout=30)
        inspected = subprocess.run(
            ["docker", "network", "inspect", name], check=True,
            capture_output=True, text=True, timeout=20,
        )
    values = json.loads(inspected.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise RuntimeError(f"network {name} inspection is invalid")
    value = values[0]
    configured = value.get("IPAM", {}).get("Config", [])
    if (
        value.get("Driver") != "bridge"
        or value.get("Internal") is not internal
        or not isinstance(configured, list)
        or not any(item.get("Subnet") == subnet for item in configured)
    ):
        raise RuntimeError(f"network {name} does not match the sealed topology")


def _isolate_container_network() -> None:
    """Install fail-closed IMDS and host-to-writer boundaries, then seal bridges."""
    rules = [
        ("iptables", "DOCKER-USER", ["-d", "169.254.169.254/32", "-j", "REJECT"]),
        (
            "iptables", "OUTPUT",
            ["-d", WRITER_SUBNET, "-p", "tcp", "--dport", "8002", "-j", "REJECT"],
        ),
    ]
    ipv6 = subprocess.run(
        ["sh", "-c", "command -v ip6tables"], check=False,
        capture_output=True, timeout=5,
    )
    if ipv6.returncode == 0:
        rules.append(("ip6tables", "DOCKER-USER", ["-d", "fd00:ec2::254/128", "-j", "REJECT"]))
    for executable, chain, rule in rules:
        check = [executable, "-C", chain, *rule]
        if subprocess.run(
            check, check=False, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10,
        ).returncode != 0:
            subprocess.run([executable, "-I", chain, "1", *rule], check=True, timeout=10)
        subprocess.run(check, check=True, timeout=10)
    _ensure_network(READ_NETWORK, "172.28.70.0/24", internal=True)
    _ensure_network(WRITER_NETWORK, WRITER_SUBNET, internal=True)
    _ensure_network(BEDROCK_EGRESS_NETWORK, "172.28.72.0/24", internal=False)
    _ensure_network(GATEWAY_EGRESS_NETWORK, "172.28.73.0/24", internal=False)


def _connect_network(container: str, network: str, alias: str | None = None) -> None:
    subprocess.run(
        ["docker", "network", "disconnect", "--force", network, container],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
    )
    command = ["docker", "network", "connect"]
    if alias is not None:
        command.extend(["--alias", alias])
    command.extend([network, container])
    subprocess.run(command, check=True, timeout=20)


def _attach_gms_networks() -> None:
    _connect_network("datahub-gms", READ_NETWORK, "archon-gms")
    _connect_network("datahub-gms", WRITER_NETWORK, "archon-writer-gms")

def _wait_for_datahub() -> None:
    deadline = time.monotonic() + 12 * 60
    while time.monotonic() < deadline:
        if _request(GMS_URL + "/health", 10)[0] == 200 and _request(
            FRONTEND_URL + "/", 10
        )[0] in {200, 302}:
            return
        time.sleep(5)
    raise TimeoutError("DataHub Core did not become healthy")


def _json_request(
    opener: Any, url: str, body: dict[str, Any], timeout: int = 20
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=_canonical(body),
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(128 * 1024)
            if response.status not in {200, 204}:
                raise RuntimeError("DataHub rejected a bootstrap request")
    except (OSError, urllib.error.HTTPError) as error:
        raise RuntimeError("DataHub bootstrap request failed") from error
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("DataHub bootstrap response was not an object")
    return value


def _graphql(
    opener: Any, query: str, variables: dict[str, Any]
) -> dict[str, Any]:
    response = _json_request(
        opener,
        FRONTEND_URL + "/api/v2/graphql",
        {"query": query, "variables": variables},
    )
    if response.get("errors") or not isinstance(response.get("data"), dict):
        raise RuntimeError("DataHub GraphQL operation failed")
    return response["data"]


def _mint_datahub_tokens(session_id: str) -> dict[str, Any]:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar)
    )
    _json_request(
        opener,
        FRONTEND_URL + "/logIn",
        {"username": "datahub", "password": "datahub"},
    )
    suffix = hashlib.sha256(session_id.encode("ascii")).hexdigest()[:12]
    account_mutation = (
        "mutation createServiceAccount($input: CreateServiceAccountInput!) {"
        " createServiceAccount(input: $input) { urn } }"
    )

    def account(name: str, description: str) -> str:
        data = _graphql(
            opener,
            account_mutation,
            {"input": {"displayName": name, "description": description}},
        )
        urn = data.get("createServiceAccount", {}).get("urn")
        if (
            not isinstance(urn, str)
            or not urn.startswith("urn:li:corpuser:")
            or len(urn) > 512
        ):
            raise RuntimeError("DataHub returned an invalid service account")
        return urn

    read_urn = account(
        f"Archon Core Reader {suffix}",
        "Ephemeral read-only official MCP identity.",
    )
    writer_urn = account(
        f"Archon Core Governed Writer {suffix}",
        "Ephemeral canonical-column PII mutation identity.",
    )
    _graphql(
        opener,
        "mutation batchAssignRole($input: BatchAssignRoleInput!) {"
        " batchAssignRole(input: $input) }",
        {
            "input": {
                "roleUrn": "urn:li:dataHubRole:Reader",
                "actors": [read_urn],
            }
        },
    )
    policy_input = {
        "type": "METADATA",
        "state": "ACTIVE",
        "name": f"Archon exact governed writer {suffix}",
        "description": (
            "One ephemeral service account may edit only the PII tag on the "
            "canonical demo dataset."
        ),
        "resources": {
            "type": "dataset",
            "resources": [SOURCE_URN],
            "allResources": False,
            "privilegeConstraints": {
                "criteria": [
                    {
                        "field": "URN",
                        "values": ["urn:li:tag:PII"],
                        "condition": "EQUALS",
                    }
                ]
            },
        },
        "privileges": [
            "VIEW_ENTITY_PAGE",
            "GET_ENTITY_PRIVILEGE",
            "EDIT_DATASET_COL_TAGS",
        ],
        "actors": {
            "users": [writer_urn],
            "groups": [],
            "resourceOwners": False,
            "resourceOwnersTypes": [],
            "allUsers": False,
            "allGroups": False,
        },
    }
    policy_urn = _graphql(
        opener,
        "mutation createPolicy($input: PolicyUpdateInput!) {"
        " createPolicy(input: $input) }",
        {"input": policy_input},
    ).get("createPolicy")
    if (
        not isinstance(policy_urn, str)
        or not policy_urn.startswith("urn:li:dataHubPolicy:")
        or len(policy_urn) > 512
    ):
        raise RuntimeError("DataHub returned an invalid governed policy")

    token_mutation = (
        "mutation createAccessToken($input: CreateAccessTokenInput!) {"
        " createAccessToken(input: $input) { accessToken metadata { id } } }"
    )

    def mint(
        actor_urn: str, token_type: str, duration: str, name: str
    ) -> tuple[str, str]:
        token_data = _graphql(
            opener,
            token_mutation,
            {
                "input": {
                    "type": token_type,
                    "actorUrn": actor_urn,
                    "duration": duration,
                    "name": name,
                    "description": "Ephemeral Archon Core runtime credential.",
                }
            },
        ).get("createAccessToken", {})
        token = token_data.get("accessToken")
        token_id = token_data.get("metadata", {}).get("id")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 8192
            or not isinstance(token_id, str)
            or not token_id
            or len(token_id) > 1024
        ):
            raise RuntimeError("DataHub returned an invalid access token")
        return token, token_id

    read_token, _ = mint(
        read_urn,
        "SERVICE_ACCOUNT",
        "ONE_DAY",
        f"archon-core-read-{suffix}",
    )
    write_token, _ = mint(
        writer_urn,
        "SERVICE_ACCOUNT",
        "ONE_DAY",
        f"archon-core-writer-{suffix}",
    )
    seed_token, seed_token_id = mint(
        "urn:li:corpuser:datahub",
        "PERSONAL",
        "ONE_HOUR",
        f"archon-core-seed-{suffix}",
    )
    if (
        hmac.compare_digest(read_token, write_token)
        or hmac.compare_digest(read_token, seed_token)
        or hmac.compare_digest(write_token, seed_token)
    ):
        raise RuntimeError("DataHub returned non-distinct credentials")
    _write_private(
        CREDENTIALS,
        json.dumps(
            {"readToken": read_token, "writeToken": write_token},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    return {
        "opener": opener,
        "seedToken": seed_token,
        "seedTokenId": seed_token_id,
        "readActorUrn": read_urn,
        "writerActorUrn": writer_urn,
        "writerPolicyUrn": policy_urn,
        "writerPolicy": policy_input,
    }

def _credentials() -> tuple[str, str]:
    descriptor = os.open(
        CREDENTIALS,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("runtime credential file is not private")
        with os.fdopen(os.dup(descriptor), encoding="utf-8") as stream:
            value = json.load(stream)
    finally:
        os.close(descriptor)
    if set(value) != {"readToken", "writeToken"}:
        raise RuntimeError("runtime credential schema is invalid")
    read_token, write_token = value["readToken"], value["writeToken"]
    if not all(isinstance(token, str) and token for token in (read_token, write_token)):
        raise RuntimeError("runtime credentials are invalid")
    return read_token, write_token


def _revoke_seed_token(identity: dict[str, Any]) -> None:
    _graphql(
        identity["opener"],
        "mutation revokeAccessToken($tokenId: String!) {"
        " revokeAccessToken(tokenId: $tokenId) }",
        {"tokenId": identity["seedTokenId"]},
    )


def _seed_and_configure(
    session_id: str, identity: dict[str, Any]
) -> None:
    database = DEMO_DIR / "archon-demo.sqlite"
    marker = RUNTIME / "seed-session"
    seed_credentials = RUNTIME / "seed-admin-credentials.json"
    already_seeded = (
        marker.is_file()
        and not marker.is_symlink()
        and marker.read_text("utf-8") == session_id
        and database.is_file()
    )
    try:
        if not already_seeded:
            _write_private(
                seed_credentials,
                json.dumps(
                    {
                        "readToken": identity["seedToken"],
                        "writeToken": identity["seedToken"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
            )
            subprocess.run(
                [
                    str(ROOT / "governed/.venv/bin/python"),
                    str(ROOT / "core/demo/seed_datahub.py"),
                    "--database",
                    str(database),
                    "--gms-url",
                    GMS_URL,
                    "--credential-file",
                    str(seed_credentials),
                ],
                check=True,
                timeout=180,
                stdin=subprocess.DEVNULL,
            )
            os.chown(database, 65532, 65532)
            _write_private(marker, session_id)
    finally:
        seed_credentials.unlink(missing_ok=True)
        _revoke_seed_token(identity)
        identity.pop("seedToken", None)
        identity.pop("seedTokenId", None)
    config = (
        "context_platforms:\n"
        "  - type: datahub-mcp\n"
        "    name: archon-datahub-mcp\n"
        "    transport: http\n"
        f"    url: {CONTAINER_READ_MCP_URL}\n"
        "engines:\n"
        "  - type: sqlite\n"
        "    name: archon_demo\n"
        "    connection:\n"
        "      dialect: sqlite\n"
        "      database: /var/lib/archon/demo/archon-demo.sqlite\n"
    )
    config_path = ANALYTICS_DIR / "config.yaml"
    _write_private(config_path, config)
    os.chown(config_path, 65532, 65532)

def _credential_context(lease: dict[str, Any], capability: str) -> dict[str, str]:
    return {
        "stage": _required("ARCHON_STAGE"),
        "sessionId": str(lease["sessionId"]),
        "generation": _required("ARCHON_RUNTIME_GENERATION"),
        "capabilityDigest": _required("ARCHON_RUNTIME_CAPABILITY_DIGEST"),
        "capability": capability,
    }


def _decrypt_scoped_credentials(
    lease: dict[str, Any], *, field_prefix: str, capability: str, version_pattern: str
) -> tuple[dict[str, str], str]:
    version = lease.get(f"{field_prefix}CredentialsVersion")
    ciphertext = lease.get(f"{field_prefix}CredentialsCiphertext")
    public_expiry = lease.get(f"{field_prefix}CredentialsExpiresAt")
    if (
        not isinstance(version, str)
        or re.fullmatch(version_pattern, version) is None
        or not isinstance(ciphertext, str)
        or len(ciphertext) > 32768
        or not isinstance(public_expiry, int)
        or isinstance(public_expiry, bool)
    ):
        raise RuntimeError(f"{field_prefix} credential lease binding is invalid")
    try:
        ciphertext_blob = base64.b64decode(ciphertext, validate=True)
    except ValueError as error:
        raise RuntimeError(f"{field_prefix} credential ciphertext is invalid") from error
    response = boto3.client("kms", region_name=_required("AWS_REGION")).decrypt(
        KeyId=_required("ARCHON_CORE_DATA_KEY_ARN"),
        CiphertextBlob=ciphertext_blob,
        EncryptionContext=_credential_context(lease, capability),
    )
    plaintext = response.get("Plaintext")
    if not isinstance(plaintext, bytes) or len(plaintext) > 16384:
        raise RuntimeError(f"{field_prefix} credential plaintext is invalid")
    value = json.loads(plaintext)
    if set(value) != {"accessKeyId", "secretAccessKey", "sessionToken", "expirationEpoch"}:
        raise RuntimeError(f"{field_prefix} credential schema is invalid")
    if (
        not all(
            isinstance(value[key], str) and 1 <= len(value[key]) <= 4096
            for key in ("accessKeyId", "secretAccessKey", "sessionToken")
        )
        or not value["accessKeyId"].startswith("ASIA")
        or value["expirationEpoch"] != public_expiry
        or public_expiry <= _epoch() + 300
    ):
        raise RuntimeError(f"{field_prefix} scoped credential is expired or inconsistent")
    return (
        {
            "AWS_ACCESS_KEY_ID": value["accessKeyId"],
            "AWS_SECRET_ACCESS_KEY": value["secretAccessKey"],
            "AWS_SESSION_TOKEN": value["sessionToken"],
        },
        version,
    )


def _analytics_env_values(
    scoped: dict[str, str], version: str, oauth_master_key: str
) -> dict[str, str]:
    model = _required("ARCHON_LLM_MODEL")
    region = _required("AWS_REGION")
    try:
        decoded_key = base64.urlsafe_b64decode(oauth_master_key.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise RuntimeError("Analytics OAuth master key is invalid") from error
    if (
        re.fullmatch(r"[A-Za-z0-9_-]{43}=", oauth_master_key) is None
        or len(decoded_key) != 32
    ):
        raise RuntimeError("Analytics OAuth master key is invalid")
    return {
        "ANALYTICS_AGENT_CONFIG_DIR": "/var/lib/archon/analytics",
        "ENGINES_CONFIG": "/var/lib/archon/analytics/config.yaml",
        "DATABASE_URL": "sqlite+aiosqlite:////var/lib/archon/analytics/state.sqlite",
        "OAUTH_MASTER_KEY": oauth_master_key,
        "LLM_PROVIDER": "bedrock",
        "LLM_MODEL": model,
        "CHART_LLM_MODEL": _required("ARCHON_CHART_LLM_MODEL"),
        "QUALITY_LLM_MODEL": _required("ARCHON_QUALITY_LLM_MODEL"),
        "DELIGHT_LLM_MODEL": _required("ARCHON_DELIGHT_LLM_MODEL"),
        "AWS_REGION": region,
        "AWS_DEFAULT_REGION": region,
        "DATAHUB_TELEMETRY_ENABLED": "false",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "",
        "ARCHON_ANALYTICS_CREDENTIAL_VERSION": version,
        **scoped,
    }

def _run_handle_key() -> str:
    path = RUNTIME / "run-handle.key"
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("run-handle key is not one regular file")
        value = path.read_text("ascii")
        try:
            decoded = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, TypeError) as error:
            raise RuntimeError("run-handle key is invalid") from error
        if len(value) != 44 or len(decoded) != 32:
            raise RuntimeError("run-handle key length is invalid")
        return value
    value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    _write_private(path, value)
    return value


def _analytics_oauth_master_key() -> str:
    """Keep one Fernet key only in the protected Analytics environment file."""
    if ANALYTICS_ENV.exists():
        if ANALYTICS_ENV.is_symlink() or not ANALYTICS_ENV.is_file():
            raise RuntimeError("Analytics environment is not one regular file")
        if stat.S_IMODE(ANALYTICS_ENV.stat().st_mode) != 0o600:
            raise RuntimeError("Analytics environment permissions are invalid")
        matches = [
            line.split("=", 1)[1]
            for line in ANALYTICS_ENV.read_text("utf-8").splitlines()
            if line.startswith("OAUTH_MASTER_KEY=")
        ]
        if len(matches) != 1:
            raise RuntimeError("Analytics OAuth master key is missing")
        value = matches[0]
    else:
        value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    try:
        decoded = base64.urlsafe_b64decode(value.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise RuntimeError("Analytics OAuth master key is invalid") from error
    if re.fullmatch(r"[A-Za-z0-9_-]{43}=", value) is None or len(decoded) != 32:
        raise RuntimeError("Analytics OAuth master key is invalid")
    return value


def _prepare_process_env(
    lease: dict[str, Any],
) -> tuple[Path, Path, Path, Path, Path, tuple[str, str]]:
    read_token, write_token = _credentials()
    read_env = RUNTIME / "read-mcp.env"
    writer_env = RUNTIME / "writer-mcp.env"
    companion_env = RUNTIME / "companion.env"
    gateway_env = RUNTIME / "governed-gateway.env"
    bedrock_scoped, analytics_version = _decrypt_scoped_credentials(
        lease, field_prefix="analytics", capability="analytics-agent-bedrock",
        version_pattern=r"^acv_[0-9a-f]{32}$",
    )
    gateway_scoped, gateway_version = _decrypt_scoped_credentials(
        lease, field_prefix="gateway", capability="governed-gateway-control",
        version_pattern=r"^gcv_[0-9a-f]{32}$",
    )
    _write_env(
        read_env,
        {
            "DATAHUB_GMS_URL": CONTAINER_GMS_URL,
            "DATAHUB_GMS_TOKEN": read_token,
            "FASTMCP_HOST": "0.0.0.0", "FASTMCP_PORT": "8000",
            "TOOLS_IS_MUTATION_ENABLED": "false", "SAVE_DOCUMENT_TOOL_ENABLED": "false",
            "TOOLS_IS_USER_ENABLED": "false", "DATA_QUALITY_TOOLS_ENABLED": "false",
            "DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED": "true", "SEMANTIC_SEARCH_ENABLED": "false",
            "DATAHUB_TELEMETRY_ENABLED": "false", "UPDATE_CHECK_ENABLED": "false",
        },
    )
    oauth_master_key = _analytics_oauth_master_key()
    _write_env(
        ANALYTICS_ENV,
        _analytics_env_values(bedrock_scoped, analytics_version, oauth_master_key),
    )
    model = _required("ARCHON_LLM_MODEL")
    region = _required("AWS_REGION")
    fernet_key = _run_handle_key()
    _write_env(
        companion_env,
        {
            "ARCHON_RUNTIME_PROFILE_ID": "core",
            "ARCHON_RUNTIME_GENERATION": _required("ARCHON_RUNTIME_GENERATION"),
            "ARCHON_RUNTIME_CAPABILITY_DIGEST": _required("ARCHON_RUNTIME_CAPABILITY_DIGEST"),
            "ARCHON_RUN_HANDLE_FERNET_KEY": fernet_key,
            "ARCHON_AGENT_STACK_LOCK": "/opt/archon/.github/locks/datahub-agent-stack.json",
            "ARCHON_DATAHUB_MCP_LOCK": "/opt/archon/.github/locks/datahub-mcp-v0.6.0.json",
            "ARCHON_DATAHUB_SKILLS_DIR": "/opt/archon/datahub-skills",
            "ARCHON_CUSTOM_SKILLS_DIR": "/opt/archon/contrib",
            "ARCHON_DATAHUB_MCP_URL": CONTAINER_READ_MCP_URL,
            "ARCHON_DATAHUB_MCP_CONNECTION": "archon-datahub-mcp",
            "ARCHON_ANALYTICS_AGENT_URL": CONTAINER_ANALYTICS_URL,
            "ARCHON_ANALYTICS_ENGINE": "archon_demo",
            "ARCHON_ANALYTICS_LLM_PROVIDER": "bedrock",
            "ARCHON_ANALYTICS_LLM_MODEL": model,
            "ARCHON_ANALYTICS_AWS_REGION": region,
            "ARCHON_DEMO_QUERY": _required("ARCHON_DEMO_QUERY"),
            "ARCHON_ANALYTICS_QUESTION": _required("ARCHON_ANALYTICS_QUESTION"),
            "DATAHUB_GMS_URL": CONTAINER_GMS_URL,
            "DATAHUB_GMS_TOKEN": read_token,
            "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
            "ARCHON_ANALYTICS_CREDENTIAL_VERSION": analytics_version,
            **bedrock_scoped,
        },
    )
    _write_env(
        writer_env,
        {
            "DATAHUB_GMS_URL": WRITER_GMS_URL, "DATAHUB_GMS_TOKEN": write_token,
            "FASTMCP_HOST": "0.0.0.0", "FASTMCP_PORT": "8002",
            "TOOLS_IS_MUTATION_ENABLED": "true", "SAVE_DOCUMENT_TOOL_ENABLED": "false",
            "TOOLS_IS_USER_ENABLED": "false", "DATA_QUALITY_TOOLS_ENABLED": "false",
            "DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED": "true", "SEMANTIC_SEARCH_ENABLED": "false",
            "DATAHUB_TELEMETRY_ENABLED": "false", "UPDATE_CHECK_ENABLED": "false",
        },
    )
    _write_env(
        gateway_env,
        {
            "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
            "ARCHON_STAGE": _required("ARCHON_STAGE"),
            "ARCHON_SESSION_ID": str(lease["sessionId"]),
            "ARCHON_RUNTIME_GENERATION": _required("ARCHON_RUNTIME_GENERATION"),
            "ARCHON_RUNTIME_CAPABILITY_DIGEST": _required("ARCHON_RUNTIME_CAPABILITY_DIGEST"),
            "ARCHON_MUTATION_SIGNING_KEY_ARN": _required("ARCHON_MUTATION_SIGNING_KEY_ARN"),
            "ARCHON_OFFICIAL_WRITER_MCP_URL": WRITER_MCP_URL,
            "CORE_LEASE_TABLE": _required("CORE_LEASE_TABLE"),
            "FASTMCP_HOST": "0.0.0.0", "FASTMCP_PORT": "8001",
            "ARCHON_GATEWAY_CREDENTIAL_VERSION": gateway_version,
            **gateway_scoped,
        },
    )
    return read_env, ANALYTICS_ENV, companion_env, writer_env, gateway_env, (analytics_version, gateway_version)

def _verify_datahub_images() -> None:
    inventory = DATAHUB_IMAGE_INVENTORY
    if inventory.is_symlink() or not inventory.is_file():
        raise RuntimeError("DataHub image inventory is not one regular file")
    raw = inventory.read_text("utf-8")
    if len(raw.encode("utf-8")) > 256 * 1024:
        raise RuntimeError("DataHub image inventory is too large")
    lines = raw.splitlines()
    if not 8 <= len(lines) <= 32:
        raise RuntimeError("DataHub image inventory count is invalid")

    references: set[str] = set()
    for line in lines:
        fields = line.split("\t")
        if len(fields) != 2:
            raise RuntimeError("DataHub image inventory entry is invalid")
        reference, expected = fields
        if (
            not reference
            or len(reference) > 512
            or any(character.isspace() for character in reference)
            or "@" in reference
            or reference in references
            or REPO_DIGEST_RE.fullmatch(expected) is None
        ):
            raise RuntimeError("DataHub image inventory entry is invalid")
        last_slash = reference.rfind("/")
        last_colon = reference.rfind(":")
        reference_repository = (
            reference[:last_colon]
            if last_colon > last_slash
            else reference
        )
        expected_repository = expected.rsplit("@", 1)[0]
        if not hmac.compare_digest(
            reference_repository, expected_repository
        ):
            raise RuntimeError("DataHub image repository binding is invalid")
        references.add(reference)
        result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{json .RepoDigests}}",
                reference,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        observed = json.loads(result.stdout)
        if (
            not isinstance(observed, list)
            or not all(isinstance(value, str) for value in observed)
            or expected not in observed
        ):
            raise RuntimeError(
                "DataHub runtime image differs from sealed AMI evidence"
            )

def _verified_image() -> str:
    expected = IMAGE_ID.read_text("utf-8").strip()
    if re.fullmatch(r"sha256:[a-f0-9]{64}", expected) is None:
        raise RuntimeError("sealed companion image ID is invalid")
    observed = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE_REF],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    ).stdout.strip()
    if not hmac.compare_digest(expected, observed):
        raise RuntimeError("loaded companion image differs from sealed AMI evidence")
    return IMAGE_REF


def _container(
    name: str,
    env_file: Path,
    published_port: int | None,
    networks: tuple[tuple[str, str | None], ...],
    command: list[str],
    mounts: tuple[tuple[Path, str, bool], ...] = (),
) -> None:
    if published_port is not None and published_port not in {8000, 8001, 8080, 8100}:
        raise RuntimeError("container publication is outside the loopback allowlist")
    if not networks or any(network == "archon-core_default" for network, _ in networks):
        raise RuntimeError("agent containers require dedicated sealed networks")
    subprocess.run(
        ["docker", "rm", "--force", name], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
    )
    arguments = [
        "docker", "create", "--name", name, "--network", "none",
        "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "256",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=268435456",
        "--log-driver", "local", "--log-opt", "max-size=10m",
        "--log-opt", "max-file=2", "--env-file", str(env_file),
    ]
    if published_port is not None:
        arguments.extend(["--publish", f"127.0.0.1:{published_port}:{published_port}"])
    for source, target, read_only in mounts:
        spec = f"type=bind,src={source},dst={target}"
        if read_only:
            spec += ",readonly"
        arguments.extend(["--mount", spec])
    arguments.extend([_verified_image(), *command])
    subprocess.run(arguments, cwd=ROOT, check=True, timeout=60)
    try:
        for network, alias in networks:
            _connect_network(name, network, alias)
        process = subprocess.Popen(
            ["docker", "start", "--attach", name], cwd=ROOT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
    except Exception:
        subprocess.run(
            ["docker", "rm", "--force", name], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )
        raise
    PROCESSES[name] = process


def _start_writer(writer_env: Path) -> None:
    _container(
        "archon-writer-mcp", writer_env, None,
        ((WRITER_NETWORK, "archon-writer-mcp"),),
        ["/opt/archon/mcp/.venv/bin/mcp-server-datahub", "--transport", "http"],
    )


def _start_gateway(gateway_env: Path) -> None:
    _container(
        "archon-governed-gateway", gateway_env, 8001,
        ((WRITER_NETWORK, "archon-governed-gateway"), (GATEWAY_EGRESS_NETWORK, None)),
        [
            "/opt/archon/companion/.venv/bin/python", "-m", "uvicorn",
            "--app-dir", "/opt/archon", "governed_gateway:app",
            "--host", "0.0.0.0", "--port", "8001", "--no-access-log",
        ],
        ((ROOT / "governed_gateway.py", "/opt/archon/governed_gateway.py", True),),
    )


def _start_analytics(analytics_env: Path) -> None:
    _container(
        "archon-analytics", analytics_env, 8100,
        ((READ_NETWORK, "archon-analytics"), (BEDROCK_EGRESS_NETWORK, None)),
        [
            "/opt/archon/companion/.venv/bin/python", "-m", "uvicorn",
            "analytics_agent.main:app", "--host", "0.0.0.0", "--port", "8100",
            "--no-access-log",
        ],
        ((ANALYTICS_DIR, "/var/lib/archon/analytics", False), (DEMO_DIR, "/var/lib/archon/demo", True)),
    )


def _start_companion(companion_env: Path) -> None:
    _container(
        "archon-companion", companion_env, 8080,
        ((READ_NETWORK, "archon-companion"), (BEDROCK_EGRESS_NETWORK, None)),
        [
            "/opt/archon/companion/.venv/bin/python", "-m", "uvicorn",
            "archon_companion:app", "--host", "0.0.0.0", "--port", "8080",
            "--no-access-log",
        ],
    )


def _refresh_scoped_credentials(
    lease: dict[str, Any], current_versions: tuple[str, str]
) -> tuple[str, str]:
    next_versions = (
        lease.get("analyticsCredentialsVersion"), lease.get("gatewayCredentialsVersion")
    )
    if next_versions == current_versions:
        return current_versions
    if not all(isinstance(value, str) for value in next_versions):
        raise RuntimeError("rotated scoped credential versions are invalid")
    _, analytics_env, companion_env, _, gateway_env, exact_versions = _prepare_process_env(lease)
    _start_analytics(analytics_env)
    _start_companion(companion_env)
    _start_gateway(gateway_env)
    return exact_versions


def _start_components(
    lease: dict[str, Any]
) -> tuple[tuple[str, str], dict[str, Any]]:
    _verify_datahub_images()
    _isolate_container_network()
    _prepare_compose_env()
    _compose("up", "-d", "--no-build", "--remove-orphans")
    _attach_gms_networks()
    _wait_for_datahub()
    identity = _mint_datahub_tokens(str(lease["sessionId"]))
    _seed_and_configure(str(lease["sessionId"]), identity)
    read_env, analytics_env, companion_env, writer_env, gateway_env, versions = _prepare_process_env(lease)
    subprocess.run(
        ["systemctl", "stop", "archon-governed-gateway.service"], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
    )
    _start_writer(writer_env)
    _start_gateway(gateway_env)
    _container(
        "archon-read-mcp", read_env, 8000, ((READ_NETWORK, "archon-read-mcp"),),
        ["/opt/archon/mcp/.venv/bin/mcp-server-datahub", "--transport", "http"],
    )
    _start_analytics(analytics_env)
    _start_companion(companion_env)
    authority = {
        "sessionId": str(lease["sessionId"]),
        "readActorUrn": identity["readActorUrn"],
        "writerActorUrn": identity["writerActorUrn"],
        "writerPolicyUrn": identity["writerPolicyUrn"],
        "writerPolicy": identity["writerPolicy"],
    }
    identity.clear()
    return versions, authority

def _mcp_probe(
    container: str, url: str, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    script = r"""
import asyncio, json, sys
from fastmcp import Client
value = json.loads(sys.stdin.buffer.read(65536))
async def main():
    try:
        async with Client(value["url"]) as client:
            response = await client.call_tool(value["tool"], value["arguments"])
        data = getattr(response, "data", None)
        if data is None:
            data = getattr(response, "structured_content", None)
        if data is None:
            texts = [getattr(block, "text", None) for block in getattr(response, "content", [])]
            data = [text for text in texts if isinstance(text, str)]
        print(json.dumps({"isError": bool(getattr(response, "is_error", False)), "payload": data}, default=str, separators=(",", ":")))
    except Exception:
        print(json.dumps({"raised": True}, separators=(",", ":")))
asyncio.run(main())
"""
    completed = subprocess.run(
        [
            "docker", "exec", "--user", "65532:65532", "--interactive", container,
            "/opt/archon/mcp/.venv/bin/python", "-c", script,
        ],
        input=_canonical({"url": url, "tool": tool, "arguments": arguments}),
        check=True, capture_output=True, timeout=45,
    )
    if len(completed.stdout) > 128 * 1024:
        raise RuntimeError("MCP preflight response exceeded the bound")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict) or not set(value).issubset({"raised", "isError", "payload"}):
        raise RuntimeError("MCP preflight response schema drifted")
    return value


def _probe_ok(value: dict[str, Any]) -> bool:
    if value.get("raised") is True or value.get("isError") is True:
        return False
    payload = value.get("payload")
    if isinstance(payload, dict) and payload.get("success") is False:
        return False
    return True


def _probe_payload(value: dict[str, Any]) -> Any:
    payload = value.get("payload")
    if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], str):
        payload = payload[0]
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except ValueError:
            return payload
    return payload


def _column_tag_state(value: Any) -> dict[str, Any]:
    found = False
    tags: set[str] = set()

    def walk(node: Any, within_column: bool = False) -> None:
        nonlocal found
        if isinstance(node, list):
            for child in node:
                walk(child, within_column)
            return
        if not isinstance(node, dict):
            return
        if any(node.get(key) == "customer_email" for key in ("fieldPath", "columnPath", "path")):
            found = True
            within_column = True
        for child in node.values():
            if within_column and isinstance(child, str) and child.startswith("urn:li:tag:"):
                tags.add(child)
            else:
                walk(child, within_column)

    walk(value)
    if not found:
        raise RuntimeError("RBAC preflight did not find the canonical column")
    state = {"entityUrn": SOURCE_URN, "columnPath": "customer_email", "tagUrns": sorted(tags)}
    return {**state, "stateDigest": _digest(state)}


def _wait_read_state(expected_tags: list[str]) -> dict[str, Any]:
    deadline = time.monotonic() + 45
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        response = _mcp_probe(
            "archon-read-mcp", "http://127.0.0.1:8000/mcp", "get_entities",
            {"urns": [SOURCE_URN]},
        )
        if _probe_ok(response):
            last = _column_tag_state(_probe_payload(response))
            if last["tagUrns"] == expected_tags:
                return last
        time.sleep(2)
    raise RuntimeError(f"RBAC live read did not converge: {last}")


def _assert_writer_network_boundary() -> None:
    writer_ip = subprocess.run(
        [
            "docker", "inspect", "--format",
            '{{with index .NetworkSettings.Networks "archon-writer"}}{{.IPAddress}}{{end}}',
            "archon-writer-mcp",
        ],
        check=True, capture_output=True, text=True, timeout=20,
    ).stdout.strip()
    if re.fullmatch(r"^172\.28\.71\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$", writer_ip) is None:
        raise RuntimeError("writer address is outside the sealed bridge")
    for host in ("127.0.0.1", writer_ip):
        try:
            connection = socket.create_connection((host, 8002), timeout=2)
        except OSError:
            continue
        connection.close()
        raise RuntimeError("host reached the ungoverned writer MCP")
    denial_script = (
        "import socket; socket.create_connection(('archon-writer-mcp',8002),2)"
    )
    for container in ("archon-read-mcp", "archon-analytics", "archon-companion"):
        denied = subprocess.run(
            [
                "docker", "exec", "--user", "65532:65532", container,
                "/opt/archon/mcp/.venv/bin/python", "-c", denial_script,
            ],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        if denied.returncode == 0:
            raise RuntimeError(f"{container} reached the ungoverned writer MCP")


def _rbac_preflight(identity: dict[str, Any]) -> None:
    pii = "urn:li:tag:PII"
    exact_arguments = {
        "tag_urns": [pii], "entity_urns": [SOURCE_URN],
        "column_paths": ["customer_email"],
    }
    initial = _wait_read_state([])
    read_mutation = _mcp_probe(
        "archon-read-mcp", "http://127.0.0.1:8000/mcp", "add_tags", exact_arguments
    )
    if _probe_ok(read_mutation):
        _mcp_probe(
            "archon-writer-mcp", "http://127.0.0.1:8002/mcp", "remove_tags", exact_arguments
        )
        raise RuntimeError("read-only MCP unexpectedly accepted a mutation")
    added = _mcp_probe(
        "archon-writer-mcp", "http://127.0.0.1:8002/mcp", "add_tags", exact_arguments
    )
    if not _probe_ok(added):
        raise RuntimeError("governed writer service account could not add the exact PII tag")
    tagged = _wait_read_state([pii])
    removed = _mcp_probe(
        "archon-writer-mcp", "http://127.0.0.1:8002/mcp", "remove_tags", exact_arguments
    )
    if not _probe_ok(removed):
        raise RuntimeError("governed writer service account could not remove the exact PII tag")
    final = _wait_read_state([])
    if not hmac.compare_digest(initial["stateDigest"], final["stateDigest"]):
        raise RuntimeError("RBAC preflight did not restore the initial tag state")
    unsigned = _mcp_probe(
        "archon-governed-gateway", "http://127.0.0.1:8001/mcp",
        "execute_governed_mutation", {"job_id": "job_" + "U" * 22, "request": {}},
    )
    if _probe_ok(unsigned):
        raise RuntimeError("governed gateway accepted an unsigned request")
    _assert_writer_network_boundary()
    policy = identity["writerPolicy"]
    proof = {
        "schemaVersion": "archon.datahub-core-rbac-preflight/v1",
        "sessionId": identity["sessionId"],
        "readActorUrn": identity["readActorUrn"],
        "writerActorUrn": identity["writerActorUrn"],
        "writerPolicyUrn": identity["writerPolicyUrn"],
        "writerPolicyDigest": _digest(policy),
        "resourceUrn": SOURCE_URN,
        "columnPath": "customer_email",
        "tagUrn": pii,
        "readMutationDenied": True,
        "writerRoundTripVerified": True,
        "gatewayUnsignedDenied": True,
        "hostAndAgentDirectWriterDenied": True,
        "initialStateDigest": initial["stateDigest"],
        "taggedStateDigest": tagged["stateDigest"],
        "finalStateDigest": final["stateDigest"],
        "checkedAt": _iso(),
    }
    _write_private(
        RUNTIME / "datahub-rbac-preflight.json",
        json.dumps({**proof, "proofDigest": _digest(proof)}, sort_keys=True, separators=(",", ":")) + "\n",
    )

def _assert_analytics_token_not_at_rest() -> None:
    """Fail closed if the read PAT is present in Analytics persistent state."""
    read_token, _ = _credentials()
    needle = read_token.encode("utf-8")
    if not needle or len(needle) > 8192:
        raise RuntimeError("read credential is invalid for at-rest verification")
    state = ANALYTICS_DIR / "state.sqlite"
    if state.is_symlink() or not state.is_file():
        raise RuntimeError("Analytics state database is not one regular file")
    scanned: list[dict[str, Any]] = []
    for path in (
        state,
        ANALYTICS_DIR / "state.sqlite-wal",
        ANALYTICS_DIR / "state.sqlite-shm",
    ):
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"Analytics state artifact {path.name} is invalid")
        size = path.stat().st_size
        if size > 256 * 1024 * 1024:
            raise RuntimeError(f"Analytics state artifact {path.name} exceeds its bound")
        if needle in path.read_bytes():
            raise RuntimeError(
                f"plaintext DataHub read credential found in {path.name}"
            )
        scanned.append({"name": path.name, "size": size})
    proof = {
        "schemaVersion": "archon.analytics-credential-at-rest-proof/v1",
        "oauthMasterKeyValidated": True,
        "plaintextReadTokenPresent": False,
        "files": scanned,
        "checkedAt": _iso(),
    }
    _write_private(
        RUNTIME / "analytics-credential-at-rest-proof.json",
        json.dumps(
            {**proof, "proofDigest": _digest(proof)},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )


def _components_ready() -> bool:
    checks = (
        (GMS_URL + "/health", None),
        ("http://127.0.0.1:8000/health", "ok"),
        ("http://127.0.0.1:8001/health", "ok"),
        (ANALYTICS_URL + "/health", None),
        (COMPANION_URL + "/livez", None),
        (COMPANION_URL + "/healthz", None),
    )
    for url, required_status in checks:
        status, raw = _request(url, timeout=35)
        if status != 200:
            return False
        if required_status is not None:
            try:
                body = json.loads(raw)
            except ValueError:
                return False
            if body.get("status") != required_status:
                return False
    processes_ready = (
        len(PROCESSES) == len(CONTAINER_NAMES)
        and set(PROCESSES) == set(CONTAINER_NAMES)
        and all(process.poll() is None for process in PROCESSES.values())
    )
    if not processes_ready:
        return False
    _assert_analytics_token_not_at_rest()
    return True

def _model_ready(lease: dict[str, Any]) -> bool:
    """Require and seal a real bounded Bedrock Converse round trip."""
    if _required("ARCHON_LLM_PROVIDER") != "bedrock":
        return False
    model = _required("ARCHON_LLM_MODEL")
    region = _required("AWS_REGION")
    try:
        scoped, _ = _decrypt_scoped_credentials(
            lease, field_prefix="analytics", capability="analytics-agent-bedrock",
            version_pattern=r"^acv_[0-9a-f]{32}$",
        )
        response = boto3.client(
            "bedrock-runtime",
            region_name=region,
            aws_access_key_id=scoped["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=scoped["AWS_SECRET_ACCESS_KEY"],
            aws_session_token=scoped["AWS_SESSION_TOKEN"],
        ).converse(
            modelId=model,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"text": "Connectivity probe. Reply with the single token OK."}
                    ],
                }
            ],
            inferenceConfig={"maxTokens": 4, "temperature": 0},
        )
        content = response.get("output", {}).get("message", {}).get("content", [])
        request_id = response.get("ResponseMetadata", {}).get("RequestId", "")
        if (
            not isinstance(request_id, str)
            or not request_id
            or len(request_id) > 256
            or not any(
                isinstance(block, dict)
                and isinstance(block.get("text"), str)
                and bool(block["text"].strip())
                for block in content
            )
        ):
            return False
        proof = {
            "schemaVersion": "archon.bedrock-runtime-preflight/v1",
            "provider": "bedrock",
            "model": model,
            "region": region,
            "responseId": request_id,
            "checkedAt": _iso(),
        }
        _write_private(
            RUNTIME / "bedrock-preflight.json",
            json.dumps(
                {**proof, "proofDigest": _digest(proof)},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
        return True
    except (BotoCoreError, ClientError, OSError, TypeError, ValueError):
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
    except OSError as error:
        LOGGER.warning(
            "IMDS instance-id lookup failed; publishing an unknown instance ID",
            exc_info=error,
        )
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
    subprocess.run(
        ["systemctl", "stop", "archon-governed-gateway.service"],
        check=False,
        timeout=30,
    )
    for process in PROCESSES.values():
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                LOGGER.info(
                    "component process %s exited before SIGTERM", process.pid
                )
    deadline = time.monotonic() + 20
    for process in PROCESSES.values():
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    LOGGER.info(
                        "component process %s exited before SIGKILL", process.pid
                    )
    for name in CONTAINER_NAMES:
        subprocess.run(
            ["docker", "rm", "--force", name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    if COMPOSE_ENV.exists():
        _compose("down", "--volumes", "--remove-orphans", check=False, timeout=180)


def main() -> int:
    global TABLE
    for name in REQUIRED:
        _required(name)
    if _required("ARCHON_DEMO_QUERY") != SOURCE_URN:
        return 18
    if _required("ARCHON_ANALYTICS_QUESTION") != EXPECTED_QUESTION:
        return 19
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

    _prepare_runtime()
    try:
        credential_versions, datahub_authority = _start_components(lease)
        ready_deadline = min(
            time.monotonic() + 20 * 60,
            time.monotonic() + max(1, int(lease["hardExpiresAt"]) - _epoch()),
        )
        model_ready = False
        rbac_ready = False
        next_model_probe = 0.0
        while time.monotonic() < ready_deadline:
            components_ready = _components_ready()
            if components_ready and time.monotonic() >= next_model_probe:
                model_ready = _model_ready(lease)
                next_model_probe = time.monotonic() + 15
            if components_ready and model_ready and not rbac_ready:
                _rbac_preflight(datahub_authority)
                rbac_ready = True
            if components_ready and model_ready and rbac_ready:
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
            credential_versions = _refresh_scoped_credentials(
                current, credential_versions
            )
            adapter.process_once()
            if time.monotonic() >= next_health:
                if time.monotonic() >= next_model_health:
                    model_healthy = _model_ready(current)
                    next_model_health = time.monotonic() + 300
                healthy = _components_ready() and model_healthy
                _publish_health(current, "READY" if healthy else "UNHEALTHY")
                next_health = time.monotonic() + 30
            time.sleep(2)
    except Exception:
        LOGGER.exception("DataHub Core supervisor failed")
        _mark_failed(lease)
        return 22
    finally:
        _stop_components()


if __name__ == "__main__":
    sys.exit(main())