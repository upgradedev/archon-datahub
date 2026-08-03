"""Secret-safe HTTP, MCP, and AWS clients for the DataHub Cloud trial workflow."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

MAX_RESPONSE_BYTES = 262_144
MCP_PROTOCOL_VERSION = "2025-06-18"
TENANT_HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.acryl\.io$"
)
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
STAGE = re.compile(r"^(staging|production)$")
RUN_ID = re.compile(r"^[1-9][0-9]{0,19}$")
SESSION_ID = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")


class TrialError(RuntimeError):
    """A deliberately sanitized operational failure."""


class DataHubHttpStatusError(TrialError):
    """A sanitized provider status that remains distinct from transport failure."""

    def __init__(self, status: int) -> None:
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise TrialError("DataHub Cloud status failed policy")
        super().__init__("DataHub Cloud returned a non-success status")
        self.status = status


class McpCallDenied(TrialError):
    """Expected authorization or tool-surface denial."""


AUTHORIZATION_DENIAL = re.compile(
    r"\b(?:access\s+denied|authorization\s+(?:failed|required)|forbidden|"
    r"insufficient\s+(?:permission|permissions|privilege|privileges)|"
    r"not\s+authorized|permission\s+denied|unauthorized)\b",
    re.IGNORECASE,
)
SECRET_VERSION_ID = re.compile(r"^[A-Za-z0-9-]{32,64}$")
SECRET_STAGE = re.compile(r"^[A-Za-z0-9/_+=.@-]{1,256}$")
TRIAL_STAGE = re.compile(r"^archon-trial-[1-9][0-9]{0,19}-[1-9][0-9]{0,19}$")


def _explicit_authorization_denial(value: Any) -> bool:
    """Accept only provider text that explicitly names an authorization denial."""
    candidates: list[str] = []
    if isinstance(value, dict):
        for key in ("message", "error", "detail", "reason"):
            item = value.get(key)
            if isinstance(item, str):
                candidates.append(item)
        data = value.get("data")
        if isinstance(data, str):
            candidates.append(data)
        elif isinstance(data, dict):
            for key in ("message", "error", "detail", "reason"):
                item = data.get(key)
                if isinstance(item, str):
                    candidates.append(item)
        content = value.get("content")
        if isinstance(content, list):
            for item in content[:20]:
                if (
                    isinstance(item, dict)
                    and item.get("type") == "text"
                    and isinstance(item.get("text"), str)
                ):
                    candidates.append(item["text"])
    return any(
        len(candidate.encode("utf-8")) <= 16 * 1024
        and AUTHORIZATION_DENIAL.search(candidate) is not None
        for candidate in candidates
    )


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class CloudEndpoints:
    gms_url: str
    graphql_path: str
    mcp_path: str
    host: str


@dataclass(frozen=True)
class StagedSecret:
    secret_arn: str
    version_id: str
    previous_current: str | None
    stage_label: str


def cloud_endpoints(gms_url: str) -> CloudEndpoints:
    parsed = urlparse(gms_url)
    try:
        port = parsed.port
    except ValueError:
        raise TrialError("DataHub Cloud endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or port not in (None, 443)
        or not isinstance(parsed.hostname, str)
        or TENANT_HOST.fullmatch(parsed.hostname) is None
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/", "/gms")
    ):
        raise TrialError("DataHub Cloud endpoint is outside the tenant allowlist")
    return CloudEndpoints(
        gms_url=f"https://{parsed.hostname}/gms",
        graphql_path="/api/graphql",
        mcp_path="/integrations/ai/mcp",
        host=parsed.hostname,
    )


def validate_credential(value: str, label: str) -> None:
    if (
        not value
        or len(value) > 8192
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise TrialError(f"{label} credential policy failed")


def contains_exact(value: Any, expected: str, limit: int = 10_000) -> bool:
    pending = [value]
    reviewed = 0
    while pending:
        current = pending.pop()
        reviewed += 1
        if reviewed > limit:
            raise TrialError("provider response exceeded traversal policy")
        if isinstance(current, str):
            if current == expected:
                return True
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
    return False


def _read_bounded(response: http.client.HTTPResponse) -> bytes:
    data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise TrialError("provider response exceeded byte policy")
    return data


class _Https:
    def __init__(self, host: str, token: str) -> None:
        if TENANT_HOST.fullmatch(host) is None:
            raise TrialError("DataHub Cloud host policy failed")
        validate_credential(token, "DataHub")
        self._host = host
        self._token = token

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        accepted: set[int] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        if method not in {"POST", "DELETE"} or not path.startswith("/"):
            raise TrialError("outbound request policy failed")
        body = b"" if payload is None else canonical_bytes(payload)
        request_headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "archon-datahub-cloud-trial/1.0",
        }
        if headers:
            request_headers.update(headers)
        connection = http.client.HTTPSConnection(
            self._host,
            port=443,
            timeout=30,
            context=ssl.create_default_context(),
        )
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            data = _read_bounded(response)
            normalized_headers = {
                key.lower(): value for key, value in response.getheaders()
            }
            allowed = accepted if accepted is not None else {200}
            if response.status not in allowed:
                raise DataHubHttpStatusError(response.status)
            return response.status, normalized_headers, data
        except (OSError, http.client.HTTPException):
            raise TrialError("DataHub Cloud transport failed") from None
        finally:
            connection.close()


class GraphQLClient:
    def __init__(self, endpoints: CloudEndpoints, token: str) -> None:
        self._http = _Https(endpoints.host, token)
        self._path = endpoints.graphql_path

    def execute(
        self,
        operation: str,
        document: str,
        variables: dict[str, Any],
    ) -> dict[str, Any]:
        _, headers, body = self._http.request(
            "POST",
            self._path,
            payload={
                "operationName": operation,
                "query": document,
                "variables": variables,
            },
        )
        if headers.get("content-type", "").split(";", 1)[0] != "application/json":
            raise TrialError(f"{operation} returned an unexpected media type")
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError(f"{operation} returned invalid JSON") from None
        if (
            not isinstance(decoded, dict)
            or decoded.get("errors")
            or not isinstance(decoded.get("data"), dict)
        ):
            raise TrialError(f"{operation} was rejected")
        return decoded["data"]


def _decode_mcp(body: bytes, content_type: str, request_id: int) -> dict[str, Any]:
    media_type = content_type.split(";", 1)[0]
    messages: list[Any] = []
    if media_type == "application/json":
        try:
            messages = [json.loads(body)]
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("MCP returned invalid JSON") from None
    elif media_type == "text/event-stream":
        try:
            text = body.decode("utf-8", errors="strict").replace("\r\n", "\n")
        except UnicodeDecodeError:
            raise TrialError("MCP returned invalid SSE") from None
        if "\r" in text or not text.endswith("\n\n"):
            raise TrialError("MCP SSE framing failed")
        for block in text.split("\n\n"):
            if not block:
                continue
            fields = []
            for line in block.split("\n"):
                if line.startswith(":"):
                    continue
                name, separator, value = line.partition(":")
                if not separator:
                    raise TrialError("MCP SSE field failed")
                if value.startswith(" "):
                    value = value[1:]
                if name == "data":
                    fields.append(value)
                elif name == "event" and value == "message":
                    continue
                else:
                    raise TrialError("MCP SSE field failed")
            if fields:
                try:
                    messages.append(json.loads("\n".join(fields)))
                except json.JSONDecodeError:
                    raise TrialError("MCP SSE JSON failed") from None
    else:
        raise TrialError("MCP returned an unexpected media type")
    matches = [
        item
        for item in messages
        if isinstance(item, dict) and item.get("id") == request_id
    ]
    if len(matches) != 1:
        raise TrialError("MCP response binding failed")
    return matches[0]


class McpClient:
    def __init__(self, endpoints: CloudEndpoints, token: str, client_name: str) -> None:
        self._http = _Https(endpoints.host, token)
        self._path = endpoints.mcp_path
        self._client_name = client_name
        self._session: str | None = None
        self._next_id = 1

    def _rpc(
        self,
        method: str,
        params: dict[str, Any],
        *,
        allow_denial: bool = False,
    ) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        headers = {"Accept": "application/json, text/event-stream"}
        if method != "initialize":
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        if self._session is not None:
            headers["Mcp-Session-Id"] = self._session
        try:
            _, response_headers, body = self._http.request(
                "POST",
                self._path,
                payload={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                },
                headers=headers,
            )
        except DataHubHttpStatusError as error:
            if allow_denial and error.status == 403:
                raise McpCallDenied("MCP mutation denied by provider authorization")
            raise
        message = _decode_mcp(
            body,
            response_headers.get("content-type", ""),
            request_id,
        )
        error = message.get("error")
        if error is not None:
            if allow_denial and _explicit_authorization_denial(error):
                raise McpCallDenied(
                    "MCP mutation explicitly denied by provider authorization"
                )
            raise TrialError("MCP JSON-RPC operation failed")
        result = message.get("result")
        if not isinstance(result, dict):
            raise TrialError("MCP result contract failed")
        if result.get("isError") is True:
            if allow_denial and _explicit_authorization_denial(result):
                raise McpCallDenied(
                    "MCP mutation explicitly denied by tool authorization"
                )
            raise TrialError("MCP tool operation failed")
        assigned = response_headers.get("mcp-session-id")
        if method == "initialize" and assigned is not None:
            if SESSION_ID.fullmatch(assigned) is None:
                raise TrialError("MCP session identifier failed policy")
            self._session = assigned
        elif assigned is not None and assigned != self._session:
            raise TrialError("MCP session binding failed")
        return result

    def initialize(self) -> dict[str, Any]:
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self._client_name, "version": "1.0.0"},
            },
        )
        if (
            result.get("protocolVersion") != MCP_PROTOCOL_VERSION
            or not isinstance(result.get("serverInfo"), dict)
            or not isinstance(result.get("capabilities"), dict)
        ):
            raise TrialError("MCP initialize contract failed")
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        }
        if self._session is not None:
            headers["Mcp-Session-Id"] = self._session
        self._http.request(
            "POST",
            self._path,
            payload={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
            accepted={202, 204},
        )
        return {
            "name": str(result["serverInfo"].get("name", ""))[:128],
            "version": str(result["serverInfo"].get("version", ""))[:128],
        }

    def tools(self) -> dict[str, dict[str, Any]]:
        inventory: dict[str, dict[str, Any]] = {}
        cursor: str | None = None
        for _ in range(10):
            params = {} if cursor is None else {"cursor": cursor}
            result = self._rpc("tools/list", params)
            tools = result.get("tools")
            if not isinstance(tools, list) or len(tools) > 100:
                raise TrialError("MCP tool inventory failed")
            for item in tools:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    raise TrialError("MCP tool schema failed")
                name = item["name"]
                if name in inventory:
                    raise TrialError("MCP duplicate tool failed")
                inventory[name] = item
            cursor = result.get("nextCursor")
            if cursor is None:
                return inventory
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512:
                raise TrialError("MCP cursor failed")
        raise TrialError("MCP pagination exceeded policy")

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        allow_denial: bool = False,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise TrialError("MCP tool name failed policy")
        return self._rpc(
            "tools/call",
            {"name": name, "arguments": arguments},
            allow_denial=allow_denial,
        )

    def close(self) -> None:
        if self._session is None:
            return
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "Mcp-Session-Id": self._session,
        }
        try:
            self._http.request(
                "DELETE",
                self._path,
                headers=headers,
                accepted={200, 202, 204, 404, 405},
            )
        finally:
            self._session = None

    def __enter__(self) -> "McpClient":
        self.initialize()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AwsSecretWriter:
    READER_SCHEMA = "archon.datahub-cloud-reader-secret/v1"
    WRITER_SCHEMA = "archon.datahub-cloud-writer-secret/v1"
    REVOKED_SCHEMA = "archon.datahub-cloud-credential-state/v1"

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        stage: str,
        stack_name: str,
    ) -> None:
        if ACCOUNT_ID.fullmatch(account_id) is None:
            raise TrialError("AWS account identifier failed policy")
        if region != "eu-west-1" or STAGE.fullmatch(stage) is None:
            raise TrialError("AWS region or stage failed policy")
        if stack_name != f"Archon-{stage}-Judge":
            raise TrialError("AWS stack name failed policy")
        self.account_id = account_id
        self.region = region
        self.stage = stage
        self.stack_name = stack_name

    @staticmethod
    def _run(arguments: list[str], stdin: bytes | None = None) -> bytes:
        environment = dict(os.environ)
        environment["AWS_PAGER"] = ""
        completed = subprocess.run(
            ["aws", *arguments],
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        if completed.returncode != 0:
            raise TrialError("AWS secret operation failed")
        return completed.stdout

    def bindings(self) -> tuple[str, str, str]:
        caller = self._run(
            ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]
        )
        try:
            caller_document = json.loads(caller)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS caller response failed") from None
        if caller_document.get("Account") != self.account_id:
            raise TrialError("AWS caller account binding failed")
        stack = self._run(
            [
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                self.stack_name,
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ]
        )
        try:
            document = json.loads(stack)
            stacks = document["Stacks"]
            outputs = {
                item["OutputKey"]: item["OutputValue"]
                for item in stacks[0]["Outputs"]
            }
        except (KeyError, IndexError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS stack output contract failed") from None
        if len(stacks) != 1:
            raise TrialError("AWS stack cardinality failed")
        read_arn = outputs.get("ArchonCloudReaderSecretArn", "")
        write_arn = outputs.get("ArchonCloudWriterSecretArn", "")
        key_arn = outputs.get("ArchonSecretsKeyArn", "")
        secret_prefix = (
            f"arn:aws:secretsmanager:{self.region}:{self.account_id}:"
            f"secret:archon/{self.stage}/datahub-cloud/"
        )
        if (
            not read_arn.startswith(secret_prefix + "reader-")
            or not write_arn.startswith(secret_prefix + "writer-")
            or read_arn == write_arn
            or re.fullmatch(
                rf"arn:aws:kms:{self.region}:{self.account_id}:"
                r"key/[0-9a-f-]{36}",
                key_arn,
            )
            is None
        ):
            raise TrialError("AWS DataHub secret or key binding failed")
        key = self._run(
            [
                "kms",
                "describe-key",
                "--key-id",
                f"alias/archon/{self.stage}/judge-secrets",
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ]
        )
        try:
            metadata = json.loads(key)["KeyMetadata"]
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS Judge secrets key response failed") from None
        if (
            metadata.get("Arn") != key_arn
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or metadata.get("Origin") != "AWS_KMS"
            or metadata.get("MultiRegion") is not False
        ):
            raise TrialError("AWS Judge secrets key posture failed")
        return read_arn, write_arn, key_arn

    def _version_stages(self, secret_arn: str) -> dict[str, tuple[str, ...]]:
        response = self._run(
            [
                "secretsmanager",
                "describe-secret",
                "--secret-id",
                secret_arn,
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ]
        )
        try:
            document = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS secret description failed") from None
        versions = document.get("VersionIdsToStages", {})
        if document.get("ARN") != secret_arn or not isinstance(versions, dict):
            raise TrialError("AWS secret description contract failed")
        normalized: dict[str, tuple[str, ...]] = {}
        for version_id, stages in versions.items():
            if (
                not isinstance(version_id, str)
                or SECRET_VERSION_ID.fullmatch(version_id) is None
                or not isinstance(stages, list)
                or len(stages) > 20
                or any(
                    not isinstance(stage, str)
                    or SECRET_STAGE.fullmatch(stage) is None
                    for stage in stages
                )
                or len(set(stages)) != len(stages)
            ):
                raise TrialError("AWS secret version-stage contract failed")
            normalized[version_id] = tuple(stages)
        if (
            sum("AWSCURRENT" in stages for stages in normalized.values()) > 1
            or sum("AWSPREVIOUS" in stages for stages in normalized.values()) > 1
        ):
            raise TrialError("AWS secret version-stage uniqueness failed")
        return normalized

    def _current_version(self, secret_arn: str) -> str | None:
        current = [
            version_id
            for version_id, stages in self._version_stages(secret_arn).items()
            if "AWSCURRENT" in stages
        ]
        return None if not current else current[0]

    @staticmethod
    def staging_label(run_id: str, run_attempt: str) -> str:
        label = f"archon-trial-{run_id}-{run_attempt}"
        if (
            RUN_ID.fullmatch(run_id) is None
            or RUN_ID.fullmatch(run_attempt) is None
            or TRIAL_STAGE.fullmatch(label) is None
        ):
            raise TrialError("workflow staging label failed policy")
        return label

    def _current_secret_string(self, secret_arn: str) -> str | None:
        current_version = self._current_version(secret_arn)
        if current_version is None:
            return None
        response = self._run(
            [
                "secretsmanager",
                "get-secret-value",
                "--secret-id",
                secret_arn,
                "--version-stage",
                "AWSCURRENT",
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ]
        )
        try:
            document = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS reader secret response failed") from None
        value = document.get("SecretString")
        stages = document.get("VersionStages")
        if (
            document.get("ARN") != secret_arn
            or document.get("VersionId") != current_version
            or not isinstance(value, str)
            or not 1 <= len(value.encode("utf-8")) <= 16 * 1024
            or not isinstance(stages, list)
            or "AWSCURRENT" not in stages
            or document.get("SecretBinary") is not None
        ):
            raise TrialError("AWS reader secret state failed")
        return value

    @staticmethod
    def _fernet_key(value: Any) -> str:
        if not isinstance(value, str) or len(value) != 44:
            raise TrialError("retained Fernet key failed policy")
        try:
            decoded = base64.b64decode(
                value.encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except (UnicodeError, ValueError):
            raise TrialError("retained Fernet key failed policy") from None
        if len(decoded) != 32:
            raise TrialError("retained Fernet key failed policy")
        return value

    @staticmethod
    def _new_fernet_key() -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

    def reader_keys(self, read_arn: str, action: str) -> tuple[str, str]:
        if action not in {"bootstrap", "reconcile", "rotate"}:
            raise TrialError("reader key action failed policy")
        current = self._current_secret_string(read_arn)
        if current is None:
            document = None
        else:
            try:
                document = json.loads(current)
            except json.JSONDecodeError:
                document = None
        if isinstance(document, dict) and document.get("schemaVersion") == self.READER_SCHEMA:
            if set(document) != {
                "schemaVersion",
                "gmsUrl",
                "token",
                "runHandleFernetKey",
                "oauthMasterKey",
            }:
                raise TrialError("managed reader secret shape drift")
            cloud_endpoints(document.get("gmsUrl"))
            validate_credential(document.get("token"), "retained reader")
            return (
                self._fernet_key(document.get("runHandleFernetKey")),
                self._fernet_key(document.get("oauthMasterKey")),
            )
        revoked = (
            isinstance(document, dict)
            and document.get("schemaVersion") == self.REVOKED_SCHEMA
            and set(document) == {"schemaVersion", "status", "workflowRunId"}
            and document.get("status") == "revoked"
            and isinstance(document.get("workflowRunId"), str)
            and RUN_ID.fullmatch(document["workflowRunId"]) is not None
        )
        if action != "bootstrap":
            raise TrialError("managed reader keys are unavailable for preservation")
        if current is not None and isinstance(document, dict) and not revoked:
            raise TrialError("bootstrap refused malformed previously managed secret")
        first = self._new_fernet_key()
        second = self._new_fernet_key()
        if first == second:
            raise TrialError("generated reader keys were not distinct")
        return first, second

    def _stage_document(
        self,
        secret_arn: str,
        document: dict[str, Any],
        stage_label: str,
    ) -> StagedSecret:
        if TRIAL_STAGE.fullmatch(stage_label) is None:
            raise TrialError("secret staging label failed policy")
        versions = self._version_stages(secret_arn)
        if any(stage_label in stages for stages in versions.values()):
            raise TrialError("secret staging label already exists")
        previous_current = next(
            (
                version_id
                for version_id, stages in versions.items()
                if "AWSCURRENT" in stages
            ),
            None,
        )
        payload = canonical_bytes(document)
        if not 1 <= len(payload) <= 16 * 1024:
            raise TrialError("secret payload size failed policy")
        response = self._run(
            [
                "secretsmanager",
                "put-secret-value",
                "--secret-id",
                secret_arn,
                "--secret-string",
                "file:///dev/stdin",
                "--version-stages",
                stage_label,
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            payload,
        )
        try:
            result = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS staged secret response failed") from None
        version_id = result.get("VersionId")
        result_stages = result.get("VersionStages")
        if (
            result.get("ARN") != secret_arn
            or not isinstance(version_id, str)
            or SECRET_VERSION_ID.fullmatch(version_id) is None
            or not isinstance(result_stages, list)
            or stage_label not in result_stages
            or "AWSCURRENT" in result_stages
        ):
            raise TrialError("AWS staged secret response contract failed")
        staged = StagedSecret(
            secret_arn=secret_arn,
            version_id=version_id,
            previous_current=previous_current,
            stage_label=stage_label,
        )
        self._verify_stage(staged, stage_label, True)
        return staged

    def _update_version_stage(
        self,
        secret_arn: str,
        stage: str,
        *,
        move_to: str | None = None,
        remove_from: str | None = None,
    ) -> None:
        if (
            SECRET_STAGE.fullmatch(stage) is None
            or (move_to is None and remove_from is None)
            or (
                move_to is not None
                and SECRET_VERSION_ID.fullmatch(move_to) is None
            )
            or (
                remove_from is not None
                and SECRET_VERSION_ID.fullmatch(remove_from) is None
            )
            or move_to == remove_from
        ):
            raise TrialError("secret version-stage mutation failed policy")
        arguments = [
            "secretsmanager",
            "update-secret-version-stage",
            "--secret-id",
            secret_arn,
            "--version-stage",
            stage,
        ]
        if move_to is not None:
            arguments.extend(["--move-to-version-id", move_to])
        if remove_from is not None:
            arguments.extend(["--remove-from-version-id", remove_from])
        arguments.extend(
            [
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ]
        )
        self._run(arguments)

    def _verify_stage(
        self,
        staged: StagedSecret,
        stage: str,
        expected: bool,
    ) -> None:
        versions = self._version_stages(staged.secret_arn)
        actual = stage in versions.get(staged.version_id, ())
        if actual is not expected:
            raise TrialError("secret version-stage verification failed")

    def verify_current(self, staged: StagedSecret) -> None:
        if self._current_version(staged.secret_arn) != staged.version_id:
            raise TrialError("secret current-version verification failed")

    def promote(self, staged: StagedSecret) -> None:
        if self._current_version(staged.secret_arn) != staged.previous_current:
            raise TrialError("secret current version changed before promotion")
        self._update_version_stage(
            staged.secret_arn,
            "AWSCURRENT",
            move_to=staged.version_id,
            remove_from=staged.previous_current,
        )
        self.verify_current(staged)

    def rollback(self, staged: StagedSecret) -> None:
        current = self._current_version(staged.secret_arn)
        if current == staged.previous_current:
            return
        if current != staged.version_id:
            raise TrialError("secret rollback found unexpected current version")
        if staged.previous_current is None:
            self._update_version_stage(
                staged.secret_arn,
                "AWSCURRENT",
                remove_from=staged.version_id,
            )
        else:
            self._update_version_stage(
                staged.secret_arn,
                "AWSCURRENT",
                move_to=staged.previous_current,
                remove_from=staged.version_id,
            )
        if self._current_version(staged.secret_arn) != staged.previous_current:
            raise TrialError("secret rollback verification failed")

    def drop_stage(self, staged: StagedSecret) -> None:
        versions = self._version_stages(staged.secret_arn)
        if staged.stage_label not in versions.get(staged.version_id, ()):
            return
        self._update_version_stage(
            staged.secret_arn,
            staged.stage_label,
            remove_from=staged.version_id,
        )
        self._verify_stage(staged, staged.stage_label, False)

    def stage_writer(
        self,
        secret_arn: str,
        *,
        gms_url: str,
        token: str,
        stage_label: str,
    ) -> StagedSecret:
        validate_credential(token, "generated DataHub writer")
        return self._stage_document(
            secret_arn,
            {
                "schemaVersion": self.WRITER_SCHEMA,
                "gmsUrl": gms_url,
                "token": token,
            },
            stage_label,
        )

    def stage_reader(
        self,
        secret_arn: str,
        *,
        gms_url: str,
        token: str,
        run_handle_key: str,
        oauth_master_key: str,
        stage_label: str,
    ) -> StagedSecret:
        validate_credential(token, "generated DataHub reader")
        return self._stage_document(
            secret_arn,
            {
                "schemaVersion": self.READER_SCHEMA,
                "gmsUrl": gms_url,
                "token": token,
                "runHandleFernetKey": self._fernet_key(run_handle_key),
                "oauthMasterKey": self._fernet_key(oauth_master_key),
            },
            stage_label,
        )

    def _put_current_document(
        self,
        secret_arn: str,
        document: dict[str, Any],
    ) -> str:
        payload = canonical_bytes(document)
        if not 1 <= len(payload) <= 16 * 1024:
            raise TrialError("secret payload size failed policy")
        response = self._run(
            [
                "secretsmanager",
                "put-secret-value",
                "--secret-id",
                secret_arn,
                "--secret-string",
                "file:///dev/stdin",
                "--region",
                self.region,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            payload,
        )
        try:
            result = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TrialError("AWS current secret response failed") from None
        version_id = result.get("VersionId")
        stages = result.get("VersionStages")
        if (
            result.get("ARN") != secret_arn
            or not isinstance(version_id, str)
            or SECRET_VERSION_ID.fullmatch(version_id) is None
            or not isinstance(stages, list)
            or "AWSCURRENT" not in stages
            or self._current_version(secret_arn) != version_id
        ):
            raise TrialError("AWS current secret verification failed")
        return version_id

    def put_revoked_marker(self, secret_arn: str, run_id: str) -> str:
        if RUN_ID.fullmatch(run_id) is None:
            raise TrialError("workflow run identifier failed policy")
        return self._put_current_document(
            secret_arn,
            {
                "schemaVersion": self.REVOKED_SCHEMA,
                "status": "revoked",
                "workflowRunId": run_id,
            },
        )
