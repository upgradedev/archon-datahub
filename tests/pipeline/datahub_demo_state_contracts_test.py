#!/usr/bin/env python3
"""Hermetic functional contracts for the stdlib-only demo-state controller."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest import mock


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER_PATH = REPOSITORY_ROOT / "scripts" / "datahub-demo-state.py"
CONTRACT_PATH = REPOSITORY_ROOT / "contracts" / "datahub-demo-state-v1.json"


def load_driver() -> ModuleType:
    """Import the checked-in driver without writing cache files into the checkout."""

    sys.dont_write_bytecode = True
    specification = importlib.util.spec_from_file_location(
        "archon_datahub_demo_state",
        DRIVER_PATH,
    )
    if specification is None or specification.loader is None:
        raise AssertionError(f"could not load demo-state driver: {DRIVER_PATH}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


DRIVER = load_driver()
REVIEWED_CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def write_canonical(path: pathlib.Path, value: Any) -> None:
    path.write_bytes(DRIVER.canonical_bytes(value))


def make_baseline_manifest(
    directory: pathlib.Path,
    contract: dict[str, Any],
    contract_digest: str,
) -> tuple[pathlib.Path, dict[str, Any], str]:
    manifest = {
        "schemaVersion": "archon.datahub-demo-baseline/v1",
        "stateContractSha256": contract_digest,
        "name": contract["officialBaseline"]["name"],
        "repository": contract["officialBaseline"]["repository"],
        "commit": contract["officialBaseline"]["commit"],
        "tree": contract["officialBaseline"]["tree"],
        "commitSignatureVerified": True,
        "indexVersion": contract["officialBaseline"]["indexVersion"],
        "mcpCount": contract["officialBaseline"]["expectedMcpCount"],
        "uniqueEntityUrnCount": contract["officialBaseline"][
            "expectedUniqueEntityUrnCount"
        ],
        "files": [
            {
                "path": item["path"],
                "size": item["size"],
                "sha256": item["sha256"],
                "gitBlob": item["gitBlob"],
            }
            for item in contract["officialBaseline"]["files"]
        ],
    }
    manifest["contentDigest"] = DRIVER.digest_obj(manifest)
    path = directory / "baseline-manifest.json"
    write_canonical(path, manifest)
    (directory / "index.json").write_text("{}\n", encoding="utf-8")
    return path, manifest, DRIVER.digest_obj(manifest)


def exact_anchors(contract: dict[str, Any]) -> dict[str, Any]:
    count = len(contract["officialBaseline"]["anchors"])
    return {
        "expected": count,
        "present": count,
        "complete": True,
        "missingDigest": DRIVER.digest_obj([]),
    }


def state_projection(
    contract: dict[str, Any],
    *,
    classification: str,
    digest: str,
    target_present: bool,
    domain_present: bool,
) -> dict[str, Any]:
    return {
        "classification": classification,
        "digest": digest,
        "mismatches": [] if classification in {"absent", "exact"} else ["partial"],
        "history": (
            copy.deepcopy(contract["state"]["ownershipHistory"])
            if classification == "exact"
            else []
        ),
        "danglingUpstreamAbsent": True,
        "ownedUrnPresence": [
            {
                "urn": contract["binding"]["ownedUrns"][0],
                "present": target_present,
            },
            {
                "urn": contract["binding"]["ownedUrns"][1],
                "present": domain_present,
            },
        ],
    }


def make_plan(
    path: pathlib.Path,
    contract: dict[str, Any],
    contract_digest: str,
    manifest: dict[str, Any],
    manifest_digest: str,
    before: dict[str, Any],
    anchors: dict[str, Any],
    *,
    action: str,
    operation: str,
    mutation_required: bool,
    release_sha: str,
) -> tuple[dict[str, Any], str]:
    plan = {
        "schemaVersion": "archon.datahub-demo-plan/v1",
        "repository": "upgradedev/archon-datahub",
        "releaseSha": release_sha,
        "gmsEndpointFingerprint": DRIVER.gms_endpoint_fingerprint(
            "https://datahub.example.test"
        ),
        "action": action,
        "operation": operation,
        "mutationRequired": mutation_required,
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
            DRIVER.digest_bytes(contract["resetConfirmation"].encode("utf-8"))
            if action == "reset"
            else None
        ),
    }
    write_canonical(path, plan)
    return plan, DRIVER.digest_obj(plan)


def make_approval_receipt(
    path: pathlib.Path,
    *,
    action: str,
    release_sha: str,
    plan_sha256: str,
    run_id: str = "4242",
    run_attempt: str = "1",
    actor: str = "dispatch-user",
    triggering_actor: str = "rerun-user",
    approver_id: int = 707,
    approver_login: str = "independent-reviewer",
) -> dict[str, Any]:
    receipt = {
        "schemaVersion": "archon.datahub-demo-approval/v1",
        "repository": "upgradedev/archon-datahub",
        "workflowRunId": run_id,
        "workflowRunAttempt": run_attempt,
        "action": action,
        "releaseSha": release_sha,
        "planSha256": plan_sha256,
        "initiators": {
            "actor": actor,
            "triggeringActor": triggering_actor,
        },
        "environment": {
            "id": 909,
            "name": "datahub-demo-seed",
        },
        "configuredReviewerIds": [approver_id],
        "approval": {
            "state": "approved",
            "comment": DRIVER.approval_comment(
                run_id,
                run_attempt,
                action,
                release_sha,
                plan_sha256,
            ),
            "user": {
                "id": approver_id,
                "login": approver_login,
            },
        },
    }
    write_canonical(path, receipt)
    return receipt


def make_executable(path: pathlib.Path) -> None:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o700)


def exact_state_aspect_reader(
    contract: dict[str, Any],
    contract_digest: str,
    *,
    logical_type_overrides: dict[str, str | None] | None = None,
    logical_payload_overrides: dict[str, dict[str, Any]] | None = None,
) -> Callable[..., dict[str, Any] | None]:
    binding = contract["binding"]
    dataset = contract["state"]["dataset"]
    domain = contract["state"]["domain"]
    history = contract["state"]["ownershipHistory"]
    overrides = logical_type_overrides or {}
    payload_overrides = logical_payload_overrides or {}
    discriminators = {
        "string": "com.linkedin.schema.StringType",
        "number": "com.linkedin.schema.NumberType",
    }

    fields: list[dict[str, Any]] = []
    for expected in dataset["fields"]:
        field = {
            "fieldPath": expected["path"],
            "nativeDataType": expected["nativeType"],
            "nullable": expected["nullable"],
            "isPartOfKey": expected["isPartOfKey"],
        }
        logical_type = overrides.get(expected["path"], expected["logicalType"])
        if logical_type is not None:
            field["type"] = {
                "type": {
                    discriminators[logical_type]: copy.deepcopy(
                        payload_overrides.get(expected["path"], {})
                    ),
                }
            }
        fields.append(field)

    def ownership_aspect(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "value": {
                "owners": [
                    {
                        "owner": item["owner"],
                        "type": item["ownershipType"],
                    }
                ]
            },
            "systemMetadata": {
                "pipelineName": item["pipelineName"],
                "runId": item["runId"],
                "lastObserved": item["lastObserved"],
            },
        }

    aspects: dict[tuple[str, str, str, int], dict[str, Any]] = {
        (
            "dataset",
            binding["targetUrn"],
            "datasetKey",
            0,
        ): {"value": {"urn": binding["targetUrn"]}},
        (
            "dataset",
            binding["targetUrn"],
            "datasetProperties",
            0,
        ): {
            "value": {
                "name": dataset["name"],
                "description": dataset["description"],
                "qualifiedName": dataset["qualifiedName"],
                "customProperties": DRIVER.expected_custom_properties(
                    contract,
                    contract_digest,
                ),
            }
        },
        (
            "dataset",
            binding["targetUrn"],
            "schemaMetadata",
            0,
        ): {
            "value": {
                "schemaName": dataset["schemaName"],
                "platform": "urn:li:dataPlatform:snowflake",
                "fields": fields,
            }
        },
        (
            "dataset",
            binding["targetUrn"],
            "ownership",
            0,
        ): ownership_aspect(history[1]),
        (
            "dataset",
            binding["targetUrn"],
            "ownership",
            1,
        ): ownership_aspect(history[0]),
        (
            "dataset",
            binding["targetUrn"],
            "domains",
            0,
        ): {"value": {"domains": [binding["domainUrn"]]}},
        (
            "dataset",
            binding["targetUrn"],
            "upstreamLineage",
            0,
        ): {
            "value": {
                "upstreams": [
                    {
                        "dataset": binding["danglingUpstreamUrn"],
                        "type": "TRANSFORMED",
                    }
                ]
            }
        },
        (
            "dataset",
            binding["targetUrn"],
            "editableSchemaMetadata",
            0,
        ): {"value": {"editableSchemaFieldInfo": []}},
        (
            "domain",
            binding["domainUrn"],
            "domainProperties",
            0,
        ): {"value": copy.deepcopy(domain)},
        (
            "domain",
            binding["domainUrn"],
            "domainKey",
            0,
        ): {"value": {"urn": binding["domainUrn"]}},
    }

    def read_aspect(
        gms: str,
        token: str,
        entity_type: str,
        urn: str,
        aspect: str,
        version: int = 0,
    ) -> dict[str, Any] | None:
        del gms, token
        value = aspects.get((entity_type, urn, aspect, version))
        return copy.deepcopy(value)

    return read_aspect


class DemoStateDriverContracts(unittest.TestCase):
    def test_git_blob_identity_is_exact_and_tampering_fails_closed(self) -> None:
        payload = b"test content\n"
        self.assertEqual(
            DRIVER.git_blob_sha1(payload),
            "d670460b4b4aece5915caf5c68d12f560a9fe3e4",
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = pathlib.Path(temporary) / "baseline.json"
            with (
                mock.patch.object(
                    DRIVER.urllib.request,
                    "urlopen",
                    return_value=io.BytesIO(payload),
                ),
                self.assertRaisesRegex(SystemExit, "Git blob"),
            ):
                DRIVER.download_exact(
                    "https://raw.githubusercontent.com/example/repository/commit/file",
                    destination,
                    len(payload),
                    DRIVER.digest_bytes(payload),
                    "0" * 40,
                )
            self.assertFalse(destination.exists())

    def test_reviewed_contract_loads_and_has_a_canonical_digest(self) -> None:
        contract, observed_digest = DRIVER.load_contract(CONTRACT_PATH)

        expected_digest = hashlib.sha256(DRIVER.canonical_bytes(contract)).hexdigest()
        reordered = {
            key: copy.deepcopy(REVIEWED_CONTRACT[key])
            for key in reversed(REVIEWED_CONTRACT)
        }

        self.assertEqual(contract, REVIEWED_CONTRACT)
        self.assertEqual(observed_digest, expected_digest)
        self.assertEqual(DRIVER.digest_obj(reordered), expected_digest)
        self.assertEqual(
            DRIVER.canonical_bytes({"z": 1, "a": "stable"}),
            b'{"a":"stable","z":1}\n',
        )

    def test_baseline_manifest_requires_exact_canonical_schema(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            path, manifest, manifest_digest = make_baseline_manifest(
                directory,
                contract,
                contract_digest,
            )
            observed, observed_digest = DRIVER.load_baseline_manifest(
                path,
                contract,
                contract_digest,
            )
            self.assertEqual(observed, manifest)
            self.assertEqual(observed_digest, manifest_digest)

            tampered = copy.deepcopy(manifest)
            tampered["unreviewed"] = True
            tampered_path = directory / "tampered-baseline-manifest.json"
            write_canonical(tampered_path, tampered)
            with self.assertRaisesRegex(SystemExit, "keys differ"):
                DRIVER.load_baseline_manifest(
                    tampered_path,
                    contract,
                    contract_digest,
                )

    def test_endpoint_validation_accepts_only_credential_free_https(self) -> None:
        self.assertEqual(
            DRIVER.validate_endpoint("https://datahub.example.test/api/gms/"),
            "https://datahub.example.test/api/gms",
        )
        self.assertEqual(
            DRIVER.validate_endpoint(
                "https://DATAHUB.EXAMPLE.TEST:443/api/gms/"
            ),
            "https://datahub.example.test/api/gms",
        )
        self.assertEqual(
            DRIVER.gms_endpoint_fingerprint(
                "https://datahub.example.test/api/gms/"
            ),
            DRIVER.gms_endpoint_fingerprint(
                "https://datahub.example.test/api/gms"
            ),
        )

        rejected = (
            "http://datahub.example.test",
            "https://user:secret@datahub.example.test",
            "https://datahub.example.test?token=secret",
            "https://datahub.example.test/#fragment",
            "https://datahub.example.test?",
            "https://@datahub.example.test",
            "https://datahub.example.test/api/../admin",
            "https://datahub.example.test\\@attacker.example.test",
            " https://datahub.example.test",
            "https://",
        )
        for endpoint in rejected:
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(
                    SystemExit,
                    "credential-free HTTPS origin/base path",
                ):
                    DRIVER.validate_endpoint(endpoint)

        with (
            mock.patch.object(
                DRIVER,
                "live_config",
                return_value=("https://datahub.example.test", "test-token"),
            ),
            self.assertRaisesRegex(SystemExit, "endpoint fingerprint"),
        ):
            DRIVER.command_validate_config(
                SimpleNamespace(expected_fingerprint="0" * 64)
            )

    def test_authenticated_reads_reject_redirects_and_ignore_proxy_environment(
        self,
    ) -> None:
        proxy_handlers = [
            handler
            for handler in DRIVER.DATAHUB_API_OPENER.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})

        redirect_handler = DRIVER.RejectDataHubRedirects()
        original = urllib.request.Request(
            "https://datahub.example.test/openapi/v3/entity/dataset/example",
            headers={"Authorization": "Bearer test-only-token"},
        )
        self.assertIsNone(
            redirect_handler.redirect_request(
                original,
                None,
                302,
                "Found",
                {"Location": "https://attacker.example.test/collect"},
                "https://attacker.example.test/collect",
            )
        )

        redirect_error = urllib.error.HTTPError(
            original.full_url,
            302,
            "Found",
            {"Location": "https://attacker.example.test/collect"},
            None,
        )
        poisoned_environment = {
            "HTTP_PROXY": "http://poisoned-proxy.example.test:8080",
            "HTTPS_PROXY": "http://poisoned-proxy.example.test:8080",
            "NO_PROXY": "",
        }
        with (
            mock.patch.dict(
                DRIVER.os.environ,
                poisoned_environment,
                clear=True,
            ),
            mock.patch.object(
                DRIVER.DATAHUB_API_OPENER,
                "open",
                side_effect=redirect_error,
            ) as opener,
            self.assertRaisesRegex(SystemExit, "HTTP 302"),
        ):
            DRIVER.request_json(
                original.full_url,
                "test-only-token",
            )

        opener.assert_called_once()
        sent_request = opener.call_args.args[0]
        self.assertEqual(sent_request.full_url, original.full_url)
        self.assertEqual(
            sent_request.get_header("Authorization"),
            "Bearer test-only-token",
        )

    def test_reviewed_contract_tampering_fails_closed(self) -> None:
        def add_unreviewed_key(contract: dict[str, Any]) -> None:
            contract["unreviewed"] = True

        def change_baseline_commit(contract: dict[str, Any]) -> None:
            contract["officialBaseline"]["commit"] = "0" * 39

        def add_unreviewed_baseline_key(contract: dict[str, Any]) -> None:
            contract["officialBaseline"]["unreviewed"] = True

        def change_baseline_digest(contract: dict[str, Any]) -> None:
            contract["officialBaseline"]["files"][0]["sha256"] = "0" * 63

        def widen_delete_allowlist(contract: dict[str, Any]) -> None:
            contract["binding"]["ownedUrns"].append(
                contract["binding"]["danglingUpstreamUrn"]
            )

        def remove_history_contradiction(contract: dict[str, Any]) -> None:
            contract["state"]["ownershipHistory"][1]["owner"] = contract["state"][
                "ownershipHistory"
            ][0]["owner"]

        def change_reset_confirmation(contract: dict[str, Any]) -> None:
            contract["resetConfirmation"] = "RESET EVERYTHING"

        cases: tuple[
            tuple[str, Callable[[dict[str, Any]], None], str],
            ...,
        ] = (
            ("unreviewed key", add_unreviewed_key, "keys differ"),
            (
                "unreviewed baseline key",
                add_unreviewed_baseline_key,
                "keys differ",
            ),
            (
                "baseline commit",
                change_baseline_commit,
                "showcase-ecommerce provenance changed",
            ),
            (
                "baseline file digest",
                change_baseline_digest,
                "baseline file binding is invalid",
            ),
            (
                "delete allowlist",
                widen_delete_allowlist,
                "hard-delete allowlist",
            ),
            (
                "retained contradiction",
                remove_history_contradiction,
                "retained-history contradiction binding changed",
            ),
            (
                "reset confirmation",
                change_reset_confirmation,
                "reset confirmation phrase changed",
            ),
        )

        for name, tamper, expected_message in cases:
            with self.subTest(tamper=name):
                candidate = copy.deepcopy(REVIEWED_CONTRACT)
                tamper(candidate)
                with self.assertRaisesRegex(SystemExit, expected_message):
                    DRIVER.validate_contract(candidate)

    def test_cli_subprocess_environment_never_inherits_runner_secrets(self) -> None:
        poisoned_runner_environment = {
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "github-oidc",
            "AWS_ACCESS_KEY_ID": "aws-access",
            "AWS_SECRET_ACCESS_KEY": "aws-secret",
            "GH_TOKEN": "github-token",
            "HOME": "/home/runner",
            "OPENAI_API_KEY": "model-secret",
            "PATH": "/untrusted/bin",
        }
        with mock.patch.dict(
            DRIVER.os.environ,
            poisoned_runner_environment,
            clear=True,
        ):
            environment = DRIVER.datahub_cli_environment(
                "https://datahub.example.test",
                "datahub-token",
            )

        self.assertEqual(
            environment,
            {
                "DATAHUB_GMS_TOKEN": "datahub-token",
                "DATAHUB_GMS_URL": "https://datahub.example.test",
            },
        )
        DRIVER.assert_datahub_cli_environment(environment)
        with self.assertRaisesRegex(SystemExit, "two-key allowlist"):
            DRIVER.assert_datahub_cli_environment(
                {**environment, "AWS_SESSION_TOKEN": "must-not-cross"}
            )

    def test_datahub_sdk_failures_never_surface_provider_messages(self) -> None:
        sentinel = "SENTINEL_PROVIDER_SECRET_MUST_NOT_REACH_CI"

        class SchemaValue:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.args = args
                self.kwargs = kwargs

        class Proposal(SchemaValue):
            def validate(self) -> bool:
                return True

            def make_mcp(self) -> "Proposal":
                return self

        class DatasetLineageType:
            TRANSFORMED = "TRANSFORMED"

        class OwnershipType:
            DATAOWNER = "DATAOWNER"

        emitter_mcp = ModuleType("datahub.emitter.mcp")
        emitter_mcp.MetadataChangeProposalWrapper = Proposal
        rest_emitter = ModuleType("datahub.emitter.rest_emitter")
        rest_emitter.EmitMode = SimpleNamespace(SYNC_PRIMARY="SYNC_PRIMARY")
        schema_classes = ModuleType("datahub.metadata.schema_classes")
        schema_names = (
            "AuditStampClass",
            "DatasetPropertiesClass",
            "DomainPropertiesClass",
            "DomainsClass",
            "NumberTypeClass",
            "OtherSchemaClass",
            "OwnerClass",
            "OwnershipClass",
            "SchemaFieldClass",
            "SchemaFieldDataTypeClass",
            "SchemaMetadataClass",
            "StringTypeClass",
            "SystemMetadataClass",
            "UpstreamClass",
            "UpstreamLineageClass",
        )
        for name in schema_names:
            setattr(schema_classes, name, SchemaValue)
        schema_classes.DatasetLineageTypeClass = DatasetLineageType
        schema_classes.OwnershipTypeClass = OwnershipType

        packages: dict[str, ModuleType] = {}
        for name in (
            "datahub",
            "datahub.emitter",
            "datahub.metadata",
        ):
            package = ModuleType(name)
            package.__path__ = []  # type: ignore[attr-defined]
            packages[name] = package
        imported_modules = {
            **packages,
            "datahub.emitter.mcp": emitter_mcp,
            "datahub.emitter.rest_emitter": rest_emitter,
            "datahub.metadata.schema_classes": schema_classes,
        }

        for failure_phase in (
            "initialization",
            "connection",
            "emission",
            "close",
        ):
            with self.subTest(failure_phase=failure_phase):

                class FailingEmitter:
                    def __init__(self, *args: Any, **kwargs: Any) -> None:
                        if failure_phase == "initialization":
                            raise RuntimeError(sentinel)

                    def test_connection(self) -> None:
                        if failure_phase == "connection":
                            raise RuntimeError(sentinel)

                    def emit_mcp(self, *args: Any, **kwargs: Any) -> None:
                        if failure_phase == "emission":
                            raise RuntimeError(sentinel)

                    def close(self) -> None:
                        if failure_phase == "close":
                            raise RuntimeError(sentinel)

                rest_emitter.DatahubRestEmitter = FailingEmitter
                with (
                    mock.patch.dict(sys.modules, imported_modules),
                    self.assertRaises(SystemExit) as caught,
                ):
                    DRIVER.emit_demo_state(
                        copy.deepcopy(REVIEWED_CONTRACT),
                        DRIVER.digest_obj(REVIEWED_CONTRACT),
                        "https://datahub.example.test",
                        "test-token",
                    )

                surfaced = str(caught.exception)
                self.assertNotIn(sentinel, surfaced)
                self.assertIn("RuntimeError", surfaced)
                self.assertIn(failure_phase, surfaced)

    def test_reset_candidates_skip_already_absent_owned_urns(self) -> None:
        owned_urns = REVIEWED_CONTRACT["binding"]["ownedUrns"]
        presence = [
            {"urn": owned_urns[0], "present": False},
            {"urn": owned_urns[1], "present": True},
        ]

        self.assertEqual(
            DRIVER.reset_delete_candidates(presence, owned_urns),
            [owned_urns[1]],
        )
        self.assertEqual(
            DRIVER.reset_delete_candidates(
                [
                    {"urn": owned_urns[0], "present": False},
                    {"urn": owned_urns[1], "present": False},
                ],
                owned_urns,
            ),
            [],
        )

    def test_exact_state_rejects_noncanonical_field_logical_type(
        self,
    ) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)

        with mock.patch.object(
            DRIVER,
            "read_aspect",
            side_effect=exact_state_aspect_reader(contract, contract_digest),
        ):
            exact = DRIVER.inspect_state(
                contract,
                contract_digest,
                "https://datahub.example.test",
                "test-token",
            )
        self.assertEqual(exact["classification"], "exact")
        self.assertEqual(exact["mismatches"], [])

        invalid_cases = (
            {
                "name": "missing",
                "logical_type_overrides": {"email": None},
                "logical_payload_overrides": {},
            },
            {
                "name": "wrong-discriminator",
                "logical_type_overrides": {"email": "number"},
                "logical_payload_overrides": {},
            },
            {
                "name": "nonempty-union-payload",
                "logical_type_overrides": {},
                "logical_payload_overrides": {"email": {"unexpected": True}},
            },
        )
        for invalid in invalid_cases:
            with (
                self.subTest(case=invalid["name"]),
                mock.patch.object(
                    DRIVER,
                    "read_aspect",
                    side_effect=exact_state_aspect_reader(
                        contract,
                        contract_digest,
                        logical_type_overrides=invalid["logical_type_overrides"],
                        logical_payload_overrides=invalid[
                            "logical_payload_overrides"
                        ],
                    ),
                ),
            ):
                observed = DRIVER.inspect_state(
                    contract,
                    contract_digest,
                    "https://datahub.example.test",
                    "test-token",
                )

            self.assertEqual(observed["classification"], "drift")
            self.assertIn("schema-or-g6-gap", observed["mismatches"])

    def test_dangling_existence_uses_the_dataset_key_not_optional_properties(
        self,
    ) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        dangling = contract["binding"]["danglingUpstreamUrn"]

        def read_aspect(
            gms: str,
            token: str,
            entity_type: str,
            urn: str,
            aspect: str,
            version: int = 0,
        ) -> dict[str, Any] | None:
            if (
                entity_type == "dataset"
                and urn == dangling
                and aspect == "datasetKey"
                and version == 0
            ):
                return {"value": {"urn": dangling}}
            return None

        with mock.patch.object(DRIVER, "read_aspect", side_effect=read_aspect):
            observed = DRIVER.inspect_state(
                contract,
                DRIVER.digest_obj(contract),
                "https://datahub.example.test",
                "test-token",
            )

        self.assertEqual(observed["classification"], "drift")
        self.assertFalse(observed["danglingUpstreamAbsent"])
        self.assertEqual(observed["mismatches"], ["dangling-upstream-exists"])

    def test_command_plan_covers_noop_reset_and_drift_fail_closed(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        release_sha = "a" * 40
        anchors = exact_anchors(contract)
        exact = state_projection(
            contract,
            classification="exact",
            digest="1" * 64,
            target_present=True,
            domain_present=True,
        )
        partial = state_projection(
            contract,
            classification="drift",
            digest="2" * 64,
            target_present=False,
            domain_present=True,
        )
        drift = state_projection(
            contract,
            classification="drift",
            digest="3" * 64,
            target_present=True,
            domain_present=True,
        )

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            baseline_path, _, _ = make_baseline_manifest(
                directory,
                contract,
                contract_digest,
            )

            def arguments(
                *,
                action: str,
                confirmation: str,
                output: pathlib.Path,
            ) -> SimpleNamespace:
                return SimpleNamespace(
                    contract=str(CONTRACT_PATH),
                    baseline_manifest=str(baseline_path),
                    action=action,
                    confirmation=confirmation,
                    query=contract["binding"]["query"],
                    release_sha=release_sha,
                    repository="upgradedev/archon-datahub",
                    output=str(output),
                )

            noop_path = directory / "noop-plan.json"
            reset_path = directory / "reset-plan.json"
            rejected_path = directory / "rejected-plan.json"
            with (
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=("https://datahub.example.test", "test-token"),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    side_effect=[exact, partial, drift],
                ),
                mock.patch.object(
                    DRIVER,
                    "baseline_anchor_state",
                    return_value=anchors,
                ),
                mock.patch("builtins.print"),
            ):
                DRIVER.command_plan(
                    arguments(
                        action="seed",
                        confirmation="",
                        output=noop_path,
                    )
                )
                DRIVER.command_plan(
                    arguments(
                        action="reset",
                        confirmation=contract["resetConfirmation"],
                        output=reset_path,
                    )
                )
                with self.assertRaisesRegex(
                    SystemExit,
                    "dispatch an approved reset",
                ):
                    DRIVER.command_plan(
                        arguments(
                            action="seed",
                            confirmation="",
                            output=rejected_path,
                        )
                    )

            noop = json.loads(noop_path.read_text(encoding="utf-8"))
            reset = json.loads(reset_path.read_text(encoding="utf-8"))
            self.assertEqual(noop["operation"], "noop")
            self.assertFalse(noop["mutationRequired"])
            self.assertEqual(
                noop["gmsEndpointFingerprint"],
                DRIVER.gms_endpoint_fingerprint(
                    "https://datahub.example.test"
                ),
            )
            self.assertEqual(
                noop["before"]["ownedUrnPresence"],
                exact["ownedUrnPresence"],
            )
            self.assertEqual(reset["operation"], "reset")
            self.assertTrue(reset["mutationRequired"])
            self.assertEqual(
                reset["before"]["ownedUrnPresence"],
                partial["ownedUrnPresence"],
            )
            self.assertFalse(rejected_path.exists())

    def test_command_apply_binds_the_exact_approval_receipt(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        release_sha = "b" * 40
        anchors = exact_anchors(contract)
        exact = state_projection(
            contract,
            classification="exact",
            digest="4" * 64,
            target_present=True,
            domain_present=True,
        )

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            baseline_path, manifest, manifest_digest = make_baseline_manifest(
                directory,
                contract,
                contract_digest,
            )
            plan_path = directory / "plan.json"
            _, plan_sha256 = make_plan(
                plan_path,
                contract,
                contract_digest,
                manifest,
                manifest_digest,
                exact,
                anchors,
                action="seed",
                operation="noop",
                mutation_required=False,
                release_sha=release_sha,
            )
            approval_path = directory / "approval-receipt.json"
            approval = make_approval_receipt(
                approval_path,
                action="seed",
                release_sha=release_sha,
                plan_sha256=plan_sha256,
            )
            cli = directory / "datahub"
            make_executable(cli)
            receipt_path = directory / "receipt.json"
            arguments = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                baseline_manifest=str(baseline_path),
                plan=str(plan_path),
                approval_receipt=str(approval_path),
                expected_plan_sha256=plan_sha256,
                release_sha=release_sha,
                workflow_run_id="4242",
                workflow_run_attempt="1",
                actor="dispatch-user",
                triggering_actor="rerun-user",
                datahub_cli=str(cli),
                receipt=str(receipt_path),
            )

            with (
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=("https://datahub.example.test", "test-token"),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    side_effect=[exact, exact],
                ),
                mock.patch.object(
                    DRIVER,
                    "baseline_anchor_state",
                    return_value=anchors,
                ),
                mock.patch.object(
                    DRIVER,
                    "wait_for_anchors",
                    return_value=anchors,
                ),
                mock.patch("builtins.print"),
            ):
                DRIVER.command_apply(arguments)

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["approvalReceiptSha256"],
                DRIVER.digest_obj(approval),
            )
            self.assertEqual(receipt["approval"]["state"], "approved")
            self.assertEqual(
                receipt["approval"]["user"],
                approval["approval"]["user"],
            )
            self.assertEqual(receipt["outcome"], "unchanged")
            self.assertEqual(
                receipt["gmsEndpointFingerprint"],
                DRIVER.gms_endpoint_fingerprint(
                    "https://datahub.example.test"
                ),
            )

            with (
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=("https://other-datahub.example.test", "test-token"),
                ),
                mock.patch.object(DRIVER, "inspect_state") as forbidden_inspect,
                self.assertRaisesRegex(
                    SystemExit,
                    "endpoint differs from the reviewed plan",
                ),
            ):
                DRIVER.command_apply(arguments)
            forbidden_inspect.assert_not_called()

            casing_alias_path = directory / "casing-alias-approval.json"
            make_approval_receipt(
                casing_alias_path,
                action="seed",
                release_sha=release_sha,
                plan_sha256=plan_sha256,
                approver_login="DISPATCH-USER",
            )
            rejected_arguments = SimpleNamespace(
                **{
                    **vars(arguments),
                    "approval_receipt": str(casing_alias_path),
                    "receipt": str(directory / "rejected-receipt.json"),
                }
            )
            with self.assertRaisesRegex(
                SystemExit,
                "must differ from actor",
            ):
                DRIVER.command_apply(rejected_arguments)

    def test_command_apply_resumes_a_partial_reset_without_redeleting_absent_urns(
        self,
    ) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        release_sha = "c" * 40
        anchors = exact_anchors(contract)
        partial = state_projection(
            contract,
            classification="drift",
            digest="5" * 64,
            target_present=False,
            domain_present=True,
        )
        after_delete = state_projection(
            contract,
            classification="absent",
            digest="6" * 64,
            target_present=False,
            domain_present=False,
        )
        exact = state_projection(
            contract,
            classification="exact",
            digest="7" * 64,
            target_present=True,
            domain_present=True,
        )

        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            baseline_path, manifest, manifest_digest = make_baseline_manifest(
                directory,
                contract,
                contract_digest,
            )
            plan_path = directory / "plan.json"
            _, plan_sha256 = make_plan(
                plan_path,
                contract,
                contract_digest,
                manifest,
                manifest_digest,
                partial,
                anchors,
                action="reset",
                operation="reset",
                mutation_required=True,
                release_sha=release_sha,
            )
            approval_path = directory / "approval-receipt.json"
            make_approval_receipt(
                approval_path,
                action="reset",
                release_sha=release_sha,
                plan_sha256=plan_sha256,
            )
            cli = directory / "datahub"
            make_executable(cli)
            receipt_path = directory / "receipt.json"
            arguments = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                baseline_manifest=str(baseline_path),
                plan=str(plan_path),
                approval_receipt=str(approval_path),
                expected_plan_sha256=plan_sha256,
                release_sha=release_sha,
                workflow_run_id="4242",
                workflow_run_attempt="1",
                actor="dispatch-user",
                triggering_actor="rerun-user",
                datahub_cli=str(cli),
                receipt=str(receipt_path),
            )

            with (
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=("https://datahub.example.test", "test-token"),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    side_effect=[partial, after_delete, exact],
                ),
                mock.patch.object(
                    DRIVER,
                    "baseline_anchor_state",
                    return_value=anchors,
                ),
                mock.patch.object(
                    DRIVER,
                    "run_datahub_cli",
                    side_effect=[
                        SimpleNamespace(returncode=1),
                        SimpleNamespace(returncode=0),
                    ],
                ) as run_cli,
                mock.patch.object(
                    DRIVER,
                    "wait_for_anchors",
                    return_value=anchors,
                ),
                mock.patch.object(
                    DRIVER,
                    "prepare_demo_emission",
                    return_value={"prepared": True},
                ) as prepare,
                mock.patch.object(DRIVER, "emit_prepared_demo_state") as emit,
                mock.patch.object(DRIVER, "close_prepared_demo_emission") as close,
                mock.patch("builtins.print"),
            ):
                DRIVER.command_apply(arguments)

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["resetDeletes"],
                [
                    {
                        "urn": contract["binding"]["ownedUrns"][0],
                        "outcome": "already-absent",
                    },
                    {
                        "urn": contract["binding"]["ownedUrns"][1],
                        "outcome": "absence-proved-after-cli-error",
                    },
                ],
            )
            self.assertEqual(receipt["outcome"], "reset")
            self.assertEqual(run_cli.call_count, 2)
            delete_argv = run_cli.call_args_list[0].args[0]
            self.assertEqual(delete_argv[1:3], ["delete", "--urn"])
            self.assertEqual(
                delete_argv[3],
                contract["binding"]["ownedUrns"][1],
            )
            self.assertNotIn(
                contract["binding"]["ownedUrns"][0],
                delete_argv,
            )
            self.assertEqual(
                run_cli.call_args_list[1].args[0][1:3],
                ["datapack", "load"],
            )
            prepare.assert_called_once()
            emit.assert_called_once_with({"prepared": True})
            close.assert_called_once_with({"prepared": True})

            with (
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=("https://datahub.example.test", "test-token"),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    return_value=partial,
                ),
                mock.patch.object(
                    DRIVER,
                    "baseline_anchor_state",
                    return_value=anchors,
                ),
                mock.patch.object(
                    DRIVER,
                    "prepare_demo_emission",
                    side_effect=SystemExit("SDK preflight failed"),
                ),
                mock.patch.object(DRIVER, "run_datahub_cli") as forbidden_cli,
                mock.patch.object(DRIVER, "delete_owned_urn") as forbidden_delete,
                self.assertRaisesRegex(SystemExit, "SDK preflight failed"),
            ):
                DRIVER.command_apply(arguments)

            forbidden_cli.assert_not_called()
            forbidden_delete.assert_not_called()

    def test_ambiguous_delete_is_accepted_only_after_proven_absence(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        owned_urns = contract["binding"]["ownedUrns"]
        target = owned_urns[0]
        environment = DRIVER.datahub_cli_environment(
            "https://datahub.example.test",
            "datahub-token",
        )
        absent_readback = {
            "ownedUrnPresence": [
                {"urn": owned_urns[0], "present": False},
                {"urn": owned_urns[1], "present": True},
            ]
        }

        with (
            mock.patch.object(
                DRIVER,
                "run_datahub_cli",
                return_value=SimpleNamespace(returncode=1),
            ) as run_cli,
            mock.patch.object(
                DRIVER,
                "inspect_state",
                return_value=absent_readback,
            ) as inspect,
        ):
            outcome = DRIVER.delete_owned_urn(
                pathlib.Path("/runner/datahub"),
                target,
                contract,
                "0" * 64,
                "https://datahub.example.test",
                "datahub-token",
                environment,
            )

        self.assertEqual(outcome, "absence-proved-after-cli-error")
        run_cli.assert_called_once_with(
            [
                "/runner/datahub",
                "delete",
                "--urn",
                target,
                "--hard",
                "--force",
            ],
            environment,
        )
        inspect.assert_called_once()

        present_readback = {
            "ownedUrnPresence": [
                {"urn": owned_urns[0], "present": True},
                {"urn": owned_urns[1], "present": True},
            ]
        }
        for returncode in (0, 1):
            with (
                self.subTest(returncode=returncode),
                mock.patch.object(
                    DRIVER,
                    "run_datahub_cli",
                    return_value=SimpleNamespace(returncode=returncode),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    return_value=present_readback,
                ),
                self.assertRaisesRegex(SystemExit, "live readback"),
            ):
                DRIVER.delete_owned_urn(
                    pathlib.Path("/runner/datahub"),
                    target,
                    contract,
                    "0" * 64,
                    "https://datahub.example.test",
                    "datahub-token",
                    environment,
                )


if __name__ == "__main__":
    unittest.main()
