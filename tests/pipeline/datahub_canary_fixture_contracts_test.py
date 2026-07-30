from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "contracts" / "datahub-canary-fixture-v1.json"
DRIVER_PATH = ROOT / "scripts" / "datahub-canary-fixture.py"
SPEC = importlib.util.spec_from_file_location("datahub_canary_fixture", DRIVER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the governed-canary fixture controller")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
REVIEWED_CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def envelope(value: dict[str, object] | None = None) -> dict[str, object]:
    return {"value": {} if value is None else value}


def schema_field(
    path: str,
    native_type: str,
    discriminator: str,
    *,
    key: bool = False,
) -> dict[str, object]:
    return {
        "fieldPath": path,
        "type": {
            "type": {
                f"com.linkedin.schema.{discriminator}": {},
            }
        },
        "nativeDataType": native_type,
        "nullable": False,
        "recursive": False,
        "isPartOfKey": key,
    }


def exact_aspects(
    contract: dict[str, object],
    contract_digest: str,
) -> dict[tuple[str, str, str], dict[str, object] | None]:
    binding = contract["binding"]
    state = contract["state"]
    dataset = state["dataset"]
    owner = {
        "owners": [
            {
                "owner": binding["ownerUrn"],
                "type": state["ownerType"],
            }
        ]
    }
    return {
        ("dataset", DRIVER.TARGET_URN, "datasetKey"): envelope(),
        (
            "dataset",
            DRIVER.TARGET_URN,
            "datasetProperties",
        ): envelope(
            {
                "name": dataset["name"],
                "description": dataset["description"],
                "qualifiedName": dataset["qualifiedName"],
                "customProperties": DRIVER.expected_custom_properties(
                    contract,
                    contract_digest,
                ),
            }
        ),
        (
            "dataset",
            DRIVER.TARGET_URN,
            "schemaMetadata",
        ): envelope(
            {
                "schemaName": dataset["schemaName"],
                "platform": binding["platformUrn"],
                "fields": [
                    schema_field(
                        "customer_id",
                        "VARCHAR",
                        "StringType",
                        key=True,
                    ),
                    schema_field("email", "VARCHAR", "StringType"),
                    schema_field("amount", "NUMBER", "NumberType"),
                ],
            }
        ),
        ("dataset", DRIVER.TARGET_URN, "ownership"): envelope(owner),
        (
            "dataset",
            DRIVER.TARGET_URN,
            "domains",
        ): envelope({"domains": [DRIVER.DOMAIN_URN]}),
        ("dataset", DRIVER.TARGET_URN, "deprecation"): None,
        (
            "dataset",
            DRIVER.TARGET_URN,
            "editableSchemaMetadata",
        ): envelope({"editableSchemaFieldInfo": []}),
        ("domain", DRIVER.DOMAIN_URN, "domainKey"): envelope(),
        (
            "domain",
            DRIVER.DOMAIN_URN,
            "domainProperties",
        ): envelope(
            {
                **state["domain"],
                "customProperties": DRIVER.expected_custom_properties(
                    contract,
                    contract_digest,
                ),
            }
        ),
        ("domain", DRIVER.DOMAIN_URN, "ownership"): envelope(owner),
        ("tag", DRIVER.PII_TAG_URN, "tagProperties"): envelope({"name": "PII"}),
    }


def observed_state(
    classification: str,
    digest: str,
    *,
    dataset_present: bool,
    domain_present: bool,
    marker_exact: bool = True,
    g6_state: str | None = None,
) -> dict[str, object]:
    exact = classification == "exact"
    classification_state = g6_state or ("absent" if exact else "unknown")
    return {
        "classification": classification,
        "digest": digest,
        "rawAspectSnapshotSha256": digest,
        "exactQueryMatchCount": 1 if dataset_present else 0,
        "mismatches": [] if classification != "drift" else ["typed-schema"],
        "ownedUrnPresence": [
            {"urn": DRIVER.TARGET_URN, "present": dataset_present},
            {"urn": DRIVER.DOMAIN_URN, "present": domain_present},
        ],
        "provenance": [
            {
                "urn": DRIVER.TARGET_URN,
                "present": dataset_present,
                "markerExact": dataset_present and marker_exact,
            },
            {
                "urn": DRIVER.DOMAIN_URN,
                "present": domain_present,
                "markerExact": domain_present and marker_exact,
            },
        ],
        "piiTagPresent": True,
        "g1ToG5": {
            "G1": exact,
            "G2": exact,
            "G3": exact,
            "G4": True,
            "G5": exact,
        },
        "g6Gap": {
            "fieldPath": "email",
            "classificationState": classification_state,
            "piiClassificationAbsent": classification_state == "absent",
        },
    }


class DataHubCanaryFixtureContractsTest(unittest.TestCase):
    def test_contract_is_the_single_owned_test_fixture(self) -> None:
        contract = DRIVER.validate_contract(copy.deepcopy(REVIEWED_CONTRACT))
        binding = contract["binding"]
        self.assertEqual(binding["query"], "archon_governed_canary_fixture")
        self.assertEqual(
            binding["targetUrn"],
            (
                "urn:li:dataset:(urn:li:dataPlatform:snowflake,"
                "archon_governed_canary_fixture,TEST)"
            ),
        )
        self.assertNotIn(",PROD)", binding["targetUrn"])
        self.assertEqual(
            binding["ownedUrns"],
            [binding["targetUrn"], binding["domainUrn"]],
        )
        self.assertEqual(binding["sensitiveFieldPath"], "email")
        self.assertEqual(binding["piiTagUrn"], "urn:li:tag:PII")
        fields = contract["state"]["dataset"]["fields"]
        self.assertTrue(all(field["logicalType"] for field in fields))
        self.assertTrue(contract["state"]["dataset"]["description"])
        self.assertEqual(contract["state"]["ownerType"], "DATAOWNER")
        self.assertEqual(
            contract["provenance"],
            {
                "contractSha256Property": "archonFixtureContractSha256",
                "customProperties": {
                    "archonFixtureOwner": (
                        "https://github.com/upgradedev/archon-datahub"
                    ),
                    "archonFixturePurpose": "governed-canary-write-rollback",
                    "archonFixtureSchema": "archon.datahub-canary-fixture/v1",
                },
            },
        )

    def test_contract_rejects_target_query_and_delete_allowlist_drift(self) -> None:
        mutations = (
            ("query", "orders"),
            (
                "targetUrn",
                (
                    "urn:li:dataset:(urn:li:dataPlatform:snowflake,"
                    "archon_governed_canary_fixture,PROD)"
                ),
            ),
            (
                "ownedUrns",
                [
                    DRIVER.TARGET_URN,
                    DRIVER.DOMAIN_URN,
                    "urn:li:dataset:(urn:li:dataPlatform:snowflake,other,TEST)",
                ],
            ),
        )
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(REVIEWED_CONTRACT)
                changed["binding"][key] = value
                with self.assertRaisesRegex(SystemExit, "allowlist"):
                    DRIVER.validate_contract(changed)

    def test_contract_rejects_provenance_marker_drift(self) -> None:
        changed = copy.deepcopy(REVIEWED_CONTRACT)
        changed["provenance"]["customProperties"][
            "archonFixturePurpose"
        ] = "unreviewed-purpose"
        with self.assertRaisesRegex(SystemExit, "provenance marker"):
            DRIVER.validate_contract(changed)

    def test_endpoint_requires_https_and_a_complete_isolation_dns_label(self) -> None:
        marker = "archon-canary"
        self.assertEqual(
            DRIVER.validate_endpoint(
                "https://tenant.archon-canary.example.test/gms/",
                marker,
            ),
            "https://tenant.archon-canary.example.test/gms",
        )
        rejected = (
            "http://tenant.archon-canary.example.test",
            "https://tenant.not-archon-canary.example.test",
            "https://archon-canary.example.test@good.example.test",
            "https://tenant.archon-canary.example.test/gms?next=other",
            "https://tenant.archon-canary.example.test/a/../gms",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                DRIVER.validate_endpoint(value, marker)

    def test_aspect_reader_accepts_only_fixed_urns_and_aspects(self) -> None:
        url = DRIVER.aspect_url(
            "https://tenant.archon-canary.example.test",
            "dataset",
            DRIVER.TARGET_URN,
            "schemaMetadata",
        )
        self.assertIn("/openapi/v3/entity/dataset/", url)
        self.assertIn("version=0", url)
        with self.assertRaisesRegex(SystemExit, "URN allowlist"):
            DRIVER.aspect_url(
                "https://tenant.archon-canary.example.test",
                "dataset",
                "urn:li:dataset:(urn:li:dataPlatform:snowflake,other,TEST)",
                "schemaMetadata",
            )
        with self.assertRaisesRegex(SystemExit, "endpoint allowlist"):
            DRIVER.aspect_url(
                "https://tenant.archon-canary.example.test",
                "dataset",
                DRIVER.TARGET_URN,
                "upstreamLineage",
            )

    def test_inspection_proves_exact_one_g1_to_g5_and_open_g6(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        aspects = exact_aspects(contract, contract_digest)

        def read(
            _gms: str,
            _token: str,
            entity_type: str,
            urn: str,
            aspect: str,
        ) -> dict[str, object] | None:
            return aspects[(entity_type, urn, aspect)]

        with (
            mock.patch.object(
                DRIVER,
                "exact_query",
                return_value={"total": 1, "urns": [DRIVER.TARGET_URN]},
            ),
            mock.patch.object(DRIVER, "read_aspect", side_effect=read),
        ):
            observed = DRIVER.inspect_state(
                contract,
                contract_digest,
                "https://tenant.archon-canary.example.test",
                "token",
            )

        self.assertEqual(observed["classification"], "exact")
        self.assertEqual(observed["exactQueryMatchCount"], 1)
        self.assertTrue(all(observed["g1ToG5"].values()))
        self.assertEqual(
            observed["g6Gap"],
            {
                "classificationState": "absent",
                "fieldPath": "email",
                "piiClassificationAbsent": True,
            },
        )

    def test_inspection_distinguishes_absence_from_pii_or_query_drift(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)

        def absent_read(
            _gms: str,
            _token: str,
            entity_type: str,
            urn: str,
            aspect: str,
        ) -> dict[str, object] | None:
            if (entity_type, urn, aspect) == (
                "tag",
                DRIVER.PII_TAG_URN,
                "tagProperties",
            ):
                return envelope({"name": "PII"})
            return None

        with (
            mock.patch.object(
                DRIVER,
                "exact_query",
                return_value={"total": 0, "urns": []},
            ),
            mock.patch.object(DRIVER, "read_aspect", side_effect=absent_read),
        ):
            absent = DRIVER.inspect_state(
                contract,
                contract_digest,
                "https://tenant.archon-canary.example.test",
                "token",
            )
        self.assertEqual(absent["classification"], "absent")

        aspects = exact_aspects(contract, contract_digest)
        aspects[
            ("dataset", DRIVER.TARGET_URN, "editableSchemaMetadata")
        ] = envelope(
            {
                "editableSchemaFieldInfo": [
                    {
                        "fieldPath": "email",
                        "globalTags": {
                            "tags": [{"tag": DRIVER.PII_TAG_URN}],
                        },
                    }
                ]
            }
        )

        def drift_read(
            _gms: str,
            _token: str,
            entity_type: str,
            urn: str,
            aspect: str,
        ) -> dict[str, object] | None:
            return aspects[(entity_type, urn, aspect)]

        with (
            mock.patch.object(
                DRIVER,
                "exact_query",
                return_value={"total": 2, "urns": [DRIVER.TARGET_URN, "other"]},
            ),
            mock.patch.object(DRIVER, "read_aspect", side_effect=drift_read),
        ):
            drift = DRIVER.inspect_state(
                contract,
                contract_digest,
                "https://tenant.archon-canary.example.test",
                "token",
            )
        self.assertEqual(drift["classification"], "drift")
        self.assertIn("email-pii-classification-present", drift["mismatches"])
        self.assertIn("exact-one-query-readback", drift["mismatches"])

    def test_malformed_g6_evidence_is_unknown_and_never_absent(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        aspects = exact_aspects(contract, contract_digest)
        aspects[
            ("dataset", DRIVER.TARGET_URN, "editableSchemaMetadata")
        ] = envelope(
            {
                "editableSchemaFieldInfo": [
                    {
                        "fieldPath": "email",
                        "globalTags": {"tags": [{"unexpected": "missing-tag-urn"}]},
                    }
                ]
            }
        )

        def malformed_read(
            _gms: str,
            _token: str,
            entity_type: str,
            urn: str,
            aspect: str,
        ) -> dict[str, object] | None:
            return aspects[(entity_type, urn, aspect)]

        with (
            mock.patch.object(
                DRIVER,
                "exact_query",
                return_value={"total": 1, "urns": [DRIVER.TARGET_URN]},
            ),
            mock.patch.object(DRIVER, "read_aspect", side_effect=malformed_read),
        ):
            observed = DRIVER.inspect_state(
                contract,
                contract_digest,
                "https://tenant.archon-canary.example.test",
                "token",
            )

        self.assertEqual(observed["classification"], "drift")
        self.assertEqual(observed["g6Gap"]["classificationState"], "unknown")
        self.assertIs(observed["g6Gap"]["piiClassificationAbsent"], False)
        self.assertIn(
            "email-pii-classification-unknown",
            observed["mismatches"],
        )

    def test_malformed_g6_field_collections_fail_closed(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        schema_fields = [
            schema_field("email", "VARCHAR", "StringType"),
        ]
        malformed_editable_collections = (
            {"fieldPath": "email"},
            [{"unexpected": "field path is not attributable"}],
        )
        for editable_fields in malformed_editable_collections:
            with self.subTest(editable_fields=editable_fields):
                self.assertEqual(
                    DRIVER.pii_classification_state(
                        contract,
                        schema_fields,
                        editable_fields,
                    ),
                    "unknown",
                )

    def test_raw_snapshot_digest_binds_unprojected_editable_metadata(self) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        contract_digest = DRIVER.digest_obj(contract)
        original = exact_aspects(contract, contract_digest)
        changed = copy.deepcopy(original)
        changed[
            ("dataset", DRIVER.TARGET_URN, "editableSchemaMetadata")
        ] = envelope(
            {
                "editableSchemaFieldInfo": [
                    {
                        "fieldPath": "email",
                        "globalTags": {
                            "tags": [{"tag": "urn:li:tag:NonPiiReviewTag"}],
                        },
                    }
                ]
            }
        )

        def observe(
            aspects: dict[
                tuple[str, str, str],
                dict[str, object] | None,
            ],
        ) -> dict[str, object]:
            def read(
                _gms: str,
                _token: str,
                entity_type: str,
                urn: str,
                aspect: str,
            ) -> dict[str, object] | None:
                return aspects[(entity_type, urn, aspect)]

            with (
                mock.patch.object(
                    DRIVER,
                    "exact_query",
                    return_value={"total": 1, "urns": [DRIVER.TARGET_URN]},
                ),
                mock.patch.object(DRIVER, "read_aspect", side_effect=read),
            ):
                return DRIVER.inspect_state(
                    contract,
                    contract_digest,
                    "https://tenant.archon-canary.example.test",
                    "token",
                )

        original_state = observe(original)
        changed_state = observe(changed)
        self.assertEqual(original_state["classification"], "exact")
        self.assertEqual(changed_state["classification"], "exact")
        self.assertEqual(original_state["digest"], changed_state["digest"])
        self.assertNotEqual(
            original_state["rawAspectSnapshotSha256"],
            changed_state["rawAspectSnapshotSha256"],
        )

    def test_seed_plan_creates_absent_is_noop_when_exact_and_rejects_drift(
        self,
    ) -> None:
        contract = copy.deepcopy(REVIEWED_CONTRACT)
        release_sha = "a" * 40
        cases = (
            (
                observed_state(
                    "absent",
                    "1" * 64,
                    dataset_present=False,
                    domain_present=False,
                ),
                "seed",
                True,
            ),
            (
                observed_state(
                    "exact",
                    "2" * 64,
                    dataset_present=True,
                    domain_present=True,
                ),
                "noop",
                False,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            environment = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_TEMP": str(directory),
            }
            for index, (state, operation, mutation_required) in enumerate(cases):
                with self.subTest(operation=operation):
                    output = directory / f"plan-{index}.json"
                    args = SimpleNamespace(
                        contract=str(CONTRACT_PATH),
                        repository=DRIVER.REPOSITORY,
                        release_sha=release_sha,
                        query=DRIVER.QUERY,
                        action="seed",
                        confirmation="",
                        output=str(output),
                    )
                    with (
                        mock.patch.dict(os.environ, environment, clear=False),
                        mock.patch.object(
                            DRIVER,
                            "live_config",
                            return_value=(
                                "https://tenant.archon-canary.example.test",
                                "token",
                                "archon-canary",
                            ),
                        ),
                        mock.patch.object(
                            DRIVER,
                            "inspect_state",
                            return_value=state,
                        ),
                        mock.patch("builtins.print"),
                    ):
                        DRIVER.command_plan(args)
                    plan = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(plan["operation"], operation)
                    self.assertIs(
                        plan["mutationRequired"],
                        mutation_required,
                    )
                    self.assertNotIn("token", output.read_text(encoding="utf-8"))
                    self.assertNotIn(
                        "tenant.archon-canary.example.test",
                        output.read_text(encoding="utf-8"),
                    )

            drift_output = directory / "drift-plan.json"
            drift = observed_state(
                "drift",
                "3" * 64,
                dataset_present=True,
                domain_present=True,
            )
            args.output = str(drift_output)
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=(
                        "https://tenant.archon-canary.example.test",
                        "token",
                        "archon-canary",
                    ),
                ),
                mock.patch.object(DRIVER, "inspect_state", return_value=drift),
                self.assertRaisesRegex(SystemExit, "explicitly confirmed reset"),
            ):
                DRIVER.command_plan(args)
            self.assertFalse(drift_output.exists())

    def test_reset_requires_exact_confirmation_and_delete_is_allowlisted(
        self,
    ) -> None:
        contract = DRIVER.validate_contract(copy.deepcopy(REVIEWED_CONTRACT))
        contract_digest = DRIVER.digest_obj(contract)
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            args = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                repository=DRIVER.REPOSITORY,
                release_sha="b" * 40,
                query=DRIVER.QUERY,
                action="reset",
                confirmation="wrong",
                output=str(directory / "plan.json"),
            )
            with self.assertRaisesRegex(SystemExit, "confirmation"):
                DRIVER.command_plan(args)

        with self.assertRaisesRegex(SystemExit, "two-URN allowlist"):
            DRIVER.delete_owned_urn(
                contract,
                contract_digest,
                "urn:li:dataset:(urn:li:dataPlatform:snowflake,other,TEST)",
                "https://tenant.archon-canary.example.test",
                "token",
            )

        with (
            mock.patch.object(
                DRIVER,
                "request_json",
                return_value={"value": {"rows": 4, "timeseriesRows": 0}},
            ) as request,
            mock.patch.object(DRIVER, "require_live_delete_provenance"),
            mock.patch.object(
                DRIVER,
                "authoritative_entity_present",
                return_value=False,
            ),
        ):
            outcome = DRIVER.delete_owned_urn(
                contract,
                contract_digest,
                DRIVER.TARGET_URN,
                "https://tenant.archon-canary.example.test",
                "token",
            )
        self.assertEqual(outcome, "deleted")
        request.assert_called_once_with(
            "https://tenant.archon-canary.example.test/entities?action=delete",
            "token",
            method="POST",
            body={"urn": DRIVER.TARGET_URN},
            restli=True,
        )

    def test_reset_refuses_foreign_provenance_before_deletion(self) -> None:
        foreign = observed_state(
            "drift",
            "4" * 64,
            dataset_present=True,
            domain_present=True,
            marker_exact=False,
            g6_state="present",
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            args = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                repository=DRIVER.REPOSITORY,
                release_sha="b" * 40,
                query=DRIVER.QUERY,
                action="reset",
                confirmation=REVIEWED_CONTRACT["resetConfirmation"],
                output=str(directory / "plan.json"),
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "GITHUB_ACTIONS": "true",
                        "RUNNER_TEMP": str(directory),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    DRIVER,
                    "live_config",
                    return_value=(
                        "https://tenant.archon-canary.example.test",
                        "token",
                        "archon-canary",
                    ),
                ),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    return_value=foreign,
                ),
                self.assertRaisesRegex(SystemExit, "provenance marker"),
            ):
                DRIVER.command_plan(args)
            self.assertFalse((directory / "plan.json").exists())

    def test_hard_delete_fails_on_invalid_response_or_retained_key(self) -> None:
        contract = DRIVER.validate_contract(copy.deepcopy(REVIEWED_CONTRACT))
        contract_digest = DRIVER.digest_obj(contract)
        gms = "https://tenant.archon-canary.example.test"
        with (
            mock.patch.object(
                DRIVER,
                "read_aspect",
                return_value=envelope(
                    {"customProperties": {"archonFixturePurpose": "foreign"}}
                ),
            ),
            mock.patch.object(DRIVER, "request_json") as forbidden_request,
            self.assertRaisesRegex(SystemExit, "exact Archon provenance"),
        ):
            DRIVER.delete_owned_urn(
                contract,
                contract_digest,
                DRIVER.TARGET_URN,
                gms,
                "token",
            )
        forbidden_request.assert_not_called()

        with (
            mock.patch.object(DRIVER, "require_live_delete_provenance"),
            mock.patch.object(
                DRIVER,
                "request_json",
                return_value={"value": {"rows": 0, "timeseriesRows": 0}},
            ),
            self.assertRaisesRegex(SystemExit, "did not prove removal"),
        ):
            DRIVER.delete_owned_urn(
                contract,
                contract_digest,
                DRIVER.TARGET_URN,
                gms,
                "token",
            )

        with (
            mock.patch.object(
                DRIVER,
                "authoritative_entity_present",
                side_effect=(False, True),
            ),
            self.assertRaisesRegex(SystemExit, "authoritative entity keys"),
        ):
            DRIVER.require_owned_urns_absent(gms, "token")

        with (
            mock.patch.object(DRIVER, "require_live_delete_provenance"),
            mock.patch.object(
                DRIVER,
                "request_json",
                return_value={"value": {"rows": 3, "timeseriesRows": 0}},
            ),
            mock.patch.object(
                DRIVER,
                "authoritative_entity_present",
                return_value=True,
            ),
            mock.patch.object(
                DRIVER.time,
                "monotonic",
                side_effect=(0, 121),
            ),
            mock.patch.object(DRIVER.time, "sleep"),
            self.assertRaisesRegex(SystemExit, "authoritative key"),
        ):
            DRIVER.delete_owned_urn(
                contract,
                contract_digest,
                DRIVER.TARGET_URN,
                gms,
                "token",
            )

    def test_seed_and_reset_apply_mutation_matrix(self) -> None:
        cases = (
            (
                "seed",
                "",
                observed_state(
                    "absent",
                    "6" * 64,
                    dataset_present=False,
                    domain_present=False,
                ),
                "seeded",
                0,
            ),
            (
                "reset",
                REVIEWED_CONTRACT["resetConfirmation"],
                observed_state(
                    "drift",
                    "7" * 64,
                    dataset_present=True,
                    domain_present=True,
                    marker_exact=True,
                    g6_state="present",
                ),
                "reset",
                2,
            ),
        )
        exact = observed_state(
            "exact",
            "8" * 64,
            dataset_present=True,
            domain_present=True,
        )
        common_live = (
            "https://tenant.archon-canary.example.test",
            "super-secret-token",
            "archon-canary",
        )
        for index, (
            action,
            confirmation,
            before,
            expected_outcome,
            expected_deletes,
        ) in enumerate(cases):
            with (
                self.subTest(action=action),
                tempfile.TemporaryDirectory() as temporary,
            ):
                directory = pathlib.Path(temporary)
                environment = {
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_TEMP": str(directory),
                }
                plan_path = directory / f"plan-{index}.json"
                plan_args = SimpleNamespace(
                    contract=str(CONTRACT_PATH),
                    repository=DRIVER.REPOSITORY,
                    release_sha="d" * 40,
                    query=DRIVER.QUERY,
                    action=action,
                    confirmation=confirmation,
                    output=str(plan_path),
                )
                with (
                    mock.patch.dict(os.environ, environment, clear=False),
                    mock.patch.object(
                        DRIVER,
                        "live_config",
                        return_value=common_live,
                    ),
                    mock.patch.object(
                        DRIVER,
                        "inspect_state",
                        return_value=before,
                    ),
                    mock.patch("builtins.print"),
                ):
                    DRIVER.command_plan(plan_args)

                receipt_path = directory / f"receipt-{index}.json"
                apply_args = SimpleNamespace(
                    contract=str(CONTRACT_PATH),
                    plan=str(plan_path),
                    expected_plan_sha256=DRIVER.digest_bytes(
                        plan_path.read_bytes()
                    ),
                    confirmation=confirmation,
                    release_sha="d" * 40,
                    repository=DRIVER.REPOSITORY,
                    workflow_run_id="84",
                    workflow_run_attempt="2",
                    receipt=str(receipt_path),
                )
                prepared = {"prepared": True}
                with (
                    mock.patch.dict(os.environ, environment, clear=False),
                    mock.patch.object(
                        DRIVER,
                        "live_config",
                        return_value=common_live,
                    ),
                    mock.patch.object(
                        DRIVER,
                        "inspect_state",
                        side_effect=(before, before),
                    ),
                    mock.patch.object(
                        DRIVER,
                        "prepare_emission",
                        return_value=prepared,
                    ),
                    mock.patch.object(DRIVER, "emit_prepared") as emit,
                    mock.patch.object(DRIVER, "close_prepared") as close,
                    mock.patch.object(
                        DRIVER,
                        "delete_owned_urn",
                        return_value="deleted",
                    ) as delete,
                    mock.patch.object(
                        DRIVER,
                        "require_owned_urns_absent",
                    ) as require_absent,
                    mock.patch.object(
                        DRIVER,
                        "wait_for_exact",
                        return_value=exact,
                    ),
                    mock.patch("builtins.print"),
                ):
                    DRIVER.command_apply(apply_args)

                emit.assert_called_once_with(prepared)
                close.assert_called_once_with(prepared)
                require_absent.assert_called_once_with(
                    common_live[0],
                    common_live[1],
                )
                self.assertEqual(delete.call_count, expected_deletes)
                if expected_deletes:
                    self.assertEqual(
                        [call.args[2] for call in delete.call_args_list],
                        [DRIVER.TARGET_URN, DRIVER.DOMAIN_URN],
                    )
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                self.assertEqual(receipt["outcome"], expected_outcome)
                self.assertEqual(len(receipt["resetDeletes"]), expected_deletes)
                self.assertNotIn(
                    b"super-secret-token",
                    receipt_path.read_bytes(),
                )

    def test_apply_rechecks_raw_snapshot_immediately_before_mutation(self) -> None:
        before = observed_state(
            "absent",
            "9" * 64,
            dataset_present=False,
            domain_present=False,
        )
        changed = copy.deepcopy(before)
        changed["rawAspectSnapshotSha256"] = "a" * 64
        common_live = (
            "https://tenant.archon-canary.example.test",
            "token",
            "archon-canary",
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            environment = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_TEMP": str(directory),
            }
            plan_path = directory / "plan.json"
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(DRIVER, "live_config", return_value=common_live),
                mock.patch.object(DRIVER, "inspect_state", return_value=before),
                mock.patch("builtins.print"),
            ):
                DRIVER.command_plan(
                    SimpleNamespace(
                        contract=str(CONTRACT_PATH),
                        repository=DRIVER.REPOSITORY,
                        release_sha="e" * 40,
                        query=DRIVER.QUERY,
                        action="seed",
                        confirmation="",
                        output=str(plan_path),
                    )
                )

            receipt_path = directory / "receipt.json"
            apply_args = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                plan=str(plan_path),
                expected_plan_sha256=DRIVER.digest_bytes(plan_path.read_bytes()),
                confirmation="",
                release_sha="e" * 40,
                repository=DRIVER.REPOSITORY,
                workflow_run_id="85",
                workflow_run_attempt="1",
                receipt=str(receipt_path),
            )
            prepared = {"prepared": True}
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(DRIVER, "live_config", return_value=common_live),
                mock.patch.object(
                    DRIVER,
                    "inspect_state",
                    side_effect=(before, changed),
                ),
                mock.patch.object(
                    DRIVER,
                    "prepare_emission",
                    return_value=prepared,
                ),
                mock.patch.object(DRIVER, "emit_prepared") as forbidden_emit,
                mock.patch.object(DRIVER, "close_prepared") as close,
                mock.patch.object(
                    DRIVER,
                    "delete_owned_urn",
                ) as forbidden_delete,
                mock.patch.object(
                    DRIVER,
                    "require_owned_urns_absent",
                ) as forbidden_absence_check,
                self.assertRaisesRegex(SystemExit, "immediately before mutation"),
            ):
                DRIVER.command_apply(apply_args)
            forbidden_emit.assert_not_called()
            forbidden_delete.assert_not_called()
            forbidden_absence_check.assert_not_called()
            close.assert_called_once_with(prepared)
            self.assertFalse(receipt_path.exists())

    def test_exact_seed_noop_writes_a_canonical_sanitized_receipt(self) -> None:
        exact = observed_state(
            "exact",
            "5" * 64,
            dataset_present=True,
            domain_present=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            environment = {
                "GITHUB_ACTIONS": "true",
                "RUNNER_TEMP": str(directory),
            }
            plan_path = directory / "plan.json"
            plan_args = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                repository=DRIVER.REPOSITORY,
                release_sha="c" * 40,
                query=DRIVER.QUERY,
                action="seed",
                confirmation="",
                output=str(plan_path),
            )
            common_live = (
                "https://tenant.archon-canary.example.test",
                "super-secret-token",
                "archon-canary",
            )
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(DRIVER, "live_config", return_value=common_live),
                mock.patch.object(DRIVER, "inspect_state", return_value=exact),
                mock.patch("builtins.print"),
            ):
                DRIVER.command_plan(plan_args)
            plan_sha = DRIVER.digest_bytes(plan_path.read_bytes())
            receipt_path = directory / "receipt.json"
            apply_args = SimpleNamespace(
                contract=str(CONTRACT_PATH),
                plan=str(plan_path),
                expected_plan_sha256=plan_sha,
                confirmation="",
                release_sha="c" * 40,
                repository=DRIVER.REPOSITORY,
                workflow_run_id="42",
                workflow_run_attempt="1",
                receipt=str(receipt_path),
            )
            with (
                mock.patch.dict(os.environ, environment, clear=False),
                mock.patch.object(DRIVER, "live_config", return_value=common_live),
                mock.patch.object(DRIVER, "inspect_state", return_value=exact),
                mock.patch.object(DRIVER, "prepare_emission") as forbidden_emit,
                mock.patch("builtins.print"),
            ):
                DRIVER.command_apply(apply_args)
            forbidden_emit.assert_not_called()
            raw = receipt_path.read_bytes()
            receipt = json.loads(raw)
            self.assertEqual(raw, DRIVER.canonical_bytes(receipt))
            self.assertEqual(receipt["outcome"], "unchanged")
            self.assertEqual(receipt["exactQueryMatchCount"], 1)
            self.assertNotIn(b"super-secret-token", raw)
            self.assertNotIn(b"tenant.archon-canary.example.test", raw)

    def test_validate_runtime_is_credentialless_and_sanitized(self) -> None:
        class FakeAspect:
            def __init__(self, name: str, value: dict[str, object]) -> None:
                self.name = name
                self.value = value

            def get_aspect_name(self) -> str:
                return self.name

            def to_obj(self) -> dict[str, object]:
                return self.value

        proposals = [
            SimpleNamespace(
                entityUrn=DRIVER.TARGET_URN,
                aspect=FakeAspect("datasetProperties", {"name": "fixture"}),
            ),
            SimpleNamespace(
                entityUrn=DRIVER.DOMAIN_URN,
                aspect=FakeAspect("domainProperties", {"name": "domain"}),
            ),
        ]
        with (
            mock.patch.object(
                DRIVER,
                "build_proposals",
                return_value=(proposals, object(), object()),
            ),
            mock.patch.object(DRIVER, "live_config") as forbidden_live_config,
            mock.patch("builtins.print") as output,
        ):
            DRIVER.command_validate_runtime(
                SimpleNamespace(contract=str(CONTRACT_PATH))
            )
        forbidden_live_config.assert_not_called()
        payload = json.loads(output.call_args.args[0])
        self.assertEqual(
            set(payload),
            {
                "schemaVersion",
                "stateContractSha256",
                "proposalCount",
                "proposalSetSha256",
            },
        )
        self.assertEqual(payload["proposalCount"], 2)
        self.assertRegex(payload["stateContractSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(payload["proposalSetSha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(DRIVER.TARGET_URN, output.call_args.args[0])
        self.assertNotIn(DRIVER.DOMAIN_URN, output.call_args.args[0])

    @unittest.skipUnless(
        os.environ.get("ARCHON_LOCKED_DATAHUB_RUNTIME") == "true",
        "requires the CI-materialized locked acryl-datahub runtime",
    )
    def test_locked_sdk_builds_and_validates_exact_proposals(self) -> None:
        contract = DRIVER.validate_contract(copy.deepcopy(REVIEWED_CONTRACT))
        contract_digest = DRIVER.digest_obj(contract)
        proposals, emitter_class, emit_mode = DRIVER.build_proposals(
            contract,
            contract_digest,
        )
        self.assertEqual(len(proposals), 6)
        self.assertTrue(
            all(
                proposal.validate() and proposal.make_mcp().validate()
                for proposal in proposals
            )
        )
        expected_marker = DRIVER.expected_custom_properties(
            contract,
            contract_digest,
        )
        properties = {
            proposal.aspect.get_aspect_name(): proposal.aspect.to_obj()
            for proposal in proposals
            if proposal.aspect.get_aspect_name()
            in {"datasetProperties", "domainProperties"}
        }
        self.assertEqual(
            properties["datasetProperties"]["customProperties"],
            expected_marker,
        )
        self.assertEqual(
            properties["domainProperties"]["customProperties"],
            expected_marker,
        )
        self.assertEqual(emitter_class.__name__, "DataHubRestEmitter")
        self.assertIsNotNone(emit_mode.SYNC_PRIMARY)

    def test_controller_source_has_no_shell_or_local_bootstrap_escape_hatch(
        self,
    ) -> None:
        source = DRIVER_PATH.read_text(encoding="utf-8")
        self.assertIn('os.environ.get("GITHUB_ACTIONS") != "true"', source)
        self.assertIn("RejectDataHubRedirects", source)
        self.assertIn("urllib.request.ProxyHandler({})", source)
        self.assertIn('f"{gms}/entities?action=delete"', source)
        self.assertIn('"X-RestLi-Protocol-Version": "2.0.0"', source)
        self.assertIn('commands.add_parser("validate-runtime")', source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("--datahub-cli", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("verify=False", source)


if __name__ == "__main__":
    unittest.main()
