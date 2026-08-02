from __future__ import annotations

import importlib.util
import pathlib
import sqlite3
import tempfile
from unittest import TestCase, main

path = pathlib.Path(__file__).with_name("seed_datahub.py")
spec = importlib.util.spec_from_file_location("seed_datahub", path)
assert spec is not None and spec.loader is not None
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class PortableDemoSeedTests(TestCase):
    def test_regenerates_expected_q2_result_in_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / "archon-demo.sqlite"
            seed.create_database(database)
            self.assertTrue(database.is_file())
            connection = sqlite3.connect(database)
            try:
                rows = connection.execute(
                    "SELECT segment, customer_count, net_revenue_cents "
                    "FROM customer_segment_revenue "
                    "ORDER BY net_revenue_cents DESC, segment"
                ).fetchall()
            finally:
                connection.close()
        self.assertEqual(
            rows,
            [
                ("enterprise", 2, 1850000),
                ("smb", 1, 1200000),
                ("mid_market", 1, 900000),
            ],
        )

    def test_metadata_plan_matches_canonical_core_story(self) -> None:
        plan = seed.metadata_plan()
        self.assertEqual(
            plan["source"]["urn"],
            "urn:li:dataset:(urn:li:dataPlatform:sqlite,"
            "archon_demo.customers,PROD)",
        )
        self.assertEqual(
            plan["downstream"]["upstreams"], [plan["source"]["urn"]]
        )
        self.assertEqual(plan["schemaVersion"], "archon.datahub-core-demo-seed/v2")
        self.assertEqual(plan["source"]["customerEmailTags"], [])
        self.assertIn("customers.customer_email", plan["question"])
        self.assertTrue(plan["source"]["quality"]["q2RevenueReconciled"])
        self.assertEqual(
            plan["domain"]["datasets"],
            [plan["source"]["urn"], plan["downstream"]["urn"]],
        )
        self.assertEqual(
            plan["glossaryTerm"]["datasets"], [plan["downstream"]["urn"]]
        )
        self.assertIn("Gross recognized revenue minus refunds", plan["glossaryTerm"]["definition"])
        self.assertIn("2026-04-01", plan["glossaryTerm"]["definition"])
        self.assertIn("2026-07-01", plan["glossaryTerm"]["definition"])
        self.assertIn(plan["source"]["urn"], plan["query"]["subjects"])
        self.assertIn("ORDER BY net_revenue_cents DESC", plan["query"]["statement"])

    def test_metadata_entities_are_defined_before_dataset_references(self) -> None:
        source = path.read_text("utf-8")
        owner = source.index("aspect=CorpUserInfoClass(")
        tag = source.index("aspect=TagPropertiesClass(")
        domain = source.index("aspect=DomainPropertiesClass(")
        term = source.index("aspect=GlossaryTermInfoClass(")
        dataset = source.index("aspect=DatasetPropertiesClass(")
        self.assertLess(owner, dataset)
        self.assertLess(tag, dataset)
        self.assertLess(domain, dataset)
        self.assertLess(term, dataset)
        self.assertIn("DomainsClass(domains=[DOMAIN_URN])", source)
        self.assertIn("GlossaryTermsClass(", source)
        self.assertIn("QueryPropertiesClass(", source)
        self.assertIn("QuerySubjectsClass(", source)
        self.assertNotIn("TagAssociationClass", source)

    def test_repository_contains_source_only_not_generated_database(self) -> None:
        directory = pathlib.Path(__file__).parent
        generated = [
            item.name
            for item in directory.iterdir()
            if item.suffix in {".db", ".sqlite", ".sqlite3"}
        ]
        self.assertEqual(generated, [])


if __name__ == "__main__":
    main()