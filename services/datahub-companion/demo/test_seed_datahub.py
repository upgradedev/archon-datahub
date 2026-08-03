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
                segments = [
                    row[0]
                    for row in connection.execute(
                        "SELECT DISTINCT segment FROM customers ORDER BY segment"
                    ).fetchall()
                ]
                q2_gross = connection.execute(
                    "SELECT SUM(gross_revenue_cents) FROM orders "
                    "WHERE recognized_at >= '2026-04-01T00:00:00Z' "
                    "AND recognized_at < '2026-07-01T00:00:00Z'"
                ).fetchone()[0]
                q2_refunds = connection.execute(
                    "SELECT SUM(r.refund_cents) "
                    "FROM refunds AS r "
                    "JOIN orders AS o ON o.order_id = r.order_id "
                    "WHERE o.recognized_at >= '2026-04-01T00:00:00Z' "
                    "AND o.recognized_at < '2026-07-01T00:00:00Z' "
                    "AND r.recognized_at >= '2026-04-01T00:00:00Z' "
                    "AND r.recognized_at < '2026-07-01T00:00:00Z'"
                ).fetchone()[0]
            finally:
                connection.close()
        self.assertEqual(
            rows,
            [
                ("enterprise", 2, 1850000),
                ("mid_market", 1, 1150000),
                ("small_business", 1, 600000),
            ],
        )
        self.assertEqual(
            segments,
            ["enterprise", "mid_market", "small_business"],
        )
        self.assertEqual(q2_gross, 4000000)
        self.assertEqual(q2_refunds, 400000)
        self.assertEqual(
            sum(net_revenue_cents for _, _, net_revenue_cents in rows),
            q2_gross - q2_refunds,
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

    def test_cloud_emitter_requires_exact_explicit_tenant_binding(self) -> None:
        seed._validate_emitter_target("http://127.0.0.1:18080", None)
        seed._validate_emitter_target(
            "https://demo.acryl.io/gms",
            "demo.acryl.io",
        )
        invalid = (
            ("https://demo.acryl.io/gms", None),
            ("https://demo.acryl.io/gms", "other.acryl.io"),
            ("https://demo.acryl.io:443/gms", "demo.acryl.io"),
            ("https://demo.acryl.io/gms?token=x", "demo.acryl.io"),
            ("https://demo.acryl.io.evil.invalid/gms", "demo.acryl.io"),
            ("http://127.0.0.1:18080", "demo.acryl.io"),
        )
        for gms_url, tenant_host in invalid:
            with self.subTest(gms_url=gms_url, tenant_host=tenant_host):
                with self.assertRaises(RuntimeError):
                    seed._validate_emitter_target(gms_url, tenant_host)

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