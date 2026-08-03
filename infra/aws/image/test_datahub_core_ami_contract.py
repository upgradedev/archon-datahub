from __future__ import annotations

import json
import pathlib
from unittest import TestCase, main

ROOT = pathlib.Path(__file__).resolve().parents[3]
CONTRACT_PATH = (
    ROOT / "infra/aws/packer/datahub-core-ami-builder-policy-contract.json"
)
LOCK_PATH = ROOT / "infra/aws/image/datahub-core-image.lock.json"
WORKFLOW_PATH = ROOT / ".github/workflows/datahub-core-ami.yml"
PACKER_PATH = ROOT / "infra/aws/packer/datahub-core.pkr.hcl"
PROVISION_PATH = ROOT / "infra/aws/packer/provision-datahub-core.sh"


class AmiBuilderPolicyContractTests(TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT_PATH.read_text("utf-8"))
        self.lock = json.loads(LOCK_PATH.read_text("utf-8"))
        self.workflow = WORKFLOW_PATH.read_text("utf-8")
        self.packer = PACKER_PATH.read_text("utf-8")
        self.provision = PROVISION_PATH.read_text("utf-8")

    def test_contract_has_no_wildcard_action_and_exact_sensitive_resources(self) -> None:
        self.assertEqual(
            self.contract["schemaVersion"],
            "archon.datahub-core-ami-builder-iam/v1",
        )
        actions = [
            action
            for group in self.contract["actionGroups"].values()
            for action in group
        ]
        self.assertEqual(len(actions), len(set(actions)))
        self.assertTrue(all("*" not in action for action in actions))
        self.assertEqual(
            self.contract["resourcePatterns"]["al2023Parameter"],
            "arn:aws:ssm:eu-west-1::parameter/aws/service/"
            "ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
        )
        self.assertEqual(
            self.contract["conditions"]["passRole"]["StringEquals"],
            {"iam:PassedToService": "ec2.amazonaws.com"},
        )
        self.assertEqual(
            self.contract["stableBuilderIdentity"]["managedPolicy"],
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        )
        self.assertEqual(
            self.contract["oidcTrust"]["subject"],
            "repo:upgradedev/archon-datahub:environment:staging",
        )
        self.assertIn("iam:PassRole", actions)
        self.assertIn("cloudtrail:LookupEvents", actions)
        self.assertNotIn("ec2:AuthorizeSecurityGroupIngress", actions)
        for denied in (
            "iam:CreateRole",
            "iam:DeleteRole",
            "iam:CreateInstanceProfile",
            "iam:DeleteInstanceProfile",
            "ec2:AuthorizeSecurityGroupIngress",
        ):
            self.assertNotIn(denied, actions)
            self.assertIn(denied, self.contract["deniedByContract"])

    def test_build_boundary_is_exactly_tagged_and_cloudtrail_proven(self) -> None:
        required = {
            "Application": "archon-datahub",
            "Environment": "staging",
            "ManagedBy": "github-actions",
            "archon:Purpose": "datahub-core-ami",
            "archon:BuildRun": "{workflowRunId}",
        }
        self.assertEqual(
            self.lock["builder"]["requestTagProof"]["requiredTags"],
            required,
        )
        for source in (self.workflow, self.packer):
            for key, value in required.items():
                self.assertIn(key, source)
                if value != "{workflowRunId}":
                    self.assertIn(value, source)
        self.assertIn("aws ec2 create-key-pair", self.workflow)
        self.assertIn("--key-type ed25519", self.workflow)
        self.assertIn("aws ec2 delete-key-pair", self.workflow)
        self.assertIn("aws cloudtrail", self.workflow)
        self.assertIn("lookup-events", self.workflow)
        self.assertIn("archon.packer-request-tag-proof/v1", self.workflow)
        for event in ("CreateKeyPair", "CreateSecurityGroup", "RunInstances"):
            self.assertIn(event, self.workflow)
        self.assertIn('"accountIdentifierRetained": false', LOCK_PATH.read_text("utf-8"))
        self.assertIn("accountIdentifierRetained: false", self.workflow)
        self.assertIn("requestTagProofDigest", self.workflow)
        self.assertIn('rm -f -- "${PRIVATE_KEY_FILE}"', self.workflow)
        self.assertIn('test ! -e "${PRIVATE_KEY_FILE}"', self.workflow)

    def test_packer_uses_run_owned_key_and_clears_runtime_authorized_keys(self) -> None:
        self.assertIn('communicator                = "ssh"', self.packer)
        self.assertIn('ssh_interface               = "session_manager"', self.packer)
        self.assertIn("ssh_keypair_name            = var.builder_key_pair_name", self.packer)
        self.assertIn("ssh_private_key_file        = var.builder_private_key_file", self.packer)
        self.assertIn("ssh_clear_authorized_keys   = true", self.packer)
        self.assertNotIn("temporary_key_pair_type", self.packer)
        self.assertIn("bake_evidence_output", self.packer)
        self.assertIn("direction   = \"download\"", self.packer)
        self.assertIn("datahub-core-bake-evidence.tar.gz", self.packer)
        for tag in ("Application", "Environment", "ManagedBy", "archon:BuildRun"):
            self.assertGreaterEqual(self.packer.count(tag), 4)

    def test_core_images_are_resolved_once_scanned_sequentially_and_never_repulled(self) -> None:
        policy = self.lock["dataHubCore"]["containerPolicy"]
        self.assertEqual(policy["resolution"], "resolve-once-in-ci")
        self.assertEqual(policy["resolutionCount"], 1)
        self.assertTrue(policy["pullDuringAmiBuild"])
        self.assertEqual(policy["amiBuildPullReference"], "exact RepoDigest only")
        self.assertEqual(policy["scanOrder"], "sequential")
        self.assertFalse(policy["runtimePullsAllowed"])
        self.assertFalse(policy["vexGenerated"])
        self.assertIn(
            "aquasecurity/setup-trivy@3fb12ec12f41e471780db15c232d5dd185dcb514",
            self.workflow,
        )
        self.assertIn("TRIVY_VERSION: v0.70.0", self.workflow)
        self.assertIn("trivy image --download-db-only", self.workflow)
        self.assertIn('for reference in "${references[@]}"', self.workflow)
        self.assertIn("docker image rm --force", self.workflow)
        self.assertIn("docker system prune --all --force --volumes", self.workflow)
        for value in (
            "--format json",
            "--format sarif",
            "--format cyclonedx",
            "--format spdx-json",
            "aggregate.cdx.json",
            "aggregate.spdx.json",
            "rawFindingsRetained:true",
            "unfixedFindingsRetained:true",
            'actionableGate:"fixed HIGH,CRITICAL"',
            "vexGenerated:false",
        ):
            self.assertIn(value, self.workflow)
        self.assertIn('docker pull --quiet "${resolved}"', self.provision)
        self.assertNotIn('docker pull --quiet "${reference}"', self.provision)
        self.assertIn('pull_policy:"never"', self.provision)
        self.assertIn("docker-compose.images.yml", self.provision)

    def test_al2023_is_patched_scanned_and_scanner_is_removed(self) -> None:
        base_policy = self.lock["builder"]["baseImagePolicy"]
        scanner = self.lock["builder"]["scanner"]
        self.assertTrue(base_policy["dnfUpgradeDuringBake"])
        self.assertEqual(base_policy["applicableSecurityUpdatesRequired"], 0)
        self.assertTrue(base_policy["osCycloneDx"])
        self.assertTrue(base_policy["osSpdx"])
        self.assertTrue(scanner["scannerBinaryRemovedFromAmi"])
        self.assertTrue(scanner["scannerDatabaseRemovedFromAmi"])
        self.assertTrue(scanner["databaseMetadataRetained"])
        self.assertTrue(scanner["unfixedFindingsRetained"])
        self.assertFalse(scanner["vexGenerated"])
        for value in (
            "dnf --refresh upgrade -y",
            "dnf --refresh check-update --security",
            "trivy rootfs --scanners vuln --pkg-types os",
            '--format cyclonedx',
            '--format spdx-json',
            "installed-rpms.tsv",
            "archon.al2023-security-update-proof/v1",
            "archon.ami-scanner-removal-proof/v1",
            "trivy-db-metadata.json",
            "databaseMetadataSha256",
            "test -z \"$(command -v trivy || true)\"",
            "test ! -e \"${TRIVY_CACHE_DIR}\"",
        ):
            self.assertIn(value, self.provision)
        self.assertNotIn("openvex", self.provision.lower())

    def test_ami_and_request_tag_evidence_are_sealed_and_attested(self) -> None:
        self.assertIn("archon.datahub-core-ami-build/v2", self.workflow)
        self.assertIn("archon.datahub-core-resolved-images/v1", self.workflow)
        self.assertIn("archon.datahub-core-ami-manifest/v2", self.workflow)
        self.assertIn("requestTagProofFileSha256", self.workflow)
        self.assertIn("bakeEvidenceArchiveSha256", self.workflow)
        self.assertIn("databaseMetadataRetained", self.workflow)
        self.assertIn("aggregateCycloneDxSha256", self.workflow)
        self.assertIn("aggregateSpdxSha256", self.workflow)
        self.assertIn("actions/attest-build-provenance@", self.workflow)
        for path in (
            "steps.request_tags.outputs.path",
            "steps.packer.outputs.bake_evidence",
            "steps.bake.outputs.directory",
            "steps.core_images.outputs.directory",
        ):
            self.assertIn(path, self.workflow)
        self.assertEqual(
            self.lock["evidence"]["amiBuildSchema"],
            "archon.datahub-core-ami-build/v2",
        )

    def test_cleanup_is_run_owned_and_failed_images_are_not_retained(self) -> None:
        cleanup = self.contract["cleanup"]
        self.assertEqual(cleanup["failure"]["retain"], [])
        self.assertIn("run-tagged partial AMIs", cleanup["failure"]["delete"])
        for action in (
            "deregister-image",
            "delete-snapshot",
            "delete-key-pair",
            "delete-vpc",
        ):
            self.assertIn(action, self.workflow)
        for denied in (
            "delete-instance-profile",
            "create-instance-profile",
            "create-role",
            "attach-role-policy",
            "remove-role-from-instance-profile",
            "authorize-security-group-ingress",
        ):
            self.assertNotIn(denied, self.workflow)
        self.assertIn("retained foundation-managed", cleanup["stableIdentity"])

    def test_ami_never_contains_generated_demo_or_runtime_credentials(self) -> None:
        self.assertIn(
            'test ! -e "${install_root}/core/demo/archon-demo.sqlite"',
            self.provision,
        )
        self.assertIn(
            "test ! -e /run/archon/datahub-credentials.json", self.provision
        )
        self.assertIn("staticArchonCredentialsPresent: false", self.provision)
        self.assertIn(
            "vendorLoopbackBootstrapCredentialRequired: true", self.provision
        )
        self.assertIn("dataHubHardenedComposeSha256", self.provision)
        self.assertIn("generatedDatabasePresent: false", self.provision)
        self.assertIn(
            "services/datahub-companion/demo/seed_datahub.py", self.provision
        )
        self.assertNotIn("archon-governed-gateway.service", self.provision)

    def test_lock_seals_dual_runtime_security_contracts(self) -> None:
        runtime = self.lock["runtime"]
        gateway = runtime["governedGateway"]
        self.assertEqual(
            self.lock["schemaVersion"], "archon.datahub-core-image-lock/v2"
        )
        self.assertEqual(
            set(self.lock["agentStack"]["requiredComponents"]),
            {
                "mcp-server-datahub",
                "datahub-agent-context",
                "datahub-skills",
                "datahub-analytics-agent",
            },
        )
        self.assertEqual(
            gateway["authorization"]["algorithm"], "KMS_ECDSA_SHA_256"
        )
        self.assertEqual(
            gateway["authorization"]["keySpec"], "ECC_NIST_P256"
        )
        self.assertFalse(gateway["unauthenticatedCallsAllowed"])
        self.assertEqual(
            runtime["networkIsolation"]["interfaceEndpoints"],
            ["bedrock-runtime", "kms", "sts"],
        )
        self.assertEqual(
            runtime["credentials"]["analyticsRoleProof"]["operation"],
            "GetCallerIdentity",
        )
        analytics = runtime["analyticsAgent"]
        self.assertEqual(analytics["oauthMasterKey"]["mode"], "0600")
        self.assertFalse(analytics["plaintextDataHubTokenAtRestAllowed"])
        self.assertEqual(
            analytics["readinessTokenScan"],
            ["state.sqlite", "state.sqlite-wal", "state.sqlite-shm"],
        )


if __name__ == "__main__":
    main()