# Ephemeral DataHub Core judge runtime

Archon is one portable product with two DataHub runtime profiles:

- `cloud`: a DataHub Cloud trial or paid tenant whose endpoints, credentials, and required capabilities pass the live preflight.
- `core`: DataHub Core v1.6.0 on one ephemeral EC2 host, reproduced from immutable CI evidence.

The application keeps a visible `Auto / Cloud / Core` selector. `Auto` prefers a healthy Cloud binding and otherwise offers Core. A binding is immutable for the lifetime of a run, and judges can always select `Core` explicitly. Core is not an EKS deployment.

## What the Core control creates

The persistent control plane is serverless: S3/CloudFront, API Gateway, Lambda, Step Functions, DynamoDB, and an Auto Scaling group fixed at `min=0`, `max=1`. Compute remains at zero while no Core session exists.

Starting Core performs an authoritative DynamoDB compare-and-swap, creates session-owned private interface endpoints for Bedrock Runtime, KMS, and regional STS, and scales one private `t3a.xlarge` host from the CI-baked AMI. DynamoDB uses the VPC gateway endpoint. The runtime host has no public IP, inbound rule, SSH key, NAT gateway, load balancer, or persistent application volume.

The lease has a 30-minute idle deadline, a two-hour hard deadline, a server-derived countdown, exact-revision watchdogs, and a five-minute independent reaper. Stop, expiry, or failed startup drains work, scales the ASG to zero, deletes all three session-owned interface endpoints by exact identifiers, and terminates the encrypted root volume. CloudWatch is evidence and observability; it is not the lease authority.

## The four required DataHub components

- The official `mcp-server-datahub==0.6.0` exposes the sealed read-only tool set on loopback port 8000.
- Agent Context Kit and the pinned official DataHub Skills run in the companion image.
- Analytics Agent v0.4.0 runs its deterministic SQLite engine on loopback port 8100 and uses the configured Bedrock inference profile.
- The companion orchestrates the bounded end-to-end workflow and exposes only its loopback health/API surface.

`governed_datahub_gateway.py` is an Archon policy gateway, not the official DataHub MCP Server. It is the narrow write boundary on loopback port 8001. It verifies a human-approved, evidence-bound mutation envelope and delegates only the allowlisted `add_tags` or `remove_tags` operation to an isolated official writer MCP container.

## Credentials, authorization, and container boundaries

After GMS is healthy, every session mints three distinct DataHub credentials:

- the read PAT is available only to the official read MCP and companion;
- the write PAT is available only to the official writer MCP and governed gateway;
- the one-hour seed token is used for deterministic bootstrap and then revoked.

Credentials live only in regular mode-0600 files under `/run/archon`; the AMI contains no PAT. Separate `archon-read`, `archon-writer`, and `archon-bedrock-egress` bridges prevent the official writer from becoming a general read or network path.

Every mutation uses the golden `KMS_ECDSA_SHA_256` contract in `contracts/datahub-core-mutation-authorization-golden.json`. The cloud-side signer has `kms:Sign` on one dedicated `ECC_NIST_P256` key. The gateway retrieves only the public key, verifies the canonical UTF-8 JSON envelope, enforces expiry/session/job/credential-version bindings, and never receives signing authority. Mutations remain exact-schema, approval-bound, read-before/write/read-after verified, idempotent, and sealed in a canonical receipt.

Analytics receives one-hour scoped AWS credentials for an exact Bedrock-only role. Before readiness, it calls `GetCallerIdentity` through the private regional STS endpoint and compares the returned identity with the server-owned `ARCHON_EXPECTED_ANALYTICS_ROLE_ARN`; a client cannot choose that expected role. The endpoint policy permits only `sts:GetCallerIdentity` to that exact role.

Analytics uses a valid 32-byte Fernet `OAUTH_MASTER_KEY` stored only in `/run/archon/analytics.env` at mode 0600 and kept stable during scoped-credential rotation. The exact DataHub read PAT is not an Analytics environment value. Readiness still scans `state.sqlite`, `state.sqlite-wal`, and `state.sqlite-shm` byte-for-byte for the PAT and fails closed if plaintext is found. The resulting proof contains paths and digests, never the token.

## Portable deterministic fixture

Source fixtures are committed; generated databases are not:

- `services/datahub-companion/demo/archon_demo.sql`
- `services/datahub-companion/demo/seed_datahub.py`

Every session regenerates `/run/archon/demo/archon-demo.sqlite`. The seeder emits matching SQLite dataset URNs, schema, owner, lineage, and a schema-quality assertion.

Canonical source:

`urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)`

Canonical downstream view:

`urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customer_segment_revenue,PROD)`

Canonical question:

`Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?`

The deterministic answer is `enterprise`, `1,850,000` net-revenue cents. `customers.customer_email` intentionally starts without `urn:li:tag:PII`; one approved mutation adds it and a rerun proves that the source context changed. Archon does not claim that OSS Core automatically propagates the tag to the downstream view.

## Immutable AMI and image supply chain

`.github/workflows/datahub-core-ami.yml` is manual and billable. It requires:

1. exact confirmation `BUILD_EPHEMERAL_DATAHUB_CORE_AMI`;
2. dispatch ref, workflow SHA, companion source SHA, and the current remote
   `master` SHA all resolving to the same exact commit;
3. one completed-success `DataHub companion OCI` run from
   `.github/workflows/datahub-companion-image.yml`, produced by a `push` on
   `master` in this same repository at that exact SHA;
4. protected `staging` environment approval.

Before any billable work, the downloaded companion archive checksums are
verified and `gh attestation verify` binds the repository, signer workflow and
digest, source digest, source ref `refs/heads/master`, exact companion predicate
type, and denial of self-hosted runners.

Before any billable build, CI validates the Python contracts, CDK stack, shell source, and Packer template. It then:

1. verifies the official DataHub commit, tree, and upstream Quickstart compose hash;
2. resolves every declared image exactly once;
3. pulls and scans images sequentially to bound runner disk use;
4. retains raw Trivy JSON and SARIF, including unfixed findings;
5. emits per-image and aggregate CycloneDX and SPDX SBOMs;
6. blocks only fixed, actionable HIGH/CRITICAL findings and does not fabricate VEX;
7. seals every RepoDigest, image ID, report path, database metadata, and checksum in `resolved-images.json`;
8. passes that sealed manifest and the previously attested companion archive to Packer.

The AMI bake pulls only the sealed RepoDigests, verifies image IDs, writes an immutable `docker-compose.images.yml` with `pull_policy: never`, and records the installed image inventory. Runtime image pulls and source builds are disabled.

The AL2023 base is upgraded during the bake. CI retains a post-update raw OS vulnerability report, SARIF, CycloneDX, SPDX, installed-RPM inventory, and an empty applicable-security-update proof. Trivy and its database/cache are then removed from the AMI and their absence is proven before the snapshot.

Packer uses a run-owned temporary ED25519 key pair with SSH transported through Session Manager. The temporary builder has a public egress path but no ingress; the final runtime does not. CI deletes the key pair and private key, and Packer clears authorized keys from the AMI. The builder VPC, route, gateway, subnet, security group, failed AMIs, and snapshots are cleaned by exact run-owned identifiers.

CloudTrail independently proves request-time tags for `CreateKeyPair`, `CreateSecurityGroup`, and `RunInstances`. Each event must contain exactly the required ownership values for `Application`, `Environment`, `ManagedBy`, `archon:Purpose`, and `archon:BuildRun`. The sealed proof retains event digests but no AWS account identifier.

The final attested `archon.datahub-core-ami-build/v2` projection binds the AMI, base AMI, source bundle, resolved-image manifest, request-tag proof, companion provenance, full image/OS reports, aggregate SBOMs, Packer manifest, and safely extracted bake evidence. All artifacts are retained by GitHub Actions; none belongs on a contributor workstation.

## CI/CD security and local-disk policy

Security is implemented in GitHub Actions: unit and contract tests, CDK build/synth, Packer validation, secret detection, SCA, CodeQL, IaC/container/OS scans, SBOMs, SARIF, provenance attestations, AMI creation, and deployment gates. Codex Security is not used. Jobs use runner-temporary paths and upload sealed evidence. No generated SQLite database, downloaded scanner database, OCI archive, build directory, or ephemeral evidence directory is created locally.

## Cost boundary

Core avoids the permanent EKS cost, but zero compute does not mean zero total AWS cost. During an active session, charges can include one `t3a.xlarge`, its 50-GiB gp3 root volume, and three private interface endpoints. Between sessions, the AMI snapshot and customer-managed KMS keys remain intentional costs; serverless requests, logs, and DynamoDB usage are metered at their normal rates. The DynamoDB gateway endpoint has no endpoint-hour charge. Current regional prices must be checked before a paid judging extension, and the retained AMI/snapshot should be retired after judging when no longer needed.