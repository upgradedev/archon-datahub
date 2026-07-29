# Reproducible DataHub demo state

The `DataHub demo state` workflow is the only supported seed/reset path. It creates the
live state that makes Archon's three headline checks independently demonstrable:

1. the same dataset has two retained `ownership` values from the stable
   `snowflake-prod` and `dbt-prod` sources;
2. its `email` field is deliberately left without an accepted tag or glossary term, so
   governance rule G6 fails for a precise reason;
3. its lineage declares one upstream dataset URN that deliberately does not exist.

The exact query is also the exact target URN:

```text
urn:li:dataset:(urn:li:dataPlatform:snowflake,b2fd91.archon_demo.archon_orders_audit_target,PROD)
```

This makes the live-proof search binding unambiguous. The target otherwise has an owner,
domain, description, and resolved field types, so the planted G6 failure is not confused
with basic catalog hygiene failures.

## Submission blocker: renew the OpenVEX evidence

The committed OpenVEX statement expires at `2026-08-22T11:30:00Z`. The 14-day CI and
independent daily maintenance gates begin failing at `2026-08-08T11:30:00Z`. Renew the
statement before submission or judging, after re-evaluating the advisory against the exact
runtime and retaining the evidence review; every renewed statement remains limited to a
maximum of 30 days. Follow the renewal procedure in
[`LIVE_DATAHUB_PROOF.md`](LIVE_DATAHUB_PROOF.md#openvex-renewal-runbook) and let CI perform
the validation.

## Official baseline and reproducibility

The workflow loads DataHub's official `showcase-ecommerce` pack. The upstream registry
normally resolves that name through mutable `main` URLs. Archon instead binds the official
content to:

- `datahub-project/static-assets` commit
  `edbfb6dafd95fc401d90b104776eb790077c4478`;
- its verified commit/root-tree identity and the non-recursively traversed
  `datapacks/showcase-ecommerce` pack tree;
- the byte size, Git blob, and SHA-256 of the index and all three data files;
- index version `4`, 3,873 MCPs, and 1,088 unique entity URNs.

The reviewed source of truth is
[`contracts/datahub-demo-state-v1.json`](../contracts/datahub-demo-state-v1.json).
The CLI requires `--trust-custom` when it consumes the already verified, runner-local
`file://` index. That flag does not authorize arbitrary internet content: the controller
first downloads only the immutable commit URLs, enforces the four exact byte sizes and
SHA-256 values, recomputes each downloaded byte sequence's Git `blob <size>\0<bytes>`
identity, validates the index, and checks the MCP/entity counts. The Git API gates require
each contract file to be the exact `100644` blob member of the signed commit's traversed
pack tree. Git SHA-1 is used only as Git object identity; SHA-256 remains the security
integrity digest. Both plan and apply independently repeat this materialization and
byte-compare their manifests. Time shifting is disabled. Baseline retrieval is
unauthenticated and remains byte/digest-bound if GitHub redirects it; no DataHub
credential is attached to that download.

## Protected environments

Create these GitHub environments:

| Environment | Purpose | Required configuration |
| --- | --- | --- |
| `datahub-demo` | Read-only dry-run and live-state plan | secrets `DATAHUB_GMS_URL`, `DATAHUB_GMS_TOKEN` using a read-only DataHub principal |
| `datahub-demo-seed` | Human-approved mutation and post-read | sole individual User reviewer `upgradedev`, self-review allowed (`prevent self-review` disabled), one custom deployment branch policy for `master`; admin bypass disabled in the UI as defense-in-depth; secrets `DATAHUB_GMS_URL`, `DATAHUB_GMS_TOKEN` using the narrow demo writer; optional public variable `DATAHUB_URL` |

`DATAHUB_GMS_URL` and `DATAHUB_GMS_TOKEN` are environment-only secret names. Do not
define secrets or variables with either name at organization or repository scope:
GitHub's context precedence can otherwise fall back to a broader-scope value when an
environment value is missing. Keep the read principal only in `datahub-demo` and the
writer only in `datahub-demo-seed`.

The plan and apply jobs do not request an OIDC token and never acquire AWS credentials.
AWS credentials must not coexist with the third-party DataHub runtime or its token. The
workflow launches the entire plan/apply Python controller—and every DataHub CLI
child—with a fresh two-key environment containing only `DATAHUB_GMS_URL` and
`DATAHUB_GMS_TOKEN`. The SDK, stdlib HTTP client, and CLI therefore cannot inherit GitHub,
AWS, cloud-provider, model-provider, proxy, home-directory, or other runner secrets. The
authenticated stdlib DataHub opener also installs `ProxyHandler({})` and rejects every
HTTP redirect, so a Bearer token cannot follow a credential-bearing redirect or ambient
proxy. Before either credential-bearing DataHub CLI dry-run, an offline controller
preflight validates that the URL is a credential-free HTTPS endpoint and that the token
has a safe shape. The canonical endpoint itself is never retained: its SHA-256
`gmsEndpointFingerprint` is sealed into the plan, checked before the apply dry-run or any
other outbound apply call, and copied into the receipt. DataHub CLI output, including
direct dry-run output, is discarded, and SDK initialization, connection, emission, and
close failures are reduced to their exception type; provider response bodies and
exception messages are not surfaced in CI logs. No AWS access key or DataHub token is
accepted as a dispatch input, command-line argument, plan field, artifact, log field, or
receipt field.

A separate downstream attestation job has no protected environment, DataHub secret,
DataHub runtime, or AWS credential. Only that secretless job receives GitHub
`id-token: write`: it verifies the uploaded artifact's GitHub digest and inner
`SHA256SUMS` before attesting the receipt.

GitHub's environment REST and GraphQL responses do not expose the admin-bypass toggle, so
the workflow does not present that UI setting as machine-verified. Keep admin bypass
disabled as defense-in-depth. The explicit solo-owner control is the first apply step: before
checkout, runtime creation, secret use, or mutation, it reads the run's environment
approval receipts and requires an approval for exactly `datahub-demo-seed`. The approver
must be the environment's sole configured individual User reviewer, and that login must
case-insensitively equal the repository owner (`upgradedev`). Team reviewers are rejected.
The receipt retains the initiating identities for attribution, but the deliberate second
approval action may be performed by the solo owner.

The approval comment must exactly match this deterministic format:

```text
APPROVE ARCHON DATAHUB DEMO run_id=<run_id> run_attempt=<run_attempt> action=<seed-or-reset> release_sha=<40-character-release-sha> plan_sha256=<64-character-plan-sha256>
```

The plan job prints the fully substituted phrase in its GitHub step summary for copying
into the environment approval dialog. Run ID, run attempt, action, release SHA, and sealed
plan digest are all bound; a comment from another attempt or plan is invalid. Therefore a
UI admin bypass without that explicit receipt cannot reach a DataHub mutation step.
The apply gate retains only a canonical, allowlisted `approval-receipt.json`: exact
workflow/repository/plan fields, environment name and ID, configured reviewer IDs,
initiator logins, and the one matched decision/comment/user. It never retains unrelated
approval history.

The DataHub write principal should be limited to ingesting the official demo pack,
upserting the two Archon-owned URNs below, and deleting those same two URNs. The workflow's
software allowlist is independently fixed to:

```text
urn:li:dataset:(urn:li:dataPlatform:snowflake,b2fd91.archon_demo.archon_orders_audit_target,PROD)
urn:li:domain:archonShowcaseEcommerce
```

It never deletes, unloads, or resets official pack entities. It also refuses to proceed if
the intentionally missing upstream URN's identity key (`datasetKey`) exists, even when
optional dataset properties do not, because that URN is outside Archon's delete authority.

## Pipeline protocol

Dispatch the workflow from the current `master` SHA with `action=seed`, the exact SHA, and
the exact query above. The pipeline:

1. proves that the SHA is still `master` and that exact-SHA CI, CodeQL, and Workflow
   security push runs are green;
2. validates that the protected mutation environment has exactly the repository owner as
   its individual User reviewer, allows self-review, and allows only `master`;
3. recreates the hash-locked Python/DataHub runtime; normal CI also constructs and
   validates all seven exact SDK proposals/MCPs with this pinned runtime;
4. materializes and verifies the immutable official pack;
5. validates the normalized endpoint/token offline, then runs DataHub's own pack loader
   with `--dry-run` while suppressing provider output;
6. directly reads current aspects/history and writes a canonical plan;
7. uploads the plan, baseline manifest, control-plane receipt, and checksums before the
   mutation job can start; both the producer and apply consumer require that sealed plan
   directory to contain exactly those three JSON files plus `SHA256SUMS`;
8. prints the exact attempt-bound approval phrase and pauses on the
   `datahub-demo-seed` environment approval;
9. independently verifies the approval state, exact environment, exact comment,
   configured reviewer ID, and case-insensitive repository-owner identity before any
   mutation step, then writes the canonical sanitized approval receipt;
10. revalidates the ref, signed upstream tree membership, security runs, GitHub artifact
    digest, inner checksums, runtime, baseline, endpoint fingerprint, dry-run, and live
    before-state including presence for each allowlisted URN; after runtime/baseline
    reconstruction it requires a clean checkout and repeats the exact-current-`master`
    and three-green-workflow gate immediately before the first credential-bearing apply
    step;
11. prepares every SDK model/proposal and tests the reusable emitter connection before
    deletion or pack loading, then applies the exact plan and post-reads the target,
    retained history, G6 gap, dangling lineage, and representative official-pack anchors;
12. checksum-seals the approval, baseline, control-plane, plan, and live receipt files and
    retains them for 90 days;
13. downloads that exact artifact in a secretless job, requires an exact six-entry
    directory inventory, re-fetches the current environment reviewers and exact run
    approval, compares them to the retained sanitized receipt, verifies canonical JSON,
    exact top-level and nested key sets, fixed semantic values, every
    cross-file/run/release/user/endpoint binding, and the fixed checksum closure, then
    attests all five JSON subjects plus `SHA256SUMS`.

## Deployment handoff

A successful seed/reset is a required deployment input, not an informal prerequisite.
`Deploy immutable AWS release` requires all five values copied from the successful
demo-state run:

- `demo_state_run_id`;
- `demo_state_run_attempt`;
- `demo_state_artifact_id`;
- `demo_state_artifact_digest` in `sha256:<64 lowercase hex>` form;
- `demo_state_receipt_sha256`, the exact inner `receipt.json` SHA-256.

The selected artifact name must be
`datahub-demo-receipt-<run-id>-<run-attempt>`. Both staging and production independently
fetch the exact GitHub run-attempt and artifact records, download by artifact ID, require
the fixed six-file inventory, check its strict `SHA256SUMS`, validate canonical JSON and
every cross-file release/approval/post-state binding, and verify the receipt attestation.
The signer is `.github/workflows/datahub-demo-state.yml`; the predicate type is
`https://github.com/upgradedev/archon-datahub/attestations/datahub-demo-state/v1`.

The sanitized `archon.datahub-demo-receipt-binding/v1` projection retains the repository,
release, source workflow path/run/attempt, artifact name/ID/digest, signer and predicate
type/digest, receipt/state-contract/post-state/query/semantic digests, and only the
normalized GMS endpoint fingerprint. It never contains the DataHub URL or token.
Staging and production each fingerprint their configured read GMS endpoint without a
token and require equality with the seed receipt before smoke traffic.

The deployed smoke is semantic, not a connectivity/count check. It requires exactly one
dataset, one exact G6 `email` gap, one exact dangling-upstream finding whose bounded blast
radius contains the target consumer at one hop, and one retained `owner` contradiction
whose two stable sources and runs match the state contract. The same deterministic,
URN-redacted semantic projection must be byte-identical in staging and production.

The checksum-sealed artifacts are:

- `staging-deployment-evidence-<release-sha>-<deployment-attempt>`, attested with
  `https://github.com/upgradedev/archon-datahub/attestations/staging-deployment/v1`;
- `deployment-evidence-<release-sha>-<deployment-attempt>`, attested with
  `https://github.com/upgradedev/archon-datahub/attestations/production-deployment/v1`.

Each retains the sanitized binding and an independently rechecked copy of the original
sealed receipt. These exact names and predicates are the source contract for downstream
submission-readiness aggregation.

`seed` is idempotent: an already exact state produces an `unchanged` receipt without a
DataHub write. A partial or modified state fails closed and instructs the operator to use
reset.

`reset` is destructive only for the two allowlisted Archon URNs. It requires this exact
dispatch confirmation:

```text
RESET ARCHON DATAHUB DEMO
```

The plan binds a presence boolean for each of the two owned URNs. Apply rejects any
before-state change, skips an allowlisted URN that was already absent, and performs an
exact key-aspect plus managed-aspect live readback after every attempted hard delete. A
non-zero CLI response is treated as an applied-but-ambiguous delete only when that
readback proves the exact URN absent; otherwise the run fails closed.

After deletion, the same immutable baseline is loaded and the same aspect sequence is
emitted. A post-read must recover exactly two ownership versions with the two stable
pipeline identities before the receipt is written. If a runner or provider failure occurs
after only part of reset was applied, do not reuse the stale plan. Dispatch a new `reset`
from the still-current `master` SHA with the exact confirmation and obtain a fresh
approval. The new plan records the partial presence state, skips already-absent owned
URNs, and resumes without ever widening the two-URN allowlist.

## Evidence boundary

The local pack validation covers every pinned byte and all 3,873 MCPs. The live
postcondition checks eleven representative assets across datasets, BI surfaces, domain,
data product, and glossary plus every aspect/history condition on Archon's target. It is
not a proof that all 1,088 upstream entities are searchable at one instant; DataHub's pack
loader and the retained digest/anchor receipt are the baseline evidence for that broader
load.

Until a protected workflow run succeeds against the intended hosted DataHub, this remains
source-complete CI/CD capability—not a claim that the hosted demo has already been seeded.
