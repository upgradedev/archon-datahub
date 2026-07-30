# Attested submission judge pack

`submission-judge-pack.yml` converts the optional, recommended synthetic judge pack from
the exact successful default-branch CI run into the registered `SQ9` standard-v1 evidence
source. It does not generate a new pack and never presents fixture output as live DataHub
or deployment proof.

## Inputs

The manual workflow accepts only two required scalar identifiers:

- `release_sha`: the exact lowercase 40-character commit currently at `master`;
- `ci_run_id`: the exact successful `push` run of `.github/workflows/ci.yml` for that
  release.

Artifact IDs, names, digests, predicate data, URLs, and evidence facts are resolved by the
workflow. They are not caller-selected.

## Upstream trust chain

Both the read-only producer and the isolated final attester independently:

1. verify the canonical repository, current `master`, CI run identity, successful current
   run attempt, the current successful release-attestation job, and the latest successful
   judge/container producer jobs across attempts 1 through the current attempt (with a
   fail-closed maximum of 20);
2. resolve the unique `judge-evidence-<release>-<producer-attempt>` and
   `container-<release>` artifacts whose creation timestamps fall within those exact
   producer-attempt job windows;
3. download the immutable artifacts by ID and verify each GitHub artifact archive against
   its API `sha256` digest;
4. inspect every ZIP entry before extraction, rejecting absolute, backslash, NUL,
   traversal, duplicate, encrypted, non-regular, unexpected file/directory, oversized,
   and over-count archives;
5. verify the judge pack's exact file tree, `SHA256SUMS`, canonical manifest digest,
   fixed synthetic claims, semantic summary, payload descriptors, and per-file bytes;
6. verify the signed CI release attestation against the exact workflow, release, source
   ref, predicate type, three-subject release set, and GitHub-hosted-runner policy;
7. require every exact CI gate to be successful, require the signed predicate's
   `source.runAttempt` to equal the current successful CI attempt, and require its
   `releaseArtifacts` identities (artifact ID, name, GitHub archive digest, and producer
   attempt) to equal the independently selected judge and container artifacts;
8. require `judgeEvidenceArtifactDigest` to equal the exact selected judge-pack archive
   digest and the signed container subject to equal the downloaded container bytes.

The container archive is used only as an already signed CI release subject. Its signed
statement binds the CI predicate, which in turn binds the judge-pack artifact digest. The
workflow does not retain the container or any duplicate judge-pack payload.

## Retained standard-v1 evidence

The producer delegates canonical envelope/support/predicate construction and semantic
validation to `scripts/validate-submission-proof-receipts.py`. The retained artifact is:

```text
submission-judge-pack-<release>-<producer-attempt>/
  SHA256SUMS
  attestation-predicate.json
  proofs/SQ9.json
  support/SQ9/ci-attestation.json
  support/SQ9/judge-pack-manifest.json
```

The four subjects listed by `SHA256SUMS` are retained for 90 days and attested together
with
`https://archon.datahub.dev/attestations/submission-judge-pack/v1`.
The `SQ9` facts are exactly:

- `evidenceClass: SYNTHETIC_OFFLINE_FIXTURE`;
- the CI workflow/run/attempt, CI predicate type, and canonical predicate digest;
- the exact judge artifact ID, attempt-scoped name, GitHub artifact digest, and producer
  attempt;
- the judge manifest's verified canonical digest;
- the fixed approval, dossier, JSON, Markdown, plan, receipt, rollback, and SARIF format
  inventory;
- `sanitized: true` and `notLiveProof: true`.

Before attestation, the final job independently discovers the latest eligible producer
attempt, downloads it by immutable artifact ID, reconstructs every upstream fact from
fresh downloads and signature verification, compares the complete `SQ9` facts, and
rechecks the release, CI run attempt, upstream artifacts, retained artifact, and repository
control plane. It never trusts producer job outputs for discovery.

All stable-name artifacts in CI use explicit retry overwrite semantics, while the judge
pack is attempt-scoped. An overwrite is a new immutable artifact identity: it does not
preserve the previous artifact ID or archive digest. Any deployment or supply-chain
evidence bound to the prior stable artifact therefore fails closed and must be promoted
again from the new successful CI attempt; historical identity preservation is never
claimed. CI prefixes the upload action's bare hexadecimal digest exactly once before
signing, so retained Actions API identities and the signed predicate use the same
`sha256:<hex>` representation.

## Running and aggregation

Run the workflow only after the exact `master` CI push, including its `Sign exact CI
release candidates` job, has completed successfully. Supply the resulting judge-pack
workflow run ID as optional `judge_pack_run_id` when dispatching
`submission-evidence.yml`.

`SQ9` remains optional and nonblocking in the aggregate submission contract. It is useful
judge-facing sample output, while `D4`, `U3`, and the live submission proof sources remain
the authority for deployed behavior.
