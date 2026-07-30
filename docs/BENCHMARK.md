# DataHub temporal-provenance benchmark

Archon's frozen benchmark isolates one precise DataHub boundary: an aspect's current view
contains its latest value, while retained aspect history can preserve disagreements between
stable ingestion sources. The benchmark executes the same version-history mapper and
consistency engine that ship in the application.

It is intentionally a **capability benchmark**, not a hosted performance claim and not a
comparison with DataHub Analytics Agent or another vendor product.

## Frozen cases

The seven DataHub-shaped cases cover:

- owner and schema conflicts between distinct stable `pipelineName` identities;
- older history whose run ids are resolved through an explicit trusted source map;
- two runs of one stable pipeline, which must remain ordinary drift;
- unresolved provenance, which must fail closed;
- two sources that agree on the value; and
- a single write with no evidence to compare.

The current-view boundary sees only the highest retained version of each aspect. Archon
sees all retained versions. Both paths use the production audit engine; the only controlled
difference is the evidence made available to it.

The same run also executes the production `AuditPipeline` with its deterministic narrator,
proves that the fixture catalog evaluates G1–G6, emits an L1 lineage gap, and records the
four-agent trace returned by that execution.

## Reproducible CI evidence

The benchmark is generated only into a new caller-provided absolute output directory and
refuses to overwrite an existing path. In GitHub Actions the directory must remain below
`RUNNER_TEMP`:

```text
npm run benchmark:datahub -- --output "$RUNNER_TEMP/datahub-benchmark"
```

CI validates the JSON contract, seals both JSON and Markdown with SHA-256, and retains the
artifact for 90 days. On a default-branch release, the GitHub artifact digest is also bound
into the signed release predicate. The JSON carries a canonical digest of the complete
frozen dataset so results cannot silently move with a changed fixture.

The dataset digest covers both the seven benchmark cases and the fixture reports/history
used for G1–G6, lineage-gap, and executed-pipeline controls. CI pins that digest to the
dataset version, so any fixture drift requires an explicit version/digest update.

- Frozen dataset version: `2026-07-25`
- Frozen dataset digest:
  `sha256:ef244f25fe085245b9153814d9c36e1a5f12112a5dc0dc39a315e40df586f42b`

The implementation is source-complete; a benchmark result becomes evidence only when the
exact commit's remote `DataHub capability benchmark` job succeeds.

## Interpretation

A current view with zero positive predictions has undefined precision, reported honestly as
`null`/`n/a`, and zero recall. It is not assigned a misleading 100% precision. False-positive
controls are as important as recovery: different run ids alone never count as different
sources, and unknown provenance cannot manufacture a conflict.

The benchmark does **not** replace the protected live proof. A production claim requires a
real DataHub instance with aspect retention, two stable source identities, a recovered
contradiction, and the separately approved governed write/readback/rollback evidence.
