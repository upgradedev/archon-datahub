# Examples and evidence

Everything in this folder can be read as it is. No install, no DataHub, no network.

## judge-pack

[`judge-pack/`](judge-pack/) is one complete run of Archon's audit and its governed
remediation chain, exactly as GitHub Actions produced it for commit
[`d7b80c8`](https://github.com/upgradedev/archon-datahub/commit/d7b80c814e0762e3f010b4cf8fe7791893793396).
Twelve files:

| File | What it is |
| --- | --- |
| [`README.md`](judge-pack/README.md) | The pack's own cover note and integrity chain, written by the generator |
| [`manifest.json`](judge-pack/manifest.json) | Byte size, media type and SHA-256 for every file, plus the run summary |
| [`SHA256SUMS`](judge-pack/SHA256SUMS) | A plain checksum list, so verification needs no tooling beyond `sha256sum` |
| [`audit/report.md`](judge-pack/audit/report.md) | The audit written for a person to read |
| [`audit/report.json`](judge-pack/audit/report.json) | The same audit as structured evidence, carrying provenance and digests |
| [`audit/report.sarif`](judge-pack/audit/report.sarif) | The same audit as SARIF, so it opens in a code-scanning viewer |
| [`control/evidence-dossier.json`](judge-pack/control/evidence-dossier.json) | The before-state the plan was built against |
| [`control/remediation-plan.json`](judge-pack/control/remediation-plan.json) | The single G6 action Archon is willing to propose |
| [`control/approval-request.json`](judge-pack/control/approval-request.json) | What a human is asked to approve, bound to exact digests |
| [`control/approval-decision.json`](judge-pack/control/approval-decision.json) | The recorded decision, with an expiry |
| [`control/execution-receipt.json`](judge-pack/control/execution-receipt.json) | The write, the read-back check, and the outcome |
| [`control/rollback-proposal.json`](judge-pack/control/rollback-proposal.json) | The separately approvable undo |

Check the bytes yourself:

```bash
cd examples/judge-pack
sha256sum --check SHA256SUMS
```

Eleven `OK` lines. `manifest.json` records the same digests a second time, so an edit
to any file is caught twice.

### What this pack is, and what it is not

`manifest.json` records `"evidenceClass": "SYNTHETIC_OFFLINE_FIXTURE"` and
`"claims": { "liveDataHub": false, "liveMutation": false }`. Read it that way. The code
that produced it is the shipping audit, planning, approval, execution-verification,
receipt and rollback path, but the catalog underneath is a committed deterministic
fixture rather than a tenant, and the write landed on an in-memory port.

The live path is the hosted demo. Open
[https://archon-datahub.web.app](https://archon-datahub.web.app) and select **Run live
audit**. That reads one dataset from a private DataHub Core 1.6 catalog through the
read-only Cloud Run adapter.

One note on wording. `audit/report.md` is copied byte for byte out of the CI pack, so
its phrasing is program output, not prose anyone wrote for this repository. Nothing in
`judge-pack/` has been touched after generation, because `SHA256SUMS` and
`manifest.json` pin every file.

## Also worth opening

- [`audit-governance-coverage.json`](../contrib/datahub-audit/evaluations/audit-governance-coverage.json)
  is a DataHub Skill evaluation case for governance-control coverage.
- [`audit-sensitive-and-lineage.json`](../contrib/datahub-audit/evaluations/audit-sensitive-and-lineage.json)
  is a DataHub Skill evaluation case for sensitive-data and lineage evidence.
- [`manifest.json`](../contrib/mcp-get-aspect-history/manifest.json) records the
  proposed bounded aspect-history tool for the upstream MCP server and its
  validation surface.
- [`JUDGE_EVIDENCE.md`](../docs/JUDGE_EVIDENCE.md) maps product claims to exact
  repository and CI evidence.
