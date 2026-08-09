# Readiness

## Current submission authority

The project is submitted and publicly testable. The authoritative evidence is:

- exact frozen submission release
  [`f3dc6e2499ce07ee5ffd28c3b714facaacaf5aa1`](https://github.com/upgradedev/archon-datahub/releases/tag/datahub-hackathon-2026-submission);
- exact-candidate CI and security run
  [31313870849](https://github.com/upgradedev/archon-datahub/actions/runs/31313870849);
- hosted deploy, live DataHub proof, browser journey and DAST run
  [31313877712](https://github.com/upgradedev/archon-datahub/actions/runs/31313877712);
- separately approved write/read-back and rollback/restoration run
  [31314046380](https://github.com/upgradedev/archon-datahub/actions/runs/31314046380);
- release-bound 2:41 submission-video run
  [31314313445](https://github.com/upgradedev/archon-datahub/actions/runs/31314313445);
- live application, public repository, public video and submitted
  [Devpost entry](https://devpost.com/software/archon-for-datahub).

Post-submit judge-polish changes must pass the same protected CI/CD, hosted
proof, browser and security gates before deployment. Security evidence is
pipeline-only; local build or scan output is not accepted.

## Historical AWS evidence plan

Earlier revisions of this document described AWS staging, Lambda, AMI,
CloudWatch, Cognito and production-promotion receipts. That material remains
implemented reference architecture, not the deployed submission path and not a
judge-readiness blocker. The active demo is Firebase Hosting, Cloud Run Direct
VPC egress and one private OSS DataHub Core host.

The remaining external obligations are operational: keep the public project
available through judging and continue upstream maintainer follow-up for
[PR #183](https://github.com/acryldata/mcp-server-datahub/pull/183). An optional
public post is not a submission requirement.
