# Readiness

## Current judge authority

The project is submitted and publicly testable. The authoritative evidence is:

- exact final judge application release
  [`7cf2ab063312c2bf06fd2d65c798e802f7070a37`](https://github.com/upgradedev/archon-datahub/releases/tag/datahub-hackathon-2026-final);
- exact-candidate CI and security run
  [31325113177](https://github.com/upgradedev/archon-datahub/actions/runs/31325113177);
- hosted deploy, live DataHub proof, browser journey and DAST run
  [31325348693](https://github.com/upgradedev/archon-datahub/actions/runs/31325348693);
- separately approved write/read-back and rollback/restoration run
  [31325511840](https://github.com/upgradedev/archon-datahub/actions/runs/31325511840);
- exact-release 2:41 refreshed submission-video package
  [31325774888](https://github.com/upgradedev/archon-datahub/actions/runs/31325774888),
  sealed in Actions with no local media retained;
- [live application](https://archon-datahub.web.app),
  [public repository](https://github.com/upgradedev/archon-datahub),
  existing valid [public 2:41 video](https://youtu.be/iB1mVoUqgRU), and submitted
  [Devpost entry](https://devpost.com/software/archon-for-datahub).

The refreshed exact-release video is prepared but is not claimed as public. Replacing the
existing valid public video requires an explicitly owner-authorized YouTube upload. The
original `datahub-hackathon-2026-submission` tag remains immutable historical provenance;
later documentation or monitoring commits on the default branch do not change the deployed
application, whose `/readyz` response reports the exact release above.

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
available through judging, optionally publish the prepared refreshed video after owner
authorization, and continue upstream maintainer follow-up for
[PR #183](https://github.com/acryldata/mcp-server-datahub/pull/183). An optional
public post is not a submission requirement.
