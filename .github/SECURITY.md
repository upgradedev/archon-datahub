# Security policy

## Supported code

Security fixes target the latest commit on the default branch. Historical challenge
snapshots are not maintained as separate supported releases.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting or draft security-advisory channel for
this repository. Include the affected commit, the narrowest reproducible scenario, impact,
and any relevant sanitized logs. Do not open a public issue for an unpatched vulnerability,
publish credentials, or test against infrastructure or DataHub tenants you do not own.

## Verification model

Security evidence is produced by the repository's GitHub Actions workflows. The required
gates cover secrets, application tests, CodeQL, dependency and container vulnerabilities,
CloudFormation policy, workflow configuration, DAST, SBOMs, and signed build provenance.
Local scanner output is not accepted as release evidence. A source-level control is not
described as deployed or verified until the corresponding immutable CI/CD evidence exists.
