# Archon DataHub Companion

This private runtime makes the Agent Context Kit and the official Analytics Agent
substantive parts of the same governed Archon journey.

- Agent Context Kit tools are loaded read-only and produce bounded provenance receipts.
- Official DataHub Skills are materialized from the commit pinned in
  `.github/locks/datahub-agent-stack.json`.
- Analytics Agent answers the allowlisted synthetic judge question and returns SQL,
  results, chart, tool trace, and context-quality evidence.
- Upstream mutation tools are disabled. Every write remains owned by Archon's isolated
  remediation worker and requires a fresh digest-bound DataSteward approval.
- The runtime accepts only a server-resolved `cloud` or `core` binding. It never accepts
  an endpoint or credential from the browser and never changes profile mid-execution.

The frozen `uv.lock`, SBOM, vulnerability audit, imports, API contracts, and source
provenance are generated and verified only in GitHub Actions. Do not build this service
on a contributor workstation.
