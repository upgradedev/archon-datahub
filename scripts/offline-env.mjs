// Hermetic execution guard for tests, readiness, and load checks.
//
// Developer machines and CI runners can carry provider credentials in their ambient
// environment. These commands are explicitly offline and must never become billable or
// non-deterministic merely because a key happens to be present. The live demo command does
// not import this file, so `npm run audit:demo` can still use configured providers/DataHub.

const OFFLINE_SECRET_VARS = [
  "LLM_API_KEY",
  "DASHSCOPE_API_KEY",
  "GEMINI_API_KEY",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "DATAHUB_GMS_URL",
  "DATAHUB_GMS_TOKEN",
  "DATAHUB_MCP_URL",
  "DATAHUB_WRITE_MCP_URL",
  "DATAHUB_WRITE_GMS_URL",
  "DATAHUB_WRITE_GMS_TOKEN",
  "ARCHON_MUTATIONS_ENABLED",
  "ARCHON_APPROVAL_SECRET",
];

for (const name of OFFLINE_SECRET_VARS) {
  delete process.env[name];
}
