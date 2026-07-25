# Strict, fail-closed validator for archon.audit-report/v1.
#
# Input: one audit report JSON object.
# Output: true only when the complete report and its privacy-safe model
# provenance satisfy the authoritative runtime contract.

def exact_keys($wanted):
  if type != "object" then
    false
  else
    ((keys | sort) == ($wanted | sort))
  end;

def utf16_length:
  (([explode[] | if . > 65535 then 2 else 1 end] | add) // 0);

def bounded_text($maximum):
  if type != "string" then
    false
  else
    (utf16_length) as $length |
    $length > 0 and
    $length <= $maximum and
    (test("[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f]") | not)
  end;

def valid_instant:
  bounded_text(128) and
  test(
    "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
  );

def safe_count:
  type == "number" and
  . >= 0 and
  . <= 9007199254740991 and
  floor == .;

def valid_digest:
  type == "string" and
  test("^sha256:[a-f0-9]{64}$");

def valid_count_map:
  if type != "object" then
    false
  else
    (keys | length) <= 1000 and
    all(
      to_entries[];
      (.key | bounded_text(256)) and
      (.value | safe_count)
    )
  end;

def has_credential_substring:
  if type != "string" then
    false
  else
    test(
      "(sk-(ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|(AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})"
    )
  end;

def has_public_credential_value:
  if type != "string" then
    false
  else
    has_credential_substring or
    test(
      "(?i)(Bearer\\s+[A-Za-z0-9._~+/=-]{12,}|sk-(ant-)?[A-Za-z0-9._~+/=-]{12,}|(api[_ -]?key|password|passwd|pwd|secret|token)\\s*[:=]\\s*[\"']?[^\\s\"',;]{8,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)"
    )
  end;

def forbidden_public_key:
  if type != "string" then
    true
  else
    (
      gsub("[^A-Za-z0-9]"; "") |
      ascii_downcase |
      IN(
        "accesstoken",
        "accesstokens",
        "apikey",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "credentials",
        "idtoken",
        "jwt",
        "password",
        "privatekey",
        "rawresponse",
        "refreshtoken",
        "secret",
        "secretaccesskey",
        "sessiontoken",
        "tasktoken",
        "token",
        "tokens"
      )
    )
  end;

def public_safe:
  if type == "string" then
    (has_public_credential_value | not)
  elif type == "array" then
    all(.[]; public_safe)
  elif type == "object" then
    all(
      to_entries[];
      (.key | forbidden_public_key | not) and
      (.key | has_public_credential_value | not) and
      (.value | public_safe)
    )
  else
    true
  end;

def safe_model_id:
  if type != "string" then
    false
  else
    test("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$") and
    (contains("://") | not) and
    (has_credential_substring | not)
  end;

def safe_response_id:
  if type != "string" then
    false
  else
    test("^[A-Za-z0-9][A-Za-z0-9._:-]{5,199}$") and
    (has_credential_substring | not)
  end;

def valid_token_usage:
  if . == null then
    true
  elif exact_keys(["inputTokens", "outputTokens", "totalTokens"]) then
    (.inputTokens | safe_count) and
    (.outputTokens | safe_count) and
    (.totalTokens | safe_count) and
    .totalTokens == (.inputTokens + .outputTokens)
  else
    false
  end;

def valid_model_provenance:
  if (
    exact_keys([
      "schemaVersion",
      "source",
      "modelCall",
      "provider",
      "requestedModel",
      "returnedModel",
      "providerResponseId",
      "tokenUsage",
      "latencyMs"
    ]) |
    not
  ) then
    false
  elif .schemaVersion != "archon.model-runtime-provenance/v1" then
    false
  elif (.requestedModel | safe_model_id | not) then
    false
  elif .source == "deterministic-fixture" then
    .modelCall == false and
    .provider == "fixture" and
    .returnedModel == null and
    .providerResponseId == null and
    .tokenUsage == null and
    .latencyMs == null
  elif .source == "live-provider" then
    .modelCall == true and
    (.provider | IN("custom", "qwen", "gemini", "openai", "anthropic")) and
    (.returnedModel | safe_model_id) and
    (.providerResponseId | safe_response_id) and
    (.tokenUsage | valid_token_usage) and
    (.latencyMs | safe_count) and
    .latencyMs <= 3600000
  else
    false
  end;

def valid_classification:
  exact_keys([
    "totalEntities",
    "withLineage",
    "sensitiveEntities",
    "domains",
    "platforms"
  ]) and
  (.totalEntities | safe_count) and
  (.withLineage | safe_count) and
  (.sensitiveEntities | safe_count) and
  .withLineage <= .totalEntities and
  .sensitiveEntities <= .totalEntities and
  (.domains | valid_count_map) and
  (.platforms | valid_count_map);

def valid_blast_radius:
  exact_keys([
    "rootUrn",
    "downstream",
    "maxHops",
    "truncated",
    "impact"
  ]) and
  (.rootUrn | bounded_text(2048)) and
  (.downstream | type == "array") and
  (.downstream | length) <= 10000 and
  all(
    .downstream[];
    exact_keys(["urn", "minHops"]) and
    (.urn | bounded_text(2048)) and
    (.minHops | safe_count) and
    .minHops <= 10
  ) and
  (.maxHops | safe_count) and
  .maxHops <= 10 and
  (.truncated | type == "boolean") and
  (.impact | IN("none", "low", "medium", "high", "critical"));

def valid_public_provenance:
  type == "array" and
  length <= 1000 and
  all(
    .[];
    exact_keys(["source", "runId", "observedAt", "status"]) and
    (.source | bounded_text(512)) and
    (.runId | bounded_text(512)) and
    (.observedAt | valid_instant) and
    (.status | IN("trusted", "conflicting", "observed"))
  );

def valid_dossier:
  exact_keys([
    "dossierId",
    "digest",
    "policyDigest",
    "generatedAt",
    "evidenceCount"
  ]) and
  (.dossierId | bounded_text(512)) and
  (.digest | valid_digest) and
  (.policyDigest | valid_digest) and
  (.generatedAt | valid_instant) and
  (.evidenceCount | safe_count) and
  .evidenceCount <= 100000;

def valid_string_array($maximum_entries; $maximum_text):
  type == "array" and
  length <= $maximum_entries and
  all(.[]; bounded_text($maximum_text));

def valid_approval:
  exact_keys([
    "approvalId",
    "expiresAt",
    "targetField",
    "proposedTag",
    "before",
    "after",
    "planDigest",
    "risk"
  ]) and
  (.approvalId | bounded_text(512)) and
  (.expiresAt | valid_instant) and
  (.targetField | bounded_text(1024)) and
  (.proposedTag | bounded_text(2048)) and
  (.before | valid_string_array(1000; 2048)) and
  (.after | valid_string_array(1000; 2048)) and
  (.planDigest | valid_digest) and
  (.risk | IN("low", "medium", "high"));

def valid_public_detail:
  if type != "object" then
    false
  else
    (
      keys -
      [
        "ruleId",
        "rule",
        "attribute",
        "unclassifiedFields",
        "blastRadius",
        "provenance",
        "dossier",
        "approval"
      ] |
      length == 0
    ) and
    ((has("ruleId") | not) or (.ruleId | bounded_text(128))) and
    ((has("rule") | not) or (.rule | bounded_text(2048))) and
    ((has("attribute") | not) or (.attribute | bounded_text(512))) and
    (
      (has("unclassifiedFields") | not) or
      (.unclassifiedFields | valid_string_array(1000; 1024))
    ) and
    ((has("blastRadius") | not) or (.blastRadius | valid_blast_radius)) and
    (
      (has("provenance") | not) or
      (.provenance | valid_public_provenance)
    ) and
    ((has("dossier") | not) or (.dossier | valid_dossier)) and
    ((has("approval") | not) or (.approval | valid_approval))
  end;

def valid_finding:
  if type != "object" then
    false
  else
    has("type") and
    has("severity") and
    has("subject") and
    has("summary") and
    has("detail") and
    (
      keys -
      ["type", "severity", "subject", "summary", "detail", "recommendation"] |
      length == 0
    ) and
    (.type | IN("contradiction", "lineage_gap", "governance_violation")) and
    (.severity | IN("low", "medium", "high")) and
    (.subject | bounded_text(2048)) and
    (.summary | bounded_text(4000)) and
    (.detail | valid_public_detail) and
    (
      (has("recommendation") | not) or
      (.recommendation | bounded_text(4000))
    )
  end;

def valid_trace_step:
  exact_keys(["agent", "produced"]) and
  (.agent | bounded_text(128)) and
  (.produced | bounded_text(2000));

def valid_audit_report:
  exact_keys([
    "schemaVersion",
    "scanId",
    "classification",
    "findings",
    "narrative",
    "modelProvenance",
    "trace"
  ]) and
  .schemaVersion == "archon.audit-report/v1" and
  (.scanId | bounded_text(512)) and
  (.classification | valid_classification) and
  (.findings | type == "array") and
  (.findings | length) <= 10000 and
  all(.findings[]; valid_finding) and
  (.narrative | bounded_text(8000)) and
  (.modelProvenance | valid_model_provenance) and
  (.trace | type == "array") and
  (.trace | length) <= 32 and
  all(.trace[]; valid_trace_step) and
  public_safe;

valid_audit_report
