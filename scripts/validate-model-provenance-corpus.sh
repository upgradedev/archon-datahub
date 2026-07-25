#!/usr/bin/env bash
set -euo pipefail

corpus="${1:-contracts/model-provenance-v1.cases.json}"
validator="${2:-scripts/validate-audit-report.jq}"

jq -e '
  .schemaVersion == "archon.model-provenance-conformance/v1" and
  (.credentialMacros | type == "object") and
  all(
    .credentialMacros | to_entries[];
    (.key | test("^[a-z]+$")) and
    (.value | type == "array" and length >= 2) and
    all(.value[]; type == "string" and length > 0)
  ) and
  (.cases | type == "array") and
  (.cases | length) >= 20 and
  all(
    .cases[];
    (.id | type == "string" and length > 0) and
    (.valid | type == "boolean") and
    (.value | type == "object")
  )
' "${corpus}" >/dev/null

while IFS= read -r candidate; do
  case_id="$(jq -r '.id' <<<"${candidate}")"
  expected="$(jq -r '.valid' <<<"${candidate}")"
  provenance="$(jq -c '.value' <<<"${candidate}")"
  while IFS= read -r macro_name; do
    token="{{credential:${macro_name}}}"
    replacement="$(
      jq -r --arg name "${macro_name}" \
        '.credentialMacros[$name] | join("")' \
        "${corpus}"
    )"
    provenance="${provenance//$token/$replacement}"
  done < <(jq -r '.credentialMacros | keys[]' "${corpus}")
  report="$(
    jq -cn --argjson provenance "${provenance}" '{
      schemaVersion: "archon.audit-report/v1",
      scanId: "model-provenance-conformance",
      classification: {
        totalEntities: 0,
        withLineage: 0,
        sensitiveEntities: 0,
        domains: {},
        platforms: {}
      },
      findings: [],
      narrative: "Model provenance conformance case.",
      modelProvenance: $provenance,
      trace: []
    }'
  )"

  actual=false
  if jq -e -f "${validator}" <<<"${report}" >/dev/null; then
    actual=true
  fi
  if [[ "${actual}" != "${expected}" ]]; then
    echo "::error::jq model-provenance conformance mismatch for ${case_id}: expected=${expected} actual=${actual}"
    exit 1
  fi
done < <(jq -c '.cases[]' "${corpus}")

fixture_provenance="$(
  jq -c '.cases[] | select(.id == "fixture-valid") | .value' "${corpus}"
)"
public_secret="sk-$(printf 'x%.0s' {1..12})"
public_jwt="eyJ$(printf 'a%.0s' {1..8}).$(printf 'b%.0s' {1..8}).$(printf 'c%.0s' {1..8})"
for unsafe_public_value in "${public_secret}" "${public_jwt}"; do
  unsafe_report="$(
    jq -cn \
      --arg narrative "Provider diagnostic ${unsafe_public_value}" \
      --argjson provenance "${fixture_provenance}" '{
        schemaVersion: "archon.audit-report/v1",
        scanId: "public-output-safety-conformance",
        classification: {
          totalEntities: 0,
          withLineage: 0,
          sensitiveEntities: 0,
          domains: {},
          platforms: {}
        },
        findings: [],
        narrative: $narrative,
        modelProvenance: $provenance,
        trace: []
      }'
  )"
  if jq -e -f "${validator}" <<<"${unsafe_report}" >/dev/null; then
    echo "::error::jq public-output safety validator accepted a credential-shaped value"
    exit 1
  fi
done

echo "PASS shared model-provenance corpus"
