#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME:?ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME is required}"
: "${DATAHUB_READ_GMS_URL:?DATAHUB_READ_GMS_URL is required}"
: "${DATAHUB_READ_MCP_URL:?DATAHUB_READ_MCP_URL is required}"
: "${DATAHUB_WRITE_GMS_URL:?DATAHUB_WRITE_GMS_URL is required}"
: "${DATAHUB_WRITE_MCP_URL:?DATAHUB_WRITE_MCP_URL is required}"

[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]] || {
  echo "::error::EXPECTED_ACCOUNT_ID must be a 12-digit AWS account ID" >&2
  exit 1
}
[[ "${AWS_REGION}" == "eu-west-1" ]] || {
  echo "::error::DataHub PrivateLink must be preflighted in eu-west-1" >&2
  exit 1
}
[[ "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME}" =~ ^com\.amazonaws\.vpce\.eu-west-1\.vpce-svc-([0-9a-f]{8}|[0-9a-f]{17})$ ]] || {
  echo "::error::ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME is not an exact eu-west-1 endpoint service name" >&2
  exit 1
}

caller_account_id="$(
  aws sts get-caller-identity \
    --query Account \
    --output text
)"
[[ "${caller_account_id}" == "${EXPECTED_ACCOUNT_ID}" ]] || {
  echo "::error::DataHub PrivateLink preflight is using the wrong AWS account" >&2
  exit 1
}

availability_zones_json="$(
  aws ec2 describe-availability-zones \
    --filters "Name=state,Values=available" \
    --output json
)"
account_availability_zones="$(
  jq --compact-output --exit-status '
    [
      .AvailabilityZones[] |
      select(
        .State == "available" and
        (
          .OptInStatus == "opt-in-not-required" or
          .OptInStatus == "opted-in"
        )
      ) |
      .ZoneName
    ] |
    unique |
    sort |
    if length >= 2 then .
    else error("fewer than two usable availability zones")
    end
  ' <<<"${availability_zones_json}"
)" || {
  echo "::error::The deployment account does not expose two usable availability zones in ${AWS_REGION}" >&2
  exit 1
}

service_json="$(
  aws ec2 describe-vpc-endpoint-services \
    --service-names "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME}" \
    --output json
)"
service_identity="$(
  jq --compact-output --sort-keys --exit-status \
    --arg serviceName "${ARCHON_DATAHUB_PRIVATE_LINK_SERVICE_NAME}" \
    --arg region "${AWS_REGION}" \
    --arg deploymentAccountId "${EXPECTED_ACCOUNT_ID}" \
    --argjson accountAvailabilityZones "${account_availability_zones}" \
    '
      (
        [
          $accountAvailabilityZones[] as $accountAz |
          select(
            (.ServiceDetails[0].AvailabilityZones | index($accountAz)) !=
            null
          ) |
          $accountAz
        ] |
        unique |
        sort |
        .[0:2]
      ) as $selectedAvailabilityZones |
      if (
        (.ServiceNames | length) == 1 and
        .ServiceNames[0] == $serviceName and
        (.ServiceDetails | length) == 1 and
        .ServiceDetails[0].ServiceName == $serviceName and
        (
          (.ServiceDetails[0].ServiceRegion // $region) == $region
        ) and
        (
          (.ServiceDetails[0].ServiceState // "Available") == "Available"
        ) and
        any(
          .ServiceDetails[0].ServiceType[];
          .ServiceType == "Interface"
        ) and
        (.ServiceDetails[0].ServiceId | type) == "string" and
        (
          .ServiceDetails[0].ServiceId |
          test("^vpce-svc-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
        ) and
        .ServiceDetails[0].Owner != $deploymentAccountId and
        (.ServiceDetails[0].AcceptanceRequired | type) == "boolean" and
        .ServiceDetails[0].AcceptanceRequired == false and
        ($selectedAvailabilityZones | length) == 2 and
        (
          $selectedAvailabilityZones -
          (.ServiceDetails[0].AvailabilityZones | unique)
        ) == [] and
        (.ServiceDetails[0].Owner | type) == "string" and
        (.ServiceDetails[0].Owner | test("^[0-9]{12}$")) and
        (.ServiceDetails[0].PrivateDnsName | type) == "string" and
        (
          .ServiceDetails[0].PrivateDnsName |
          test(
            "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
          )
        ) and
        .ServiceDetails[0].PrivateDnsNameVerificationState == "verified" and
        (
          (.ServiceDetails[0].SupportedIpAddressTypes // ["ipv4"]) |
          index("ipv4")
        ) != null
      ) then
        {
          id: .ServiceDetails[0].ServiceId,
          name: .ServiceDetails[0].ServiceName,
          ownerAccountId: .ServiceDetails[0].Owner,
          region:
            (.ServiceDetails[0].ServiceRegion // $region),
          type: "Interface",
          acceptanceRequired:
            .ServiceDetails[0].AcceptanceRequired,
          privateDnsName:
            .ServiceDetails[0].PrivateDnsName,
          privateDnsVerificationState:
            .ServiceDetails[0].PrivateDnsNameVerificationState,
          supportedAvailabilityZones:
            (.ServiceDetails[0].AvailabilityZones | unique | sort),
          selectedAvailabilityZones:
            $selectedAvailabilityZones,
          supportedIpAddressTypes:
            (
              .ServiceDetails[0].SupportedIpAddressTypes //
              ["ipv4"] |
              unique |
              sort
            )
        }
      else
        error(
          "service is unavailable, is not a verified-private-DNS Interface service, or does not cover both selected availability zones"
        )
      end
    ' <<<"${service_json}"
)" || {
  echo "::error::DataHub endpoint service is not available with verified provider private DNS and exact two-AZ coverage" >&2
  exit 1
}

private_dns_name="$(
  jq --exit-status --raw-output '.privateDnsName' <<<"${service_identity}"
)"

validate_tenant_url() {
  local label="$1"
  local url="$2"
  local remainder
  local authority

  (( ${#url} >= 12 && ${#url} <= 2048 )) || {
    echo "::error::${label} must be between 12 and 2048 characters" >&2
    exit 1
  }
  [[ "${url}" =~ ^https://[^[:space:]#]+$ ]] || {
    echo "::error::${label} must be an HTTPS URL without whitespace or a fragment" >&2
    exit 1
  }
  remainder="${url#https://}"
  authority="${remainder%%/*}"
  authority="${authority%%\?*}"
  [[ "${authority}" == "${private_dns_name}" ]] || {
    echo "::error::${label} must use the endpoint service's exact tenant-scoped provider private DNS origin" >&2
    exit 1
  }
}

validate_tenant_url DATAHUB_READ_GMS_URL "${DATAHUB_READ_GMS_URL}"
validate_tenant_url DATAHUB_READ_MCP_URL "${DATAHUB_READ_MCP_URL}"
validate_tenant_url DATAHUB_WRITE_GMS_URL "${DATAHUB_WRITE_GMS_URL}"
validate_tenant_url DATAHUB_WRITE_MCP_URL "${DATAHUB_WRITE_MCP_URL}"

jq --compact-output --sort-keys \
  --arg deploymentAccountId "${EXPECTED_ACCOUNT_ID}" \
  --arg region "${AWS_REGION}" \
  --arg tenantOrigin "https://${private_dns_name}" \
  --argjson service "${service_identity}" \
  '{
    schemaVersion: "archon.datahub-private-link-preflight/v1",
    deploymentAccountId: $deploymentAccountId,
    region: $region,
    service: $service,
    urlBinding: {
      tenantOrigin: $tenantOrigin,
      allConfigured: true,
      allHttps: true,
      allSameOrigin: true,
      gms: {
        readConfigured: true,
        writeConfigured: true
      },
      mcp: {
        readConfigured: true,
        writeConfigured: true,
        pathSource: "environment-configuration"
      }
    },
    validation: "passed"
  }'
