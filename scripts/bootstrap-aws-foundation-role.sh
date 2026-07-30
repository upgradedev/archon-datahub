#!/usr/bin/env bash
set -euo pipefail

: "${EXPECTED_ACCOUNT_ID:?EXPECTED_ACCOUNT_ID is required}"
: "${EXPECTED_HEAD_SHA:?EXPECTED_HEAD_SHA is required}"
: "${CONFIRMATION:?CONFIRMATION is required}"

[[ "${EXPECTED_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]
[[ "${EXPECTED_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]
test "${CONFIRMATION}" = "BOOTSTRAP_FOUNDATION_POLICIES"
test "$(git rev-parse HEAD)" = "${EXPECTED_HEAD_SHA}"
test "$(git branch --show-current)" = "master"
test -z "$(git status --porcelain --untracked-files=all)"

readonly FOUNDATION_ROLE_NAME="archon-datahub-github-foundation"
readonly FOUNDATION_ROLE_DESCRIPTION="Short-lived GitHub OIDC role restricted to the Archon AWS foundation control plane."
readonly LEGACY_FOUNDATION_ROLE_DESCRIPTION="GitHub OIDC role for the Archon DataHub CDK foundation bootstrap pipeline"
readonly POLICY_SOURCE="infra/aws/foundation/github-actions-foundation-policy.json"
readonly EXPECTED_SUBJECT="repo:upgradedev/archon-datahub:environment:aws-foundation"
readonly OIDC_PROVIDER_ARN="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
readonly -a POLICY_GROUPS=(control assets identity attachments)
declare -A POLICY_ARN
declare -A RENDERED_POLICY

canonical_policy() {
  jq -cS '
    def sorted_array:
      if type == "array" then sort else [.] end;
    .Statement |= (
      map(
        .Action |= sorted_array |
        .Resource |= sorted_array
      ) |
      sort_by(.Sid)
    )
  '
}

caller_account="$(aws sts get-caller-identity --query Account --output text)"
test "${caller_account}" = "${EXPECTED_ACCOUNT_ID}"

aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn "${OIDC_PROVIDER_ARN}" \
  --output json |
  jq -e '
    .Url == "token.actions.githubusercontent.com" and
    (.ClientIDList | index("sts.amazonaws.com")) != null
  ' >/dev/null

expected_attachments='[]'
for group in "${POLICY_GROUPS[@]}"; do
  policy_name="archon-aws-foundation-${group}"
  policy_arn="arn:aws:iam::${EXPECTED_ACCOUNT_ID}:policy/${policy_name}"
  POLICY_ARN["${group}"]="${policy_arn}"
  RENDERED_POLICY["${group}"]="$(
    node scripts/render-aws-foundation-policy.mjs \
      --input "${POLICY_SOURCE}" \
      --account "${EXPECTED_ACCOUNT_ID}" \
      --stdout-group "${group}"
  )"
  expected="$(
    canonical_policy <<<"${RENDERED_POLICY[${group}]}"
  )"
  policy_error="$(
    aws iam get-policy \
      --policy-arn "${policy_arn}" \
      --output json 2>&1 >/dev/null || true
  )"
  if grep -q 'NoSuchEntity' <<<"${policy_error}"; then
    aws iam create-policy \
      --policy-name "${policy_name}" \
      --description \
        "Reviewed Archon AWS foundation ${group} control-plane policy" \
      --policy-document "${RENDERED_POLICY[${group}]}" \
      --tags \
        Key=Application,Value=archon-datahub \
        Key=Environment,Value=aws-foundation \
        Key=ManagedBy,Value=reviewed-bootstrap-bundle >/dev/null
  elif [[ -n "${policy_error}" ]]; then
    echo "${policy_error}" >&2
    exit 1
  fi

  metadata="$(aws iam get-policy --policy-arn "${policy_arn}" --output json)"
  jq -e \
    --arg arn "${policy_arn}" \
    --arg name "${policy_name}" '
      .Policy.Arn == $arn and
      .Policy.PolicyName == $name and
      .Policy.Path == "/"
    ' <<<"${metadata}" >/dev/null
  version_id="$(jq -er '.Policy.DefaultVersionId' <<<"${metadata}")"
  actual="$(
    aws iam get-policy-version \
      --policy-arn "${policy_arn}" \
      --version-id "${version_id}" \
      --output json |
      jq '.PolicyVersion.Document' |
      canonical_policy
  )"
  test "${actual}" = "${expected}"
  compact_size="$(
    jq -c '.' <<<"${actual}" |
      wc -c |
    awk '{print $1 - 1}'
  )"
  test "${compact_size}" -le 6144
  expected_attachments="$(
    jq -cnS \
      --argjson current "${expected_attachments}" \
      --arg name "${policy_name}" \
      --arg arn "${policy_arn}" '
        ($current + [{
          PolicyArn: $arn,
          PolicyName: $name
        }]) |
        sort_by(.PolicyName)
      '
  )"
done

trust_policy="$(
  jq -cnS \
    --arg provider "${OIDC_PROVIDER_ARN}" \
    --arg subject "${EXPECTED_SUBJECT}" '
      {
        Version: "2012-10-17",
        Statement: [{
          Sid: "GitHubEnvironmentOidcOnly",
          Effect: "Allow",
          Principal: {
            Federated: $provider
          },
          Action: "sts:AssumeRoleWithWebIdentity",
          Condition: {
            StringEquals: {
              "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
              "token.actions.githubusercontent.com:sub": $subject
            }
          }
        }]
      }
    '
)"
legacy_trust_policy="$(
  jq -cnS \
    --arg provider "${OIDC_PROVIDER_ARN}" \
    --arg subject "${EXPECTED_SUBJECT}" '
      {
        Version: "2012-10-17",
        Statement: [{
          Effect: "Allow",
          Principal: {
            Federated: $provider
          },
          Action: "sts:AssumeRoleWithWebIdentity",
          Condition: {
            StringEquals: {
              "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
              "token.actions.githubusercontent.com:sub": $subject
            }
          }
        }]
      }
    '
)"
expected_role_tags='[
  {"Key":"Application","Value":"archon-datahub"},
  {"Key":"Environment","Value":"aws-foundation"},
  {"Key":"ManagedBy","Value":"reviewed-bootstrap-bundle"}
]'
legacy_role_tags='[
  {"Key":"Application","Value":"archon-datahub"},
  {"Key":"Environment","Value":"foundation"},
  {"Key":"ManagedBy","Value":"github-actions"}
]'

role_error="$(
  aws iam get-role \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --output json 2>&1 >/dev/null || true
)"
if grep -q 'NoSuchEntity' <<<"${role_error}"; then
  role_origin="created"
  aws iam create-role \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --description "${FOUNDATION_ROLE_DESCRIPTION}" \
    --max-session-duration 3600 \
    --assume-role-policy-document "${trust_policy}" \
    --tags \
      Key=Application,Value=archon-datahub \
      Key=Environment,Value=aws-foundation \
      Key=ManagedBy,Value=reviewed-bootstrap-bundle >/dev/null
elif [[ -n "${role_error}" ]]; then
  echo "${role_error}" >&2
  exit 1
else
  role_origin="existing"
fi

role_json="$(aws iam get-role --role-name "${FOUNDATION_ROLE_NAME}" --output json)"
canonical_role_matches() {
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg description "${FOUNDATION_ROLE_DESCRIPTION}" \
    --argjson trust "${trust_policy}" \
    --argjson tags "${expected_role_tags}" '
      def normalize_actions:
        .Statement |= map(
          .Action |= (
            if type == "array" then sort else [.] end
          )
        );
      .Role.RoleName == "archon-datahub-github-foundation" and
      .Role.Arn ==
        ("arn:aws:iam::" + $account +
          ":role/archon-datahub-github-foundation") and
      .Role.Path == "/" and
      .Role.Description == $description and
      .Role.MaxSessionDuration == 3600 and
      (.Role.PermissionsBoundary == null) and
      (.Role.AssumeRolePolicyDocument | normalize_actions) ==
        ($trust | normalize_actions) and
      ((.Role.Tags // []) | sort_by(.Key)) == ($tags | sort_by(.Key))
    ' <<<"$1" >/dev/null
}

if ! canonical_role_matches "${role_json}"; then
  test "${role_origin}" = "existing"
  test "$(
    aws iam list-role-policies \
      --role-name "${FOUNDATION_ROLE_NAME}" \
      --query 'length(PolicyNames)' \
      --output text
  )" = "0"
  aws iam list-attached-role-policies \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --output json |
    jq -e '.AttachedPolicies == []' >/dev/null
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" \
    --arg canonicalDescription "${FOUNDATION_ROLE_DESCRIPTION}" \
    --arg legacyDescription "${LEGACY_FOUNDATION_ROLE_DESCRIPTION}" \
    --argjson canonicalTrust "${trust_policy}" \
    --argjson legacyTrust "${legacy_trust_policy}" \
    --argjson canonicalTags "${expected_role_tags}" \
    --argjson legacyTags "${legacy_role_tags}" '
      def normalize_actions:
        .Statement |= map(
          .Action |= (
            if type == "array" then sort else [.] end
          )
        );
      .Role.RoleName == "archon-datahub-github-foundation" and
      .Role.Arn ==
        ("arn:aws:iam::" + $account +
          ":role/archon-datahub-github-foundation") and
      .Role.Path == "/" and
      .Role.MaxSessionDuration == 3600 and
      (.Role.PermissionsBoundary == null) and
      (
        .Role.Description == $legacyDescription or
        .Role.Description == $canonicalDescription
      ) and
      (
        (.Role.AssumeRolePolicyDocument | normalize_actions) ==
          ($legacyTrust | normalize_actions) or
        (.Role.AssumeRolePolicyDocument | normalize_actions) ==
          ($canonicalTrust | normalize_actions)
      ) and
      (
        ((.Role.Tags // []) | sort_by(.Key)) ==
          ($legacyTags | sort_by(.Key)) or
        ((.Role.Tags // []) | sort_by(.Key)) ==
          ($canonicalTags | sort_by(.Key))
      )
    ' <<<"${role_json}" >/dev/null

  aws iam update-assume-role-policy \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --policy-document "${trust_policy}"
  aws iam update-role-description \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --description "${FOUNDATION_ROLE_DESCRIPTION}"
  aws iam tag-role \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --tags \
      Key=Application,Value=archon-datahub \
      Key=Environment,Value=aws-foundation \
      Key=ManagedBy,Value=reviewed-bootstrap-bundle
  role_json="$(
    aws iam get-role \
      --role-name "${FOUNDATION_ROLE_NAME}" \
      --output json
  )"
fi

canonical_role_matches "${role_json}"

test "$(
  aws iam list-role-policies \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --query 'length(PolicyNames)' \
    --output text
)" = "0"

current_attachments="$(
  aws iam list-attached-role-policies \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --output json
)"
jq -e \
  --argjson expected "${expected_attachments}" '
    (.AttachedPolicies | length) <= ($expected | length) and
    all(
      .AttachedPolicies[];
      . as $actual |
      ($expected | index($actual)) != null
    )
  ' <<<"${current_attachments}" >/dev/null

for group in "${POLICY_GROUPS[@]}"; do
  aws iam attach-role-policy \
    --role-name "${FOUNDATION_ROLE_NAME}" \
    --policy-arn "${POLICY_ARN[${group}]}"
done

aws iam list-attached-role-policies \
  --role-name "${FOUNDATION_ROLE_NAME}" \
  --output json |
  jq -e --argjson expected "${expected_attachments}" '
    (.AttachedPolicies | length) == 4 and
    (10 - (.AttachedPolicies | length)) >= 6 and
    (.AttachedPolicies | sort_by(.PolicyName)) == $expected
  ' >/dev/null

printf '%s\n' \
  "Foundation bootstrap complete for ${FOUNDATION_ROLE_NAME} at ${EXPECTED_HEAD_SHA}."
