#!/usr/bin/env bash
set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/../.."
  pwd
)"
manager="${repository_root}/scripts/manage-cognito-judge-user.sh"
emergency_verifier="$(
  printf '%s/scripts/verify-judge-emergency-control-plane.sh' \
    "${repository_root}"
)"
approval_verifier="$(
  printf '%s/scripts/verify-judge-environment-approval.sh' \
    "${repository_root}"
)"
test_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/archon-judge-contracts.XXXXXX")"
state_dir="${test_root}/state"
bin_dir="${test_root}/bin"
result_log="${test_root}/result.log"
mkdir -p "${state_dir}" "${bin_dir}"
trap 'rm -rf -- "${test_root}"' EXIT

bash -n "${manager}"
bash -n "${emergency_verifier}"
bash -n "${approval_verifier}"

cat >"${bin_dir}/aws" <<'FAKE_AWS'
#!/usr/bin/env bash
set -euo pipefail

service="${1:-}"
operation="${2:-}"
if [[ -n "${JUDGE_PASSWORD:-}" ]]; then
  echo "The judge password remained exported to an AWS child process" >&2
  exit 2
fi
if [[ -n "${JUDGE_USERNAME:-}" ]]; then
  echo "The protected judge username remained exported to an AWS child process" >&2
  exit 2
fi
if [[ "${AWS_IGNORE_CONFIGURED_ENDPOINT_URLS:-}" != "true" ]]; then
  echo "Configured AWS endpoint URLs were not disabled" >&2
  exit 2
fi
if [[ -n "${judge_password:-}" ||
  -n "${judge_username:-}" ||
  -n "${internal_temporary_password:-}" ]]; then
  echo "A shell-only password value reached an AWS child process" >&2
  exit 2
fi
printf '%s:%s\n' "${service}" "${operation}" >>"${FAKE_STATE_DIR}/calls"

argument_value() {
  local expected="$1"
  shift
  local arguments=("$@")
  local index

  for (( index = 0; index < ${#arguments[@]}; index += 1 )); do
    if [[ "${arguments[index]}" == "${expected}" ]]; then
      printf '%s' "${arguments[index + 1]}"
      return 0
    fi
  done
  return 1
}

case "${service}:${operation}" in
  sts:get-caller-identity)
    assumed_role_name="${FAKE_ASSUMED_ROLE_NAME:-archon-staging-judge-user}"
    session_name="archon-judge-${GITHUB_RUN_ID}-staging"
    jq -cn \
      --arg account "${FAKE_ACCOUNT_ID}" \
      --arg arn "arn:aws:sts::${FAKE_ACCOUNT_ID}:assumed-role/${assumed_role_name}/${session_name}" \
      --arg userId "AROAJUDGEUSERROLE12345:${session_name}" '
        {
          Account: $account,
          Arn: $arn,
          UserId: $userId
        }
      '
    ;;

  cloudformation:describe-stacks)
    cat <<JSON
{
  "Stacks": [{
    "StackStatus": "${FAKE_STACK_STATUS:-UPDATE_COMPLETE}",
    "Outputs": [
      {
        "OutputKey": "ArchonUserPoolId",
        "OutputValue": "${FAKE_REGION}_JudgePool123"
      },
      {
        "OutputKey": "ArchonUserPoolClientId",
        "OutputValue": "JudgeClient123"
      },
      {
        "OutputKey": "ArchonApplicationUrl",
        "OutputValue": "${FAKE_APPLICATION_URL:-https://staging.archon.example}"
      },
      {
        "OutputKey": "ArchonApproverGroupName",
        "OutputValue": "archon-approvers"
      },
      {
        "OutputKey": "ArchonRegionalWebAclArn",
        "OutputValue": "arn:aws:wafv2:${FAKE_REGION}:${FAKE_ACCOUNT_ID}:regional/webacl/archon-staging-api/12345678-1234-1234-1234-123456789abc"
      }
    ]
  }]
}
JSON
    ;;

  cognito-idp:admin-get-user)
    state="$(<"${FAKE_STATE_DIR}/status")"
    if [[ "${state}" == "absent" ]]; then
      echo "UserNotFoundException" >&2
      exit 254
    fi
    requested_username="$(argument_value --username "$@")"
    canonical_username="$(<"${FAKE_STATE_DIR}/canonical")"
    if [[ "${requested_username}" != "${FAKE_EMAIL}" &&
      "${requested_username}" != "${canonical_username}" ]]; then
      echo "UserNotFoundException" >&2
      exit 254
    fi
    binding="$(<"${FAKE_STATE_DIR}/binding")"
    enabled=true
    user_status="CONFIRMED"
    email_verified="false"
    user_mfa_settings='[]'
    legacy_mfa_options='[]'
    preferred_mfa=""
    if [[ "${state}" == "force" || "${state}" == "disabled-force" ]]; then
      user_status="FORCE_CHANGE_PASSWORD"
    fi
    if [[ "${state}" == "disabled" || "${state}" == "disabled-force" ]]; then
      enabled=false
    fi
    if [[ "${FAKE_VERIFIED_EMAIL_DRIFT:-0}" == "1" ]]; then
      email_verified="true"
    fi
    if [[ "${FAKE_MFA_DRIFT:-0}" == "1" ]]; then
      user_mfa_settings='["SOFTWARE_TOKEN_MFA"]'
      legacy_mfa_options='[
        {
          "DeliveryMedium": "SMS",
          "AttributeName": "phone_number"
        }
      ]'
      preferred_mfa="SOFTWARE_TOKEN_MFA"
    fi
    jq -cn \
      --arg email "${FAKE_EMAIL}" \
      --arg username "${canonical_username}" \
      --arg binding "${binding}" \
      --arg status "${user_status}" \
      --arg emailVerified "${email_verified}" \
      --argjson enabled "${enabled}" \
      --argjson userMfaSettings "${user_mfa_settings}" \
      --argjson legacyMfaOptions "${legacy_mfa_options}" \
      --arg preferredMfa "${preferred_mfa}" '
        {
          Username: $username,
          Enabled: $enabled,
          UserStatus: $status,
          UserMFASettingList: $userMfaSettings,
          MFAOptions: $legacyMfaOptions,
          UserAttributes: [
            {Name: "email", Value: $email},
            {Name: "email_verified", Value: $emailVerified},
            {
              Name: "custom:archon_judge_binding",
              Value: $binding
            }
          ]
        } +
        (
          if $preferredMfa == "" then
            {}
          else
            {PreferredMfaSetting: $preferredMfa}
          end
        )
      '
    ;;

  cognito-idp:admin-list-groups-for-user)
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    test "$(argument_value --limit "$@")" = "60"
    jq -Rn \
      --argjson paginated "${FAKE_GROUP_PAGINATION_DRIFT:-0}" '
      {
        Groups: [inputs | select(length > 0) | {GroupName: .}]
      } +
      (
        if $paginated == 1 then
          {NextToken: "unexpected-next-page"}
        else
          {}
        end
      )
    ' <"${FAKE_STATE_DIR}/groups"
    ;;

  cognito-idp:describe-user-pool)
    allow_admin_create=true
    password_history_size=24
    recovery_mechanisms='[{"Name":"verified_email","Priority":1}]'
    if [[ "${FAKE_POOL_DRIFT:-0}" == "1" ]]; then
      allow_admin_create=false
    fi
    if [[ "${FAKE_PASSWORD_HISTORY_DRIFT:-0}" == "1" ]]; then
      password_history_size=0
    fi
    if [[ "${FAKE_ACCOUNT_RECOVERY_DRIFT:-0}" == "1" ]]; then
      recovery_mechanisms='[{"Name":"verified_phone_number","Priority":1}]'
    fi
    jq -cn \
      --arg id "${FAKE_REGION}_JudgePool123" \
      --argjson allowAdminCreate "${allow_admin_create}" \
      --argjson passwordHistorySize "${password_history_size}" \
      --argjson recoveryMechanisms "${recovery_mechanisms}" '
        {
          UserPool: {
            Id: $id,
            Name: "archon-staging",
            UsernameAttributes: ["email"],
            UsernameConfiguration: {CaseSensitive: false},
            AdminCreateUserConfig: {
              AllowAdminCreateUserOnly: $allowAdminCreate
            },
            AccountRecoverySetting: {
              RecoveryMechanisms: $recoveryMechanisms
            },
            Policies: {
              PasswordPolicy: {
                MinimumLength: 14,
                PasswordHistorySize: $passwordHistorySize,
                RequireLowercase: true,
                RequireUppercase: true,
                RequireNumbers: true,
                RequireSymbols: true,
                TemporaryPasswordValidityDays: 3
              }
            },
            DeletionProtection: "ACTIVE",
            MfaConfiguration: "OPTIONAL",
            UserPoolTier: "PLUS",
            UserPoolAddOns: {AdvancedSecurityMode: "ENFORCED"},
            SchemaAttributes: [
              {
                Name: "email",
                Required: true,
                Mutable: false
              },
              {
                Name: "custom:archon_judge_binding",
                Required: false,
                Mutable: false,
                AttributeDataType: "String",
                StringAttributeConstraints: {
                  MinLength: "64",
                  MaxLength: "64"
                }
              }
            ]
          }
        }
      '
    ;;

  cognito-idp:list-user-pool-clients)
    test "$(argument_value --user-pool-id "$@")" = \
      "${FAKE_REGION}_JudgePool123"
    test "$(argument_value --max-results "$@")" = "60"
    rogue_client=false
    next_token=""
    if [[ "${FAKE_ROGUE_CLIENT_DRIFT:-0}" == "1" ]]; then
      rogue_client=true
    fi
    if [[ "${FAKE_CLIENT_PAGINATION_DRIFT:-0}" == "1" ]]; then
      next_token="unexpected-next-page"
    fi
    jq -cn \
      --arg pool "${FAKE_REGION}_JudgePool123" \
      --argjson rogueClient "${rogue_client}" \
      --arg nextToken "${next_token}" '
        {
          UserPoolClients: (
            [
              {
                UserPoolId: $pool,
                ClientId: "JudgeClient123",
                ClientName: "archon-staging-spa"
              }
            ] +
            (
              if $rogueClient then
                [
                  {
                    UserPoolId: $pool,
                    ClientId: "RogueClient456",
                    ClientName: "rogue-password-client"
                  }
                ]
              else
                []
              end
            )
          )
        } +
        (
          if $nextToken == "" then
            {}
          else
            {NextToken: $nextToken}
          end
        )
      '
    ;;

  cognito-idp:describe-user-pool-client)
    test "$(argument_value --user-pool-id "$@")" = \
      "${FAKE_REGION}_JudgePool123"
    test "$(argument_value --client-id "$@")" = "JudgeClient123"
    explicit_auth_flows='["ALLOW_REFRESH_TOKEN_AUTH"]'
    oauth_flows='["code"]'
    oauth_scopes='["openid","email","archon/approve"]'
    prevent_user_existence_errors="ENABLED"
    callback_urls='["https://staging.archon.example/"]'
    logout_urls='["https://staging.archon.example/"]'
    default_redirect=""
    if [[ "${FAKE_CLIENT_FLOW_DRIFT:-0}" == "1" ]]; then
      explicit_auth_flows='[
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_PASSWORD_AUTH"
      ]'
      oauth_flows='["code","implicit"]'
    fi
    if [[ "${FAKE_CLIENT_ADMIN_SCOPE:-0}" == "1" ]]; then
      oauth_scopes='[
        "openid",
        "email",
        "archon/approve",
        "aws.cognito.signin.user.admin"
      ]'
    fi
    if [[ "${FAKE_USER_EXISTENCE_DRIFT:-0}" == "1" ]]; then
      prevent_user_existence_errors="LEGACY"
    fi
    if [[ "${FAKE_REDIRECT_DRIFT:-0}" == "1" ]]; then
      callback_urls='[
        "https://staging.archon.example/",
        "https://attacker.example/callback"
      ]'
    fi
    if [[ "${FAKE_LOGOUT_REDIRECT_DRIFT:-0}" == "1" ]]; then
      logout_urls='[
        "https://staging.archon.example/",
        "https://attacker.example/logout"
      ]'
    fi
    if [[ "${FAKE_DEFAULT_REDIRECT_DRIFT:-0}" == "1" ]]; then
      default_redirect="https://attacker.example/callback"
    fi
    jq -cn \
      --arg pool "${FAKE_REGION}_JudgePool123" \
      --argjson authFlows "${explicit_auth_flows}" \
      --argjson oauthFlows "${oauth_flows}" \
      --argjson oauthScopes "${oauth_scopes}" \
      --arg preventUserExistenceErrors "${prevent_user_existence_errors}" \
      --argjson callbackUrls "${callback_urls}" \
      --argjson logoutUrls "${logout_urls}" \
      --arg defaultRedirect "${default_redirect}" '
        {
          UserPoolClient: (
            {
              UserPoolId: $pool,
              ClientId: "JudgeClient123",
              ClientName: "archon-staging-spa",
              PreventUserExistenceErrors: $preventUserExistenceErrors,
              EnableTokenRevocation: true,
              AccessTokenValidity: 15,
              IdTokenValidity: 15,
              RefreshTokenValidity: 1,
              ExplicitAuthFlows: $authFlows,
              AllowedOAuthFlows: $oauthFlows,
              AllowedOAuthFlowsUserPoolClient: true,
              AllowedOAuthScopes: $oauthScopes,
              CallbackURLs: $callbackUrls,
              LogoutURLs: $logoutUrls,
              SupportedIdentityProviders: ["COGNITO"],
              ReadAttributes: ["email"],
              TokenValidityUnits: {
                AccessToken: "minutes",
                IdToken: "minutes",
                RefreshToken: "days"
              }
            } +
            (
              if $defaultRedirect == "" then
                {}
              else
                {DefaultRedirectURI: $defaultRedirect}
              end
            }
          )
        }
      '
    ;;

  cognito-idp:describe-risk-configuration)
    test "$(argument_value --user-pool-id "$@")" = \
      "${FAKE_REGION}_JudgePool123"
    test "$(argument_value --client-id "$@")" = "JudgeClient123"
    high_action="NO_ACTION"
    high_notify=false
    compromised_action="BLOCK"
    event_filter='["SIGN_IN","PASSWORD_CHANGE"]'
    if [[ "${FAKE_RISK_ACTION_DRIFT:-0}" == "1" ]]; then
      high_action="BLOCK"
    fi
    if [[ "${FAKE_RISK_NOTIFY_DRIFT:-0}" == "1" ]]; then
      high_notify=true
    fi
    if [[ "${FAKE_COMPROMISED_ACTION_DRIFT:-0}" == "1" ]]; then
      compromised_action="NO_ACTION"
    fi
    if [[ "${FAKE_RISK_FILTER_DRIFT:-0}" == "1" ]]; then
      event_filter='["SIGN_IN","SIGN_UP","PASSWORD_CHANGE"]'
    fi
    jq -cn \
      --arg pool "${FAKE_REGION}_JudgePool123" \
      --arg highAction "${high_action}" \
      --arg compromisedAction "${compromised_action}" \
      --argjson highNotify "${high_notify}" \
      --argjson eventFilter "${event_filter}" '
        {
          RiskConfiguration: {
            UserPoolId: $pool,
            ClientId: "JudgeClient123",
            AccountTakeoverRiskConfiguration: {
              Actions: {
                LowAction: {
                  EventAction: "NO_ACTION",
                  Notify: false
                },
                MediumAction: {
                  EventAction: "NO_ACTION",
                  Notify: false
                },
                HighAction: {
                  EventAction: $highAction,
                  Notify: $highNotify
                }
              }
            },
            CompromisedCredentialsRiskConfiguration: {
              Actions: {EventAction: $compromisedAction},
              EventFilter: $eventFilter
            }
          }
        }
      '
    ;;

  wafv2:get-web-acl-for-resource)
    test "$(argument_value --resource-arn "$@")" = \
      "arn:aws:cognito-idp:${FAKE_REGION}:${FAKE_ACCOUNT_ID}:userpool/${FAKE_REGION}_JudgePool123"
    acl_arn="arn:aws:wafv2:${FAKE_REGION}:${FAKE_ACCOUNT_ID}:regional/webacl/archon-staging-api/12345678-1234-1234-1234-123456789abc"
    if [[ "${FAKE_WAF_ASSOCIATION_DRIFT:-0}" == "1" ]]; then
      acl_arn="arn:aws:wafv2:${FAKE_REGION}:${FAKE_ACCOUNT_ID}:regional/webacl/unexpected/87654321-4321-4321-4321-cba987654321"
    fi
    rate_limit=300
    if [[ "${FAKE_WAF_RULE_DRIFT:-0}" == "1" ]]; then
      rate_limit=301
    fi
    jq -cn \
      --arg arn "${acl_arn}" \
      --argjson scopeDown "${FAKE_WAF_SCOPE_DOWN_DRIFT:-0}" \
      --argjson rateLimit "${rate_limit}" '
        {
          WebACL: {
            Name: "archon-staging-api",
            Id: ($arn | split("/") | last),
            ARN: $arn,
            DefaultAction: {Allow: {}},
            Rules: [
              {
                Name: "AWSManagedRulesAmazonIpReputationList",
                OverrideAction: {None: {}},
                Statement: {
                  ManagedRuleGroupStatement: {
                    Name: "AWSManagedRulesAmazonIpReputationList",
                    VendorName: "AWS"
                  }
                }
              },
              {
                Name: "AWSManagedRulesCommonRuleSet",
                OverrideAction: {None: {}},
                Statement: {
                  ManagedRuleGroupStatement: {
                    Name: "AWSManagedRulesCommonRuleSet",
                    VendorName: "AWS"
                  }
                }
              },
              {
                Name: "AWSManagedRulesKnownBadInputsRuleSet",
                OverrideAction: {None: {}},
                Statement: {
                  ManagedRuleGroupStatement: {
                    Name: "AWSManagedRulesKnownBadInputsRuleSet",
                    VendorName: "AWS"
                  }
                }
              },
              {
                Name: "PerIpRateLimit",
                Action: {Block: {}},
                Statement: {
                  RateBasedStatement: (
                    {
                      AggregateKeyType: "IP",
                      EvaluationWindowSec: 300,
                      Limit: $rateLimit
                    } +
                    if $scopeDown == 1 then
                      {
                        ScopeDownStatement: {
                          ByteMatchStatement: {
                            SearchString: "unexpected"
                          }
                        }
                      }
                    else
                      {}
                    end
                  )
                }
              }
            ]
          }
        }
      '
    ;;

  cognito-idp:admin-create-user)
    request="$(cat)"
    jq -e \
      --arg pool "${FAKE_REGION}_JudgePool123" \
      --arg email "${FAKE_EMAIL}" \
      --arg judgePassword "${FAKE_JUDGE_PASSWORD}" '
        .UserPoolId == $pool and
        .Username == $email and
        (.TemporaryPassword | test("^Aa1![0-9a-f]{56}$")) and
        .TemporaryPassword != $judgePassword and
        .MessageAction == "SUPPRESS" and
        .ForceAliasCreation == false and
        (
          [.UserAttributes[] | select(
            .Name == "email" and .Value == $email
          )] |
          length
        ) == 1 and
        (
          [.UserAttributes[] | select(
            .Name == "custom:archon_judge_binding" and
            (.Value | test("^[0-9a-f]{64}$"))
          )] |
          length
        ) == 1 and
        ([.UserAttributes[] | select(.Name == "email_verified")] | length) == 0
      ' <<<"${request}" >/dev/null
    request_binding="$(
      jq -er '
        [
          .UserAttributes[] |
          select(.Name == "custom:archon_judge_binding") |
          .Value
        ][0]
      ' <<<"${request}"
    )"
    if [[ "${FAKE_CREATE_RACE_ERROR:-0}" == "1" ]]; then
      printf 'confirmed\n' >"${FAKE_STATE_DIR}/status"
      printf 'raced-id-999\n' >"${FAKE_STATE_DIR}/canonical"
      printf '%064d\n' 0 | tr '0' 'b' >"${FAKE_STATE_DIR}/binding"
      exit 3
    fi
    printf 'force\n' >"${FAKE_STATE_DIR}/status"
    printf 'judge-created-001\n' >"${FAKE_STATE_DIR}/canonical"
    printf '%s\n' "${request_binding}" >"${FAKE_STATE_DIR}/binding"
    if [[ "${FAKE_CREATE_APPLIED_ERROR:-0}" == "1" ]]; then
      exit 3
    fi
    ;;

  cognito-idp:admin-set-user-password)
    request="$(cat)"
    previous_state="$(<"${FAKE_STATE_DIR}/status")"
    jq -e \
      --arg pool "${FAKE_REGION}_JudgePool123" \
      --arg username "$(<"${FAKE_STATE_DIR}/canonical")" \
      --arg judgePassword "${FAKE_JUDGE_PASSWORD}" '
        .UserPoolId == $pool and
        .Username == $username and
        .Password == $judgePassword and
        .Permanent == true
      ' <<<"${request}" >/dev/null
    password_digest="$(
      jq -j '.Password' <<<"${request}" |
        sha256sum |
        awk '{print $1}'
    )"
    if grep -Fxq "${password_digest}" \
      "${FAKE_STATE_DIR}/password-history"; then
      echo "PasswordHistoryPolicyViolationException" >&2
      exit 3
    fi
    if [[ "${FAKE_PASSWORD_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    printf '%s\n' "${password_digest}" \
      >>"${FAKE_STATE_DIR}/password-history"
    if [[ "${previous_state}" == "disabled" ||
      "${previous_state}" == "disabled-force" ]]; then
      printf 'disabled\n' >"${FAKE_STATE_DIR}/status"
    else
      printf 'confirmed\n' >"${FAKE_STATE_DIR}/status"
    fi
    if [[ "${FAKE_PASSWORD_APPLIED_ERROR:-0}" == "1" ]]; then
      exit 3
    fi
    ;;

  cognito-idp:admin-add-user-to-group)
    if [[ "${FAKE_ADD_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    test "$(argument_value --group-name "$@")" = "archon-approvers"
    if ! grep -Fxq "archon-approvers" "${FAKE_STATE_DIR}/groups"; then
      printf 'archon-approvers\n' >>"${FAKE_STATE_DIR}/groups"
    fi
    ;;

  cognito-idp:admin-remove-user-from-group)
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    test "$(argument_value --group-name "$@")" = "archon-approvers"
    if [[ "${FAKE_REMOVE_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    grep -Fxv "archon-approvers" "${FAKE_STATE_DIR}/groups" \
      >"${FAKE_STATE_DIR}/groups.next" || true
    mv -- "${FAKE_STATE_DIR}/groups.next" "${FAKE_STATE_DIR}/groups"
    if [[ "${FAKE_REMOVE_APPLIED_ERROR:-0}" == "1" ]]; then
      exit 3
    fi
    ;;

  cognito-idp:admin-disable-user)
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    if [[ "${FAKE_DISABLE_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    if [[ "$(<"${FAKE_STATE_DIR}/status")" == "force" ]]; then
      printf 'disabled-force\n' >"${FAKE_STATE_DIR}/status"
    else
      printf 'disabled\n' >"${FAKE_STATE_DIR}/status"
    fi
    if [[ "${FAKE_DISABLE_APPLIED_ERROR:-0}" == "1" ]]; then
      exit 3
    fi
    ;;

  cognito-idp:admin-enable-user)
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    if [[ "${FAKE_ENABLE_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    test "$(<"${FAKE_STATE_DIR}/status")" = "disabled"
    printf 'confirmed\n' >"${FAKE_STATE_DIR}/status"
    if [[ "${FAKE_ENABLE_APPLIED_ERROR:-0}" == "1" ]]; then
      exit 3
    fi
    ;;

  cognito-idp:admin-user-global-sign-out)
    if [[ "${FAKE_SIGNOUT_FAILURE:-0}" == "1" ]]; then
      exit 3
    fi
    test "$(argument_value --username "$@")" = \
      "$(<"${FAKE_STATE_DIR}/canonical")"
    ;;

  *)
    echo "Unexpected fake AWS call: ${service}:${operation}" >&2
    exit 2
    ;;
esac
FAKE_AWS
chmod 0755 "${bin_dir}/aws"

cat >"${bin_dir}/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail

test "${1:-}" = "api"
endpoint="${!#}"
printf '%s\n' "${endpoint}" >>"${FAKE_STATE_DIR}/gh-calls"

case "${endpoint}" in
  /repos/upgradedev/archon-datahub)
    jq -cn \
      --arg repository \
        "${FAKE_REPOSITORY_FULL_NAME:-upgradedev/archon-datahub}" \
      --arg branch "${FAKE_DEFAULT_BRANCH:-master}" '
        {
          archived: false,
          default_branch: $branch,
          disabled: false,
          fork: false,
          full_name: $repository
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/git/ref/heads/master)
    ref_reads_file="${FAKE_STATE_DIR}/emergency-ref-reads"
    ref_reads=0
    if [[ -f "${ref_reads_file}" ]]; then
      ref_reads="$(<"${ref_reads_file}")"
    fi
    ref_reads=$((ref_reads + 1))
    printf '%s\n' "${ref_reads}" >"${ref_reads_file}"
    ref_sha="${FAKE_REF_SHA:-${FAKE_CONTROL_PLANE_SHA}}"
    if [[ "${FAKE_BRANCH_MOVE:-0}" == "1" && ${ref_reads} -ge 2 ]]; then
      ref_sha="ffffffffffffffffffffffffffffffffffffffff"
    fi
    jq -cn \
      --arg ref "refs/heads/master" \
      --arg sha "${ref_sha}" '
        {
          ref: $ref,
          object: {
            sha: $sha,
            type: "commit"
          }
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/actions/runs/123456/attempts/2)
    run_reads_file="${FAKE_STATE_DIR}/emergency-run-reads"
    run_reads=0
    if [[ -f "${run_reads_file}" ]]; then
      run_reads="$(<"${run_reads_file}")"
    fi
    run_reads=$((run_reads + 1))
    printf '%s\n' "${run_reads}" >"${run_reads_file}"
    run_event="${FAKE_RUN_EVENT:-workflow_dispatch}"
    if [[ "${FAKE_RUN_PROJECTION_DRIFT:-0}" == "1" &&
      ${run_reads} -ge 2 ]]; then
      run_event="push"
    fi
    jq -cn \
      --arg actor "${FAKE_RUN_ACTOR:-requester}" \
      --arg branch "${FAKE_RUN_HEAD_BRANCH:-master}" \
      --arg event "${run_event}" \
      --arg path \
        "${FAKE_RUN_PATH:-.github/workflows/judge-user.yml}" \
      --arg repository \
        "${FAKE_RUN_REPOSITORY:-upgradedev/archon-datahub}" \
      --arg sha "${FAKE_RUN_HEAD_SHA:-${FAKE_CONTROL_PLANE_SHA}}" \
      --arg triggeringActor \
        "${FAKE_RUN_TRIGGERING_ACTOR:-rerun-operator}" \
      --arg url \
        "${FAKE_RUN_URL:-https://github.com/upgradedev/archon-datahub/actions/runs/123456}" \
      --argjson attempt "${FAKE_RUN_ATTEMPT:-2}" \
      --argjson id "${FAKE_RUN_ID:-123456}" \
      --argjson workflowId "${FAKE_RUN_WORKFLOW_ID:-777}" '
        {
          actor: {
            login: $actor,
            type: "User"
          },
          event: $event,
          head_branch: $branch,
          head_repository: {
            full_name: $repository
          },
          head_sha: $sha,
          html_url: $url,
          id: $id,
          name: "Manage Cognito judge user",
          path: $path,
          repository: {
            full_name: $repository
          },
          run_attempt: $attempt,
          triggering_actor: {
            login: $triggeringActor,
            type: "User"
          },
          workflow_id: $workflowId
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/actions/workflows/*)
    jq -cn \
      --arg name \
        "${FAKE_WORKFLOW_NAME:-Manage Cognito judge user}" \
      --arg path \
        "${FAKE_WORKFLOW_PATH:-.github/workflows/judge-user.yml}" \
      --arg state "${FAKE_WORKFLOW_STATE:-active}" \
      --argjson id "${FAKE_WORKFLOW_ID:-777}" '
        {
          id: $id,
          name: $name,
          path: $path,
          state: $state
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/contents/.github/workflows/judge-user.yml\?ref=*)
    test "${endpoint##*\?ref=}" = "${FAKE_CONTROL_PLANE_SHA}"
    workflow_content_path="${FAKE_WORKFLOW_CONTENT_PATH}"
    workflow_size="$(
      wc -c <"${workflow_content_path}" |
        tr -d '[:space:]'
    )"
    workflow_content="$(
      base64 <"${workflow_content_path}" |
        tr -d '\r\n'
    )"
    workflow_blob_sha="$(
      {
        printf 'blob %s\0' "${workflow_size}"
        cat "${workflow_content_path}"
      } |
        sha1sum |
        awk '{print $1}'
    )"
    if [[ -n "${FAKE_WORKFLOW_BLOB_SHA:-}" ]]; then
      workflow_blob_sha="${FAKE_WORKFLOW_BLOB_SHA}"
    fi
    jq -cn \
      --arg blobSha "${workflow_blob_sha}" \
      --arg content "${workflow_content}" \
      --argjson size "${workflow_size}" '
        {
          content: $content,
          encoding: "base64",
          name: "judge-user.yml",
          path: ".github/workflows/judge-user.yml",
          sha: $blobSha,
          size: $size,
          type: "file"
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/environments/judge-access-staging)
    jq -cn \
      --arg name "judge-access-staging" \
      --arg reviewerType "${FAKE_REVIEWER_TYPE:-User}" \
      --arg reviewerLogin "${FAKE_REVIEWER_LOGIN}" \
      --argjson preventSelfReview "${FAKE_PREVENT_SELF_REVIEW:-true}" \
      --argjson reviewerId "${FAKE_REVIEWER_ID}" '
        {
          name: $name,
          deployment_branch_policy: {
            protected_branches: false,
            custom_branch_policies: true
          },
          protection_rules: [{
            type: "required_reviewers",
            prevent_self_review: $preventSelfReview,
            reviewers: [{
              type: $reviewerType,
              reviewer: {
                id: $reviewerId,
                login: $reviewerLogin
              }
            }]
          }]
        }
      '
    ;;

  /repos/upgradedev/archon-datahub/environments/judge-access-staging/deployment-branch-policies\?per_page=100)
    jq -cn '
      {
        total_count: 1,
        branch_policies: [{
          name: "master",
          type: "branch"
        }]
      }
    '
    ;;

  /repos/upgradedev/archon-datahub/actions/runs/123456/approvals)
    jq -cn \
      --arg state "${FAKE_APPROVAL_STATE:-approved}" \
      --arg comment "${FAKE_APPROVAL_COMMENT}" \
      --arg environment "${FAKE_APPROVAL_ENVIRONMENT:-judge-access-staging}" \
      --arg userType "${FAKE_APPROVAL_USER_TYPE:-User}" \
      --arg userLogin "${FAKE_APPROVAL_LOGIN:-${FAKE_REVIEWER_LOGIN}}" \
      --argjson userId "${FAKE_APPROVAL_USER_ID:-${FAKE_REVIEWER_ID}}" '
        [{
          state: $state,
          comment: $comment,
          environments: [{name: $environment}],
          user: {
            type: $userType,
            id: $userId,
            login: $userLogin
          }
        }]
      '
    ;;

  *)
    echo "Unexpected fake GitHub API path" >&2
    exit 2
    ;;
esac
FAKE_GH
chmod 0755 "${bin_dir}/gh"

email="judge@example.com"
judge_password='Correct-Horse-7!'
rotated_password='Fresh-Staple-8!'
judge_account_id="$(
  printf '%064d' 0 |
    tr '0' 'a'
)"

reset_state() {
  local status="$1"
  shift

  printf '%s\n' "${status}" >"${state_dir}/status"
  printf 'judge-id-001\n' >"${state_dir}/canonical"
  printf '%s\n' "${judge_account_id}" >"${state_dir}/binding"
  : >"${state_dir}/groups"
  : >"${state_dir}/calls"
  : >"${state_dir}/gh-calls"
  : >"${state_dir}/password-history"
  rm -f -- \
    "${state_dir}/emergency-ref-reads" \
    "${state_dir}/emergency-run-reads"
  if [[ "${status}" != "absent" ]]; then
    printf '%s' "${judge_password}" |
      sha256sum |
      awk '{print $1}' >"${state_dir}/password-history"
  fi
  if (( $# > 0 )); then
    printf '%s\n' "$@" >"${state_dir}/groups"
  fi
  : >"${result_log}"
}

run_request() {
  env \
    ARCHON_STAGE=staging \
    JUDGE_USER_OPERATION="${1}" \
    JUDGE_ACCOUNT_ID="${2}" \
    bash "${manager}" request
}

run_apply() {
  local operation="$1"
  local password="${2:-}"
  local username="${3:-${email}}"

  env \
    -u AWS_DEFAULT_PROFILE \
    -u AWS_ENDPOINT_URL \
    -u AWS_ENDPOINT_URL_CLOUDFORMATION \
    -u AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER \
    -u AWS_ENDPOINT_URL_COGNITO_IDP \
    -u AWS_ENDPOINT_URL_STS \
    -u AWS_ENDPOINT_URL_WAFV2 \
    -u AWS_PROFILE \
    PATH="${bin_dir}:${PATH}" \
    RUNNER_TEMP="${test_root}" \
    FAKE_STATE_DIR="${state_dir}" \
    FAKE_ACCOUNT_ID=111111111111 \
    FAKE_ASSUMED_ROLE_NAME="${FAKE_ASSUMED_ROLE_NAME:-}" \
    FAKE_REGION=eu-west-1 \
    FAKE_EMAIL="${username}" \
    FAKE_JUDGE_PASSWORD="${password}" \
    FAKE_ADD_FAILURE="${FAKE_ADD_FAILURE:-0}" \
    FAKE_CREATE_APPLIED_ERROR="${FAKE_CREATE_APPLIED_ERROR:-0}" \
    FAKE_CREATE_RACE_ERROR="${FAKE_CREATE_RACE_ERROR:-0}" \
    FAKE_DISABLE_APPLIED_ERROR="${FAKE_DISABLE_APPLIED_ERROR:-0}" \
    FAKE_DISABLE_FAILURE="${FAKE_DISABLE_FAILURE:-0}" \
    FAKE_ENABLE_APPLIED_ERROR="${FAKE_ENABLE_APPLIED_ERROR:-0}" \
    FAKE_ENABLE_FAILURE="${FAKE_ENABLE_FAILURE:-0}" \
    FAKE_PASSWORD_APPLIED_ERROR="${FAKE_PASSWORD_APPLIED_ERROR:-0}" \
    FAKE_PASSWORD_FAILURE="${FAKE_PASSWORD_FAILURE:-0}" \
    FAKE_PASSWORD_HISTORY_DRIFT="${FAKE_PASSWORD_HISTORY_DRIFT:-0}" \
    FAKE_POOL_DRIFT="${FAKE_POOL_DRIFT:-0}" \
    FAKE_ACCOUNT_RECOVERY_DRIFT="${FAKE_ACCOUNT_RECOVERY_DRIFT:-0}" \
    FAKE_CLIENT_ADMIN_SCOPE="${FAKE_CLIENT_ADMIN_SCOPE:-0}" \
    FAKE_CLIENT_FLOW_DRIFT="${FAKE_CLIENT_FLOW_DRIFT:-0}" \
    FAKE_ROGUE_CLIENT_DRIFT="${FAKE_ROGUE_CLIENT_DRIFT:-0}" \
    FAKE_CLIENT_PAGINATION_DRIFT="${FAKE_CLIENT_PAGINATION_DRIFT:-0}" \
    FAKE_USER_EXISTENCE_DRIFT="${FAKE_USER_EXISTENCE_DRIFT:-0}" \
    FAKE_REDIRECT_DRIFT="${FAKE_REDIRECT_DRIFT:-0}" \
    FAKE_LOGOUT_REDIRECT_DRIFT="${FAKE_LOGOUT_REDIRECT_DRIFT:-0}" \
    FAKE_DEFAULT_REDIRECT_DRIFT="${FAKE_DEFAULT_REDIRECT_DRIFT:-0}" \
    FAKE_APPLICATION_URL="${FAKE_APPLICATION_URL:-}" \
    FAKE_VERIFIED_EMAIL_DRIFT="${FAKE_VERIFIED_EMAIL_DRIFT:-0}" \
    FAKE_MFA_DRIFT="${FAKE_MFA_DRIFT:-0}" \
    FAKE_GROUP_PAGINATION_DRIFT="${FAKE_GROUP_PAGINATION_DRIFT:-0}" \
    FAKE_RISK_ACTION_DRIFT="${FAKE_RISK_ACTION_DRIFT:-0}" \
    FAKE_RISK_FILTER_DRIFT="${FAKE_RISK_FILTER_DRIFT:-0}" \
    FAKE_RISK_NOTIFY_DRIFT="${FAKE_RISK_NOTIFY_DRIFT:-0}" \
    FAKE_COMPROMISED_ACTION_DRIFT="${FAKE_COMPROMISED_ACTION_DRIFT:-0}" \
    FAKE_REMOVE_APPLIED_ERROR="${FAKE_REMOVE_APPLIED_ERROR:-0}" \
    FAKE_REMOVE_FAILURE="${FAKE_REMOVE_FAILURE:-0}" \
    FAKE_SIGNOUT_FAILURE="${FAKE_SIGNOUT_FAILURE:-0}" \
    FAKE_WAF_ASSOCIATION_DRIFT="${FAKE_WAF_ASSOCIATION_DRIFT:-0}" \
    FAKE_WAF_RULE_DRIFT="${FAKE_WAF_RULE_DRIFT:-0}" \
    FAKE_WAF_SCOPE_DOWN_DRIFT="${FAKE_WAF_SCOPE_DOWN_DRIFT:-0}" \
    ARCHON_STAGE=staging \
    JUDGE_USER_OPERATION="${operation}" \
    JUDGE_ACCOUNT_ID="${judge_account_id}" \
    JUDGE_USERNAME="${username}" \
    JUDGE_PASSWORD="${password}" \
    EXPECTED_ACCOUNT_ID=111111111111 \
    EXPECTED_APPLICATION_URL="${EXPECTED_APPLICATION_URL_OVERRIDE:-https://staging.archon.example}" \
    AWS_REGION=eu-west-1 \
    AWS_DEFAULT_REGION=eu-west-1 \
    GITHUB_RUN_ID=123456 \
    bash "${manager}" apply
}

expect_failure() {
  if "$@" >"${result_log}" 2>&1; then
    echo "::error::Expected judge-user contract failure" >&2
    exit 1
  fi
}

gate_sha256="$(
  printf '%064d' 0 |
    tr '0' 'c'
)"
release_sha="$(
  printf '%040d' 0 |
    tr '0' 'd'
)"
target_account_id=111111111111
target_region=eu-west-1
target_role_arn="arn:aws:iam::111111111111:role/archon-staging-judge-user"
target_application_url="https://staging.archon.example"
target_sha256="$(
  env \
    ARCHON_STAGE=staging \
    JUDGE_TARGET_ACCOUNT_ID="${target_account_id}" \
    JUDGE_TARGET_REGION="${target_region}" \
    JUDGE_TARGET_ROLE_ARN="${target_role_arn}" \
    JUDGE_TARGET_APPLICATION_URL="${target_application_url}" \
    bash "${approval_verifier}" target-digest
)"
[[ "${target_sha256}" =~ ^[0-9a-f]{64}$ ]]

emergency_receipt_path="${test_root}/judge-emergency-control-plane.json"
run_emergency_verify() {
  local operation="${1:-deactivate}"

  env \
    PATH="${bin_dir}:${PATH}" \
    RUNNER_TEMP="${test_root}" \
    FAKE_STATE_DIR="${state_dir}" \
    FAKE_BRANCH_MOVE="${FAKE_BRANCH_MOVE:-0}" \
    FAKE_CONTROL_PLANE_SHA="${release_sha}" \
    FAKE_DEFAULT_BRANCH="${FAKE_DEFAULT_BRANCH:-master}" \
    FAKE_REF_SHA="${FAKE_REF_SHA:-${release_sha}}" \
    FAKE_REPOSITORY_FULL_NAME="${FAKE_REPOSITORY_FULL_NAME:-upgradedev/archon-datahub}" \
    FAKE_RUN_ACTOR="${FAKE_RUN_ACTOR:-requester}" \
    FAKE_RUN_ATTEMPT="${FAKE_RUN_ATTEMPT:-2}" \
    FAKE_RUN_EVENT="${FAKE_RUN_EVENT:-workflow_dispatch}" \
    FAKE_RUN_HEAD_BRANCH="${FAKE_RUN_HEAD_BRANCH:-master}" \
    FAKE_RUN_HEAD_SHA="${FAKE_RUN_HEAD_SHA:-${release_sha}}" \
    FAKE_RUN_ID="${FAKE_RUN_ID:-123456}" \
    FAKE_RUN_PATH="${FAKE_RUN_PATH:-.github/workflows/judge-user.yml}" \
    FAKE_RUN_PROJECTION_DRIFT="${FAKE_RUN_PROJECTION_DRIFT:-0}" \
    FAKE_RUN_REPOSITORY="${FAKE_RUN_REPOSITORY:-upgradedev/archon-datahub}" \
    FAKE_RUN_TRIGGERING_ACTOR="${FAKE_RUN_TRIGGERING_ACTOR:-rerun-operator}" \
    FAKE_RUN_URL="${FAKE_RUN_URL:-https://github.com/upgradedev/archon-datahub/actions/runs/123456}" \
    FAKE_RUN_WORKFLOW_ID="${FAKE_RUN_WORKFLOW_ID:-777}" \
    FAKE_WORKFLOW_BLOB_SHA="${FAKE_WORKFLOW_BLOB_SHA:-}" \
    FAKE_WORKFLOW_CONTENT_PATH="${repository_root}/.github/workflows/judge-user.yml" \
    FAKE_WORKFLOW_ID="${FAKE_WORKFLOW_ID:-777}" \
    FAKE_WORKFLOW_NAME="${FAKE_WORKFLOW_NAME:-Manage Cognito judge user}" \
    FAKE_WORKFLOW_PATH="${FAKE_WORKFLOW_PATH:-.github/workflows/judge-user.yml}" \
    FAKE_WORKFLOW_STATE="${FAKE_WORKFLOW_STATE:-active}" \
    GH_TOKEN=fake-token \
    GITHUB_ACTOR=requester \
    GITHUB_API_URL=https://api.github.com \
    GITHUB_EVENT_NAME=workflow_dispatch \
    GITHUB_REF="${VERIFY_EMERGENCY_GITHUB_REF:-refs/heads/master}" \
    GITHUB_REF_NAME=master \
    GITHUB_REF_TYPE=branch \
    GITHUB_REPOSITORY=upgradedev/archon-datahub \
    GITHUB_RUN_ATTEMPT=2 \
    GITHUB_RUN_ID=123456 \
    GITHUB_SERVER_URL=https://github.com \
    GITHUB_SHA="${release_sha}" \
    GITHUB_TRIGGERING_ACTOR=rerun-operator \
    GITHUB_WORKFLOW="Manage Cognito judge user" \
    GITHUB_WORKFLOW_REF="${VERIFY_EMERGENCY_GITHUB_WORKFLOW_REF:-upgradedev/archon-datahub/.github/workflows/judge-user.yml@refs/heads/master}" \
    GITHUB_WORKFLOW_SHA="${VERIFY_EMERGENCY_GITHUB_WORKFLOW_SHA:-${release_sha}}" \
    EXECUTING_WORKFLOW_FILE_PATH="${VERIFY_EMERGENCY_EXECUTING_WORKFLOW_FILE_PATH:-.github/workflows/judge-user.yml}" \
    EXECUTING_WORKFLOW_REF="${VERIFY_EMERGENCY_EXECUTING_WORKFLOW_REF:-upgradedev/archon-datahub/.github/workflows/judge-user.yml@refs/heads/master}" \
    EXECUTING_WORKFLOW_REPOSITORY="${VERIFY_EMERGENCY_EXECUTING_WORKFLOW_REPOSITORY:-upgradedev/archon-datahub}" \
    EXECUTING_WORKFLOW_SHA="${VERIFY_EMERGENCY_EXECUTING_WORKFLOW_SHA:-${release_sha}}" \
    JUDGE_USER_OPERATION="${operation}" \
    CONTROL_PLANE_SHA="${release_sha}" \
    EXPECTED_GATE_SHA256="${EMERGENCY_EXPECTED_GATE_SHA256:-}" \
    OUTPUT_PATH="${emergency_receipt_path}" \
    bash "${emergency_verifier}"
}

reset_state absent
run_emergency_verify >"${result_log}" 2>&1
jq -e \
  --arg sha "${release_sha}" '
    (keys | sort) == [
      "branch",
      "ciStatus",
      "mode",
      "operation",
      "repository",
      "run",
      "schemaVersion",
      "sourceSha",
      "workflow"
    ] and
    .schemaVersion == "archon.judge-emergency-control-plane/v1" and
    .mode == "emergency-deactivate-current-master" and
    .operation == "deactivate" and
    .ciStatus == "not-asserted" and
    .repository == "upgradedev/archon-datahub" and
    .branch == "master" and
    .sourceSha == $sha and
    .workflow.path == ".github/workflows/judge-user.yml" and
    .workflow.ref ==
      "upgradedev/archon-datahub/.github/workflows/judge-user.yml@refs/heads/master" and
    .workflow.sha == $sha and
    (.workflow.fileSha256 | test("^[0-9a-f]{64}$")) and
    .run.id == 123456 and
    .run.attempt == 2 and
    .run.event == "workflow_dispatch" and
    .run.headSha == $sha and
    .run.headBranch == "master"
  ' "${emergency_receipt_path}" >/dev/null
emergency_receipt="$(<"${emergency_receipt_path}")"
emergency_gate_sha256="$(
  sha256sum "${emergency_receipt_path}" |
    awk '{print $1}'
)"
[[ "${emergency_gate_sha256}" =~ ^[0-9a-f]{64}$ ]]
EMERGENCY_EXPECTED_GATE_SHA256="${emergency_gate_sha256}" \
  run_emergency_verify >"${result_log}" 2>&1
test "$(<"${emergency_receipt_path}")" = "${emergency_receipt}"
test "$(
  grep -Ec \
    "/actions/workflows/(ci.yml|codeql.yml|workflow-security.yml)/runs" \
    "${state_dir}/gh-calls" || true
)" = "0"

reset_state absent
expect_failure run_emergency_verify provision
test ! -s "${state_dir}/gh-calls"

reset_state absent
VERIFY_EMERGENCY_GITHUB_WORKFLOW_SHA="$(
  printf '%040d' 0 |
    tr '0' 'f'
)" expect_failure run_emergency_verify
test ! -s "${state_dir}/gh-calls"

reset_state absent
VERIFY_EMERGENCY_EXECUTING_WORKFLOW_REF=upgradedev/archon-datahub/.github/workflows/other.yml@refs/heads/master \
  expect_failure run_emergency_verify
test ! -s "${state_dir}/gh-calls"

reset_state absent
FAKE_RUN_EVENT=push expect_failure run_emergency_verify

reset_state absent
FAKE_RUN_HEAD_SHA="$(
  printf '%040d' 0 |
    tr '0' 'f'
)" expect_failure run_emergency_verify

reset_state absent
FAKE_WORKFLOW_STATE=disabled_manually expect_failure run_emergency_verify

reset_state absent
FAKE_WORKFLOW_BLOB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  expect_failure run_emergency_verify

reset_state absent
FAKE_BRANCH_MOVE=1 expect_failure run_emergency_verify

reset_state absent
FAKE_RUN_PROJECTION_DRIFT=1 expect_failure run_emergency_verify

reset_state absent
EMERGENCY_EXPECTED_GATE_SHA256="$(
  printf '%064d' 0 |
    tr '0' 'f'
)" expect_failure run_emergency_verify

request_sha256="$(
  env \
    ARCHON_STAGE=staging \
    JUDGE_USER_OPERATION=provision \
    JUDGE_ACCOUNT_ID="${judge_account_id}" \
    JUDGE_TARGET_ACCOUNT_ID="${target_account_id}" \
    JUDGE_TARGET_REGION="${target_region}" \
    JUDGE_TARGET_ROLE_ARN="${target_role_arn}" \
    JUDGE_TARGET_APPLICATION_URL="${target_application_url}" \
    EXPECTED_GATE_SHA256="${gate_sha256}" \
    CONTROL_PLANE_SHA="${release_sha}" \
    bash "${approval_verifier}" request-digest
)"
[[ "${request_sha256}" =~ ^[0-9a-f]{64}$ ]]
reactivate_request_sha256="$(
  env \
    ARCHON_STAGE=staging \
    JUDGE_USER_OPERATION=reactivate \
    JUDGE_ACCOUNT_ID="${judge_account_id}" \
    JUDGE_TARGET_ACCOUNT_ID="${target_account_id}" \
    JUDGE_TARGET_REGION="${target_region}" \
    JUDGE_TARGET_ROLE_ARN="${target_role_arn}" \
    JUDGE_TARGET_APPLICATION_URL="${target_application_url}" \
    EXPECTED_GATE_SHA256="${gate_sha256}" \
    CONTROL_PLANE_SHA="${release_sha}" \
    bash "${approval_verifier}" request-digest
)"
[[ "${reactivate_request_sha256}" =~ ^[0-9a-f]{64}$ ]]
test "${reactivate_request_sha256}" != "${request_sha256}"
approval_comment="$(
  env \
    GITHUB_RUN_ID=123456 \
    GITHUB_RUN_ATTEMPT=2 \
    JUDGE_REQUEST_SHA256="${request_sha256}" \
    bash "${approval_verifier}" approval-comment
)"
test "${approval_comment}" = \
  "ARCHON_JUDGE_ACCESS_APPROVAL_V3|run_id=123456|run_attempt=2|request_sha256=${request_sha256}"
[[ "${approval_comment}" != *"${email}"* ]]

run_approval_verify() {
  env \
    PATH="${bin_dir}:${PATH}" \
    FAKE_STATE_DIR="${state_dir}" \
    FAKE_APPROVAL_COMMENT="${FAKE_APPROVAL_COMMENT_OVERRIDE:-${approval_comment}}" \
    FAKE_APPROVAL_ENVIRONMENT="${FAKE_APPROVAL_ENVIRONMENT:-judge-access-staging}" \
    FAKE_APPROVAL_LOGIN="${FAKE_APPROVAL_LOGIN:-}" \
    FAKE_APPROVAL_STATE="${FAKE_APPROVAL_STATE:-approved}" \
    FAKE_APPROVAL_USER_ID="${FAKE_APPROVAL_USER_ID:-24680}" \
    FAKE_APPROVAL_USER_TYPE="${FAKE_APPROVAL_USER_TYPE:-User}" \
    FAKE_PREVENT_SELF_REVIEW="${FAKE_PREVENT_SELF_REVIEW:-true}" \
    FAKE_REVIEWER_ID=24680 \
    FAKE_REVIEWER_LOGIN="${FAKE_REVIEWER_LOGIN:-independent-reviewer}" \
    FAKE_REVIEWER_TYPE="${FAKE_REVIEWER_TYPE:-User}" \
    ARCHON_STAGE=staging \
    JUDGE_USER_OPERATION=provision \
    JUDGE_ACCOUNT_ID="${VERIFY_ACCOUNT_ID:-${judge_account_id}}" \
    JUDGE_TARGET_ACCOUNT_ID="${VERIFY_TARGET_ACCOUNT_ID:-${target_account_id}}" \
    JUDGE_TARGET_REGION="${VERIFY_TARGET_REGION:-${target_region}}" \
    JUDGE_TARGET_ROLE_ARN="${VERIFY_TARGET_ROLE_ARN:-${target_role_arn}}" \
    JUDGE_TARGET_APPLICATION_URL="${VERIFY_TARGET_APPLICATION_URL:-${target_application_url}}" \
    EXPECTED_GATE_SHA256="${gate_sha256}" \
    EXPECTED_REQUEST_SHA256="${EXPECTED_REQUEST_SHA256_OVERRIDE:-${request_sha256}}" \
    CONTROL_PLANE_SHA="${release_sha}" \
    JUDGE_REVIEWER_USER_ID=24680 \
    GH_TOKEN=fake-token \
    GITHUB_ACTOR=requester \
    GITHUB_TRIGGERING_ACTOR=rerun-operator \
    GITHUB_REPOSITORY=upgradedev/archon-datahub \
    GITHUB_RUN_ID=123456 \
    GITHUB_RUN_ATTEMPT="${VERIFY_RUN_ATTEMPT:-2}" \
    bash "${approval_verifier}" verify
}

reset_state absent
run_approval_verify >"${result_log}" 2>&1
if grep -Fq "${email}" "${result_log}"; then
  echo "::error::Judge username reached approval-verifier output" >&2
  exit 1
fi
grep -Fxq \
  "/repos/upgradedev/archon-datahub/actions/runs/123456/approvals" \
  "${state_dir}/gh-calls"
test "$(
  grep -Fxc \
    "/repos/upgradedev/archon-datahub/actions/runs/123456/approvals" \
    "${state_dir}/gh-calls"
)" = "1"
FAKE_APPROVAL_COMMENT_OVERRIDE=wrong \
  expect_failure run_approval_verify
EXPECTED_REQUEST_SHA256_OVERRIDE="${gate_sha256}" \
  expect_failure run_approval_verify
VERIFY_ACCOUNT_ID="$(
  printf '%064d' 0 |
    tr '0' 'b'
)" expect_failure run_approval_verify
VERIFY_TARGET_APPLICATION_URL=https://other.archon.example \
  expect_failure run_approval_verify
VERIFY_TARGET_REGION=us-east-1 \
  expect_failure run_approval_verify
VERIFY_RUN_ATTEMPT=3 \
  expect_failure run_approval_verify
FAKE_APPROVAL_STATE=rejected \
  expect_failure run_approval_verify
FAKE_APPROVAL_USER_ID=97531 \
  expect_failure run_approval_verify
FAKE_APPROVAL_ENVIRONMENT=judge-access-production \
  expect_failure run_approval_verify
FAKE_REVIEWER_TYPE=Team \
  expect_failure run_approval_verify
FAKE_PREVENT_SELF_REVIEW=false \
  expect_failure run_approval_verify
FAKE_REVIEWER_LOGIN=Requester \
  expect_failure run_approval_verify
FAKE_REVIEWER_LOGIN=RERUN-OPERATOR \
  expect_failure run_approval_verify

run_request provision "${judge_account_id}" >"${result_log}" 2>&1
run_request reactivate "${judge_account_id}" >"${result_log}" 2>&1
expect_failure run_request provision short
expect_failure run_request delete "${judge_account_id}"

reset_state absent
expect_failure \
  run_apply provision "${judge_password}" "Judge@example.com"
test ! -s "${state_dir}/calls"

reset_state absent
if env \
  PATH="${bin_dir}:${PATH}" \
  RUNNER_TEMP="${test_root}" \
  FAKE_STATE_DIR="${state_dir}" \
  FAKE_ACCOUNT_ID=111111111111 \
  FAKE_REGION=eu-west-1 \
  FAKE_EMAIL="${email}" \
  ARCHON_STAGE=staging \
  JUDGE_USER_OPERATION=provision \
  JUDGE_ACCOUNT_ID="${judge_account_id}" \
  JUDGE_USERNAME="${email}" \
  JUDGE_PASSWORD=weak \
  EXPECTED_ACCOUNT_ID=111111111111 \
  EXPECTED_APPLICATION_URL=https://staging.archon.example \
  AWS_REGION=eu-west-1 \
  GITHUB_RUN_ID=123456 \
  bash "${manager}" apply >"${result_log}" 2>&1; then
  echo "::error::Weak judge password was accepted" >&2
  exit 1
fi
test ! -s "${state_dir}/calls"

workflow_source="${repository_root}/.github/workflows/judge-user.yml"
test "$(
  grep -Fc \
    'if [[ "${JUDGE_USER_OPERATION}" == "deactivate" ]]; then' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'bash scripts/verify-judge-emergency-control-plane.sh' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'bash scripts/verify-github-control-plane.sh' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'EXECUTING_WORKFLOW_FILE_PATH: .github/workflows/judge-user.yml' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'EXECUTING_WORKFLOW_REF: ${{ github.workflow_ref }}' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'EXECUTING_WORKFLOW_REPOSITORY: ${{ github.repository }}' \
    "${workflow_source}"
)" = "3"
test "$(
  grep -Fc \
    'EXECUTING_WORKFLOW_SHA: ${{ github.workflow_sha }}' \
    "${workflow_source}"
)" = "3"
if grep -Eq '\$\{\{[[:space:]]*job\.workflow_' "${workflow_source}"; then
  printf 'judge-user.yml must not use unsupported job.workflow_* expressions\n' >&2
  exit 1
fi
if grep -Eq '^[[:space:]]*workflow_call:' "${workflow_source}"; then
  printf 'judge-user.yml must remain directly dispatched, not reusable\n' >&2
  exit 1
fi
grep -Fq \
  'Emergency deactivation binds the exact current master workflow and run, but deliberately does not assert green CI status.' \
  "${workflow_source}"
grep -Fq \
  'emergency_workflow_file_sha256: ${{ steps.gate.outputs.emergency_workflow_file_sha256 }}' \
  "${workflow_source}"
grep -Fq \
  '.workflow.fileSha256 |' \
  "${workflow_source}"
grep -Fq \
  '[[ "${emergency_workflow_file_sha256}" =~ ^[0-9a-f]{64}$ ]]' \
  "${workflow_source}"
test "$(
  grep -Fc \
    'echo "emergency_workflow_file_sha256=${emergency_workflow_file_sha256}"' \
    "${workflow_source}"
)" = "1"
grep -Fq \
  'EMERGENCY_WORKFLOW_FILE_SHA256: ${{ steps.gate.outputs.emergency_workflow_file_sha256 }}' \
  "${workflow_source}"
grep -Fq \
  '[[ "${EMERGENCY_WORKFLOW_FILE_SHA256}" =~ ^[0-9a-f]{64}$ ]]' \
  "${workflow_source}"
grep -Fq \
  'Workflow file SHA-256: \`${EMERGENCY_WORKFLOW_FILE_SHA256}\`' \
  "${workflow_source}"
grep -Fq \
  'gate_mode="emergency-deactivate-current-master"' \
  "${workflow_source}"
grep -Fq 'gate_mode="full-green"' "${workflow_source}"

reset_state absent
if env \
  AWS_ENDPOINT_URL_COGNITO_IDENTITY_PROVIDER=https://attacker.invalid \
  PATH="${bin_dir}:${PATH}" \
  RUNNER_TEMP="${test_root}" \
  FAKE_STATE_DIR="${state_dir}" \
  FAKE_ACCOUNT_ID=111111111111 \
  FAKE_REGION=eu-west-1 \
  FAKE_EMAIL="${email}" \
  ARCHON_STAGE=staging \
  JUDGE_USER_OPERATION=provision \
  JUDGE_ACCOUNT_ID="${judge_account_id}" \
  JUDGE_USERNAME="${email}" \
  JUDGE_PASSWORD="${judge_password}" \
  FAKE_JUDGE_PASSWORD="${judge_password}" \
  EXPECTED_ACCOUNT_ID=111111111111 \
  EXPECTED_APPLICATION_URL=https://staging.archon.example \
  AWS_REGION=eu-west-1 \
  bash "${manager}" apply >"${result_log}" 2>&1; then
  echo "::error::Cognito endpoint override was accepted" >&2
  exit 1
fi
test ! -s "${state_dir}/calls"

reset_state absent
run_apply provision "${judge_password}" >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/groups")" = "archon-approvers"
grep -Fxq "cognito-idp:describe-user-pool-client" "${state_dir}/calls"
grep -Fxq "cognito-idp:list-user-pool-clients" "${state_dir}/calls"
grep -Fxq "cognito-idp:describe-risk-configuration" "${state_dir}/calls"
grep -Fxq "wafv2:get-web-acl-for-resource" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-create-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-set-user-password" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-add-user-to-group" "${state_dir}/calls"
test "$(
  grep -E \
    'cognito-idp:admin-(list-groups-for-user|get-user)' \
    "${state_dir}/calls" |
    tail -n 2 |
    paste -sd '>' -
)" = \
  "cognito-idp:admin-list-groups-for-user>cognito-idp:admin-get-user"
if grep -Fq "${judge_password}" "${result_log}" ||
  grep -Fq "${judge_password}" "${state_dir}/calls"; then
  echo "::error::Judge password reached judge-user output" >&2
  exit 1
fi

reset_state absent
FAKE_ADD_FAILURE=1 expect_failure run_apply provision "${judge_password}"
test "$(<"${state_dir}/status")" = "disabled"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"

reset_state absent
FAKE_CREATE_APPLIED_ERROR=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"

reset_state absent
FAKE_CREATE_RACE_ERROR=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/canonical")" = "raced-id-999"
test "$(
  grep -Fc "cognito-idp:admin-disable-user" "${state_dir}/calls" || true
)" = "0"
test "$(
  grep -Fc "cognito-idp:admin-remove-user-from-group" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_PASSWORD_APPLIED_ERROR=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fxq "cognito-idp:admin-set-user-password" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"

reset_state absent
FAKE_PASSWORD_FAILURE=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed archon-approvers
expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
expect_failure run_apply rotate "${judge_password}"
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/groups")" = "archon-approvers"
grep -Fq "24-password history policy" "${result_log}"
test "$(
  grep -Ec "cognito-idp:admin-(disable-user|remove-user-from-group|user-global-sign-out)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
run_apply rotate "${rotated_password}" >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/groups")" = "archon-approvers"
grep -Fxq "cognito-idp:admin-set-user-password" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"
test "$(
  grep -Fc "cognito-idp:admin-add-user-to-group" "${state_dir}/calls" || true
)" = "0"
test "$(
  grep -E \
    'cognito-idp:admin-(list-groups-for-user|get-user)' \
    "${state_dir}/calls" |
    tail -n 2 |
    paste -sd '>' -
)" = \
  "cognito-idp:admin-list-groups-for-user>cognito-idp:admin-get-user"
if grep -Fq "${rotated_password}" "${result_log}" ||
  grep -Fq "${rotated_password}" "${state_dir}/calls"; then
  echo "::error::Rotated judge password reached judge-user output" >&2
  exit 1
fi

reset_state confirmed archon-approvers
FAKE_PASSWORD_APPLIED_ERROR=1 \
  expect_failure run_apply rotate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-remove-user-from-group" "${state_dir}/calls"

reset_state confirmed archon-approvers
FAKE_PASSWORD_FAILURE=1 \
  expect_failure run_apply rotate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed
expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers unexpected-admins
expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
FAKE_GROUP_PAGINATION_DRIFT=1 \
  expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
printf '%064d\n' 0 | tr '0' 'b' >"${state_dir}/binding"
expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
FAKE_VERIFIED_EMAIL_DRIFT=1 \
  expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state confirmed archon-approvers
FAKE_MFA_DRIFT=1 expect_failure run_apply rotate "${rotated_password}"
test "$(
  grep -Fc "cognito-idp:admin-set-user-password" "${state_dir}/calls" || true
)" = "0"

reset_state disabled
run_apply reactivate "${rotated_password}" >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/groups")" = "archon-approvers"
test "$(
  grep -E \
    'cognito-idp:admin-(user-global-sign-out|set-user-password|enable-user|add-user-to-group)' \
    "${state_dir}/calls" |
    paste -sd '>' -
)" = \
  "cognito-idp:admin-user-global-sign-out>cognito-idp:admin-set-user-password>cognito-idp:admin-enable-user>cognito-idp:admin-add-user-to-group"
test "$(
  grep -E \
    'cognito-idp:admin-(list-groups-for-user|get-user)' \
    "${state_dir}/calls" |
    tail -n 2 |
    paste -sd '>' -
)" = \
  "cognito-idp:admin-list-groups-for-user>cognito-idp:admin-get-user"

reset_state disabled-force
run_apply reactivate "${rotated_password}" >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "confirmed"
test "$(<"${state_dir}/groups")" = "archon-approvers"

reset_state absent
expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state confirmed
expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled unexpected-admins
expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled
printf '%064d\n' 0 | tr '0' 'b' >"${state_dir}/binding"
expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled
FAKE_VERIFIED_EMAIL_DRIFT=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled
FAKE_MFA_DRIFT=1 expect_failure run_apply reactivate "${rotated_password}"
test "$(
  grep -Ec "cognito-idp:admin-(set-user-password|enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled
expect_failure run_apply reactivate "${judge_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
test "$(
  grep -Ec "cognito-idp:admin-(enable-user|add-user-to-group)" \
    "${state_dir}/calls" || true
)" = "0"

reset_state disabled
FAKE_PASSWORD_FAILURE=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state disabled
FAKE_PASSWORD_APPLIED_ERROR=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state disabled
FAKE_ENABLE_FAILURE=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state disabled
FAKE_ENABLE_APPLIED_ERROR=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state disabled
FAKE_ADD_FAILURE=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state disabled
FAKE_SIGNOUT_FAILURE=1 \
  expect_failure run_apply reactivate "${rotated_password}"
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed archon-approvers
FAKE_VERIFIED_EMAIL_DRIFT=1 run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed archon-approvers
FAKE_MFA_DRIFT=1 run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed archon-approvers
run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-remove-user-from-group" "${state_dir}/calls"

for emergency_drift in \
  FAKE_POOL_DRIFT \
  FAKE_ROGUE_CLIENT_DRIFT \
  FAKE_REDIRECT_DRIFT \
  FAKE_RISK_ACTION_DRIFT \
  FAKE_WAF_ASSOCIATION_DRIFT; do
  reset_state confirmed archon-approvers
  export "${emergency_drift}=1"
  run_apply deactivate >"${result_log}" 2>&1
  unset "${emergency_drift}"
  test "$(<"${state_dir}/status")" = "disabled"
  test ! -s "${state_dir}/groups"
  grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
  grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"
  test "$(
    grep -Ec \
      "cognito-idp:(describe-user-pool|list-user-pool-clients|describe-risk-configuration)|wafv2:get-web-acl-for-resource" \
      "${state_dir}/calls" || true
  )" = "0"
done

reset_state confirmed archon-approvers
FAKE_SIGNOUT_FAILURE=1 run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fq "ambiguous error" "${result_log}"

reset_state confirmed archon-approvers
FAKE_DISABLE_APPLIED_ERROR=1 run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fq "ambiguous error" "${result_log}"

reset_state confirmed archon-approvers
FAKE_REMOVE_APPLIED_ERROR=1 run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"
grep -Fq "ambiguous error" "${result_log}"

reset_state confirmed archon-approvers
FAKE_DISABLE_FAILURE=1 expect_failure run_apply deactivate
test "$(<"${state_dir}/status")" = "confirmed"
test ! -s "${state_dir}/groups"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-remove-user-from-group" "${state_dir}/calls"

reset_state confirmed archon-approvers
FAKE_REMOVE_FAILURE=1 expect_failure run_apply deactivate
test "$(<"${state_dir}/status")" = "disabled"
test "$(<"${state_dir}/groups")" = "archon-approvers"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"

reset_state confirmed
run_apply deactivate >"${result_log}" 2>&1
test "$(<"${state_dir}/status")" = "disabled"
test ! -s "${state_dir}/groups"

reset_state confirmed archon-approvers unexpected-admins
expect_failure run_apply deactivate
test "$(<"${state_dir}/status")" = "disabled"
test "$(<"${state_dir}/groups")" = "unexpected-admins"

reset_state confirmed archon-approvers
FAKE_GROUP_PAGINATION_DRIFT=1 expect_failure run_apply deactivate
test "$(<"${state_dir}/status")" = "disabled"
grep -Fxq "cognito-idp:admin-disable-user" "${state_dir}/calls"
grep -Fxq "cognito-idp:admin-user-global-sign-out" "${state_dir}/calls"

reset_state absent
FAKE_POOL_DRIFT=1 expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_ASSUMED_ROLE_NAME=unexpected-broad-role \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cloudformation:|cognito-idp:admin-" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_PASSWORD_HISTORY_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_ACCOUNT_RECOVERY_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_ROGUE_CLIENT_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_CLIENT_PAGINATION_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_CLIENT_ADMIN_SCOPE=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_CLIENT_FLOW_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_USER_EXISTENCE_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_REDIRECT_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_LOGOUT_REDIRECT_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_DEFAULT_REDIRECT_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_APPLICATION_URL="https://staging.archon.example@attacker.example" \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:(describe|admin-)" "${state_dir}/calls" || true
)" = "0"

reset_state absent
EXPECTED_APPLICATION_URL_OVERRIDE=https://other.archon.example \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_RISK_ACTION_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_RISK_NOTIFY_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_COMPROMISED_ACTION_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_RISK_FILTER_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_WAF_ASSOCIATION_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_WAF_RULE_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
FAKE_WAF_SCOPE_DOWN_DRIFT=1 \
  expect_failure run_apply provision "${judge_password}"
test "$(
  grep -Ec "cognito-idp:admin-(get|create)-user" \
    "${state_dir}/calls" || true
)" = "0"

reset_state absent
if env \
  FAKE_STACK_STATUS=UPDATE_ROLLBACK_COMPLETE \
  PATH="${bin_dir}:${PATH}" \
  RUNNER_TEMP="${test_root}" \
  FAKE_STATE_DIR="${state_dir}" \
  FAKE_ACCOUNT_ID=111111111111 \
  FAKE_REGION=eu-west-1 \
  FAKE_EMAIL="${email}" \
  ARCHON_STAGE=staging \
  JUDGE_USER_OPERATION=provision \
  JUDGE_ACCOUNT_ID="${judge_account_id}" \
  JUDGE_USERNAME="${email}" \
  JUDGE_PASSWORD="${judge_password}" \
  FAKE_JUDGE_PASSWORD="${judge_password}" \
  EXPECTED_ACCOUNT_ID=111111111111 \
  EXPECTED_APPLICATION_URL=https://staging.archon.example \
  AWS_REGION=eu-west-1 \
  GITHUB_RUN_ID=123456 \
  bash "${manager}" apply >"${result_log}" 2>&1; then
  echo "::error::Unaccepted stack state was accepted" >&2
  exit 1
fi
test "$(
  grep -Fc "cognito-idp:admin-create-user" "${state_dir}/calls" || true
)" = "0"

reset_state absent
if env \
  AWS_ENDPOINT_URL=https://attacker.invalid \
  PATH="${bin_dir}:${PATH}" \
  RUNNER_TEMP="${test_root}" \
  FAKE_STATE_DIR="${state_dir}" \
  FAKE_ACCOUNT_ID=111111111111 \
  FAKE_REGION=eu-west-1 \
  FAKE_EMAIL="${email}" \
  ARCHON_STAGE=staging \
  JUDGE_USER_OPERATION=provision \
  JUDGE_ACCOUNT_ID="${judge_account_id}" \
  JUDGE_USERNAME="${email}" \
  JUDGE_PASSWORD="${judge_password}" \
  FAKE_JUDGE_PASSWORD="${judge_password}" \
  EXPECTED_ACCOUNT_ID=111111111111 \
  EXPECTED_APPLICATION_URL=https://staging.archon.example \
  AWS_REGION=eu-west-1 \
  bash "${manager}" apply >"${result_log}" 2>&1; then
  echo "::error::AWS endpoint override was accepted" >&2
  exit 1
fi
test ! -s "${state_dir}/calls"

reset_state absent
if env \
  AWS_ENDPOINT_URL_WAFV2=https://attacker.invalid \
  PATH="${bin_dir}:${PATH}" \
  RUNNER_TEMP="${test_root}" \
  FAKE_STATE_DIR="${state_dir}" \
  FAKE_ACCOUNT_ID=111111111111 \
  FAKE_REGION=eu-west-1 \
  FAKE_EMAIL="${email}" \
  ARCHON_STAGE=staging \
  JUDGE_USER_OPERATION=provision \
  JUDGE_ACCOUNT_ID="${judge_account_id}" \
  JUDGE_USERNAME="${email}" \
  JUDGE_PASSWORD="${judge_password}" \
  FAKE_JUDGE_PASSWORD="${judge_password}" \
  EXPECTED_ACCOUNT_ID=111111111111 \
  EXPECTED_APPLICATION_URL=https://staging.archon.example \
  AWS_REGION=eu-west-1 \
  bash "${manager}" apply >"${result_log}" 2>&1; then
  echo "::error::WAFv2 endpoint override was accepted" >&2
  exit 1
fi
test ! -s "${state_dir}/calls"
