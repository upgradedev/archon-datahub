$migration[0] as $m |
. as $policy |
($m.policy.exactDelta.statements) as $delta |
([$policy.Statement[] |
  select(.Sid == "ReconcileExactFoundationStacks")]) as $stackScoped |
([$policy.Statement[] |
  select(.Sid == "InspectFoundationTemplates")]) as $wildcardRead |
.Version == "2012-10-17" and
(([$policy.Statement[].Action] | flatten | index("*")) | not) and
([$policy.Statement[] |
  select(.Sid == "RejectLegacySharedDeployRole")] | length) == 1 and
([$policy.Statement[] |
  select(.Sid == "ConfigureSharedApiGatewayLogging")] | length) == 1 and
($stackScoped | length) == 1 and
($wildcardRead | length) == 1 and
$stackScoped[0].Effect == "Allow" and
($stackScoped[0].Resource | type) == "array" and
all($stackScoped[0].Resource[]; . != "*") and
($stackScoped[0].Action |
  index("cloudformation:DetectStackResourceDrift")) != null and
$wildcardRead[0].Effect == "Allow" and
$wildcardRead[0].Resource == "*" and
($wildcardRead[0].Action |
  index("cloudformation:BatchDescribeTypeConfigurations")) != null and
(([$policy.Statement[].Action] | flatten |
  map(select(. == "cloudformation:DetectStackResourceDrift"))) |
  length) == 1 and
(([$policy.Statement[].Action] | flatten |
  map(select(. == "cloudformation:BatchDescribeTypeConfigurations"))) |
  length) == 1 and
($m.policy.group == "assets") and
($m.policy.name == "archon-aws-foundation-assets") and
($delta | length) == 2 and
all($delta[];
  . as $spec |
  ([$policy.Statement[] |
    select(.Sid == $spec.sid)]) as $added |
  ([$policy.Statement[] |
    select(.Sid == $spec.resourcesMatchStatement)]) as $source |
  ($added | length) == 1 and
  ($source | length) == 1 and
  ($added[0] | keys | sort) ==
    ["Action", "Effect", "Resource", "Sid"] and
  $added[0].Effect == "Allow" and
  (($added[0].Action |
    if type == "array" then sort else [.] end) ==
    ($spec.actions | sort)) and
  ($added[0].Resource | type) == "array" and
  ($source[0].Resource | type) == "array" and
  (($added[0].Resource | sort) ==
    ($source[0].Resource | sort)) and
  all($added[0].Resource[]; . != "*")) and
all($delta[].actions[];
  . as $action |
  (([$policy.Statement[].Action] | flatten |
    map(select(. == $action))) | length) == 1)
