import {
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps
} from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as logs from "aws-cdk-lib/aws-logs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";

const CLOUDFRONT_CONTROL_PLANE_REGION = "us-east-1";
export interface ArchonEdgeStackProps extends StackProps {
  readonly stage: string;
}

export class ArchonEdgeStack extends Stack {
  readonly webAclArn: string;

  constructor(scope: Construct, id: string, props: ArchonEdgeStackProps) {
    const { stage, env, ...stackProps } = props;
    if (!/^[a-z][a-z0-9-]{1,15}$/.test(stage)) {
      throw new Error("ArchonEdgeStack stage must match ^[a-z][a-z0-9-]{1,15}$");
    }
    if (stage !== "staging" && stage !== "production") {
      throw new Error(
        "ArchonEdgeStack stage must be exactly staging or production"
      );
    }
    if (
      env?.region !== undefined &&
      env.region !== CLOUDFRONT_CONTROL_PLANE_REGION
    ) {
      throw new Error(
        `ArchonEdgeStack must be deployed in ${CLOUDFRONT_CONTROL_PLANE_REGION}`
      );
    }
    super(scope, id, {
      ...stackProps,
      env: {
        account: env?.account,
        region: CLOUDFRONT_CONTROL_PLANE_REGION
      }
    });

    const isProduction = stage === "production";
    const wafLogKey = new kms.Key(this, "WafLogKey", {
      alias: `alias/archon/${stage}/edge-waf-logs`,
      description: "KMS key for retained Archon CloudFront WAF logs",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN
    });
    const wafLogGroupName = `aws-waf-logs-archon-${stage}-cloudfront`;
    const wafLogGroupResourceArn = this.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: wafLogGroupName,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    });
    wafLogKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowCloudWatchLogsEncryption",
        principals: [
          new iam.ServicePrincipal(
            `logs.${CLOUDFRONT_CONTROL_PLANE_REGION}.${this.urlSuffix}`
          )
        ],
        actions: [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ],
        resources: ["*"],
        conditions: {
          ArnEquals: {
            "kms:EncryptionContext:aws:logs:arn": wafLogGroupResourceArn
          }
        }
      })
    );
    const wafLogGroup = new logs.LogGroup(this, "WafLogGroup", {
      logGroupName: wafLogGroupName,
      encryptionKey: wafLogKey,
      retention: logs.RetentionDays.ONE_YEAR,
      removalPolicy: RemovalPolicy.RETAIN
    });

    const webAcl = new wafv2.CfnWebACL(this, "CloudFrontWebAcl", {
      name: `archon-${stage}-cloudfront`,
      description: `Archon ${stage} global CloudFront protections`,
      scope: "CLOUDFRONT",
      defaultAction: { allow: {} },
      dataProtectionConfig: {
        dataProtections: [
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["authorization"]
            }
          },
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["cookie"]
            }
          },
          {
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: ["x-api-key"]
            }
          }
        ]
      },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `archon-${stage}-cloudfront-waf`,
        sampledRequestsEnabled: true
      },
      rules: [
        managedWafRule("AWSManagedRulesAmazonIpReputationList", 0),
        managedWafRule("AWSManagedRulesCommonRuleSet", 10),
        managedWafRule("AWSManagedRulesKnownBadInputsRuleSet", 20),
        {
          name: "PerIpRateLimit",
          priority: 30,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              aggregateKeyType: "IP",
              evaluationWindowSec: 300,
              limit: isProduction ? 1_000 : 300
            }
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `archon-${stage}-cloudfront-rate-limit`,
            sampledRequestsEnabled: true
          }
        }
      ]
    });
    this.webAclArn = webAcl.attrArn;

    const wafLogging = new wafv2.CfnLoggingConfiguration(
      this,
      "WafLogging",
      {
        resourceArn: webAcl.attrArn,
        // ILogGroup.logGroupArn ends in :* for IAM use. WAF requires the
        // log-group resource ARN without that wildcard suffix.
        logDestinationConfigs: [wafLogGroupResourceArn],
        loggingFilter: {
          DefaultBehavior: "DROP",
          Filters: [
            {
              Behavior: "KEEP",
              Conditions: [
                { ActionCondition: { Action: "BLOCK" } },
                { ActionCondition: { Action: "COUNT" } }
              ],
              Requirement: "MEETS_ANY"
            }
          ]
        },
        redactedFields: [
          { singleHeader: { Name: "authorization" } },
          { singleHeader: { Name: "cookie" } },
          { singleHeader: { Name: "x-api-key" } }
        ]
      }
    );
    wafLogging.node.addDependency(webAcl, wafLogGroup);

    new CfnOutput(this, "ArchonCloudFrontWebAclArn", {
      value: this.webAclArn,
      description:
        "CLOUDFRONT WAFv2 Web ACL ARN to pass to ArchonPlatformStack"
    });
    new CfnOutput(this, "ArchonCloudFrontWafLogKeyArn", {
      value: wafLogKey.keyArn,
      description: "KMS key ARN bound to the retained CloudFront WAF log group"
    });
  }
}

function managedWafRule(
  name: string,
  priority: number
): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    priority,
    overrideAction: { none: {} },
    statement: {
      managedRuleGroupStatement: {
        name,
        vendorName: "AWS"
      }
    },
    visibilityConfig: {
      cloudWatchMetricsEnabled: true,
      metricName: name,
      sampledRequestsEnabled: true
    }
  };
}
