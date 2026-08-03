import {
  ArnFormat,
  Aws,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack
} from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";

export type ArchonStage = "staging" | "production";

export const CANONICAL_DATASET_URN =
  "urn:li:dataset:(urn:li:dataPlatform:sqlite,archon_demo.customers,PROD)";
export const CANONICAL_QUESTION =
  "Which customer segment generated the highest net revenue in Q2 2026, and is customers.customer_email governed as PII?";
export const GOVERNED_COLUMN_PATH = "customer_email";
export const RUNTIME_OPERATOR_GROUP = "archon-runtime-operators";
export const RUNTIME_APPROVER_GROUP = "archon-approvers";
export const APPROVAL_SCOPE = "archon/approve";
export const BEDROCK_INFERENCE_PROFILE =
  "eu.anthropic.claude-sonnet-4-5-20250929-v1:0";
export const BEDROCK_BASE_MODEL =
  "anthropic.claude-sonnet-4-5-20250929-v1:0";
export const BEDROCK_BASE_REGIONS = [
  "eu-central-1",
  "eu-north-1",
  "eu-south-1",
  "eu-south-2",
  "eu-west-1",
  "eu-west-3"
] as const;

const baseResponseParameters: Record<string, string> = {
  "method.response.header.Cache-Control": "'no-store'",
  "method.response.header.Content-Type":
    "'application/json; charset=utf-8'",
  "method.response.header.Cross-Origin-Resource-Policy": "'same-origin'",
  "method.response.header.Referrer-Policy": "'no-referrer'",
  "method.response.header.X-Content-Type-Options": "'nosniff'"
};
const responseParameters: Record<string, string> = {
  ...baseResponseParameters,
  "method.response.header.Location":
    "integration.response.body.headers.location",
  "method.response.header.Retry-After":
    "integration.response.body.headers.retryAfter"
};
const methodResponseParameters: Record<string, boolean> =
  Object.fromEntries(
    Object.keys(responseParameters).map((parameter) => [
      parameter,
      parameter !== "method.response.header.Location" &&
        parameter !== "method.response.header.Retry-After"
    ])
  );

export function retainedKey(
  scope: Construct,
  id: string,
  alias: string,
  description: string
): kms.Key {
  return new kms.Key(scope, id, {
    alias,
    description,
    enableKeyRotation: true,
    pendingWindow: Duration.days(30),
    removalPolicy: RemovalPolicy.RETAIN
  });
}

export function allowCloudWatchLogs(
  key: kms.Key,
  stage: ArchonStage
): void {
  const stack = Stack.of(key);
  const logArns = [
    stack.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: `/archon/${stage}/*`,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    }),
    stack.formatArn({
      service: "logs",
      resource: "log-group",
      resourceName: `aws-waf-logs-archon-${stage}-api`,
      arnFormat: ArnFormat.COLON_RESOURCE_NAME
    })
  ];
  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: "AllowOnlyArchonCloudWatchLogsEncryption",
      principals: [
        new iam.ServicePrincipal(`logs.${Aws.REGION}.${Aws.URL_SUFFIX}`)
      ],
      actions: [
        "kms:Decrypt",
        "kms:Describe*",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:ReEncrypt*"
      ],
      resources: ["*"],
      conditions: {
        ArnLike: {
          "kms:EncryptionContext:aws:logs:arn": logArns
        }
      }
    })
  );
}

export function retainedLogGroup(
  scope: Construct,
  id: string,
  name: string,
  key: kms.IKey,
  retention: logs.RetentionDays = logs.RetentionDays.ONE_YEAR
): logs.LogGroup {
  return new logs.LogGroup(scope, id, {
    logGroupName: name,
    encryptionKey: key,
    retention,
    removalPolicy: RemovalPolicy.RETAIN
  });
}

export function narrowLambdaIntegration(
  handler: lambda.IFunction,
  requestTemplate: string
): apigateway.LambdaIntegration {
  return new apigateway.LambdaIntegration(handler, {
    proxy: false,
    allowTestInvoke: false,
    passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
    requestTemplates: { "application/json": requestTemplate },
    integrationResponses: [
      {
        selectionPattern: "(?s).+",
        statusCode: "502",
        responseParameters: baseResponseParameters,
        responseTemplates: {
          "application/json": '{"error":"lambda_integration_failed"}\n'
        }
      },
      {
        statusCode: "200",
        responseParameters,
        responseTemplates: {
          "application/json": [
            "#set($statusCode = $input.path('$.statusCode'))",
            "#set($context.responseOverride.status = $statusCode)",
            "$input.json('$.payload')"
          ].join("\n")
        }
      }
    ]
  });
}

export function narrowMethodResponses(
  statusCodes: string[]
): apigateway.MethodResponse[] {
  return [...new Set(statusCodes)].map((statusCode) => ({
    statusCode,
    responseParameters: methodResponseParameters
  }));
}

export function managedWafRule(
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
      sampledRequestsEnabled: false
    }
  };
}

export function output(
  scope: Construct,
  id: string,
  value: string
): void {
  new CfnOutput(scope, id, { value });
}
