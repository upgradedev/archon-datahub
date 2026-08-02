import {
  ArnFormat,
  Aws,
  Duration,
  Fn,
  RemovalPolicy,
  Stack
} from "aws-cdk-lib";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import {
  APPROVAL_SCOPE,
  RUNTIME_APPROVER_GROUP,
  RUNTIME_OPERATOR_GROUP,
  managedWafRule,
  narrowLambdaIntegration,
  narrowMethodResponses,
  output,
  retainedLogGroup,
  type ArchonStage
} from "./judge-contract";

export interface JudgeIdentityProps {
  readonly stage: ArchonStage;
  readonly applicationDomain: string;
}

export interface JudgeIdentity {
  readonly userPool: cognito.UserPool;
  readonly userPoolClient: cognito.UserPoolClient;
  readonly userPoolDomain: cognito.UserPoolDomain;
  readonly applicationUrl: string;
  readonly issuer: string;
}

export function createJudgeIdentity(
  scope: Construct,
  props: JudgeIdentityProps
): JudgeIdentity {
  const { stage, applicationDomain } = props;
  const applicationUrl = Fn.join("", [
    "https://",
    applicationDomain,
    "/"
  ]);
  const userPool = new cognito.UserPool(scope, "JudgeUserPool", {
    userPoolName: `archon-${stage}`,
    selfSignUpEnabled: false,
    signInAliases: { email: true },
    signInCaseSensitive: false,
    standardAttributes: {
      email: { required: true, mutable: false }
    },
    customAttributes: {
      archon_judge_binding: new cognito.StringAttribute({
        minLen: 64,
        maxLen: 64,
        mutable: false
      })
    },
    passwordPolicy: {
      minLength: 14,
      passwordHistorySize: 24,
      requireDigits: true,
      requireLowercase: true,
      requireSymbols: true,
      requireUppercase: true,
      tempPasswordValidity: Duration.days(3)
    },
    mfa: cognito.Mfa.OPTIONAL,
    mfaSecondFactor: { otp: true, sms: false },
    accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
    featurePlan: cognito.FeaturePlan.PLUS,
    standardThreatProtectionMode:
      cognito.StandardThreatProtectionMode.FULL_FUNCTION,
    deletionProtection: true,
    removalPolicy: RemovalPolicy.RETAIN
  });
  const approvalScope = new cognito.ResourceServerScope({
    scopeName: "approve",
    scopeDescription:
      "Submit a human decision for one digest-bound DataHub proposal"
  });
  const resourceServer = userPool.addResourceServer(
    "ApprovalResourceServer",
    {
      identifier: "archon",
      userPoolResourceServerName: `archon-${stage}-approval-api`,
      scopes: [approvalScope]
    }
  );
  const userPoolDomain = userPool.addDomain("HostedDomain", {
    cognitoDomain: {
      domainPrefix: `archon-${stage}-${Aws.ACCOUNT_ID}`
    },
    managedLoginVersion:
      cognito.ManagedLoginVersion.CLASSIC_HOSTED_UI
  });
  new cognito.CfnUserPoolGroup(scope, "RuntimeOperatorGroup", {
    userPoolId: userPool.userPoolId,
    groupName: RUNTIME_OPERATOR_GROUP,
    description:
      "Starts and operates immutable DataHub runtime sessions",
    precedence: 10
  });
  new cognito.CfnUserPoolGroup(scope, "RuntimeApproverGroup", {
    userPoolId: userPool.userPoolId,
    groupName: RUNTIME_APPROVER_GROUP,
    description:
      "Approves or rejects one digest-bound governed mutation",
    precedence: 20
  });
  const userPoolClient = userPool.addClient("SpaClient", {
    userPoolClientName: `archon-${stage}-spa`,
    authFlows: { userSrp: false },
    generateSecret: false,
    preventUserExistenceErrors: true,
    enableTokenRevocation: true,
    readAttributes:
      new cognito.ClientAttributes().withStandardAttributes({
        email: true
      }),
    accessTokenValidity: Duration.minutes(15),
    idTokenValidity: Duration.minutes(15),
    refreshTokenValidity: Duration.days(1),
    supportedIdentityProviders: [
      cognito.UserPoolClientIdentityProvider.COGNITO
    ],
    oAuth: {
      callbackUrls: [applicationUrl],
      logoutUrls: [applicationUrl],
      flows: {
        authorizationCodeGrant: true,
        implicitCodeGrant: false,
        clientCredentials: false
      },
      scopes: [
        cognito.OAuthScope.OPENID,
        cognito.OAuthScope.EMAIL,
        cognito.OAuthScope.PROFILE,
        cognito.OAuthScope.resourceServer(
          resourceServer,
          approvalScope
        )
      ]
    }
  });
  const cfnClient =
    userPoolClient.node.defaultChild as cognito.CfnUserPoolClient;
  cfnClient.refreshTokenValidity = 1;
  cfnClient.tokenValidityUnits = {
    accessToken: "minutes",
    idToken: "minutes",
    refreshToken: "days"
  };
  new cognito.CfnUserPoolRiskConfigurationAttachment(
    scope,
    "SpaRiskConfiguration",
    {
      userPoolId: userPool.userPoolId,
      clientId: userPoolClient.userPoolClientId,
      accountTakeoverRiskConfiguration: {
        actions: {
          lowAction: { eventAction: "NO_ACTION", notify: false },
          mediumAction: { eventAction: "NO_ACTION", notify: false },
          highAction: { eventAction: "NO_ACTION", notify: false }
        }
      },
      compromisedCredentialsRiskConfiguration: {
        actions: { eventAction: "BLOCK" },
        eventFilter: ["SIGN_IN", "PASSWORD_CHANGE"]
      }
    }
  );

  return {
    userPool,
    userPoolClient,
    userPoolDomain,
    applicationUrl,
    issuer: userPool.userPoolProviderUrl
  };
}

export interface JudgeEdgeApiProps {
  readonly stage: ArchonStage;
  readonly applicationDomain: string;
  readonly hostedZoneId: string;
  readonly certificateArn: string;
  readonly cloudFrontWebAclArn: string;
  readonly identity: JudgeIdentity;
  readonly runtimeControlFunction: lambda.IFunction;
  readonly controlFunction: lambda.IFunction;
  readonly spaBucket: s3.Bucket;
  readonly spaKey: kms.Key;
  readonly logsKey: kms.IKey;
  readonly originKeySecret: secretsmanager.ISecret;
}

export interface JudgeEdgeApi {
  readonly apiUrl: string;
  readonly distributionId: string;
  readonly distributionDomainName: string;
  readonly regionalWebAclArn: string;
}

export function addJudgeEdgeApi(
  scope: Construct,
  props: JudgeEdgeApiProps
): JudgeEdgeApi {
  const stack = Stack.of(scope);
  const {
    stage,
    applicationDomain,
    hostedZoneId,
    certificateArn,
    cloudFrontWebAclArn,
    identity,
    runtimeControlFunction,
    controlFunction,
    spaBucket,
    spaKey,
    logsKey,
    originKeySecret
  } = props;
  const isProduction = stage === "production";
  const apiAccessLogs = retainedLogGroup(
    scope,
    "ApiAccessLogs",
    `/archon/${stage}/api`,
    logsKey,
    logs.RetentionDays.ONE_YEAR
  );
  const api = new apigateway.RestApi(scope, "JudgeApi", {
    restApiName: `archon-${stage}-judge`,
    description:
      "Low-cost dual-runtime DataHub judge API; direct origin requires a private key",
    endpointTypes: [apigateway.EndpointType.REGIONAL],
    apiKeySourceType: apigateway.ApiKeySourceType.HEADER,
    cloudWatchRole: false,
    deployOptions: {
      stageName: stage,
      cacheClusterEnabled: false,
      dataTraceEnabled: false,
      loggingLevel: apigateway.MethodLoggingLevel.ERROR,
      metricsEnabled: true,
      tracingEnabled: true,
      throttlingBurstLimit: isProduction ? 100 : 20,
      throttlingRateLimit: isProduction ? 50 : 10,
      accessLogDestination:
        new apigateway.LogGroupLogDestination(apiAccessLogs),
      accessLogFormat:
        apigateway.AccessLogFormat.jsonWithStandardFields({
          caller: false,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: false
        })
    },
    defaultCorsPreflightOptions: undefined
  });
  const originApiKey = new apigateway.ApiKey(scope, "OriginApiKey", {
    apiKeyName: `archon-${stage}-cloudfront-origin`,
    description:
      "CloudFront-only API origin credential stored in Secrets Manager",
    enabled: true,
    value: originKeySecret.secretValue.unsafeUnwrap()
  });
  const usagePlan = api.addUsagePlan("OriginUsagePlan", {
    name: `archon-${stage}-cloudfront-origin`,
    throttle: {
      burstLimit: isProduction ? 100 : 20,
      rateLimit: isProduction ? 50 : 10
    },
    quota: {
      limit: isProduction ? 250_000 : 25_000,
      period: apigateway.Period.DAY
    }
  });
  usagePlan.addApiStage({ stage: api.deploymentStage });
  usagePlan.addApiKey(originApiKey);

  const authorizer = new apigateway.CognitoUserPoolsAuthorizer(
    scope,
    "JudgeAuthorizer",
    {
      cognitoUserPools: [identity.userPool],
      authorizerName: `archon-${stage}-cognito`,
      identitySource: "method.request.header.Authorization",
      resultsCacheTtl: Duration.minutes(5)
    }
  );
  const authenticated: apigateway.MethodOptions = {
    authorizationType: apigateway.AuthorizationType.COGNITO,
    authorizer,
    authorizationScopes: [APPROVAL_SCOPE],
    apiKeyRequired: true
  };
  const validator = new apigateway.RequestValidator(
    scope,
    "RequestValidator",
    {
      restApi: api,
      requestValidatorName: "strict-body-and-path",
      validateRequestBody: true,
      validateRequestParameters: true
    }
  );
  const sessionModel = model(api, "RuntimeSessionModel", {
    type: apigateway.JsonSchemaType.OBJECT,
    additionalProperties: false,
    required: ["requestedProfile"],
    properties: {
      requestedProfile: {
        type: apigateway.JsonSchemaType.STRING,
        enum: ["auto", "cloud", "core"]
      }
    }
  });
  const runModel = model(api, "RuntimeControlLoopModel", {
    type: apigateway.JsonSchemaType.OBJECT,
    additionalProperties: false,
    required: [
      "query",
      "question",
      "datasetUrn",
      "sessionId",
      "mode"
    ],
    properties: {
      query: { type: apigateway.JsonSchemaType.STRING },
      question: { type: apigateway.JsonSchemaType.STRING },
      datasetUrn: { type: apigateway.JsonSchemaType.STRING },
      sessionId: {
        type: apigateway.JsonSchemaType.STRING,
        pattern: "^rs_[A-Za-z0-9_-]{43}$"
      },
      mode: {
        type: apigateway.JsonSchemaType.STRING,
        enum: ["GOVERNED"]
      }
    }
  });
  const emptyModel = model(api, "EmptyCommandModel", {
    type: apigateway.JsonSchemaType.OBJECT,
    additionalProperties: false
  });
  const decisionModel = model(api, "RuntimeDecisionModel", {
    type: apigateway.JsonSchemaType.OBJECT,
    additionalProperties: false,
    required: ["decision", "comment"],
    properties: {
      decision: {
        type: apigateway.JsonSchemaType.STRING,
        enum: ["APPROVE", "REJECT"]
      },
      comment: {
        type: apigateway.JsonSchemaType.STRING,
        maxLength: 512
      }
    }
  });

  addRoutes({
    api,
    validator,
    authenticated,
    sessionModel,
    runModel,
    emptyModel,
    decisionModel,
    runtimeControlFunction,
    controlFunction
  });

  const regionalWebAcl = new wafv2.CfnWebACL(
    scope,
    "RegionalWebAcl",
    {
      name: `archon-${stage}-api`,
      description:
        "Regional protections shared by the judge API and Cognito",
      scope: "REGIONAL",
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `archon-${stage}-api-waf`,
        sampledRequestsEnabled: false
      },
      dataProtectionConfig: {
        dataProtections: ["authorization", "cookie", "x-api-key"].map(
          (header) => ({
            action: "SUBSTITUTION",
            excludeRateBasedDetails: false,
            excludeRuleMatchDetails: false,
            field: {
              fieldType: "SINGLE_HEADER",
              fieldKeys: [header]
            }
          })
        )
      },
      rules: [
        managedWafRule(
          "AWSManagedRulesAmazonIpReputationList",
          0
        ),
        managedWafRule("AWSManagedRulesCommonRuleSet", 10),
        managedWafRule(
          "AWSManagedRulesKnownBadInputsRuleSet",
          20
        ),
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
            metricName: `archon-${stage}-api-rate`,
            sampledRequestsEnabled: false
          }
        }
      ]
    }
  );
  const apiStageArn =
    `arn:${Aws.PARTITION}:apigateway:${Aws.REGION}::/restapis/` +
    `${api.restApiId}/stages/${api.deploymentStage.stageName}`;
  const apiWafAssociation = new wafv2.CfnWebACLAssociation(
    scope,
    "ApiWafAssociation",
    {
      resourceArn: apiStageArn,
      webAclArn: regionalWebAcl.attrArn
    }
  );
  apiWafAssociation.node.addDependency(api.deploymentStage);
  const cognitoWafAssociation =
    new wafv2.CfnWebACLAssociation(
      scope,
      "CognitoWafAssociation",
      {
        resourceArn: identity.userPool.userPoolArn,
        webAclArn: regionalWebAcl.attrArn
      }
    );
  cognitoWafAssociation.node.addDependency(
    identity.userPool,
    regionalWebAcl
  );

  const wafLogs = retainedLogGroup(
    scope,
    "ApiWafLogs",
    `aws-waf-logs-archon-${stage}-api`,
    logsKey,
    logs.RetentionDays.ONE_YEAR
  );
  const wafLogArn = stack.formatArn({
    service: "logs",
    resource: "log-group",
    resourceName: wafLogs.logGroupName,
    arnFormat: ArnFormat.COLON_RESOURCE_NAME
  });
  const wafLogging = new wafv2.CfnLoggingConfiguration(
    scope,
    "ApiWafLogging",
    {
      resourceArn: regionalWebAcl.attrArn,
      logDestinationConfigs: [wafLogArn],
      loggingFilter: {
        defaultBehavior: "DROP",
        filters: [
          {
            behavior: "KEEP",
            conditions: [
              { actionCondition: { action: "BLOCK" } },
              { actionCondition: { action: "COUNT" } }
            ],
            requirement: "MEETS_ANY"
          }
        ]
      },
      redactedFields: [
        { singleHeader: { name: "authorization" } },
        { singleHeader: { name: "cookie" } },
        { singleHeader: { name: "x-api-key" } }
      ]
    }
  );
  wafLogging.node.addDependency(regionalWebAcl, wafLogs);

  const responseHeaders = new cloudfront.ResponseHeadersPolicy(
    scope,
    "SecurityHeaders",
    {
      responseHeadersPolicyName:
        `archon-${stage}-security-headers`,
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          contentSecurityPolicy: [
            "default-src 'self'",
            "base-uri 'self'",
            `connect-src 'self' ${identity.userPoolDomain.baseUrl()}`,
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "object-src 'none'",
            "script-src 'self'",
            "style-src 'self'"
          ].join("; "),
          override: true
        },
        contentTypeOptions: { override: true },
        frameOptions: {
          frameOption: cloudfront.HeadersFrameOption.DENY,
          override: true
        },
        referrerPolicy: {
          referrerPolicy:
            cloudfront.HeadersReferrerPolicy.NO_REFERRER,
          override: true
        },
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(730),
          includeSubdomains: true,
          preload: true,
          override: true
        },
        xssProtection: {
          protection: true,
          modeBlock: true,
          override: true
        }
      }
    }
  );
  const router = new cloudfront.Function(scope, "SpaRouter", {
    functionName: `archon-${stage}-spa-router`,
    runtime: cloudfront.FunctionRuntime.JS_2_0,
    comment:
      "Reject non-canonical hosts and route extensionless SPA paths",
    code: cloudfront.FunctionCode.fromInline(
      [
        "function handler(event) {",
        "  var request = event.request;",
        '  var host = (request.headers.host && request.headers.host.value || "").toLowerCase();',
        `  if (host !== "${applicationDomain}") return {statusCode:421,statusDescription:"Misdirected Request",headers:{"cache-control":{value:"no-store"}}};`,
        '  if (request.uri.indexOf("/api/") !== 0 && request.uri !== "/runtime-config.json" && request.uri.split("/").pop().indexOf(".") < 0) request.uri = "/index.html";',
        "  return request;",
        "}"
      ].join("\n")
    )
  });
  const routerAssociation = {
    function: router,
    eventType: cloudfront.FunctionEventType.VIEWER_REQUEST
  };
  // CloudFront rejects Authorization in an OriginRequestPolicy. A zero-TTL
  // CachePolicy is the supported forwarding path: the header reaches API
  // Gateway, participates in the (unused) cache key, and no authenticated
  // response can be retained.
  const apiCachePolicy = new cloudfront.CachePolicy(
    scope,
    "ApiNoCachePolicy",
    {
      cachePolicyName:
        `archon-${stage}-api-no-cache`,
      comment:
        "Forward Authorization to the judge API while retaining zero objects",
      defaultTtl: Duration.seconds(0),
      minTtl: Duration.seconds(0),
      maxTtl: Duration.seconds(0),
      cookieBehavior:
        cloudfront.CacheCookieBehavior.none(),
      headerBehavior:
        cloudfront.CacheHeaderBehavior.allowList(
          "authorization"
        ),
      queryStringBehavior:
        cloudfront.CacheQueryStringBehavior.none()
    }
  );
  const apiOriginPolicy = new cloudfront.OriginRequestPolicy(
    scope,
    "ApiOriginPolicy",
    {
      originRequestPolicyName:
        `archon-${stage}-api-origin`,
      cookieBehavior:
        cloudfront.OriginRequestCookieBehavior.none(),
      headerBehavior:
        cloudfront.OriginRequestHeaderBehavior.allowList(
          "accept",
          "content-type"
        ),
      queryStringBehavior:
        cloudfront.OriginRequestQueryStringBehavior.all()
    }
  );
  const apiOrigin = new origins.HttpOrigin(
    `${api.restApiId}.execute-api.${Aws.REGION}.${Aws.URL_SUFFIX}`,
    {
      protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
      originPath: `/${stage}`,
      customHeaders: {
        "x-api-key":
          originKeySecret.secretValue.unsafeUnwrap()
      },
      connectionAttempts: 3,
      connectionTimeout: Duration.seconds(10)
    }
  );
  const spaOrigin =
    origins.S3BucketOrigin.withOriginAccessControl(spaBucket);
  const certificate = acm.Certificate.fromCertificateArn(
    scope,
    "ViewerCertificate",
    certificateArn
  );
  const distribution = new cloudfront.Distribution(
    scope,
    "JudgeDistribution",
    {
      comment:
        `Archon ${stage}: private SPA and same-origin serverless API`,
      defaultRootObject: "index.html",
      domainNames: [applicationDomain],
      certificate,
      webAclId: cloudFrontWebAclArn,
      minimumProtocolVersion:
        cloudfront.SecurityPolicyProtocol.TLS_V1_3_2025,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      enableIpv6: true,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: {
        origin: spaOrigin,
        allowedMethods:
          cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods:
          cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        compress: true,
        functionAssociations: [routerAssociation],
        responseHeadersPolicy: responseHeaders,
        viewerProtocolPolicy:
          cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
      },
      additionalBehaviors: {
        "runtime-config.json": {
          origin: spaOrigin,
          allowedMethods:
            cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
          cachedMethods:
            cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
          compress: true,
          functionAssociations: [routerAssociation],
          responseHeadersPolicy: responseHeaders,
          viewerProtocolPolicy:
            cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        },
        "api/*": {
          origin: apiOrigin,
          allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
          cachedMethods:
            cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
          cachePolicy: apiCachePolicy,
          compress: true,
          functionAssociations: [routerAssociation],
          originRequestPolicy: apiOriginPolicy,
          responseHeadersPolicy: responseHeaders,
          viewerProtocolPolicy:
            cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        }
      }
    }
  );
  distribution.node.addDependency(originApiKey);
  spaKey.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: "AllowCloudFrontOacToDecryptSpaObjects",
      principals: [
        new iam.ServicePrincipal("cloudfront.amazonaws.com")
      ],
      actions: ["kms:Decrypt"],
      resources: ["*"],
      conditions: {
        StringEquals: {
          "AWS:SourceAccount": Aws.ACCOUNT_ID
        },
        ArnLike: {
          "AWS:SourceArn":
            `arn:${Aws.PARTITION}:cloudfront::${Aws.ACCOUNT_ID}:distribution/*`
        }
      }
    })
  );
  const aliasTarget = {
    dnsName: distribution.distributionDomainName,
    hostedZoneId: "Z2FDTNDATAQYW2",
    evaluateTargetHealth: false
  };
  for (const recordType of ["A", "AAAA"] as const) {
    new route53.CfnRecordSet(
      scope,
      `ApplicationAlias${recordType}`,
      {
        hostedZoneId,
        name: applicationDomain,
        type: recordType,
        aliasTarget
      }
    );
  }

  output(
    scope,
    "ArchonApplicationUrl",
    Fn.join("", ["https://", applicationDomain])
  );
  output(
    scope,
    "ArchonApiUrl",
    Fn.join("", ["https://", applicationDomain, "/api"])
  );
  output(scope, "ArchonApiInvokeUrl", api.url);
  output(
    scope,
    "ArchonApiStageArn",
    apiStageArn
  );
  output(
    scope,
    "ArchonCloudFrontDistributionId",
    distribution.distributionId
  );
  output(
    scope,
    "ArchonCloudFrontDomainName",
    distribution.distributionDomainName
  );
  output(
    scope,
    "ArchonRegionalWebAclArn",
    regionalWebAcl.attrArn
  );
  output(scope, "ArchonUserPoolId", identity.userPool.userPoolId);
  output(scope, "ArchonUserPoolArn", identity.userPool.userPoolArn);
  output(
    scope,
    "ArchonUserPoolClientId",
    identity.userPoolClient.userPoolClientId
  );
  output(
    scope,
    "ArchonCognitoHostedUiOrigin",
    identity.userPoolDomain.baseUrl()
  );
  output(
    scope,
    "ArchonCognitoAuthorizationEndpoint",
    `${identity.userPoolDomain.baseUrl()}/oauth2/authorize`
  );
  output(
    scope,
    "ArchonCognitoTokenEndpoint",
    `${identity.userPoolDomain.baseUrl()}/oauth2/token`
  );
  output(
    scope,
    "ArchonCognitoLogoutEndpoint",
    `${identity.userPoolDomain.baseUrl()}/logout`
  );
  output(scope, "ArchonApprovalOAuthScope", APPROVAL_SCOPE);
  output(
    scope,
    "ArchonAuthRedirectUri",
    identity.applicationUrl
  );
  output(
    scope,
    "ArchonAuthLogoutUri",
    identity.applicationUrl
  );
  output(
    scope,
    "ArchonApproverGroupName",
    RUNTIME_APPROVER_GROUP
  );
  output(
    scope,
    "ArchonRuntimeOperatorGroupName",
    RUNTIME_OPERATOR_GROUP
  );

  return {
    apiUrl: Fn.join("", ["https://", applicationDomain, "/api"]),
    distributionId: distribution.distributionId,
    distributionDomainName: distribution.distributionDomainName,
    regionalWebAclArn: regionalWebAcl.attrArn
  };
}

function model(
  api: apigateway.RestApi,
  id: string,
  schema: apigateway.JsonSchema
): apigateway.Model {
  return api.addModel(id, {
    contentType: "application/json",
    modelName: id,
    schema: {
      schema: apigateway.JsonSchemaVersion.DRAFT4,
      ...schema
    }
  });
}

interface RouteProps {
  readonly api: apigateway.RestApi;
  readonly validator: apigateway.IRequestValidator;
  readonly authenticated: apigateway.MethodOptions;
  readonly sessionModel: apigateway.IModel;
  readonly runModel: apigateway.IModel;
  readonly emptyModel: apigateway.IModel;
  readonly decisionModel: apigateway.IModel;
  readonly runtimeControlFunction: lambda.IFunction;
  readonly controlFunction: lambda.IFunction;
}

function addRoutes(props: RouteProps): void {
  const claim = (name: "sub" | "iss"): string =>
    `"$util.escapeJavaScript($context.authorizer.claims.${name}).replaceAll("\\\\'","'")"`;
  const groups =
    `"$util.escapeJavaScript($context.authorizer.claims['cognito:groups']).replaceAll("\\\\'","'")"`;
  const identity =
    `"identity":{"subject":${claim("sub")},"issuer":${claim("iss")},"groups":${groups}}`;
  const requestId =
    `"$util.escapeJavaScript($context.extendedRequestId).replaceAll("\\\\'","'")"`;
  const path = (name: string) =>
    `"$util.escapeJavaScript($input.params('${name}')).replaceAll("\\\\'","'")"`;
  const templates = {
    profiles:
      `{"operation":"profiles","requestId":${requestId}}`,
    sessionStart:
      `{"operation":"sessionStart","requestId":${requestId},"body":$input.json('$'),${identity}}`,
    sessionStatus:
      `{"operation":"sessionStatus","requestId":${requestId},"sessionId":${path("sessionId")}}`,
    sessionActivity:
      `{"operation":"sessionActivity","requestId":${requestId},"sessionId":${path("sessionId")},${identity}}`,
    sessionStop:
      `{"operation":"sessionStop","requestId":${requestId},"sessionId":${path("sessionId")},${identity}}`,
    runStart:
      `{"operation":"startV2","requestId":${requestId},"body":$input.json('$'),${identity}}`,
    runStatus:
      `{"operation":"statusV2","requestId":${requestId},"auditId":${path("auditId")},${identity}}`,
    improve:
      `{"operation":"improveV2","requestId":${requestId},"auditId":${path("auditId")},"body":$input.json('$'),${identity}}`,
    decide:
      `{"operation":"decideV2","requestId":${requestId},"auditId":${path("auditId")},"body":$input.json('$'),${identity}}`
  };
  const apiRoot = props.api.root.addResource("api");
  const profiles = apiRoot.addResource("runtime-profiles");
  profiles.addMethod(
    "GET",
    narrowLambdaIntegration(
      props.runtimeControlFunction,
      templates.profiles
    ),
    {
      authorizationType: apigateway.AuthorizationType.NONE,
      apiKeyRequired: true,
      methodResponses: narrowMethodResponses(["200", "502"])
    }
  );
  const sessions = apiRoot.addResource("runtime-sessions");
  sessions.addMethod(
    "POST",
    narrowLambdaIntegration(
      props.runtimeControlFunction,
      templates.sessionStart
    ),
    {
      ...props.authenticated,
      requestValidator: props.validator,
      requestModels: {
        "application/json": props.sessionModel
      },
      methodResponses: narrowMethodResponses([
        "200",
        "201",
        "202",
        "400",
        "401",
        "403",
        "409",
        "413",
        "502"
      ])
    }
  );
  const session = sessions.addResource("{sessionId}");
  const sessionPath = {
    "method.request.path.sessionId": true
  };
  session.addMethod(
    "GET",
    narrowLambdaIntegration(
      props.runtimeControlFunction,
      templates.sessionStatus
    ),
    {
      authorizationType: apigateway.AuthorizationType.NONE,
      apiKeyRequired: true,
      requestValidator: props.validator,
      requestParameters: sessionPath,
      methodResponses: narrowMethodResponses([
        "200",
        "400",
        "404",
        "409",
        "502"
      ])
    }
  );
  for (const [name, operation] of [
    ["activity", templates.sessionActivity],
    ["stop", templates.sessionStop]
  ] as const) {
    session.addResource(name).addMethod(
      "POST",
      narrowLambdaIntegration(
        props.runtimeControlFunction,
        operation
      ),
      {
        ...props.authenticated,
        requestValidator: props.validator,
        requestParameters: sessionPath,
        requestModels: {
          "application/json": props.emptyModel
        },
        methodResponses: narrowMethodResponses([
          "200",
          "202",
          "400",
          "401",
          "403",
          "404",
          "409",
          "502"
        ])
      }
    );
  }
  const runs = apiRoot.addResource("control-loops-v2");
  runs.addMethod(
    "POST",
    narrowLambdaIntegration(
      props.controlFunction,
      templates.runStart
    ),
    {
      ...props.authenticated,
      requestValidator: props.validator,
      requestModels: {
        "application/json": props.runModel
      },
      methodResponses: narrowMethodResponses([
        "202",
        "400",
        "401",
        "403",
        "404",
        "409",
        "413",
        "502"
      ])
    }
  );
  const run = runs.addResource("{auditId}");
  const auditPath = { "method.request.path.auditId": true };
  run.addMethod(
    "GET",
    narrowLambdaIntegration(
      props.controlFunction,
      templates.runStatus
    ),
    {
      ...props.authenticated,
      requestValidator: props.validator,
      requestParameters: auditPath,
      methodResponses: narrowMethodResponses([
        "200",
        "400",
        "401",
        "403",
        "404",
        "409",
        "410",
        "502"
      ])
    }
  );
  run.addResource("improve-context").addMethod(
    "POST",
    narrowLambdaIntegration(
      props.controlFunction,
      templates.improve
    ),
    {
      ...props.authenticated,
      requestValidator: props.validator,
      requestParameters: auditPath,
      requestModels: {
        "application/json": props.emptyModel
      },
      methodResponses: narrowMethodResponses([
        "200",
        "202",
        "400",
        "401",
        "403",
        "404",
        "409",
        "413",
        "502"
      ])
    }
  );
  run.addResource("approval").addMethod(
    "POST",
    narrowLambdaIntegration(
      props.controlFunction,
      templates.decide
    ),
    {
      ...props.authenticated,
      requestValidator: props.validator,
      requestParameters: auditPath,
      requestModels: {
        "application/json": props.decisionModel
      },
      methodResponses: narrowMethodResponses([
        "200",
        "202",
        "400",
        "401",
        "403",
        "404",
        "409",
        "413",
        "502"
      ])
    }
  );
}
