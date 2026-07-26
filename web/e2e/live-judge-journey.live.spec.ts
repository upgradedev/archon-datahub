import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readdirSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  expect,
  test,
  type APIRequestContext,
  type APIResponse,
  type BrowserContext,
  type Page,
  type Request,
  type Response,
} from "@playwright/test";

test.skip(
  process.env.ARCHON_LIVE_JUDGE_JOURNEY !== "1",
  "The credentialed journey runs only in its protected CI/CD job.",
);

const SECRET_ENVIRONMENT_KEYS = [
  "JUDGE_USERNAME",
  "JUDGE_PASSWORD",
  "JUDGE_ACCOUNT_ID",
] as const;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const RAW_DIGEST = /^[a-f0-9]{64}$/u;
const RELEASE_SHA = /^[a-f0-9]{40}$/u;
const AUDIT_ID = /^[a-f0-9]{64}$/u;
const UUID =
  /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RFC3339_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

interface RuntimeConfig {
  readonly schemaVersion: 1;
  readonly demoQuery: string;
  readonly auth: {
    readonly clientId: string;
    readonly authorizationEndpoint: string;
    readonly tokenEndpoint: string;
    readonly logoutEndpoint: string;
    readonly redirectUri: string;
    readonly logoutUri: string;
    readonly scopes: readonly string[];
  };
}

interface ProtectedCredentials {
  username: string;
  password: string;
  accountId: string;
}

interface ExpectedBindings {
  readonly applicationOrigin: string;
  readonly applicationOriginSha256: string;
  readonly runtimeConfigSha256: string;
  readonly releaseSha: string;
  readonly identityDigest: string;
  readonly lifecycleDigest: string;
  readonly cognitoSubjectDigest: string;
  readonly cognitoHostedUiOrigin: string;
  readonly cognitoClientId: string;
  readonly cognitoIssuer: string;
  readonly outputDirectory: string;
}

interface IdentityEvidence {
  readonly identityDigest: string;
  readonly cognitoSubjectDigest: string;
  readonly authenticatedAt: string;
  readonly issuedAt: string;
  readonly issuerSha256: string;
  readonly jwksSha256: string;
  readonly idTokenKidSha256: string;
  readonly accessTokenKidSha256: string;
}

interface AuthenticatedSession {
  readonly identity: IdentityEvidence;
  accessToken: string;
}

interface CognitoJwk {
  readonly alg: "RS256";
  readonly e: "AQAB";
  readonly kid: string;
  readonly kty: "RSA";
  readonly n: string;
  readonly use: "sig";
}

interface CognitoJwks {
  readonly keys: readonly CognitoJwk[];
  readonly documentSha256: string;
}

interface StartProjection {
  readonly auditId: string;
  readonly pollUrl: string;
  readonly submittedAt: string;
}

interface AwaitingProjection {
  readonly auditId: string;
  readonly approvalId: string;
  readonly releaseSha: string;
  readonly reportSha256: string;
  readonly submittedAt: string;
}

interface TerminalProjection {
  readonly schemaVersion: "archon.control-loop-terminal-public-projection/v1";
  readonly status: "SUCCEEDED";
  readonly releaseSha: string;
  readonly approvalDecision: "REJECT";
  readonly outcome: "REJECTED";
  readonly completedAt: string;
  readonly receiptDigest: string;
  readonly executionEvidenceDigest: string;
  readonly reportSha256: string;
  readonly verification: {
    readonly checkCount: 0;
    readonly eventCount: 5;
    readonly rollbackAvailability: "NOT_APPLICABLE";
  };
}

interface NetworkObservation {
  startRequests: number;
  decisionRequests: number;
  tokenRequests: number;
  authorizationRequests: number;
  callbackRequests: number;
  logoutRequests: number;
  allowedApplicationRequests: number;
  allowedHostedUiRequests: number;
  allowedIssuerRequests: number;
  unexpectedRequests: number;
  blockedWebSockets: number;
  serviceWorkerViolations: number;
  requestContractValid: boolean;
  unexpectedMutationRequestEmitted: boolean;
}

interface JsonResponse {
  body(): Promise<Buffer>;
  headers(): Record<string, string>;
  status(): number;
  url(): string;
}

interface AuthorizationRequestEvidence {
  state: string;
  codeChallenge: string;
  readonly digest: string;
}

interface CallbackRequestEvidence {
  code: string;
  readonly digest: string;
}

function ensure(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index])
  );
}

function canonicalJson(value: Json): string {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key]!)}`)
    .join(",")}}`;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sha256Bytes(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function digest(value: Json): string {
  return `sha256:${sha256(canonicalJson(value))}`;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  ensure(value !== undefined && value !== "", `${name} is required.`);
  return value;
}

function exactHttpsOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("The live application origin is invalid.");
  }
  ensure(
    parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.pathname === "/" &&
      parsed.search === "" &&
      parsed.hash === "" &&
      parsed.origin === value,
    "The live application must be an exact canonical HTTPS origin.",
  );
  return value;
}

function exactCognitoIssuer(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("The expected Cognito issuer is invalid.");
  }
  ensure(
    parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === "" &&
      /^cognito-idp\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/u.test(
        parsed.hostname,
      ) &&
      /^\/[a-z0-9-]+_[A-Za-z0-9]+$/u.test(parsed.pathname) &&
      parsed.toString() === value,
    "The expected Cognito issuer must be one exact canonical user-pool URL.",
  );
  return value;
}

function parseExpectedBindings(): ExpectedBindings {
  const applicationOrigin = exactHttpsOrigin(
    requiredEnvironment("ARCHON_LIVE_BASE_URL"),
  );
  const applicationOriginSha256 = requiredEnvironment(
    "ARCHON_EXPECTED_APPLICATION_ORIGIN_SHA256",
  );
  const releaseSha = requiredEnvironment("ARCHON_EXPECTED_RELEASE_SHA");
  const identityDigest = requiredEnvironment("ARCHON_EXPECTED_IDENTITY_DIGEST");
  const lifecycleDigest = requiredEnvironment(
    "ARCHON_EXPECTED_LIFECYCLE_DIGEST",
  );
  const cognitoSubjectDigest = requiredEnvironment(
    "ARCHON_EXPECTED_COGNITO_SUBJECT_DIGEST",
  );
  const runtimeConfigSha256 = requiredEnvironment(
    "ARCHON_EXPECTED_RUNTIME_CONFIG_SHA256",
  );
  const cognitoHostedUiOrigin = exactHttpsOrigin(
    requiredEnvironment("ARCHON_EXPECTED_COGNITO_HOSTED_UI_ORIGIN"),
  );
  const cognitoClientId = requiredEnvironment(
    "ARCHON_EXPECTED_COGNITO_CLIENT_ID",
  );
  const cognitoIssuer = exactCognitoIssuer(
    requiredEnvironment("ARCHON_EXPECTED_COGNITO_ISSUER"),
  );
  ensure(
    RAW_DIGEST.test(applicationOriginSha256) &&
      applicationOriginSha256 === sha256(applicationOrigin),
    "The expected application-origin digest does not bind the live origin.",
  );
  ensure(RELEASE_SHA.test(releaseSha), "The expected release SHA is invalid.");
  ensure(
    DIGEST.test(identityDigest) &&
      DIGEST.test(lifecycleDigest) &&
      DIGEST.test(cognitoSubjectDigest),
    "An expected journey binding digest is invalid.",
  );
  ensure(
    RAW_DIGEST.test(runtimeConfigSha256),
    "The expected raw runtime-configuration digest is invalid.",
  );
  ensure(
    /^[A-Za-z0-9]{8,128}$/u.test(cognitoClientId),
    "The expected Cognito app-client ID is invalid.",
  );
  ensure(
    new Set([
      applicationOrigin,
      cognitoHostedUiOrigin,
      new URL(cognitoIssuer).origin,
    ]).size === 3,
    "The application, Hosted UI, and Cognito issuer origins must be isolated.",
  );
  return {
    applicationOrigin,
    applicationOriginSha256,
    runtimeConfigSha256,
    releaseSha,
    identityDigest,
    lifecycleDigest,
    cognitoSubjectDigest,
    cognitoHostedUiOrigin,
    cognitoClientId,
    cognitoIssuer,
    outputDirectory: requiredEnvironment("ARCHON_LIVE_OUTPUT_DIR"),
  };
}

function consumeProtectedCredentials(): ProtectedCredentials {
  let username: string | undefined;
  let password: string | undefined;
  let accountId: string | undefined;
  try {
    username = requiredEnvironment("JUDGE_USERNAME");
    password = requiredEnvironment("JUDGE_PASSWORD");
    accountId = requiredEnvironment("JUDGE_ACCOUNT_ID");
    ensure(
      username.length <= 320 &&
        username === username.trim() &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(username),
      "The protected judge username is invalid.",
    );
    ensure(
      password.length >= 12 &&
        password.length <= 256 &&
        !/[\u0000-\u001f\u007f]/u.test(password),
      "The protected judge password is invalid.",
    );
    ensure(
      RAW_DIGEST.test(accountId),
      "The protected judge account binding is invalid.",
    );
    return { username, password, accountId };
  } finally {
    for (const key of SECRET_ENVIRONMENT_KEYS) delete process.env[key];
  }
}

function isInstant(value: unknown): value is string {
  return (
    typeof value === "string" &&
    RFC3339_INSTANT.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function exactEndpoint(value: unknown, pathname: string): string {
  ensure(typeof value === "string" && value.length <= 2048, "A Cognito endpoint is invalid.");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("A Cognito endpoint is invalid.");
  }
  ensure(
    parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.pathname === pathname &&
      parsed.search === "" &&
      parsed.hash === "" &&
      parsed.toString() === value,
    "A Cognito endpoint violates the exact HTTPS contract.",
  );
  return value;
}

function hasExactSearchKeys(
  value: URLSearchParams,
  expected: readonly string[],
): boolean {
  const actual = [...value.keys()].sort();
  const wanted = [...expected].sort();
  return (
    actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index]) &&
    wanted.every((key) => value.getAll(key).length === 1)
  );
}

function hasBoundedAuthorizationCallbackQuery(
  url: URL,
  expectedIssuer: string,
): boolean {
  const keys = [...url.searchParams.keys()].sort();
  const exactKeys =
    (keys.length === 2 &&
      keys[0] === "code" &&
      keys[1] === "state") ||
    (keys.length === 3 &&
      keys[0] === "code" &&
      keys[1] === "iss" &&
      keys[2] === "state");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  return (
    exactKeys &&
    keys.every((key) => url.searchParams.getAll(key).length === 1) &&
    typeof code === "string" &&
    code.length >= 8 &&
    code.length <= 4_096 &&
    !/[\s\u0000-\u001f\u007f]/u.test(code) &&
    typeof state === "string" &&
    /^[A-Za-z0-9_-]{43}$/u.test(state) &&
    (url.searchParams.get("iss") === null ||
      url.searchParams.get("iss") === expectedIssuer)
  );
}

function parseRuntimeConfig(
  value: unknown,
  expected: ExpectedBindings,
): RuntimeConfig {
  ensure(
    isRecord(value) &&
      hasExactKeys(value, ["schemaVersion", "demoQuery", "auth"]) &&
      value.schemaVersion === 1 &&
      isRecord(value.auth) &&
      hasExactKeys(value.auth, [
        "clientId",
        "authorizationEndpoint",
        "tokenEndpoint",
        "logoutEndpoint",
        "redirectUri",
        "logoutUri",
        "scopes",
      ]),
    "The live runtime configuration has an invalid schema.",
  );
  const auth = value.auth;
  ensure(
    typeof value.demoQuery === "string" &&
      value.demoQuery.length >= 1 &&
      value.demoQuery.length <= 256 &&
      value.demoQuery === value.demoQuery.trim() &&
      !/[*?\u0000-\u001f\u007f]/u.test(value.demoQuery) &&
      value.demoQuery !== "{}",
    "The live runtime audit scope is not narrow.",
  );
  ensure(
    typeof auth.clientId === "string" &&
      auth.clientId === expected.cognitoClientId,
    "The live Cognito client ID is not the sealed expected client.",
  );
  const authorizationEndpoint = exactEndpoint(
    auth.authorizationEndpoint,
    "/oauth2/authorize",
  );
  const tokenEndpoint = exactEndpoint(auth.tokenEndpoint, "/oauth2/token");
  const logoutEndpoint = exactEndpoint(auth.logoutEndpoint, "/logout");
  ensure(
    authorizationEndpoint ===
      `${expected.cognitoHostedUiOrigin}/oauth2/authorize` &&
      tokenEndpoint === `${expected.cognitoHostedUiOrigin}/oauth2/token` &&
      logoutEndpoint === `${expected.cognitoHostedUiOrigin}/logout`,
    "The runtime Cognito endpoints do not match the sealed Hosted UI origin.",
  );
  ensure(
    auth.redirectUri === `${expected.applicationOrigin}/` &&
      auth.logoutUri === `${expected.applicationOrigin}/`,
    "The runtime callback roots do not bind the live application.",
  );
  ensure(
    Array.isArray(auth.scopes) &&
      auth.scopes.length === 3 &&
      auth.scopes[0] === "openid" &&
      auth.scopes[1] === "email" &&
      auth.scopes[2] === "archon/approve",
    "The live Cognito scopes are not exact.",
  );
  return {
    schemaVersion: 1,
    demoQuery: value.demoQuery,
    auth: {
      clientId: auth.clientId,
      authorizationEndpoint,
      tokenEndpoint,
      logoutEndpoint,
      redirectUri: auth.redirectUri,
      logoutUri: auth.logoutUri,
      scopes: [...auth.scopes] as string[],
    },
  };
}

async function responseJson(
  response: JsonResponse,
  expectedStatus: number | readonly number[],
  expectedUrl: string,
): Promise<unknown> {
  const acceptedStatuses =
    typeof expectedStatus === "number" ? [expectedStatus] : expectedStatus;
  ensure(
    acceptedStatuses.includes(response.status()) && response.url() === expectedUrl,
    "A live HTTP response violated its status or URL contract.",
  );
  ensure(
    (response.headers()["content-type"] ?? "")
      .toLowerCase()
      .startsWith("application/json"),
    "A live HTTP response was not JSON.",
  );
  const raw = await response.body();
  ensure(
    raw.length >= 2 && raw.length <= 1_048_576,
    "A live JSON response violated its bounded body contract.",
  );
  try {
    const decoded = raw.toString("utf8");
    ensure(
      !decoded.includes("\uFFFD"),
      "A live JSON response was not canonical UTF-8.",
    );
    return JSON.parse(decoded) as unknown;
  } catch {
    throw new Error("A live HTTP response did not contain valid JSON.");
  }
}

async function loadRuntimeConfig(
  request: APIRequestContext,
  expected: ExpectedBindings,
): Promise<RuntimeConfig> {
  const url = `${expected.applicationOrigin}/runtime-config.json`;
  const response = await request.get(url, {
    failOnStatusCode: false,
    headers: { Accept: "application/json" },
    maxRedirects: 0,
  });
  ensure(
    response.status() === 200 &&
      response.url() === url &&
      (response.headers()["content-type"] ?? "")
        .toLowerCase()
        .startsWith("application/json") &&
    (response.headers()["cache-control"] ?? "").includes("no-store"),
    "The live runtime configuration violated its HTTP contract.",
  );
  const raw = await response.body();
  ensure(
    raw.length >= 2 &&
      raw.length <= 65_536 &&
      sha256Bytes(raw) === expected.runtimeConfigSha256,
    "The pre-credential runtime configuration is not the sealed raw document.",
  );
  let value: unknown;
  try {
    const decoded = raw.toString("utf8");
    ensure(
      !decoded.includes("\uFFFD"),
      "The live runtime configuration was not canonical UTF-8.",
    );
    value = JSON.parse(decoded) as unknown;
  } catch {
    throw new Error("The live runtime configuration was not valid JSON.");
  }
  return parseRuntimeConfig(value, expected);
}

async function validateBrowserRuntimeConfig(
  response: Response,
  expected: ExpectedBindings,
): Promise<void> {
  const url = `${expected.applicationOrigin}/runtime-config.json`;
  ensure(
    response.request().method() === "GET" &&
      response.status() === 200 &&
      response.url() === url &&
      (response.headers()["content-type"] ?? "")
        .toLowerCase()
        .startsWith("application/json") &&
      (response.headers()["cache-control"] ?? "").includes("no-store"),
    "The browser-consumed runtime configuration violated its HTTP contract.",
  );
  const raw = await response.body();
  ensure(
    raw.length >= 2 &&
      raw.length <= 65_536 &&
      sha256Bytes(raw) === expected.runtimeConfigSha256,
    "The browser did not consume the sealed raw runtime configuration.",
  );
  let value: unknown;
  try {
    const decoded = raw.toString("utf8");
    ensure(
      !decoded.includes("\uFFFD"),
      "The browser runtime configuration was not canonical UTF-8.",
    );
    value = JSON.parse(decoded) as unknown;
  } catch {
    throw new Error("The browser runtime configuration was not valid JSON.");
  }
  parseRuntimeConfig(value, expected);
}

function decodeCanonicalBase64url(
  value: string,
  maximumBytes: number,
  label: string,
): Buffer {
  ensure(
    value.length >= 1 &&
      value.length <= maximumBytes * 2 &&
      /^[A-Za-z0-9_-]+$/u.test(value),
    `${label} is not canonical base64url.`,
  );
  const decoded = Buffer.from(value, "base64url");
  ensure(
    decoded.length >= 1 &&
      decoded.length <= maximumBytes &&
      decoded.toString("base64url") === value,
    `${label} is not canonical base64url.`,
  );
  return decoded;
}

function parseBoundedJsonObject(
  encoded: string,
  maximumBytes: number,
  label: string,
): Record<string, unknown> {
  const decoded = decodeCanonicalBase64url(encoded, maximumBytes, label);
  try {
    const text = decoded.toString("utf8");
    ensure(!text.includes("\uFFFD"), `${label} is not canonical UTF-8.`);
    const value: unknown = JSON.parse(text);
    ensure(isRecord(value), `${label} is not a JSON object.`);
    return value;
  } catch {
    throw new Error(`${label} is not a valid JSON object.`);
  }
}

async function loadCognitoJwks(
  request: APIRequestContext,
  expected: ExpectedBindings,
): Promise<CognitoJwks> {
  const url = `${expected.cognitoIssuer}/.well-known/jwks.json`;
  const response = await request.get(url, {
    failOnStatusCode: false,
    headers: { Accept: "application/json" },
    maxRedirects: 0,
  });
  ensure(
    response.status() === 200 &&
      response.url() === url &&
      (response.headers()["content-type"] ?? "")
        .toLowerCase()
        .startsWith("application/json"),
    "The Cognito JWKS endpoint violated its exact HTTPS contract.",
  );
  const raw = await response.body();
  ensure(
    raw.length >= 2 && raw.length <= 65_536,
    "The Cognito JWKS document violated its bounded body contract.",
  );
  let value: unknown;
  try {
    const decoded = raw.toString("utf8");
    ensure(!decoded.includes("\uFFFD"), "The Cognito JWKS was not canonical UTF-8.");
    value = JSON.parse(decoded) as unknown;
  } catch {
    throw new Error("The Cognito JWKS document was not valid JSON.");
  }
  ensure(
    isRecord(value) &&
      hasExactKeys(value, ["keys"]) &&
      Array.isArray(value.keys) &&
      value.keys.length >= 2 &&
      value.keys.length <= 8,
    "The Cognito JWKS document has an invalid bounded schema.",
  );
  const seenKids = new Set<string>();
  const keys = value.keys.map((candidate): CognitoJwk => {
    ensure(
      isRecord(candidate) &&
        hasExactKeys(candidate, ["alg", "e", "kid", "kty", "n", "use"]) &&
        candidate.alg === "RS256" &&
        candidate.e === "AQAB" &&
        typeof candidate.kid === "string" &&
        /^[A-Za-z0-9_+=/-]{8,256}$/u.test(candidate.kid) &&
        candidate.kty === "RSA" &&
        typeof candidate.n === "string" &&
        candidate.use === "sig",
      "A Cognito signing key violates the exact RS256 contract.",
    );
    ensure(
      !seenKids.has(candidate.kid),
      "The Cognito JWKS contains a duplicate signing-key identifier.",
    );
    seenKids.add(candidate.kid);
    ensure(
      decodeCanonicalBase64url(
        candidate.n,
        512,
        "The Cognito RSA modulus",
      ).length === 256,
      "A Cognito signing key is not an exact 2048-bit RSA key.",
    );
    return {
      alg: "RS256",
      e: "AQAB",
      kid: candidate.kid,
      kty: "RSA",
      n: candidate.n,
      use: "sig",
    };
  });
  return {
    keys,
    documentSha256: `sha256:${sha256Bytes(raw)}`,
  };
}

function verifyCognitoJwt(
  token: string,
  jwks: CognitoJwks,
  label: "ID token" | "access token",
): { readonly claims: Record<string, unknown>; readonly kidSha256: string } {
  ensure(
    token.length >= 40 &&
      token.length <= 32_768 &&
      /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token),
    `Cognito returned an invalid ${label} envelope.`,
  );
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  ensure(
    encodedHeader !== undefined &&
      encodedPayload !== undefined &&
      encodedSignature !== undefined,
    `Cognito returned an invalid ${label} envelope.`,
  );
  const header = parseBoundedJsonObject(
    encodedHeader,
    1_024,
    `The Cognito ${label} header`,
  );
  ensure(
    (hasExactKeys(header, ["alg", "kid"]) ||
      hasExactKeys(header, ["alg", "kid", "typ"])) &&
      header.alg === "RS256" &&
      typeof header.kid === "string" &&
      /^[A-Za-z0-9_+=/-]{8,256}$/u.test(header.kid) &&
      (header.typ === undefined || header.typ === "JWT"),
    `The Cognito ${label} header violates the exact RS256 contract.`,
  );
  const matching = jwks.keys.filter((key) => key.kid === header.kid);
  ensure(
    matching.length === 1,
    `The Cognito ${label} does not select exactly one bounded signing key.`,
  );
  const signature = decodeCanonicalBase64url(
    encodedSignature,
    512,
    `The Cognito ${label} signature`,
  );
  ensure(
    signature.length === 256,
    `The Cognito ${label} signature is not an exact RSA-2048 signature.`,
  );
  const key = matching[0]!;
  const verified = verifySignature(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
    createPublicKey({
      format: "jwk",
      key: { e: key.e, kty: key.kty, n: key.n },
    }),
    signature,
  );
  ensure(verified, `The Cognito ${label} RS256 signature is invalid.`);
  return {
    claims: parseBoundedJsonObject(
      encodedPayload,
      16_384,
      `The Cognito ${label} claims`,
    ),
    kidSha256: `sha256:${sha256(key.kid)}`,
  };
}

function exactScopeSet(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 256) return false;
  const scopes = value.split(" ");
  return (
    scopes.length === 3 &&
    new Set(scopes).size === 3 &&
    ["openid", "email", "archon/approve"].every((scope) =>
      scopes.includes(scope),
    )
  );
}

function validateFreshClaims(
  claims: Record<string, unknown>,
  journeyStartedAt: string,
  label: string,
): { readonly authTime: number; readonly issuedAt: number } {
  ensure(
    Number.isSafeInteger(claims.auth_time) &&
      Number.isSafeInteger(claims.iat) &&
      Number.isSafeInteger(claims.exp),
    `The Cognito ${label} timestamps are invalid.`,
  );
  const journeyStartSeconds = Math.floor(Date.parse(journeyStartedAt) / 1000);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const authTime = claims.auth_time as number;
  const issuedAt = claims.iat as number;
  const expiresAt = claims.exp as number;
  ensure(
    authTime >= journeyStartSeconds - 60 &&
      issuedAt >= authTime &&
      issuedAt <= nowSeconds + 60 &&
      expiresAt >= nowSeconds + 60 &&
      expiresAt > issuedAt,
    `The Cognito ${label} is not fresh for this journey.`,
  );
  return { authTime, issuedAt };
}

function validateIdentityClaims(
  idToken: {
    readonly claims: Record<string, unknown>;
    readonly kidSha256: string;
  },
  accessToken: {
    readonly claims: Record<string, unknown>;
    readonly kidSha256: string;
  },
  credentials: ProtectedCredentials,
  expected: ExpectedBindings,
  jwks: CognitoJwks,
  journeyStartedAt: string,
): IdentityEvidence {
  const idClaims = idToken.claims;
  const accessClaims = accessToken.claims;
  ensure(
    typeof idClaims.sub === "string" && UUID.test(idClaims.sub),
    "The Cognito subject claim is invalid.",
  );
  ensure(
    idClaims.email === credentials.username &&
      idClaims.email_verified === false,
    "The Cognito email claims do not bind the protected judge.",
  );
  ensure(
    !Object.prototype.hasOwnProperty.call(
      idClaims,
      "custom:archon_judge_binding",
    ),
    "The Cognito ID token unexpectedly exposed the private lifecycle binding.",
  );
  ensure(
    idClaims.token_use === "id" &&
      idClaims.aud === expected.cognitoClientId &&
      idClaims.iss === expected.cognitoIssuer,
    "The Cognito ID token does not bind the live app client.",
  );
  ensure(
    accessClaims.token_use === "access" &&
      accessClaims.sub === idClaims.sub &&
      accessClaims.iss === expected.cognitoIssuer &&
      accessClaims.client_id === expected.cognitoClientId &&
      exactScopeSet(accessClaims.scope) &&
      Array.isArray(accessClaims["cognito:groups"]) &&
      accessClaims["cognito:groups"].length === 1 &&
      accessClaims["cognito:groups"][0] === "archon-approvers",
    "The Cognito access token does not carry the sole exact approver authority.",
  );
  const idFreshness = validateFreshClaims(
    idClaims,
    journeyStartedAt,
    "ID token",
  );
  const accessFreshness = validateFreshClaims(
    accessClaims,
    journeyStartedAt,
    "access token",
  );
  ensure(
    accessFreshness.authTime === idFreshness.authTime,
    "The ID and access tokens do not bind the same authentication event.",
  );

  const identityDigest = `sha256:${sha256(
    `archon-judge-identity-v1\u0000${credentials.accountId}`,
  )}`;
  const cognitoSubjectDigest = `sha256:${sha256(
    `archon-cognito-subject-v1\u0000${idClaims.sub}`,
  )}`;
  ensure(
    identityDigest === expected.identityDigest &&
      cognitoSubjectDigest === expected.cognitoSubjectDigest,
    "The live Cognito identity does not match the upstream lifecycle evidence.",
  );
  return {
    identityDigest,
    cognitoSubjectDigest,
    authenticatedAt: new Date(idFreshness.authTime * 1000).toISOString(),
    issuedAt: new Date(idFreshness.issuedAt * 1000).toISOString(),
    issuerSha256: `sha256:${sha256(expected.cognitoIssuer)}`,
    jwksSha256: jwks.documentSha256,
    idTokenKidSha256: idToken.kidSha256,
    accessTokenKidSha256: accessToken.kidSha256,
  };
}

async function inspectTokenResponse(
  response: Response,
  credentials: ProtectedCredentials,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
  jwks: CognitoJwks,
  journeyStartedAt: string,
): Promise<AuthenticatedSession> {
  const value = await responseJson(
    response,
    200,
    runtime.auth.tokenEndpoint,
  );
  ensure(isRecord(value), "The Cognito token response has an invalid schema.");
  ensure(
    Object.keys(value).every((key) =>
      [
        "access_token",
        "expires_in",
        "id_token",
        "refresh_token",
        "scope",
        "token_type",
      ].includes(key),
    ) &&
      typeof value.access_token === "string" &&
      typeof value.id_token === "string" &&
      value.token_type === "Bearer" &&
      Number.isSafeInteger(value.expires_in) &&
      (value.expires_in as number) >= 60 &&
      (value.expires_in as number) <= 86_400 &&
      (value.scope === undefined || exactScopeSet(value.scope)) &&
      (value.refresh_token === undefined ||
        (typeof value.refresh_token === "string" &&
          value.refresh_token.length >= 20 &&
          value.refresh_token.length <= 32_768)),
    "The Cognito token response violates the bounded OAuth contract.",
  );
  let idToken = value.id_token;
  let accessToken = value.access_token;
  try {
    const verifiedIdToken = verifyCognitoJwt(idToken, jwks, "ID token");
    const verifiedAccessToken = verifyCognitoJwt(
      accessToken,
      jwks,
      "access token",
    );
    return {
      identity: validateIdentityClaims(
        verifiedIdToken,
        verifiedAccessToken,
        credentials,
        expected,
        jwks,
        journeyStartedAt,
      ),
      accessToken,
    };
  } finally {
    for (const key of ["access_token", "id_token", "refresh_token"]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) value[key] = "";
    }
    idToken = "";
    accessToken = "";
  }
}

function validateAuthorizationRequest(
  request: Request,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
): AuthorizationRequestEvidence {
  const url = new URL(request.url());
  ensure(
    request.method() === "GET" &&
      request.isNavigationRequest() &&
      `${url.origin}${url.pathname}` === runtime.auth.authorizationEndpoint &&
      url.hash === "" &&
      hasExactSearchKeys(url.searchParams, [
        "client_id",
        "code_challenge",
        "code_challenge_method",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
      ]),
    "The Cognito authorization request violated the exact PKCE route contract.",
  );
  const state = url.searchParams.get("state")!;
  const codeChallenge = url.searchParams.get("code_challenge")!;
  ensure(
    url.searchParams.get("response_type") === "code" &&
      url.searchParams.get("client_id") === expected.cognitoClientId &&
      url.searchParams.get("redirect_uri") === runtime.auth.redirectUri &&
      url.searchParams.get("scope") === runtime.auth.scopes.join(" ") &&
      url.searchParams.get("code_challenge_method") === "S256" &&
      /^[A-Za-z0-9_-]{43}$/u.test(state) &&
      /^[A-Za-z0-9_-]{43}$/u.test(codeChallenge),
    "The Cognito authorization request did not bind the sealed client and S256 transaction.",
  );
  return {
    state,
    codeChallenge,
    digest: digest({
      clientIdSha256: `sha256:${sha256(expected.cognitoClientId)}`,
      codeChallengeSha256: `sha256:${sha256(codeChallenge)}`,
      redirectUriSha256: `sha256:${sha256(runtime.auth.redirectUri)}`,
      scopeSha256: `sha256:${sha256(runtime.auth.scopes.join(" "))}`,
      stateSha256: `sha256:${sha256(state)}`,
    }),
  };
}

function validateAuthorizationCallback(
  request: Request,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
  transaction: AuthorizationRequestEvidence,
): CallbackRequestEvidence {
  const url = new URL(request.url());
  const prior = request.redirectedFrom();
  const code = url.searchParams.get("code")!;
  ensure(
    request.method() === "GET" &&
      request.isNavigationRequest() &&
      `${url.origin}${url.pathname}` === runtime.auth.redirectUri &&
      url.hash === "" &&
      hasBoundedAuthorizationCallbackQuery(url, expected.cognitoIssuer) &&
      url.searchParams.get("state") === transaction.state &&
      prior !== null &&
      new URL(prior.url()).origin === expected.cognitoHostedUiOrigin,
    "The Cognito authorization callback did not bind the exact state, code, issuer, and redirect.",
  );
  return {
    code,
    digest: digest({
      codeSha256: `sha256:${sha256(code)}`,
      issuerSha256: `sha256:${sha256(expected.cognitoIssuer)}`,
      redirectUriSha256: `sha256:${sha256(runtime.auth.redirectUri)}`,
      stateSha256: `sha256:${sha256(transaction.state)}`,
    }),
  };
}

async function validateTokenRequest(
  request: Request,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
  transaction: AuthorizationRequestEvidence,
  callback: CallbackRequestEvidence,
): Promise<string> {
  const [authorization, contentType, cookie, origin, referer, allHeaders] =
    await Promise.all([
      request.headerValue("authorization"),
      request.headerValue("content-type"),
      request.headerValue("cookie"),
      request.headerValue("origin"),
      request.headerValue("referer"),
      request.allHeaders(),
    ]);
  const encoded = request.postData();
  ensure(
    request.method() === "POST" &&
      !request.isNavigationRequest() &&
      request.url() === runtime.auth.tokenEndpoint &&
      authorization === null &&
      allHeaders.authorization === undefined &&
      cookie === null &&
      allHeaders.cookie === undefined &&
      contentType === "application/x-www-form-urlencoded" &&
      origin === expected.applicationOrigin &&
      referer === null &&
      typeof encoded === "string" &&
      encoded.length >= 64 &&
      encoded.length <= 8_192,
    "The Cognito token request violated its exact browser transport contract.",
  );
  const form = new URLSearchParams(encoded);
  ensure(
    hasExactSearchKeys(form, [
      "client_id",
      "code",
      "code_verifier",
      "grant_type",
      "redirect_uri",
    ]),
    "The Cognito token request contained an unexpected form field.",
  );
  const verifier = form.get("code_verifier")!;
  ensure(
    form.get("grant_type") === "authorization_code" &&
      form.get("client_id") === expected.cognitoClientId &&
      form.get("redirect_uri") === runtime.auth.redirectUri &&
      form.get("code") === callback.code &&
      /^[A-Za-z0-9_-]{86}$/u.test(verifier) &&
      createHash("sha256").update(verifier, "ascii").digest("base64url") ===
        transaction.codeChallenge,
    "The Cognito token request did not bind the callback code and S256 verifier.",
  );
  return digest({
    codeSha256: `sha256:${sha256(callback.code)}`,
    codeVerifierSha256: `sha256:${sha256(verifier)}`,
    tokenEndpointSha256: `sha256:${sha256(runtime.auth.tokenEndpoint)}`,
  });
}

async function validateLogoutRedirect(
  logoutRequest: Request,
  returnRequest: Request,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
): Promise<string> {
  const url = new URL(logoutRequest.url());
  const response = await logoutRequest.response();
  const returnResponse = await returnRequest.response();
  ensure(
    logoutRequest.method() === "GET" &&
      logoutRequest.isNavigationRequest() &&
      `${url.origin}${url.pathname}` === runtime.auth.logoutEndpoint &&
      url.hash === "" &&
      hasExactSearchKeys(url.searchParams, ["client_id", "logout_uri"]) &&
      url.searchParams.get("client_id") === expected.cognitoClientId &&
      url.searchParams.get("logout_uri") === runtime.auth.logoutUri &&
      response !== null &&
      response.status() === 302 &&
      response.url() === logoutRequest.url() &&
      response.headers().location === runtime.auth.logoutUri &&
      logoutRequest.redirectedTo() === returnRequest &&
      returnRequest.redirectedFrom() === logoutRequest &&
      returnRequest.redirectedTo() === null &&
      returnRequest.method() === "GET" &&
      returnRequest.isNavigationRequest() &&
      returnRequest.url() === runtime.auth.logoutUri &&
      returnResponse !== null &&
      returnResponse.status() === 200 &&
      returnResponse.url() === runtime.auth.logoutUri,
    "The Cognito logout request did not produce the exact application-root redirect chain.",
  );
  return digest({
    clientIdSha256: `sha256:${sha256(expected.cognitoClientId)}`,
    logoutEndpointSha256: `sha256:${sha256(runtime.auth.logoutEndpoint)}`,
    logoutUriSha256: `sha256:${sha256(runtime.auth.logoutUri)}`,
    redirectStatus: response.status(),
  });
}

async function installNetworkBoundary(
  context: BrowserContext,
  expected: ExpectedBindings,
  runtime: RuntimeConfig,
  expectedScope: string,
): Promise<NetworkObservation> {
  const observation: NetworkObservation = {
    startRequests: 0,
    decisionRequests: 0,
    tokenRequests: 0,
    authorizationRequests: 0,
    callbackRequests: 0,
    logoutRequests: 0,
    allowedApplicationRequests: 0,
    allowedHostedUiRequests: 0,
    allowedIssuerRequests: 0,
    unexpectedRequests: 0,
    blockedWebSockets: 0,
    serviceWorkerViolations: 0,
    requestContractValid: true,
    unexpectedMutationRequestEmitted: false,
  };

  context.on("serviceworker", () => {
    observation.serviceWorkerViolations += 1;
    observation.requestContractValid = false;
  });
  await context.routeWebSocket(/.*/u, async (webSocket) => {
    observation.blockedWebSockets += 1;
    observation.requestContractValid = false;
    await webSocket.close({
      code: 1008,
      reason: "Blocked by protected live-browser journey",
    });
  });
  await context.route("**/*", async (route, request) => {
    let url: URL;
    try {
      url = new URL(request.url());
    } catch {
      observation.unexpectedRequests += 1;
      observation.requestContractValid = false;
      await route.abort("blockedbyclient");
      return;
    }
    const method = request.method();
    const safeMethod = ["GET", "HEAD", "OPTIONS"].includes(method);
    if (
      url.protocol !== "https:" ||
      url.username !== "" ||
      url.password !== ""
    ) {
      observation.unexpectedRequests += 1;
      observation.requestContractValid = false;
      if (!safeMethod) observation.unexpectedMutationRequestEmitted = true;
      await route.abort("blockedbyclient");
      return;
    }

    if (url.origin === expected.applicationOrigin) {
      observation.allowedApplicationRequests += 1;
      const authorizationCallback =
        method === "GET" &&
        url.pathname === "/" &&
        url.hash === "" &&
        hasBoundedAuthorizationCallbackQuery(url, expected.cognitoIssuer);
      if (authorizationCallback) {
        observation.callbackRequests += 1;
      }
      const staticApplicationRead =
        method === "GET" &&
        url.search === "" &&
        url.hash === "" &&
        (url.pathname === "/" ||
          url.pathname === "/favicon.ico" ||
          url.pathname === "/runtime-config.json" ||
          /^\/assets\/[A-Za-z0-9][A-Za-z0-9._-]{0,240}\.(?:css|js|png|svg|woff2)$/u.test(
            url.pathname,
          ));
      if (authorizationCallback || staticApplicationRead) {
        await route.continue();
        return;
      }
      if (
        method === "GET" &&
        /^\/api\/control-loops\/[a-f0-9]{64}$/u.test(url.pathname) &&
        url.search === "" &&
        url.hash === ""
      ) {
        await route.continue();
        return;
      }
      if (
        method === "POST" &&
        url.pathname === "/api/control-loops" &&
        url.search === "" &&
        url.hash === ""
      ) {
        observation.startRequests += 1;
        try {
          const body: unknown = request.postDataJSON();
          observation.requestContractValid =
            observation.requestContractValid &&
            isRecord(body) &&
            hasExactKeys(body, ["query"]) &&
            body.query === expectedScope;
        } catch {
          observation.requestContractValid = false;
        }
        await route.continue();
        return;
      }
      if (
        method === "POST" &&
        /^\/api\/approvals\/[A-Za-z0-9._%:-]{8,480}\/decisions$/u.test(
          url.pathname,
        ) &&
        url.search === "" &&
        url.hash === ""
      ) {
        observation.decisionRequests += 1;
        await route.continue();
        return;
      }
      observation.unexpectedRequests += 1;
      observation.requestContractValid = false;
      if (!safeMethod) observation.unexpectedMutationRequestEmitted = true;
      await route.abort("blockedbyclient");
      return;
    }

    if (url.origin === expected.cognitoHostedUiOrigin) {
      observation.allowedHostedUiRequests += 1;
      const hostedUiRead =
        method === "GET" &&
        (
          [
            "/error",
            "/favicon.ico",
            "/login",
            "/logout",
            "/oauth2/authorize",
            "/oauth2/idpresponse",
          ].includes(url.pathname) ||
          /^\/(?:css|js|static)\/[A-Za-z0-9][A-Za-z0-9._/-]{0,480}$/u.test(
            url.pathname,
          )
        );
      if (hostedUiRead) {
        if (url.pathname === "/oauth2/authorize") {
          observation.authorizationRequests += 1;
        } else if (url.pathname === "/logout") {
          observation.logoutRequests += 1;
        }
        await route.continue();
        return;
      }
      if (
        method === "POST" &&
        url.pathname === "/oauth2/token" &&
        url.search === "" &&
        url.hash === "" &&
        request.url() === runtime.auth.tokenEndpoint
      ) {
        observation.tokenRequests += 1;
        await route.continue();
        return;
      }
      if (
        method === "POST" &&
        ["/login", "/oauth2/authorize", "/oauth2/idpresponse"].includes(
          url.pathname,
        )
      ) {
        await route.continue();
        return;
      }
      observation.unexpectedRequests += 1;
      observation.requestContractValid = false;
      observation.unexpectedMutationRequestEmitted = true;
      await route.abort("blockedbyclient");
      return;
    }

    if (url.origin === new URL(expected.cognitoIssuer).origin) {
      observation.allowedIssuerRequests += 1;
      if (
        method === "GET" &&
        request.url() === `${expected.cognitoIssuer}/.well-known/jwks.json`
      ) {
        await route.continue();
        return;
      }
      observation.unexpectedRequests += 1;
      observation.requestContractValid = false;
      if (!safeMethod) observation.unexpectedMutationRequestEmitted = true;
      await route.abort("blockedbyclient");
      return;
    }

    observation.unexpectedRequests += 1;
    observation.requestContractValid = false;
    if (!safeMethod) observation.unexpectedMutationRequestEmitted = true;
    await route.abort("blockedbyclient");
  });
  return observation;
}

async function validateDecisionRequest(
  request: Request,
  expectedUrl: string,
  accessToken: string,
): Promise<string> {
  ensure(
    request.method() === "POST" && request.url() === expectedUrl,
    "The captured rejection request violated its exact route contract.",
  );
  let body: unknown;
  try {
    body = request.postDataJSON();
  } catch {
    throw new Error("The captured rejection request was not valid JSON.");
  }
  const [authorization, idempotencyKey, allHeaders] = await Promise.all([
    request.headerValue("authorization"),
    request.headerValue("idempotency-key"),
    request.allHeaders(),
  ]);
  ensure(
    isRecord(body) &&
      hasExactKeys(body, ["decision"]) &&
      body.decision === "REJECT" &&
      accessToken.length >= 40 &&
      authorization === `Bearer ${accessToken}` &&
      allHeaders.authorization === authorization &&
      typeof idempotencyKey === "string" &&
      UUID.test(idempotencyKey) &&
      allHeaders["idempotency-key"] === idempotencyKey,
    "The rejection request did not carry the exact verified-token contract.",
  );
  return digest({
    body: { decision: "REJECT" },
    idempotencyKeySha256: `sha256:${sha256(idempotencyKey)}`,
    pathSha256: `sha256:${sha256(new URL(expectedUrl).pathname)}`,
  });
}

async function parseStartResponse(
  response: Response,
  applicationOrigin: string,
): Promise<StartProjection> {
  const value = await responseJson(
    response,
    202,
    `${applicationOrigin}/api/control-loops`,
  );
  ensure(
    isRecord(value) &&
      hasExactKeys(value, [
        "schemaVersion",
        "auditId",
        "status",
        "pollUrl",
        "submittedAt",
      ]) &&
      value.schemaVersion === "archon.control-loop-start/v1" &&
      typeof value.auditId === "string" &&
      AUDIT_ID.test(value.auditId) &&
      value.status === "RUNNING" &&
      value.pollUrl === `/api/control-loops/${value.auditId}` &&
      isInstant(value.submittedAt),
    "The live control-loop start response is invalid.",
  );
  ensure(
    response.headers().location === value.pollUrl &&
      response.headers()["retry-after"] === "2",
    "The live control-loop start headers are invalid.",
  );
  return {
    auditId: value.auditId,
    pollUrl: value.pollUrl,
    submittedAt: value.submittedAt,
  };
}

async function fetchStatus(
  request: APIRequestContext,
  applicationOrigin: string,
  start: StartProjection,
): Promise<Record<string, unknown>> {
  const url = `${applicationOrigin}${start.pollUrl}`;
  const response: APIResponse = await request.get(url, {
    failOnStatusCode: false,
    headers: { Accept: "application/json" },
    maxRedirects: 0,
  });
  const value = await responseJson(response, 200, url);
  ensure(
    isRecord(value),
    "The live control-loop status response has an invalid schema.",
  );
  return value;
}

function validateApproval(
  value: unknown,
  expectedStatus: "PENDING" | "DECIDED",
): Record<string, unknown> {
  ensure(
    isRecord(value) &&
      hasExactKeys(
        value,
        expectedStatus === "PENDING"
          ? [
              "approvalId",
              "status",
              "expiresAt",
              "planDigest",
              "evidenceDigest",
            ]
          : [
              "approvalId",
              "status",
              "expiresAt",
              "planDigest",
              "evidenceDigest",
              "decision",
            ],
      ) &&
      typeof value.approvalId === "string" &&
      /^[A-Za-z0-9._:-]{8,160}$/u.test(value.approvalId) &&
      value.status === expectedStatus &&
      isInstant(value.expiresAt) &&
      typeof value.planDigest === "string" &&
      DIGEST.test(value.planDigest) &&
      typeof value.evidenceDigest === "string" &&
      DIGEST.test(value.evidenceDigest) &&
      (expectedStatus === "PENDING"
        ? value.decision === undefined
        : value.decision === "REJECT"),
    "The live approval projection is invalid.",
  );
  return value;
}

function validateReportBinding(
  value: unknown,
  releaseSha: unknown,
  approvalId: string,
  expectedReleaseSha: string,
): string {
  ensure(
    releaseSha === expectedReleaseSha &&
      isRecord(value) &&
      value.schemaVersion === "archon.audit-report/v1" &&
      typeof value.scanId === "string" &&
      Array.isArray(value.findings),
    "The live report is not bound to the expected release.",
  );
  const matching = value.findings.filter(
    (finding) =>
      isRecord(finding) &&
      isRecord(finding.detail) &&
      finding.detail.ruleId === "G6" &&
      isRecord(finding.detail.approval) &&
      finding.detail.approval.approvalId === approvalId,
  );
  ensure(
    matching.length === 1,
    "The live report does not contain one exact approval-bound G6 finding.",
  );
  return digest(value as unknown as Json);
}

function validateAwaitingStatus(
  value: Record<string, unknown>,
  start: StartProjection,
  expectedReleaseSha: string,
): AwaitingProjection {
  ensure(
    hasExactKeys(value, [
      "schemaVersion",
      "auditId",
      "status",
      "submittedAt",
      "updatedAt",
      "releaseSha",
      "report",
      "approval",
    ]) &&
      value.schemaVersion === "archon.control-loop-status/v1" &&
      value.auditId === start.auditId &&
      value.status === "AWAITING_APPROVAL" &&
      isInstant(value.submittedAt) &&
      Date.parse(value.submittedAt) >= Date.parse(start.submittedAt) &&
      Date.parse(value.submittedAt) - Date.parse(start.submittedAt) <= 60_000 &&
      isInstant(value.updatedAt),
    "The live audit did not expose one exact awaiting-approval projection.",
  );
  const approval = validateApproval(value.approval, "PENDING");
  const approvalId = approval.approvalId as string;
  return {
    auditId: start.auditId,
    approvalId,
    releaseSha: expectedReleaseSha,
    reportSha256: validateReportBinding(
      value.report,
      value.releaseSha,
      approvalId,
      expectedReleaseSha,
    ),
    submittedAt: value.submittedAt,
  };
}

async function validateDecisionAck(
  response: Response,
  applicationOrigin: string,
  approvalId: string,
): Promise<{
  readonly digest: string;
  readonly disposition:
    | "recorded"
    | "already_recorded"
    | "recorded_callback_closed"
    | "callback_delivery_in_progress";
  readonly statusCode: 200 | 202;
}> {
  const url = `${applicationOrigin}/api/approvals/${encodeURIComponent(
    approvalId,
  )}/decisions`;
  const statusCode = response.status();
  const value = await responseJson(response, [200, 202], url);
  ensure(
    isRecord(value) &&
      hasExactKeys(value, [
        "approvalId",
        "decision",
        "status",
        "decisionId",
        "disposition",
      ]) &&
      value.approvalId === approvalId &&
      value.decision === "REJECT" &&
      value.status === "recorded" &&
      typeof value.decisionId === "string" &&
      DIGEST.test(value.decisionId) &&
      ((statusCode === 200 &&
        (value.disposition === "recorded" ||
          value.disposition === "already_recorded")) ||
        (statusCode === 202 &&
          (value.disposition === "recorded_callback_closed" ||
            value.disposition === "callback_delivery_in_progress"))),
    "The live rejection acknowledgement is invalid.",
  );
  ensure(
    (response.headers()["cache-control"] ?? "").includes("no-store"),
    "The live rejection acknowledgement is not marked no-store.",
  );
  return {
    digest: digest(value as unknown as Json),
    disposition: value.disposition,
    statusCode,
  };
}

function validateTerminalStatus(
  value: Record<string, unknown>,
  start: StartProjection,
  awaiting: AwaitingProjection,
  expectedReleaseSha: string,
): TerminalProjection {
  ensure(
    hasExactKeys(value, [
      "schemaVersion",
      "auditId",
      "status",
      "submittedAt",
      "updatedAt",
      "completedAt",
      "releaseSha",
      "report",
      "approval",
      "result",
    ]) &&
      value.schemaVersion === "archon.control-loop-status/v1" &&
      value.auditId === start.auditId &&
      value.status === "SUCCEEDED" &&
      value.submittedAt === awaiting.submittedAt &&
      isInstant(value.updatedAt) &&
      isInstant(value.completedAt) &&
      Date.parse(value.completedAt) >= Date.parse(start.submittedAt),
    "The live audit terminal status is invalid.",
  );
  const approval = validateApproval(value.approval, "DECIDED");
  ensure(
    approval.approvalId === awaiting.approvalId,
    "The terminal approval is not bound to the awaiting projection.",
  );
  const reportSha256 = validateReportBinding(
    value.report,
    value.releaseSha,
    awaiting.approvalId,
    expectedReleaseSha,
  );
  ensure(
    reportSha256 === awaiting.reportSha256,
    "The live report changed across the approval boundary.",
  );
  const result = value.result;
  ensure(
    isRecord(result) &&
      hasExactKeys(result, [
        "outcome",
        "receiptDigest",
        "executionEvidenceDigest",
        "completedAt",
        "verification",
      ]) &&
      result.outcome === "REJECTED" &&
      typeof result.receiptDigest === "string" &&
      DIGEST.test(result.receiptDigest) &&
      typeof result.executionEvidenceDigest === "string" &&
      DIGEST.test(result.executionEvidenceDigest) &&
      isInstant(result.completedAt) &&
      isRecord(result.verification) &&
      hasExactKeys(result.verification, [
        "checks",
        "eventCount",
        "rollbackAvailability",
      ]) &&
      Array.isArray(result.verification.checks) &&
      result.verification.checks.length === 0 &&
      result.verification.eventCount === 5 &&
      result.verification.rollbackAvailability === "NOT_APPLICABLE",
    "The live rejection terminal proof is invalid.",
  );
  return {
    schemaVersion: "archon.control-loop-terminal-public-projection/v1",
    status: "SUCCEEDED",
    releaseSha: expectedReleaseSha,
    approvalDecision: "REJECT",
    outcome: "REJECTED",
    completedAt: result.completedAt,
    receiptDigest: result.receiptDigest,
    executionEvidenceDigest: result.executionEvidenceDigest,
    reportSha256,
    verification: {
      checkCount: 0,
      eventCount: 5,
      rollbackAvailability: "NOT_APPLICABLE",
    },
  };
}

function validateOutputDirectory(
  configured: string,
  projectOutputDirectory: string,
): string {
  const runnerTemp = requiredEnvironment("RUNNER_TEMP");
  ensure(
    path.isAbsolute(runnerTemp) &&
      path.isAbsolute(configured) &&
      path.resolve(runnerTemp) === runnerTemp &&
      path.resolve(configured) === configured &&
      path.dirname(configured) === runnerTemp &&
      path.resolve(projectOutputDirectory) === configured,
    "The live receipt output path escaped its configured RUNNER_TEMP child.",
  );
  const runnerStat = lstatSync(runnerTemp);
  const configuredStat = lstatSync(configured);
  ensure(
    runnerStat.isDirectory() &&
      !runnerStat.isSymbolicLink() &&
      configuredStat.isDirectory() &&
      !configuredStat.isSymbolicLink() &&
      realpathSync(runnerTemp) === runnerTemp &&
      realpathSync(configured) === configured &&
      path.dirname(realpathSync(configured)) === realpathSync(runnerTemp),
    "The live receipt output directory is not symlink-free.",
  );
  ensure(
    readdirSync(configured).length === 0,
    "The protected live-browser output directory was not fresh at test start.",
  );
  return configured;
}

function bestEffortChmod(target: string, mode: number): void {
  try {
    chmodSync(target, mode);
  } catch {
    // GitHub-hosted filesystems support POSIX permissions. Other runners still
    // retain the no-overwrite and exact-parent guarantees.
  }
}

function atomicWriteNoReplace(
  directory: string,
  filename: string,
  body: string,
): string {
  const target = path.join(directory, filename);
  const temporary = path.join(directory, `.${filename}.${process.pid}.tmp`);
  bestEffortChmod(directory, 0o700);
  ensure(
    path.dirname(target) === directory &&
      path.dirname(temporary) === directory &&
      !existsSync(target),
    "The canonical live-browser receipt already exists.",
  );

  let descriptor: number | undefined;
  try {
    descriptor = openSync(temporary, "wx", 0o600);
    writeFileSync(descriptor, body, { encoding: "utf8" });
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    bestEffortChmod(temporary, 0o600);
    // A same-directory hard link is atomic and fails with EEXIST instead of
    // replacing a prior canonical receipt.
    linkSync(temporary, target);
    bestEffortChmod(target, 0o600);
    try {
      const directoryDescriptor = openSync(directory, constants.O_RDONLY);
      try {
        fsyncSync(directoryDescriptor);
      } finally {
        closeSync(directoryDescriptor);
      }
    } catch {
      // Directory fsync is unavailable on some otherwise supported filesystems.
    }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
    if (existsSync(temporary)) unlinkSync(temporary);
  }

  const written = lstatSync(target);
  ensure(
    written.isFile() && !written.isSymbolicLink(),
    "The canonical live-browser receipt is not a regular file.",
  );
  return target;
}

function hostedCredentialInputs(page: Page) {
  return {
    username: page
      .locator(
        'input[name="username"]:visible, input#signInFormUsername:visible, input[type="email"]:visible',
      )
      .first(),
    password: page
      .locator(
        'input[name="password"]:visible, input#signInFormPassword:visible, input[type="password"]:visible',
      )
      .first(),
  };
}

test("rejects one protected live proposal and seals a sanitized journey receipt", async ({
  browser,
  page,
  request,
}, testInfo) => {
  const expected = parseExpectedBindings();
  const outputDirectory = validateOutputDirectory(
    expected.outputDirectory,
    testInfo.project.outputDir,
  );
  const journeyStartedAt = new Date().toISOString();
  const runtime = await loadRuntimeConfig(request, expected);
  const jwks = await loadCognitoJwks(request, expected);
  const observation = await installNetworkBoundary(
    page.context(),
    expected,
    runtime,
    runtime.demoQuery,
  );
  let identity: IdentityEvidence | undefined;
  let verifiedAccessToken = "";
  let authorizationRequestSha256: string | undefined;
  let authorizationCallbackSha256: string | undefined;
  let tokenRequestSha256: string | undefined;
  let logoutRedirectSha256: string | undefined;
  let postLogoutAuthorizationRequestSha256: string | undefined;
  const browserRuntimeResponsePromise = page.waitForResponse(
    (response) =>
      response.url() === `${expected.applicationOrigin}/runtime-config.json` &&
      response.request().method() === "GET",
    { timeout: 30_000 },
  );
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await validateBrowserRuntimeConfig(
    await browserRuntimeResponsePromise,
    expected,
  );
  let credentials = consumeProtectedCredentials();
  try {
    const signIn = page.getByRole("button", { name: "Steward sign in" });
    await expect(signIn).toBeVisible();
    const authorizationRequestPromise = page.context().waitForEvent("request", {
      predicate: (candidate) =>
        candidate.method() === "GET" &&
        candidate.url().startsWith(`${runtime.auth.authorizationEndpoint}?`),
      timeout: 30_000,
    });
    await signIn.click();
    const authorization = validateAuthorizationRequest(
      await authorizationRequestPromise,
      expected,
      runtime,
    );
    authorizationRequestSha256 = authorization.digest;

    const hostedInputs = hostedCredentialInputs(page);
    await hostedInputs.username.waitFor({
      state: "visible",
      timeout: 30_000,
    });
    await hostedInputs.password.waitFor({
      state: "visible",
      timeout: 30_000,
    });
    ensure(
      new URL(page.url()).origin === expected.cognitoHostedUiOrigin,
      "The browser did not reach the exact sealed Cognito Hosted UI.",
    );
    await hostedInputs.username.fill(credentials.username);
    await hostedInputs.password.fill(credentials.password);

    const tokenResponsePromise = page.waitForResponse(
      (response) =>
        response.url() === runtime.auth.tokenEndpoint &&
        response.request().method() === "POST",
      { timeout: 45_000 },
    );
    const callbackRequestPromise = page.context().waitForEvent("request", {
      predicate: (candidate) => {
        if (candidate.method() !== "GET") return false;
        try {
          const url = new URL(candidate.url());
          return (
            `${url.origin}${url.pathname}` === runtime.auth.redirectUri &&
            url.searchParams.has("code") &&
            url.searchParams.has("state")
          );
        } catch {
          return false;
        }
      },
      timeout: 45_000,
    });
    const hostedSubmit = page
      .locator(
        'input[name="signInSubmitButton"]:visible, button[type="submit"]:visible, input[type="submit"]:visible',
      )
      .first();
    await hostedSubmit.waitFor({ state: "visible", timeout: 30_000 });
    await hostedSubmit.click();
    let callback: CallbackRequestEvidence | undefined;
    try {
      callback = validateAuthorizationCallback(
        await callbackRequestPromise,
        expected,
        runtime,
        authorization,
      );
      authorizationCallbackSha256 = callback.digest;
      const tokenResponse = await tokenResponsePromise;
      tokenRequestSha256 = await validateTokenRequest(
        tokenResponse.request(),
        expected,
        runtime,
        authorization,
        callback,
      );
      const authenticated = await inspectTokenResponse(
        tokenResponse,
        credentials,
        expected,
        runtime,
        jwks,
        journeyStartedAt,
      );
      identity = authenticated.identity;
      verifiedAccessToken = authenticated.accessToken;
      authenticated.accessToken = "";
    } finally {
      authorization.state = "";
      authorization.codeChallenge = "";
      if (callback !== undefined) callback.code = "";
    }
    await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible({
      timeout: 30_000,
    });
  } finally {
    credentials.username = "";
    credentials.password = "";
    credentials.accountId = "";
  }
  ensure(
    identity !== undefined &&
      verifiedAccessToken.length >= 40 &&
      authorizationRequestSha256 !== undefined &&
      authorizationCallbackSha256 !== undefined &&
      tokenRequestSha256 !== undefined &&
      observation.tokenRequests === 1 &&
      SECRET_ENVIRONMENT_KEYS.every((key) => process.env[key] === undefined),
    "The protected sign-in did not consume exactly one scrubbed credential set.",
  );

  const scopeInput = page.getByLabel(
    "Scope audit by asset, domain, or platform",
  );
  ensure(
    (await scopeInput.inputValue()) === runtime.demoQuery,
    "The live audit did not use the prefilled narrow runtime scope.",
  );
  const startResponsePromise = page.waitForResponse(
    (response) =>
      response.url() === `${expected.applicationOrigin}/api/control-loops` &&
      response.request().method() === "POST",
    { timeout: 30_000 },
  );
  await page.getByRole("button", { name: "Run audit" }).click();
  const start = await parseStartResponse(
    await startResponsePromise,
    expected.applicationOrigin,
  );

  await expect(
    page.getByRole("button", { name: "Awaiting steward approval" }),
  ).toBeVisible({ timeout: 180_000 });
  const awaiting = validateAwaitingStatus(
    await fetchStatus(request, expected.applicationOrigin, start),
    start,
    expected.releaseSha,
  );
  const g6Finding = page
    .getByRole("list", { name: "Audit findings" })
    .getByRole("button")
    .filter({ hasText: /\bG6\b/u });
  ensure(
    (await g6Finding.count()) === 1,
    "The browser did not render one exact approval-bound G6 finding.",
  );
  await g6Finding.click();
  const reject = page.getByRole("button", { name: "Reject proposal" });
  await expect(reject).toBeVisible();
  ensure(
    await reject.isEnabled(),
    "The authenticated rejection control remained locked.",
  );

  const decisionUrl = `${expected.applicationOrigin}/api/approvals/${encodeURIComponent(
    awaiting.approvalId,
  )}/decisions`;
  const decisionRequestPromise = page.context().waitForEvent("request", {
    predicate: (request) =>
      request.url() === decisionUrl && request.method() === "POST",
    timeout: 30_000,
  });
  const decisionResponsePromise = page.waitForResponse(
    (response) =>
      response.url() === decisionUrl &&
      response.request().method() === "POST",
    { timeout: 30_000 },
  );
  let decisionRequestSha256: string | undefined;
  let decisionAck:
    | Awaited<ReturnType<typeof validateDecisionAck>>
    | undefined;
  try {
    await reject.click();
    const decisionRequest = await decisionRequestPromise;
    decisionRequestSha256 = await validateDecisionRequest(
      decisionRequest,
      decisionUrl,
      verifiedAccessToken,
    );
    decisionAck = await validateDecisionAck(
      await decisionResponsePromise,
      expected.applicationOrigin,
      awaiting.approvalId,
    );
  } finally {
    verifiedAccessToken = "";
  }
  ensure(
    decisionAck !== undefined && decisionRequestSha256 !== undefined,
    "The live rejection request or acknowledgement evidence is missing.",
  );
  await expect(page.getByText(/^Rejection recorded\./u)).toBeVisible();

  await expect(page.getByTestId("terminal-evidence")).toBeVisible({
    timeout: 120_000,
  });
  const terminal = validateTerminalStatus(
    await fetchStatus(request, expected.applicationOrigin, start),
    start,
    awaiting,
    expected.releaseSha,
  );

  const logoutRequestPromise = page.context().waitForEvent("request", {
    predicate: (candidate) =>
      candidate.method() === "GET" &&
      candidate.url().startsWith(`${runtime.auth.logoutEndpoint}?`),
    timeout: 30_000,
  });
  const logoutReturnRequestPromise = page.context().waitForEvent("request", {
    predicate: (candidate) => {
      const prior = candidate.redirectedFrom();
      return (
        candidate.method() === "GET" &&
        candidate.isNavigationRequest() &&
        candidate.url() === runtime.auth.logoutUri &&
        prior !== null &&
        prior.url().startsWith(`${runtime.auth.logoutEndpoint}?`)
      );
    },
    timeout: 45_000,
  });
  await page.getByRole("button", { name: "Sign out" }).click();
  const logoutRequest = await logoutRequestPromise;
  logoutRedirectSha256 = await validateLogoutRedirect(
    logoutRequest,
    await logoutReturnRequestPromise,
    expected,
    runtime,
  );
  await expect(
    page.getByRole("button", { name: "Steward sign in" }),
  ).toBeVisible({ timeout: 45_000 });
  ensure(
    page.url() === `${expected.applicationOrigin}/`,
    "Cognito logout did not return to the exact logged-out application root.",
  );
  const transactionRetained = await page.evaluate(
    () => window.sessionStorage.getItem("archon.auth.pkce.v1") !== null,
  );
  ensure(!transactionRetained, "The PKCE transaction survived logout.");

  const postLogoutAuthorizePromise = page.context().waitForEvent("request", {
    predicate: (candidate) => {
      if (candidate.method() !== "GET") return false;
      try {
        const url = new URL(candidate.url());
        return (
          url.origin === expected.cognitoHostedUiOrigin &&
          url.pathname === "/oauth2/authorize"
        );
      } catch {
        return false;
      }
    },
    timeout: 30_000,
  });
  await page.getByRole("button", { name: "Steward sign in" }).click();
  const postLogoutAuthorization = validateAuthorizationRequest(
    await postLogoutAuthorizePromise,
    expected,
    runtime,
  );
  postLogoutAuthorizationRequestSha256 = postLogoutAuthorization.digest;
  postLogoutAuthorization.state = "";
  postLogoutAuthorization.codeChallenge = "";
  const postLogoutInputs = hostedCredentialInputs(page);
  await postLogoutInputs.username.waitFor({
    state: "visible",
    timeout: 30_000,
  });
  await postLogoutInputs.password.waitFor({
    state: "visible",
    timeout: 30_000,
  });
  ensure(
    new URL(page.url()).origin === expected.cognitoHostedUiOrigin &&
      observation.tokenRequests === 1,
    "The same browser context retained a Cognito session after logout.",
  );
  await page.goto(`${expected.applicationOrigin}/`, {
    waitUntil: "domcontentloaded",
  });
  await page.evaluate(() =>
    window.sessionStorage.removeItem("archon.auth.pkce.v1"),
  );
  ensure(
    (await page.evaluate(
      () => window.sessionStorage.getItem("archon.auth.pkce.v1"),
    )) === null,
    "The post-logout authorize probe left a PKCE transaction behind.",
  );
  await expect(
    page.getByRole("button", { name: "Steward sign in" }),
  ).toBeVisible({ timeout: 30_000 });

  const freshContext = await browser.newContext({
    baseURL: expected.applicationOrigin,
    colorScheme: "dark",
    serviceWorkers: "block",
  });
  try {
    const freshObservation = await installNetworkBoundary(
      freshContext,
      expected,
      runtime,
      runtime.demoQuery,
    );
    const freshPage = await freshContext.newPage();
    const freshRuntimeResponsePromise = freshPage.waitForResponse(
      (response) =>
        response.url() ===
          `${expected.applicationOrigin}/runtime-config.json` &&
        response.request().method() === "GET",
      { timeout: 30_000 },
    );
    await freshPage.goto("/", { waitUntil: "domcontentloaded" });
    await validateBrowserRuntimeConfig(
      await freshRuntimeResponsePromise,
      expected,
    );
    await expect(
      freshPage.getByRole("button", { name: "Steward sign in" }),
    ).toBeVisible({ timeout: 30_000 });
    ensure(
      (await freshPage.getByText("Steward signed in").count()) === 0 &&
        freshObservation.startRequests === 0 &&
        freshObservation.decisionRequests === 0 &&
        freshObservation.tokenRequests === 0 &&
        freshObservation.authorizationRequests === 0 &&
        freshObservation.callbackRequests === 0 &&
        freshObservation.logoutRequests === 0 &&
        freshObservation.unexpectedRequests === 0 &&
        freshObservation.blockedWebSockets === 0 &&
        freshObservation.serviceWorkerViolations === 0 &&
        freshObservation.requestContractValid &&
        !freshObservation.unexpectedMutationRequestEmitted,
      "A fresh browser context inherited authority or violated the network boundary.",
    );
    await freshContext.unrouteAll({ behavior: "wait" });
  } finally {
    await freshContext.close();
  }

  ensure(
    observation.startRequests === 1 &&
      observation.decisionRequests === 1 &&
      observation.tokenRequests === 1 &&
      observation.authorizationRequests === 2 &&
      observation.callbackRequests === 1 &&
      observation.logoutRequests === 1 &&
      observation.allowedApplicationRequests > 0 &&
      observation.allowedHostedUiRequests > 0 &&
      observation.unexpectedRequests === 0 &&
      observation.blockedWebSockets === 0 &&
      observation.serviceWorkerViolations === 0 &&
      observation.requestContractValid &&
      !observation.unexpectedMutationRequestEmitted &&
      verifiedAccessToken === "" &&
      authorizationRequestSha256 !== undefined &&
      authorizationCallbackSha256 !== undefined &&
      tokenRequestSha256 !== undefined &&
      logoutRedirectSha256 !== undefined &&
      postLogoutAuthorizationRequestSha256 !== undefined,
    "The browser-context network boundary did not remain exact and non-mutating.",
  );
  await page.context().unrouteAll({ behavior: "wait" });

  const journeyCompletedAt = new Date().toISOString();
  ensure(
    Date.parse(journeyCompletedAt) >= Date.parse(journeyStartedAt),
    "The live journey timestamps are not monotonic.",
  );
  const terminalPublicProjection = terminal as unknown as Json;
  const receipt: Json = {
    schemaVersion: "archon.browser-judge-journey-receipt/v1",
    bindings: {
      releaseSha: expected.releaseSha,
      applicationOriginSha256: expected.applicationOriginSha256,
      runtimeConfigSha256: `sha256:${expected.runtimeConfigSha256}`,
      cognitoHostedUiOriginSha256: `sha256:${sha256(
        expected.cognitoHostedUiOrigin,
      )}`,
      cognitoClientIdSha256: `sha256:${sha256(expected.cognitoClientId)}`,
      identityDigest: expected.identityDigest,
      lifecycleDigest: expected.lifecycleDigest,
      cognitoSubjectDigest: expected.cognitoSubjectDigest,
    },
    startedAt: journeyStartedAt,
    completedAt: journeyCompletedAt,
    identityAuthenticatedAt: identity.authenticatedAt,
    identityIssuedAt: identity.issuedAt,
    cognitoIssuerSha256: identity.issuerSha256,
    cognitoJwksSha256: identity.jwksSha256,
    idTokenKidSha256: identity.idTokenKidSha256,
    accessTokenKidSha256: identity.accessTokenKidSha256,
    auditScopeSha256: `sha256:${sha256(runtime.demoQuery)}`,
    auditCapabilitySha256: digest({
      auditIdSha256: `sha256:${sha256(start.auditId)}`,
      approvalIdSha256: `sha256:${sha256(awaiting.approvalId)}`,
      pollUrlSha256: `sha256:${sha256(start.pollUrl)}`,
    }),
    oauth: {
      authorizationRequestSha256,
      authorizationCallbackSha256,
      tokenRequestSha256,
      logoutRedirectSha256,
      postLogoutAuthorizationRequestSha256,
    },
    decisionRequestSha256,
    decisionAckSha256: decisionAck.digest,
    decisionAckStatus: decisionAck.statusCode,
    decisionAckDisposition: decisionAck.disposition,
    network: {
      allowedApplicationRequests: observation.allowedApplicationRequests,
      allowedHostedUiRequests: observation.allowedHostedUiRequests,
      allowedIssuerRequests: observation.allowedIssuerRequests,
      startRequests: observation.startRequests,
      decisionRequests: observation.decisionRequests,
      tokenRequests: observation.tokenRequests,
      authorizationRequests: observation.authorizationRequests,
      callbackRequests: observation.callbackRequests,
      logoutRequests: observation.logoutRequests,
      unexpectedRequests: observation.unexpectedRequests,
      blockedWebSockets: observation.blockedWebSockets,
      serviceWorkerViolations: observation.serviceWorkerViolations,
    },
    terminalPublicProjection,
    terminalPublicProjectionSha256: digest(terminalPublicProjection),
    outcome: "REJECTED",
    checks: {
      runtimeConfigRawDigestVerified: true,
      idTokenSignatureVerified: true,
      accessTokenSignatureVerified: true,
      oauthPkceRequestBound: true,
      identityIsFresh: true,
      login: true,
      start: true,
      status: true,
      decisionAck: true,
      terminal: true,
      terminalCapabilityHandoffCreated: true,
      logout: true,
      logoutRedirectChainVerified: true,
      sameContextLogoutProbe: true,
      freshContextLocked: true,
      browserContextOriginAndPathAllowlist: true,
      serviceWorkersBlocked: true,
      webSocketsBlocked: true,
      unexpectedMutationRequestEmitted: false,
      sanitized: true,
      secretMaterialRetained: false,
    },
  };

  const receiptBody = `${canonicalJson(receipt)}\n`;
  const capabilityIssuedAt = new Date().toISOString();
  const capability: Json = {
    schemaVersion: "archon.browser-terminal-observer-capability/v1",
    applicationOrigin: expected.applicationOrigin,
    releaseSha: expected.releaseSha,
    auditId: start.auditId,
    pollUrl: start.pollUrl,
    expectedTerminalPublicProjectionSha256: digest(
      terminalPublicProjection,
    ),
    browserReceiptSha256: `sha256:${sha256(receiptBody)}`,
    issuedAt: capabilityIssuedAt,
    expiresAt: new Date(
      Date.parse(capabilityIssuedAt) + 10 * 60_000,
    ).toISOString(),
    containsCredentialMaterial: false,
    transient: true,
  };
  atomicWriteNoReplace(
    outputDirectory,
    "terminal-observer-capability.json",
    `${canonicalJson(capability)}\n`,
  );
  // The sanitized receipt is the final commit marker. A failed capability
  // write can therefore never leave a receipt that claims a nonexistent
  // observer handoff.
  atomicWriteNoReplace(
    outputDirectory,
    "browser-journey-receipt.json",
    receiptBody,
  );
});
