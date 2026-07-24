const RUNTIME_CONFIG_PATH = "/runtime-config.json";
const TRANSACTION_KEY = "archon.auth.pkce.v1";
const TRANSACTION_TTL_MS = 10 * 60 * 1000;
const TOKEN_EXPIRY_SKEW_MS = 5 * 1000;
const REQUIRED_APPROVAL_SCOPE = "archon/approve";

export interface RuntimeAuthConfig {
  schemaVersion: 1;
  auth: {
    clientId: string;
    authorizationEndpoint: string;
    tokenEndpoint: string;
    logoutEndpoint: string;
    redirectUri: string;
    logoutUri: string;
    scopes: string[];
  };
}

export type AuthSnapshot =
  | { status: "loading" }
  | { status: "anonymous" }
  | { status: "redirecting" }
  | { status: "authenticated"; expiresAt: number }
  | { status: "error"; message: string; recoverable: boolean };

interface PkceTransaction {
  version: 1;
  state: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
}

interface AccessToken {
  value: string;
  expiresAt: number;
}

interface SessionStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface AuthEnvironment {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  currentUrl(): string;
  navigate(url: string): void;
  replaceUrl(url: string): void;
  randomBytes(length: number): Uint8Array;
  sha256(value: Uint8Array): Promise<ArrayBuffer>;
  sessionStorage: SessionStorage;
  now(): number;
  setTimer(callback: () => void, delayMs: number): number;
  clearTimer(handle: number): void;
}

export class AuthError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function parseEndpoint(value: unknown, pathname: string, label: string): URL {
  if (typeof value !== "string" || value.length > 2048) {
    throw new AuthError(`${label} is missing or invalid.`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthError(`${label} is not a valid URL.`);
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== pathname ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new AuthError(`${label} must be an exact HTTPS Cognito endpoint.`);
  }
  return url;
}

function parseAppUri(value: unknown, appOrigin: string, label: string): string {
  if (typeof value !== "string" || value.length > 2048) {
    throw new AuthError(`${label} is missing or invalid.`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthError(`${label} is not a valid URL.`);
  }
  if (
    url.protocol !== "https:" ||
    url.origin !== appOrigin ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.username !== "" ||
    url.password !== ""
  ) {
    throw new AuthError(`${label} must be the hosted application root on this origin.`);
  }
  return url.toString();
}

export function parseRuntimeConfig(value: unknown, appOrigin: string): RuntimeAuthConfig {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["schemaVersion", "auth"]) ||
    value.schemaVersion !== 1 ||
    !isRecord(value.auth) ||
    !hasExactKeys(value.auth, [
      "clientId",
      "authorizationEndpoint",
      "tokenEndpoint",
      "logoutEndpoint",
      "redirectUri",
      "logoutUri",
      "scopes",
    ])
  ) {
    throw new AuthError("Runtime authentication configuration has an invalid schema.");
  }

  const auth = value.auth;
  if (
    typeof auth.clientId !== "string" ||
    !/^[A-Za-z0-9]{8,128}$/.test(auth.clientId)
  ) {
    throw new AuthError("Runtime authentication client ID is invalid.");
  }
  if (
    !Array.isArray(auth.scopes) ||
    auth.scopes.length < 1 ||
    auth.scopes.length > 10 ||
    !auth.scopes.every(
      (scope) =>
        typeof scope === "string" &&
        scope.length >= 1 &&
        scope.length <= 128 &&
        /^[A-Za-z0-9._:/-]+$/.test(scope),
    ) ||
    new Set(auth.scopes).size !== auth.scopes.length ||
    !auth.scopes.includes("openid") ||
    !auth.scopes.includes(REQUIRED_APPROVAL_SCOPE)
  ) {
    throw new AuthError("Runtime authentication scopes are invalid.");
  }

  const authorizationEndpoint = parseEndpoint(
    auth.authorizationEndpoint,
    "/oauth2/authorize",
    "Authorization endpoint",
  );
  const tokenEndpoint = parseEndpoint(auth.tokenEndpoint, "/oauth2/token", "Token endpoint");
  const logoutEndpoint = parseEndpoint(auth.logoutEndpoint, "/logout", "Logout endpoint");
  if (
    tokenEndpoint.origin !== authorizationEndpoint.origin ||
    logoutEndpoint.origin !== authorizationEndpoint.origin
  ) {
    throw new AuthError("Cognito authorization, token, and logout endpoints must share an origin.");
  }

  return {
    schemaVersion: 1,
    auth: {
      clientId: auth.clientId,
      authorizationEndpoint: authorizationEndpoint.toString(),
      tokenEndpoint: tokenEndpoint.toString(),
      logoutEndpoint: logoutEndpoint.toString(),
      redirectUri: parseAppUri(auth.redirectUri, appOrigin, "Redirect URI"),
      logoutUri: parseAppUri(auth.logoutUri, appOrigin, "Logout URI"),
      scopes: [...auth.scopes],
    },
  };
}

function base64Url(value: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let encoded = "";
  for (let offset = 0; offset < value.length; offset += 3) {
    const first = value[offset] ?? 0;
    const second = value[offset + 1];
    const third = value[offset + 2];
    const combined = (first << 16) | ((second ?? 0) << 8) | (third ?? 0);
    encoded += alphabet[(combined >>> 18) & 63];
    encoded += alphabet[(combined >>> 12) & 63];
    if (second !== undefined) encoded += alphabet[(combined >>> 6) & 63];
    if (third !== undefined) encoded += alphabet[combined & 63];
  }
  return encoded;
}

function constantTimeEqual(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function parseTransaction(raw: string | null): PkceTransaction {
  if (raw === null || raw.length > 4096) {
    throw new AuthError("The sign-in transaction is missing or invalid. Start sign-in again.");
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new AuthError("The sign-in transaction is missing or invalid. Start sign-in again.");
  }
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["version", "state", "codeVerifier", "redirectUri", "createdAt"]) ||
    value.version !== 1 ||
    typeof value.state !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.state) ||
    typeof value.codeVerifier !== "string" ||
    !/^[A-Za-z0-9_-]{43,128}$/.test(value.codeVerifier) ||
    typeof value.redirectUri !== "string" ||
    typeof value.createdAt !== "number" ||
    !Number.isSafeInteger(value.createdAt)
  ) {
    throw new AuthError("The sign-in transaction is missing or invalid. Start sign-in again.");
  }
  return value as unknown as PkceTransaction;
}

function safeOAuthMessage(value: unknown): string {
  if (typeof value !== "string") return "Cognito rejected the sign-in request.";
  const normalized = value.replace(/[\u0000-\u001F\u007F]/g, " ").trim().slice(0, 240);
  return normalized || "Cognito rejected the sign-in request.";
}

function cleanCallbackUrl(url: URL): string {
  for (const key of [
    "code",
    "state",
    "error",
    "error_description",
    "error_uri",
    "iss",
    "session_state",
  ]) {
    url.searchParams.delete(key);
  }
  return `${url.pathname}${url.search}${url.hash}`;
}

function hasCallbackParameters(url: URL): boolean {
  return ["code", "state", "error", "error_description"].some((key) =>
    url.searchParams.has(key),
  );
}

function defaultEnvironment(): AuthEnvironment {
  return {
    fetch: (input, init) => globalThis.fetch(input, init),
    currentUrl: () => window.location.href,
    navigate: (url) => window.location.assign(url),
    replaceUrl: (url) => window.history.replaceState(null, "", url),
    randomBytes: (length) => {
      const value = new Uint8Array(length);
      globalThis.crypto.getRandomValues(value);
      return value;
    },
    sha256: (value) => {
      const input = new Uint8Array(value.byteLength);
      input.set(value);
      return globalThis.crypto.subtle.digest("SHA-256", input.buffer);
    },
    sessionStorage: window.sessionStorage,
    now: () => Date.now(),
    setTimer: (callback, delayMs) => window.setTimeout(callback, delayMs),
    clearTimer: (handle) => window.clearTimeout(handle),
  };
}

export class AuthController {
  private readonly environment: AuthEnvironment;
  private readonly listeners = new Set<() => void>();
  private snapshot: AuthSnapshot = { status: "loading" };
  private config?: RuntimeAuthConfig;
  private token?: AccessToken;
  private initialization?: Promise<void>;
  private expiryTimer?: number;

  constructor(environment: AuthEnvironment = defaultEnvironment()) {
    this.environment = environment;
  }

  readonly getSnapshot = (): AuthSnapshot => this.snapshot;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  private publish(snapshot: AuthSnapshot): void {
    this.snapshot = snapshot;
    for (const listener of this.listeners) listener();
  }

  private clearToken(): void {
    this.token = undefined;
    if (this.expiryTimer !== undefined) {
      this.environment.clearTimer(this.expiryTimer);
      this.expiryTimer = undefined;
    }
  }

  private fail(error: unknown): void {
    this.clearToken();
    this.publish({
      status: "error",
      message:
        error instanceof AuthError
          ? error.message
          : "Approval authentication could not be initialized safely.",
      recoverable: this.config !== undefined,
    });
  }

  async initialize(): Promise<void> {
    if (this.initialization) return this.initialization;
    this.initialization = this.initializeOnce().catch((error: unknown) => {
      this.fail(error);
    });
    return this.initialization;
  }

  private async initializeOnce(): Promise<void> {
    const initialUrl = new URL(this.environment.currentUrl());
    if (hasCallbackParameters(initialUrl)) {
      // Remove short-lived OAuth material before the first network request so it
      // cannot escape in a same-origin Referer or remain in browser history.
      this.environment.replaceUrl(cleanCallbackUrl(new URL(initialUrl)));
    }
    const runtimeResponse = await this.environment.fetch(RUNTIME_CONFIG_PATH, {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/json" },
    });
    const contentType = runtimeResponse.headers.get("content-type") ?? "";
    if (
      !runtimeResponse.ok ||
      !contentType.toLowerCase().startsWith("application/json") ||
      runtimeResponse.redirected
    ) {
      throw new AuthError("Approval authentication is unavailable: runtime config was rejected.");
    }
    let rawConfig: unknown;
    try {
      rawConfig = await runtimeResponse.json();
    } catch {
      throw new AuthError("Approval authentication is unavailable: runtime config is not JSON.");
    }
    this.config = parseRuntimeConfig(rawConfig, initialUrl.origin);
    await this.completeCallback(initialUrl);
  }

  private removeTransaction(): void {
    try {
      this.environment.sessionStorage.removeItem(TRANSACTION_KEY);
    } catch {
      // An inaccessible transaction store is handled as a missing transaction
      // during callback validation. Token material is never stored here.
    }
  }

  private readTransaction(): PkceTransaction {
    let raw: string | null;
    try {
      raw = this.environment.sessionStorage.getItem(TRANSACTION_KEY);
    } catch {
      throw new AuthError("The browser blocked the short-lived sign-in transaction.");
    }
    return parseTransaction(raw);
  }

  private async completeCallback(current: URL): Promise<void> {
    const config = this.config;
    if (!config) throw new AuthError("Runtime authentication configuration is unavailable.");

    const code = current.searchParams.getAll("code");
    const state = current.searchParams.getAll("state");
    const oauthError = current.searchParams.getAll("error");
    const oauthDescription = current.searchParams.getAll("error_description");
    const hasCallback =
      code.length > 0 || state.length > 0 || oauthError.length > 0 || oauthDescription.length > 0;
    if (!hasCallback) {
      this.publish({ status: "anonymous" });
      return;
    }

    if (`${current.origin}${current.pathname}` !== config.auth.redirectUri) {
      this.removeTransaction();
      throw new AuthError("The sign-in response arrived on an unexpected callback URI.");
    }
    let transaction: PkceTransaction;
    try {
      transaction = this.readTransaction();
    } finally {
      this.removeTransaction();
    }
    const age = this.environment.now() - transaction.createdAt;
    if (
      age < -60_000 ||
      age > TRANSACTION_TTL_MS ||
      transaction.redirectUri !== config.auth.redirectUri
    ) {
      throw new AuthError("The sign-in transaction expired or no longer matches this deployment.");
    }
    if (state.length !== 1 || !constantTimeEqual(state[0]!, transaction.state)) {
      throw new AuthError("The sign-in response did not match the cryptographic state.");
    }

    if (oauthError.length > 0 || oauthDescription.length > 0) {
      if (oauthError.length !== 1 || code.length !== 0 || oauthDescription.length > 1) {
        throw new AuthError("Cognito returned an invalid OAuth error response.");
      }
      throw new AuthError(safeOAuthMessage(oauthDescription[0] ?? oauthError[0]));
    }
    if (
      code.length !== 1 ||
      code[0]!.length < 8 ||
      code[0]!.length > 4096 ||
      /[\s\u0000-\u001F\u007F]/.test(code[0]!)
    ) {
      throw new AuthError("Cognito returned an invalid authorization code.");
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.auth.clientId,
      code: code[0]!,
      redirect_uri: config.auth.redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    const tokenResponse = await this.environment.fetch(config.auth.tokenEndpoint, {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    const contentType = tokenResponse.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().startsWith("application/json") || tokenResponse.redirected) {
      throw new AuthError("Cognito returned an invalid token response.");
    }
    let tokenPayload: unknown;
    try {
      tokenPayload = await tokenResponse.json();
    } catch {
      throw new AuthError("Cognito returned an invalid token response.");
    }
    if (!tokenResponse.ok) {
      throw new AuthError(
        isRecord(tokenPayload)
          ? safeOAuthMessage(tokenPayload.error_description ?? tokenPayload.error)
          : "Cognito rejected the authorization code.",
      );
    }
    if (
      !isRecord(tokenPayload) ||
      !hasOnlyKeys(tokenPayload, [
        "access_token",
        "token_type",
        "expires_in",
        "scope",
        "id_token",
        "refresh_token",
      ]) ||
      typeof tokenPayload.access_token !== "string" ||
      tokenPayload.access_token.length < 20 ||
      tokenPayload.access_token.length > 16_384 ||
      /[\s\u0000-\u001F\u007F]/.test(tokenPayload.access_token) ||
      tokenPayload.token_type !== "Bearer" ||
      typeof tokenPayload.expires_in !== "number" ||
      !Number.isSafeInteger(tokenPayload.expires_in) ||
      tokenPayload.expires_in < 30 ||
      tokenPayload.expires_in > 86_400 ||
      // OAuth token responses may omit `scope` when it is unchanged from the
      // authorization request. If Cognito does return it, enforce the custom
      // API scope; API Gateway remains the authoritative access-token gate.
      (tokenPayload.scope !== undefined &&
        (typeof tokenPayload.scope !== "string" ||
          tokenPayload.scope.length > 2048 ||
          !/^[A-Za-z0-9._:/-]+(?: [A-Za-z0-9._:/-]+)*$/.test(tokenPayload.scope) ||
          !tokenPayload.scope.split(/\s+/).includes(REQUIRED_APPROVAL_SCOPE))) ||
      (tokenPayload.id_token !== undefined &&
        (typeof tokenPayload.id_token !== "string" ||
          tokenPayload.id_token.length > 16_384 ||
          /[\s\u0000-\u001F\u007F]/.test(tokenPayload.id_token))) ||
      (tokenPayload.refresh_token !== undefined &&
        (typeof tokenPayload.refresh_token !== "string" ||
          tokenPayload.refresh_token.length > 16_384 ||
          /[\s\u0000-\u001F\u007F]/.test(tokenPayload.refresh_token)))
    ) {
      throw new AuthError("Cognito returned an invalid token response contract.");
    }

    const expiresAt = this.environment.now() + tokenPayload.expires_in * 1000;
    this.token = { value: tokenPayload.access_token, expiresAt };
    const delay = Math.max(0, expiresAt - this.environment.now() - TOKEN_EXPIRY_SKEW_MS);
    this.expiryTimer = this.environment.setTimer(() => {
      this.clearToken();
      this.publish({ status: "anonymous" });
    }, delay);
    this.publish({ status: "authenticated", expiresAt });
  }

  async signIn(): Promise<void> {
    await this.initialize();
    const config = this.config;
    if (!config) {
      throw new AuthError("Approval authentication is unavailable for this deployment.");
    }
    this.clearToken();
    try {
      const state = base64Url(this.environment.randomBytes(32));
      const codeVerifier = base64Url(this.environment.randomBytes(64));
      const challenge = base64Url(
        new Uint8Array(
          await this.environment.sha256(new TextEncoder().encode(codeVerifier)),
        ),
      );
      const transaction: PkceTransaction = {
        version: 1,
        state,
        codeVerifier,
        redirectUri: config.auth.redirectUri,
        createdAt: this.environment.now(),
      };
      this.environment.sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify(transaction));

      const authorizationUrl = new URL(config.auth.authorizationEndpoint);
      authorizationUrl.search = new URLSearchParams({
        response_type: "code",
        client_id: config.auth.clientId,
        redirect_uri: config.auth.redirectUri,
        scope: config.auth.scopes.join(" "),
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      }).toString();
      this.publish({ status: "redirecting" });
      this.environment.navigate(authorizationUrl.toString());
    } catch (error) {
      this.removeTransaction();
      this.fail(error);
      throw error;
    }
  }

  signOut(): void {
    const config = this.config;
    this.clearToken();
    this.removeTransaction();
    if (!config) {
      this.publish({
        status: "error",
        message: "Approval authentication is unavailable for this deployment.",
        recoverable: false,
      });
      return;
    }
    this.publish({ status: "anonymous" });
    const logoutUrl = new URL(config.auth.logoutEndpoint);
    logoutUrl.search = new URLSearchParams({
      client_id: config.auth.clientId,
      logout_uri: config.auth.logoutUri,
    }).toString();
    this.environment.navigate(logoutUrl.toString());
  }

  getAccessToken(): string {
    if (
      !this.token ||
      this.environment.now() >= this.token.expiresAt - TOKEN_EXPIRY_SKEW_MS
    ) {
      this.clearToken();
      if (this.config) this.publish({ status: "anonymous" });
      throw new AuthError("The steward session is missing or expired. Sign in again.");
    }
    return this.token.value;
  }
}

const authController = new AuthController();

export const initializeAuthentication = (): Promise<void> => authController.initialize();
export const beginSignIn = (): Promise<void> => authController.signIn();
export const signOut = (): void => authController.signOut();
export const getAccessToken = (): string => authController.getAccessToken();
export const getAuthSnapshot = authController.getSnapshot;
export const subscribeToAuth = authController.subscribe;
