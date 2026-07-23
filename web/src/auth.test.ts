import { describe, expect, it, vi } from "vitest";
import {
  AuthController,
  parseRuntimeConfig,
  type AuthEnvironment,
} from "./auth";

const runtimeConfig = {
  schemaVersion: 1,
  auth: {
    clientId: "5k6exampleclientid9h2",
    authorizationEndpoint: "https://auth.archon.example/oauth2/authorize",
    tokenEndpoint: "https://auth.archon.example/oauth2/token",
    logoutEndpoint: "https://auth.archon.example/logout",
    redirectUri: "https://app.archon.example/",
    logoutUri: "https://app.archon.example/",
    scopes: ["openid", "email", "archon/approve"],
  },
};

function json(value: unknown, status = 200): Response {
  return {
    status,
    ok: status >= 200 && status < 300,
    redirected: false,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-type" ? "application/json" : null,
    },
    json: async () => value,
  } as unknown as Response;
}

interface TestBrowser {
  environment: AuthEnvironment;
  fetchMock: ReturnType<typeof vi.fn>;
  navigate: ReturnType<typeof vi.fn>;
  replaceUrl: ReturnType<typeof vi.fn>;
  storage: Map<string, string>;
}

function testBrowser(
  responses: Response[],
  currentUrl = "https://app.archon.example/",
  initialStorage: Record<string, string> = {},
): TestBrowser {
  const storage = new Map(Object.entries(initialStorage));
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
    const response = responses.shift();
    if (!response) throw new Error("unexpected fetch");
    return response;
  });
  const navigate = vi.fn();
  const replaceUrl = vi.fn();
  let nextByte = 1;
  const environment: AuthEnvironment = {
    fetch: (input, init) => fetchMock(input, init) as Promise<Response>,
    currentUrl: () => currentUrl,
    navigate,
    replaceUrl,
    randomBytes: (length) =>
      Uint8Array.from({ length }, () => {
        const value = nextByte;
        nextByte = (nextByte + 1) & 0xff;
        return value;
      }),
    sha256: async () => Uint8Array.from({ length: 32 }, (_, index) => index + 1).buffer,
    sessionStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => {
        storage.delete(key);
      },
    },
    now: () => 1_800_000_000_000,
    setTimer: () => 17,
    clearTimer: () => undefined,
  };
  return { environment, fetchMock, navigate, replaceUrl, storage };
}

describe("runtime authentication config", () => {
  it("accepts only the exact hosted Cognito and application contract", () => {
    expect(parseRuntimeConfig(runtimeConfig, "https://app.archon.example")).toEqual(
      runtimeConfig,
    );

    expect(() =>
      parseRuntimeConfig(
        {
          ...runtimeConfig,
          auth: {
            ...runtimeConfig.auth,
            redirectUri: "https://attacker.example/",
          },
        },
        "https://app.archon.example",
      ),
    ).toThrow(/application root/i);
    expect(() =>
      parseRuntimeConfig(
        { ...runtimeConfig, unexpected: true },
        "https://app.archon.example",
      ),
    ).toThrow(/schema/i);
  });

  it("fails closed when runtime config cannot be validated", async () => {
    const browser = testBrowser([
      json({
        ...runtimeConfig,
        auth: { ...runtimeConfig.auth, clientSecret: true },
      }),
    ]);
    const controller = new AuthController(browser.environment);

    await controller.initialize();

    expect(controller.getSnapshot()).toMatchObject({
      status: "error",
      recoverable: false,
    });
    expect(() => controller.getAccessToken()).toThrow(/missing or expired/i);
    expect(browser.navigate).not.toHaveBeenCalled();
  });
});

describe("Cognito Authorization Code + PKCE", () => {
  it("creates cryptographic state and an S256 challenge with only a short-lived transaction stored", async () => {
    const browser = testBrowser([json(runtimeConfig)]);
    const controller = new AuthController(browser.environment);

    await controller.initialize();
    await controller.signIn();

    const destination = new URL(String(browser.navigate.mock.calls[0]?.[0]));
    expect(destination.origin + destination.pathname).toBe(
      runtimeConfig.auth.authorizationEndpoint,
    );
    expect(destination.searchParams.get("response_type")).toBe("code");
    expect(destination.searchParams.get("code_challenge_method")).toBe("S256");
    expect(destination.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(destination.searchParams.get("code_challenge")).toMatch(
      /^[A-Za-z0-9_-]{43}$/,
    );
    expect(browser.storage.size).toBe(1);
    const transaction = JSON.parse([...browser.storage.values()][0]!) as Record<
      string,
      unknown
    >;
    expect(transaction.state).toBe(destination.searchParams.get("state"));
    expect(transaction.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(destination.searchParams.get("code_challenge")).not.toBe(
      transaction.codeVerifier,
    );
    expect(JSON.stringify(transaction)).not.toContain("access_token");
    expect(JSON.stringify(transaction)).not.toContain("refresh_token");
  });

  it("exchanges a matching callback and keeps the access token in controller memory only", async () => {
    const state = "A".repeat(43);
    const verifier = "B".repeat(64);
    const accessToken = "TEST_ONLY_TOKEN_000000000000";
    const browser = testBrowser(
      [
        json(runtimeConfig),
        json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 900,
          id_token: "TEST_ID_TOKEN_000000000000",
          refresh_token: "TEST_REFRESH_TOKEN_000000000000",
        }),
      ],
      `https://app.archon.example/?code=authorization-code-123&state=${state}`,
      {
        "archon.auth.pkce.v1": JSON.stringify({
          version: 1,
          state,
          codeVerifier: verifier,
          redirectUri: runtimeConfig.auth.redirectUri,
          createdAt: 1_800_000_000_000,
        }),
      },
    );
    const controller = new AuthController(browser.environment);

    await controller.initialize();

    expect(controller.getSnapshot()).toMatchObject({ status: "authenticated" });
    expect(controller.getAccessToken()).toBe(accessToken);
    expect(browser.storage.size).toBe(0);
    expect([...browser.storage.values()].join("")).not.toContain(accessToken);
    expect(browser.replaceUrl).toHaveBeenCalledWith("/");
    expect(browser.replaceUrl.mock.invocationCallOrder[0]).toBeLessThan(
      browser.fetchMock.mock.invocationCallOrder[0]!,
    );
    expect(browser.fetchMock).toHaveBeenCalledTimes(2);
    const [tokenUrl, tokenInit] = browser.fetchMock.mock.calls[1] as unknown as [
      string,
      RequestInit,
    ];
    expect(String(tokenUrl)).toBe(runtimeConfig.auth.tokenEndpoint);
    expect(tokenInit.credentials).toBe("omit");
    const tokenBody = new URLSearchParams(String(tokenInit.body));
    expect(tokenBody.get("grant_type")).toBe("authorization_code");
    expect(tokenBody.get("code_verifier")).toBe(verifier);
    expect(tokenBody.has("client_secret")).toBe(false);
  });

  it("rejects a mismatched state before any token exchange", async () => {
    const browser = testBrowser(
      [json(runtimeConfig)],
      `https://app.archon.example/?code=authorization-code-123&state=${"Z".repeat(43)}`,
      {
        "archon.auth.pkce.v1": JSON.stringify({
          version: 1,
          state: "A".repeat(43),
          codeVerifier: "B".repeat(64),
          redirectUri: runtimeConfig.auth.redirectUri,
          createdAt: 1_800_000_000_000,
        }),
      },
    );
    const controller = new AuthController(browser.environment);

    await controller.initialize();

    expect(controller.getSnapshot()).toMatchObject({
      status: "error",
      recoverable: true,
    });
    expect(browser.fetchMock).toHaveBeenCalledTimes(1);
    expect(browser.storage.size).toBe(0);
    expect(browser.replaceUrl).toHaveBeenCalledWith("/");
  });
});
