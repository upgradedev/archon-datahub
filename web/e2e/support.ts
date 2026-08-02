import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, type Request, type TestInfo } from "@playwright/test";

export interface AuthorityBoundary {
  readonly apiRequests: Request[];
  readonly externalRequests: Request[];
}

function isApiPath(pathname: string): boolean {
  return pathname === "/api" || pathname.startsWith("/api/");
}

export async function installFixtureAuthorityBoundary(
  page: Page,
  testInfo: TestInfo,
): Promise<AuthorityBoundary> {
  const apiRequests: Request[] = [];
  const externalRequests: Request[] = [];
  const configuredBaseUrl = testInfo.project.use.baseURL;
  if (typeof configuredBaseUrl !== "string") {
    throw new Error("Fixture browser tests require an explicit Playwright baseURL.");
  }
  const allowedOrigin = new URL(configuredBaseUrl).origin;

  await page.emulateMedia({ reducedMotion: "reduce" });

  page.on("request", (request) => {
    const url = new URL(request.url());
    if (isApiPath(url.pathname)) {
      apiRequests.push(request);
    }
    if (url.origin !== allowedOrigin) {
      externalRequests.push(request);
    }
  });

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== allowedOrigin) {
      await route.abort("blockedbyclient");
      return;
    }
    if (url.pathname === "/runtime-config.json") {
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({
          error: "CI fixture mode has no approval identity provider.",
        }),
      });
      return;
    }
    if (isApiPath(url.pathname)) {
      await route.abort("blockedbyclient");
      return;
    }
    await route.continue();
  });

  return { apiRequests, externalRequests };
}

export async function expectNoHorizontalOverflow(
  page: Page,
  testInfo: TestInfo,
): Promise<void> {
  const measurement = await page.evaluate(() => ({
    viewportWidth: window.innerWidth,
    documentOverflow: Math.max(
      0,
      document.documentElement.scrollWidth -
        Math.max(window.innerWidth, document.documentElement.clientWidth),
    ),
    bodyOverflow: Math.max(
      0,
      document.body.scrollWidth - Math.max(window.innerWidth, document.documentElement.clientWidth),
    ),
  }));

  await testInfo.attach("viewport-overflow", {
    body: `${JSON.stringify(measurement, null, 2)}\n`,
    contentType: "application/json",
  });
  expect(measurement.documentOverflow).toBe(0);
  expect(measurement.bodyOverflow).toBe(0);
}

function compactViolations(
  violations: Awaited<ReturnType<AxeBuilder["analyze"]>>["violations"],
) {
  return violations.map((violation) => ({
    rule: violation.id,
    impact: violation.impact,
    help: violation.help,
    helpUrl: violation.helpUrl,
    nodes: violation.nodes.map((node) => ({
      target: node.target,
      html: node.html,
      failureSummary: node.failureSummary,
    })),
  }));
}

export async function expectNoSeriousAccessibilityViolations(
  page: Page,
  testInfo: TestInfo,
  state: string,
): Promise<void> {
  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa"])
    .analyze();
  const severe = result.violations.filter(
    (violation) =>
      violation.impact === "critical" || violation.impact === "serious",
  );
  const evidence = {
    project: testInfo.project.name,
    state,
    tags: ["wcag2a", "wcag2aa"],
    totalViolations: result.violations.length,
    criticalOrSeriousViolations: compactViolations(severe),
  };

  await testInfo.attach(`accessibility-${state}`, {
    body: `${JSON.stringify(evidence, null, 2)}\n`,
    contentType: "application/json",
  });
  expect(
    compactViolations(severe),
    `${testInfo.project.name} ${state} critical/serious accessibility violations`,
  ).toEqual([]);
}
