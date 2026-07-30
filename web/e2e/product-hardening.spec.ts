import { expect, test } from "@playwright/test";
import {
  expectNoHorizontalOverflow,
  expectNoSeriousAccessibilityViolations,
  installFixtureAuthorityBoundary,
} from "./support";

test("keeps keyboard orientation and responsive layout usable", async ({
  page,
}, testInfo) => {
  const boundary = await installFixtureAuthorityBoundary(page, testInfo);
  await page.goto("/");

  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", {
    name: "Skip to integrity overview",
  });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeInViewport();

  const tourTrigger = page.getByRole("button", { name: "Start judge tour" });
  await tourTrigger.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog", { name: "Run a governed audit" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("dialog", { name: "Run a governed audit" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Restart judge tour" }),
  ).toBeFocused();

  await expectNoHorizontalOverflow(page, testInfo);
  expect(boundary.apiRequests).toHaveLength(0);
  expect(boundary.externalRequests).toHaveLength(0);
});

test("has no critical or serious WCAG A/AA violations in judge states", async ({
  page,
}, testInfo) => {
  const boundary = await installFixtureAuthorityBoundary(page, testInfo);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Integrity findings" }),
  ).toBeVisible();
  await expectNoSeriousAccessibilityViolations(
    page,
    testInfo,
    "fixture-ready",
  );

  await page.getByRole("button", { name: "Start judge tour" }).click();
  const tour = page.getByRole("dialog", { name: "Run a governed audit" });
  await expect(tour).toBeVisible();
  await expectNoSeriousAccessibilityViolations(
    page,
    testInfo,
    "judge-tour-open",
  );
  await tour.getByRole("button", { name: "Dismiss tour" }).click();
  await expect(tour).toHaveCount(0);

  await page.getByRole("button", { name: "Approve exact plan" }).click();
  await expect(
    page.getByText(/no backend decision or mutation was sent/i),
  ).toBeVisible();
  await expectNoSeriousAccessibilityViolations(
    page,
    testInfo,
    "fixture-decision-preview",
  );

  expect(boundary.apiRequests).toHaveLength(0);
  expect(boundary.externalRequests).toHaveLength(0);
});
