import { expect, test } from "@playwright/test";
import {
  expectNoHorizontalOverflow,
  installFixtureAuthorityBoundary,
} from "./support";

test("completes the deterministic judge journey without acquiring mutation authority", async ({
  page,
}, testInfo) => {
  const boundary = await installFixtureAuthorityBoundary(page, testInfo);
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      level: 1,
      name: /Know when your catalog stops telling one truth/i,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("status", { name: "Fixture preview" }),
  ).toBeVisible();
  await expect(
    page.getByText(/Approval authentication is fail-closed/i),
  ).toBeVisible();
  await expect(
    page.getByText(/Deterministic showcase mode/i),
  ).toBeVisible();

  const tourTrigger = page.getByRole("button", { name: "Start judge tour" });
  await tourTrigger.click();
  const tour = page.getByRole("dialog", { name: "Run a governed audit" });
  await expect(tour).toBeVisible();
  await expect(tour).toContainText(
    "Passive orientation: no audit, approval, mutation, or API request is performed.",
  );
  await tour.getByRole("button", { name: "Next" }).click();
  await expect(
    page.getByRole("dialog", {
      name: "Inspect temporal provenance and blast radius",
    }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Next" }).click();
  await expect(
    page.getByRole("dialog", {
      name: "Review the exact plan and terminal proof",
    }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Finish tour" }).click();
  await expect(page.getByText("Tour completed.")).toBeVisible();
  expect(boundary.apiRequests).toHaveLength(0);

  await expect(
    page.getByRole("heading", { name: "Review the immutable proposal" }),
  ).toBeVisible();
  await expect(
    page.getByText(/Fixture preview is non-mutating/i),
  ).toBeVisible();
  await page.getByRole("button", { name: "Approve exact plan" }).click();
  await expect(
    page.getByText(/no backend decision or mutation was sent/i),
  ).toBeVisible();
  expect(boundary.apiRequests).toHaveLength(0);

  await page.getByRole("button", { name: "Prepare & verify pack" }).click();
  await expect(page.getByText(/files verified/i)).toBeVisible();
  expect(boundary.apiRequests).toHaveLength(0);

  await page
    .getByLabel("Filter findings by severity")
    .selectOption("medium");
  await expect(page.getByText("2 results", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("list", { name: "Audit findings" }).getByRole("button"),
  ).toHaveCount(2);
  await expect(page.getByRole("heading", { name: "Blast radius" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Source provenance" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Evidence dossier" }),
  ).toBeVisible();

  await expectNoHorizontalOverflow(page, testInfo);
  await page.screenshot({
    path: testInfo.outputPath(`archon-judge-${testInfo.project.name}.png`),
    fullPage: true,
  });
  await testInfo.attach("authority-boundary", {
    body: `${JSON.stringify(
      {
        dataMode: "deterministic-fixture",
        apiRequestCount: boundary.apiRequests.length,
        externalRequestCount: boundary.externalRequests.length,
        authenticatedHumanApprovalEmitted: false,
        mutationRequestEmitted: false,
      },
      null,
      2,
    )}\n`,
    contentType: "application/json",
  });

  expect(boundary.apiRequests).toHaveLength(0);
  expect(boundary.externalRequests).toHaveLength(0);
});
