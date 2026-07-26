import {
  lstatSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required by the protected live-browser configuration.`);
  }
  return value;
}

function exactHttpsOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("ARCHON_LIVE_BASE_URL must be an exact HTTPS origin.");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin !== value
  ) {
    throw new Error("ARCHON_LIVE_BASE_URL must be an exact HTTPS origin.");
  }
  return value;
}

function liveOutputDirectory(): string {
  const runnerTemp = requiredEnvironment("RUNNER_TEMP");
  const outputDirectory = requiredEnvironment("ARCHON_LIVE_OUTPUT_DIR");
  if (
    !path.isAbsolute(runnerTemp) ||
    !path.isAbsolute(outputDirectory) ||
    path.resolve(runnerTemp) !== runnerTemp ||
    path.resolve(outputDirectory) !== outputDirectory ||
    path.dirname(outputDirectory) !== runnerTemp
  ) {
    throw new Error(
      "ARCHON_LIVE_OUTPUT_DIR must be an exact absolute direct child of RUNNER_TEMP.",
    );
  }

  const runnerStat = lstatSync(runnerTemp);
  const outputStat = lstatSync(outputDirectory);
  if (
    !runnerStat.isDirectory() ||
    runnerStat.isSymbolicLink() ||
    !outputStat.isDirectory() ||
    outputStat.isSymbolicLink() ||
    realpathSync(runnerTemp) !== runnerTemp ||
    realpathSync(outputDirectory) !== outputDirectory ||
    path.dirname(realpathSync(outputDirectory)) !== realpathSync(runnerTemp)
  ) {
    throw new Error("The protected live-browser output path must be a symlink-free directory.");
  }
  return outputDirectory;
}

if (process.env.ARCHON_LIVE_JUDGE_JOURNEY !== "1") {
  throw new Error(
    "The protected live-browser configuration requires ARCHON_LIVE_JUDGE_JOURNEY=1.",
  );
}

const baseURL = exactHttpsOrigin(requiredEnvironment("ARCHON_LIVE_BASE_URL"));
const outputDir = liveOutputDirectory();

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/live-judge-journey.live.spec.ts",
  outputDir,
  preserveOutput: "always",
  fullyParallel: false,
  forbidOnly: true,
  failOnFlakyTests: true,
  retries: 0,
  workers: 1,
  timeout: 900_000,
  expect: {
    timeout: 30_000,
  },
  reporter: [["list"]],
  metadata: {
    dataMode: "protected-live",
    authBoundary: "cognito-pkce",
    decision: "reject-only",
    mutationAuthority: "one-reject-only",
  },
  use: {
    baseURL,
    actionTimeout: 30_000,
    navigationTimeout: 45_000,
    colorScheme: "dark",
    serviceWorkers: "block",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    {
      name: "protected-live-chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
