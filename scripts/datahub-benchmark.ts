import { mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import {
  dataHubBenchmarkToMarkdown,
  runDataHubBenchmark,
} from "../src/evaluation/datahub-benchmark.js";

function outputDirectory(argv: string[]): string {
  const flag = argv.indexOf("--output");
  const value = flag >= 0 ? argv[flag + 1] : undefined;
  if (!value || !isAbsolute(value)) {
    throw new Error("--output must name an absolute runner-temporary directory.");
  }
  if (argv.length !== 2 || flag !== 0) {
    throw new Error("Usage: datahub-benchmark --output <absolute-directory>");
  }
  return resolve(value);
}

const output = outputDirectory(process.argv.slice(2));
if (process.env["GITHUB_ACTIONS"] === "true") {
  const runnerTemp = process.env["RUNNER_TEMP"];
  if (!runnerTemp) {
    throw new Error("RUNNER_TEMP is required in GitHub Actions.");
  }
  const fromRunnerTemp = relative(resolve(runnerTemp), output);
  if (
    fromRunnerTemp.length === 0 ||
    fromRunnerTemp === ".." ||
    fromRunnerTemp.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(fromRunnerTemp)
  ) {
    throw new Error("--output must remain below RUNNER_TEMP in GitHub Actions.");
  }
}
const report = await runDataHubBenchmark();
await mkdir(output, { recursive: false, mode: 0o700 });
await Promise.all([
  writeFile(
    resolve(output, "datahub-benchmark.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 }
  ),
  writeFile(
    resolve(output, "datahub-benchmark.md"),
    dataHubBenchmarkToMarkdown(report),
    { encoding: "utf8", flag: "wx", mode: 0o600 }
  ),
]);

console.log(
  `DataHub benchmark ${report.dataset.version} ${report.dataset.digest}: retained-history recall ${report.systems.retainedHistory.metrics.recall}; current-view recall ${report.systems.currentView.metrics.recall}.`
);
