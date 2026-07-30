import { readFileSync } from "node:fs";
import { resolve, sep } from "node:path";

const summary = JSON.parse(
  readFileSync("coverage/coverage-summary.json", "utf8"),
);

const criticalFiles = [
  {
    path: "src/api.ts",
    statements: 80,
    branches: 70,
    functions: 80,
    lines: 80,
  },
  {
    path: "src/auth.ts",
    statements: 70,
    branches: 60,
    functions: 70,
    lines: 70,
  },
  {
    path: "src/App.tsx",
    statements: 70,
    branches: 60,
    functions: 70,
    lines: 70,
  },
  {
    path: "src/evidence-pack.ts",
    statements: 80,
    branches: 70,
    functions: 80,
    lines: 80,
  },
  {
    path: "src/GuidedTour.tsx",
    statements: 90,
    branches: 80,
    functions: 90,
    lines: 90,
  },
];

const normalizedSummary = new Map(
  Object.entries(summary)
    .filter(([path]) => path !== "total")
    .map(([path, metrics]) => [
      resolve(path).split(sep).join("/"),
      metrics,
    ]),
);

const failures = [];
for (const required of criticalFiles) {
  const normalizedPath = resolve(required.path).split(sep).join("/");
  const metrics = normalizedSummary.get(normalizedPath);
  if (!metrics) {
    failures.push(`${required.path}: missing from measured coverage`);
    continue;
  }

  for (const metric of ["statements", "branches", "functions", "lines"]) {
    const actual = metrics[metric]?.pct;
    const minimum = required[metric];
    if (typeof actual !== "number" || actual < minimum) {
      failures.push(
        `${required.path}: ${metric} ${String(actual)}% is below ${minimum}%`,
      );
    }
  }

  console.log(
    [
      `MEASURED ${required.path}`,
      `statements=${metrics.statements.pct}%`,
      `branches=${metrics.branches.pct}%`,
      `functions=${metrics.functions.pct}%`,
      `lines=${metrics.lines.pct}%`,
    ].join(" "),
  );
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`FAIL critical coverage ${failure}`);
  }
  process.exitCode = 1;
} else {
  console.log("PASS decision-critical web coverage ratchets");
}
