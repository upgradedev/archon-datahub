#!/usr/bin/env node

import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";

if (process.env.GITHUB_ACTIONS !== "true") {
  throw new Error(
    "The canonical flow-YAML emitter is restricted to GitHub Actions runners"
  );
}

if (process.argv.length !== 3) {
  throw new Error(
    "Usage: render-canonical-flow-yaml.mjs <runner-temp-canonical.json>"
  );
}

const runnerTemp = realpathSync(
  process.env.RUNNER_TEMP ??
    (() => {
      throw new Error("RUNNER_TEMP is required");
    })()
);
const requestedInputStat = lstatSync(process.argv[2]);
if (!requestedInputStat.isFile() || requestedInputStat.isSymbolicLink()) {
  throw new Error("Canonical JSON input must be a regular non-symlink file");
}
const inputPath = realpathSync(process.argv[2]);
const relativeInput = path.relative(runnerTemp, inputPath);
if (
  relativeInput.length === 0 ||
  relativeInput.startsWith(`..${path.sep}`) ||
  path.isAbsolute(relativeInput)
) {
  throw new Error("Canonical JSON input must be below RUNNER_TEMP");
}

const document = JSON.parse(readFileSync(inputPath, "utf8"));
if (
  document === null ||
  Array.isArray(document) ||
  typeof document !== "object" ||
  document.Resources === null ||
  Array.isArray(document.Resources) ||
  typeof document.Resources !== "object" ||
  Object.keys(document.Resources).length === 0
) {
  throw new Error("Canonical CloudFormation JSON must contain Resources");
}

const safePlainScalar = /^[A-Za-z_$][A-Za-z0-9_./:$*+=@%?-]*$/u;
const implicitYamlScalar =
  /^(?:null|true|false|yes|no|y|n|on|off|nan|inf|infinity|~)$/iu;

function emitString(value) {
  if (safePlainScalar.test(value) && !implicitYamlScalar.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function emit(value) {
  if (value === null) return "null";
  if (typeof value === "string") return emitString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Canonical JSON contains a non-finite number");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => emit(entry)).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.entries(value)
      .map(([key, entry]) => `${emitString(key)}: ${emit(entry)}`)
      .join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON value type: ${typeof value}`);
}

process.stdout.write(`${emit(document)}\n`);
