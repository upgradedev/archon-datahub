#!/usr/bin/env node

import assert from "node:assert/strict";
import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

if (
  process.env.CI !== "true" ||
  process.env.GITHUB_ACTIONS !== "true"
) {
  throw new Error("Exact npm override verification is CI/CD-only");
}
if (process.argv.length !== 3) {
  throw new Error("usage: verify-exact-npm-overrides.mjs <package-directory>");
}

const workspace = realpathSync(process.env.GITHUB_WORKSPACE);
const packageDirectory = realpathSync(process.argv[2]);
if (
  packageDirectory !== workspace &&
  !packageDirectory.startsWith(`${workspace}${path.sep}`)
) {
  throw new Error("Package directory must remain within GITHUB_WORKSPACE");
}

function readJson(file) {
  const stat = lstatSync(file);
  assert.equal(stat.isFile(), true, `${file} must be a regular file`);
  assert.equal(stat.isSymbolicLink(), false, `${file} must not be a symlink`);
  return JSON.parse(readFileSync(file, "utf8"));
}

const packageJson = readJson(path.join(packageDirectory, "package.json"));
const lock = readJson(path.join(packageDirectory, "package-lock.json"));
assert.equal(lock.lockfileVersion, 3);
assert.equal(typeof packageJson.overrides, "object");

for (const [lockPath, metadata] of Object.entries(lock.packages ?? {})) {
  if (lockPath === "") {
    continue;
  }
  assert.notEqual(metadata.link, true, `${lockPath} must not be a lock link`);
  if (metadata.inBundle === true) {
    continue;
  }
  assert.equal(
    typeof metadata.resolved,
    "string",
    `${lockPath} must have a registry source`
  );
  const resolved = new URL(metadata.resolved);
  assert.equal(resolved.protocol, "https:", `${lockPath} must use HTTPS`);
  assert.equal(
    resolved.hostname,
    "registry.npmjs.org",
    `${lockPath} must come from the reviewed npm registry`
  );
  assert.match(
    metadata.integrity,
    /^sha512-[A-Za-z0-9+/]+={0,2}$/u,
    `${lockPath} must have SHA-512 registry integrity`
  );
}

if (packageJson.name === "@archon/datahub-aws-infra") {
  const cdk = lock.packages?.["node_modules/aws-cdk-lib"];
  assert.deepEqual(
    {
      version: cdk?.version,
      resolved: cdk?.resolved,
      integrity: cdk?.integrity,
    },
    {
      version: "2.262.1",
      resolved:
        "https://registry.npmjs.org/aws-cdk-lib/-/aws-cdk-lib-2.262.1.tgz",
      integrity:
        "sha512-B6YP4r6ojUZCDhl+qBu/CrWzcipR8sIgshcqYvgw013sghPXmVkYdJ3yuI9+DKML3YLSjQrHy1nGJs+Nqq7JCg==",
    }
  );
}

if (packageJson.name === "archon-datahub") {
  const coverage = lock.packages?.["node_modules/c8"];
  assert.deepEqual(
    {
      version: coverage?.version,
      resolved: coverage?.resolved,
      integrity: coverage?.integrity,
    },
    {
      version: "12.0.0",
      resolved: "https://registry.npmjs.org/c8/-/c8-12.0.0.tgz",
      integrity:
        "sha512-4zpJvrd1nKWutnnKC2pXkFmb6iM1l+ffN//o1CzlTNwW7GSOs9a1xrLqkC48nU8oEkjmPZLPiwMsIaOvoF4Pqg==",
    }
  );
}

const overrides = Object.entries(packageJson.overrides);
assert.ok(overrides.length > 0, "At least one exact override is required");
for (const [name, version] of overrides) {
  assert.equal(typeof version, "string", `${name} override must be a string`);
  assert.match(
    version,
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u,
    `${name} override must be an exact version`
  );
}

function packageNameForLockPath(lockPath) {
  const match = lockPath.match(
    /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/u
  );
  return match?.[1];
}

const exactBundledException = {
  project: "@archon/datahub-aws-infra",
  package: "brace-expansion",
  path: "node_modules/aws-cdk-lib/node_modules/brace-expansion",
  lockedVersion: "5.0.7",
  replacementVersion: "5.0.8",
};

const verified = [];
for (const [overrideName, overrideVersion] of overrides) {
  const occurrences = Object.entries(lock.packages ?? {}).filter(
    ([lockPath]) => packageNameForLockPath(lockPath) === overrideName
  );
  assert.ok(
    occurrences.length > 0,
    `${overrideName} override does not resolve any locked package`
  );

  for (const [lockPath, metadata] of occurrences) {
    const installedPackageJson = path.join(
      packageDirectory,
      ...lockPath.split("/"),
      "package.json"
    );
    assert.equal(
      existsSync(installedPackageJson),
      true,
      `${lockPath} is absent from the exact npm installation`
    );
    const installed = readJson(installedPackageJson);

    const isReviewedBundledException =
      packageJson.name === exactBundledException.project &&
      overrideName === exactBundledException.package &&
      lockPath === exactBundledException.path &&
      metadata.version === exactBundledException.lockedVersion &&
      metadata.inBundle === true &&
      overrideVersion === exactBundledException.replacementVersion;

    if (isReviewedBundledException) {
      assert.equal(installed.name, overrideName);
      assert.equal(installed.version, exactBundledException.lockedVersion);
      verified.push({
        name: overrideName,
        path: lockPath,
        version: installed.version,
        disposition: "exact-bundled-compensation-required",
      });
      continue;
    }

    assert.equal(
      metadata.version,
      overrideVersion,
      `${lockPath} escaped the exact ${overrideName} override`
    );
    assert.equal(installed.name, overrideName);
    assert.equal(
      installed.version,
      overrideVersion,
      `${lockPath} installation differs from its reviewed lock`
    );
    verified.push({
      name: overrideName,
      path: lockPath,
      version: installed.version,
      disposition: "exact-override",
    });
  }
}

verified.sort((left, right) => left.path.localeCompare(right.path));
process.stdout.write(
  `${JSON.stringify(
    {
      schemaVersion: 1,
      package: packageJson.name,
      verified,
    },
    null,
    2
  )}\n`
);
