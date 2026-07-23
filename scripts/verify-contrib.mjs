import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve("contrib/datahub-audit");
const requiredFiles = [
  "README.md",
  "SKILL.md",
  "commands/catalog-audit.md",
  "evaluations/audit-governance-coverage.json",
  "evaluations/audit-sensitive-and-lineage.json",
];

for (const relativePath of requiredFiles) {
  const file = resolve(root, relativePath);
  const metadata = await stat(file);
  if (!metadata.isFile()) {
    throw new Error(`${relativePath} must be a regular file.`);
  }
}

const skill = await readFile(resolve(root, "SKILL.md"), "utf8");
const skillFrontmatter = skill.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
if (!skillFrontmatter) {
  throw new Error("SKILL.md must begin with YAML frontmatter.");
}
for (const contract of [
  /^name:\s*datahub-audit\s*$/m,
  /^user-invocable:\s*true\s*$/m,
  /^allowed-tools:\s*Bash\(datahub \*\)\s*$/m,
]) {
  if (!contract.test(skillFrontmatter[1])) {
    throw new Error(`SKILL.md frontmatter is missing ${contract}.`);
  }
}
if (!skill.includes("read-only") || !skill.includes("never mutate")) {
  throw new Error("SKILL.md must preserve its explicit read-only boundary.");
}

const command = await readFile(resolve(root, "commands/catalog-audit.md"), "utf8");
if (
  !/^---\r?\n[\s\S]*?^name:\s*catalog-audit\s*$[\s\S]*?\r?\n---\r?\n/m.test(
    command
  ) ||
  !command.includes('skill: "datahub-skills:datahub-audit"')
) {
  throw new Error("catalog-audit command is not bound to the datahub-audit skill.");
}

for (const relativePath of requiredFiles.filter((file) => file.endsWith(".json"))) {
  const document = JSON.parse(await readFile(resolve(root, relativePath), "utf8"));
  if (
    !Array.isArray(document.skills) ||
    document.skills.length !== 1 ||
    document.skills[0] !== "datahub-audit" ||
    typeof document.query !== "string" ||
    document.query.trim().length === 0 ||
    !Array.isArray(document.expected_behavior) ||
    document.expected_behavior.length < 5 ||
    document.expected_behavior.some(
      (expectation) =>
        typeof expectation !== "string" || expectation.trim().length === 0
    )
  ) {
    throw new Error(`${relativePath} does not satisfy the evaluation contract.`);
  }
}

console.log("DataHub audit contribution contract verified.");
