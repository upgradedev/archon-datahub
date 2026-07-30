export function required(name: string, maxLength = 2048): string {
  const value = process.env[name]?.trim();
  if (!value || value.length > maxLength || value === "replace-after-deploy") {
    throw new Error(`Required runtime configuration ${name} is missing or invalid.`);
  }
  return value;
}

export function httpsUrl(name: string): string {
  const value = required(name);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`Required runtime configuration ${name} is not a URL.`);
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.hash.length > 0
  ) {
    throw new Error(
      `Required runtime configuration ${name} must be a credential-free HTTPS URL.`
    );
  }
  return parsed.toString();
}

export function releaseSha(): string {
  const value = required("ARCHON_RELEASE_SHA", 64);
  if (!/^[a-f0-9]{7,64}$/u.test(value)) {
    throw new Error("ARCHON_RELEASE_SHA must be a lowercase Git commit id.");
  }
  return value;
}

export function rejectCapabilities(names: readonly string[]): void {
  const present = names.filter((name) => Boolean(process.env[name]?.trim()));
  if (present.length > 0) {
    throw new Error(
      `This runtime refuses capabilities outside its trust boundary: ${present.join(", ")}.`
    );
  }
}
