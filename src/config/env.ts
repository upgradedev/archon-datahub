// Minimal, zero-dependency .env loader. Imported FIRST by the demo/slice scripts so
// that a `.env` file (see .env.example) is honored on the live path — without pulling in
// a dotenv dependency. Absent `.env` → no-op (the agent stays on the offline Fakes).
// Existing process.env values always win (never overwrite an explicitly-set var).

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function loadEnv(path: string = resolve(process.cwd(), ".env")): void {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return; // no .env — offline Fakes
  }
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

loadEnv();
