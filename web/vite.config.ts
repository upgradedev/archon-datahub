import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // The hosted judges' bundle is public. Keep source maps out of the promoted
    // artifact; CI still type-checks and tests the original TypeScript sources.
    sourcemap: false,
    target: "es2022",
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/healthz": "http://127.0.0.1:8080",
      "/readyz": "http://127.0.0.1:8080",
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
