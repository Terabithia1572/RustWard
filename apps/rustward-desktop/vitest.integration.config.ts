/// <reference types="vitest/config" />
// Frontend ↔ real backend integration tests (development backend over SQLite).
// Run by scripts/verify-all.sh after building the stdio_backend example.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    include: ["src/**/*.integration.test.tsx"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // One backend process per test; keep files sequential.
    fileParallelism: false,
  },
});
