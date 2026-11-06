/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Local assets only: no CDN, no remote fonts. Tauri serves ../dist.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: { port: 5173, strictPort: true, host: "127.0.0.1" },
  // No module-preload polyfill: WebView2 (Chromium) supports modulepreload
  // natively, and the polyfill is the only fetch() in the bundle
  // (scripts/check-offline-assets.mjs forbids runtime network calls).
  build: { target: "es2022", outDir: "dist", sourcemap: false, modulePreload: { polyfill: false } },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    // Real-backend tests need the stdio_backend binary: vitest.integration.config.ts.
    exclude: ["**/node_modules/**", "**/dist/**", "src/**/*.integration.test.tsx"],
  },
});
