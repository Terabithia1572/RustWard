import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { Api, tauriBackend } from "./api/client";
import { App } from "./App";
import { translate } from "./i18n";
import { readCachedPrefs } from "./lib/prefs";
import "./index.css";

const root = createRoot(document.getElementById("root") as HTMLElement);

// Only run against the real backend inside the Tauri shell. In a plain
// browser there is no backend, and no fake data is shown.
const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

if (inTauri) {
  const api = new Api(tauriBackend((cmd, args) => invoke(cmd, args)));
  root.render(
    <StrictMode>
      <App api={api} />
    </StrictMode>,
  );
} else {
  const lang = readCachedPrefs().language;
  root.render(
    <div className="flex h-full items-center justify-center p-8">
      <p className="max-w-md text-center text-sm text-slate-600">{translate(lang, "app.notInShell")}</p>
    </div>,
  );
}
