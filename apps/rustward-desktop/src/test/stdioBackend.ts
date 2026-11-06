// Frontend integration tests ONLY: a Backend that talks to the real RustWard
// backend (AppService + SQLite, same validation/authorization as the service)
// through the development-only `stdio_backend` example binary. Never bundled.
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { ApiError, type Backend } from "../api/client";
import type { Request, ResponseBody } from "../api/types";

export const STDIO_BACKEND = process.env.RUSTWARD_STDIO_BACKEND ?? "";

export interface RealBackend {
  backend: Backend;
  /** Direct call bypassing the UI (to check what the backend stored). */
  call(request: Request): Promise<ResponseBody>;
  dataDir: string;
  close(): void;
}

/** Start a real backend over a fresh SQLite database. */
export function startRealBackend(caller: "admin" | "user" = "admin", dataDir?: string): RealBackend {
  if (!STDIO_BACKEND) {
    throw new Error("RUSTWARD_STDIO_BACKEND is not set (run scripts/verify-all.sh or see docs/TEST-RESULTS.md)");
  }
  const dir = dataDir ?? mkdtempSync(join(tmpdir(), "rustward-ui-int-"));
  const child: ChildProcessWithoutNullStreams = spawn(STDIO_BACKEND, [dir, caller], { stdio: "pipe" });
  const pending: Array<{ resolve: (v: ResponseBody) => void; reject: (e: unknown) => void }> = [];
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
  const rl = createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    const p = pending.shift();
    if (!p) return;
    const msg = JSON.parse(line) as { ok?: ResponseBody; err?: { code: string; message: string } };
    if (msg.ok) p.resolve(msg.ok);
    // Shape of the Tauri rejection value (IpcError), as in production.
    else p.reject(msg.err ?? { code: "internal", message: "empty reply" });
  });
  child.on("exit", (code) => {
    while (pending.length) pending.shift()!.reject(new ApiError("client", `backend exited (${code}): ${stderr}`));
  });
  let closed = false;
  const call = (request: Request) =>
    new Promise<ResponseBody>((resolve, reject) => {
      // A page may still poll after the test finished: answer like a stopped
      // service instead of writing to a closed pipe.
      if (closed || !child.stdin.writable) {
        reject({ code: "unavailable", message: "test backend closed" });
        return;
      }
      pending.push({ resolve, reject });
      child.stdin.write(`${JSON.stringify(request)}\n`);
    });
  return {
    backend: { call },
    call,
    dataDir: dir,
    close() {
      closed = true;
      child.stdin.end();
      child.kill();
      if (!dataDir) rmSync(dir, { recursive: true, force: true });
    },
  };
}
