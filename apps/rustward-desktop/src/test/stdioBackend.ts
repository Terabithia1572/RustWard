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
  close(): Promise<void>;
}

/** Start a real backend over a fresh SQLite database. */
export function startRealBackend(
  caller: "admin" | "user" = "admin",
  dataDir?: string,
  options: { policyCapture?: string; liveInventory?: boolean } = {},
): RealBackend {
  if (!STDIO_BACKEND) {
    throw new Error("RUSTWARD_STDIO_BACKEND is not set (run scripts/verify-all.sh or see docs/TEST-RESULTS.md)");
  }
  const dir = dataDir ?? mkdtempSync(join(tmpdir(), "rustward-ui-int-"));
  const env = { ...process.env };
  // Isolate tests from the host machine's live USB hardware and Group Policy
  // unless a test explicitly opts into live read-only Windows inspection.
  env.RUSTWARD_DEV_INVENTORY = options.liveInventory ? "live" : "empty";
  if (options.policyCapture === "live") {
    delete env.RUSTWARD_DEV_POLICY_CAPTURE;
  } else if (options.policyCapture) {
    // A SYNTHETIC policy capture file stands in for the read-only registry read.
    env.RUSTWARD_DEV_POLICY_CAPTURE = options.policyCapture;
  } else {
    env.RUSTWARD_DEV_POLICY_CAPTURE = "unavailable";
  }
  const child: ChildProcessWithoutNullStreams = spawn(STDIO_BACKEND, [dir, caller], { stdio: "pipe", env });
  const pending: Array<{ resolve: (v: ResponseBody) => void; reject: (e: unknown) => void }> = [];
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
  child.stdin.on("error", () => {});
  let closed = false;
  const rl = createInterface({ input: child.stdout });
  rl.on("line", (line) => {
    // After close() the process is killed, possibly mid-write: readline then
    // flushes a truncated last line. Nothing is waiting for it.
    if (closed) return;
    const p = pending.shift();
    if (!p) return;
    let msg: { ok?: ResponseBody; err?: { code: string; message: string } };
    try {
      msg = JSON.parse(line) as typeof msg;
    } catch {
      p.reject(new ApiError("client", `unparseable backend reply: ${line.slice(0, 120)}`));
      return;
    }
    if (msg.ok) p.resolve(msg.ok);
    // Shape of the Tauri rejection value (IpcError), as in production.
    else p.reject(msg.err ?? { code: "internal", message: "empty reply" });
  });
  child.on("exit", (code) => {
    while (pending.length) pending.shift()!.reject(new ApiError("client", `backend exited (${code}): ${stderr}`));
  });
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
    async close() {
      closed = true;
      rl.close();
      child.stdin.end();
      const exited =
        child.exitCode !== null || child.signalCode !== null
          ? Promise.resolve()
          : new Promise<void>((resolve) => {
              const timer = setTimeout(resolve, 2000);
              child.once("close", () => {
                clearTimeout(timer);
                resolve();
              });
            });
      child.kill();
      await exited;
      if (!dataDir) {
        try {
          rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        } catch {
          // Best-effort cleanup on Windows if an indexer briefly holds a file handle.
        }
      }
    },
  };
}
