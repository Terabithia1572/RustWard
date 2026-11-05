import { describe, expect, it, vi } from "vitest";
import { Api, ApiError, tauriBackend, toApiError } from "../api/client";

describe("api client", () => {
  it("maps IPC errors to ApiError with their code", () => {
    const e = toApiError({ code: "unauthorized", message: "elevation required" });
    expect(e).toBeInstanceOf(ApiError);
    expect(e.code).toBe("unauthorized");
    expect(e.message).toBe("elevation required");
  });

  it("maps unknown throwables to client errors", () => {
    expect(toApiError(new Error("boom")).code).toBe("client");
    expect(toApiError("x").message).toBe("x");
  });

  it("calls only the ipc_call Tauri command, with the request as payload", async () => {
    const invoke = vi.fn().mockResolvedValue({ type: "settings", data: { theme: "dark" } });
    const api = new Api(tauriBackend(invoke));
    await api.settings();
    expect(invoke).toHaveBeenCalledWith("ipc_call", { request: { type: "get_settings" } });
  });

  it("propagates backend rejections as ApiError", async () => {
    const invoke = vi.fn().mockRejectedValue({ code: "conflict", message: "stale" });
    const api = new Api(tauriBackend(invoke));
    await expect(api.setAllowed("x", true, 1)).rejects.toMatchObject({ code: "conflict" });
  });

  it("rejects a response of the wrong type", async () => {
    const invoke = vi.fn().mockResolvedValue({ type: "done", data: { message: "?" } });
    const api = new Api(tauriBackend(invoke));
    await expect(api.dashboard()).rejects.toMatchObject({ code: "client" });
  });
});
