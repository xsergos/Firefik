import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { queryClient } from "@/lib/queryClient";
import { APIError } from "@/lib/api";

vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn(), info: vi.fn(), warning: vi.fn(), dismiss: vi.fn() },
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("queryClient", () => {
  it("is configured with the expected default staleTime", () => {
    const defaults = queryClient.getDefaultOptions();
    expect(defaults.queries?.staleTime).toBe(10_000);
  });

  it("has a retry predicate that refuses 4xx APIError", () => {
    const defaults = queryClient.getDefaultOptions();
    const retry = defaults.queries?.retry;
    expect(typeof retry).toBe("function");
    if (typeof retry !== "function") return;
    const err = new APIError(404, "not_found", "nope");
    expect(retry(0, err)).toBe(false);
    expect(retry(1, err)).toBe(false);
  });

  it("retries up to 2 times on non-APIError failures", () => {
    const defaults = queryClient.getDefaultOptions();
    const retry = defaults.queries?.retry;
    if (typeof retry !== "function") throw new Error("retry not a function");
    const err = new Error("network");
    expect(retry(0, err)).toBe(true);
    expect(retry(1, err)).toBe(true);
    expect(retry(2, err)).toBe(false);
  });

  it("retries on 5xx APIError (treated like a generic transient error)", () => {
    const defaults = queryClient.getDefaultOptions();
    const retry = defaults.queries?.retry;
    if (typeof retry !== "function") throw new Error("retry not a function");
    const err = new APIError(500, "internal_error", "boom");
    expect(retry(0, err)).toBe(true);
    expect(retry(2, err)).toBe(false);
  });

  it("has configured a QueryCache and MutationCache", () => {
    expect(queryClient.getQueryCache()).toBeDefined();
    expect(queryClient.getMutationCache()).toBeDefined();
  });
});

describe("queryClient error handling", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders APIError via toast with code-scoped id", () => {
    const qc = queryClient;
    const cache = qc.getQueryCache();
    const sub = cache.config.onError;
    expect(typeof sub).toBe("function");
    sub?.(new APIError(500, "apply_failed", "Failed to apply."), {} as never);
    expect(toast.error).toHaveBeenCalledWith(
      "Failed to apply.",
      expect.objectContaining({ id: "api-apply_failed" }),
    );
  });

  it("renders a plain Error.message via toast description", () => {
    const cache = queryClient.getQueryCache();
    cache.config.onError?.(new Error("wat"), {} as never);
    expect(toast.error).toHaveBeenCalledWith(
      "Unexpected error",
      expect.objectContaining({ description: "wat" }),
    );
  });

  it("renders a generic toast for non-Error rejections", () => {
    const cache = queryClient.getQueryCache();
    cache.config.onError?.("string-thrown" as unknown as Error, {} as never);
    expect(toast.error).toHaveBeenCalledWith("Unexpected error");
  });

  it("renders a generic toast for an Error without a message", () => {
    const cache = queryClient.getQueryCache();
    cache.config.onError?.(new Error(""), {} as never);
    expect(toast.error).toHaveBeenCalledWith("Unexpected error");
  });

  it("wires the same error handler to the mutation cache", () => {
    const cache = queryClient.getMutationCache();
    cache.config.onError?.(
      new APIError(403, "forbidden", "No way."),
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );
    expect(toast.error).toHaveBeenCalledWith(
      "No way.",
      expect.objectContaining({ id: "api-forbidden" }),
    );
  });
});
