import { describe, expect, it } from "vitest";
import { invalidateAfterMutation, queryKeys } from "@/lib/queryKeys";

describe("queryKeys", () => {
  it("produces deterministic array tuples", () => {
    expect(queryKeys.containers()).toEqual(["containers"]);
    expect(queryKeys.container("abc")).toEqual(["containers", "abc"]);
    expect(queryKeys.rules()).toEqual(["rules"]);
    expect(queryKeys.profiles()).toEqual(["rules", "profiles"]);
    expect(queryKeys.stats()).toEqual(["stats"]);
    expect(queryKeys.templates()).toEqual(["templates"]);
    expect(queryKeys.approvals()).toEqual(["approvals"]);
    expect(queryKeys.approvals("pending")).toEqual(["approvals", "pending"]);
  });

  it("invalidateAfterMutation covers every view that can change", () => {
    const names = invalidateAfterMutation.map((k) => k[0]);
    expect(names).toContain("containers");
    expect(names).toContain("rules");
    expect(names).toContain("stats");
  });
});
