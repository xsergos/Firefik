import { describe, expect, it } from "vitest";

import { initI18n } from "./index";

describe("initI18n", () => {
  it("returns the same instance on the second call without re-initializing", () => {
    const first = initI18n();
    expect(first.isInitialized).toBe(true);
    const second = initI18n();
    expect(second).toBe(first);
    expect(second.isInitialized).toBe(true);
  });
});
