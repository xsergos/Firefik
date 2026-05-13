import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthGate } from "./AuthGate";

vi.mock("@/lib/fleetApi", () => ({
  whoami: vi.fn(),
}));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/login" element={<div data-testid="login">login</div>} />
        <Route element={<AuthGate />}>
          <Route path="/" element={<div data-testid="home">home</div>} />
          <Route path="/foo" element={<div data-testid="foo">foo</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => vi.clearAllMocks());

describe("AuthGate", () => {
  it("renders the outlet when the user has a session", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.whoami).mockResolvedValue({ username: "admin", auth_kind: "session" });
    renderAt("/");
    expect(await screen.findByTestId("home")).toBeInTheDocument();
  });

  it("redirects to /login when whoami returns null", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.whoami).mockResolvedValue(null);
    renderAt("/foo");
    expect(await screen.findByTestId("login")).toBeInTheDocument();
  });

  it("treats whoami throws as unauthenticated", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.whoami).mockRejectedValue(new Error("boom"));
    renderAt("/");
    expect(await screen.findByTestId("login")).toBeInTheDocument();
  });

  it("shows a Checking session… placeholder while in flight", async () => {
    const api = await import("@/lib/fleetApi");
    let resolve!: (v: { username: string; auth_kind: "session" } | null) => void;
    vi.mocked(api.whoami).mockReturnValue(
      new Promise((r) => {
        resolve = r;
      }),
    );
    renderAt("/");
    expect(screen.getByText(/Checking session/)).toBeInTheDocument();
    resolve({ username: "x", auth_kind: "session" });
    expect(await screen.findByTestId("home")).toBeInTheDocument();
  });
});
