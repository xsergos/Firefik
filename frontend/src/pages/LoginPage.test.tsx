import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LoginPage from "./LoginPage";

vi.mock("@/lib/fleetApi", () => ({
  login: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function renderLogin() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/login"]}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<div data-testid="home">home</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  const api = await import("@/lib/fleetApi");
  vi.mocked(api.login).mockResolvedValue({
    username: "admin",
    expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
  });
});

afterEach(() => vi.clearAllMocks());

describe("LoginPage", () => {
  it("renders the form", () => {
    renderLogin();
    expect(screen.getByRole("heading", { name: "Firefik panel" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeDisabled();
  });

  it("submits credentials and navigates home on success", async () => {
    const api = await import("@/lib/fleetApi");
    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "secret");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(api.login).toHaveBeenCalledWith("admin", "secret"));
    expect(await screen.findByTestId("home")).toBeInTheDocument();
  });

  it("surfaces an error message when login fails", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.login).mockRejectedValue(new Error("nope"));
    renderLogin();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/nope/i);
  });
});
