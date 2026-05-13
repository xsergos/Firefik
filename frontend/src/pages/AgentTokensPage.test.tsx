import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AgentTokensPage from "./AgentTokensPage";

vi.mock("@/lib/fleetApi", () => ({
  fetchAgentTokens: vi.fn(),
  createAgentToken: vi.fn(),
  revokeAgentToken: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AgentTokensPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(async () => {
  const api = await import("@/lib/fleetApi");
  vi.mocked(api.fetchAgentTokens).mockResolvedValue([
    {
      id: "id-1",
      name: "prod-1",
      description: "primary",
      issued_by: "operator-x",
      issued_at: "2026-04-23T10:00:00Z",
      last_used_at: "2026-04-23T11:00:00Z",
      last_used_ip: "10.0.0.5",
      revoked_at: null,
    },
  ]);
  vi.mocked(api.createAgentToken).mockResolvedValue({
    id: "id-2",
    name: "new-host",
    description: "",
    issued_by: "operator-x",
    issued_at: "2026-04-23T12:00:00Z",
    last_used_at: null,
    last_used_ip: "",
    revoked_at: null,
    token: "agt_aabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaa11",
  });
  vi.mocked(api.revokeAgentToken).mockResolvedValue();
});

afterEach(() => vi.clearAllMocks());

describe("AgentTokensPage", () => {
  it("renders the list with active badge and last-seen info", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "Agent tokens" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("prod-1")).toBeInTheDocument());
    expect(screen.getByText("primary")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
    expect(screen.getByText(/10\.0\.0\.5/)).toBeInTheDocument();
  });

  it("disables Issue when name is blank", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "Agent tokens" });
    const btn = screen.getByRole("button", { name: "Issue token" });
    expect(btn).toBeDisabled();
  });

  it("issues a token and surfaces the plaintext banner", async () => {
    const api = await import("@/lib/fleetApi");
    renderPage();
    const user = userEvent.setup();
    await screen.findByRole("heading", { name: "Agent tokens" });
    await user.type(screen.getByPlaceholderText("prod-host-01"), "new-host");
    await user.click(screen.getByRole("button", { name: "Issue token" }));
    await waitFor(() => expect(api.createAgentToken).toHaveBeenCalledWith("new-host", undefined));
    expect(await screen.findByText(/Copy this token now/i)).toBeInTheDocument();
    expect(screen.getByText(/agt_aabbccddeeff/)).toBeInTheDocument();
  });

  it("revokes a token after confirmation", async () => {
    const api = await import("@/lib/fleetApi");
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    await screen.findByRole("heading", { name: "Agent tokens" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.revokeAgentToken).toHaveBeenCalledWith("id-1"));
    confirm.mockRestore();
  });

  it("skips revoke when the operator cancels the confirm dialog", async () => {
    const api = await import("@/lib/fleetApi");
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderPage();
    await screen.findByRole("heading", { name: "Agent tokens" });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Revoke" }));
    expect(api.revokeAgentToken).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("renders empty state when no tokens exist", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.fetchAgentTokens).mockResolvedValue([]);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/No agent tokens issued yet/i)).toBeInTheDocument(),
    );
  });

  it("renders error state when API rejects", async () => {
    const api = await import("@/lib/fleetApi");
    vi.mocked(api.fetchAgentTokens).mockRejectedValue(new Error("boom"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/Could not load agent tokens/i),
    );
  });

  it("re-fetches with include_revoked when checkbox toggles", async () => {
    const api = await import("@/lib/fleetApi");
    renderPage();
    await screen.findByText("prod-1");
    const user = userEvent.setup();
    await user.click(screen.getByRole("checkbox"));
    await waitFor(() => expect(api.fetchAgentTokens).toHaveBeenLastCalledWith(true));
  });
});
