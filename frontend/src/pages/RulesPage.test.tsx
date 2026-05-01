import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RuleEntry } from "@/types/api";
import RulesPage from "./RulesPage";

vi.mock("@/lib/api", () => ({
  fetchRules: vi.fn(),
  APIError: class APIError extends Error {
    readonly status: number;
    readonly code: string;
    readonly userMessage: string;
    constructor(status: number, code: string, userMessage: string) {
      super(userMessage);
      this.status = status;
      this.code = code;
      this.userMessage = userMessage;
    }
  },
}));

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <RulesPage />
    </QueryClientProvider>,
  );
}

const baseEntry: RuleEntry = {
  containerID: "abcdef012345",
  containerName: "nginx",
  status: "running",
  defaultPolicy: "DROP",
  ruleSets: [
    {
      name: "web",
      ports: [80, 443],
      allowlist: ["10.0.0.0/24"],
      blocklist: [],
      protocol: "tcp",
      profile: "edge",
      log: true,
      rateLimit: { rate: 100, burst: 50 },
    },
  ],
};

beforeEach(async () => {
  const api = await import("@/lib/api");
  vi.mocked(api.fetchRules).mockResolvedValue([baseEntry]);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("RulesPage", () => {
  it("renders the heading and the container card after fetch resolves", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Active Rules")).toBeInTheDocument());
    expect(screen.getByText("nginx")).toBeInTheDocument();
    expect(screen.getByText("abcdef012345")).toBeInTheDocument();
    expect(screen.getByText("DROP")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
  });

  it("renders rule-set ports, protocol, profile, allowlist, and rate-limit badges", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("web")).toBeInTheDocument());
    expect(screen.getByText("80, 443")).toBeInTheDocument();
    expect(screen.getByText("TCP")).toBeInTheDocument();
    expect(screen.getByText("edge")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.0/24")).toBeInTheDocument();
    expect(screen.getByText("log")).toBeInTheDocument();
    expect(screen.getByText("100/s")).toBeInTheDocument();
  });

  it("collapses long allowlists into a +N more badge", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchRules).mockResolvedValue([
      {
        ...baseEntry,
        ruleSets: [
          {
            name: "web",
            ports: [],
            allowlist: ["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24", "4.0.0.0/24", "5.0.0.0/24"],
            blocklist: [],
          },
        ],
      },
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText("+3 more")).toBeInTheDocument());
    expect(screen.getByText("any")).toBeInTheDocument();
  });

  it("renders geo allow/block badges when present", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchRules).mockResolvedValue([
      {
        ...baseEntry,
        ruleSets: [
          {
            name: "geo",
            ports: [22],
            allowlist: [],
            blocklist: ["6.6.6.6"],
            geoBlock: ["RU", "CN"],
            geoAllow: ["US"],
          },
        ],
      },
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText("block:RU,CN")).toBeInTheDocument());
    expect(screen.getByText("allow:US")).toBeInTheDocument();
    expect(screen.getByText("6.6.6.6")).toBeInTheDocument();
  });

  it("falls back to a 'No rule sets' message when ruleSets is empty", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchRules).mockResolvedValue([
      { ...baseEntry, ruleSets: [] },
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText("No rule sets.")).toBeInTheDocument());
  });

  it("shows an empty-state hint when the response is an empty array", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchRules).mockResolvedValue([]);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/No active firewall rules/i)).toBeInTheDocument(),
    );
  });

  it("renders the error state when fetchRules rejects", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchRules).mockRejectedValue(new Error("boom"));
    renderPage();
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/Failed to load rules/i));
  });
});
