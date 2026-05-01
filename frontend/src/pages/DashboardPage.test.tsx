import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { StatsResponse } from "@/types/api";
import DashboardPage from "./DashboardPage";

vi.mock("recharts", () => {
  const Stub = ({ children }: { children?: React.ReactNode }) => (
    <div data-testid="rechart-stub">{children}</div>
  );
  const XAxis = ({ tickFormatter }: { tickFormatter?: (v: string) => string }) => (
    <div data-testid="xaxis-stub">
      {tickFormatter ? tickFormatter("2026-04-23T10:00:00Z") : null}
    </div>
  );
  const Tooltip = ({
    labelFormatter,
    formatter,
  }: {
    labelFormatter?: (v: unknown) => string;
    formatter?: (value: unknown, name: unknown) => unknown;
  }) => (
    <div data-testid="tooltip-stub">
      <span>{labelFormatter ? labelFormatter("2026-04-23T10:00:00Z") : ""}</span>
      <span>{labelFormatter ? labelFormatter("") : ""}</span>
      <span>{labelFormatter ? labelFormatter(42) : ""}</span>
      <span>
        {formatter ? JSON.stringify(formatter(100, "accepted")) : ""}
      </span>
      <span>
        {formatter ? JSON.stringify(formatter(50, "dropped")) : ""}
      </span>
    </div>
  );
  const Legend = ({ formatter }: { formatter?: (v: unknown) => string }) => (
    <div data-testid="legend-stub">
      <span>{formatter ? formatter("accepted") : ""}</span>
      <span>{formatter ? formatter("dropped") : ""}</span>
    </div>
  );
  return {
    AreaChart: Stub,
    Area: Stub,
    XAxis,
    YAxis: Stub,
    Tooltip,
    Legend,
    ResponsiveContainer: Stub,
  };
});

vi.mock("@/lib/api", () => ({
  fetchStats: vi.fn(),
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
      <DashboardPage />
    </QueryClientProvider>,
  );
}

function buildStats(overrides?: Partial<StatsResponse>): StatsResponse {
  return {
    containers: { total: 5, running: 3, enabled: 2 },
    traffic: [
      { ts: "2026-04-23T10:00:00Z", accepted: 100, dropped: 5 },
      { ts: "2026-04-23T10:01:00Z", accepted: 120, dropped: 8 },
    ],
    ...overrides,
  };
}

beforeEach(async () => {
  const api = await import("@/lib/api");
  vi.mocked(api.fetchStats).mockResolvedValue(buildStats());
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("DashboardPage", () => {
  it("renders the heading and stat cards once data resolves", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Total containers")).toBeInTheDocument());
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
  });

  it("renders the traffic chart container when traffic data is present", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("Traffic (last 60 min)")).toBeInTheDocument());
    expect(await screen.findAllByTestId("rechart-stub")).not.toHaveLength(0);
  });

  it("renders the empty-state message when traffic is missing", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchStats).mockResolvedValue(
      buildStats({ traffic: [] }),
    );
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/No traffic data yet/i)).toBeInTheDocument(),
    );
  });

  it("downsamples a long traffic series without crashing", async () => {
    const long: StatsResponse["traffic"] = [];
    for (let i = 0; i < 700; i++) {
      long.push({
        ts: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
        accepted: i,
        dropped: i % 3,
      });
    }
    const api = await import("@/lib/api");
    vi.mocked(api.fetchStats).mockResolvedValue(buildStats({ traffic: long }));
    renderPage();
    await waitFor(() => expect(screen.getByText("Total containers")).toBeInTheDocument());
    const stubs = await screen.findAllByTestId("rechart-stub");
    expect(stubs.length).toBeGreaterThan(0);
  });

  it("shows an error state when fetchStats rejects", async () => {
    const api = await import("@/lib/api");
    vi.mocked(api.fetchStats).mockRejectedValue(new Error("nope"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/Failed to load dashboard stats/i),
    );
  });
});
