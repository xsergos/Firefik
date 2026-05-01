import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppShell } from "@/components/layout/AppShell";

let setTheme: ReturnType<typeof vi.fn>;
let resolvedTheme: "light" | "dark";

vi.mock("next-themes", () => ({
  useTheme: () => ({ resolvedTheme, setTheme }),
}));

beforeEach(() => {
  setTheme = vi.fn();
  resolvedTheme = "light";
});

afterEach(() => {
  vi.clearAllMocks();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<div data-testid="outlet-dashboard">Dash</div>} />
          <Route path="containers" element={<div data-testid="outlet-containers">Containers</div>} />
          <Route path="rules" element={<div data-testid="outlet-rules">Rules</div>} />
          <Route path="policies" element={<div data-testid="outlet-policies">Policies</div>} />
          <Route path="proposals" element={<div data-testid="outlet-proposals">Proposals</div>} />
          <Route path="logs" element={<div data-testid="outlet-logs">Logs</div>} />
          <Route path="history" element={<div data-testid="outlet-history">History</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("AppShell", () => {
  it("renders the Firefik brand and all nav links", () => {
    renderAt("/");
    expect(screen.getByText("Firefik")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Containers" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Rules" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Policies" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Proposals" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Logs" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "History" })).toBeInTheDocument();
  });

  it("renders the outlet content for the current route", () => {
    renderAt("/containers");
    expect(screen.getByTestId("outlet-containers")).toBeInTheDocument();
  });

  it("highlights the active route on the dashboard", () => {
    renderAt("/");
    const dashboardLink = screen.getByRole("link", { name: "Dashboard" });
    expect(dashboardLink.className).toMatch(/bg-primary/);
  });

  it("highlights the containers link when on /containers", () => {
    renderAt("/containers");
    const containersLink = screen.getByRole("link", { name: "Containers" });
    expect(containersLink.className).toMatch(/bg-primary/);
    const dashboardLink = screen.getByRole("link", { name: "Dashboard" });
    expect(dashboardLink.className).not.toMatch(/bg-primary/);
  });

  it("uses the main navigation landmark", () => {
    renderAt("/");
    expect(screen.getByRole("navigation", { name: "Main navigation" })).toBeInTheDocument();
  });

  it("shows the dark mode toggle when current theme is light", async () => {
    resolvedTheme = "light";
    renderAt("/");
    const user = userEvent.setup();
    const toggle = screen.getByRole("button", { name: /switch to dark mode/i });
    expect(toggle).toHaveTextContent("Dark mode");
    await user.click(toggle);
    expect(setTheme).toHaveBeenCalledWith("dark");
  });

  it("shows the light mode toggle when current theme is dark", async () => {
    resolvedTheme = "dark";
    renderAt("/");
    const user = userEvent.setup();
    const toggle = screen.getByRole("button", { name: /switch to light mode/i });
    expect(toggle).toHaveTextContent("Light mode");
    await user.click(toggle);
    expect(setTheme).toHaveBeenCalledWith("light");
  });
});
