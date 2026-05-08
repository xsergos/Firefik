import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AgentLogsPanel } from "./AgentLogsPanel";

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  closed = false;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  close() {
    this.closed = true;
    this.onclose?.();
  }
}

afterEach(() => {
  FakeWebSocket.instances.length = 0;
  vi.unstubAllGlobals();
});

describe("AgentLogsPanel", () => {
  it("opens a websocket against /api/agents/:id/logs and shows status", () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    render(<AgentLogsPanel agentID="host%a" />);
    expect(FakeWebSocket.instances).toHaveLength(1);
    const ws = FakeWebSocket.instances[0]!;
    expect(ws.url).toContain("/api/agents/host%25a/logs");
    expect(screen.getByText(/connecting/)).toBeInTheDocument();

    act(() => ws.onopen?.());
    expect(screen.getByText(/open/)).toBeInTheDocument();
  });

  it("appends parsed log lines and keeps the rolling buffer", () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    render(<AgentLogsPanel agentID="h1" />);
    const ws = FakeWebSocket.instances[0]!;
    act(() => ws.onopen?.());

    act(() => {
      ws.onmessage?.({
        data: JSON.stringify({
          agent: { instance_id: "h1", hostname: "h1" },
          at: "2026-04-23T10:00:00Z",
          level: "info",
          source: "rules",
          line: "applied",
        }),
      });
    });
    expect(screen.getByText(/1 lines/)).toBeInTheDocument();

    act(() => ws.onmessage?.({ data: "{not-json" }));
    expect(screen.getByText(/1 lines/)).toBeInTheDocument();
  });

  it("renders a closed status when the websocket closes", () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    const { unmount } = render(<AgentLogsPanel agentID="h1" />);
    const ws = FakeWebSocket.instances[0]!;
    act(() => ws.onerror?.());
    expect(screen.getByText(/error/)).toBeInTheDocument();
    unmount();
    expect(ws.closed).toBe(true);
  });

  it("does nothing when agentID is empty", () => {
    vi.stubGlobal("WebSocket", FakeWebSocket as unknown as typeof WebSocket);
    render(<AgentLogsPanel agentID="" />);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });
});
