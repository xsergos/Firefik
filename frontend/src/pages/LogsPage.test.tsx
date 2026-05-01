import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LogsPage from "./LogsPage";

vi.mock("sonner", () => ({
  toast: {
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
    success: vi.fn(),
    dismiss: vi.fn(),
  },
}));

type Listener = (ev: MessageEvent<string>) => void;
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readyState = 0;
  url: string;
  onopen: (() => void) | null = null;
  onmessage: Listener | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
  }
}

let originalWebSocket: typeof WebSocket;

beforeEach(() => {
  originalWebSocket = globalThis.WebSocket;
  Object.defineProperty(globalThis, "WebSocket", {
    configurable: true,
    value: FakeWebSocket,
  });
  FakeWebSocket.instances = [];
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  Object.defineProperty(globalThis, "WebSocket", {
    configurable: true,
    value: originalWebSocket,
  });
  vi.clearAllMocks();
});

function mostRecentWS(): FakeWebSocket {
  const last = FakeWebSocket.instances.at(-1);
  if (!last) throw new Error("no fake websocket created yet");
  return last;
}

describe("LogsPage", () => {
  it("renders heading and disconnected badge before the socket opens", () => {
    render(<LogsPage />);
    expect(screen.getByRole("heading", { name: /Live Logs/i })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Disconnected");
    expect(screen.getByText(/Waiting for firewall events/i)).toBeInTheDocument();
  });

  it("flips the badge to Connected once the socket opens", () => {
    render(<LogsPage />);
    const ws = mostRecentWS();
    act(() => ws.onopen?.());
    expect(screen.getByRole("status")).toHaveTextContent("Connected");
  });

  it("renders an incoming log entry with action, srcIP, port, container, and proto", () => {
    render(<LogsPage />);
    const ws = mostRecentWS();
    act(() => {
      ws.onopen?.();
      ws.onmessage?.(
        new MessageEvent("message", {
          data: JSON.stringify({
            ts: "2026-04-23T10:00:00Z",
            action: "DROP",
            srcIP: "1.2.3.4",
            dstPort: 443,
            container: "nginx",
            proto: "tcp",
          }),
        }),
      );
    });
    expect(screen.getByText("DROP")).toBeInTheDocument();
    expect(screen.getByText("1.2.3.4")).toBeInTheDocument();
    expect(screen.getByText(":443")).toBeInTheDocument();
    expect(screen.getByText("nginx")).toBeInTheDocument();
    expect(screen.getByText("tcp")).toBeInTheDocument();
  });

  it("displays both ACCEPT and DROP rows in reverse-chronological order", () => {
    render(<LogsPage />);
    const ws = mostRecentWS();
    act(() => {
      ws.onopen?.();
      ws.onmessage?.(
        new MessageEvent("message", {
          data: JSON.stringify({ ts: "2026-04-23T10:00:00Z", action: "DROP", srcIP: "9.9.9.9" }),
        }),
      );
      ws.onmessage?.(
        new MessageEvent("message", {
          data: JSON.stringify({ ts: "2026-04-23T10:00:01Z", action: "ACCEPT", srcIP: "8.8.8.8" }),
        }),
      );
    });
    expect(screen.getByText("ACCEPT")).toBeInTheDocument();
    expect(screen.getByText("DROP")).toBeInTheDocument();
    expect(screen.getByText("9.9.9.9")).toBeInTheDocument();
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
  });
});
