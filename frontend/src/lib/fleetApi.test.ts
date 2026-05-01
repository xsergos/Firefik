import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createEnrollmentToken,
  fetchAgent,
  fetchAgents,
  fetchAgentSnapshot,
  sendAgentCommand,
} from "@/lib/fleetApi";

const originalFetch = globalThis.fetch;

function mockJSON(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
}

function installFetch(impl: typeof fetch) {
  globalThis.fetch = impl as typeof fetch;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("fleetApi", () => {
  it("fetchAgents returns parsed list", async () => {
    installFetch(async () =>
      mockJSON([
        {
          instance_id: "h1",
          hostname: "h1",
          version: "0.1",
          backend: "nft",
          chain: "FF",
          first_seen: "2026-01-01T00:00:00Z",
          last_seen: "2026-01-01T00:01:00Z",
          event_count: 0,
          has_snapshot: false,
          status: "healthy",
        },
      ]),
    );
    const out = await fetchAgents();
    expect(out).toHaveLength(1);
    expect(out[0]?.instance_id).toBe("h1");
    expect(out[0]?.status).toBe("healthy");
  });

  it("fetchAgents tolerates null body", async () => {
    installFetch(async () => mockJSON(null));
    const out = await fetchAgents();
    expect(out).toEqual([]);
  });

  it("fetchAgent returns detail without snapshot", async () => {
    installFetch(async () =>
      mockJSON({
        agent: {
          instance_id: "h1",
          hostname: "h1",
          version: "0.1",
          backend: "nft",
          chain: "FF",
          first_seen: "2026-01-01T00:00:00Z",
          last_seen: "2026-01-01T00:01:00Z",
          event_count: 0,
          has_snapshot: false,
          status: "healthy",
        },
      }),
    );
    const out = await fetchAgent("h1");
    expect(out.snapshot ?? null).toBeNull();
  });

  it("fetchAgentSnapshot parses containers list", async () => {
    installFetch(async () =>
      mockJSON({
        agent: {
          instance_id: "h1",
          hostname: "h1",
          version: "0.1",
          backend: "nft",
          chain: "FF",
          first_seen: "2026-01-01T00:00:00Z",
          last_seen: "2026-01-01T00:01:00Z",
          event_count: 0,
          has_snapshot: true,
          status: "healthy",
        },
        snapshot: {
          agent: { instance_id: "h1", hostname: "h1", version: "0.1", backend: "nft", chain: "FF" },
          containers: [
            {
              id: "c1",
              name: "nginx",
              status: "running",
              firewall_status: "active",
              default_policy: "DROP",
              rule_set_count: 1,
            },
          ],
          at: "2026-01-01T00:00:00Z",
        },
      }),
    );
    const out = await fetchAgentSnapshot("h1");
    expect(out.snapshot?.containers).toHaveLength(1);
    expect(out.snapshot?.containers[0]?.name).toBe("nginx");
  });

  it("sendAgentCommand posts JSON body", async () => {
    let captured: { url: string; init?: RequestInit } | null = null;
    installFetch(async (input, init) => {
      captured = { url: input.toString(), init };
      return mockJSON({ id: "abc", agent_id: "h1", action: "disable" }, { status: 202 });
    });
    const out = await sendAgentCommand("h1", "disable", "container-x");
    expect(out.id).toBe("abc");
    expect(captured!.url).toContain("/api/agents/h1/commands");
    expect(captured!.init?.method).toBe("POST");
    expect(JSON.parse(captured!.init?.body as string)).toEqual({
      action: "disable",
      container_id: "container-x",
    });
  });

  it("throws on non-2xx", async () => {
    installFetch(async () => new Response("forbidden", { status: 403 }));
    await expect(fetchAgents()).rejects.toThrow();
  });

  it("createEnrollmentToken posts and parses", async () => {
    let captured: { url: string; init?: RequestInit } | null = null;
    installFetch(async (input, init) => {
      captured = { url: input.toString(), init };
      return mockJSON({
        token: "abc123",
        agent_id: "host-a",
        expires_at: "2026-05-08T00:00:00Z",
        issued_at: "2026-05-07T23:45:00Z",
      }, { status: 201 });
    });
    const out = await createEnrollmentToken("host-a", 900);
    expect(out.token).toBe("abc123");
    expect(captured!.url).toContain("/api/enrollment-tokens");
    expect(captured!.init?.method).toBe("POST");
    expect(JSON.parse(captured!.init?.body as string)).toEqual({
      agent_id: "host-a",
      ttl_seconds: 900,
    });
  });
});
