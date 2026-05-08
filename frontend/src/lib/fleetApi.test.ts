import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createEnrollmentToken,
  fetchAgent,
  fetchAgents,
  fetchAgentSnapshot,
  fetchAgentStats,
  fetchFleetStats,
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

  it("fetchFleetStats parses agents/containers/traffic", async () => {
    installFetch(async () =>
      mockJSON({
        agents: { total: 4, healthy: 2, stale: 1, dead: 1, unknown: 0 },
        containers: { total: 9, running: 7, enabled: 5 },
        traffic: [
          { ts: "2026-04-23T10:00:00Z", accepted: 100, dropped: 5 },
          { ts: "2026-04-23T10:01:00Z", accepted: 120, dropped: 8 },
        ],
      }),
    );
    const out = await fetchFleetStats();
    expect(out.agents.total).toBe(4);
    expect(out.containers.running).toBe(7);
    expect(out.traffic).toHaveLength(2);
  });

  it("fetchFleetStats normalises null traffic to empty array", async () => {
    installFetch(async () =>
      mockJSON({
        agents: { total: 0, healthy: 0, stale: 0, dead: 0, unknown: 0 },
        containers: { total: 0, running: 0, enabled: 0 },
        traffic: null,
      }),
    );
    const out = await fetchFleetStats();
    expect(out.traffic).toEqual([]);
  });

  it("fetchAgentStats parses live snapshot", async () => {
    let captured = "";
    installFetch(async (input) => {
      captured = input.toString();
      return mockJSON({
        containers: { total: 3, running: 2, enabled: 1 },
        traffic: [{ ts: "2026-04-23T10:00:00Z", accepted: 1, dropped: 0 }],
        rules_active_containers: 1,
        at: "2026-04-23T10:00:00Z",
      });
    });
    const out = await fetchAgentStats("h%/1");
    expect(out.containers?.total).toBe(3);
    expect(captured).toContain("/api/agents/h%25%2F1/stats");
  });

  it("fetchAgentStats tolerates absent fields", async () => {
    installFetch(async () => mockJSON({}));
    const out = await fetchAgentStats("h1");
    expect(out.containers).toBeUndefined();
    expect(out.traffic).toBeUndefined();
  });

  it("postJSON propagates body-text on non-2xx", async () => {
    installFetch(async () => new Response("nope", { status: 500 }));
    await expect(
      sendAgentCommand("h1", "apply", "c1"),
    ).rejects.toThrow(/nope/);
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
