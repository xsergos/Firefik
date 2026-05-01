import { describe, expect, it } from "vitest";
import { isValidInstanceID, isValidHTTPURL, isValidGRPCEndpoint } from "@/lib/enrollValidators";

describe("isValidInstanceID", () => {
  it("accepts DNS-label format", () => {
    expect(isValidInstanceID("host-prod-01")).toBe(true);
    expect(isValidInstanceID("abc")).toBe(true);
    expect(isValidInstanceID("a".repeat(63))).toBe(true);
  });
  it("rejects too-short, too-long, uppercase, special chars", () => {
    expect(isValidInstanceID("ab")).toBe(false);
    expect(isValidInstanceID("a".repeat(64))).toBe(false);
    expect(isValidInstanceID("Host")).toBe(false);
    expect(isValidInstanceID("host_a")).toBe(false);
    expect(isValidInstanceID("host.a")).toBe(false);
    expect(isValidInstanceID("host!")).toBe(false);
    expect(isValidInstanceID("")).toBe(false);
  });
});

describe("isValidHTTPURL", () => {
  it("accepts valid https/http URLs", () => {
    expect(isValidHTTPURL("https://cp.example.com")).toBe(true);
    expect(isValidHTTPURL("https://cp.example.com:8443")).toBe(true);
    expect(isValidHTTPURL("http://10.0.0.1:8080")).toBe(true);
    expect(isValidHTTPURL("https://cp.example.com/path/to/api")).toBe(true);
  });
  it("rejects shell-special chars and exotic protocols", () => {
    expect(isValidHTTPURL(`https://cp.example.com"; rm -rf /`)).toBe(false);
    expect(isValidHTTPURL("https://cp.example.com$(whoami)")).toBe(false);
    expect(isValidHTTPURL("https://cp.example.com`id`")).toBe(false);
    expect(isValidHTTPURL("https://cp.example.com'")).toBe(false);
    expect(isValidHTTPURL("file:///etc/passwd")).toBe(false);
    expect(isValidHTTPURL("javascript:alert(1)")).toBe(false);
    expect(isValidHTTPURL("ftp://cp.example.com")).toBe(false);
    expect(isValidHTTPURL("not a url")).toBe(false);
    expect(isValidHTTPURL("")).toBe(false);
  });
});

describe("isValidGRPCEndpoint", () => {
  it("accepts DNS:port and IP:port", () => {
    expect(isValidGRPCEndpoint("cp.example.com:8444")).toBe(true);
    expect(isValidGRPCEndpoint("10.0.0.1:8444")).toBe(true);
    expect(isValidGRPCEndpoint("localhost:1")).toBe(true);
    expect(isValidGRPCEndpoint("h:65535")).toBe(true);
  });
  it("rejects missing port, out-of-range port, schemes, shell chars", () => {
    expect(isValidGRPCEndpoint("cp.example.com")).toBe(false);
    expect(isValidGRPCEndpoint("cp.example.com:")).toBe(false);
    expect(isValidGRPCEndpoint("cp.example.com:0")).toBe(false);
    expect(isValidGRPCEndpoint("cp.example.com:99999")).toBe(false);
    expect(isValidGRPCEndpoint("cp.example.com:65536")).toBe(false);
    expect(isValidGRPCEndpoint("https://cp.example.com:8444")).toBe(false);
    expect(isValidGRPCEndpoint("cp.example.com:8444; rm")).toBe(false);
    expect(isValidGRPCEndpoint("")).toBe(false);
  });
});
