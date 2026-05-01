const INSTANCE_ID_RE = /^[a-z0-9-]{3,63}$/;
const HTTP_URL_RE = /^https?:\/\/[a-zA-Z0-9.-]+(?::\d{1,5})?(?:\/[\w./~:-]*)?$/;
const GRPC_ENDPOINT_RE = /^[a-zA-Z0-9.-]+:\d{1,5}$/;

export function isValidInstanceID(s: string): boolean {
  return INSTANCE_ID_RE.test(s);
}

export function isValidHTTPURL(s: string): boolean {
  if (!HTTP_URL_RE.test(s)) return false;
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

export function isValidGRPCEndpoint(s: string): boolean {
  if (!GRPC_ENDPOINT_RE.test(s)) return false;
  const colon = s.lastIndexOf(":");
  const port = Number(s.slice(colon + 1));
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}
