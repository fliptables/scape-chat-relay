/// Shared HTTP-upgrade helpers for the Worker front door and the room DO.
/// Kept dependency-free so both can import without cycles.

/// RFC 9110: `Upgrade` is a comma-separated list of case-insensitive
/// protocol tokens. Browsers send `websocket`, but `WebSocket` (and a
/// multi-token list) are equally valid — a case-sensitive `!==` compare
/// would spuriously reject conforming clients.
export function upgradeIncludesWebSocket(headerValue: string | null): boolean {
  if (headerValue === null) return false;
  return headerValue
    .split(",")
    .some((token) => token.trim().toLowerCase() === "websocket");
}
