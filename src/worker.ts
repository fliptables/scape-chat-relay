import { checkUpgradeLimit } from "./admission";
import type { Env } from "./env";
import { upgradeIncludesWebSocket } from "./http";
export { RoomDurableObject } from "./room";

/// roomId intake, DUAL-MECHANISM for one release (IT-613 migration):
///
/// NEW (preferred): `GET /connect` with `X-Scape-Room: <64-lowercase-hex>`.
/// Moving the roomId out of the URL path keeps it out of every layer
/// that logs URLs (Cloudflare invocation logs, `wrangler tail`, proxy
/// access logs) — safe by construction instead of by config default.
///
/// LEGACY (remove NEXT release): `GET /room/<64-lowercase-hex>`. Kept
/// one release so un-updated clients — and updated clients talking to
/// this relay while still probing others — keep working. The Swift
/// client connects header-first and falls back per relay only when
/// `/connect` 404s (pre-migration deploys).
///
/// The roomId value grammar is identical in both positions: the Swift
/// client computes
/// `roomId = SHA-256("scape-roomid-v2|" || lp(name) || lp(password))`
/// → 64 lowercase hex chars. (Binding the password into the roomId makes
/// typo'd-password peers route to a different DO; see
/// ChatRoomIdentity.swift.) Anchored `^…$` so wrong length, uppercase,
/// extra segments, dot-segments, and percent-encoded slashes all miss.
///
/// Both-present rule (legacy path + header on one request): EQUAL →
/// accept; DIFFERENT (or malformed header) → 404, byte-identical to the
/// bad-path 404 — fail closed on ambiguity, reveal nothing
/// (enumeration-safety). The relay must never route to one roomId while
/// a URL observer sees another.
const CONNECT_PATH = "/connect";
const ROOM_HEADER = "X-Scape-Room";
const ROOM_ID = /^[0-9a-f]{64}$/;
const ROUTE = /^\/room\/([0-9a-f]{64})$/;

/// Resolve the roomId from the dual intake, or undefined when the
/// request matches neither mechanism (or matches both, inconsistently).
function resolveRoomId(pathname: string, headerValue: string | null): string | undefined {
  if (pathname === CONNECT_PATH) {
    if (headerValue !== null && ROOM_ID.test(headerValue)) return headerValue;
    return undefined;
  }
  const fromPath = pathname.match(ROUTE)?.[1];
  if (fromPath !== undefined) {
    if (headerValue === null) return fromPath; // legacy client
    return headerValue === fromPath ? fromPath : undefined; // ambiguity → fail closed
  }
  return undefined;
}

export default {
  async fetch(req, env): Promise<Response> {
    const url = new URL(req.url);
    const roomId = resolveRoomId(url.pathname, req.headers.get(ROOM_HEADER));
    // Reject any query string outright: the client never sends one, and
    // accepting stray parameters on a public endpoint invites abuse of
    // future meaning-drift. Strict-by-default.
    if (roomId === undefined || url.search !== "") {
      return new Response("not found", { status: 404 });
    }
    // WS upgrades are GET by spec (RFC 6455 §4.1).
    if (req.method !== "GET") {
      return new Response("method not allowed", { status: 405 });
    }
    if (!upgradeIncludesWebSocket(req.headers.get("Upgrade"))) {
      return new Response("expected websocket", { status: 426 });
    }
    // Browsers always attach an Origin header to WebSocket handshakes;
    // the Scape native client (URLSession) never does. Rejecting
    // Origin-bearing upgrades closes the drive-by vector where a hostile
    // web page makes its visitors' browsers open relay connections
    // (distributed abuse that per-IP limits can't catch). If a web client
    // is ever supported, this becomes an allowlist — deliberate contract
    // decision, see README threat model.
    if (req.headers.get("Origin") !== null) {
      return new Response("browser origins not supported", { status: 403 });
    }
    // Per-IP upgrade rate limit (sizing rationale in wrangler.toml;
    // fail-open/fail-closed policy in admission.ts — missing binding
    // fails CLOSED unless explicitly opted out, runtime errors and a
    // missing IP header fail OPEN). Best-effort by nature: Cloudflare's
    // rate-limiting binding counts per CF location, not globally — see
    // README threat model for the residuals. The IP is used only as the
    // limiter key; nothing is logged or stored by this Worker.
    const decision = await checkUpgradeLimit(
      env.UPGRADES,
      req.headers.get("CF-Connecting-IP"),
      env.REQUIRE_UPGRADE_LIMITER !== "false",
    );
    if (decision === "reject_misconfigured") {
      return new Response("limiter_misconfigured", { status: 503 });
    }
    if (decision === "reject_rate_limited") {
      return new Response("too many connection attempts", {
        status: 429,
        headers: { "Retry-After": "60" },
      });
    }
    // idFromName is deterministic — same roomId → same DO instance, even
    // across reconnects. That's how peers find each other in the same
    // room without any external coordination.
    const stub = env.ROOMS.get(env.ROOMS.idFromName(roomId));
    return stub.fetch(req);
  },
} satisfies ExportedHandler<Env>;
