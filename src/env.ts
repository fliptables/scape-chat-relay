import type { RoomDurableObject } from "./room";

/// Cloudflare's rate-limiting binding (see `[[ratelimits]]` in
/// wrangler.toml). Declared structurally so the code compiles against
/// workers-types versions that predate the built-in `RateLimit` type.
export interface UpgradeRateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/// Bindings exposed by `wrangler.toml`.
export interface Env {
  /// Per-room Durable Object namespace.
  ROOMS: DurableObjectNamespace<RoomDurableObject>;
  /// Per-IP WebSocket-upgrade rate limiter. Optional in the TYPE because
  /// test harnesses can't materialize `[[ratelimits]]` — but production
  /// defaults FAIL-CLOSED: a missing binding rejects upgrades with 503
  /// unless REQUIRE_UPGRADE_LIMITER="false" explicitly opts out (see
  /// src/admission.ts for the full fail-mode split; runtime limit()
  /// errors and a missing client-IP header are the only fail-OPEN paths).
  UPGRADES?: UpgradeRateLimiter;
  /// Operator overrides for the per-room egress budget (see wrangler.toml
  /// `[vars]`). Strings because wrangler vars are strings; parsed with
  /// clamped fallbacks in room.ts.
  ROOM_EGRESS_CAPACITY_BYTES?: string;
  ROOM_EGRESS_REFILL_BYTES_PER_SEC?: string;
  /// Fail-mode switch for the upgrade limiter (see admission.ts). Any
  /// value other than the literal "false" means REQUIRED: a missing
  /// UPGRADES binding rejects upgrades with 503 (misconfigured security
  /// control) instead of silently admitting everyone. wrangler.toml
  /// ships "true"; test harnesses set "false" because the nested test
  /// runtime does not materialize `[[ratelimits]]` bindings.
  REQUIRE_UPGRADE_LIMITER?: string;
}
