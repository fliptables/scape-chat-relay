import type { UpgradeRateLimiter } from "./env";

/// Outcome of the per-IP upgrade rate-limit check. Split so the two
/// rejection modes surface differently (429 vs 503) and so the fail-open
/// vs fail-closed policy below is unit-testable without a live binding.
export type UpgradeLimitDecision =
  | "allow"
  | "reject_rate_limited"
  | "reject_misconfigured";

/// Fail-mode policy (deliberate, reviewed — see README threat model):
///
/// - Binding MISSING while required → fail CLOSED ("reject_misconfigured").
///   wrangler.toml in this repo always configures `[[ratelimits]]`, so an
///   absent binding in production is a broken deploy of a security
///   control, not an availability event. Operators knowingly running on
///   a platform without the binding opt out via
///   `REQUIRE_UPGRADE_LIMITER = "false"` — an explicit, greppable choice.
/// - Client IP header absent → fail OPEN. There is no key to limit on;
///   happens only when Cloudflare isn't fronting the request (local dev,
///   test harnesses).
/// - `limit()` throws at runtime → fail OPEN. A transient limiter error
///   must not take the relay dark; the DO-level per-connection bucket
///   and per-room egress budget still bound what an admitted flood can
///   do (fanout cost — NOT handshake work; see threat model).
export async function checkUpgradeLimit(
  limiter: UpgradeRateLimiter | undefined,
  ip: string | null,
  requireLimiter: boolean,
): Promise<UpgradeLimitDecision> {
  if (limiter === undefined) {
    return requireLimiter ? "reject_misconfigured" : "allow";
  }
  if (ip === null) return "allow";
  try {
    const { success } = await limiter.limit({ key: ip });
    return success ? "allow" : "reject_rate_limited";
  } catch {
    return "allow";
  }
}
