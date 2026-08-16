import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { checkUpgradeLimit } from "../src/admission";
import type { UpgradeRateLimiter } from "../src/env";

// COVERAGE NOTE: the nested test runtime (vitest-pool-workers' bundled
// Wrangler/Miniflare) does not materialize `[[ratelimits]]` bindings, so
// the limiter cannot be integration-tested through SELF.fetch here —
// vitest.config.ts sets REQUIRE_UPGRADE_LIMITER="false" for that reason.
// The full fail-open/fail-closed decision matrix is proven below against
// stub limiters instead, and the "documents the runtime gap" test pins
// the actual binding state so a future toolchain that DOES materialize
// the binding flips it loudly (at which point add a real integration
// test and drop the opt-out).

const allow: UpgradeRateLimiter = { limit: async () => ({ success: true }) };
const deny: UpgradeRateLimiter = { limit: async () => ({ success: false }) };
const broken: UpgradeRateLimiter = {
  limit: async () => {
    throw new Error("limiter unavailable");
  },
};

describe("checkUpgradeLimit fail-mode matrix", () => {
  it("fails CLOSED when a required binding is missing (misconfigured deploy)", async () => {
    expect(await checkUpgradeLimit(undefined, "1.2.3.4", true)).toBe(
      "reject_misconfigured",
    );
  });

  it("admits when the binding is missing but explicitly not required", async () => {
    expect(await checkUpgradeLimit(undefined, "1.2.3.4", false)).toBe("allow");
  });

  it("fails OPEN when no client IP header exists (nothing to key on)", async () => {
    expect(await checkUpgradeLimit(deny, null, true)).toBe("allow");
  });

  it("admits under the limit", async () => {
    expect(await checkUpgradeLimit(allow, "1.2.3.4", true)).toBe("allow");
  });

  it("rejects over the limit", async () => {
    expect(await checkUpgradeLimit(deny, "1.2.3.4", true)).toBe(
      "reject_rate_limited",
    );
  });

  it("fails OPEN on a runtime limiter error (availability over strictness)", async () => {
    expect(await checkUpgradeLimit(broken, "1.2.3.4", true)).toBe("allow");
  });
});

describe("limiter binding state in the nested test runtime", () => {
  it("documents the integration-coverage gap (binding not materialized)", () => {
    // If this starts failing, the toolchain now materializes
    // [[ratelimits]] — add a real SELF.fetch integration test for 429
    // + Retry-After and remove REQUIRE_UPGRADE_LIMITER="false" from
    // vitest.config.ts.
    expect((env as { UPGRADES?: unknown }).UPGRADES).toBeUndefined();
  });
});
