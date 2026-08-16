import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        // Required for WS + DO tests: a single shared worker so DO state
        // is visible across the test's two simulated clients, and shared
        // storage so peers in the same room can find each other.
        singleWorker: true,
        isolatedStorage: false,
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // Tiny room egress budget so the budget path is testable
          // without moving megabytes. Kept in sync with
          // TEST_EGRESS_CAPACITY in test/room.spec.ts.
          bindings: {
            ROOM_EGRESS_CAPACITY_BYTES: "100000",
            ROOM_EGRESS_REFILL_BYTES_PER_SEC: "1000",
            // The nested test runtime does not materialize
            // `[[ratelimits]]` bindings, so the limiter would fail
            // CLOSED under the production default and 503 every test
            // upgrade. Explicit opt-out here; the fail-mode matrix is
            // unit-tested in test/admission.spec.ts and the coverage
            // gap is documented there.
            REQUIRE_UPGRADE_LIMITER: "false",
          },
        },
      },
    },
  },
});
