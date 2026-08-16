import { describe, expect, it } from "vitest";
import {
  BUCKET_CAPACITY,
  hasToken,
  nextTokens,
  REFILL_PER_SEC,
  takeCost,
} from "../src/ratelimit";

// Pure-function tests for the bucket math. The attachment round-trip
// (survival across DO hibernation) is covered by the runtime contract —
// what matters here is that the arithmetic a restored bucket flows
// through is correct for any stored (tokens, updatedMs) pair.

describe("nextTokens", () => {
  it("seeds a full bucket when no prior state exists", () => {
    const b = nextTokens(null, 1_000_000);
    expect(b.tokens).toBe(BUCKET_CAPACITY);
    expect(b.updatedMs).toBe(1_000_000);
  });

  it("refills fractionally: 500 ms → exactly 1.0 token at 2/s", () => {
    const b = nextTokens({ tokens: 0, updatedMs: 0 }, 500);
    expect(b.tokens).toBe(REFILL_PER_SEC * 0.5);
  });

  it("clamps refill at capacity after a long idle (hibernation return)", () => {
    // A bucket restored after hours of hibernation must not exceed cap.
    const b = nextTokens({ tokens: 3, updatedMs: 0 }, 6 * 60 * 60 * 1000);
    expect(b.tokens).toBe(BUCKET_CAPACITY);
  });

  it("treats wall-clock regression as zero elapsed (no free tokens, no NaN)", () => {
    const b = nextTokens({ tokens: 4, updatedMs: 10_000 }, 5_000);
    expect(b.tokens).toBe(4);
    expect(b.updatedMs).toBe(5_000);
  });

  it("honors custom capacity/refill for the room egress budget", () => {
    const b = nextTokens({ tokens: 0, updatedMs: 0 }, 2_000, 1_000_000, 250_000);
    expect(b.tokens).toBe(500_000);
    const clamped = nextTokens({ tokens: 0, updatedMs: 0 }, 60_000, 1_000_000, 250_000);
    expect(clamped.tokens).toBe(1_000_000);
  });
});

describe("hasToken", () => {
  it("requires at least one whole token", () => {
    expect(hasToken({ tokens: 1, updatedMs: 0 })).toBe(true);
    expect(hasToken({ tokens: 0.99, updatedMs: 0 })).toBe(false);
  });
});

describe("takeCost", () => {
  it("subtracts the cost when covered", () => {
    const b = takeCost({ tokens: 100, updatedMs: 7 }, 60);
    expect(b).toEqual({ tokens: 40, updatedMs: 7 });
  });

  it("returns null when the cost exceeds the balance", () => {
    expect(takeCost({ tokens: 59, updatedMs: 7 }, 60)).toBeNull();
  });

  it("allows an exact drain to zero", () => {
    expect(takeCost({ tokens: 60, updatedMs: 7 }, 60)).toEqual({
      tokens: 0,
      updatedMs: 7,
    });
  });
});
