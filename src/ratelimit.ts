/// Token buckets, two uses:
///
/// 1. Per-connection message bucket (capacity 10, refill 2/sec → bursts of
///    10 messages, sustained 2 msg/sec). State lives on the WebSocket
///    attachment so it survives Durable Object hibernation: when the DO
///    sleeps and the CF runtime later wakes it on a new frame, the
///    attachment is restored before `webSocketMessage` fires, and
///    `nextTokens` reads the same state. Frames over budget close the WS
///    with code 1008 (policy violation).
///
/// 2. Per-room egress budget (capacity/refill in BYTES, charged at
///    frameBytes × fanout). Held in DO instance memory — see room.ts for
///    why reset-on-hibernation is semantically fine.

export const BUCKET_CAPACITY = 10;
export const REFILL_PER_SEC = 2;

export interface Bucket {
  tokens: number;
  /// Wall-clock millis at last refill. Drives the `(now - updatedMs) *
  /// refillPerSec` token-add calculation.
  updatedMs: number;
}

export function nextTokens(
  prev: Bucket | null,
  nowMs: number,
  capacity: number = BUCKET_CAPACITY,
  refillPerSec: number = REFILL_PER_SEC,
): Bucket {
  const seed = prev ?? { tokens: capacity, updatedMs: nowMs };
  const elapsed = Math.max(0, (nowMs - seed.updatedMs) / 1000);
  const tokens = Math.min(capacity, seed.tokens + elapsed * refillPerSec);
  return { tokens, updatedMs: nowMs };
}

/// `true` when the bucket has at least one whole token. Caller subtracts
/// 1 and re-serializes on the WS attachment.
export function hasToken(bucket: Bucket): boolean {
  return bucket.tokens >= 1;
}

/// Cost-based take for the byte-denominated room budget. Returns the
/// updated bucket, or `null` when the budget can't cover `cost` (caller
/// drops the frame; the bucket keeps its refreshed `updatedMs` via the
/// preceding `nextTokens` call, so refill accrual is unaffected).
export function takeCost(bucket: Bucket, cost: number): Bucket | null {
  if (bucket.tokens < cost) return null;
  return { tokens: bucket.tokens - cost, updatedMs: bucket.updatedMs };
}
