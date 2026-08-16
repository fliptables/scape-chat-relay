/// The ONLY module in the relay allowed to touch `console` — enforced by
/// scripts/check-invariants.mjs, which fails the build on any console
/// reference outside this file. Centralizing output is what makes the
/// "logs are identifier-free" claim checkable: instead of authenticating
/// helper names at call sites (spoofable), the guard verifies THIS
/// module's four call shapes and both sanitizer bodies structurally.
///
/// The closure is RUNTIME-SEMANTIC, not type-level: parameters are
/// `unknown` and every emitted value is validated at the emit point, so
/// even a caller doing `logWsClose(req.url as any)` — or handing over an
/// Error whose MUTABLE `.name` was set to request-derived text — cannot
/// push identifiers into the log stream. Emitted domain for ANY input:
/// fixed event literals, runtime-verified integers (sentinel -1
/// otherwise), the fixed literal "Error", and `typeof` strings. Proven
/// by runtime unit tests with tainted inputs (test/log.spec.ts), not
/// just asserted.
///
/// Rules the guard enforces on this file (do not "clean up"):
/// - no imports (leaf module — nothing to smuggle values through)
/// - `errClass` body must be exactly the fixed-literal-or-typeof form
///   below — NEVER `err.name`, which is mutable arbitrary text
/// - the ws_close shape must carry the exact integer sanitizer
/// - each console call must match its reviewed shape

/// Log-safe error category. Deliberately NOT `err.name`: `Error.name` is
/// a mutable string (libraries set dynamic names; an adversary can set
/// it to arbitrary text), so the only runtime-closed outputs are our own
/// literal and the fixed set of `typeof` strings.
function errClass(err: unknown): string {
  return err instanceof Error ? "Error" : typeof err;
}

/// A frame was dropped by the room egress budget.
export function logRoomBudgetDrop(): void {
  console.log({ evt: "room_budget_drop" });
}

/// A peer's socket was already dead when fanout tried to send.
export function logDeadPeerDrop(err: unknown): void {
  console.log({ evt: "dead_peer_drop", err: errClass(err) });
}

/// Abnormal WS close (normal closes 1000/1001 are skipped by the caller).
/// `unknown` + runtime integer check: a type annotation is compile-time
/// only and erased by any `as` cast at a call site.
export function logWsClose(code: unknown): void {
  console.log({ evt: "ws_close", code: Number.isInteger(code) ? code : -1 });
}

/// Runtime-reported socket error.
export function logWsError(err: unknown): void {
  console.error({ evt: "ws_error", err: errClass(err) });
}
