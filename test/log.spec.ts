import { afterEach, describe, expect, it, vi } from "vitest";
import { logDeadPeerDrop, logRoomBudgetDrop, logWsClose, logWsError } from "../src/log";

// RUNTIME proof of the logger's closed output domain. The static guard
// (check-invariants.mjs) pins the sanitizer BODIES; these tests prove
// the BEHAVIOR — a type-level claim ("code: number") is erased by an
// `as any` cast, and `Error.name` is mutable arbitrary text, so
// "identifier-free for ANY input" is only true if the emit points
// validate at runtime. Tainted inputs below simulate exactly the two
// ordinary (non-obfuscated) leaks codex demonstrated.

const TAINT = "https://relay.example/room/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?secret=1";

function captured(spy: ReturnType<typeof vi.spyOn>): unknown[] {
  return spy.mock.calls.map((args) => args[0]);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("logger runtime output domain", () => {
  it("logWsClose emits the sentinel, not the value, for a non-integer smuggled past the types", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    logWsClose(TAINT as unknown as number);
    expect(captured(spy)).toEqual([{ evt: "ws_close", code: -1 }]);
    expect(JSON.stringify(captured(spy))).not.toContain("room");
  });

  it("logWsClose passes genuine integer close codes through", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    logWsClose(1006);
    expect(captured(spy)).toEqual([{ evt: "ws_close", code: 1006 }]);
  });

  it("logWsClose sanitizes non-integer numbers too", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    logWsClose(10.5);
    expect(captured(spy)).toEqual([{ evt: "ws_close", code: -1 }]);
  });

  it("logWsError never emits a tainted Error.name", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const e = new Error("boom");
    e.name = TAINT; // Error.name is mutable arbitrary text
    logWsError(e);
    expect(captured(spy)).toEqual([{ evt: "ws_error", err: "Error" }]);
    expect(JSON.stringify(captured(spy))).not.toContain("room");
  });

  it("logWsError emits the fixed literal for Error subclasses with dynamic names", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    class Weird extends Error {
      override name = TAINT;
    }
    logWsError(new Weird());
    expect(captured(spy)).toEqual([{ evt: "ws_error", err: "Error" }]);
  });

  it("logDeadPeerDrop emits only typeof strings for non-Error inputs", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    logDeadPeerDrop(TAINT); // a raw tainted string thrown as an error value
    expect(captured(spy)).toEqual([{ evt: "dead_peer_drop", err: "string" }]);
    expect(JSON.stringify(captured(spy))).not.toContain("room");
  });

  it("logRoomBudgetDrop emits the fixed literal only", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    logRoomBudgetDrop();
    expect(captured(spy)).toEqual([{ evt: "room_budget_drop" }]);
  });
});
