import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

// roomId is just a 64-char hex routing key for these tests; we don't
// need real SHA-256 here — the Worker only validates regex shape.
const ROOM_A = "a".repeat(64);

// vitest.config.ts injects a tiny room egress budget (capacity 100 000
// bytes, refill 1 000/s) so the budget path is testable without moving
// megabytes. Keep in sync with the miniflare bindings there.
const TEST_EGRESS_CAPACITY = 100_000;

let roomCounter = 0;
/// A fresh room per test that needs isolation — the suite runs in a
/// single worker with shared storage, so reusing ROOM_A across tests
/// would leak peers (and drained rate-limit buckets) between tests.
function freshRoom(): string {
  roomCounter += 1;
  return roomCounter.toString(16).padStart(64, "0");
}

async function upgrade(
  roomId: string,
  init?: { headers?: Record<string, string>; method?: string },
): Promise<Response> {
  return SELF.fetch(`https://example.com/room/${roomId}`, {
    method: init?.method ?? "GET",
    headers: { Upgrade: "websocket", ...init?.headers },
  });
}

/// Header-mechanism upgrade (IT-613 dual window): GET /connect with the
/// roomId in X-Scape-Room instead of the path.
async function headerUpgrade(
  roomId: string | null,
  init?: { headers?: Record<string, string> },
): Promise<Response> {
  return SELF.fetch("https://example.com/connect", {
    headers: {
      Upgrade: "websocket",
      ...(roomId !== null ? { "X-Scape-Room": roomId } : {}),
      ...init?.headers,
    },
  });
}

// The exact capability hello every socket must receive FIRST. It is a
// BINARY frame (IT-613 ce:review P1 — relay-authored control is binary
// and unforgeable by peers). Asserting the decoded bytes on every open
// also proves the hello is identical for empty vs occupied rooms (peers
// 2..N join occupied ones): it reveals capabilities, not room state.
const RELAY_HELLO = JSON.stringify({ v: 2, type: "relay_hello", caps: ["ack"] });
const DECODER = new TextDecoder();

/// Await the next BINARY (relay-authored control) frame, decoded to its
/// JSON string. Rejects if a text frame arrives first (control must be
/// binary).
function nextControl(ws: WebSocket, timeoutMs = 2000): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
    ws.addEventListener(
      "message",
      (event) => {
        clearTimeout(timer);
        if (event.data instanceof ArrayBuffer) resolve(DECODER.decode(event.data));
        else reject(new Error(`expected binary control frame, got ${typeof event.data}`));
      },
      { once: true },
    );
  });
}

async function openSocket(roomId: string): Promise<WebSocket> {
  const res = await upgrade(roomId);
  expect(res.status).toBe(101);
  const ws = res.webSocket as WebSocket;
  expect(ws).toBeTruthy();
  ws.accept();
  expect(await nextControl(ws)).toBe(RELAY_HELLO);
  return ws;
}

async function openHeaderSocket(roomId: string): Promise<WebSocket> {
  const res = await headerUpgrade(roomId);
  expect(res.status).toBe(101);
  const ws = res.webSocket as WebSocket;
  expect(ws).toBeTruthy();
  ws.accept();
  expect(await nextControl(ws)).toBe(RELAY_HELLO);
  return ws;
}

/// Await the next TEXT app frame, SKIPPING binary control frames — for a
/// socket that also receives acks for its own earlier sends (those acks
/// are binary and interleave with fanned text). A peer's fanned message
/// is the only text a socket receives besides "pong".
function nextAppMessage(ws: WebSocket, timeoutMs = 2000): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
    const listener = (event: MessageEvent) => {
      if (event.data instanceof ArrayBuffer) return; // binary control — skip
      clearTimeout(timer);
      ws.removeEventListener("message", listener);
      if (typeof event.data === "string") resolve(event.data);
      else reject(new Error("expected text frame"));
    };
    ws.addEventListener("message", listener);
  });
}

function nextMessage(ws: WebSocket, timeoutMs = 2000): Promise<string> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
    ws.addEventListener(
      "message",
      (event) => {
        clearTimeout(timer);
        if (typeof event.data === "string") resolve(event.data);
        else reject(new Error("expected text frame"));
      },
      { once: true },
    );
  });
}

/// Negative delivery proof without a fixed-sleep race: `mustNotReceive`
/// installs its listener BEFORE the caller triggers the send, then the
/// caller races it against a positive signal that necessarily happens
/// AFTER the forbidden delivery would have (e.g. a later frame arriving
/// on the same room, which the DO fans out in send order). `isForbidden`
/// filters out frames the socket legitimately receives during the test;
/// omit it when ANY delivery is a violation.
function mustNotReceive(
  ws: WebSocket,
  label: string,
  isForbidden: (data: string) => boolean = () => true,
): { assertClean(): void } {
  let received: string | null = null;
  ws.addEventListener("message", (event) => {
    const data = typeof event.data === "string" ? event.data : "<binary>";
    if (received === null && isForbidden(data)) received = data;
  });
  return {
    assertClean() {
      if (received !== null) {
        throw new Error(`${label}: unexpectedly received ${received}`);
      }
    },
  };
}

function closeCode(ws: WebSocket): Promise<number> {
  return new Promise((resolve) => {
    ws.addEventListener("close", (e) => resolve(e.code), { once: true });
  });
}

describe("Worker routing", () => {
  it("rejects non-WS requests with 426", async () => {
    const res = await SELF.fetch(`https://example.com/room/${ROOM_A}`);
    expect(res.status).toBe(426);
  });

  it("accepts a mixed-case Upgrade header value", async () => {
    const res = await upgrade(freshRoom(), { headers: { Upgrade: "WebSocket" } });
    expect(res.status).toBe(101);
  });

  it("rejects non-GET requests with 405", async () => {
    // NOTE: a POST that also carries `Upgrade: websocket` is normalized
    // by the runtime into a WS handshake (workerd treats the Upgrade
    // header as authoritative and the Worker observes method GET), so
    // the method guard is exercised via a plain POST. It remains as
    // defense in depth for runtimes that pass the method through.
    const res = await SELF.fetch(`https://example.com/room/${ROOM_A}`, {
      method: "POST",
    });
    expect(res.status).toBe(405);
  });

  it("rejects Origin-bearing upgrades with 403 (no browser clients)", async () => {
    const res = await upgrade(ROOM_A, {
      headers: { Origin: "https://evil.example" },
    });
    expect(res.status).toBe(403);
  });

  it("rejects malformed paths with 404", async () => {
    const cases = [
      "/room/notlongenough",
      `/room/${"A".repeat(64)}`, // uppercase hex
      `/room/${"a".repeat(63)}`, // one short
      `/room/${"a".repeat(65)}`, // one long
      `/room/${ROOM_A}/extra`, // extra segment
      // NOTE: dot segments normalize during URL parsing BEFORE the regex
      // sees the pathname (`/room/X/../X` → `/room/X`) — an equivalent
      // path, not a bypass. This case normalizes to `/room` → 404.
      `/room/${ROOM_A}/..`,
      `/rooms/${ROOM_A}`, // wrong prefix
      `/room/${"g".repeat(64)}`, // non-hex
    ];
    for (const path of cases) {
      const res = await SELF.fetch(`https://example.com${path}`, {
        headers: { Upgrade: "websocket" },
      });
      expect(res.status, path).toBe(404);
    }
  });

  it("rejects query strings with 404", async () => {
    const res = await SELF.fetch(
      `https://example.com/room/${ROOM_A}?x=1`,
      { headers: { Upgrade: "websocket" } },
    );
    expect(res.status).toBe(404);
  });
});

describe("roomId dual intake (IT-613 migration window)", () => {
  it("accepts header-only connects and fans out between two header peers", async () => {
    const room = freshRoom();
    const a = await openHeaderSocket(room);
    const b = await openHeaderSocket(room);
    const bRecv = nextMessage(b);
    a.send("header-to-header");
    expect(await bRecv).toBe("header-to-header");
    a.close();
    b.close();
  });

  it("MUST-PASS: a header peer and a legacy-URL peer with the same roomId share one room", async () => {
    const room = freshRoom();
    const viaHeader = await openHeaderSocket(room);
    const viaPath = await openSocket(room);

    // Both directions — routing equivalence, not one-way luck.
    const pathRecv = nextMessage(viaPath);
    viaHeader.send("from-header-peer");
    expect(await pathRecv).toBe("from-header-peer");

    const headerRecv = nextAppMessage(viaHeader);
    viaPath.send("from-path-peer");
    expect(await headerRecv).toBe("from-path-peer");

    viaHeader.close();
    viaPath.close();
  });

  it("accepts both-present when the header equals the path id", async () => {
    const room = freshRoom();
    const res = await upgrade(room, { headers: { "X-Scape-Room": room } });
    expect(res.status).toBe(101);
    const ws = res.webSocket as WebSocket;
    ws.accept();
    ws.close();
  });

  it("rejects both-present mismatch with a 404 byte-identical to bad-path (fail closed)", async () => {
    const other = freshRoom();
    const mismatch = await upgrade(ROOM_A, { headers: { "X-Scape-Room": other } });
    const badPath = await SELF.fetch("https://example.com/room/notahexid", {
      headers: { Upgrade: "websocket" },
    });
    expect(mismatch.status).toBe(404);
    expect(await mismatch.text()).toBe(await badPath.text());
    expect([...mismatch.headers.entries()].sort()).toEqual(
      [...badPath.headers.entries()].sort(),
    );
  });

  it("rejects /connect with no header, byte-identical to bad-path", async () => {
    const bare = await headerUpgrade(null);
    const badPath = await SELF.fetch("https://example.com/room/notahexid", {
      headers: { Upgrade: "websocket" },
    });
    expect(bare.status).toBe(404);
    expect(await bare.text()).toBe(await badPath.text());
    expect([...bare.headers.entries()].sort()).toEqual(
      [...badPath.headers.entries()].sort(),
    );
  });

  it("rejects malformed header values with 404", async () => {
    for (const bad of ["A".repeat(64), "a".repeat(63), "a".repeat(65), "g".repeat(64)]) {
      const res = await headerUpgrade(bad);
      expect(res.status, bad).toBe(404);
    }
  });

  it("rejects a valid legacy path carrying a MALFORMED header with 404", async () => {
    const res = await upgrade(ROOM_A, { headers: { "X-Scape-Room": "not-hex" } });
    expect(res.status).toBe(404);
  });

  it("rejects duplicate X-Scape-Room headers with 404 (comma-join fails the grammar)", async () => {
    // Headers.get comma-joins duplicates — even two IDENTICAL valid
    // values become "<id>, <id>", which cannot match the anchored
    // 64-hex regex. Conservative fail-closed, pinned here.
    const headers = new Headers({ Upgrade: "websocket" });
    headers.append("X-Scape-Room", ROOM_A);
    headers.append("X-Scape-Room", ROOM_A);
    const dupSame = await SELF.fetch("https://example.com/connect", { headers });
    expect(dupSame.status).toBe(404);

    const mixed = new Headers({ Upgrade: "websocket" });
    mixed.append("X-Scape-Room", ROOM_A);
    mixed.append("X-Scape-Room", "b".repeat(64));
    const dupDiff = await SELF.fetch("https://example.com/connect", { headers: mixed });
    expect(dupDiff.status).toBe(404);
  });

  it("accepts a lowercase header NAME (header names are case-insensitive)", async () => {
    const room = freshRoom();
    const res = await SELF.fetch("https://example.com/connect", {
      headers: { Upgrade: "websocket", "x-scape-room": room },
    });
    expect(res.status).toBe(101);
    const ws = res.webSocket as WebSocket;
    ws.accept();
    ws.close();
  });

  it("rejects near-miss /connect path shapes with 404", async () => {
    for (const path of ["/Connect", "/connect/", "/%63onnect", "//connect", "/connect/x"]) {
      const res = await SELF.fetch(`https://example.com${path}`, {
        headers: { Upgrade: "websocket", "X-Scape-Room": ROOM_A },
      });
      expect(res.status, path).toBe(404);
    }
  });

  it("applies the same admission checks on /connect (Origin 403, non-GET 405, no-upgrade 426)", async () => {
    const origin = await headerUpgrade(ROOM_A, {
      headers: { Origin: "https://evil.example" },
    });
    expect(origin.status).toBe(403);

    const post = await SELF.fetch("https://example.com/connect", {
      method: "POST",
      headers: { "X-Scape-Room": ROOM_A },
    });
    expect(post.status).toBe(405);

    const noUpgrade = await SELF.fetch("https://example.com/connect", {
      headers: { "X-Scape-Room": ROOM_A },
    });
    expect(noUpgrade.status).toBe(426);
  });

  it("rejects query strings on /connect with 404", async () => {
    const res = await SELF.fetch("https://example.com/connect?x=1", {
      headers: { Upgrade: "websocket", "X-Scape-Room": ROOM_A },
    });
    expect(res.status).toBe(404);
  });
});

describe("Room fanout", () => {
  it("fans out a message from A to B but not back to A", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);

    // Listener installed BEFORE any send — a fast echo can't slip past.
    const aEcho = mustNotReceive(a, "self-echo", (d) => d === "hello-from-a");
    const bRecv = nextMessage(b);
    a.send("hello-from-a");
    expect(await bRecv).toBe("hello-from-a");

    // Positive signal ordered after the forbidden delivery: B sends, A
    // receives. The DO processes frames in order, so if A's own frame
    // had been echoed it would have arrived before this one. (App-frame
    // await: A also receives the ack for its own earlier send.)
    const aRecv = nextAppMessage(a);
    b.send("reply-from-b");
    expect(await aRecv).toBe("reply-from-b");
    aEcho.assertClean();

    a.close();
    b.close();
  });

  it("does not bridge two different rooms", async () => {
    const roomOne = freshRoom();
    const roomTwo = freshRoom();
    const a = await openSocket(roomOne);
    const b = await openSocket(roomOne);
    const c = await openSocket(roomTwo);

    const cLeak = mustNotReceive(c, "cross-room");
    const bRecv = nextMessage(b);
    a.send("only-room-one");
    // B receiving proves the fanout for this frame fully completed —
    // if C were ever in the recipient set it would have been sent to
    // in the same loop.
    expect(await bRecv).toBe("only-room-one");
    cLeak.assertClean();

    a.close();
    b.close();
    c.close();
  });
});

describe("Room capacity", () => {
  it("rejects the 26th peer with 503 and frees the slot on close", async () => {
    const room = freshRoom();
    const sockets: WebSocket[] = [];
    for (let i = 0; i < 25; i++) {
      sockets.push(await openSocket(room));
    }
    const overflow = await upgrade(room);
    expect(overflow.status).toBe(503);

    // Close one peer → the slot must become claimable again. Close
    // completion is async server-side, so poll until admitted (bounded).
    sockets[0]!.close();
    let admitted = false;
    for (let attempt = 0; attempt < 50 && !admitted; attempt++) {
      const retry = await upgrade(room);
      if (retry.status === 101) {
        admitted = true;
        (retry.webSocket as WebSocket).accept();
      } else {
        await new Promise((r) => setTimeout(r, 100));
      }
    }
    expect(admitted).toBe(true);
  });
});

describe("Frame limits", () => {
  it("accepts a frame of exactly 64 KiB", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    const exact = "x".repeat(64 * 1024);
    const bRecv = nextMessage(b);
    a.send(exact);
    expect((await bRecv).length).toBe(64 * 1024);
    a.close();
    b.close();
  });

  it("closes the WS with 1009 on 64 KiB + 1", async () => {
    const a = await openSocket(freshRoom());
    const code = closeCode(a);
    a.send("x".repeat(64 * 1024 + 1));
    expect(await code).toBe(1009);
  });

  it("closes with 1009 on multibyte frames whose BYTE length crosses the cap", async () => {
    const a = await openSocket(freshRoom());
    const code = closeCode(a);
    // "€" is 1 UTF-16 code unit but 3 UTF-8 bytes: 22 000 chars →
    // 66 000 bytes > 65 536, while code-unit length (22 000) is far
    // below the cap — only an exact byte measurement can catch it.
    a.send("€".repeat(22_000));
    expect(await code).toBe(1009);
  });

  it("accepts multibyte frames whose byte length stays under the cap", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    const payload = "€".repeat(21_000); // 63 000 bytes < 65 536
    const bRecv = nextMessage(b);
    a.send(payload);
    expect(await bRecv).toBe(payload);
    a.close();
    b.close();
  });

  it("rejects a multi-MiB frame promptly (no proportional allocation)", async () => {
    const a = await openSocket(freshRoom());
    const code = closeCode(a);
    a.send("x".repeat(4 * 1024 * 1024));
    expect(await code).toBe(1009);
  });

  it("closes the WS with 1003 on a binary frame", async () => {
    const a = await openSocket(freshRoom());
    const code = closeCode(a);
    a.send(new Uint8Array([1, 2, 3]).buffer);
    expect(await code).toBe(1003);
  });
});

describe("Keepalive", () => {
  it("answers text ping with pong and does NOT fan the ping out", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);

    const bLeak = mustNotReceive(b, "ping-fanout", (d) => d === "ping" || d === "pong");
    const pong = nextMessage(a);
    a.send("ping");
    expect(await pong).toBe("pong");

    // Positive signal after the forbidden one: a real frame reaches B.
    const bRecv = nextMessage(b);
    a.send("real-frame");
    expect(await bRecv).toBe("real-frame");
    bLeak.assertClean();

    a.close();
    b.close();
  });

  it("does not charge pings against the message token bucket", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);

    // 30 pings would exhaust a 10-token bucket three times over if
    // they were metered.
    for (let i = 0; i < 30; i++) a.send("ping");

    const bRecv = nextMessage(b);
    a.send("still-works");
    expect(await bRecv).toBe("still-works");
    a.close();
    b.close();
  });
});

describe("Rate limiting", () => {
  it("fans out exactly the burst capacity, then closes with 1008", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);

    const received: string[] = [];
    b.addEventListener("message", (e) => {
      if (typeof e.data === "string") received.push(e.data);
    });
    const code = closeCode(a);
    // Capacity 10. The synchronous burst can't earn refill (2 tokens/s),
    // so exactly frames 0..9 fan out and frame 10 trips the 1008 close.
    for (let i = 0; i < 50; i++) {
      a.send(`burst-${i}`);
    }
    expect(await code).toBe(1008);
    expect(received).toEqual(
      Array.from({ length: 10 }, (_, i) => `burst-${i}`),
    );
    b.close();
  });

  it("keeps buckets independent across connections", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    const c = await openSocket(room);

    // Drain A's bucket to the 1008 close.
    const aClosed = closeCode(a);
    for (let i = 0; i < 20; i++) a.send(`drain-${i}`);
    await aClosed;

    // B's bucket must be untouched.
    const cRecv = nextMessage(c);
    b.send("b-still-fine");
    expect(await cRecv).toBe("b-still-fine");
    b.close();
    c.close();
  });
});

describe("Delivery-ACK protocol", () => {
  it("acks every accepted frame with an increasing seq", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    for (let i = 1; i <= 3; i++) {
      const bRecv = nextMessage(b);
      const aAck = nextControl(a);
      a.send(`frame-${i}`);
      expect(await bRecv).toBe(`frame-${i}`);
      expect(JSON.parse(await aAck)).toEqual({ v: 2, type: "ack", seq: i });
    }
    a.close();
    b.close();
  });

  it("acks an alone-in-room send (accepted, forwarded to nobody)", async () => {
    const a = await openSocket(freshRoom());
    const ack = nextControl(a);
    a.send("into-the-void");
    // RAW-BYTE assertion (not JSON.parse): pins the exact wire bytes the
    // ackFrame string-concat produces, so a future edit that stays valid
    // JSON but drifts the format (whitespace, key order) fails here.
    expect(await ack).toBe('{"v":2,"type":"ack","seq":1}');
    a.close();
  });

  it("ackFrame is byte-identical to JSON.stringify across the seq domain", async () => {
    // Pure unit check (no socket): the string-concat ackFrame must equal
    // the OLD JSON.stringify({v:2,type:"ack",seq}) it replaced, for
    // multi-digit / max-safe-int / exponent-notation seqs — so a concat
    // formatting change that happens to preserve seq=1 but mishandles
    // large numbers goes RED. `ackFrame` is not exported, so reproduce
    // it here against the exact prefix and cross-check the oracle.
    const ackFrame = (seq: number) => `{"v":2,"type":"ack","seq":${seq}}`;
    const oracle = (seq: number) => JSON.stringify({ v: 2, type: "ack", seq });
    for (const seq of [0, 1, 17, 999999, Number.MAX_SAFE_INTEGER, 1e21]) {
      expect(ackFrame(seq), `seq=${seq}`).toBe(oracle(seq));
    }
  });

  it("does not consume seq for auto-answered pings", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    for (let i = 0; i < 3; i++) {
      const pong = nextMessage(a);
      a.send("ping");
      expect(await pong).toBe("pong");
    }
    const aAck = nextControl(a);
    const bRecv = nextMessage(b);
    a.send("first-real-frame");
    expect(await bRecv).toBe("first-real-frame");
    expect(JSON.parse(await aAck)).toEqual({ v: 2, type: "ack", seq: 1 });
    a.close();
    b.close();
  });

  it("rejects an oversized frame with its seq, then closes 1009", async () => {
    const a = await openSocket(freshRoom());
    const rejectMsg = nextControl(a);
    const code = closeCode(a);
    a.send("x".repeat(64 * 1024 + 1));
    expect(JSON.parse(await rejectMsg)).toEqual({
      v: 2,
      type: "error",
      code: "payload_too_large",
      seq: 1,
    });
    expect(await code).toBe(1009);
  });

  it("rejects a binary frame with its seq, then closes 1003", async () => {
    const a = await openSocket(freshRoom());
    const rejectMsg = nextControl(a);
    const code = closeCode(a);
    a.send(new Uint8Array([1, 2, 3]).buffer);
    expect(JSON.parse(await rejectMsg)).toEqual({
      v: 2,
      type: "error",
      code: "unsupported_data",
      seq: 1,
    });
    expect(await code).toBe(1003);
  });

  it("does NOT let a peer forge control: a peer's text ack/hello is fanned as text, never binary", async () => {
    // ce:review P1 — provenance by frame type. A malicious peer sends a
    // control-SHAPED text frame hoping to spoof another peer's delivery
    // verdict. The relay forwards it as an ordinary TEXT frame (it never
    // re-authors it as binary), so the victim's client — which trusts
    // ONLY binary as control — sees text and never acts on it.
    const room = freshRoom();
    const attacker = await openSocket(room);
    const victim = await openSocket(room);

    const forged = JSON.stringify({ v: 2, type: "ack", seq: 999999 });
    const recv = new Promise<{ text: boolean; data: string }>((resolve) => {
      victim.addEventListener(
        "message",
        (e) => {
          if (e.data instanceof ArrayBuffer) {
            resolve({ text: false, data: DECODER.decode(e.data) });
          } else {
            resolve({ text: true, data: e.data as string });
          }
        },
        { once: true },
      );
    });
    attacker.send(forged);
    const got = await recv;
    // The victim receives the attacker's bytes as TEXT (fanned), not as
    // a binary control frame — so its client treats it as a (bogus,
    // undecryptable) app frame and drops it, never as an ack.
    expect(got.text).toBe(true);
    expect(got.data).toBe(forged);
    attacker.close();
    victim.close();
  });

  it("acks the burst up to capacity, then rejects with the offending seq before 1008", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);
    // Control frames (acks + the reject) are BINARY now; decode them.
    const aFrames: string[] = [];
    a.addEventListener("message", (e) => {
      if (e.data instanceof ArrayBuffer) aFrames.push(DECODER.decode(e.data));
    });
    const code = closeCode(a);
    for (let i = 0; i < 11; i++) a.send(`burst-${i}`);
    expect(await code).toBe(1008);
    expect(aFrames.map((f) => JSON.parse(f))).toEqual([
      ...Array.from({ length: 10 }, (_, i) => ({ v: 2, type: "ack", seq: i + 1 })),
      { v: 2, type: "error", code: "rate_limit", seq: 11 },
    ]);
    b.close();
  });
});

describe("Room egress budget", () => {
  it("drops over-budget frames with an error frame to the sender, connection stays open", async () => {
    const room = freshRoom();
    const a = await openSocket(room);
    const b = await openSocket(room);

    // Test budget: capacity 100 000 bytes, fanout 1. A 60 000-byte frame
    // fits; a second one (120 000 cumulative ≫ refill during the test)
    // must be dropped, B must never see it, and A gets the error frame.
    const frame = "y".repeat(60_000);
    expect(frame.length * 2).toBeGreaterThan(TEST_EGRESS_CAPACITY);

    const bFirst = nextMessage(b);
    const aAck1 = nextControl(a);
    a.send(frame);
    expect((await bFirst).length).toBe(60_000);
    expect(JSON.parse(await aAck1)).toEqual({ v: 2, type: "ack", seq: 1 });

    const bLeak = mustNotReceive(b, "over-budget-frame", (d) => d.length === 60_000);
    const aErr = nextControl(a);
    a.send(frame);
    expect(JSON.parse(await aErr)).toEqual({
      v: 2,
      type: "error",
      code: "room_rate_limit",
      seq: 2,
    });
    bLeak.assertClean();

    // The sender was NOT closed — small frames still flow once the
    // budget refills enough to cover them (1 000 bytes/s; a tiny frame
    // needs only a few bytes × fanout 1). CUMULATIVE ack semantics: the
    // ack after a rejected seq keeps counting (seq 3 follows the
    // rejected seq 2).
    await new Promise((r) => setTimeout(r, 1100));
    const bSmall = nextMessage(b);
    const aAck3 = nextControl(a);
    a.send("tiny");
    expect(await bSmall).toBe("tiny");
    expect(JSON.parse(await aAck3)).toEqual({ v: 2, type: "ack", seq: 3 });

    a.close();
    b.close();
  });
});
