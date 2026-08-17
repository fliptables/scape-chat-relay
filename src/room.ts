import { Buffer } from "node:buffer";
import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import { upgradeIncludesWebSocket } from "./http";
import { logDeadPeerDrop, logRoomBudgetDrop, logWsClose, logWsError } from "./log";
import {
  BUCKET_CAPACITY,
  hasToken,
  nextTokens,
  takeCost,
  type Bucket,
} from "./ratelimit";

/// Per-room actor. One instance per `roomId`. The Worker's `fetch` routes
/// every WS upgrade for `/room/<roomId>` to the corresponding DO via
/// `idFromName(roomId)`.
///
/// Responsibilities:
/// - Accept WS upgrades, attach a fresh token bucket per connection.
/// - On every text frame: enforce a 64 KiB cap, decrement the per-conn
///   token bucket, charge the per-room egress budget, fan out to all
///   OTHER peers in the room.
/// - Hibernate cleanly (`acceptWebSocket` + auto-response ping) so an
///   idle room is eligible to sleep (no duration charges while
///   hibernated).
///
/// What this DO does NOT do:
/// - Authenticate (the client's E2E crypto is the trust boundary; the
///   relay holds no keys and never attempts decryption)
/// - Decode envelopes (forwards opaque text frames; the client owns the
///   protocol — the one reserved literal is the "ping" keepalive below)
/// - Persist messages (frames forwarded, then forgotten; the only state
///   that survives hibernation is the 3-number connection state on each
///   socket attachment — rate-limit bucket plus the ack `seq` counter —
///   see STORES-NOTHING notes in wrangler.toml)

const MAX_FRAME_BYTES = 64 * 1024;
// Hard ceiling on per-room fanout. Beacons + messages fan out to every
// other peer, so a full round of frames costs N×(N−1) sends. 25 caps a
// single frame's fanout at 24 sends (600 per full round) vs 99 (9900)
// at 100. Phase 1 dev-tool teams are typically 3–8 peers; 25 leaves
// comfortable headroom while bounding any single chatty room's relay
// cost.
const MAX_PEERS_PER_ROOM = 25;

// Per-room egress budget defaults (operator-tunable via wrangler [vars]).
// Bounds worst-case relay cost per room: every accepted frame charges
// frameBytes × fanout. 25 colluding senders at the per-conn sustained
// rate (2 msg/s × 64 KiB × 24-way fanout ≈ 76 MiB/s) collapse to the
// refill rate below; a legitimate 8-peer team's worst case (2 msg/s ×
// ~44 KiB max app frame × 7-way fanout ≈ 5 MiB/s) fits with ≥2×
// headroom.
const DEFAULT_ROOM_EGRESS_CAPACITY_BYTES = 20 * 1024 * 1024;
const DEFAULT_ROOM_EGRESS_REFILL_BYTES_PER_SEC = 10 * 1024 * 1024;

// Relay-authored wire version — MUST equal the Swift client's
// `ChatProtocol.supportedVersion` (pinned by check-swift-contract.mjs):
// clients drop any envelope whose `v` mismatches as `.unknown`, so a
// wrong version here silently disables the whole ack path.
const WIRE_VERSION = 2;

// Capability hello, sent ONCE per accepted socket before any other
// frame (WS ordering guarantees the client processes it before the
// first ack). A single constant — byte-identical for empty and occupied
// rooms, so connecting to a guessed roomId learns relay capabilities
// and NOTHING about the room (enumeration-safety, tested).
const RELAY_HELLO = JSON.stringify({
  v: WIRE_VERSION,
  type: "relay_hello",
  caps: ["ack"],
});

// The closed protocol vocabulary of reject codes the Swift client
// switches on. A union (not `string`) so a typo can't silently confuse
// the client (ce:review TS P3).
type RejectCode =
  | "unsupported_data"
  | "payload_too_large"
  | "rate_limit"
  | "room_rate_limit";

// Delivery-ACK protocol (IT-613): `seq` is a PER-CONNECTION counter
// that both ends compute independently — it increments once per frame
// reaching webSocketMessage (i.e. every text/binary frame EXCEPT the
// auto-answered "ping", which never wakes the DO), and the client
// counts its own non-ping sends over the same ordered socket. INVARIANT
// (load-bearing, tested): every webSocketMessage invocation emits
// exactly one `ack{seq}` XOR one `error{code, seq}` before any close it
// triggers. Ack semantics are CUMULATIVE — `ack{seq: N}` means every
// frame ≤ N was accepted except those explicitly rejected — so a lost
// ack frame heals on the next one without relay timers (which are
// forbidden: they'd pin the DO awake and the alarms API writes
// storage). "Accepted" means the RELAY took the frame (an alone-in-room
// send is accepted and forwarded to nobody); end-to-end receipts are
// explicitly out of scope. Relay-authored frames (hello/ack/error) are
// NOT charged to the room egress budget: they're ≤ ~60 B and bounded
// 1:1 by inbound frames, which the per-connection bucket already
// bounds.
// Ack is on the HOT path (one per accepted frame). Build it by string
// concatenation over a constant prefix rather than JSON.stringify(obj) —
// same bytes, no intermediate object + serializer walk. (`seq` is a
// safe JS integer, so its default stringification needs no escaping.)
// rejectFrame stays JSON.stringify: it's a cold error path where clarity
// wins over micro-optimization.
const ACK_PREFIX = `{"v":${WIRE_VERSION},"type":"ack","seq":`;
const ackFrame = (seq: number) => `${ACK_PREFIX}${seq}}`;
const rejectFrame = (code: RejectCode, seq: number) =>
  JSON.stringify({ v: WIRE_VERSION, type: "error", code, seq });

// Reused per DO instance — TextEncoder is stateless, so a single
// instance is safe to share across all webSocketMessage invocations.
const ENCODER = new TextEncoder();

// PROVENANCE (IT-613 ce:review P1, LOAD-BEARING): relay-authored control
// frames (relay_hello / ack / error) are sent as BINARY WebSocket
// frames. The relay NEVER fans out binary and rejects inbound binary
// with 1003, so a binary frame reaching a client is provably
// relay-authored — a room peer cannot forge a delivery verdict. All
// FANNED peer traffic is text; the client trusts only binary as control.
// Encode once for the constant hello; per-frame acks/errors encode on
// send (tiny, and off the hot data path).
const RELAY_HELLO_BYTES = ENCODER.encode(RELAY_HELLO);

/// Per-connection hibernation-surviving state: the rate-limit bucket
/// plus the ack `seq` counter. Still the stores-nothing qualifier class
/// (three numbers, no message data, dies with the socket).
interface ConnAttachment extends Bucket {
  seq: number;
}

/// What `deserializeAttachment` yields: a bucket that MAY predate the
/// ack `seq` field (a socket accepted by a pre-ack deploy). Named once
/// so the two read sites can't drift (ce:review TS P3).
type StoredAttachment = (Bucket & { seq?: number }) | null;

/// Persist the connection state on a rejection path that doesn't touch
/// the bucket: bucket fields unchanged (seeded fresh if absent), seq
/// advanced — a rejected frame still consumed its sequence number on
/// BOTH ends.
function persistConn(ws: WebSocket, att: StoredAttachment, seq: number): void {
  ws.serializeAttachment({
    tokens: att?.tokens ?? BUCKET_CAPACITY,
    updatedMs: att?.updatedMs ?? Date.now(),
    seq,
  } satisfies ConnAttachment);
}

export class RoomDurableObject extends DurableObject<Env> {
  /// Room egress budget, held in instance memory ONLY (never storage —
  /// stores-nothing). Hibernation discards it and the next wake reseeds
  /// a full bucket; that is semantically fine because the DO only
  /// hibernates when the room is idle, and an idle interval would have
  /// refilled the bucket anyway.
  private roomEgress: Bucket | null = null;
  private readonly egressCapacity: number;
  private readonly egressRefillPerSec: number;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.egressCapacity = positiveIntVar(
      env.ROOM_EGRESS_CAPACITY_BYTES,
      DEFAULT_ROOM_EGRESS_CAPACITY_BYTES,
    );
    this.egressRefillPerSec = positiveIntVar(
      env.ROOM_EGRESS_REFILL_BYTES_PER_SEC,
      DEFAULT_ROOM_EGRESS_REFILL_BYTES_PER_SEC,
    );
    // Auto-reply to "ping" text frames with "pong" without waking the DO
    // from hibernation. LOAD-BEARING: the Scape client's keepalive sends
    // a text "ping" every 25 s (native WS PING control frames proved
    // unreliable against hibernating DOs — see ChatRoomClient.pingLoop).
    // Consequence, documented in the README: "ping" is the ONE text frame
    // the relay does not forward opaquely, and the reply path is metered
    // by the runtime, not by the token bucket (1:1, 4-byte response, no
    // fanout — no amplification).
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair("ping", "pong"),
    );
  }

  override async fetch(req: Request): Promise<Response> {
    // Defense in depth — the Worker front door already enforces method,
    // Upgrade, Origin, and per-IP limits before routing here.
    if (!upgradeIncludesWebSocket(req.headers.get("Upgrade"))) {
      return new Response("expected websocket", { status: 426 });
    }
    // Hard cap on connections per room. Includes half-open sockets that
    // haven't timed out yet, so a crash-reconnect burst can transiently
    // occupy slots — accepted (see README threat model; an eviction
    // sweep would need alarms, and the alarms API writes DO storage,
    // which stores-nothing forbids).
    if (this.ctx.getWebSockets().length >= MAX_PEERS_PER_ROOM) {
      return new Response("room_full", { status: 503 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];

    // hibernation-aware accept — DO can sleep between frames
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      tokens: BUCKET_CAPACITY,
      updatedMs: Date.now(),
      seq: 0,
    } satisfies ConnAttachment);
    // Capability hello — first (binary) frame on every socket, before
    // any client frame can be processed. Binary = provably relay-authored
    // (see RELAY_HELLO_BYTES).
    server.send(RELAY_HELLO_BYTES);
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer) {
    // Restore per-connection state. Tolerant decode: a socket accepted
    // by a pre-ack deploy has no `seq` — resume from 0 rather than
    // resetting its rate-limit bucket.
    const att = ws.deserializeAttachment() as StoredAttachment;
    const seq = (att?.seq ?? 0) + 1;
    // Sender-directed control frame, sent as BINARY (provenance — see
    // RELAY_HELLO_BYTES). A throw means the sender is already gone —
    // nothing to tell it.
    const tell = (payload: string) => {
      try {
        ws.send(ENCODER.encode(payload));
      } catch {
        /* sender already gone */
      }
    };
    // Guarded close: if `tell`'s send threw because the sender vanished,
    // the paired `close` throws the same class — swallow it (ce:review
    // TS P2), matching the dead-peer / webSocketError handling below.
    const hangUp = (code: number, reason: string) => {
      try {
        ws.close(code, reason);
      } catch {
        /* already closed */
      }
    };

    if (typeof msg !== "string") {
      persistConn(ws, att, seq);
      tell(rejectFrame("unsupported_data", seq));
      hangUp(1003, "unsupported_data");
      return;
    }
    // Frame cap, allocation-safe. UTF-8 length ≥ UTF-16 code-unit count
    // for every valid JS string, so any string longer than the cap in
    // code units is over the cap in bytes — reject it BEFORE measuring.
    // (The platform accepts multi-MiB messages; this ordering bounds the
    // byte count below to a ≤ 64 Ki-code-unit walk instead of a scan of
    // the attacker's whole payload.)
    if (msg.length > MAX_FRAME_BYTES) {
      persistConn(ws, att, seq);
      tell(rejectFrame("payload_too_large", seq));
      hangUp(1009, "payload_too_large");
      return;
    }
    // Exact byte measurement: needed both for the cap (multi-byte
    // UTF-8 can cross it at ≤ 64 Ki code units) and for byte-accurate
    // egress charging below. Buffer.byteLength counts WITHOUT
    // materializing the encoded bytes — fanout sends the original
    // string, so encoding here would allocate up to 192 KiB of
    // immediate garbage per accepted frame on the hot path. Byte-exact
    // with TextEncoder (both count an unpaired surrogate as the 3-byte
    // replacement char); all legitimate traffic is ASCII JSON
    // (base64url ciphertext), so bytes ≈ code units in practice.
    const byteLen = Buffer.byteLength(msg, "utf8");
    if (byteLen > MAX_FRAME_BYTES) {
      persistConn(ws, att, seq);
      tell(rejectFrame("payload_too_large", seq));
      hangUp(1009, "payload_too_large");
      return;
    }

    // Per-connection token bucket — survives DO hibernation via WS
    // attachment. Close-on-violation (1008) is deliberate: an abusive
    // ESTABLISHED socket must not be able to burn DO CPU unbounded on
    // dropped frames — closing forces it back through the front door's
    // per-IP upgrade limit. The reject frame preceding the close names
    // the exact offending seq, so an ack-aware client marks that frame
    // honestly and resends it within policy — the pre-ACK "offending
    // frame silently lost" window is closed.
    // One wall-clock read for both the per-conn bucket and the egress
    // budget on the accept path — same instant, one fewer syscall.
    const now = Date.now();
    const bucket = nextTokens(att, now);
    if (!hasToken(bucket)) {
      ws.serializeAttachment({ tokens: bucket.tokens, updatedMs: bucket.updatedMs, seq } satisfies ConnAttachment);
      tell(rejectFrame("rate_limit", seq));
      hangUp(1008, "rate_limit");
      return;
    }
    ws.serializeAttachment({ tokens: bucket.tokens - 1, updatedMs: bucket.updatedMs, seq } satisfies ConnAttachment);

    const peers = this.ctx.getWebSockets();
    const fanout = peers.length - 1;
    if (fanout <= 0) {
      // Alone in the room: the frame is ACCEPTED (relay took it;
      // delivered-to-nobody is a room-membership fact, not a transport
      // failure) — ack it. Nothing to charge, nothing to fan out.
      tell(ackFrame(seq));
      return;
    }

    // Room egress budget: charge what the relay actually transmits
    // (bytes × fanout). On exhaustion, DROP the frame and tell the
    // sender — closing here would punish whichever peer happened to
    // send during a flood (likely legitimate) and convert one abuser
    // into a room-wide reconnect storm.
    const egress = nextTokens(
      this.roomEgress,
      now,
      this.egressCapacity,
      this.egressRefillPerSec,
    );
    const charged = takeCost(egress, byteLen * fanout);
    if (charged === null) {
      this.roomEgress = egress;
      logRoomBudgetDrop();
      tell(rejectFrame("room_rate_limit", seq));
      return;
    }
    this.roomEgress = charged;

    // Transparent fanout. Relay can't validate envelope structure (the
    // client owns that — relay is a dumb pipe). `send` only throws on
    // sockets the runtime already knows are dead; those get closed
    // individually so one dead peer never blocks the others. A slow-but-
    // alive peer buffers inside the runtime instead (Workers exposes no
    // server-side bufferedAmount) — growth is bounded by this room's
    // egress budget and, at worst, DO eviction resets the room. See
    // README threat model.
    for (const peer of peers) {
      if (peer === ws) continue;
      try {
        peer.send(msg);
      } catch (err) {
        // Error CLASS only — runtime exception text is not a stable,
        // provably identifier-free interface (see src/log.ts).
        logDeadPeerDrop(err);
        try {
          peer.close(1011, "send_failed");
        } catch {
          /* already closed */
        }
      }
    }
    // Ack AFTER the fanout loop: "accepted" is a statement that the
    // relay processed and forwarded the frame this tick.
    tell(ackFrame(seq));
  }

  override async webSocketClose(_ws: WebSocket, code: number) {
    // Normal-close codes (1000 normalClosure, 1001 goingAway) are not
    // actionable and dominate the steady-state log volume during
    // backoff churn. Skip them; only abnormal closes get a line.
    if (code !== 1000 && code !== 1001) {
      logWsClose(code);
    }
  }

  override async webSocketError(ws: WebSocket, err: unknown) {
    logWsError(err);
    try {
      ws.close(1011, "internal_error");
    } catch {
      /* already closed */
    }
  }
}

/// Parse an operator-supplied wrangler var. Anything non-numeric or
/// non-positive falls back — a misconfigured knob must never disable the
/// budget (fail-closed to defaults).
function positiveIntVar(raw: string | undefined, fallback: number): number {
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}
