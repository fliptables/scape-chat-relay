#!/usr/bin/env node
/**
 * Relay ↔ Scape-client contract lockstep check.
 *
 * The relay's wire contract (route shape, frame cap, close codes/reasons,
 * keepalive literal) is compiled into the Scape macOS client
 * (Scape/Services/Chat*.swift). In the monorepo this script cross-checks
 * both sides so a change to either fails `npm test` until the other is
 * updated in the same commit.
 *
 * In the standalone public repo the Swift tree does not exist — the
 * script prints a notice and exits 0 (the relay-side literals are still
 * guarded by check-invariants.mjs).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const relayRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const swiftDir = join(relayRoot, "..", "Scape", "Services");

if (!existsSync(swiftDir)) {
  console.log(
    "check-swift-contract: Scape client tree not present (standalone repo) — skipped",
  );
  process.exit(0);
}

const failures = [];
const fail = (msg) => failures.push(msg);
const read = (p) => readFileSync(p, "utf8");

const roomTs = read(join(relayRoot, "src", "room.ts"));
const workerTs = read(join(relayRoot, "src", "worker.ts"));
const identitySwift = read(join(swiftDir, "ChatRoomIdentity.swift"));
const plaintextSwift = read(join(swiftDir, "ChatPlaintext.swift"));
const clientSwift = read(join(swiftDir, "ChatRoomClient.swift"));
const relayURLSwift = read(join(swiftDir, "RelayURL.swift"));

// ---- roomId shape ----------------------------------------------------------
// Client derives roomId = hex(SHA-256(...)) → 64 lowercase hex chars; the
// relay route must accept exactly that shape.
if (!identitySwift.includes('"scape-roomid-v2|"')) {
  fail("ChatRoomIdentity.swift: roomId domain tag \"scape-roomid-v2|\" missing — derivation changed?");
}
if (!identitySwift.includes('String(format: "%02x", $0)')) {
  fail("ChatRoomIdentity.swift: lowercase-hex encoding of the SHA-256 roomId missing — the relay route regex assumes [0-9a-f]");
}
if (!workerTs.includes(String.raw`/^\/room\/([0-9a-f]{64})$/`)) {
  fail("worker.ts: route regex drifted from the 64-lowercase-hex roomId contract");
}

// ---- frame cap covers the client's largest legitimate frame ----------------
// Client caps text fields at 32 KiB; the sealed wire frame is JSON +
// base64url(ciphertext), ~4/3 × plaintext + envelope overhead. Assert the
// relay cap keeps ≥ 8 KiB of headroom over that worst case.
const fieldCap = plaintextSwift.match(/maxChatTextBytes\s*=\s*(\d+)\s*\*\s*(\d+)/);
if (!fieldCap) {
  fail("ChatPlaintext.swift: maxChatTextBytes literal not found");
} else {
  const capBytes = Number(fieldCap[1]) * Number(fieldCap[2]);
  const maxWireEstimate = Math.ceil((capBytes * 4) / 3) + 1024; // base64 + envelope
  const relayCap = 64 * 1024;
  if (!roomTs.includes("MAX_FRAME_BYTES = 64 * 1024")) {
    fail("room.ts: MAX_FRAME_BYTES drifted from 64 KiB");
  }
  if (maxWireEstimate + 8 * 1024 > relayCap) {
    fail(
      `frame-cap headroom violated: client max wire frame ≈ ${maxWireEstimate} bytes ` +
        `needs ≥ 8 KiB headroom under the relay's ${relayCap}-byte cap`,
    );
  }
}

// ---- close reasons the client documents must exist in the relay ------------
for (const reason of ["unsupported_data", "payload_too_large", "rate_limit", "send_failed", "internal_error"]) {
  if (!clientSwift.includes(reason)) {
    fail(`ChatRoomClient.swift: close-reason "${reason}" no longer documented client-side`);
  }
  if (!roomTs.includes(`"${reason}"`)) {
    fail(`room.ts: close-reason "${reason}" missing relay-side`);
  }
}

// ---- roomId dual-mechanism intake (IT-613 migration window) ----------------
// BOTH mechanisms must exist on BOTH sides for exactly one release:
// header-first (`/connect` + X-Scape-Room) and the legacy URL path. When
// the dual window closes (next release), flip these assertions to
// header-only and delete the relay's ROUTE + the client's fallback.
if (!workerTs.includes('CONNECT_PATH = "/connect"')) {
  fail("worker.ts: header-mechanism CONNECT_PATH drifted from \"/connect\"");
}
if (!workerTs.includes('ROOM_HEADER = "X-Scape-Room"')) {
  fail("worker.ts: roomId header name drifted from \"X-Scape-Room\"");
}
if (!relayURLSwift.includes('connectPath = "connect"')) {
  fail('RelayURL.swift: connectPath drifted from "connect" — must match the relay CONNECT_PATH');
}
if (!relayURLSwift.includes('roomHeaderName = "X-Scape-Room"')) {
  fail('RelayURL.swift: roomHeaderName drifted from "X-Scape-Room" — must match the relay ROOM_HEADER');
}
if (!clientSwift.includes("RelayURL.connectRequest(")) {
  fail("ChatRoomClient.swift: header-first connect no longer wired (RelayURL.connectRequest call missing)");
}
if (!clientSwift.includes("useLegacyConnect")) {
  fail("ChatRoomClient.swift: dual-window legacy fallback missing — required until the relay drops the URL route");
}
if (!clientSwift.includes("upgradeHTTPStatus == 404")) {
  fail("ChatRoomClient.swift: fallback trigger signature drifted — must be exactly a 404 answer to the header probe " +
    "(a real pre-migration relay always 404s /connect; anything broader is false-positive downgrade surface)");
}
// Swift-side roomId grammar must be the SAME regex as the relay's
// ROOM_ID — a looser Swift check would mark relays legacy on garbage
// input the relay would reject.
if (!relayURLSwift.includes('roomIdPattern = "^[0-9a-f]{64}$"')) {
  fail('RelayURL.swift: roomIdPattern drifted from "^[0-9a-f]{64}$" — must match the relay ROOM_ID grammar');
}

// ---- delivery-ACK protocol (IT-613) ----------------------------------------
// Relay-authored frames must carry the client's supported wire version —
// clients drop v≠supportedVersion envelopes as .unknown, so a mismatch
// silently disables the whole ack path.
const protocolSwift = read(join(swiftDir, "ChatProtocol.swift"));
if (!protocolSwift.includes("supportedVersion: Int = 2")) {
  fail("ChatProtocol.swift: supportedVersion drifted from 2 — must equal the relay's WIRE_VERSION");
}
if (!roomTs.includes("const WIRE_VERSION = 2;")) {
  fail("room.ts: WIRE_VERSION drifted from 2 — must equal ChatProtocol.supportedVersion");
}
if (!roomTs.includes('type: "relay_hello"') || !clientSwift.includes('case "relay_hello":')) {
  fail('relay_hello capability frame missing on one side (relay emit / ChatRoomClient route)');
}
if (!roomTs.includes('caps: ["ack"]') || !clientSwift.includes('contains("ack")')) {
  fail('"ack" capability literal missing on one side');
}
if (!clientSwift.includes('case "ack":') || !clientSwift.includes("envelope.seq")) {
  fail("ChatRoomClient.swift: seq-based ack routing missing — relay acks would be dropped");
}

// ---- keepalive literal -----------------------------------------------------
// Client sends a text "ping" every 25 s and relies on the DO's
// auto-response "pong" (native WS PING control frames are unreliable
// against hibernating DOs — see ChatRoomClient.pingLoop).
if (!clientSwift.includes('.string("ping")')) {
  fail('ChatRoomClient.swift: text "ping" keepalive missing — if removed, the relay auto-response is dead code');
}
if (!roomTs.includes('WebSocketRequestResponsePair("ping", "pong")')) {
  fail('room.ts: ping/pong auto-response missing — the client keepalive depends on it');
}

if (failures.length > 0) {
  console.error("check-swift-contract: FAILED\n");
  for (const f of failures) console.error(`  ✘ ${f}`);
  process.exit(1);
}
console.log("check-swift-contract: OK (relay ↔ Chat*.swift contract in lockstep)");
