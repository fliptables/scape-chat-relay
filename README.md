# scape-chat-relay

Ciphertext relay for [Scape](https://scape.work)'s end-to-end-encrypted chat. A small Cloudflare Worker + Durable Object that fans out opaque text frames between the peers of a room — and deliberately nothing else. The Scape protocol encrypts every message on the client; the relay holds no keys and never attempts decryption.

Anyone can deploy their own copy — see [Bring-your-own-relay](#bring-your-own-relay).

## What it does

- Accepts a WebSocket upgrade carrying a roomId (64-char lowercase hex; on the Scape client, `roomId = SHA-256(name ‖ password)` under a domain tag) via `GET /connect` with the roomId in the `X-Scape-Room` header. The roomId is a bearer routing capability; keeping it out of the URL path keeps it out of every layer that logs URLs (Cloudflare invocation logs, `wrangler tail`, proxy access logs) — safe by construction rather than by config default. A missing or malformed header is rejected with a 404 byte-identical to the bad-path response. **Migration caveat (one release only):** the legacy `GET /room/<64-hex>` path is still accepted so pre-header clients keep working — a roomId sent that way does transit URL-logging layers until the route is removed next release (see [Protocol notes](#protocol-notes)).
- Routes the connection to a `RoomDurableObject` keyed by `idFromName(roomId)` — the same `roomId` always lands on the same instance, so peers find each other with no external coordination.
- Fans out every text frame to every other peer in the same room, in arrival order.
- Enforces, per connection: a 64 KiB frame cap (close 1009), text-frames-only (close 1003), and a token bucket of 10 burst / 2 per second sustained (close 1008).
- Enforces, per room: a 25-peer cap (HTTP 503 `room_full`) and a byte-denominated egress budget (default 20 MiB burst / 10 MiB/s sustained, charged at `frameBytes × fanout`; over-budget frames are dropped and the sender is told via `{"v":2,"type":"error","code":"room_rate_limit","seq":N}`).
- Applies, per client IP at the front door: a **best-effort** WebSocket-upgrade rate limit (60/min, HTTP 429) via Cloudflare's rate-limiting binding — configured in `wrangler.toml`, so every fork ships it. Best-effort means exactly this: the binding counts per Cloudflare location (not a global per-IP ceiling), a runtime limiter error or a missing `CF-Connecting-IP` header admits the request (fail-open for availability), while a *missing binding* rejects upgrades with 503 (fail-closed — a vanished security control is a broken deploy, opt out only via `REQUIRE_UPGRADE_LIMITER = "false"`).
- Answers the text frame `"ping"` with `"pong"` without waking the room (reserved keepalive — the one text frame that is not forwarded; see [Protocol notes](#protocol-notes)).
- Is eligible to hibernate between frames (no duration charges while hibernated).

## What it does NOT do — the threat model

An honest statement of the boundary. This is an **unauthenticated, trustless fan-out pipe**; its guarantees and its non-guarantees both follow from that.

**Confidentiality of message content does not depend on the relay.** Scape clients seal every payload with per-room keys (PBKDF2 → ChaCha20-Poly1305) before it touches the network. The relay holds no keys, and a malicious relay operator can read exactly what any network observer can: ciphertext, frame sizes, and timing. "The relay can't read your messages" is a property of the client protocol, not something a dumb pipe could enforce — the relay will forward any text frame thrown at it.

**The relay stores nothing.**
- No message data, roomIds, IPs, or client identifiers are ever written to Durable Object storage, KV, R2, D1, caches, or analytics — there are no such bindings, and `scripts/check-invariants.mjs` fails the build if one is ever added.
- The only state that survives hibernation is a three-number per-connection counter (`tokens`, `updatedMs` for the rate-limit bucket, plus the delivery-ACK `seq`) serialized on each socket attachment. It contains no message data and dies with the connection.
- Telemetry is **off by default**. Cloudflare's automatic invocation logs capture the request URL and client IP, and Workers Logs are retained for 3–7 days — so `wrangler.toml` ships with observability disabled and `invocation_logs = false` behind it (guarded by the invariants check). If you temporarily enable observability to debug, only this Worker's own `console` lines are stored, and those carry an event tag, a close code, or an error class — never a roomId, IP, or payload.
- What the platform still sees: Cloudflare terminates TLS, so Cloudflare (and the relay operator's account) necessarily observes connection metadata *in transit*, and `wrangler tail` can live-stream request events while attached (ephemeral, nothing stored). Stores-nothing is a claim about **persistence**, and it is enforced; it is not a claim that a pipe can be metadata-blind to its own operator.

**roomIds are unguessable but bearer.** A roomId is a 256-bit hash — enumeration is infeasible, and connecting to a guessed roomId reveals nothing (no member count, no history; the relay sends nothing unprompted). But anyone who *holds* a roomId — a current member, an evicted former member, or whoever compromised one — can connect, fill the room's 25 peer slots, or spray ciphertext-shaped noise at its members. The relay cannot tell these actors apart **by design** (authenticating would require identity, which this relay refuses to hold). Recovery is client-side: rotating the room password derives a fresh roomId, which is a brand-new room as far as the relay is concerned.

**Availability is rate-limit-bounded, not guaranteed.** Known, accepted exposures of the no-auth design, and what bounds each:

| Vector | Bound |
|---|---|
| Connection floods / reconnect-cycling for fresh token buckets | Per-IP upgrade limit (60/min, in `wrangler.toml`) — best-effort and per-CF-location; a botnet or IP-rotating attacker multiplies it by their IP count |
| Drive-by abuse from hostile web pages via visitors' browsers | Origin-bearing upgrades rejected outright (403) — Scape's native client sends no Origin |
| One chatty/malicious peer drowning a room | Per-connection token bucket (10 burst / 2 s⁻¹, close 1008) |
| Colluding peers maximizing relay egress (cost attack) | Per-room egress budget: worst case drops from ~76 MiB/s (25 peers × 2 msg/s × 64 KiB × 24-way fanout) to the 10 MiB/s refill rate |
| Room-slot monopolization by a roomId holder | Accepted limitation (see above). Password rotation evicts; per-IP limits slow refills |
| Invented roomIds spawning unbounded rooms | Each hibernates idle at no duration cost; the per-IP upgrade limit bounds the creation rate **per source IP only** — the handshake/DO-creation work of a distributed attacker is NOT bounded by the room egress budget (which meters fanout, not admission). Set a [spend cap](https://developers.cloudflare.com/workers/platform/pricing/) on your account regardless |
| A slow-but-alive peer bloating the room's outbound buffers | Workers exposes no server-side `bufferedAmount`, so this cannot be detected in code — and an alarm-driven idle sweep is off the table because the alarms API persists to Durable Object storage, which the stores-nothing guarantee forbids (the invariants guard rejects `setAlarm`). The buffer's growth *rate* is bounded by the room egress budget (bytes/s), and worst case the DO is evicted and the room's sockets reset (self-healing). Dead peers *are* detected (send throws) and closed individually. Lower `MAX_PEERS_PER_ROOM` / `MAX_FRAME_BYTES` if a deployment needs a tighter absolute bound |

Under active abuse of a specific room, legitimate frames in that room can be dropped (budget) or connections closed (bucket) — the design bias is bounded cost over pretending an unauthenticated relay can distinguish friend from foe. Closing on per-connection overrun (rather than silently dropping) is deliberate: an abusive established socket must not burn per-frame relay CPU indefinitely, and a close forces it back through the front-door limiter. **Delivery visibility is ack-backed**: every frame reaching the relay is answered with `ack{seq}` on accept or `error{code, seq}` on reject (see Protocol notes), so an ack-aware client marks a frame delivered only on the relay's word, resends rejected/unanswered frames within policy (receiver-side nonce dedup makes resends double-deliver-proof), and surfaces genuinely undeliverable frames as failures instead of false "sent"s. Pre-ACK clients keep today's optimistic semantics.

**No delivery guarantees.** Fan-out is best-effort, at-most-once, in-order per sender. Clients own retries, dedup, and replay protection (they do: nonce-based dedup and a ±2-minute replay window — but that is client code, not relay code).

## Protocol notes

- Frames are opaque text to the relay, with two exceptions: (1) the literal `"ping"` is answered with `"pong"` and not forwarded — the Scape client's keepalive, needed because native WS PING control frames proved unreliable against hibernating Durable Objects; it bypasses the token bucket AND the ack `seq` counter (runtime-answered before the handler, 1:1, 4 bytes, no fanout — no amplification); (2) the relay authors its own control frames (all `"v": 2`): `{"type":"relay_hello","caps":["ack"]}` once per connection (byte-identical for empty and occupied rooms — it reveals capabilities, never room state), `{"type":"ack","seq":N}` per accepted frame (cumulative: every frame ≤ N accepted except those individually rejected; `seq` is a per-connection counter both ends compute independently, so the relay stays a zero-parse pipe), and `{"type":"error","code":...,"seq":N}` per rejected frame. Relay-authored frames are not charged to the egress budget (≤ ~60 B, bounded 1:1 by inbound frames the per-connection bucket already bounds).
- Intake migration window (one release, IT-613): alongside `GET /connect` + `X-Scape-Room`, the relay still accepts the legacy `GET /room/<64-hex>` path for clients that predate the header mechanism. When both mechanisms appear on one request they must agree, or the request gets the byte-identical 404 (fail closed on ambiguity). While the window is open, a legacy-path roomId is visible to URL-logging layers; the route (and the client's fallback) is deleted next release.
- Close codes: 1003 `unsupported_data` (binary frame), 1008 `rate_limit` (per-connection bucket), 1009 `payload_too_large` (> 64 KiB), 1011 `send_failed`/`internal_error` (peer/socket errors).
- HTTP rejections: 404 (bad path, bad/missing/mismatched `X-Scape-Room`, or query string — all byte-identical), 405 (non-GET), 426 (no `Upgrade: websocket`), 403 (Origin header present — no browser clients), 429 (per-IP upgrade limit, `Retry-After: 60`), 503 (`room_full`, or `limiter_misconfigured` when the required rate-limit binding is absent).

## First-time setup

You only do this once per Cloudflare account.

```bash
npm install
```

Then create an API token at <https://dash.cloudflare.com/profile/api-tokens> using the **"Edit Cloudflare Workers"** template, copy `.env.example` to `.env`, and fill in the values:

```bash
cp .env.example .env
# Edit .env in your editor — paste the token and your account ID.
```

`.env` is gitignored. Source it before running any wrangler command:

```bash
source .env
```

(`wrangler login` is the alternative — it does a browser-based OAuth — but it sometimes fails with vague network errors. Token auth is more reliable and works in CI.)

If this is your first Worker deploy ever on this account, you'll also need to claim a `workers.dev` subdomain in the dashboard: go to [dash.cloudflare.com](https://dash.cloudflare.com) → **Compute (Workers)** → pick a subdomain (e.g. `<your-handle>.workers.dev`). One-time, instant.

## Deploy

```bash
source .env  # if not already
npm run deploy   # runs the invariant checks, then wrangler deploy
```

Wrangler prints the deployed URL when it finishes:

```
Published scape-chat-relay (X sec)
  https://scape-chat-relay.<your-subdomain>.workers.dev
```

The Scape client connects via `wss://`, so the URL to paste into Scape's relay setting is:

```
wss://scape-chat-relay.<your-subdomain>.workers.dev
```

Recommended (not required) belt-and-suspenders on top of the in-code limits, on the Cloudflare dashboard: Bot Fight Mode on, plus an account-level spend cap. The load-bearing abuse limits (per-IP upgrade rate, per-connection bucket, per-room budget, Origin rejection) are all in code/config in this repo, so forks get them without dashboard work.

## Test

```bash
npm test    # invariant guards + mutation battery + miniflare-backed suite; ~25 sec
```

The suite covers routing strictness (path shapes, query strings, method, mixed-case `Upgrade`, Origin rejection), fanout (A→B, no self-echo, no cross-room bridging — negative cases proven by ordering, not sleeps), the exact 64 KiB boundary (ASCII and multibyte), binary rejection, burst-of-exactly-10 rate limiting with independent buckets, room capacity (26th peer rejected, slot freed on close), keepalive bypass, and the room egress budget (drop + error frame + connection survives).

`scripts/check-invariants.mjs` is the enforcement teeth behind the stores-nothing claim, and it is structural, not grep-based. What it enforces, exactly: no storage/alarm/cache/timer access in any module reachable from the configured entry point (property access, computed access with string-literal-*typed* keys, and destructuring alike); `require` banned outright, dynamic imports restricted to literal specifiers, and any module resolving outside the repo root failing the build (node_modules is the documented exclusion), so nothing escapes the audited module graph; all console output centralized in `src/log.ts`, whose four call shapes and sanitizer bodies are verified structurally AND whose closure is runtime-semantic, not type-level — close codes are integer-validated at the emit point (sentinel `-1` otherwise, so an `as any` cast can't smuggle a string through the annotation) and error values map to a fixed literal or `typeof` string, never the mutable `Error.name` — giving an emitted domain of fixed event literals, runtime-verified integers, `"Error"`, and `typeof` strings for ANY input, proven by tainted-input runtime tests in `test/log.spec.ts`; reflection and global-alias escape hatches (`globalThis`, `self`, `scheduler`, `Reflect`, `eval`, `Function`) banned in the graph, including in property position behind a `self.`/`globalThis.` receiver; `wrangler.toml` parsed for real with every key path walked (quoting and `[[env.*]]` qualification normalized), hardened defaults — including no `logpush` and no `tail_consumers` — checked in every environment block, and alternate config files refused; contract constants checked as declarations with exact initializers, the wire-version literals in this README and `wrangler.toml`'s examples pinned to `WIRE_VERSION`, and the 429 `Retry-After` hint pinned to the limiter's configured period. Every one of those classes is RED-proven by an executable mutation battery (`scripts/check-guard-battery.mjs`, 48 mutation classes, run in `npm test`) — the guard's claims are re-proven on every CI run, not asserted. Scope, stated precisely: this guard makes accidental and careless regressions of the guarantees, plus each enumerated evasion class, fail the build. It is not a sandbox — deliberately obfuscated exfiltration by a malicious committer is a code-review matter, and the guard does not claim otherwise.

## Watch live logs

```bash
npx wrangler tail
```

Streams live (nothing stored). Abnormal WS closes and errors get a structured line; normal closes (1000/1001) are deliberately skipped as non-actionable noise:

```jsonc
{"evt":"ws_close","code":1006}
{"evt":"dead_peer_drop","err":"Error"}
{"evt":"room_budget_drop"}
```

## Bring-your-own-relay

Anyone can fork + deploy this repo to their own Cloudflare account. The Scape client supports per-Space relay overrides, and invite links can carry the relay URL so invitees get routed automatically. Nothing about the protocol is locked to any particular deployment — the E2E encryption means you trust your relay operator with metadata and availability, never with content.

Operator knobs (optional `[vars]` in `wrangler.toml`): `ROOM_EGRESS_CAPACITY_BYTES`, `ROOM_EGRESS_REFILL_BYTES_PER_SEC`. The per-connection bucket, frame cap, and peer cap are part of the client contract and deliberately not configurable.

## Cost

Back-of-envelope for **normal use** (this is not an adversarial bound — see the threat model): a ~10-user team chatting normally stays inside Cloudflare's free tier (100K requests/day and the Durable Object free allocations; hibernating rooms accrue no duration charges, and the unused SQLite backing store bills nothing). Verify against [current Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/), and set an account spend cap so the worst case under attack is a rate-limited plateau, not a bill.

## Reference

Reference architecture inspiration: [cloudflare/workers-chat-demo](https://github.com/cloudflare/workers-chat-demo) (BSD). This implementation shares no code with it.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution and trademark notes — the license covers the code, not the Scape name or brand.
