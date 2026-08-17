#!/usr/bin/env node
/**
 * Executable mutation battery for check-invariants.mjs.
 *
 * A described battery isn't a battery: this script APPLIES each known
 * regression/evasion class to a temp copy of the audited surface and
 * asserts the guard exits non-zero (RED), plus a GREEN baseline. It runs
 * in `npm test`, so the guard's claims are re-proven on every CI run —
 * if someone weakens the guard, the battery fails before the suite runs.
 *
 * Classes: the original 9 drift mutations, the 5 first-round codex
 * bypasses, the 3 second-round codex evasions (fake errClass helper,
 * static require escaping the TS graph, const-literal computed storage
 * keys), the review-round additions (self/scheduler global aliases,
 * one bare mutation per banned reflection/timer name, out-of-root module
 * resolution, logpush/tail_consumers, doc'd wire-version drift,
 * Retry-After ↔ limiter-period lockstep), the codex round-4 closures
 * (timer-module namespace imports, node_modules-segment spoofing), and
 * the codex round-5 closures (import-equals, process/getBuiltinModule,
 * cloudflare:workers namespace de-aliasing), and the codex round-6
 * closures (AbortSignal.timeout, string-literal import spellings,
 * round-7's constructor laundering, and round-8's descriptor/prototype
 * laundering) plus adjacent variants — each RED-proven individually.
 */
import { execFileSync } from "node:child_process";
import {
  appendFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const relayRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const guard = join(relayRoot, "scripts", "check-invariants.mjs");

// The audited root sits one level below the temp dir so a mutation can
// place a module OUTSIDE the root (B6) without touching the shared OS
// tmpdir.
const work = mkdtempSync(join(tmpdir(), "relay-guard-battery-"));
const root = join(work, "repo");
function resetCopy() {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(root, { recursive: true });
  cpSync(join(relayRoot, "src"), join(root, "src"), { recursive: true });
  cpSync(join(relayRoot, "wrangler.toml"), join(root, "wrangler.toml"));
  cpSync(join(relayRoot, "README.md"), join(root, "README.md"));
}
function guardPasses() {
  try {
    execFileSync(process.execPath, [guard], {
      env: { ...process.env, INVARIANTS_ROOT: root },
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}
const append = (relPath, text) => appendFileSync(join(root, relPath), text);
const write = (relPath, text) => writeFileSync(join(root, relPath), text);
const sed = (relPath, from, to) => {
  const p = join(root, relPath);
  const s = readFileSync(p, "utf8");
  if (!s.includes(from)) throw new Error(`mutation anchor not found in ${relPath}: ${from}`);
  writeFileSync(p, s.replace(from, to));
};

const MUTATIONS = [
  // ---- original drift classes ----
  ["M1 nested src/lib storage", () => {
    mkdirSync(join(root, "src", "lib"), { recursive: true });
    write("src/lib/persist.ts", 'export const p = (c: any) => c.storage.put("k", 1);\n');
  }],
  ["M2 env-qualified KV binding", () => append("wrangler.toml", '\n[[env.production.kv_namespaces]]\nbinding = "KV"\nid = "x"\n')],
  ["M3 console outside the logger", () => append("src/worker.ts", 'const leaked = "x"; console.log({ leaked });\n')],
  ["M4 alternate wrangler.jsonc", () => write("wrangler.jsonc", "{}")],
  ["M5 fail-closed default flipped", () => sed("wrangler.toml", 'REQUIRE_UPGRADE_LIMITER = "true"', 'REQUIRE_UPGRADE_LIMITER = "false"')],
  ["M6 direct ctx.storage", () => append("src/worker.ts", 'export const m6 = (c: any) => c.storage.get("k");\n')],
  ["M7 observability enabled", () => sed("wrangler.toml", "enabled = false", "enabled = true")],
  ["M8 top-level KV binding", () => append("wrangler.toml", '\n[[kv_namespaces]]\nbinding = "KV"\nid = "x"\n')],
  ["M9 frame-cap drift", () => sed("src/room.ts", "MAX_FRAME_BYTES = 64 * 1024", "MAX_FRAME_BYTES = 32 * 1024")],
  // ---- alarms API (load-bearing for backpressure honesty: setAlarm
  //      persists to DO storage, so an alarm-driven idle sweep would
  //      break stores-nothing — the whole "no alarm sweep" story rests on
  //      these staying forbidden). Bare method access (NOT via `.storage.`)
  //      so each RED-proves the ALARM member rule in isolation — if a
  //      future edit dropped setAlarm/getAlarm/deleteAlarm from the
  //      guard's forbidden set, the storage rule would no longer mask it
  //      and these go GREEN, failing the battery. ----
  ["A1 setAlarm", () => append("src/room.ts", "export const a1 = (c: any) => c.setAlarm(Date.now() + 1000);\n")],
  ["A2 getAlarm", () => append("src/room.ts", "export const a2 = (c: any) => c.getAlarm();\n")],
  ["A3 deleteAlarm", () => append("src/room.ts", "export const a3 = (c: any) => c.deleteAlarm();\n")],
  // ---- first-round codex bypasses ----
  ["B1 computed ctx[\"storage\"]", () => append("src/worker.ts", 'export const b1 = (c: any) => c["storage"].put("k", 1);\n')],
  ["B2 reachable module outside src", () => {
    write("persist.ts", 'export const persist = (c: any) => c.storage.put("k", 1);\n');
    append("src/worker.ts", 'import { persist } from "../persist";\nexport const useP = persist;\n');
  }],
  ["B3a console[\"log\"]", () => append("src/worker.ts", 'export const b3 = (u: string) => console["log"]({ leaked: u });\n')],
  ["B3b aliased console method", () => append("src/worker.ts", 'const logAlias = console.log;\nexport const b3b = (u: string) => logAlias(u);\n')],
  ["B4 non-parameter value in the ws_close shape", () =>
    sed("src/log.ts", "export function logWsClose(code: unknown): void {",
      'export function logWsClose(_ignored: unknown): void {\n  const code = "leaked" as unknown as number;')],
  ["B5 single-quoted TOML key", () => append("wrangler.toml", "\n[[env.production.'kv_namespaces']]\nbinding = \"KV\"\nid = \"x\"\n")],
  // ---- second-round codex evasions ----
  ["N1 fake errClass helper outside the logger", () => append("src/room.ts",
    'function errClass2(x: unknown): string { return String((x as { url: string }).url); }\n' +
    'export const n1 = (x: unknown) => console.log({ evt: "ws_error", err: errClass2(x) });\n')],
  ["N1b corrupted errClass inside the logger", () =>
    sed("src/log.ts", 'return err instanceof Error ? "Error" : typeof err;',
      "return String((err as { url?: string }).url ?? typeof err);")],
  ["N2 static require escaping the TS graph", () => append("src/worker.ts",
    'declare const require: (id: string) => unknown;\nexport const n2 = require("../persist");\n')],
  ["N3 const-literal computed storage key", () => append("src/worker.ts",
    'const skey = "storage" as const;\nexport const n3 = (c: Record<string, { put(k: string, v: number): void }>) => c[skey].put("k", 1);\n')],
  ["N4 const-literal computed destructuring", () => append("src/worker.ts",
    'const dkey = "storage" as const;\nexport const n4 = (c: Record<string, unknown>) => { const { [dkey]: s } = c; return s; };\n')],
  ["N5 non-literal dynamic import", () => append("src/worker.ts",
    'export const n5 = (m: string) => import(m);\n')],
  // ---- round-3 runtime-semantic evasions (type-level closure defeated
  //      by ordinary inputs; the guard must pin the RUNTIME sanitizers) ----
  ["T1 ws_close sanitizer removed (raw shorthand emit)", () =>
    sed("src/log.ts",
      'console.log({ evt: "ws_close", code: Number.isInteger(code) ? code : -1 });',
      'console.log({ evt: "ws_close", code });')],
  ["T2 errClass emits mutable err.name", () =>
    sed("src/log.ts",
      'return err instanceof Error ? "Error" : typeof err;',
      "return err instanceof Error ? err.name : typeof err;")],
  // ---- dual-intake contract pins (IT-613 migration; in the standalone
  //      public repo these are the ONLY guard on the header-mechanism
  //      literals, since check-swift-contract self-skips there) ----
  ["D1 CONNECT_PATH drift", () =>
    sed("src/worker.ts", 'CONNECT_PATH = "/connect"', 'CONNECT_PATH = "/relay-connect"')],
  ["D2 ROOM_HEADER drift", () =>
    sed("src/worker.ts", 'ROOM_HEADER = "X-Scape-Room"', 'ROOM_HEADER = "X-Scape-RoomId"')],
  ["D3 ROOM_ID grammar drift", () =>
    sed("src/worker.ts", "const ROOM_ID = /^[0-9a-f]{64}$/;", "const ROOM_ID = /^[0-9a-fA-F]{64}$/;")],
  ["W1 relay wire-version drift (silently disables the ack path)", () =>
    sed("src/room.ts", "const WIRE_VERSION = 2;", "const WIRE_VERSION = 1;")],
  // ---- review-round: `self`/`scheduler` alias evasions. `self` is the
  //      idiomatic Workers global alias, so these are plausible ACCIDENTAL
  //      regressions, not just adversarial ones. Each banned capability
  //      class gets one alias-form probe. ----
  ["S1 self.caches storage alias", () => append("src/worker.ts",
    "export const s1 = () => self.caches;\n")],
  ["S2 self.setTimeout timer alias", () => append("src/worker.ts",
    "export const s2 = (f: () => void) => self.setTimeout(f, 1000);\n")],
  ["S3 self.eval reflection alias", () => append("src/worker.ts",
    "export const s3 = (code: string) => self.eval(code);\n")],
  ["S4 scheduler.wait timer", () => append("src/worker.ts",
    "export const s4 = () => scheduler.wait(1000);\n")],
  // ---- review-round: one BARE mutation per banned global name, so
  //      dropping any single name from FORBIDDEN_GLOBALS fails the
  //      battery (the S-class alias probes trip on `self` and would mask
  //      such a removal — same isolation principle as A1–A3). `require`
  //      is already isolated by N2. ----
  ["R1 bare caches", () => append("src/worker.ts",
    "export const r1 = () => caches;\n")],
  ["R2 bare setTimeout", () => append("src/worker.ts",
    "export const r2 = (f: () => void) => setTimeout(f, 1000);\n")],
  ["R3 bare setInterval", () => append("src/worker.ts",
    "export const r3 = (f: () => void) => setInterval(f, 1000);\n")],
  ["R4 bare globalThis", () => append("src/worker.ts",
    "export const r4 = () => globalThis;\n")],
  ["R5 Reflect.get", () => append("src/worker.ts",
    "export const r5 = (o: object, k: string) => Reflect.get(o, k);\n")],
  ["R6 direct eval", () => append("src/worker.ts",
    "export const r6 = (code: string) => eval(code);\n")],
  ["R7 Function constructor", () => append("src/worker.ts",
    "export const r7 = (code: string) => new Function(code);\n")],
  // ---- review-round: module resolving OUTSIDE the audited root. The
  //      escape file is deliberately innocuous so the RED can only come
  //      from the out-of-root rule, not from its contents. ----
  ["B6 import resolving outside the audited root", () => {
    writeFileSync(join(work, "outside.ts"), "export const escaped = 1;\n");
    append("src/worker.ts", 'import { escaped } from "../../outside";\nexport const b6 = escaped;\n');
  }],
  // ---- review-round: trace-event re-enablers (config keys that regress
  //      the telemetry-off default while [observability] stays clean) ----
  ["C1 logpush enabled", () =>
    sed("wrangler.toml", 'name = "scape-chat-relay"', 'name = "scape-chat-relay"\nlogpush = true')],
  ["C2 tail consumer attached", () =>
    sed("wrangler.toml", 'name = "scape-chat-relay"', 'name = "scape-chat-relay"\ntail_consumers = [{ service = "tail-log" }]')],
  // ---- review-round: doc'd wire-version examples must match
  //      WIRE_VERSION (clients drop v-mismatched envelopes as unknown,
  //      so a copied stale example silently loses frames) ----
  ["V1 stale wire-version example in README", () =>
    sed("README.md", '"v":2,"type":"error"', '"v":1,"type":"error"')],
  ["V2 stale wire-version example in wrangler.toml", () =>
    sed("wrangler.toml", '"v":2,"type":"error"', '"v":1,"type":"error"')],
  // ---- review-round: 429 Retry-After hint ↔ [ratelimits.simple] period
  //      lockstep, pinned from both sides ----
  ["RA1 limiter period drifts from the Retry-After hint", () =>
    sed("wrangler.toml", "period = 60", "period = 120")],
  ["RA2 Retry-After hint drifts from the limiter period", () =>
    sed("src/worker.ts", 'RETRY_AFTER_SECONDS = "60"', 'RETRY_AFTER_SECONDS = "45"')],
  // ---- codex round-4: timer MODULES. A namespace import hides
  //      setTimeout in property-name position, so the specifier itself
  //      must be banned — S2/R2 do not cover this path. ----
  ["TM1 namespace import of node:timers", () => append("src/worker.ts",
    'import * as timers from "node:timers";\nexport const tm1 = (f: () => void) => timers.setTimeout(f, 1000);\n')],
  ["TM2 namespace import of node:timers/promises", () => append("src/worker.ts",
    'import * as tp from "node:timers/promises";\nexport const tm2 = () => tp.setTimeout(1000);\n')],
  ["R8 bare setImmediate", () => append("src/worker.ts",
    "export const r8 = (f: () => void) => setImmediate(f);\n")],
  // R9 isolates the `self` FORBIDDEN_GLOBALS entry from the
  // receiver-de-alias branch: S1–S3 would stay RED through that branch
  // even if `self` were dropped from the set, but a BARE `self` (no
  // property access) is caught only by the set entry itself.
  ["R9 bare self", () => append("src/worker.ts",
    "export const r9 = () => self;\n")],
  // ---- codex round-4: the node_modules exclusion must match an exact
  //      path segment — a look-alike FILENAME outside the root must not
  //      borrow it. Innocuous content, same isolation rationale as B6. ----
  ["B7 out-of-root module named to spoof the node_modules exclusion", () => {
    writeFileSync(join(work, "node_modules-escape.ts"), "export const escaped = 2;\n");
    append("src/worker.ts", 'import { escaped as esc2 } from "../../node_modules-escape";\nexport const b7 = esc2;\n');
  }],
  // ---- codex round-5: remaining timer-closure family ----
  ["TM3 import-equals of node:timers", () => append("src/worker.ts",
    'import timers3 = require("node:timers");\nexport const tm3 = (f: () => void) => timers3.setTimeout(f, 1000);\n')],
  ["PR1 bare process", () => append("src/worker.ts",
    'export const pr1 = () => process.getBuiltinModule("node:timers");\n')],
  // PR2 keeps its body innocuous (`.env`, not `.getBuiltinModule`) so it
  // isolates the node:process SPECIFIER ban rather than the member ban.
  ["PR2 namespace import of node:process", () => append("src/worker.ts",
    'import * as proc from "node:process";\nexport const pr2 = () => proc.env;\n')],
  // PR3 isolates the getBuiltinModule MEMBER ban: the receiver is an
  // ordinary parameter, so neither the `process` global nor the module
  // specifiers fire — only the FORBIDDEN_MEMBERS entry does.
  ["PR3 getBuiltinModule on a laundered receiver", () => append("src/worker.ts",
    'export const pr3 = (p: { getBuiltinModule(id: string): unknown }) => p.getBuiltinModule("node:timers");\n')],
  ["CW1 namespace import of cloudflare:workers", () => append("src/worker.ts",
    'import * as w from "cloudflare:workers";\nexport const cw1 = () => w.scheduler.wait(1000);\n')],
  ["CW2 dynamic import of cloudflare:workers", () => append("src/worker.ts",
    'export const cw2 = () => import("cloudflare:workers");\n')],
  // ---- codex round-6: last two timer paths ----
  ["AS1 AbortSignal.timeout timer", () => append("src/worker.ts",
    'export const as1 = (ms: number) => new Promise((resolve) => AbortSignal.timeout(ms).addEventListener("abort", resolve, { once: true }));\n')],
  // CW3 spells the banned name as a STRING literal, which the identifier
  // ban cannot see — isolates the import/export-spelling rule (namedOnly
  // is satisfied, and `delayed.wait` sits in exempt property position).
  ["CW3 quoted named import of scheduler", () => append("src/worker.ts",
    'import { "scheduler" as delayed } from "cloudflare:workers";\nexport const cw3 = () => delayed.wait(1000);\n')],
  // ---- codex round-7: constructor laundering — recovers the AbortSignal
  //      constructor from the request signal without naming it. RED must
  //      come from the `constructor` MEMBER ban alone (`signal` is not
  //      banned; `timeout` sits in exempt property position). ----
  ["AS2 constructor laundering via req.signal", () => append("src/worker.ts",
    "export const as2 = (req: Request) => (req.signal.constructor as any).timeout(1000);\n")],
  // ---- codex round-8: descriptor-based laundering. "constructor" is a
  //      string ARGUMENT here, so only the reflection-primitive member
  //      bans can catch it. AS3 is the end-to-end repro; RF1–RF4 isolate
  //      each newly banned member. ----
  ["AS3 descriptor laundering via getOwnPropertyDescriptor", () => append("src/worker.ts",
    'export const as3 = (req: Request) => (Object.getOwnPropertyDescriptor(Object.getPrototypeOf(req.signal), "constructor") as any).value.timeout(1000);\n')],
  ["RF1 Object.getPrototypeOf", () => append("src/worker.ts",
    "export const rf1 = (x: object) => Object.getPrototypeOf(x);\n")],
  ["RF2 getOwnPropertyDescriptor", () => append("src/worker.ts",
    'export const rf2 = (x: object) => Object.getOwnPropertyDescriptor(x, "k");\n')],
  ["RF3 getOwnPropertyDescriptors", () => append("src/worker.ts",
    "export const rf3 = (x: object) => Object.getOwnPropertyDescriptors(x);\n")],
  ["RF4 legacy __proto__ accessor", () => append("src/worker.ts",
    "export const rf4 = (x: object) => (x as any).__proto__;\n")],
];

resetCopy();
if (!guardPasses()) {
  console.error("guard-battery: BASELINE IS RED — the unmutated tree fails the guard; fix that first.");
  rmSync(work, { recursive: true, force: true });
  process.exit(1);
}

const missed = [];
for (const [name, apply] of MUTATIONS) {
  resetCopy();
  apply();
  if (guardPasses()) {
    missed.push(name);
    console.error(`  ✘ ${name}: GUARD MISSED (stayed green)`);
  } else {
    console.log(`  ✔ ${name}: RED`);
  }
}
rmSync(work, { recursive: true, force: true });

if (missed.length > 0) {
  console.error(`guard-battery: FAILED — ${missed.length} mutation(s) not caught: ${missed.join("; ")}`);
  process.exit(1);
}
console.log(`guard-battery: OK (baseline GREEN, ${MUTATIONS.length} mutation classes RED)`);
