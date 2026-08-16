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
 * bypasses, and the 3 second-round codex evasions (fake errClass helper,
 * static require escaping the TS graph, const-literal computed storage
 * keys) plus adjacent variants — each RED-proven individually.
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

const work = mkdtempSync(join(tmpdir(), "relay-guard-battery-"));
function resetCopy() {
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work);
  cpSync(join(relayRoot, "src"), join(work, "src"), { recursive: true });
  cpSync(join(relayRoot, "wrangler.toml"), join(work, "wrangler.toml"));
}
function guardPasses() {
  try {
    execFileSync(process.execPath, [guard], {
      env: { ...process.env, INVARIANTS_ROOT: work },
      stdio: "pipe",
    });
    return true;
  } catch {
    return false;
  }
}
const append = (relPath, text) => appendFileSync(join(work, relPath), text);
const write = (relPath, text) => writeFileSync(join(work, relPath), text);
const sed = (relPath, from, to) => {
  const p = join(work, relPath);
  const s = readFileSync(p, "utf8");
  if (!s.includes(from)) throw new Error(`mutation anchor not found in ${relPath}: ${from}`);
  writeFileSync(p, s.replace(from, to));
};

const MUTATIONS = [
  // ---- original drift classes ----
  ["M1 nested src/lib storage", () => {
    mkdirSync(join(work, "src", "lib"), { recursive: true });
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
