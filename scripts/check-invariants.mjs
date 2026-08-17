#!/usr/bin/env node
/**
 * Stores-nothing + contract invariant guard — STRUCTURAL edition.
 *
 * Runs before the vitest suite (`npm test`) and fails the build when the
 * relay's load-bearing guarantees regress. Both configuration languages
 * are parsed for real (no regex scanning): wrangler.toml through a TOML
 * parser with every key path walked, TypeScript through the compiler AST
 * over the module graph built from the configured entry point.
 *
 * WHAT THIS GUARD ENFORCES — exactly, no more:
 *  1. No Durable Object storage / alarms / cache / timer access in any
 *     module reachable from the entry point (or present under src/):
 *     property access, computed access with string-literal-TYPED keys
 *     (`const k = "storage" as const; ctx[k]`), and destructuring —
 *     computed string access whose key type can't be resolved to a
 *     literal is rejected outright, so unresolvable access can't hide.
 *  2. The module graph is the real bundle boundary: static imports and
 *     literal dynamic imports are followed wherever they point (incl.
 *     outside src/); `require` is forbidden entirely (this is an ESM
 *     worker) and non-literal dynamic import specifiers are rejected.
 *     Any module resolving OUTSIDE the repo root fails loudly — the
 *     bundler would include it but the audit below couldn't see it
 *     (node_modules and the TS default libs are the documented
 *     exclusions; deliberately out of scope, see "not a sandbox").
 *     node_modules is recognized only as an exact path segment, so a
 *     look-alike filename ("node_modules-escape.ts") can't borrow the
 *     exclusion. The node:timers / node:timers/promises / node:process
 *     modules are banned in every import form (a namespace import would
 *     hide setTimeout/setInterval in property-name position;
 *     process.getBuiltinModule would re-expose them with no import at
 *     all), import-equals (`import x = require(...)`) is banned as a
 *     syntax, and cloudflare:workers may be imported ONLY via named
 *     bindings — its namespace object re-exports `scheduler`.
 *  3. Console output is CENTRALIZED: `console` may appear only in
 *     src/log.ts, whose four call shapes are verified structurally and
 *     whose two sanitizers are pinned to RUNTIME-semantic bodies —
 *     errClass must be the fixed-literal-or-typeof form (never the
 *     mutable `err.name`), and the ws_close value must be the verbatim
 *     `Number.isInteger(code) ? code : -1` sanitizer with `code`
 *     symbol-resolving to logWsClose's own parameter (type annotations
 *     alone are erased by `as` casts, so the guard demands the runtime
 *     check). log.ts must import nothing. Everywhere else, any
 *     `console` reference fails. The runtime behavior itself is proven
 *     by tainted-input unit tests in test/log.spec.ts.
 *  4. Reflection/global escape hatches are banned in the graph:
 *     globalThis, self, scheduler, setImmediate, process, Reflect,
 *     eval, Function, require — plus the getBuiltinModule member on
 *     any receiver.
 *     The property-name exemption is revoked when the receiver is
 *     `self`/`globalThis`, so `self.eval(...)` / `globalThis.setTimeout`
 *     cannot slip through as "property names" — de-aliasing the global
 *     must not re-open a ban.
 *  5. wrangler.toml carries no storage-shaped binding under ANY key path
 *     (quoting and [[env.*]] qualification are normalized by the
 *     parser); hardened defaults (observability off, invocation_logs
 *     false, no logpush, no tail_consumers, REQUIRE_UPGRADE_LIMITER
 *     "true") hold at top level and in every env override; no
 *     wrangler.json/jsonc exists to bypass the audited file.
 *  6. Contract constants (route regex, frame cap, peer cap, bucket
 *     parameters) exist as declarations with exact initializers.
 *  7. Doc'd examples can't drift from the wire: every `"v":N` literal in
 *     README.md / wrangler.toml matches WIRE_VERSION, and the 429
 *     Retry-After hint in worker.ts stays in lockstep with
 *     wrangler.toml's [ratelimits.simple] period.
 *
 * Every class above is RED-proven by the executable mutation battery
 * (scripts/check-guard-battery.mjs, run in `npm test`).
 *
 * WHAT THIS GUARD DOES NOT CLAIM: it is drift-protection plus the
 * enumerated evasion-class closures — not a sandbox. A deliberately
 * malicious committer writing obfuscated exfiltration is a code-review
 * matter; the guard's job is to make every accidental regression and
 * every known cheap evasion fail the build loudly.
 *
 * INVARIANTS_ROOT env var overrides the audited root (used by the
 * battery to point the guard at mutated copies); dependencies still
 * resolve from this script's own location.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";
import ts from "typescript";

const relayRoot = process.env.INVARIANTS_ROOT
  ? resolve(process.env.INVARIANTS_ROOT)
  : join(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];
const fail = (msg) => failures.push(msg);

// ============================ wrangler.toml ============================

for (const alt of ["wrangler.json", "wrangler.jsonc"]) {
  if (existsSync(join(relayRoot, alt))) {
    fail(`${alt} exists — wrangler.toml must be the single config file this guard audits`);
  }
}

const FORBIDDEN_BINDING_KEYS = new Set([
  "kv_namespaces",
  "r2_buckets",
  "d1_databases",
  "analytics_engine_datasets",
  "queues",
  "services",
  "hyperdrive",
  "vectorize",
  "send_email",
  "browser",
  "ai",
]);

let config;
try {
  config = parseToml(readFileSync(join(relayRoot, "wrangler.toml"), "utf8"));
} catch (err) {
  fail(`wrangler.toml failed to parse: ${err.message}`);
  config = {};
}

function walkKeys(node, path) {
  if (Array.isArray(node)) {
    for (const item of node) walkKeys(item, path);
    return;
  }
  if (node === null || typeof node !== "object") return;
  for (const [key, value] of Object.entries(node)) {
    if (FORBIDDEN_BINDING_KEYS.has(key)) {
      fail(`wrangler.toml: storage-shaped binding "${[...path, key].join(".")}" is forbidden (stores-nothing)`);
    }
    walkKeys(value, [...path, key]);
  }
}
walkKeys(config, []);

function checkDefaults(scope, label) {
  // Trace-event re-enablers, forbidden at every scope: `logpush = true`
  // persists trace events (console lines + request metadata) to a
  // Logpush job, and `tail_consumers` streams the same events to another
  // Worker — either one regresses the telemetry-off default while the
  // observability keys below stay clean.
  if (scope.logpush) {
    fail(`wrangler.toml (${label}): logpush must not be enabled — trace events persist console lines and request metadata (stores-nothing)`);
  }
  if (Array.isArray(scope.tail_consumers) ? scope.tail_consumers.length > 0 : scope.tail_consumers !== undefined) {
    fail(`wrangler.toml (${label}): tail_consumers must not be configured — trace events would stream to a Worker outside this audited repo`);
  }
  const obs = scope.observability;
  if (label === "top-level") {
    if (!obs || obs.enabled !== false) {
      fail(`wrangler.toml (${label}): [observability] enabled must be false (stores-nothing default)`);
    }
    if (!obs?.logs || obs.logs.invocation_logs !== false) {
      fail(
        `wrangler.toml (${label}): [observability.logs] invocation_logs = false is required — ` +
          "Cloudflare's invocation logs persist the request URL (roomId) + client IP",
      );
    }
    if (scope.vars?.REQUIRE_UPGRADE_LIMITER !== "true") {
      fail(`wrangler.toml (${label}): [vars] REQUIRE_UPGRADE_LIMITER = "true" must ship (fail-closed default)`);
    }
  } else {
    if (obs?.enabled === true) fail(`wrangler.toml (${label}): observability enabled in env override`);
    if (obs?.logs && obs.logs.invocation_logs !== false) {
      fail(`wrangler.toml (${label}): invocation_logs weakened in env override`);
    }
    if (scope.vars && scope.vars.REQUIRE_UPGRADE_LIMITER !== "true") {
      fail(`wrangler.toml (${label}): REQUIRE_UPGRADE_LIMITER weakened in env override`);
    }
  }
}
checkDefaults(config, "top-level");
for (const [envName, envScope] of Object.entries(config.env ?? {})) {
  if (envScope && typeof envScope === "object") checkDefaults(envScope, `env.${envName}`);
}

// ======================= TypeScript module graph =======================

const entryRel = typeof config.main === "string" ? config.main : "src/worker.ts";
const entry = resolve(relayRoot, entryRel);
if (!existsSync(entry)) fail(`configured entry point ${entryRel} does not exist`);

const program = ts.createProgram([entry], {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ES2022,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  noEmit: true,
  types: [],
});

// node_modules must match as an exact path SEGMENT, never a substring —
// `includes("node_modules")` would let a file named node_modules-escape.ts
// borrow the exclusion (codex round-4 finding).
const inNodeModules = (fileName) => fileName.split(/[\\/]/).includes("node_modules");

// The bundle boundary must coincide with the audited boundary: wrangler
// would happily bundle a module resolved outside the repo root, but the
// per-file walk below only covers files under it — so an out-of-root
// resolution fails loudly instead of silently escaping the audit
// (node_modules and the TS default libs are the documented exclusions).
for (const sf of program.getSourceFiles()) {
  if (inNodeModules(sf.fileName) || program.isSourceFileDefaultLibrary(sf)) continue;
  if (!resolve(sf.fileName).startsWith(relayRoot + sep)) {
    fail(
      `${sf.fileName}: module resolves OUTSIDE the audited root — the bundler would include it ` +
        "but the guard cannot audit it; move it under the repo",
    );
  }
}

const graphFiles = program
  .getSourceFiles()
  .filter((sf) => resolve(sf.fileName).startsWith(relayRoot + sep) && !inNodeModules(sf.fileName));
const graphPaths = new Set(graphFiles.map((sf) => resolve(sf.fileName)));
const srcOnly = readdirSync(join(relayRoot, "src"), { recursive: true, withFileTypes: true })
  .filter((d) => d.isFile() && d.name.endsWith(".ts"))
  .map((d) => resolve(join(d.parentPath ?? d.path, d.name)))
  .filter((p) => !graphPaths.has(p));
const extraProgram = srcOnly.length
  ? ts.createProgram(srcOnly, { target: ts.ScriptTarget.ES2022, noEmit: true, types: [] })
  : null;
const allFiles = [
  ...graphFiles.map((sf) => ({ sf, chk: program.getTypeChecker() })),
  ...(extraProgram
    ? extraProgram
        .getSourceFiles()
        .filter((sf) => srcOnly.includes(resolve(sf.fileName)))
        .map((sf) => ({ sf, chk: extraProgram.getTypeChecker() }))
    : []),
];
if (allFiles.length < 5) {
  fail(`expected ≥5 modules in the scan set, found ${allFiles.length} — graph construction broken?`);
}

// getBuiltinModule (on ANY receiver) re-exposes node builtins — incl.
// node:timers — with no import for the graph rules to see; workerd
// implements it under nodejs_compat (codex round-5 finding).
const FORBIDDEN_MEMBERS = new Set(["storage", "setAlarm", "getAlarm", "deleteAlarm", "getBuiltinModule"]);
const FORBIDDEN_GLOBALS = new Set([
  "caches",
  "setTimeout",
  "setInterval",
  // setImmediate ships as a global under nodejs_compat — same timer
  // family, same DO-pinning concern.
  "setImmediate",
  "globalThis",
  // `self` is the idiomatic Workers global alias — without it in the set,
  // `self.caches` / `self.setTimeout` / `self.eval` would all pass green
  // (their property names sit in the exempted position below).
  "self",
  // `scheduler.wait()` is a timer in different clothing: it pins the DO
  // awake exactly like setTimeout, which the no-timer guarantee forbids.
  "scheduler",
  // `process.getBuiltinModule("node:timers")` re-exposes timers with no
  // import at all; nothing in a bindings-based Worker needs `process`.
  "process",
  "eval",
  "Function",
  "Reflect",
  "require",
]);
// Capability MODULES, banned in every import form (static, re-export,
// dynamic): nodejs_compat exposes node:timers / node:timers/promises in
// workerd, and a namespace import (`import * as t from "node:timers"`)
// would put setTimeout/setInterval in the exempted property-name
// position — outside the identifier ban above (codex round-4 finding).
// node:process joins them because process.getBuiltinModule re-exposes
// every builtin with no further import (codex round-5 finding).
const FORBIDDEN_MODULE_SPECIFIERS = /^(node:)?(timers(\/promises)?|process)$/;

const LOGGER_MODULE = resolve(relayRoot, "src", "log.ts");

function rel(sf) {
  return resolve(sf.fileName).slice(relayRoot.length + 1);
}
function loc(sf, node) {
  const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return `${rel(sf)}:${line + 1}`;
}
function stringValueOf(node) {
  return ts.isStringLiteralLike(node) ? node.text : null;
}

/// Resolve a computed key to a string, using the TYPE when the syntax
/// isn't a literal: `const k = "storage" as const; ctx[k]` has a
/// string-literal type carrying the value. Returns:
///   { kind: "string", value }  — resolved string key
///   { kind: "number" }         — numeric index (allowed)
///   { kind: "opaque" }         — unresolvable (rejected by callers)
function resolveKey(expr, chk) {
  const lit = stringValueOf(expr);
  if (lit !== null) return { kind: "string", value: lit };
  const type = chk.getTypeAtLocation(expr);
  if (type.isStringLiteral()) return { kind: "string", value: type.value };
  if (type.flags & ts.TypeFlags.NumberLike) return { kind: "number" };
  return { kind: "opaque" };
}

/// The four reviewed log shapes, checked ONLY inside src/log.ts. The
/// `code` shorthand must resolve by symbol to the numeric parameter of
/// logWsClose itself; `err` values must be calls to the verified
/// errClass. Everywhere outside log.ts, ANY console reference fails.
function isAllowedConsoleCall(call, sf, chk) {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const method = call.expression.name.text;
  if (call.arguments.length !== 1) return false;
  const arg = call.arguments[0];
  if (!ts.isObjectLiteralExpression(arg)) return false;
  const props = new Map();
  for (const p of arg.properties) {
    if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) props.set(p.name.text, p);
    else if (ts.isShorthandPropertyAssignment(p)) props.set(p.name.text, p);
    else return false;
  }
  const evt = props.get("evt");
  const evtName = evt && ts.isPropertyAssignment(evt) ? stringValueOf(evt.initializer) : null;
  const errIsErrClass = (p) =>
    p &&
    ts.isPropertyAssignment(p) &&
    ts.isCallExpression(p.initializer) &&
    ts.isIdentifier(p.initializer.expression) &&
    p.initializer.expression.text === "errClass";

  if (method === "log" && evtName === "room_budget_drop" && props.size === 1) return true;
  if (method === "log" && evtName === "dead_peer_drop" && props.size === 2 && errIsErrClass(props.get("err"))) return true;
  if (method === "error" && evtName === "ws_error" && props.size === 2 && errIsErrClass(props.get("err"))) return true;
  if (method === "log" && evtName === "ws_close" && props.size === 2) {
    // The value must be the exact RUNTIME integer sanitizer — a type
    // annotation alone is erased by an `as` cast at a call site, so the
    // guard demands `Number.isInteger(code) ? code : -1` verbatim, with
    // `code` symbol-resolving to logWsClose's own parameter (a shadowing
    // local fails).
    const codeProp = props.get("code");
    if (!codeProp || !ts.isPropertyAssignment(codeProp)) return false;
    const init = codeProp.initializer;
    if (init.getText(sf).replace(/\s+/g, " ") !== "Number.isInteger(code) ? code : -1") return false;
    if (!ts.isConditionalExpression(init) || !ts.isIdentifier(init.whenTrue)) return false;
    const sym = chk.getSymbolAtLocation(init.whenTrue);
    const decl = sym?.valueDeclaration;
    return (
      decl !== undefined &&
      ts.isParameter(decl) &&
      ts.isFunctionDeclaration(decl.parent) &&
      decl.parent.name?.getText(sf) === "logWsClose"
    );
  }
  return false;
}

/// src/log.ts leaf-module checks: no imports (nothing to smuggle values
/// through), and errClass's body is exactly the class-name-or-typeof
/// form — its output domain is then closed for ANY input, so call-site
/// arguments don't need policing.
function checkLoggerModule(sf) {
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) || ts.isImportEqualsDeclaration(stmt)) {
      fail(`${rel(sf)}: the logger module must import nothing`);
    }
  }
  const errClassDecl = sf.statements.find(
    (s) => ts.isFunctionDeclaration(s) && s.name?.getText(sf) === "errClass",
  );
  if (!errClassDecl || !errClassDecl.body || errClassDecl.body.statements.length !== 1) {
    fail(`${rel(sf)}: errClass must be a single-return function declaration`);
    return;
  }
  const ret = errClassDecl.body.statements[0];
  const retText =
    ts.isReturnStatement(ret) && ret.expression
      ? ret.expression.getText(sf).replace(/\s+/g, " ")
      : null;
  // NEVER `err.name`: Error.name is MUTABLE arbitrary text (a library or
  // adversary can set it to request-derived content). Only our own fixed
  // literal and the closed set of typeof strings are runtime-safe.
  if (retText !== 'err instanceof Error ? "Error" : typeof err') {
    fail(
      `${rel(sf)}: errClass body drifted (found: ${retText ?? "not a return"}) — ` +
        'must be exactly `err instanceof Error ? "Error" : typeof err`; its runtime-closed output domain ' +
        "(fixed literal | typeof string) is what makes every log line identifier-free for ANY input",
    );
  }
}

for (const { sf, chk } of allFiles) {
  const isLoggerModule = resolve(sf.fileName) === LOGGER_MODULE;
  if (isLoggerModule) checkLoggerModule(sf);

  const visit = (node) => {
    // (1) storage-shaped member access: property, computed (with the key
    // resolved through the type system), or destructuring.
    if (ts.isPropertyAccessExpression(node) && FORBIDDEN_MEMBERS.has(node.name.text)) {
      fail(`${loc(sf, node)}: forbidden member access ".${node.name.text}" (stores-nothing)`);
    }
    if (ts.isElementAccessExpression(node)) {
      const key = resolveKey(node.argumentExpression, chk);
      if (key.kind === "string" && FORBIDDEN_MEMBERS.has(key.value)) {
        fail(`${loc(sf, node)}: forbidden computed access ["${key.value}"] (stores-nothing)`);
      } else if (key.kind === "opaque") {
        fail(
          `${loc(sf, node)}: computed access with an unresolvable string key — ` +
            "use static property access or a const string-literal key so the guard can audit it",
        );
      }
    }
    if (ts.isBindingElement(node)) {
      if (node.propertyName && ts.isComputedPropertyName(node.propertyName)) {
        const key = resolveKey(node.propertyName.expression, chk);
        if (key.kind === "string" && FORBIDDEN_MEMBERS.has(key.value)) {
          fail(`${loc(sf, node)}: forbidden computed destructuring of "${key.value}" (stores-nothing)`);
        } else if (key.kind !== "number" && key.kind !== "string") {
          fail(`${loc(sf, node)}: computed destructuring with an unresolvable key`);
        }
      } else {
        const name = (node.propertyName ?? node.name).getText(sf).replace(/^["']|["']$/g, "");
        if (FORBIDDEN_MEMBERS.has(name)) {
          fail(`${loc(sf, node)}: forbidden destructuring of "${name}" (stores-nothing)`);
        }
      }
    }
    // (2) module-graph escape hatches: require is forbidden outright
    // (ESM worker; esbuild would bundle a static require the TS graph
    // can't see), and dynamic import must use a literal specifier
    // (literal ones are part of the graph; opaque ones aren't auditable).
    if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      stringValueOf(node.arguments[0]) === null
    ) {
      fail(`${loc(sf, node)}: dynamic import with a non-literal specifier escapes the audited graph`);
    }
    // (2b) import-equals is banned as a SYNTAX: `import x = require(...)`
    // carries no `require` Identifier node (the ban above can't see it)
    // and is a different AST shape than the import forms audited below —
    // and this is an ESM worker, so it has no legitimate use.
    if (ts.isImportEqualsDeclaration(node)) {
      fail(`${loc(sf, node)}: import-equals (\`import x = require(...)\`) is forbidden — ESM worker; use a static import the guard can audit`);
    }
    // (2c) capability modules — see FORBIDDEN_MODULE_SPECIFIERS.
    const moduleSpec = ts.isImportDeclaration(node)
      ? stringValueOf(node.moduleSpecifier)
      : ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined
        ? stringValueOf(node.moduleSpecifier)
        : ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword
          ? stringValueOf(node.arguments[0])
          : null;
    if (moduleSpec !== null && FORBIDDEN_MODULE_SPECIFIERS.test(moduleSpec)) {
      fail(
        `${loc(sf, node)}: forbidden module import "${moduleSpec}" — ` +
          "node:timers re-exposes setTimeout/setInterval behind a namespace receiver, and " +
          "node:process re-exposes every builtin via getBuiltinModule (no-timers)",
      );
    }
    // (2d) cloudflare:workers may be imported ONLY via named bindings:
    // its module namespace object re-exports `scheduler`, so a
    // namespace/default/dynamic/re-export form would de-alias the banned
    // global into exempt property position (`w.scheduler.wait(...)`).
    // Named bindings stay auditable — importing `scheduler` by name
    // (renamed or not) trips the identifier ban above.
    if (moduleSpec === "cloudflare:workers") {
      const namedOnly =
        ts.isImportDeclaration(node) &&
        (node.importClause === undefined ||
          (node.importClause.name === undefined &&
            node.importClause.namedBindings !== undefined &&
            ts.isNamedImports(node.importClause.namedBindings)));
      if (!namedOnly) {
        fail(
          `${loc(sf, node)}: cloudflare:workers may only be imported via named bindings — ` +
            'its namespace object re-exposes "scheduler" (no-timers)',
        );
      }
    }
    // (3) forbidden globals incl. reflection escape hatches + require.
    // Property-name position is exempt (`obj.storage` is the MEMBER
    // rule's job; `x.eval` on an ordinary receiver is someone else's
    // method) — EXCEPT when the receiver is a global alias: de-aliasing
    // through `self.`/`globalThis.` must not re-open a ban.
    if (ts.isIdentifier(node) && FORBIDDEN_GLOBALS.has(node.text)) {
      const p = node.parent;
      const receiverIsGlobalAlias =
        ts.isPropertyAccessExpression(p) &&
        p.name === node &&
        ts.isIdentifier(p.expression) &&
        (p.expression.text === "self" || p.expression.text === "globalThis");
      const isDeclarationName =
        (ts.isPropertyAccessExpression(p) && p.name === node && !receiverIsGlobalAlias) ||
        ts.isPropertySignature(p) ||
        ts.isMethodSignature(p);
      if (!isDeclarationName) {
        fail(`${loc(sf, node)}: forbidden global "${node.text}" (stores-nothing / no-timers / no-reflection)`);
      }
    }
    // (4) console: forbidden everywhere except src/log.ts, and there only
    // as the receiver of one of the four reviewed call shapes.
    if (ts.isIdentifier(node) && node.text === "console") {
      const access = node.parent;
      const call = access?.parent;
      const ok =
        isLoggerModule &&
        ts.isPropertyAccessExpression(access) &&
        access.expression === node &&
        call !== undefined &&
        ts.isCallExpression(call) &&
        call.expression === access &&
        isAllowedConsoleCall(call, sf, chk);
      if (!ok) {
        fail(
          isLoggerModule
            ? `${loc(sf, node)}: console call in the logger does not match a reviewed shape`
            : `${loc(sf, node)}: console is forbidden outside src/log.ts — add a reviewed function to the logger instead`,
        );
      }
    }
    // (5) auto-response pairs must be exactly ping/pong.
    if (ts.isNewExpression(node) && node.expression.getText(sf) === "WebSocketRequestResponsePair") {
      const [a, b] = node.arguments ?? [];
      if (stringValueOf(a) !== "ping" || stringValueOf(b) !== "pong") {
        fail(`${loc(sf, node)}: auto-response pair other than ("ping","pong") is forbidden`);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

// ========================= contract literals ==========================
const CONTRACT = [
  ["MAX_FRAME_BYTES", "64 * 1024", "64 KiB frame cap"],
  ["MAX_PEERS_PER_ROOM", "25", "25-peer room cap"],
  ["BUCKET_CAPACITY", "10", "per-conn burst capacity"],
  ["REFILL_PER_SEC", "2", "per-conn sustained rate"],
  ["WIRE_VERSION", "2", "relay-authored envelope version (clients drop v≠supportedVersion as .unknown)"],
];
const declInits = new Map();
for (const { sf } of allFiles) {
  const collect = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      declInits.set(node.name.text, node.initializer.getText(sf).replace(/\s+/g, " "));
    }
    ts.forEachChild(node, collect);
  };
  collect(sf);
}
for (const [name, expected, what] of CONTRACT) {
  if (declInits.get(name) !== expected) {
    fail(
      `contract constant ${name} (${what}) missing or drifted (found: ${declInits.get(name) ?? "absent"}) — ` +
        "this value is compiled into the Scape client; changing it is a coordinated contract bump",
    );
  }
}
const routeInit = declInits.get("ROUTE");
if (routeInit !== String.raw`/^\/room\/([0-9a-f]{64})$/`) {
  fail(`contract constant ROUTE (legacy roomId route regex, dual window) missing or drifted (found: ${routeInit ?? "absent"})`);
}
// Dual-window intake contract (IT-613 roomId-off-URL migration): the
// header mechanism's literals are compiled into the Swift client.
const DUAL_INTAKE = [
  ["CONNECT_PATH", '"/connect"', "header-mechanism connect path"],
  ["ROOM_HEADER", '"X-Scape-Room"', "roomId header name"],
  ["ROOM_ID", String.raw`/^[0-9a-f]{64}$/`, "roomId value grammar"],
];
for (const [name, expected, what] of DUAL_INTAKE) {
  if (declInits.get(name) !== expected) {
    fail(`contract constant ${name} (${what}) missing or drifted (found: ${declInits.get(name) ?? "absent"})`);
  }
}

// ====================== doc'd wire-version pins =======================
// README.md and wrangler.toml both show example relay-authored frames.
// Clients drop v-mismatched envelopes as unknown, so a stale `"v":N` in
// an example silently loses frames for any implementer who copies it —
// pin every doc'd literal to the WIRE_VERSION contract value.
const WIRE_VERSION_EXPECTED = CONTRACT.find(([name]) => name === "WIRE_VERSION")[1];
for (const docFile of ["README.md", "wrangler.toml"]) {
  const docPath = join(relayRoot, docFile);
  if (!existsSync(docPath)) {
    fail(`${docFile} missing — the guard pins its example wire-version literals`);
    continue;
  }
  for (const m of readFileSync(docPath, "utf8").matchAll(/"v"\s*:\s*(\d+)/g)) {
    if (m[1] !== WIRE_VERSION_EXPECTED) {
      fail(
        `${docFile}: example wire version "v":${m[1]} drifted from WIRE_VERSION = ${WIRE_VERSION_EXPECTED} — ` +
          "clients drop v-mismatched envelopes as unknown, so a copied example silently loses frames",
      );
    }
  }
}

// =================== Retry-After ↔ limiter lockstep ===================
// worker.ts advertises a retry hint on 429s; wrangler.toml's
// [ratelimits.simple] period defines the actual window. Pin both sides
// so neither can drift without a coordinated change.
const retryAfterInit = declInits.get("RETRY_AFTER_SECONDS");
if (retryAfterInit !== '"60"') {
  fail(
    `contract constant RETRY_AFTER_SECONDS (429 retry hint) missing or drifted (found: ${retryAfterInit ?? "absent"}) — ` +
      "must stay in lockstep with wrangler.toml [ratelimits.simple] period",
  );
}
const upgradesLimiter = (Array.isArray(config.ratelimits) ? config.ratelimits : []).find(
  (r) => r && typeof r === "object" && r.name === "UPGRADES",
);
if (upgradesLimiter?.simple?.period !== 60) {
  fail(
    "wrangler.toml: [ratelimits.simple] period for UPGRADES missing or drifted from 60 — " +
      "the 429 Retry-After hint in src/worker.ts (RETRY_AFTER_SECONDS) advertises this window",
  );
}

// ============================== verdict ===============================
if (failures.length > 0) {
  console.error("check-invariants: FAILED\n");
  for (const f of failures) console.error(`  ✘ ${f}`);
  process.exit(1);
}
console.log("check-invariants: OK (stores-nothing + contract invariants hold, structurally)");
