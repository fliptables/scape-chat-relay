import { describe, expect, it } from "vitest";
import type { Env, UpgradeRateLimiter } from "../src/env";
import worker from "../src/worker";

// COVERAGE (ce:review #2): the nested test runtime can't materialize
// `[[ratelimits]]`, so vitest.config.ts opts the SELF.fetch suite out of
// the limiter (REQUIRE_UPGRADE_LIMITER="false") and admission.spec.ts
// stub-tests only the pure decision function. These tests close the
// remaining gap — the WORKER'S mapping of admission decisions onto HTTP
// responses, under the production fail-closed default — by calling the
// exported fetch handler directly with stub envs.

const ROOM = "a".repeat(64);

/// The handler's own request type (carries IncomingRequestCfProperties,
/// which a constructed Request can't have — irrelevant here, the worker
/// never reads req.cf).
type WorkerRequest = Parameters<typeof worker.fetch>[0];

function connectRequest(): WorkerRequest {
  return new Request("https://example.com/connect", {
    headers: {
      Upgrade: "websocket",
      "X-Scape-Room": ROOM,
      "CF-Connecting-IP": "203.0.113.7",
    },
  }) as WorkerRequest;
}

/// ROOMS is deliberately absent unless a test provides it: every
/// rejection here must be decided BEFORE the DO lookup, so reaching it
/// throws and fails the test loudly.
function stubEnv(overrides: Partial<Env>): Env {
  return { REQUIRE_UPGRADE_LIMITER: "true", ...overrides } as Env;
}

describe("worker mapping of admission decisions onto HTTP responses", () => {
  it("rejects with 503 limiter_misconfigured when the required UPGRADES binding is missing", async () => {
    const res = await worker.fetch(connectRequest(), stubEnv({ UPGRADES: undefined }));
    expect(res.status).toBe(503);
    expect(await res.text()).toBe("limiter_misconfigured");
  });

  it("rejects with 429 + Retry-After: 60 when the limiter says over-limit", async () => {
    const deny: UpgradeRateLimiter = { limit: async () => ({ success: false }) };
    const res = await worker.fetch(connectRequest(), stubEnv({ UPGRADES: deny }));
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
  });

  it("keys the limiter by CF-Connecting-IP and routes to the room DO on success", async () => {
    const keys: string[] = [];
    const allow: UpgradeRateLimiter = {
      limit: async ({ key }) => {
        keys.push(key);
        return { success: true };
      },
    };
    const sentinel = new Response("do-reached");
    const names: string[] = [];
    const rooms = {
      idFromName: (name: string) => {
        names.push(name);
        return name;
      },
      get: () => ({ fetch: async () => sentinel }),
    } as unknown as Env["ROOMS"];
    const res = await worker.fetch(connectRequest(), stubEnv({ UPGRADES: allow, ROOMS: rooms }));
    expect(res).toBe(sentinel);
    expect(keys).toEqual(["203.0.113.7"]);
    expect(names).toEqual([ROOM]);
  });
});
