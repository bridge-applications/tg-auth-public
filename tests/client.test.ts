import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { TelegramAuthClient } from "../src/client.js";
import type { TelegramAuthClientConfigInput } from "../src/client.js";
import {
  ApiAuthAppSessionReqSchema,
  ApiAuthAppSessionResSchema,
  ApiAuthAccessTokenResSchema,
  ApiStatus,
  ApiResCodes,
} from "../src/schemas.js";
import { callBackend } from "../src/logic/client/helpers/callBackend.js";
import { NOW, deferred } from "./fixtures.js";
const base = {
  status: ApiStatus.SUCCESS,
  statusCode: 200,
  respCode: ApiResCodes.SUCCESS_REQUEST_COMPLETED,
  version: "test",
};
const auth = {
  ...base,
  accessToken: "synthetic-access",
  accessTokenExpiresAt: NOW + 60_000,
  refreshTokenExpiresAt: NOW + 3_600_000,
};
const response = (value: unknown) => Response.json(value);
const init = (extra: Partial<TelegramAuthClientConfigInput> = {}) =>
  TelegramAuthClient.init({ baseUrl: "https://app.example", ...extra });
function storage(initial?: string) {
  let value = initial ?? null;
  return {
    getItem: vi.fn(() => value),
    setItem: vi.fn((_key: string, next: string) => {
      value = next;
    }),
    removeItem: vi.fn(() => {
      value = null;
    }),
  };
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  TelegramAuthClient.reset();
});
afterEach(() => {
  TelegramAuthClient.reset();
  vi.useRealTimers();
});

describe("browser session lifecycle", () => {
  it("works without window, Telegram SDK, or localStorage", async () => {
    init();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(auth)));
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    await TelegramAuthClient.getAppSession();
    expect(TelegramAuthClient.isAuthenticated).toBe(true);
    expect(TelegramAuthClient.expectedToBeAuthenticated).toBe(true);
    expect(
      (await TelegramAuthClient.getAccessTokenSilently()).accessToken,
    ).toBe(auth.accessToken);
  });
  it("injects configured version and init-data without mutating the caller's payload", async () => {
    init({ clientVersion: "1.2.3", telegram: { initData: "sdk-proof" } });
    const fetch = vi.fn().mockImplementation(async () => response(auth));
    vi.stubGlobal("fetch", fetch);
    const input = { extra: "value" };
    await TelegramAuthClient.getAppSession(input);
    expect(input).toEqual({ extra: "value" });
    expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({
      extra: "value",
      clientVersion: "1.2.3",
      telegramInitData: "sdk-proof",
    });
    await TelegramAuthClient.getAppSession({
      telegramInitData: "explicit-proof",
      clientVersion: "override",
    });
    expect(JSON.parse(fetch.mock.calls[1]![1].body)).toEqual({
      telegramInitData: "explicit-proof",
      clientVersion: "override",
    });
  });
  it("normalizes ISO expiry dates and never persists the refresh credential", async () => {
    const store = storage();
    init({ storage: store });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        response({
          ...auth,
          refreshToken: "must-not-cache",
          accessTokenExpiresAt: new Date(
            auth.accessTokenExpiresAt,
          ).toISOString(),
          refreshTokenExpiresAt: new Date(
            auth.refreshTokenExpiresAt,
          ).toISOString(),
        }),
      ),
    );
    const result = await TelegramAuthClient.getAppSession();
    expect(result.accessTokenExpiresAt).toBe(auth.accessTokenExpiresAt);
    expect(JSON.stringify(store.setItem.mock.calls)).not.toContain(
      "must-not-cache",
    );
    expect(TelegramAuthClient.isAuthenticated).toBe(true);
  });
  it("restores only valid unexpired cached credentials", () => {
    const store = storage(JSON.stringify(auth));
    init({ storage: store });
    expect(TelegramAuthClient.isAuthenticated).toBe(true);
    vi.setSystemTime(auth.accessTokenExpiresAt);
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    vi.setSystemTime(auth.refreshTokenExpiresAt);
    expect(TelegramAuthClient.expectedToBeAuthenticated).toBe(false);
    init({ storage: store });
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    expect(TelegramAuthClient.expectedToBeAuthenticated).toBe(false);
  });
  it.each([
    "invalid-json",
    '{"accessToken":5}',
    '{"accessToken":"old","accessTokenExpiresAt":0}',
  ])("discards invalid or expired caches", (raw) => {
    const store = storage(raw);
    init({ storage: store });
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    if (raw !== '{"accessToken":"old","accessTokenExpiresAt":0}')
      expect(store.removeItem).toHaveBeenCalled();
  });
  it("remains usable when storage reads, writes, and removals throw", async () => {
    const store = {
      getItem: vi.fn(() => {
        throw new Error("disabled");
      }),
      setItem: vi.fn(() => {
        throw new Error("quota");
      }),
      removeItem: vi.fn(() => {
        throw new Error("disabled");
      }),
    };
    init({ storage: store });
    TelegramAuthClient.commitAuth(auth);
    expect(TelegramAuthClient.isAuthenticated).toBe(true);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ ...base, success: true })),
    );
    await TelegramAuthClient.clearCookies();
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
  });
  it("deduplicates silent refresh and clears the pending promise after failure", async () => {
    init();
    const fetch = vi.fn().mockImplementation(async () => response(auth));
    vi.stubGlobal("fetch", fetch);
    await Promise.all([
      TelegramAuthClient.getAccessTokenSilently(),
      TelegramAuthClient.getAccessTokenSilently(),
    ]);
    expect(fetch).toHaveBeenCalledTimes(1);
    vi.setSystemTime(auth.accessTokenExpiresAt);
    fetch.mockRejectedValueOnce(new Error("network"));
    await expect(
      TelegramAuthClient.getAccessTokenSilently(),
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
    fetch.mockResolvedValue(
      response({ ...auth, accessTokenExpiresAt: NOW + 120_000 }),
    );
    await TelegramAuthClient.getAccessTokenSilently();
    expect(fetch).toHaveBeenCalledTimes(3);
  });
  it.each(["signOut", "clearCookies"] as const)(
    "ignores a late refresh after %s",
    async (method) => {
      init();
      const late = deferred<Response>();
      vi.stubGlobal(
        "fetch",
        vi
          .fn()
          .mockReturnValueOnce(late.promise)
          .mockResolvedValue(response({ ...base, success: true })),
      );
      const pending = TelegramAuthClient.getAccessToken();
      const rejected = expect(pending).rejects.toThrow("superseded");
      await TelegramAuthClient[method]();
      late.resolve(response(auth));
      await rejected;
      expect(TelegramAuthClient.isAuthenticated).toBe(false);
    },
  );
  it.each(["reset", "reinitialize"])(
    "ignores an app session after %s",
    async (action) => {
      init();
      const late = deferred<Response>();
      vi.stubGlobal(
        "fetch",
        vi.fn(() => late.promise),
      );
      const pending = TelegramAuthClient.getAppSession({
        telegramInitData: "proof",
      });
      const rejected = expect(pending).rejects.toThrow("superseded");
      if (action === "reset") TelegramAuthClient.reset();
      else init();
      late.resolve(response(auth));
      await rejected;
      if (TelegramAuthClient.isInitialized())
        expect(TelegramAuthClient.isAuthenticated).toBe(false);
    },
  );
  it("clears locally on failed logout and blocks authentication until logout finishes", async () => {
    init();
    TelegramAuthClient.commitAuth(auth);
    const late = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => late.promise),
    );
    const logout = TelegramAuthClient.signOut();
    const rejected = expect(logout).rejects.toMatchObject({
      code: "NETWORK_ERROR",
    });
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    await expect(TelegramAuthClient.getAccessTokenSilently()).rejects.toThrow(
      "sign-out",
    );
    expect(() => TelegramAuthClient.commitAuth(auth)).toThrow("sign-out");
    late.reject(new Error("offline"));
    await rejected;
    TelegramAuthClient.commitAuth(auth);
    expect(TelegramAuthClient.isAuthenticated).toBe(true);
  });
  it("rejects manual expired credentials", () => {
    init();
    expect(() =>
      TelegramAuthClient.commitAuth({ ...auth, refreshTokenExpiresAt: NOW }),
    ).toThrow("expired");
    expect(() =>
      TelegramAuthClient.commitAccess({ ...auth, accessTokenExpiresAt: NOW }),
    ).toThrow("expired");
  });
  it("supports typed custom schemas, headers, and cold-start refresh requests", async () => {
    init({
      urlPaths: { accessToken: "/custom/refresh" },
      customSchemas: {
        appSession: {
          res: ApiAuthAppSessionResSchema.extend({ userId: z.string() }),
        },
      },
    });
    const fetch = vi
      .fn()
      .mockImplementation(async () => response({ ...auth, userId: "u" }));
    vi.stubGlobal("fetch", fetch);
    const result = await TelegramAuthClient.getAppSession(
      {},
      undefined,
      ApiAuthAppSessionResSchema.extend({ userId: z.string() }),
    );
    expect(result.userId).toBe("u");
    const refreshed = await TelegramAuthClient.getAccessToken(
      ApiAuthAccessTokenResSchema.extend({ userId: z.string() }),
      { "X-Client": "test" },
      {
        payload: { telegramInitData: "proof" },
        schema: z.object({ telegramInitData: z.string() }),
      },
    );
    expect(refreshed.userId).toBe("u");
    expect(fetch.mock.lastCall).toEqual([
      "https://app.example/custom/refresh",
      expect.objectContaining({
        headers: expect.objectContaining({ "X-Client": "test" }),
        body: '{"telegramInitData":"proof"}',
      }),
    ]);
  });
  it("supports app-owned session responses without automatic credential commitment", async () => {
    init();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(response({ ...base, action: "onboard" })),
    );
    expect(
      await TelegramAuthClient.getAppSession(
        {},
        undefined,
        z.object({ action: z.string() }),
      ),
    ).toEqual({ action: "onboard" });
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
  });
});

describe("init-data adapters", () => {
  it("reports provider availability and validates session payloads", async () => {
    init();
    expect(TelegramAuthClient.hasInitDataProvider).toBe(false);
    init({ initDataProvider: () => "proof" });
    expect(TelegramAuthClient.hasInitDataProvider).toBe(true);
    await expect(
      TelegramAuthClient.getAppSession(
        null as unknown as z.input<typeof ApiAuthAppSessionReqSchema>,
      ),
    ).rejects.toThrow("must be an object");
  });
  it("uses explicit data, then SDK data, then the async provider", async () => {
    const provider = vi.fn(async () => "provider-proof");
    init({ telegram: { initData: "sdk-proof" }, initDataProvider: provider });
    expect(await TelegramAuthClient.resolveInitData("explicit-proof")).toBe(
      "explicit-proof",
    );
    expect(await TelegramAuthClient.resolveInitData()).toBe("sdk-proof");
    expect(provider).not.toHaveBeenCalled();
    init({ initDataProvider: provider });
    expect(await TelegramAuthClient.resolveInitData()).toBe("provider-proof");
    init();
    vi.stubGlobal("Telegram", { WebApp: { initData: "global-proof" } });
    expect(TelegramAuthClient.getInitData()).toBe("global-proof");
  });
  it("deduplicates provider calls without permanently caching the assertion", async () => {
    const gate = deferred<string>();
    const provider = vi.fn(() => gate.promise);
    init({ initDataProvider: provider });
    const one = TelegramAuthClient.resolveInitData();
    const two = TelegramAuthClient.resolveInitData();
    gate.resolve("  proof  ");
    expect(await one).toBe("proof");
    expect(await two).toBe("proof");
    expect(provider).toHaveBeenCalledTimes(1);
    await TelegramAuthClient.resolveInitData();
    expect(provider).toHaveBeenCalledTimes(2);
  });
  it("does not continue a session request after logout during init-data resolution", async () => {
    const gate = deferred<string>();
    init({ initDataProvider: () => gate.promise });
    const fetch = vi
      .fn()
      .mockResolvedValue(response({ ...base, success: true }));
    vi.stubGlobal("fetch", fetch);
    const pending = TelegramAuthClient.getAppSession();
    const rejected = expect(pending).rejects.toThrow("superseded");
    await TelegramAuthClient.signOut();
    gate.resolve("proof");
    await rejected;
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it("sanitizes provider failures and permits retry", async () => {
    const provider = vi
      .fn()
      .mockRejectedValueOnce(new Error("signed-secret-proof"))
      .mockResolvedValueOnce(42)
      .mockResolvedValueOnce("proof");
    init({ initDataProvider: provider });
    await expect(TelegramAuthClient.resolveInitData()).rejects.toThrow(
      "Init-data provider failed",
    );
    await expect(TelegramAuthClient.resolveInitData()).rejects.toThrow(
      "Init-data provider failed",
    );
    expect(await TelegramAuthClient.resolveInitData()).toBe("proof");
  });
});

describe("HTTP contracts and safe diagnostics", () => {
  const schema = {
    req: ApiAuthAppSessionReqSchema,
    res: ApiAuthAppSessionResSchema,
  };
  it("validates before fetching and sends parsed JSON with cookies", async () => {
    const fetch = vi.fn().mockImplementation(async () => response(auth));
    vi.stubGlobal("fetch", fetch);
    await expect(
      callBackend("https://app.example", "/auth", "POST", schema, {
        telegramInitData: 4,
      }),
    ).rejects.toMatchObject({ code: "REQUEST_VALIDATION" });
    expect(fetch).not.toHaveBeenCalled();
    await callBackend("https://app.example", "/auth", "POST", schema, {
      telegramInitData: "proof",
    });
    expect(fetch.mock.lastCall![1]).toMatchObject({
      credentials: "include",
      body: '{"telegramInitData":"proof"}',
    });
  });
  it.each([
    { ...auth, status: ApiStatus.ERROR },
    { ...auth, statusCode: 401 },
  ])("never commits an API error delivered with HTTP 200", async (body) => {
    init();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(body)));
    await expect(
      TelegramAuthClient.getAppSession({ telegramInitData: "proof" }),
    ).rejects.toMatchObject({ code: "API_ERROR" });
    expect(TelegramAuthClient.isAuthenticated).toBe(false);
    expect(TelegramAuthClient.expectedToBeAuthenticated).toBe(false);
  });
  it.each([{}, { ...auth, accessTokenExpiresAt: "tomorrow" }])(
    "rejects invalid responses",
    async (body) => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(body)));
      await expect(
        callBackend("https://app.example", "/auth", "POST", schema, {}),
      ).rejects.toMatchObject({ code: "RESPONSE_VALIDATION" });
    },
  );
  it("sanitizes non-JSON, HTTP and network errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(new Response("private-response"))
        .mockResolvedValueOnce(
          new Response("private-response", { status: 401 }),
        )
        .mockRejectedValueOnce(new Error("secret network details")),
    );
    for (const code of ["RESPONSE_VALIDATION", "HTTP_ERROR", "NETWORK_ERROR"])
      await expect(
        callBackend("https://app.example", "/auth", "POST", schema, {}),
      ).rejects.toMatchObject({ code });
  });
  it("times out a stalled fetch and a stalled response body", async () => {
    vi.useFakeTimers();
    const stalled = (_url: string, options: RequestInit) =>
      new Promise<Response>((_resolve, reject) =>
        options.signal?.addEventListener("abort", () =>
          reject(new DOMException("Abort", "AbortError")),
        ),
      );
    vi.stubGlobal("fetch", vi.fn(stalled));
    const rejected = expect(
      callBackend(
        "https://app.example",
        "/auth",
        "POST",
        schema,
        {},
        {},
        false,
        100,
      ),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    await vi.advanceTimersByTimeAsync(100);
    await rejected;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, options: RequestInit) => ({
        ok: true,
        status: 200,
        json: () =>
          new Promise((_resolve, reject) =>
            options.signal?.addEventListener("abort", () =>
              reject(new DOMException("Abort", "AbortError")),
            ),
          ),
      })),
    );
    const bodyRejected = expect(
      callBackend(
        "https://app.example",
        "/auth",
        "POST",
        schema,
        {},
        {},
        false,
        100,
      ),
    ).rejects.toMatchObject({ code: "TIMEOUT" });
    await vi.advanceTimersByTimeAsync(100);
    await bodyRejected;
  });
  it("logs metadata without headers, proofs, tokens or response contents", async () => {
    const log = vi.spyOn(console, "debug").mockImplementation(() => {});
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response(auth)));
    await callBackend(
      "https://app.example",
      "/auth",
      "POST",
      schema,
      { telegramInitData: "secret-proof" },
      { Authorization: "secret-header" },
      true,
    );
    expect(log).toHaveBeenCalled();
    expect(JSON.stringify(log.mock.calls)).not.toMatch(
      /secret-proof|secret-header|synthetic-access/,
    );
  });
  it("supports bodyless GET requests without sending JSON", async () => {
    const fetch = vi.fn().mockResolvedValue(response(base));
    vi.stubGlobal("fetch", fetch);
    await callBackend("https://app.example", "/auth", "GET", {
      req: null,
      res: z.object({ status: z.string() }),
    });
    expect(fetch.mock.lastCall![1].body).toBeUndefined();
  });
  it("requires initialization and validates configuration", () => {
    expect(TelegramAuthClient.isInitialized()).toBe(false);
    expect(() => TelegramAuthClient.isAuthenticated).toThrow("not initialized");
    for (const baseUrl of [
      "ftp://app.example",
      "https://user:password@app.example",
      "https://app.example?secret=x",
      "https://app.example#fragment",
    ])
      expect(() => init({ baseUrl })).toThrow("baseUrl");
    for (const requestTimeoutMs of [0, 120001])
      expect(() => init({ requestTimeoutMs })).toThrow("requestTimeoutMs");
    for (const appSession of ["invalid", "//evil.example", "/auth?query=x"])
      expect(() => init({ urlPaths: { appSession } })).toThrow("paths");
    expect(() => init({ clientVersion: " " })).toThrow("clientVersion");
    expect(() =>
      init({ initDataProvider: 3 as unknown as () => string }),
    ).toThrow("initDataProvider");
    expect(() =>
      init({ customSchemas: { appSession: { req: {} as z.ZodType } } }),
    ).toThrow("Zod schemas");
    expect(() =>
      init({ customSchemas: { appSession: { res: {} as z.ZodType } } }),
    ).toThrow("Zod schemas");
  });
});
