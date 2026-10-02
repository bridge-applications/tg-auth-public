import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { createAuthHandler } from "../examples/fetch-handler.js";
import { TelegramAuthServer } from "../src/server.js";
import { config, hmacData, NOW } from "./fixtures.js";
const origin = "https://app.example";
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());
async function setup() {
  const schema = z.object({ userId: z.string(), telegramId: z.string() });
  const options = {
    ...config(),
    accessTokenConfig: { ttlMs: 60000, payloadSchema: schema },
    refreshTokenConfig: {
      ttlMs: 3600000,
      payloadSchema: schema,
      idField: "userId",
    },
  };
  const auth = await TelegramAuthServer.create(options);
  const accounts = {
    resolveUser: vi.fn(async () => ({ userId: "user-1", telegramId: "12345" })),
    refreshUser: vi.fn(
      async (previous: { userId: string; telegramId: string }) => previous,
    ),
  };
  return {
    auth,
    options,
    accounts,
    handler: createAuthHandler(auth, origin, accounts),
  };
}
function request(
  path: string,
  data?: unknown,
  cookie?: string,
  extra: HeadersInit = {},
) {
  return new Request(origin + path, {
    method: "POST",
    headers: {
      Origin: origin,
      "Content-Type": "application/json",
      ...(cookie ? { Cookie: cookie } : {}),
      ...extra,
    },
    ...(data === undefined ? {} : { body: JSON.stringify(data) }),
  });
}
describe("Fetch integration", () => {
  it("authenticates, sets an HttpOnly cookie, refreshes, then revokes across devices", async () => {
    const { handler, auth } = await setup();
    const login = await handler(
      request("/api/auth/app-session", { telegramInitData: hmacData() }),
    );
    expect(login.status).toBe(200);
    expect(login.headers.get("Cache-Control")).toBe("no-store");
    const body = await login.json();
    expect(body.refreshToken).toBeUndefined();
    expect(
      (await auth.verifyAccessToken(body.accessToken)).payload?.userId,
    ).toBe("user-1");
    const header = login.headers.get("Set-Cookie")!;
    expect(header).toMatch(/HttpOnly; Secure; SameSite=Strict; Max-Age=3600/);
    const cookie = header.split(";", 1)[0]!;
    expect(
      (await handler(request("/api/auth/access-token", undefined, cookie)))
        .status,
    ).toBe(200);
    const logout = await handler(
      request("/api/auth/sign-out", { signAllOut: true }, cookie),
    );
    expect(logout.status).toBe(200);
    expect(logout.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(
      (await handler(request("/api/auth/access-token", undefined, cookie)))
        .status,
    ).toBe(401);
  });
  it("requires a same-origin HTTPS integration and rejects unknown or cross-origin requests", async () => {
    const { auth, accounts, handler } = await setup();
    for (const invalid of [
      "http://app.example",
      origin + "/path",
      origin + "/",
    ])
      expect(() => createAuthHandler(auth, invalid, accounts)).toThrow(
        "HTTPS origin",
      );
    expect(
      (
        await handler(
          request("/api/auth/app-session", {}, undefined, {
            Origin: "https://evil.example",
          }),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handler(
          new Request(origin + "/api/auth/app-session", { method: "POST" }),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handler(
          new Request("https://other.example/api/auth/app-session", {
            method: "POST",
            headers: { Origin: origin },
          }),
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await handler(
          new Request(origin + "/api/auth/app-session", {
            headers: { Origin: origin },
          }),
        )
      ).status,
    ).toBe(404);
    expect((await handler(request("/missing", {}))).status).toBe(404);
  });
  it("bounds actual streamed bodies and rejects malformed JSON, content types and requests", async () => {
    const { handler } = await setup();
    for (const req of [
      request("/api/auth/app-session"),
      request("/api/auth/app-session", {}),
      request("/api/auth/app-session", { telegramInitData: 4 }),
      request("/api/auth/app-session", { large: "x".repeat(16385) }),
      request("/api/auth/app-session", {}, undefined, {
        "Content-Type": "application/jsonp",
      }),
      new Request(origin + "/api/auth/app-session", {
        method: "POST",
        headers: { Origin: origin, "Content-Type": "application/json" },
        body: "{",
      }),
    ])
      expect((await handler(req)).status).toBe(400);
    expect((await handler(request("/api/auth/sign-out", {}))).status).toBe(400);
    expect(
      (
        await handler(
          request("/api/auth/app-session", {
            telegramInitData: "invalid-proof",
          }),
        )
      ).status,
    ).toBe(401);
  });
  it("does not trust duplicate cookies, invalid credentials, or missing refresh sessions", async () => {
    const { handler } = await setup();
    expect((await handler(request("/api/auth/access-token"))).status).toBe(401);
    expect(
      (
        await handler(
          request(
            "/api/auth/access-token",
            undefined,
            "tgAuth_refreshToken=one; tgAuth_refreshToken=two",
          ),
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await handler(
          request(
            "/api/auth/access-token",
            undefined,
            "tgAuth_refreshToken=bad",
          ),
        )
      ).status,
    ).toBe(401);
    expect(
      (
        await handler(
          request(
            "/api/auth/sign-out",
            { signAllOut: true },
            "tgAuth_refreshToken=bad",
          ),
        )
      ).status,
    ).toBe(200);
  });
  it("rechecks application authorization on login and refresh", async () => {
    const { auth, handler, accounts } = await setup();
    accounts.resolveUser.mockResolvedValueOnce(
      null as unknown as { userId: string; telegramId: string },
    );
    expect(
      (
        await handler(
          request("/api/auth/app-session", { telegramInitData: hmacData() }),
        )
      ).status,
    ).toBe(403);
    accounts.resolveUser.mockResolvedValueOnce({
      userId: "u",
      telegramId: "wrong-identity",
    });
    expect(
      (
        await handler(
          request("/api/auth/app-session", { telegramInitData: hmacData() }),
        )
      ).status,
    ).toBe(403);
    const refresh = await auth.genRefreshToken({
      userId: "u",
      telegramId: "12345",
    });
    accounts.refreshUser.mockResolvedValueOnce({
      userId: "other",
      telegramId: "12345",
    });
    expect(
      (
        await handler(
          request(
            "/api/auth/access-token",
            undefined,
            `tgAuth_refreshToken=${refresh.refreshToken}`,
          ),
        )
      ).status,
    ).toBe(403);
  });
  it("supports cookie-only logout and clears cookies while reporting shared-store failures", async () => {
    const { handler, auth, options } = await setup();
    expect(
      (await handler(request("/api/auth/clear-cookies"))).headers.get(
        "Set-Cookie",
      ),
    ).toContain("Max-Age=0");
    const { refreshToken } = await auth.genRefreshToken({
      userId: "u",
      telegramId: "12345",
    });
    options.tokenGroupStore.get.mockRejectedValue(
      new Error("secret infrastructure details"),
    );
    const res = await handler(
      request(
        "/api/auth/sign-out",
        { signAllOut: true },
        `tgAuth_refreshToken=${refreshToken}`,
      ),
    );
    expect(res.status).toBe(500);
    expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    expect(await res.text()).not.toContain("secret");
  });
});
