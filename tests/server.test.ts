import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { TelegramAuthServer } from "../src/server.js";
import type { TelegramAuthServerConfig } from "../src/server.js";
import { config, NOW, hmacData, BOT } from "./fixtures.js";
const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  incr: vi.fn(),
  set: vi.fn(),
}));
vi.mock("@upstash/redis", () => ({
  Redis: class {
    get = mocks.get;
    incr = mocks.incr;
    set = mocks.set;
  },
}));
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.clearAllMocks();
});
afterEach(() => vi.useRealTimers());

describe("application configuration", () => {
  it("reuses the same config object even during concurrent initialization", async () => {
    const options = config();
    const [first, second] = await Promise.all([
      TelegramAuthServer.init(options),
      TelegramAuthServer.init(options),
    ]);
    expect(first).toBe(second);
    expect(await TelegramAuthServer.create(options)).not.toBe(first);
  });
  it("isolates schemas with identical field names", async () => {
    const first = await TelegramAuthServer.init({
      ...config(),
      accessTokenConfig: {
        ttlMs: 1000,
        payloadSchema: z.object({ value: z.string() }),
      },
    });
    const second = await TelegramAuthServer.init({
      ...config(),
      accessTokenConfig: {
        ttlMs: 1000,
        payloadSchema: z.object({ value: z.number() }),
      },
    });
    expect(first).not.toBe(second);
    await expect(
      first.genAccessToken({ value: "text" }),
    ).resolves.toBeDefined();
    await expect(second.genAccessToken({ value: "text" })).rejects.toThrow();
  });
  it("captures key bytes and token configuration instead of mutable references", async () => {
    const options = {
      ...config(),
      secrets: { ...config().secrets, jweSecret: new Uint8Array(32).fill(7) },
    };
    const auth = await TelegramAuthServer.create(options);
    options.secrets.jweSecret.fill(0);
    options.accessTokenConfig.ttlMs = 1;
    const token = await auth.genAccessToken({ userId: "u" });
    expect(token.accessTokenExpiresAt).toBe(NOW + 60_000);
    await expect(
      auth.verifyAccessToken(token.accessToken),
    ).resolves.toBeDefined();
  });
  it.each([0, -1, NaN, Infinity, 1000.1])(
    "rejects invalid token TTL %s",
    async (ttlMs) => {
      await expect(
        TelegramAuthServer.create({
          ...config(),
          accessTokenConfig: { ttlMs },
        }),
      ).rejects.toThrow("TTL");
    },
  );
  it.each(["short", "é".repeat(32)])(
    "requires exactly 32 key bytes",
    async (jweSecret) => {
      await expect(
        TelegramAuthServer.create({
          ...config(),
          secrets: { ...config().secrets, jweSecret },
        }),
      ).rejects.toThrow("32");
    },
  );
  it("rejects invalid namespaces, missing identity fields, and absent revocation stores", async () => {
    await expect(
      TelegramAuthServer.create({ ...config(), namespace: "a:b" }),
    ).rejects.toThrow("namespace");
    await expect(
      TelegramAuthServer.create({
        ...config(),
        refreshTokenConfig: { ...config().refreshTokenConfig, idField: "" },
      }),
    ).rejects.toThrow("idField");
    await expect(
      TelegramAuthServer.create({ ...config(), tokenGroupStore: undefined }),
    ).rejects.toThrow("Configure Redis");
  });
  it("rejects non-schema config passed from JavaScript", async () => {
    const options: TelegramAuthServerConfig = config();
    Reflect.set(options.refreshTokenConfig, "payloadSchema", {});
    await expect(TelegramAuthServer.create(options)).rejects.toThrow(
      "Zod schema",
    );
    const access: TelegramAuthServerConfig = config();
    Reflect.set(access.accessTokenConfig, "payloadSchema", {});
    await expect(TelegramAuthServer.create(access)).rejects.toThrow(
      "Zod schema",
    );
  });
});

describe("Redis adapters", () => {
  it("uses atomic NX replay markers with the assertion's actual expiry and INCR groups", async () => {
    const auth = await TelegramAuthServer.create({
      ...config(),
      tokenGroupStore: undefined,
      initDataConfig: {
        botToken: BOT,
        singleUse: true,
        maxAuthDateAgeMs: 60000,
      },
      redisConfig: {
        redisUrl: "https://redis.example",
        redisToken: "synthetic-fixture",
      },
    });
    mocks.get.mockResolvedValue(null);
    mocks.set.mockResolvedValue("OK");
    mocks.incr.mockResolvedValue(1);
    expect((await auth.verifyInitData(hmacData())).valid).toBe(true);
    expect(mocks.set).toHaveBeenCalledWith(
      expect.stringMatching(
        /^test-app:bot:123456:production:replay:[a-f0-9]{64}$/,
      ),
      "used",
      { nx: true, px: 60000 },
    );
    mocks.set.mockResolvedValue(null);
    expect(await auth.verifyInitData(hmacData())).toEqual({
      valid: false,
      reason: "replayed",
    });
    const refresh = await auth.genRefreshToken({ userId: "u" });
    await auth.rotateRefreshTokenGroup(refresh.refreshToken);
    expect(mocks.incr).toHaveBeenCalledWith(
      expect.stringMatching(
        /^test-app:bot:123456:production:rtg:[a-f0-9]{64}$/,
      ),
    );
    mocks.set.mockRejectedValue(new Error("redis-secret-details"));
    expect(await auth.verifyInitData(hmacData())).toEqual({
      valid: false,
      reason: "store_unavailable",
    });
  });
  it("does not submit an expired assertion to Redis", async () => {
    const auth = await TelegramAuthServer.create({
      ...config(),
      initDataConfig: {
        botToken: BOT,
        singleUse: true,
        maxAuthDateAgeMs: 1000,
      },
      redisConfig: { redisUrl: "https://redis.example", redisToken: "fixture" },
    });
    // The clock can advance between proof validation and the atomic store operation.
    const clock = vi
      .spyOn(Date, "now")
      .mockReturnValueOnce(NOW)
      .mockReturnValueOnce(NOW)
      .mockReturnValue(NOW + 1000);
    expect((await auth.verifyInitData(hmacData())).valid).toBe(false);
    expect(mocks.set).not.toHaveBeenCalled();
    clock.mockRestore();
  });
});

describe("cookie adapters", () => {
  it("sets secure host-scoped cookies with maxAge in seconds and clamps expired cookies", async () => {
    const auth = await TelegramAuthServer.create(config());
    const write = vi.fn();
    await auth.setRefreshTokenCookie("credential", NOW + 10_500, write);
    expect(write).toHaveBeenLastCalledWith({
      name: "tgAuth_refreshToken",
      value: "credential",
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 10,
    });
    await auth.setRefreshTokenCookie("credential", NOW - 1, write);
    expect(write.mock.lastCall?.[0].maxAge).toBe(0);
    const clear = vi.fn();
    await auth.clearRefreshTokenCookie(clear);
    expect(clear).toHaveBeenCalledWith("tgAuth_refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 0,
    });
    expect(auth.getRefreshTokenCookie(() => "credential")).toBe("credential");
    expect(auth.getRefreshTokenCookie(() => "")).toBeNull();
    await expect(
      auth.setRefreshTokenCookie("credential", NaN, write),
    ).rejects.toThrow("expiry");
  });
  it("awaits asynchronous cookie adapters, including their failures", async () => {
    const auth = await TelegramAuthServer.create(config());
    const write = vi.fn(async () => {
      throw new Error("adapter failure");
    });
    await expect(
      auth.setRefreshTokenCookie("token", NOW + 1000, write),
    ).rejects.toThrow("adapter failure");
    await expect(auth.clearRefreshTokenCookie(write)).rejects.toThrow(
      "adapter failure",
    );
  });
});
