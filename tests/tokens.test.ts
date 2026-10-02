import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { CompactEncrypt } from "jose";
import { z } from "zod";
import { TelegramAuthServer } from "../src/server.js";
import { config, memoryGroups, NOW, deferred } from "./fixtures.js";

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe("encrypted tokens", () => {
  it("rejects oversized claims before issuing an unusable credential", async () => {
    const auth = await TelegramAuthServer.create(config());
    await expect(
      auth.genAccessToken({ userId: "x".repeat(24000) }),
    ).rejects.toMatchObject({ code: "INVALID_PAYLOAD" });
  });
  it("isolates credentials by bot and Telegram environment", async () => {
    const auth = await TelegramAuthServer.create(config());
    const { accessToken } = await auth.genAccessToken({ userId: "u" });
    for (const initDataConfig of [
      { botId: 654321, validation: "ed25519" as const },
      {
        botToken: config().initDataConfig.botToken,
        environment: "test" as const,
      },
    ]) {
      const other = await TelegramAuthServer.create({
        ...config(),
        initDataConfig,
      });
      await expect(other.verifyAccessToken(accessToken)).rejects.toMatchObject({
        code: "INVALID_TOKEN",
      });
    }
  });
  it("round trips validated access and refresh payloads, including defaults", async () => {
    const auth = await TelegramAuthServer.create(config());
    const access = await auth.genAccessToken({
      userId: "user-1",
      ignored: "value",
    });
    const refresh = await auth.genRefreshToken({ userId: "user-1" });
    expect((await auth.verifyAccessToken(access.accessToken)).payload).toEqual({
      userId: "user-1",
      role: "member",
    });
    expect(await auth.verifyRefreshToken(refresh.refreshToken)).toEqual({
      payload: { userId: "user-1", role: "member" },
      meta: { iat: NOW, exp: NOW + 3_600_000, idField: "user-1", group: 0 },
    });
    expect(access.accessToken.split(".")).toHaveLength(5);
    expect(access.accessToken).not.toContain("user-1");
  });
  it("supports an access token without a custom payload", async () => {
    const options = { ...config(), accessTokenConfig: { ttlMs: 1000 } };
    const auth = await TelegramAuthServer.create(options);
    const token = await auth.genAccessToken();
    expect(
      (await auth.verifyAccessToken(token.accessToken)).payload,
    ).toBeNull();
    await expect(
      auth.genAccessToken({ userId: "user-1" }),
    ).rejects.toMatchObject({ code: "INVALID_PAYLOAD" });
  });
  it("never accepts refresh credentials as access tokens or the reverse", async () => {
    const auth = await TelegramAuthServer.create(config());
    const access = await auth.genAccessToken({ userId: "user-1" });
    const refresh = await auth.genRefreshToken({ userId: "user-1" });
    await expect(
      auth.verifyAccessToken(refresh.refreshToken),
    ).rejects.toMatchObject({ code: "INVALID_TOKEN" });
    await expect(
      auth.verifyRefreshToken(access.accessToken),
    ).rejects.toMatchObject({ code: "INVALID_TOKEN" });
  });
  it("rejects different keys, tampered ciphertext, and cross-application tokens", async () => {
    const auth = await TelegramAuthServer.create(config());
    const { accessToken } = await auth.genAccessToken({ userId: "user-1" });
    const differentKey = await TelegramAuthServer.create({
      ...config(),
      secrets: { ...config().secrets, jweSecret: "x".repeat(32) },
    });
    const differentApp = await TelegramAuthServer.create({
      ...config(),
      namespace: "another-app",
    });
    for (const verifier of [differentKey, differentApp])
      await expect(
        verifier.verifyAccessToken(accessToken),
      ).rejects.toMatchObject({ code: "INVALID_TOKEN" });
    const parts = accessToken.split(".");
    parts[3] = (parts[3]![0] === "A" ? "B" : "A") + parts[3]!.slice(1);
    await expect(auth.verifyAccessToken(parts.join("."))).rejects.toMatchObject(
      { code: "INVALID_TOKEN" },
    );
  });
  it.each(["access", "refresh"] as const)(
    "expires a %s token at the exact expiry boundary",
    async (kind) => {
      const auth = await TelegramAuthServer.create(config());
      if (kind === "access") {
        const token = await auth.genAccessToken({ userId: "u" });
        vi.setSystemTime(token.accessTokenExpiresAt - 1);
        await expect(
          auth.verifyAccessToken(token.accessToken),
        ).resolves.toBeDefined();
        vi.setSystemTime(token.accessTokenExpiresAt);
        await expect(
          auth.verifyAccessToken(token.accessToken),
        ).rejects.toMatchObject({ code: "EXPIRED_TOKEN" });
      } else {
        const token = await auth.genRefreshToken({ userId: "u" });
        vi.setSystemTime(token.refreshTokenExpiresAt);
        await expect(
          auth.verifyRefreshToken(token.refreshToken),
        ).rejects.toMatchObject({ code: "EXPIRED_TOKEN" });
      }
    },
  );
  it.each([{}, { userId: 42 }, { userId: "" }, { userId: "u", role: "owner" }])(
    "rejects invalid payload %j before issuance",
    async (payload) => {
      const auth = await TelegramAuthServer.create(config());
      await expect(auth.genAccessToken(payload)).rejects.toMatchObject({
        code: "INVALID_PAYLOAD",
      });
      await expect(auth.genRefreshToken(payload)).rejects.toMatchObject({
        code: "INVALID_PAYLOAD",
      });
    },
  );
  it("requires a string identity after schema transformation", async () => {
    const auth = await TelegramAuthServer.create({
      ...config(),
      refreshTokenConfig: {
        ttlMs: 1000,
        payloadSchema: z.object({ userId: z.number() }),
        idField: "userId",
      },
    });
    await expect(auth.genRefreshToken({ userId: 42 })).rejects.toMatchObject({
      code: "INVALID_PAYLOAD",
    });
  });
  it.each(["", "bad-token", "x".repeat(32769)])(
    "rejects malformed input without reflecting it into errors",
    async (token) => {
      const auth = await TelegramAuthServer.create(config());
      await expect(auth.verifyAccessToken(token)).rejects.toMatchObject({
        code: "INVALID_TOKEN",
        message: "Token could not be verified",
      });
    },
  );
  it.each([
    { typ: "tg-auth/refresh" },
    { v: 1 },
    { kind: "refresh" },
    { aud: "other" },
    { meta: { iat: NOW + 10, exp: NOW + 1000 } },
    { meta: { iat: NOW + 2000, exp: NOW + 1000 } },
    { meta: {} },
    { payload: { userId: 42 } },
  ])("rejects an authenticated but invalid envelope %j", async (overrides) => {
    const options = config();
    const auth = await TelegramAuthServer.create(options);
    const { typ, ...bodyOverrides } = overrides as Record<string, unknown>;
    const body = {
      v: 2,
      kind: "access",
      aud: `${options.namespace}:bot:123456:production`,
      payload: { userId: "u" },
      meta: { iat: NOW, exp: NOW + 1000 },
      ...bodyOverrides,
    };
    const token = await new CompactEncrypt(
      new TextEncoder().encode(JSON.stringify(body)),
    )
      .setProtectedHeader({
        alg: "dir",
        enc: "A256GCM",
        typ: typeof typ === "string" ? typ : "tg-auth/access",
      })
      .encrypt(new TextEncoder().encode(options.secrets.jweSecret));
    await expect(auth.verifyAccessToken(token)).rejects.toThrow();
  });
});

describe("refresh-token group invalidation", () => {
  it("rechecks expiry after shared-store I/O", async () => {
    const groups = memoryGroups();
    const auth = await TelegramAuthServer.create({
      ...config(),
      tokenGroupStore: groups.store,
    });
    const { refreshToken, refreshTokenExpiresAt } = await auth.genRefreshToken({
      userId: "u",
    });
    groups.store.get.mockImplementationOnce(async () => {
      vi.setSystemTime(refreshTokenExpiresAt);
      return null;
    });
    await expect(auth.verifyRefreshToken(refreshToken)).rejects.toMatchObject({
      code: "EXPIRED_TOKEN",
    });
  });
  it("rejects invalid values returned by the atomic increment adapter", async () => {
    const groups = memoryGroups();
    const auth = await TelegramAuthServer.create({
      ...config(),
      tokenGroupStore: groups.store,
    });
    const { refreshToken } = await auth.genRefreshToken({ userId: "u" });
    groups.store.incr.mockResolvedValueOnce(0);
    await expect(
      auth.rotateRefreshTokenGroup(refreshToken),
    ).rejects.toMatchObject({ code: "INVALID_TOKEN_GROUP" });
  });
  it("invalidates all existing credentials for one user and allows newly issued credentials", async () => {
    const auth = await TelegramAuthServer.create(config());
    const one = await auth.genRefreshToken({ userId: "one" });
    const sameUser = await auth.genRefreshToken({ userId: "one" });
    const otherUser = await auth.genRefreshToken({ userId: "two" });
    await auth.rotateRefreshTokenGroup(one.refreshToken);
    for (const token of [one, sameUser])
      await expect(
        auth.verifyRefreshToken(token.refreshToken),
      ).rejects.toMatchObject({ code: "REVOKED_TOKEN" });
    await expect(
      auth.verifyRefreshToken(otherUser.refreshToken),
    ).resolves.toBeDefined();
    const fresh = await auth.genRefreshToken({ userId: "one" });
    expect((await auth.verifyRefreshToken(fresh.refreshToken)).meta.group).toBe(
      1,
    );
    await expect(
      auth.rotateRefreshTokenGroup(one.refreshToken),
    ).rejects.toMatchObject({ code: "REVOKED_TOKEN" });
    await expect(
      auth.verifyRefreshToken(fresh.refreshToken),
    ).resolves.toBeDefined();
  });
  it("atomically advances stored state under concurrent invalidations", async () => {
    const groups = memoryGroups();
    const auth = await TelegramAuthServer.create({
      ...config(),
      tokenGroupStore: groups.store,
    });
    const { refreshToken } = await auth.genRefreshToken({ userId: "u" });
    const gate = deferred<void>();
    let readers = 0;
    groups.store.get.mockImplementation(async () => {
      if (++readers === 2) gate.resolve();
      await gate.promise;
      return "0";
    });
    await Promise.all([
      auth.rotateRefreshTokenGroup(refreshToken),
      auth.rotateRefreshTokenGroup(refreshToken),
    ]);
    expect([...groups.values.values()]).toEqual([2]);
    expect(groups.store.incr).toHaveBeenCalledTimes(2);
  });
  it.each(["NaN", "1x", "-1", "1.5", "9007199254740992", {}, undefined])(
    "fails closed for malformed store value %j",
    async (raw) => {
      const groups = memoryGroups();
      groups.store.get.mockResolvedValue(raw);
      const auth = await TelegramAuthServer.create({
        ...config(),
        tokenGroupStore: groups.store,
      });
      await expect(auth.genRefreshToken({ userId: "u" })).rejects.toMatchObject(
        { code: "INVALID_TOKEN_GROUP" },
      );
    },
  );
  it("accepts Redis string counters and fails closed when the store is unavailable", async () => {
    const groups = memoryGroups();
    groups.store.get.mockResolvedValue("2");
    const auth = await TelegramAuthServer.create({
      ...config(),
      tokenGroupStore: groups.store,
    });
    const token = await auth.genRefreshToken({ userId: "u" });
    expect((await auth.verifyRefreshToken(token.refreshToken)).meta.group).toBe(
      2,
    );
    groups.store.get.mockRejectedValue(new Error("unavailable"));
    await expect(auth.verifyRefreshToken(token.refreshToken)).rejects.toThrow(
      "unavailable",
    );
  });
  it("makes disabled revocation explicit", async () => {
    const options = {
      ...config(),
      refreshTokenConfig: {
        ...config().refreshTokenConfig,
        skipTokenGroupVerification: true,
      },
    };
    const auth = await TelegramAuthServer.create(options);
    const token = await auth.genRefreshToken({ userId: "u" });
    expect(
      (await auth.verifyRefreshToken(token.refreshToken)).meta.group,
    ).toBeUndefined();
    await expect(
      auth.rotateRefreshTokenGroup(token.refreshToken),
    ).rejects.toThrow("disabled");
  });
});
