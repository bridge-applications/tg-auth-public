import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InitDataService } from "../src/server.js";
import {
  BOT,
  NOW,
  USER,
  fields,
  hmacData,
  edFixture,
  memoryReplay,
  encode,
} from "./fixtures.js";

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());
const hmac = () => new InitDataService({ botToken: BOT });
describe("Telegram init-data verification", () => {
  it("validates legacy HMAC data and returns only authenticated user fields", async () => {
    const result = await hmac().verifyInitData(
      hmacData(fields({ user: JSON.stringify({ ...USER, untrusted: true }) })),
    );
    expect(result).toMatchObject({
      valid: true,
      method: "hmac",
      user: USER,
      authDate: NOW / 1000,
      expiresAtMs: NOW + 86_400_000,
    });
    if (result.valid) expect(Object.isFrozen(result.fields)).toBe(true);
  });
  it("includes modern signature fields in the HMAC check string", async () => {
    const proof = hmacData(fields({ signature: "telegram-proof" }));
    expect((await hmac().verifyInitData(proof)).valid).toBe(true);
    expect(
      await hmac().verifyInitData(proof.replace("telegram-proof", "tampered")),
    ).toEqual({ valid: false, reason: "invalid_proof" });
  });
  it("keeps literal and percent-encoded plus signs equivalent", async () => {
    const proof = hmacData(fields({ start_param: "foo+bar" }));
    expect(
      (await hmac().verifyInitData(proof.replace("foo%2Bbar", "foo+bar")))
        .valid,
    ).toBe(true);
  });
  it("validates a real Ed25519 signature using the configured trusted key", async () => {
    const fixture = edFixture();
    const auth = new InitDataService({
      botId: 123456,
      validation: "ed25519",
      ed25519PublicKey: fixture.hex,
    });
    const proof = fixture.signed(fields({ hash: "ignored-by-ed25519" }));
    expect(await auth.verifyInitData(proof)).toMatchObject({
      valid: true,
      method: "ed25519",
      user: USER,
    });
    expect(
      (
        await auth.verifyInitData(
          proof.replace(/signature=([^&]+)/, "signature=$1%3D%3D"),
        )
      ).valid,
    ).toBe(true);
    expect(
      await auth.verifyInitData(proof.replace("synthetic-query", "tampered")),
    ).toEqual({ valid: false, reason: "invalid_proof" });
    expect(
      (await auth.verifyInitData(fixture.signed(fields(), "654321"))).valid,
    ).toBe(false);
  });
  it("prefers Ed25519 in either mode and falls back to configured HMAC", async () => {
    const fixture = edFixture();
    const auth = new InitDataService({
      botToken: BOT,
      validation: "either",
      ed25519PublicKey: fixture.hex,
    });
    expect(await auth.verifyInitData(fixture.signed())).toMatchObject({
      valid: true,
      method: "ed25519",
    });
    expect(
      await auth.verifyInitData(
        hmacData(fields({ signature: "invalid-signature" })),
      ),
    ).toMatchObject({ valid: true, method: "hmac" });
    const thirdParty = new InitDataService({
      botId: 123456,
      validation: "either",
      ed25519PublicKey: fixture.hex,
    });
    expect((await thirdParty.verifyInitData(fixture.signed())).valid).toBe(
      true,
    );
    expect((await thirdParty.verifyInitData(hmacData())).valid).toBe(false);
  });
  it.each([
    "",
    "user=%ZZ",
    "=value",
    "auth_date",
    "hash=x&hash=y",
    "Bad=x",
    "key=%0A",
    "key=%0D",
    "a=x&",
    "x".repeat(16385),
    Array.from({ length: 65 }, (_, i) => `x${i}=y`).join("&"),
  ])("returns an invalid result for malformed input", async (raw) => {
    expect(await hmac().verifyInitData(raw)).toEqual({
      valid: false,
      reason: "malformed",
    });
  });
  it("does not return an unverified identity or echo credential text", async () => {
    const raw = encode(fields());
    expect(await hmac().verifyInitData(raw)).toEqual({
      valid: false,
      reason: "missing_proof",
    });
    expect(
      await hmac().verifyInitData(raw + "&hash=" + "f".repeat(64)),
    ).toEqual({ valid: false, reason: "invalid_proof" });
    expect(
      (
        await new InitDataService({
          botToken: "123456:wrong_fixture",
        }).verifyInitData(hmacData())
      ).valid,
    ).toBe(false);
  });
  it.each(["", "123abc", "01", "-1", "1.5", "9007199254740992"])(
    "rejects a signed noncanonical timestamp %s",
    async (auth_date) => {
      expect(
        await hmac().verifyInitData(hmacData(fields({ auth_date }))),
      ).toEqual({ valid: false, reason: "invalid_auth_date" });
    },
  );
  it("requires auth_date even when the signature is valid", async () => {
    const data = fields();
    delete data.auth_date;
    expect(await hmac().verifyInitData(hmacData(data))).toEqual({
      valid: false,
      reason: "invalid_auth_date",
    });
  });
  it("expires exactly at the freshness boundary and bounds future clock skew", async () => {
    const auth = new InitDataService({
      botToken: BOT,
      maxAuthDateAgeMs: 60_000,
      clockSkewMs: 2000,
    });
    const raw = hmacData();
    vi.setSystemTime(NOW + 59_999);
    expect((await auth.verifyInitData(raw)).valid).toBe(true);
    vi.setSystemTime(NOW + 60_000);
    expect(await auth.verifyInitData(raw)).toEqual({
      valid: false,
      reason: "expired",
    });
    vi.setSystemTime(NOW - 2000);
    expect((await auth.verifyInitData(raw)).valid).toBe(true);
    vi.setSystemTime(NOW - 2001);
    expect(await auth.verifyInitData(raw)).toEqual({
      valid: false,
      reason: "future",
    });
  });
  it.each([
    "not-json",
    "null",
    "{}",
    '{"id":-1,"first_name":"Test"}',
    '{"id":9007199254740992,"first_name":"Test"}',
    '{"id":123,"first_name":4}',
  ])("rejects a signed invalid user %s", async (user) => {
    expect(await hmac().verifyInitData(hmacData(fields({ user })))).toEqual({
      valid: false,
      reason: "invalid_user",
    });
  });
  it("requires a user by default, with an explicit opt-out for non-user contexts", async () => {
    const data = fields();
    delete data.user;
    expect(await hmac().verifyInitData(hmacData(data))).toEqual({
      valid: false,
      reason: "invalid_user",
    });
    expect(
      await new InitDataService({
        botToken: BOT,
        requireUser: false,
      }).verifyInitData(hmacData(data)),
    ).toMatchObject({ valid: true });
  });
  it.each(["short", "!".repeat(86), "A".repeat(85) + "B", "A".repeat(86)])(
    "rejects invalid Ed25519 proof encodings",
    async (signature) => {
      const auth = new InitDataService({
        botId: 123456,
        validation: "ed25519",
      });
      expect(
        (await auth.verifyInitData(encode(fields({ signature })))).valid,
      ).toBe(false);
    },
  );
  it("fails closed on a Web Crypto verification failure", async () => {
    const fixture = edFixture();
    vi.spyOn(crypto.subtle, "importKey").mockRejectedValueOnce(
      new Error("runtime failure"),
    );
    const auth = new InitDataService({
      botId: 123456,
      validation: "ed25519",
      ed25519PublicKey: fixture.hex,
    });
    expect((await auth.verifyInitData(fixture.signed())).valid).toBe(false);
    expect((await auth.verifyInitData(fixture.signed())).valid).toBe(true);
  });
});

describe("canonical assertion replay protection", () => {
  it("rejects reordered and equivalently encoded queries using one replay key", async () => {
    const replay = memoryReplay();
    const auth = new InitDataService(
      { botToken: BOT, singleUse: true },
      "test",
      replay,
    );
    const raw = hmacData(fields({ start_param: "A+B" }));
    expect((await auth.verifyInitData(raw)).valid).toBe(true);
    expect(
      await auth.verifyInitData(
        raw.split("&").reverse().join("&").replace("A%2BB", "%41+B"),
      ),
    ).toEqual({ valid: false, reason: "replayed" });
    expect(replay.consume).toHaveBeenLastCalledWith(
      expect.stringMatching(/^test:replay:[a-f0-9]{64}$/),
      NOW + 86_400_000,
    );
  });
  it("treats Ed25519 and HMAC proofs of the same assertion as one replay", async () => {
    const fixture = edFixture();
    const replay = memoryReplay();
    const auth = new InitDataService(
      {
        botToken: BOT,
        validation: "either",
        ed25519PublicKey: fixture.hex,
        singleUse: true,
      },
      "test",
      replay,
    );
    expect((await auth.verifyInitData(fixture.signed())).valid).toBe(true);
    expect(await auth.verifyInitData(hmacData())).toEqual({
      valid: false,
      reason: "replayed",
    });
  });
  it("accepts at most one concurrent use and scopes markers by application and bot", async () => {
    const replay = memoryReplay();
    const auth = new InitDataService(
      { botToken: BOT, singleUse: true },
      "one",
      replay,
    );
    const results = await Promise.all([
      auth.verifyInitData(hmacData()),
      auth.verifyInitData(hmacData()),
    ]);
    expect(results.filter((result) => result.valid)).toHaveLength(1);
    expect(
      (
        await new InitDataService(
          { botToken: BOT, singleUse: true },
          "two",
          replay,
        ).verifyInitData(hmacData())
      ).valid,
    ).toBe(true);
    const other = "654321:other_fixture";
    expect(
      (
        await new InitDataService(
          { botToken: other, singleUse: true },
          "one",
          replay,
        ).verifyInitData(hmacData(fields(), other))
      ).valid,
    ).toBe(true);
  });
  it("rejects store errors and assertions expiring while consumption is pending", async () => {
    const replay = memoryReplay();
    replay.consume.mockRejectedValueOnce(
      new Error("secret connection details"),
    );
    const auth = new InitDataService(
      { botToken: BOT, singleUse: true, maxAuthDateAgeMs: 1000 },
      "test",
      replay,
    );
    expect(await auth.verifyInitData(hmacData())).toEqual({
      valid: false,
      reason: "store_unavailable",
    });
    replay.consume.mockImplementationOnce(async () => {
      vi.setSystemTime(NOW + 1000);
      return true;
    });
    expect(await auth.verifyInitData(hmacData())).toEqual({
      valid: false,
      reason: "expired",
    });
  });
  it("allows reuse only when singleUse is disabled", async () => {
    const auth = hmac();
    expect((await auth.verifyInitData(hmacData())).valid).toBe(true);
    expect((await auth.verifyInitData(hmacData())).valid).toBe(true);
  });
});

describe("init-data configuration", () => {
  it.each([
    { botId: "invalid" },
    { botId: 0 },
    { botId: "123456", botToken: "654321:fixture" },
    { botToken: "123456:" },
    { botId: 123456 },
    { botToken: BOT, maxAuthDateAgeMs: 0 },
    { botToken: BOT, maxAuthDateAgeMs: 604800001 },
    { botToken: BOT, clockSkewMs: -1 },
    { botToken: BOT, clockSkewMs: 300001 },
    { botToken: BOT, ed25519PublicKey: "bad" },
    { botToken: BOT, singleUse: true },
  ])("rejects unsafe configuration %j", (options) => {
    expect(() => new InitDataService(options)).toThrow();
  });
  it("rejects invalid runtime enum values", () => {
    expect(
      () => new InitDataService({ botToken: BOT, validation: "bad" as "hmac" }),
    ).toThrow();
    expect(
      () =>
        new InitDataService({ botToken: BOT, environment: "bad" as "test" }),
    ).toThrow();
    expect(
      () =>
        new InitDataService({
          botId: 123456,
          validation: "ed25519",
          environment: "test",
        }),
    ).not.toThrow();
  });
});
