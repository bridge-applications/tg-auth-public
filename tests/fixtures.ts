import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { vi } from "vitest";
import { z } from "zod";
import type {
  ReplayStore,
  TokenGroupStore,
  TelegramAuthServerConfig,
} from "../src/server.js";
export const NOW = Date.UTC(2026, 9, 2, 12);
/** Synthetic bot credential, never used with Telegram's API. */
export const BOT = "123456:test_fixture_only";
export const USER = { id: 12345, first_name: "Test", username: "test_user" };
export const payloadSchema = z.object({
  userId: z.string().min(1),
  role: z.enum(["member", "admin"]).default("member"),
});
export function memoryGroups() {
  const values = new Map<string, unknown>();
  const store = {
    get: vi.fn(
      async (key: string): Promise<unknown> => values.get(key) ?? null,
    ),
    incr: vi.fn(async (key: string) => {
      const next = Number(values.get(key) ?? 0) + 1;
      values.set(key, next);
      return next;
    }),
  } satisfies TokenGroupStore;
  return { values, store };
}
export function memoryReplay() {
  const used = new Set<string>();
  return {
    consume: vi.fn(async (key: string, expiry: number) => {
      if (Date.now() >= expiry || used.has(key)) return false;
      used.add(key);
      return true;
    }),
  } satisfies ReplayStore;
}
export function config() {
  return {
    secrets: { jweSecret: "k".repeat(32) },
    initDataConfig: { botToken: BOT },
    namespace: "test-app",
    accessTokenConfig: { ttlMs: 60_000, payloadSchema },
    refreshTokenConfig: { ttlMs: 3_600_000, payloadSchema, idField: "userId" },
    tokenGroupStore: memoryGroups().store,
  } satisfies TelegramAuthServerConfig;
}
export function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
export function fields(
  overrides: Record<string, string> = {},
): Record<string, string> {
  return {
    auth_date: String(Math.floor(NOW / 1000)),
    query_id: "synthetic-query",
    user: JSON.stringify(USER),
    ...overrides,
  };
}
export function encode(input: Record<string, string>) {
  return Object.entries(input)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`,
    )
    .join("&");
}
export function hmacData(input = fields(), token = BOT) {
  const secret = createHmac("sha256", "WebAppData").update(token).digest();
  const data = Object.keys(input)
    .filter((key) => key !== "hash")
    .sort()
    .map((key) => `${key}=${input[key]}`)
    .join("\n");
  return encode({
    ...input,
    hash: createHmac("sha256", secret).update(data).digest("hex"),
  });
}
export function edFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const hex = publicKey
    .export({ type: "spki", format: "der" })
    .subarray(-32)
    .toString("hex");
  return {
    hex,
    signed(input = fields(), botId = "123456") {
      const data = Object.keys(input)
        .filter((key) => !["hash", "signature"].includes(key))
        .sort()
        .map((key) => `${key}=${input[key]}`)
        .join("\n");
      const signature = sign(
        null,
        Buffer.from(`${botId}:WebAppData\n${data}`),
        privateKey,
      ).toString("base64url");
      return encode({ ...input, signature });
    },
  };
}
