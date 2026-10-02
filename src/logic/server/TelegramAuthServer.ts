import { Redis } from "@upstash/redis";
import type { z } from "zod";
import { InitDataService } from "./helpers/InitDataService.js";
import type { InitDataConfig, ReplayStore } from "./helpers/InitDataService.js";
import { TokenService } from "./helpers/TokenService.js";
import type { TokenGroupStore } from "./helpers/TokenService.js";

export interface TelegramAuthServerConfig<A = unknown, R = unknown> {
  secrets: { jweSecret: string | Uint8Array };
  initDataConfig: InitDataConfig;
  namespace?: string;
  redisConfig?: { redisUrl: string; redisToken: string };
  tokenGroupStore?: TokenGroupStore;
  replayStore?: ReplayStore;
  accessTokenConfig: { ttlMs: number; payloadSchema?: z.ZodType<A> };
  refreshTokenConfig: {
    ttlMs: number;
    payloadSchema: z.ZodType<R>;
    idField: string;
    skipTokenGroupVerification?: boolean;
  };
}

export interface RefreshCookieOptions {
  name: "tgAuth_refreshToken";
  value: string;
  httpOnly: true;
  secure: true;
  sameSite: "Strict";
  path: "/";
  /** Seconds. Express adapters must multiply by 1000. */
  maxAge: number;
}

type CookieWriter = (options: RefreshCookieOptions) => void | Promise<void>;
type CookieClearer = (
  name: string,
  options: Omit<RefreshCookieOptions, "name" | "value">,
) => void | Promise<void>;

/** Application-scoped verifier. Create once with stable secrets and a shared revocation store. */
export class TelegramAuthServer<A = unknown, R = unknown> {
  private static readonly instances = new WeakMap<
    object,
    TelegramAuthServer<unknown, unknown>
  >();
  private readonly initData: InitDataService;
  private readonly tokens: TokenService<A, R>;

  private constructor(config: TelegramAuthServerConfig<A, R>) {
    const namespace = config.namespace ?? "tg-auth";
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(namespace))
      throw new Error(
        "namespace must contain 1–64 letters, digits, underscores or hyphens",
      );
    const key =
      typeof config.secrets.jweSecret === "string"
        ? new TextEncoder().encode(config.secrets.jweSecret)
        : new Uint8Array(config.secrets.jweSecret);
    if (key.byteLength !== 32)
      throw new Error("jweSecret must contain exactly 32 bytes");
    for (const tokenConfig of [
      config.accessTokenConfig,
      config.refreshTokenConfig,
    ]) {
      if (
        !Number.isSafeInteger(tokenConfig.ttlMs) ||
        tokenConfig.ttlMs < 1000 ||
        !Number.isSafeInteger(Date.now() + tokenConfig.ttlMs)
      )
        throw new Error(
          "Token TTL must be a positive safe integer of at least 1000 milliseconds",
        );
    }
    if (!config.refreshTokenConfig.idField.trim())
      throw new Error("Refresh idField is required");
    if (
      typeof config.refreshTokenConfig.payloadSchema?.safeParse !== "function"
    )
      throw new Error("Refresh payloadSchema must be a Zod schema");
    if (
      config.accessTokenConfig.payloadSchema &&
      typeof config.accessTokenConfig.payloadSchema.safeParse !== "function"
    )
      throw new Error("Access payloadSchema must be a Zod schema");
    const verifier = new InitDataService({
      ...config.initDataConfig,
      singleUse: false,
    });
    const scope = `${namespace}:bot:${verifier.botId}:${config.initDataConfig.environment ?? "production"}`;

    const redis = config.redisConfig
      ? new Redis({
          url: config.redisConfig.redisUrl,
          token: config.redisConfig.redisToken,
          automaticDeserialization: false,
        })
      : undefined;
    const groups = config.refreshTokenConfig.skipTokenGroupVerification
      ? undefined
      : (config.tokenGroupStore ??
        (redis
          ? {
              get: (key: string) => redis.get(key),
              incr: (key: string) => redis.incr(key),
            }
          : undefined));
    if (!groups && !config.refreshTokenConfig.skipTokenGroupVerification)
      throw new Error(
        "Configure Redis or tokenGroupStore, or explicitly disable refresh-token group verification",
      );
    this.tokens = new TokenService(
      key,
      scope,
      { ...config.accessTokenConfig },
      { ...config.refreshTokenConfig },
      groups,
    );
    const replay =
      config.replayStore ??
      (redis
        ? {
            consume: async (key: string, expiresAtMs: number) => {
              const ttl = expiresAtMs - Date.now();
              if (ttl <= 0) return false;
              return (
                (await redis.set(key, "used", { nx: true, px: ttl })) === "OK"
              );
            },
          }
        : undefined);
    this.initData = new InitDataService(
      { ...config.initDataConfig },
      scope,
      replay,
    );
  }

  /** Cache by configuration object identity, never by schema field names or secret strings. */
  static async init<A = unknown, R = unknown>(
    config: TelegramAuthServerConfig<A, R>,
  ): Promise<TelegramAuthServer<A, R>> {
    const existing = this.instances.get(config);
    if (existing) return existing as TelegramAuthServer<A, R>;
    const instance = new TelegramAuthServer(config);
    this.instances.set(config, instance);
    return instance;
  }

  static async create<A = unknown, R = unknown>(
    config: TelegramAuthServerConfig<A, R>,
  ): Promise<TelegramAuthServer<A, R>> {
    return new TelegramAuthServer(config);
  }

  verifyInitData(raw: string) {
    return this.initData.verifyInitData(raw);
  }

  async genAccessToken(payload?: unknown) {
    const { token, expiresAt } = await this.tokens.genAccessToken(payload);
    return { accessToken: token, accessTokenExpiresAt: expiresAt };
  }
  verifyAccessToken(token: string) {
    return this.tokens.verifyAccessToken(token);
  }
  async genRefreshToken(payload: unknown) {
    const { token, expiresAt } = await this.tokens.genRefreshToken(payload);
    return { refreshToken: token, refreshTokenExpiresAt: expiresAt };
  }
  verifyRefreshToken(token: string) {
    return this.tokens.verifyRefreshToken(token);
  }
  rotateRefreshTokenGroup(token: string) {
    return this.tokens.rotateRefreshTokenGroup(token);
  }

  async setRefreshTokenCookie(
    token: string,
    expiresAt: number,
    callback: CookieWriter,
  ): Promise<void> {
    if (!Number.isSafeInteger(expiresAt))
      throw new Error("Cookie expiry must be a millisecond timestamp");
    await callback({
      name: "tgAuth_refreshToken",
      value: token,
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: Math.max(0, Math.floor((expiresAt - Date.now()) / 1000)),
    });
  }
  getRefreshTokenCookie(
    callback: (name: string) => string | null | undefined,
  ): string | null {
    return callback("tgAuth_refreshToken") || null;
  }
  async clearRefreshTokenCookie(callback: CookieClearer): Promise<void> {
    await callback("tgAuth_refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 0,
    });
  }
}
