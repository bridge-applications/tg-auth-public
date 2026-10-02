import { createHash } from "node:crypto";
import { CompactEncrypt, compactDecrypt } from "jose";
import { z } from "zod";

export const AccessTokenMeta = z.object({
  iat: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
});
export const RefreshTokenMeta = AccessTokenMeta.extend({
  idField: z.string().min(1),
  group: z.number().int().nonnegative().optional(),
});
export type AccessTokenMetadata = z.infer<typeof AccessTokenMeta>;
export type RefreshTokenMetadata = z.infer<typeof RefreshTokenMeta>;
export type AuthErrorCode =
  | "INVALID_TOKEN"
  | "EXPIRED_TOKEN"
  | "INVALID_PAYLOAD"
  | "REVOKED_TOKEN"
  | "INVALID_TOKEN_GROUP";

export class TelegramAuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "TelegramAuthError";
  }
}

export interface TokenGroupStore {
  get(key: string): Promise<unknown>;
  incr(key: string): Promise<number>;
}

export function groupKey(namespace: string, identity: string): string {
  return `${namespace}:rtg:${createHash("sha256").update(identity).digest("hex")}`;
}

async function currentGroup(
  store: TokenGroupStore,
  key: string,
): Promise<number> {
  const raw = await store.get(key);
  if (raw === null) return 0;
  const group =
    typeof raw === "string" && /^(0|[1-9]\d*)$/.test(raw) ? Number(raw) : raw;
  if (typeof group !== "number" || !Number.isSafeInteger(group) || group < 0) {
    throw new TelegramAuthError(
      "INVALID_TOKEN_GROUP",
      "Invalid refresh-token group state",
    );
  }
  return group;
}

export class TokenService<A, R> {
  constructor(
    private readonly key: Uint8Array,
    private readonly namespace: string,
    private readonly access: { ttlMs: number; payloadSchema?: z.ZodType<A> },
    private readonly refresh: {
      ttlMs: number;
      payloadSchema: z.ZodType<R>;
      idField: string;
    },
    private readonly groups?: TokenGroupStore,
  ) {}

  async genAccessToken(input?: unknown) {
    if (!this.access.payloadSchema && input !== undefined) {
      throw new TelegramAuthError(
        "INVALID_PAYLOAD",
        "Access payload requires a schema",
      );
    }
    const payload = this.access.payloadSchema
      ? this.parse(this.access.payloadSchema, input)
      : null;
    const meta = this.meta(this.access.ttlMs);
    return {
      token: await this.encrypt("access", payload, meta),
      expiresAt: meta.exp,
    };
  }

  async verifyAccessToken(
    token: string,
  ): Promise<{ payload: A | null; meta: AccessTokenMetadata }> {
    const envelope = await this.decrypt(token, "access");
    const meta = this.parse(AccessTokenMeta, envelope.meta);
    this.checkTime(meta);
    if (!this.access.payloadSchema && envelope.payload !== null) {
      throw new TelegramAuthError(
        "INVALID_PAYLOAD",
        "Unexpected access-token payload",
      );
    }
    return {
      payload: this.access.payloadSchema
        ? this.parse(this.access.payloadSchema, envelope.payload)
        : null,
      meta,
    };
  }

  async genRefreshToken(input: unknown) {
    const payload = this.parse(this.refresh.payloadSchema, input);
    const identity = this.identity(payload);
    const meta: RefreshTokenMetadata = {
      ...this.meta(this.refresh.ttlMs),
      idField: identity,
    };
    if (this.groups)
      meta.group = await currentGroup(
        this.groups,
        groupKey(this.namespace, identity),
      );
    return {
      token: await this.encrypt("refresh", payload, meta),
      expiresAt: meta.exp,
    };
  }

  async verifyRefreshToken(
    token: string,
  ): Promise<{ payload: R; meta: RefreshTokenMetadata }> {
    const envelope = await this.decrypt(token, "refresh");
    const meta = this.parse(RefreshTokenMeta, envelope.meta);
    this.checkTime(meta);
    const payload = this.parse(this.refresh.payloadSchema, envelope.payload);
    if (this.identity(payload) !== meta.idField)
      throw new TelegramAuthError("INVALID_TOKEN", "Refresh identity mismatch");
    if (this.groups) {
      const group = await currentGroup(
        this.groups,
        groupKey(this.namespace, meta.idField),
      );
      if (meta.group === undefined || meta.group !== group)
        throw new TelegramAuthError("REVOKED_TOKEN", "Refresh token revoked");
    } else if (meta.group !== undefined) {
      throw new TelegramAuthError(
        "INVALID_TOKEN_GROUP",
        "Token requires group verification",
      );
    }
    // Shared-store I/O may cross the expiry boundary.
    this.checkTime(meta);
    return { payload, meta };
  }

  /** Invalidates every refresh token for this identity; this is not per-session rotation. */
  async rotateRefreshTokenGroup(token: string): Promise<void> {
    if (!this.groups)
      throw new Error("Refresh-token group verification is disabled");
    const { meta } = await this.verifyRefreshToken(token);
    // Increment the stored value, never a token's potentially stale group number.
    const next = await this.groups.incr(groupKey(this.namespace, meta.idField));
    if (!Number.isSafeInteger(next) || next <= 0)
      throw new TelegramAuthError(
        "INVALID_TOKEN_GROUP",
        "Invalid refresh-token group state",
      );
  }

  private identity(payload: R): string {
    const value =
      payload && typeof payload === "object"
        ? Reflect.get(payload, this.refresh.idField)
        : undefined;
    if (typeof value !== "string" || !value.trim())
      throw new TelegramAuthError(
        "INVALID_PAYLOAD",
        "Refresh identity must be a nonempty string",
      );
    return value;
  }

  private meta(ttl: number): AccessTokenMetadata {
    const iat = Date.now();
    return { iat, exp: iat + ttl };
  }

  private checkTime(meta: AccessTokenMetadata): void {
    if (meta.exp <= Date.now())
      throw new TelegramAuthError("EXPIRED_TOKEN", "Token expired");
    if (meta.iat > Date.now() || meta.exp <= meta.iat)
      throw new TelegramAuthError("INVALID_TOKEN", "Invalid token timestamps");
  }

  private parse<T>(schema: z.ZodType<T>, input: unknown): T {
    const parsed = schema.safeParse(input);
    if (!parsed.success)
      throw new TelegramAuthError(
        "INVALID_PAYLOAD",
        "Token payload failed validation",
      );
    return parsed.data;
  }

  private async encrypt(
    kind: "access" | "refresh",
    payload: unknown,
    meta: unknown,
  ): Promise<string> {
    const plaintext = new TextEncoder().encode(
      JSON.stringify({ v: 2, kind, aud: this.namespace, payload, meta }),
    );
    if (plaintext.byteLength > 24000)
      throw new TelegramAuthError(
        "INVALID_PAYLOAD",
        "Token payload exceeds the size limit",
      );
    return new CompactEncrypt(plaintext)
      .setProtectedHeader({
        alg: "dir",
        enc: "A256GCM",
        typ: `tg-auth/${kind}`,
      })
      .encrypt(this.key);
  }

  private async decrypt(token: string, kind: "access" | "refresh") {
    try {
      if (typeof token !== "string" || token.length > 32_768)
        throw new Error("Invalid token length");
      const { plaintext, protectedHeader } = await compactDecrypt(
        token,
        this.key,
        {
          keyManagementAlgorithms: ["dir"],
          contentEncryptionAlgorithms: ["A256GCM"],
        },
      );
      const envelope = z
        .object({
          v: z.literal(2),
          kind: z.literal(kind),
          aud: z.literal(this.namespace),
          payload: z.unknown(),
          meta: z.unknown(),
        })
        .parse(JSON.parse(new TextDecoder().decode(plaintext)));
      if (protectedHeader.typ !== `tg-auth/${kind}`)
        throw new Error("Invalid token type");
      return envelope;
    } catch {
      throw new TelegramAuthError(
        "INVALID_TOKEN",
        "Token could not be verified",
      );
    }
  }
}
