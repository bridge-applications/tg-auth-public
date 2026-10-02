import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type {
  TelegramEnvironment,
  TelegramUser,
  TelegramValidationMode,
} from "../../../types/telegram.js";

export interface ReplayStore {
  /** Atomically return true once, retaining the marker until expiresAtMs. */
  consume(key: string, expiresAtMs: number): Promise<boolean>;
}
export interface InitDataConfig {
  botId?: string | number;
  botToken?: string;
  validation?: TelegramValidationMode;
  environment?: TelegramEnvironment;
  /** Trusted override for key rotation; never accept this value from a request. */
  ed25519PublicKey?: string;
  maxAuthDateAgeMs?: number;
  clockSkewMs?: number;
  requireUser?: boolean;
  singleUse?: boolean;
}
export type InitDataFailure =
  | "malformed"
  | "missing_proof"
  | "invalid_proof"
  | "invalid_auth_date"
  | "expired"
  | "future"
  | "invalid_user"
  | "replayed"
  | "store_unavailable";
export type InitDataVerification =
  | {
      valid: true;
      method: "hmac" | "ed25519";
      authDate: number;
      expiresAtMs: number;
      user?: TelegramUser;
      fields: Readonly<Record<string, string>>;
    }
  | { valid: false; reason: InitDataFailure };

const publicKeys = {
  production:
    "e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d",
  test: "40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec",
} as const;
const userSchema = z.object({
  id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  first_name: z.string(),
  is_bot: z.boolean().optional(),
  last_name: z.string().optional(),
  username: z.string().optional(),
  language_code: z.string().optional(),
  is_premium: z.boolean().optional(),
  added_to_attachment_menu: z.boolean().optional(),
  allows_write_to_pm: z.boolean().optional(),
  photo_url: z.string().optional(),
});

function parseFields(raw: string): Record<string, string> {
  if (typeof raw !== "string" || !raw || Buffer.byteLength(raw) > 16_384)
    throw new Error("Invalid input");
  const entries = raw.split("&");
  if (entries.length > 64) throw new Error("Too many fields");
  const result: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  for (const entry of entries) {
    const eq = entry.indexOf("=");
    if (eq < 1) throw new Error("Invalid field");
    // Telegram query data uses percent encoding; literal '+' must not become a space.
    const key = decodeURIComponent(entry.slice(0, eq));
    const value = decodeURIComponent(entry.slice(eq + 1));
    if (
      !/^[a-z][a-z0-9_]*$/.test(key) ||
      Object.hasOwn(result, key) ||
      /[\r\n]/.test(value)
    )
      throw new Error("Ambiguous field");
    result[key] = value;
  }
  return result;
}
function canonical(
  fields: Record<string, string>,
  exclude: readonly string[],
): string {
  return Object.keys(fields)
    .filter((key) => !exclude.includes(key))
    .sort()
    .map((key) => `${key}=${fields[key]}`)
    .join("\n");
}

/** Verifies Telegram's assertion. Application authorization remains the caller's responsibility. */
export class InitDataService {
  readonly botId: string;
  private readonly mode: TelegramValidationMode;
  private readonly token?: string;
  private readonly publicKey: string;
  private readonly maxAge: number;
  private readonly skew: number;
  private readonly requireUser: boolean;
  private readonly singleUse: boolean;
  private importedKey?: Promise<CryptoKey>;

  constructor(
    config: InitDataConfig,
    private readonly scope = "tg-auth",
    private readonly replayStore?: ReplayStore,
  ) {
    const tokenId = config.botToken?.split(":", 1)[0];
    this.botId = String(config.botId ?? tokenId ?? "");
    if (
      !/^[1-9]\d{0,15}$/.test(this.botId) ||
      !Number.isSafeInteger(Number(this.botId))
    )
      throw new Error("A valid botId or botToken is required");
    if (
      config.botToken &&
      (!/^[1-9]\d*:[A-Za-z0-9_-]+$/.test(config.botToken) ||
        tokenId !== this.botId)
    )
      throw new Error("botToken must match botId");
    this.mode = config.validation ?? "hmac";
    if (!["hmac", "ed25519", "either"].includes(this.mode))
      throw new Error("Invalid validation mode");
    if (this.mode === "hmac" && !config.botToken)
      throw new Error("HMAC validation requires botToken");
    const environment = config.environment ?? "production";
    if (!(environment in publicKeys))
      throw new Error("Invalid Telegram environment");
    this.publicKey = config.ed25519PublicKey ?? publicKeys[environment];
    if (!/^[a-fA-F0-9]{64}$/.test(this.publicKey))
      throw new Error("Ed25519 public key must be 32 hexadecimal bytes");
    this.maxAge = config.maxAuthDateAgeMs ?? 86_400_000;
    this.skew = config.clockSkewMs ?? 30_000;
    if (
      !Number.isSafeInteger(this.maxAge) ||
      this.maxAge < 1000 ||
      this.maxAge > 604_800_000
    )
      throw new Error("maxAuthDateAgeMs must be between 1000 and 604800000");
    if (
      !Number.isSafeInteger(this.skew) ||
      this.skew < 0 ||
      this.skew > 300_000
    )
      throw new Error("clockSkewMs must be between 0 and 300000");
    this.token = config.botToken;
    this.requireUser = config.requireUser ?? true;
    this.singleUse = config.singleUse ?? false;
    if (this.singleUse && !replayStore)
      throw new Error("singleUse requires an atomic replay store");
  }

  async verifyInitData(raw: string): Promise<InitDataVerification> {
    let fields: Record<string, string>;
    try {
      fields = parseFields(raw);
    } catch {
      return { valid: false, reason: "malformed" };
    }
    let method: "hmac" | "ed25519" | undefined;
    if (this.mode !== "hmac" && (await this.ed25519(fields)))
      method = "ed25519";
    if (!method && this.mode !== "ed25519" && this.hmac(fields))
      method = "hmac";
    if (!method)
      return {
        valid: false,
        reason:
          fields.hash || fields.signature ? "invalid_proof" : "missing_proof",
      };
    if (!/^[1-9]\d*$/.test(fields.auth_date ?? ""))
      return { valid: false, reason: "invalid_auth_date" };
    const authDate = Number(fields.auth_date);
    const timestamp = authDate * 1000;
    const expiresAtMs = timestamp + this.maxAge;
    if (!Number.isSafeInteger(timestamp) || !Number.isSafeInteger(expiresAtMs))
      return { valid: false, reason: "invalid_auth_date" };
    const timeFailure = this.checkTime(timestamp, expiresAtMs);
    if (timeFailure) return { valid: false, reason: timeFailure };
    let user: TelegramUser | undefined;
    if (fields.user !== undefined) {
      try {
        user = userSchema.parse(JSON.parse(fields.user));
      } catch {
        return { valid: false, reason: "invalid_user" };
      }
    } else if (this.requireUser)
      return { valid: false, reason: "invalid_user" };
    if (this.singleUse) {
      // Fingerprint the authenticated assertion, not its transport ordering or proof encoding.
      const fingerprint = createHash("sha256")
        .update(
          `${this.botId}:WebAppData\n${canonical(fields, ["hash", "signature"])}`,
        )
        .digest("hex");
      try {
        if (
          !(await this.replayStore!.consume(
            `${this.scope}:replay:${fingerprint}`,
            expiresAtMs,
          ))
        )
          return { valid: false, reason: "replayed" };
      } catch {
        return { valid: false, reason: "store_unavailable" };
      }
      const afterStore = this.checkTime(timestamp, expiresAtMs);
      if (afterStore) return { valid: false, reason: afterStore };
    }
    return {
      valid: true,
      method,
      authDate,
      expiresAtMs,
      ...(user ? { user } : {}),
      fields: Object.freeze({ ...fields }),
    };
  }
  private checkTime(
    timestamp: number,
    expiresAtMs: number,
  ): "expired" | "future" | undefined {
    if (Date.now() >= expiresAtMs) return "expired";
    if (timestamp > Date.now() + this.skew) return "future";
    return undefined;
  }
  private hmac(fields: Record<string, string>): boolean {
    if (!this.token || !/^[a-fA-F0-9]{64}$/.test(fields.hash ?? ""))
      return false;
    const key = createHmac("sha256", "WebAppData").update(this.token).digest();
    const expected = createHmac("sha256", key)
      .update(canonical(fields, ["hash"]))
      .digest();
    return timingSafeEqual(expected, Buffer.from(fields.hash!, "hex"));
  }
  private async ed25519(fields: Record<string, string>): Promise<boolean> {
    const signature = fields.signature;
    if (!signature || !/^[A-Za-z0-9_-]{86}(?:==)?$/.test(signature))
      return false;
    try {
      const bytes = Buffer.from(signature, "base64url");
      if (bytes.toString("base64url") !== signature.replace(/==$/, ""))
        return false;
      this.importedKey ??= crypto.subtle.importKey(
        "raw",
        Buffer.from(this.publicKey, "hex"),
        "Ed25519",
        false,
        ["verify"],
      );
      return await crypto.subtle.verify(
        "Ed25519",
        await this.importedKey,
        bytes,
        new TextEncoder().encode(
          `${this.botId}:WebAppData\n${canonical(fields, ["hash", "signature"])}`,
        ),
      );
    } catch {
      this.importedKey = undefined;
      return false;
    }
  }
}
