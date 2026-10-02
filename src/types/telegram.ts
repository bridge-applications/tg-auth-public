// telegram.ts

// =============== TELEGRAM USER ===============
// Shape of the `user` object embedded (URL-encoded JSON) inside `initData`.
// https://core.telegram.org/bots/webapps#webappuser
export interface TelegramUser {
  id: number;
  // └──UNIQUE TELEGRAM USER-ID
  is_bot?: boolean;
  first_name?: string;
  last_name?: string;
  username?: string;
  language_code?: string;
  is_premium?: boolean;
  added_to_attachment_menu?: boolean;
  allows_write_to_pm?: boolean;
  photo_url?: string;
}

// =============== VALIDATION MODE ===============
// - "hmac":    classic first-party validation against the bot token `hash`.
// - "ed25519": third-party validation against Telegram's own public-key `signature`.
// - "either":  accept if EITHER configured path validates (Ed25519 preferred).
export type TelegramValidationMode = "hmac" | "ed25519" | "either";

// =============== ENVIRONMENT ===============
// Selects which Telegram Ed25519 public key is used for third-party validation.
export type TelegramEnvironment = "production" | "test";
