import {
  ApiAuthAppSessionReqSchema,
  ApiAuthSignOutReqSchema,
  ApiResCodes,
  ApiStatus,
  HttpStatusCodes,
} from "../src/schemas.js";
import { TelegramAuthError } from "../src/server.js";
import type { TelegramAuthServer, TelegramUser } from "../src/server.js";

export interface SessionClaims {
  userId: string;
  telegramId: string;
}
export interface AccountHooks {
  /** Resolve a verified Telegram identity to an allowed application account. */
  resolveUser(user: TelegramUser): Promise<SessionClaims | null>;
  /** Recheck current account status and privileges on every refresh. */
  refreshUser(previous: SessionClaims): Promise<SessionClaims | null>;
}
class InvalidRequestError extends Error {}
function cookie(request: Request, name: string): string | null {
  const matches = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${name}=`));
  return matches.length === 1 ? matches[0]!.slice(name.length + 1) : null;
}
function serialize(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
async function readJson(request: Request): Promise<unknown> {
  if (
    request.headers
      .get("content-type")
      ?.split(";", 1)[0]
      ?.trim()
      .toLowerCase() !== "application/json"
  )
    throw new InvalidRequestError("Expected JSON");
  const reader = request.body?.getReader();
  if (!reader) throw new InvalidRequestError("Missing body");
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 16_384) {
        await reader.cancel();
        throw new InvalidRequestError("Body too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

/** Same-origin HTTPS Fetch integration. Mount behind application rate limits and request deadlines. */
export function createAuthHandler(
  auth: TelegramAuthServer<SessionClaims, SessionClaims>,
  publicOrigin: string,
  accounts: AccountHooks,
) {
  const origin = new URL(publicOrigin);
  if (origin.protocol !== "https:" || origin.origin !== publicOrigin)
    throw new Error("publicOrigin must be an HTTPS origin");
  return async (request: Request): Promise<Response> => {
    const headers = new Headers({ "Cache-Control": "no-store" });
    const result = (
      fields: object,
      status: HttpStatusCodes = HttpStatusCodes.OK,
    ) =>
      Response.json(
        {
          status: status === 200 ? ApiStatus.SUCCESS : ApiStatus.ERROR,
          statusCode: status,
          respCode:
            status === 200
              ? ApiResCodes.SUCCESS_REQUEST_COMPLETED
              : ApiResCodes.ERROR_ACCESS_DENIED,
          version: "example",
          ...fields,
        },
        { status, headers },
      );
    const url = new URL(request.url);
    if (
      url.origin !== origin.origin ||
      request.headers.get("origin") !== origin.origin
    )
      return result({}, HttpStatusCodes.FORBIDDEN);
    if (request.method !== "POST") return result({}, HttpStatusCodes.NOT_FOUND);
    const refresh = () =>
      auth.getRefreshTokenCookie((name) => cookie(request, name));
    const clearCookie = () =>
      auth.clearRefreshTokenCookie((name) => {
        headers.append("Set-Cookie", serialize(name, "", 0));
      });
    try {
      if (url.pathname === "/api/auth/app-session") {
        const input = ApiAuthAppSessionReqSchema.safeParse(
          await readJson(request),
        );
        if (!input.success || !input.data.telegramInitData)
          return result({}, HttpStatusCodes.BAD_REQUEST);
        const verified = await auth.verifyInitData(input.data.telegramInitData);
        if (!verified.valid || !verified.user)
          return result({}, HttpStatusCodes.UNAUTHORIZED);
        const claims = await accounts.resolveUser(verified.user);
        if (!claims || claims.telegramId !== String(verified.user.id))
          return result({}, HttpStatusCodes.FORBIDDEN);
        const token = await auth.genRefreshToken(claims);
        const access = await auth.genAccessToken(claims);
        await auth.setRefreshTokenCookie(
          token.refreshToken,
          token.refreshTokenExpiresAt,
          (options) => {
            headers.append(
              "Set-Cookie",
              serialize(options.name, options.value, options.maxAge),
            );
          },
        );
        return result({
          ...access,
          refreshTokenExpiresAt: token.refreshTokenExpiresAt,
        });
      }
      if (url.pathname === "/api/auth/access-token") {
        const credential = refresh();
        if (!credential) return result({}, HttpStatusCodes.UNAUTHORIZED);
        const { payload } = await auth.verifyRefreshToken(credential);
        const claims = await accounts.refreshUser(payload);
        if (
          !claims ||
          claims.userId !== payload.userId ||
          claims.telegramId !== payload.telegramId
        )
          return result({}, HttpStatusCodes.FORBIDDEN);
        return result(await auth.genAccessToken(claims));
      }
      if (url.pathname === "/api/auth/sign-out") {
        const options = ApiAuthSignOutReqSchema.safeParse(
          await readJson(request),
        );
        if (!options.success) return result({}, HttpStatusCodes.BAD_REQUEST);
        // Clear this browser's cookie even if the shared revocation store is unavailable.
        await clearCookie();
        const credential = refresh();
        if (options.data.signAllOut && credential) {
          try {
            await auth.rotateRefreshTokenGroup(credential);
          } catch (error) {
            if (
              !(error instanceof TelegramAuthError) ||
              error.code === "INVALID_TOKEN_GROUP"
            )
              throw error;
          }
        }
        return result({ success: true });
      }
      if (url.pathname === "/api/auth/clear-cookies") {
        await clearCookie();
        return result({ success: true });
      }
      return result({}, HttpStatusCodes.NOT_FOUND);
    } catch (error) {
      if (error instanceof TelegramAuthError)
        return result(
          {},
          error.code === "INVALID_TOKEN_GROUP"
            ? HttpStatusCodes.INTERNAL_SERVER_ERROR
            : HttpStatusCodes.UNAUTHORIZED,
        );
      if (error instanceof InvalidRequestError || error instanceof SyntaxError)
        return result({}, HttpStatusCodes.BAD_REQUEST);
      return result({}, HttpStatusCodes.INTERNAL_SERVER_ERROR);
    }
  };
}
