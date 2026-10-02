# HTTP integration

The client sends JSON requests with `credentials: "include"`. Default routes are:

| Route                     | Method | Request                                                             |
| ------------------------- | ------ | ------------------------------------------------------------------- |
| `/api/auth/app-session`   | POST   | Object with optional `telegramInitData` and `clientVersion`         |
| `/api/auth/access-token`  | POST   | HttpOnly refresh cookie; optional application-owned cold-start body |
| `/api/auth/sign-out`      | POST   | `{ "signAllOut": true }`                                            |
| `/api/auth/clear-cookies` | POST   | No body                                                             |

The generic app-session schema permits extra application fields. Your backend must require a verified proof or valid refresh session before issuing credentials. The [Fetch example](../examples/fetch-handler.ts) requires launch data for app-session and a cookie for refresh. It does not implement custom cold-start bodies; applications that need them must validate and verify them explicitly.

## Response contract

Every response includes the shared envelope:

```ts
{
  status: ApiStatus.SUCCESS,
  statusCode: HttpStatusCodes.OK,
  respCode: ApiResCodes.SUCCESS_REQUEST_COMPLETED,
  version: "1.0.0",
  accessToken: "<encrypted access credential>",
  accessTokenExpiresAt: 1790942700000,
  refreshTokenExpiresAt: 1791547200000,
}
```

App-session's default schema requires both access fields and refresh expiry. Refresh responses require only access fields. Expiries may be millisecond integers or ISO datetime strings; the default schemas normalize strings. Sign-out and clear-cookie responses include `success: boolean`. A custom app-session response can instead represent onboarding; it is not committed as an authenticated session without valid access fields.

The client validates the base envelope before any custom schema. HTTP errors, `status: ERROR`, or a non-200 `statusCode` reject the request even if a custom schema strips those fields. `TelegramAuthApiError.code` distinguishes request/response validation, API rejection, HTTP errors, timeout, and network failure. Errors and debug output do not echo request or response contents.

## Cookies and authorization

Refresh cookies default to `tgAuth_refreshToken`, HttpOnly, Secure, SameSite=Strict, and Path=/. Cookie maxAge is in **seconds**; Express adapters must convert it to milliseconds. Cookie callbacks can be async and are awaited. Clear cookies using the same attributes as issuance. If an adapter deliberately overrides attributes, apply the corresponding overrides when clearing.

The example requires HTTPS, exact same-origin requests with an Origin header, and POST for all auth routes. It rejects duplicate refresh-cookie names, bounds the actual JSON body to 16 KiB without trusting Content-Length, and sets Cache-Control: no-store. Its account hooks resolve a verified Telegram identity and recheck account status on refresh. It does not return refresh credentials in JSON.

Provide deployment rate limits, request deadlines, HTTPS, and appropriate secret storage. Choose short access TTLs, a freshness window appropriate to launches, and durable atomic stores shared by all replicas. Do not log raw credentials, request bodies, Telegram user records, or infrastructure exceptions. A cross-origin integration needs its own reviewed Origin/CORS/CSRF and cookie policy; this example is intentionally same-origin.

When `signAllOut` is true, the example advances the account's refresh group. A false value clears only this browser's cookie. Copied refresh credentials remain usable until expiry unless their group is invalidated. Access credentials remain valid until their own expiry. If shared revocation fails, the example clears the browser cookie and reports a server error rather than claiming that all devices were revoked.

See Telegram's [first-party verification](https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app) and [third-party verification](https://core.telegram.org/bots/webapps#validating-data-for-third-party-use) specifications and Cloudflare's [Node compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/) documentation.
