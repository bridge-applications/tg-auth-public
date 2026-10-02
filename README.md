# @bridge-applications/tg-auth

Typed authentication and encrypted application sessions for Telegram Mini Apps.

This is the public edition of Bridge Applications' private Telegram authentication package, used in production by [Pebbler Telegram](https://t.me/pebbler_bot) and its backend services. It brings the shared browser and server authentication code into a standalone, documented package. Created and maintained by [Tessel Punt](https://github.com/tspunt) at [Bridge Applications](https://github.com/bridge-applications).

## What it handles

- Telegram `initData` verification using bot-token HMAC, Telegram's Ed25519 signatures, or either configured path.
- Strict freshness checks, bounded clock skew, validated user data, and optional atomic replay protection.
- Encrypted access and refresh tokens with separate purposes and application, bot, and environment scopes.
- Shared refresh-token revocation through Redis or an application-supplied atomic store.
- Browser session bootstrapping, asynchronous init-data providers, cached access credentials, and deduplicated silent refresh.
- Zod request/response contracts, credential-safe diagnostics, request timeouts, and asynchronous cookie adapters.

The package authenticates identities and manages credentials. Your application owns account lookup, permissions, rate limits, and business rules. Verified Telegram data is a bearer assertion; handle it as a credential.

## Runtime and installation

Node.js 22 or later, ESM, and Zod 4 are required. The server also runs in Cloudflare Workers with `nodejs_compat`; the repository includes a real workerd compatibility check. The browser entry uses neither Node APIs nor server cryptography or Redis dependencies.

The current source version is `2.0.0-rc.1`. Until a public package is published, build and install a local tarball:

```sh
npm ci
npm run check
npm pack --ignore-scripts
# In your application, install the generated tarball and zod@^4.
```

Use the appropriate entry point:

```ts
import { TelegramAuthClient } from "@bridge-applications/tg-auth/client";
import { TelegramAuthServer } from "@bridge-applications/tg-auth/server";
import { ApiAuthAppSessionResSchema } from "@bridge-applications/tg-auth/schemas";
```

The root entry combines browser and server exports for server-side consumers. Use `/client` in browser bundles. CommonJS and Zod 3 are not supported.

## Browser session

```ts
import { TelegramAuthClient } from "@bridge-applications/tg-auth/client";

TelegramAuthClient.init({
  baseUrl: "https://app.example.com",
  clientVersion: "1.0.0",
  // Optional: otherwise reads globalThis.Telegram?.WebApp?.initData.
  telegram: { initData: telegramWebApp.initData },
  requestTimeoutMs: 15_000,
});

// Adds SDK initData and the configured clientVersion when absent from the payload.
await TelegramAuthClient.getAppSession({});

// Reuses a valid access credential or performs one shared refresh request.
const { accessToken } = await TelegramAuthClient.getAccessTokenSilently();
await fetch("/api/account", {
  headers: { Authorization: `Bearer ${accessToken}` },
});

await TelegramAuthClient.signOut({ signAllOut: true });
```

`telegramWebApp` above is the Telegram WebApp object supplied by your integration; no Telegram SDK dependency is required. `initDataProvider` can instead return a string or `Promise<string>` from an application-owned bridge. Explicit init-data takes priority over SDK data, followed by the provider. Concurrent provider requests are shared; the assertion is not permanently cached.

Access credentials stay in memory by default. An optional `storage` adapter accepts the `getItem`, `setItem`, and `removeItem` methods of browser storage. Persisting bearer credentials increases exposure to XSS; opt in deliberately. Refresh credentials belong in HttpOnly cookies and are never cached by the client. Storage failures do not prevent local sign-out.

Responses must include a successful [API envelope](docs/http-integration.md). HTTP 200 alone does not indicate authentication success. Millisecond timestamps and ISO datetime strings are accepted at response boundaries; cached expiry values are normalized to milliseconds. `isAuthenticated` and `expectedToBeAuthenticated` describe local expiry state, not server authorization.

## Server verification and credentials

```ts
import { z } from "zod";
import { TelegramAuthServer } from "@bridge-applications/tg-auth/server";

const claims = z.object({
  userId: z.string().min(1),
  telegramId: z.string().min(1),
});

const auth = await TelegramAuthServer.create({
  namespace: "my-app-production",
  secrets: { jweSecret: encryptionKeyBytes }, // Exactly 32 random bytes from secret storage.
  initDataConfig: {
    botToken: botTokenFromSecrets,
    validation: "hmac",
    maxAuthDateAgeMs: 300_000,
    clockSkewMs: 30_000,
  },
  redisConfig: {
    redisUrl: redisUrlFromSecrets,
    redisToken: redisTokenFromSecrets,
  },
  accessTokenConfig: { ttlMs: 300_000, payloadSchema: claims },
  refreshTokenConfig: {
    ttlMs: 604_800_000,
    payloadSchema: claims,
    idField: "userId",
  },
});

const verified = await auth.verifyInitData(initDataFromRequest);
if (!verified.valid || !verified.user)
  throw new Error("Authentication rejected");

// Resolve the verified identity through your own account and authorization service.
const account = await accounts.findAllowedTelegramUser(verified.user.id);
const payload = { userId: account.id, telegramId: String(verified.user.id) };
const access = await auth.genAccessToken(payload);
const refresh = await auth.genRefreshToken(payload);

// Adapter receives HttpOnly, Secure, SameSite=Strict, Path=/, and maxAge in seconds.
await auth.setRefreshTokenCookie(
  refresh.refreshToken,
  refresh.refreshTokenExpiresAt,
  (options) => cookieAdapter.set(options),
);
// Return access and refreshTokenExpiresAt to the browser, never the refresh credential.
```

The example's secrets, account service, and cookie adapter are supplied by your application. See the typechecked [Fetch integration](examples/fetch-handler.ts) for complete same-origin request handling and account hooks.

For third-party verification, set `validation: "ed25519"` and `botId` without a bot token. `environment` selects Telegram's production or test public key. A trusted `ed25519PublicKey` override supports key rotation. `validation: "either"` accepts either configured proof, preferring Ed25519. It does not require both proofs.

Freshness defaults to 24 hours, with 30 seconds of future clock skew. Choose a tighter window appropriate for your app; long-running sessions should use refresh cookies. `requireUser` defaults to true. Disable it only when verifying a launch context that genuinely has no user; that result must not be treated as a user login.

`singleUse: true` requires Redis or an atomic `replayStore`. It prevents reuse across reordered or equivalently encoded queries and across supported proof methods. Telegram may supply the same assertion more than once during a launch, so single-use behavior is opt-in. With it enabled, resume sessions using the refresh cookie rather than repeatedly exchanging init-data.

## API overview

| Browser API                                                 | Purpose                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------- |
| `init(config)`, `reset()`, `isInitialized()`                | Configure or invalidate the browser singleton                 |
| `getInitData(explicit?)`, `resolveInitData(explicit?)`      | Read or asynchronously resolve launch data                    |
| `getAppSession(payload?, reqSchema?, resSchema?, headers?)` | Exchange launch data through your backend                     |
| `getAccessToken(resSchema?, headers?, request?)`            | Refresh with custom contracts or a cold-start body            |
| `getAccessTokenSilently()`                                  | Reuse cached access or deduplicate refresh                    |
| `commitAuth(fields)`, `commitAccess(fields)`                | Commit credentials obtained through an application-owned flow |
| `signOut({ signAllOut })`, `clearCookies()`                 | Clear local state and request server-side session closure     |

Endpoint paths and schemas can be overridden in `init`. Custom schemas retain their inferred output types. A successful custom app-session response may represent onboarding without credentials; no authentication is committed in that case. Manual commit functions require future expiry timestamps. Reset, reinitialization, and sign-out invalidate pending session operations.

| Server API                                                                  | Purpose                                              |
| --------------------------------------------------------------------------- | ---------------------------------------------------- |
| `create(config)`                                                            | Create an independent application verifier           |
| `init(config)`                                                              | Reuse a verifier for the same configuration object   |
| `verifyInitData(raw)`                                                       | Return a discriminated verified/invalid result       |
| `genAccessToken(payload?)`, `verifyAccessToken(token)`                      | Issue and verify access credentials                  |
| `genRefreshToken(payload)`, `verifyRefreshToken(token)`                     | Issue and verify refresh credentials                 |
| `rotateRefreshTokenGroup(token)`                                            | Invalidate every refresh credential for its identity |
| `setRefreshTokenCookie`, `getRefreshTokenCookie`, `clearRefreshTokenCookie` | Integrate framework cookie handling                  |

Refresh identity fields must resolve to nonempty strings. Payload schemas may strip unknown fields and supply defaults. Use stable claim schemas whose output remains valid input; perform non-idempotent transformations in your account layer before issuance.

Group invalidation requires a currently valid refresh credential and atomically increments shared state. It does not rotate an individual session or immediately revoke access tokens; short access TTLs bound that interval. Without a store, revocation must be explicitly disabled with `skipTokenGroupVerification: true`.

## Development

```sh
npm ci
npm run check
```

Checks include formatting, strict TypeScript, unit and HTTP integration tests with enforced coverage thresholds, packed ESM imports, NodeNext/Bundler consumer types, browser dependency isolation, and actual workerd HMAC/Ed25519/JWE verification. CI runs the suite on Node 22 and 24. Tests use synthetic identities and credentials; no live Telegram bot or Redis service is needed.

- [Architecture and trust boundaries](docs/architecture.md)
- [HTTP integration and deployment responsibilities](docs/http-integration.md)
- [Migration from internal 1.x](docs/migration.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

Licensed under [ISC](LICENSE).
