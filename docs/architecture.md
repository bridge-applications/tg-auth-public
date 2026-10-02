# Architecture

## Trust boundaries

The browser reads Telegram's raw `initData` and exchanges it with the application backend. Browser-provided user objects and `initDataUnsafe` are not identity evidence. Only the server's verified result may be used for account lookup.

The server verifies Telegram's protocol proofs. HMAC uses the bot token and includes every received field except `hash` in Telegram's sorted data-check string. Ed25519 uses the configured Telegram public key and bot ID, excluding `hash` and `signature` from its sorted data-check string. Either mode prefers Ed25519 and accepts a valid HMAC fallback when a bot token is configured.

Input is limited to 16 KiB and 64 fields. Duplicate decoded keys, invalid percent encoding, invalid key names, and literal line breaks are rejected to avoid ambiguous canonicalization. Timestamp parsing is strict and freshness is checked at the exact expiry boundary. Invalid results contain only a reason code, never an unverified identity or the submitted credential.

## Assertion replay

Init-data is a bearer assertion, not a request-bound challenge. Validating a proof does not itself make it single-use. Optional replay protection fingerprints the authenticated field set in canonical order, excluding protocol proof fields. Equivalent transport encodings and supported signature paths produce the same identity. The marker is scoped by application, bot, and environment.

`ReplayStore.consume(key, expiresAtMs)` must atomically allow at most one success and retain the marker until the assertion expires. Redis implements this using `SET NX PX`. A store failure rejects verification. An in-memory set is appropriate only for tests; it cannot coordinate replicas or survive process restarts. Enabling single-use requires a refresh-cookie resume path for repeated launches.

## Credentials and revocation

Tokens are compact JWE values using direct encryption and A256GCM. They contain a version, purpose, audience, validated payload, and millisecond issuance/expiry metadata. Protected headers distinguish access from refresh credentials. Server verification restricts accepted algorithms and rejects cross-purpose, cross-application, cross-bot, and cross-environment credentials.

Claims are validated at issuance and verification; refresh identities must be nonempty strings. Use claim schemas whose output is also valid input. Credentials have bounded size. Secret bytes and configuration are captured when creating the verifier; mutate neither an initialized configuration nor its schemas.

Refresh groups use hashed identity keys and atomic increments. The default group is zero only when the store reports a missing key as `null`. Other malformed state fails closed. Do not expire or evict group counters: deleting a counter can restore an older generation's authority. Use durable, shared storage and preserve counters across deployments.

`rotateRefreshTokenGroup` first verifies a current credential, then increments the live stored counter. Concurrent invalidations advance state monotonically. This is account-wide refresh invalidation, not per-session rotation or immediate access-token revocation. Already issued access tokens remain valid until expiry. Changing namespaces, environments, keys, or disabling group verification is a session migration decision.

## Browser state

The client is a singleton for one application per browser realm. Tokens stay in memory unless storage is explicitly configured. Refresh tokens remain in HttpOnly cookies; the client stores only their expiry estimate. An expired access credential triggers a shared silent refresh. Async init-data provider requests are shared only while pending.

A session generation guards all asynchronous credential commits. Logout clears local state before requesting server closure, even when the server request fails. Pending responses from a superseded generation cannot restore the session. While closure is pending, new authentication is blocked. This protects client state; it cannot retract HTTP requests already sent or replace server-side revocation.

## Modules

- `/client`: browser session lifecycle, HTTP contracts, safe API errors, and Telegram adapter types.
- `/server`: Telegram verification, JWE issuance/verification, shared stores, and cookie adapters.
- `/schemas`: shared Zod 4 request/response schemas and API enums.
- Root: combined exports for server-side use.

The server uses Node crypto for HMAC/hash operations and Web Crypto for Ed25519 and JWE. Workers require `nodejs_compat`. CI's runtime check runs actual workerd cryptography without external services; it is not a production deployment test.
