# Repository guidance

## Scope and context

This repository contains the public source edition of `@bridge-applications/tg-auth`, the shared Telegram Mini App authentication library maintained by Bridge Applications. Treat it as an authentication dependency used by production applications, with explicit contracts and migration requirements.

Read [README.md](README.md) and [docs/architecture.md](docs/architecture.md) before changing behavior. Consult [docs/http-integration.md](docs/http-integration.md), [docs/migration.md](docs/migration.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) when relevant.

Keep changes within the requested scope. Public package changes do not automatically authorize changes to sibling repositories or private production consumers. Pushes, publishing, deployments, and secret rotation are separate actions; perform them only when included in the user's authorization. Routine local implementation and verification within the authorized scope do not require another confirmation.

## Repository map

- `src/client.ts`: browser-facing exports and adapter types.
- `src/server.ts`: server-facing verification, token, store, and cookie exports.
- `src/schemas.ts`: shared Zod request/response contracts.
- `src/index.ts`: combined exports for server-side consumers.
- `src/logic/client/TelegramAuthClient.ts`: browser session state and lifecycle.
- `src/logic/client/helpers/callBackend.ts`: HTTP validation, timeouts, and safe errors.
- `src/logic/server/TelegramAuthServer.ts`: application configuration and integration adapters.
- `src/logic/server/helpers/InitDataService.ts`: Telegram proof verification and replay protection.
- `src/logic/server/helpers/TokenService.ts`: encrypted credentials and refresh-group invalidation.
- `tests/`: synthetic protocol fixtures, unit tests, and HTTP integration tests.
- `examples/fetch-handler.ts`: typechecked same-origin HTTP integration with application account hooks.
- `scripts/check-package.mjs`: packed exports, consumer types, and browser dependency isolation.
- `scripts/check-workers.mjs`: actual workerd cryptographic compatibility checks.

Edit source files rather than generated `dist/`, coverage reports, or temporary package-check output.

## Development and validation

Use Node.js 22 or later, npm, ESM, TypeScript, and Zod 4. Follow the existing strict TypeScript configuration. Use type-only imports where appropriate and `.js` extensions for relative TypeScript module imports under NodeNext. Preserve schema-inferred input/output types; do not conceal validation gaps with `any`, blanket casts, or suppressed compiler errors.

```sh
npm ci
npm run typecheck
npm test
npm run test:coverage
npm run test:package
npm run test:workers
npm run format:check
npm run check
```

`npm run check` is the complete release gate. It includes formatting, strict types, coverage, packaged-consumer checks, and the Workers runtime check. The runtime check needs permission to open a local loopback port; it does not require a deployment or live Telegram/Redis credentials. CI checks Node 22 and 24.

For a documentation-only change, check the affected Markdown formatting and verify its references; rerunning the authentication suite is unnecessary. For code changes, start with the relevant tests, then complete the checks affected by the change. Run the full release gate before preparing a release. Report any check that could not run and why; do not describe unexecuted CI as passing.

Keep the existing coverage thresholds. Add focused tests for observable behavior and regressions rather than tests that merely mirror the implementation. Do not lower thresholds, remove assertions, or replace real cryptographic verification with mocks to make a change pass.

## Authentication invariants

- Keep server crypto, Redis, and Node dependencies out of `/client`. Preserve the explicit package exports and browser isolation check.
- Verify Telegram's raw signed `initData` on the server. Never use `initDataUnsafe` or browser-provided identity/privilege fields as authentication evidence.
- Preserve Telegram's distinct HMAC and Ed25519 canonicalization rules, configured bot identity, trusted public keys, and explicit verification mode.
- Reject ambiguous or malformed input. Preserve size/field limits, duplicate-key rejection, strict timestamps, bounded future skew, and exact expiry boundaries.
- Invalid verification results must not contain an unverified identity or echo the submitted credential.
- Replay markers must identify the canonical authenticated assertion, independent of query ordering, equivalent encoding, or supported proof method. Shared consumption must be atomic and retain the marker until expiry; store failures must fail closed.
- Keep credential version, purpose, application, bot, and environment boundaries. Access and refresh credentials must never be interchangeable. Restrict accepted cryptographic algorithms and preserve size limits.
- Validate claims at issuance and verification. Refresh identities must be nonempty strings. Claim schemas must have outputs that remain valid inputs; apply non-idempotent transformations in the application account layer.
- Refresh invalidation must verify a current credential and atomically increment live shared state. Never derive a new counter from a stale credential, reset a counter, or add counter expiry/eviction that could revive revoked credentials.
- Preserve expiry checks after asynchronous verification/store work. Account-wide refresh invalidation is not immediate access-token revocation or individual session rotation.

## Browser and HTTP invariants

- Keep access credentials in memory by default. Persistent storage is explicit and failure-tolerant. Never cache raw init-data or refresh credentials.
- Preserve session-generation guards across logout, reset, and reinitialization. Late responses must not restore a closed session; local state must clear even when remote logout fails.
- Preserve pending provider and silent-refresh deduplication without permanently caching launch assertions or retaining rejected promises.
- Validate the shared API envelope before a custom response schema. HTTP 200 with an API error must never commit credentials.
- Maintain typed custom contracts, response expiry normalization, bounded request timeouts, and sanitized error categories.
- Await asynchronous cookie adapters. Keep issuance and clearing attributes consistent, and document that cookie `maxAge` is measured in seconds.
- Preserve the example's same-origin HTTPS checks, POST-only auth routes, bounded streamed JSON parsing, duplicate-cookie rejection, and no-store responses.
- Application account lookup and authorization remain application-owned. Do not turn a verified Telegram identity directly into trusted roles or permissions.

## Tests, privacy, and external specifications

Use synthetic users, generated/test-only keys, and clearly identified fixture credentials. Do not copy production init-data, bot tokens, user records, cookies, Redis credentials, `.env` files, application exports, or private Git history into this repository.

Preserve real HMAC, Ed25519, and JWE coverage. Exercise tampering, wrong scopes/purposes, malformed input, expiry boundaries, replay/concurrency, unavailable stores, and browser session races when changing those paths. Mock external stores/network behavior where appropriate without mocking away the protocol under test.

Never log request headers/bodies, proofs, tokens, cookies, user records, or raw infrastructure exceptions. Follow `SECURITY.md` for sensitive findings, especially issues shared with private production consumers; do not publish exploit details in ordinary issues or release notes.

Verify protocol or runtime assumptions against current primary documentation when changing cryptography, Telegram verification, Workers compatibility, or dependencies. Preserve the locked dependency workflow and do not add dependencies without a concrete need.

## Compatibility and release preparation

Treat token formats, cookie behavior, identity mapping, namespaces, stores, schema requirements, exports, and replay semantics as public contracts. Explain intentional breaking changes in `docs/migration.md` and `CHANGELOG.md`; update the README and examples with the implementation.

Before a release, run the complete checks, inspect packed contents and dependency sources, and coordinate any necessary private-consumer remediation or migration. Keep CI verification separate from publication. Do not claim that this public version is already deployed in private applications or independently security-audited without supporting evidence.

In the final change summary, state what changed, the checks actually run, and any material compatibility implications or remaining limitations.
