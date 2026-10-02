# Changelog

## 2.0.0-rc.1 — Unreleased

- Public source edition of the shared Bridge Applications Telegram authentication package.
- Separate ESM browser, server, and schema entry points with typed package exports.
- HMAC and Ed25519 assertion validation, strict parsing and freshness, and optional canonical atomic replay detection.
- Versioned and purpose-scoped JWE credentials, validated claims, bot/environment isolation, and shared refresh-group invalidation.
- Browser generation guards, memory-first credential storage, provider and silent-refresh deduplication, and strict API envelopes.
- Asynchronous cookie adapters and a bounded same-origin Fetch integration with account authorization hooks.
- Automated regression tests, enforced coverage, packaged-consumer checks, and a workerd runtime check.

This release changes token formats and several integration contracts. See [migration notes](docs/migration.md) before upgrading an internal 1.x application.
