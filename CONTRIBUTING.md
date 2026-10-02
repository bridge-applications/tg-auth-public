# Contributing

Use Node.js 22 or later and npm. Install the locked dependencies with `npm ci`, then run `npm run check`. The runtime check starts a local workerd process; it needs permission to open a loopback port. No live account credentials are needed.

For fixes, include a focused regression test that demonstrates the behavior being corrected. Keep changes narrow and explain observable behavior, compatibility implications, and validation. Preserve browser/server isolation and inferred schema types. Test both the protocol path and failure paths when modifying authentication or session state.

Do not add real Telegram users, tokens, cookies, bot credentials, Redis credentials, or application exports to fixtures. Synthetic keys must be clearly identified. Never log authentication payloads or raw infrastructure errors. Security reports should follow [SECURITY.md](SECURITY.md) rather than public issues.

Public source changes do not automatically upgrade internal production consumers. Changes to credential formats, cookie behavior, identity mapping, or replay semantics require explicit migration planning. Publishing is a maintainer action; CI only verifies the repository.
