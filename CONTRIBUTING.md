# Contributing to RASP

RASP is a multi-module repository. Keep a change scoped to the module it
affects unless the integration contract genuinely requires a coordinated
change.

## Branches and commits

- Create work from `main` using `feature/<area>-<short-description>`,
  `fix/<area>-<short-description>`, or `docs/<short-description>`.
- Use imperative, concise commit subjects, for example
  `Backend: validate credential expiry`.
- Do not commit build products, local `.env` files, private keys, tokens, or
  generated production credentials.

## Pull requests

- Explain the module(s) changed and any cross-module contract change.
- Include relevant test, lint, or build output.
- Update user-facing documentation and safe example environment files when
  configuration changes.
- Keep dependency upgrades focused; do not bundle unrelated refactors.

## Quality checks

Run the relevant module checks before requesting review:

- Dashboard: `npm ci`, `npx tsc --noEmit`, `node --test lib/*.test.ts`, and
  `npm run build` in `RASP_Dashboard/`.
- Backend: `npm ci`, `npx prisma generate`, `npm test`, and `npm run build`
  in `RASP_Backend/`. Database integration tests also require PostgreSQL and
  Redis configured as documented by that module.
- Flutter wrapper: `flutter pub get`, `flutter analyze --no-fatal-warnings
  --no-fatal-infos`, and `flutter test` in
  `RASP_SDK_Wrappers/flutter/rasp_shield_sdk/`.
- Engine: follow `RASP_SDK_1/docs/PUBLISHING.md`; it requires the pinned
  Android NDK, Rust targets, and `cargo-ndk`.

## Security

Treat credentials, signing keys, API secrets, private certificates, and
production configuration as sensitive. The TLS key under the Flutter test
fixtures is deliberately a test-only fixture; do not reuse it outside tests
or add real keys beside it. Report security-sensitive issues privately to the
project maintainers rather than opening a public issue.
