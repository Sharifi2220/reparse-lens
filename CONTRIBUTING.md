# Contributing to Reparse Lens

Reparse Lens is a small dependency-free, advisory filesystem metadata scanner. Contributions should improve reproducibility, documentation, Windows/macOS/Linux portability and honest reporting of uncertainty — not turn it into an unreviewed execution permission system.

## Setup

Use **Node.js 22 or 24** and a clean checkout or source ZIP. No `npm install` is required.

```sh
node src/cli.mjs --help
node src/cli.mjs doctor --json
npm run check
npm test
npm pack --dry-run --json --ignore-scripts
```

Run optional manual `scan` commands only against a disposable synthetic workspace, never against a contributor's real secrets without their permission. Tests must create and clean up synthetic fixtures; teardown must not follow junction or symlink targets.

## Change contract

1. State the observed platform/Node version, expected result and failure. Add a minimal regression test when possible.
2. Preserve the **metadata-only, no intentional Git/subprocess/network/file-body-read** behaviour of `scan` and `doctor`.
3. Maintain `schemaVersion: 1`, `authorization: false`, and the documented exit-code semantics unless a deliberately versioned migration is approved.
4. Use `INCOMPLETE` for I/O failures, unresolved entry types and budget exhaustion; do not replace incomplete coverage with a false `ADVISORY`.
5. Retain bounded `--max-entries`, `--max-depth` and `--max-findings` behaviour. An observed blocked link must remain blocked after reporting truncation.
6. Cross-platform fixtures should **SKIP explicitly** when the filesystem cannot create them. Clearly report PASS/FAIL/SKIP; never convert a SKIP into a security PASS.
7. Describe any external dependencies, native Windows code or changes to scanning trust boundaries before implementation. Avoid new runtime dependencies.
8. Keep public contributions free of personal file paths, secrets, private project names, unrelated proprietary code and full private scans. Respect the [MPL-2.0](LICENSE), including existing notices.

## Where to contribute

Start with a focused issue or patch describing the user-visible behaviour. Do not upload a private workspace or an unredacted `--json` report. Security issues belong in [SECURITY.md](SECURITY.md), **not** a public issue.

The synchronized baseline has **25 tests**. On 2026-10-21 its cross-platform CI matrix passed with documented platform SKIPs; a passing matrix is not proof of complete native NTFS or TOCTOU coverage. See the [README](README.md) for architecture and the [Threat model](docs/THREAT_MODEL.md) for what this scanner cannot establish.

For public contributions, use GitHub issues or pull requests. Security issues follow [SECURITY.md](SECURITY.md) and should not be disclosed publicly.
