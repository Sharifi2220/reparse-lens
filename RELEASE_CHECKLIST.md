# Reparse Lens 0.1.0-preview.1 — GitHub Release and npm checklist

This release is **experimental and advisory-only**. The GitHub repository source was already made public before this packaging work. An official GitHub prerelease and an npm package are **separate publication events** with separate verification.

## Allowlisted public repository source

The previous GitHub repository had 14 public files. This preview adds precisely two GitHub Actions workflows for release/publishing. All **16 intended repository paths**:

```text
.gitattributes
.github/workflows/ci.yml
.github/workflows/npm-publish.yml
.github/workflows/release-preview.yml
.gitignore
CONTRIBUTING.md
LICENSE
README.md
RELEASE_CHECKLIST.md
SECURITY.md
docs/FAQ.md
docs/THREAT_MODEL.md
package.json
src/cli.mjs
src/scanner.mjs
test/scanner.test.mjs
```

Do not add private internal project records, Codex instructions, validation data, backups, secrets, local path inventories, personal information or temporary test fixtures. Verify both the Git history and source tree before publishing a new artifact. Workflow permissions are scoped to their specific tasks.

## Eight-file npm allowlist

Only the following files are permitted in `npm pack --dry-run --json --ignore-scripts`:

```text
LICENSE
README.md
SECURITY.md
docs/FAQ.md
docs/THREAT_MODEL.md
package.json
src/cli.mjs
src/scanner.mjs
```

The preview manifest uses `"name": "reparse-lens"`, `"version": "0.1.0-preview.1"`, `"private": false`, `"publishConfig.tag": "preview"` and requires Node 22+. The bin entry remains `reparse-lens -> ./src/cli.mjs`.

**The manifest allows publication but does not mean the package exists in the npm registry.** Publishing to `preview` must never silently promote this build to the `latest` dist-tag.

## Previously established source evidence

- [x] MPL-2.0 full license and security/disclosure docs included.
- [x] Windows Node 24 host acceptance: `npm run check` PASS, 25 synthetic tests with 21 PASS, 0 FAIL, 4 SKIP.
- [x] Actual Windows junction -> `BLOCKED` / exit 2 / `authorization: false`; clean Windows scan -> `INCOMPLETE` / exit 3.
- [x] Public baseline GitHub Actions run `39602926526` on Node 22/24 × Windows/macOS/Ubuntu completed 6/6 SUCCESS.
- [x] Prior npm dry-run listed exactly eight intended runtime files.

These are **dated historical checks**. Re-run on the actual preview commit; do not count SKIP as PASS.

## Gate A: First GitHub prerelease

- [ ] Synchronize changed release files to the authoritative project root and read back bytes/hashes before the release is considered complete.
- [ ] Run 25 synthetic tests on all six cross-platform CI jobs on the final PR head.
- [ ] Pass the dedicated preview packaging audit (version check, `doctor --json`, eight-file `npm pack` inspection).
- [ ] Validate the final exact 16-file tree, whole visible Git history, code/license/docs and private-data patterns.
- [ ] Merge reviewed PR into `main` by squash and verify its SHA.
- [ ] Verify that `.github/workflows/release-preview.yml` created **only one** `v0.1.0-preview.1` GitHub prerelease via a `main` push, with GitHub's built-in source ZIP and tar.gz.
- [ ] Verify public release URL, tag target SHA, notes, and automatic download links. No binary executable is promised.

## Gate B: First npm publish — independent of GitHub

- [ ] Query the official npm registry from an internet-connected runner to establish whether `reparse-lens` exists. A 404 is **not** a reservation or an ownership guarantee.
- [ ] Confirm an authenticated npm publisher has rights to `reparse-lens`. The first package release generally needs a logged-in npm owner or authorized publish token; do not assume GitHub OIDC trusted publishing is already linked to an uncreated package.
- [ ] With the GitHub tag verified, configure an authorized short-lived automation token or an already established npm trusted publisher (see npm's current security documentation). Never paste tokens into issues or logs.
- [ ] Trigger the **manual only** `.github/workflows/npm-publish.yml` workflow using input `confirm_tag: v0.1.0-preview.1`; it checks out that tag and publishes with `--tag preview` only.
- [ ] Verify the actual registry URL and `npm view reparse-lens@preview`; test `npm install -g reparse-lens@preview` and `reparse-lens --version` in a clean environment.
- [ ] Record publisher, tarball integrity, provenance (if present), final package version, dist-tag and CI logs in the private project release record. Do not claim npm was published from a successful dry-run alone.

## Security/quality disclosures

An `ADVISORY` scan is not authorization. Windows-native reparse-tag coverage is incomplete; a clean Windows scan remains `INCOMPLETE`. Metadata checking does not prevent TOCTOU races or protect against malicious concurrent processes; Git worktree pointers, hardlink aliases, cloud and UNC metadata may be unresolved. No independent safety certification is claimed.

The product is a **free experimental developer preview**, not a sandbox, malware scanner or guaranteed workspace protection.
