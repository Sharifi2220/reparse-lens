# Release checklist — Reparse Lens 0.1.0-preview.2

Reparse Lens is an **experimental, advisory-only** filesystem metadata inspector. This version adds a voluntary npm dual-use declaration and the required disclosure; it does not add new scanner security capabilities.

## Exact public source allowlist (17 files)

```text
.gitattributes
.github/workflows/ci.yml
.github/workflows/npm-publish.yml
.github/workflows/release-preview.yml
.gitignore
CONTRIBUTING.md
DISCLOSURE
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

No internal STATUS, private workspace contents, backups, agent plans, personal paths, credentials or unrelated project files belong in the public tree or distributed archive. Check the final reachable Git history and diff, not just the working tree.

## Exact npm distribution allowlist (9 files)

```text
DISCLOSURE
LICENSE
README.md
SECURITY.md
docs/FAQ.md
docs/THREAT_MODEL.md
package.json
src/cli.mjs
src/scanner.mjs
```

Package contract: `name: reparse-lens`, `version: 0.1.0-preview.2`, `private: false`, `publishConfig.tag: preview`, `publishConfig.access: public`, Node 22+, and `bin.reparse-lens = ./src/cli.mjs`.

**npm policy:** The `contentPolicy.class = dual-use` declaration and root `DISCLOSURE` are required for this security-relevant preview. npm's [Dual-Use Content Policy](https://docs.npmjs.com/policies/dual-use/) requires **2FA enforcement for publication**. Direct publication is allowed only with interactive 2FA; a token that bypasses 2FA or direct OIDC trusted publishing must NOT be used. The existing `.github/workflows/npm-publish.yml` now performs only **read-only package preflight checks**. For future versions, maintain the dual-use declaration and disclosure unless npm's Trust & Safety team approves their removal.

## Source and test evidence already established

- [x] Earlier GitHub source preview `v0.1.0-preview.1` was publicly released.
- [x] The tested scanner behavior is conservative: recognized Windows junction -> `BLOCKED`/exit 2; clean Windows scan -> `INCOMPLETE`/exit 3; `authorization: false`.
- [x] A previous Windows Node 24.15.0 host run reported 21 PASS, 0 FAIL, 4 SKIP; prior six-platform matrix 6/6 success.
- [x] Root `DISCLOSURE` and explicit `contentPolicy.class = dual-use` were added to the new candidate branch.
- [x] The npm publisher workflow has been converted into a token-free preflight, with **no direct npm publish** or registry credentials.

Prior evidence does not automatically validate the new release tag. Skips are not passing security checks.

## A. Preview.2 GitHub source release gate

- [ ] Review final 17-file repository tree, Git history, license, relative links and absence of private data or secrets.
- [ ] Sync modified GitHub source files into the corresponding **existing** Google Drive project originals; create only the new `DISCLOSURE` inside the same project code root; read back files and compare SHA-256. Keep private STATUS outside GitHub.
- [ ] Run `npm run check` and `npm test` on Node 22/24 across Windows, Ubuntu and macOS (six CI jobs). Report PASS/FAIL/SKIP separately.
- [ ] Run GitHub preview workflow for 0.1.0-preview.2; prove the npm archive contains exactly the nine files listed above; check CLI `--version` and policy metadata.
- [ ] After all checks pass, squash-merge the review branch into `main`; record exact SHA.
- [ ] Verify GitHub Actions generated prerelease `v0.1.0-preview.2` and its automatic source ZIP/tar.gz. Do not alter the original `v0.1.0-preview.1` tag or release.
- [ ] Record results and remaining limitations in the **private** project STATUS.

## B. Separate npm first-publication gate

- [ ] Confirm official registry package/name status and logged-in owner `npm whoami`.
- [ ] Verify 2FA is enabled and the interactive publishing session enforces 2FA. Do NOT use direct OIDC or a bypass-2FA token for this dual-use package.
- [ ] Check out the exact immutable GitHub tag `v0.1.0-preview.2` in the authorized local project or verified release checkout.
- [ ] Re-run version, tests, license/disclosure check, `npm pack --dry-run --json --ignore-scripts`, and compare exactly nine paths.
- [ ] Publish with an interactive 2FA challenge only: `npm publish --access public --tag preview --registry https://registry.npmjs.org/`.
- [ ] Independently verify `npm view reparse-lens@preview`, published version, tarball integrity and `npm install -g reparse-lens@preview` / `reparse-lens --version`.
- [ ] Update the private STATUS; if any check fails, stop and document the exact failure. No stable `latest`, second package name, bypass token or unrelated GitHub tag.

## Known limitations to preserve

No complete native NTFS reparse-tag inspection; no race-resistant TOCTOU or security sandbox; provider/cloud/UNC ambiguity; Git-worktree pointers are not parsed; hardlink aliases may be unknown; portability warnings can be heuristic. Treat reports as diagnostic evidence, not access authorization.
