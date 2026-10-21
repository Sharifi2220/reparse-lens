# Release checklist — Reparse Lens v0.1 experimental preview

This checklist distinguishes **validated evidence**, **still-open checks** and the **publication action**. A public source preview is not a stable/security-certified product or an npm publish. No internal development, personal or unrelated-project files belong in the release.

## Exact public GitHub source allowlist

The reviewed tree contains only the following **14 tracked public files**:

```text
.gitattributes
.gitignore
.github/workflows/ci.yml
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

Do not add internal progress records, agent instructions, validation reports, private workspace contents, local backups, temporary build folders, credentials, secret logs, screenshots or code from other projects. **Before changing visibility, re-enumerate the entire branch AND default-branch history/tree**; a file excluded from the current tree might still exist in Git history. Never publish a private repository with contaminated history.

The npm dry-run allowlist is smaller and independent: exactly eight runtime/distribution files — `LICENSE`, `README.md`, `SECURITY.md`, `docs/FAQ.md`, `docs/THREAT_MODEL.md`, `package.json`, `src/cli.mjs`, `src/scanner.mjs`. Keep `"private": true`: there is **no** approved npm publication.

## Evidence already collected for the tested source revision (2026-10-21)

- [x] Reviewed the six public documentation files against the release candidate, with exact content match at the tested revision.
- [x] Release-candidate test suite has 25 tests; Windows Node 24.15.0: `npm run check` exit 0, `npm test` 21 PASS, 0 FAIL, 4 SKIP.
- [x] Actual isolated NTFS junction on Windows reported `BLOCKED` / exit 2 and `authorization: false`; sentinel target not traversed in the test.
- [x] Clean Windows scan reported `INCOMPLETE` / exit 3.
- [x] Final GitHub Actions run `39601823151`: six jobs succeeded (Node 22/24 × Windows/Ubuntu/macOS; Windows 21 PASS/4 SKIP, Ubuntu 25/0, macOS 24/1 per job).
- [x] `npm pack --dry-run --json --ignore-scripts` reported eight allowlisted runtime files for the tested source.
- [x] Initial current-tree inventory of 14 intended public tracked files completed; no status, research or temporary files in this tree.

**These checks apply to the cited tested source/CI run, not automatically to future commits.** SKIP does not count as PASS.

## Final checks before public visibility

- [ ] Synchronize the reviewed public documentation and verify the saved bytes. Internal working notes must remain outside the public repository.
- [ ] Re-run and review all six CI jobs on the **final** source/documentation commit; inspect failures and SKIPs individually.
- [ ] Inspect the exact default-branch tree and **full Git history** for secrets, private paths and unintended files. Also inspect PR commits, metadata, LICENSE and current README links. If history includes confidential bytes, resolve them before changing visibility.
- [ ] Confirm release README commands on a fresh source ZIP and package dry run. Verify `node src/cli.mjs --help`, `doctor --json`, a disposable scan, exit codes, paths, platform notes and link targets.
- [ ] Verify MPL-2.0 full license text/attribution, source originality, contact address, repository name and publicly visible issue/security reporting path. Record any uncompleted external security review as a limitation, not as approval.
- [ ] Verify source ZIP/npm file lists, `.gitignore`, `.gitattributes`, workflow permissions and Actions dependencies. No token, signing key, CI fixture, Windows absolute private path or extra internal file may be published.
- [ ] Record final hashes, Git commit, check results, skip reasons and residual risk in private internal release records.

## Publication controls

- [ ] Final public-source preview is authorized by the owner, with explicit scope (GitHub source only vs npm/release artifacts). A user authorization never proves technical gate success.
- [ ] Merge only the reviewed/safe branch into `main`, with new head SHA checked immediately before merge.
- [ ] Make only the **clean, reviewed source repository** public through a GitHub administrative UI/authorized workflow, after rechecking the entire visible history.
- [ ] Verify anonymously/publicly accessible README, license, security contact, intended files and links.
- [ ] Optional later: decide whether a GitHub Release/tag is needed. npm publish is a **separate** decision and remains disabled via `private: true`.

## Known preview limitations — disclose publicly

No full native Windows reparse-tag adapter; no TOCTOU-resistant handle traversal; unclear cloud/UNC/provider behavior; legitimate internal symlinks may be reported BLOCKED; portability heuristics can be noisy; Git worktree pointer files are not parsed; no independent security certification. The diagnostic result always carries `authorization: false`.

The objective is a **clearly labeled experimental developer preview**, not a guarantee of workspace safety.

