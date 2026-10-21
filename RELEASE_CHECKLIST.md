# Reparse Lens release checklist

This checklist is for a future release. It does not publish code, create a GitHub release, change repository visibility or publish to npm.

## Source and documentation

- [ ] Review the exact release diff and confirm that it contains only the Reparse Lens package.
- [ ] Confirm MPL-2.0 licensing, preserved notices and no copied private or third-party source.
- [ ] Confirm README quickstart, FAQ, CONTRIBUTING.md and SECURITY.md are current.
- [ ] Confirm the public contact address is `akkbkk10@gmail.com` and no other private contact data is present.
- [ ] Confirm internal instructions, validation notes, status files, private paths, credentials and temporary fixtures are excluded.

## Verification

- [ ] Run Node.js 22 and 24 checks on Windows, macOS and Linux through GitHub Actions.
- [ ] Run all 19 tests and record PASS, FAIL and SKIP counts separately.
- [ ] On Windows, verify a real NTFS junction is `BLOCKED` with exit 2 and is not traversed.
- [ ] Keep a clean Windows scan as `INCOMPLETE` with exit 3 until native reparse-tag coverage exists.
- [ ] Run `npm pack --dry-run --json --ignore-scripts` and review the exact package file list.
- [ ] Extract the offline archive and run `node src/cli.mjs --help` and a disposable scan.
- [ ] Complete an independent security and license/IP review.

## GitHub and npm

- [ ] Keep `Sharifi2220/reparse-lens` private until the owner gives explicit public-release approval.
- [ ] Apply the agreed repository topics and verify the default branch and CI workflow.
- [ ] Before public visibility, recheck the final diff, hashes, repository metadata and issue/security contact path.
- [ ] Create a GitHub release only after the public-release approval and successful release gates.
- [ ] Decide separately whether an npm package is wanted; `private: true` must remain until that decision.
