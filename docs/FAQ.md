# Reparse Lens — Developer FAQ

**Current stage:** `0.1.0-preview.2`, experimental and advisory-only. A scan is a snapshot of selected metadata, **never** permission for an agent or script to operate on a workspace. See the [JSON interface reference](JSON_API.md) before integrating reports into scripts.

## What problem does it solve?

Git tracks or reports a different view from the underlying filesystem. An empty, ignored or untracked directory junction may not appear in `git status`, yet still redirect filesystem access. Reparse Lens checks filesystem metadata directly and reports recognized links, possible scope escapes and unresolved cases.

## I installed it successfully. What should I scan first?

Start with **one existing development project**, rather than your whole user profile. For example, in PowerShell:

```powershell
reparse-lens --version
reparse-lens doctor --json
reparse-lens scan "C:\\Projects\\my-app" --json
```

Replace the example path with your actual project directory. From inside that directory, `reparse-lens scan . --json` is equivalent. See the [README quick start](../README.md#quick-start-install-and-run). The CLI inspects metadata; it does not intentionally read source-file contents or modify the scanned tree.

## Why do I see BLOCKED and scanComplete: false together?

They describe **different facts**, not contradictory results:

- `BLOCKED`: a recognizable link, junction or path escape was observed. On Windows, older compatibility directories in a user profile can cause this without indicating malware.
- `scanComplete: false`: traversal did not start, was interrupted by an I/O error, or reached a budget. Only a budget stop has `scanLimit.kind`, `scanLimit.limit`, and `scanLimit.nextPath`; the latter names the first **not inspected** entry, not necessarily a problem. Also examine `coverage.enumeration`.
- `entriesChecked` does not exceed the configured `maxEntries`. For example, 30,000 checked entries and a limit of 30,000 does not mean the remaining files were examined.
- `SCAN_LIMIT_REACHED` is an explicit warning separate from any observed links. Raising a limit or narrowing the scan scope may help investigate, but neither approach makes the tool a security gate.

An ordinary Windows profile scan may contain both normal junctions and large dependency trees. Do **not** delete junctions or make system changes merely because this report says `BLOCKED`.

## Why does a clean Windows scan return INCOMPLETE / exit 3?

Node-based metadata checks cannot prove coverage of all native NTFS reparse tags. A clean Windows result therefore stays `INCOMPLETE`, while a recognized junction is `BLOCKED` / exit 2. This is deliberate, not an installation problem.

## Does BLOCKED mean a link is malicious?

No. The scanner conservatively reports recognized links, including legitimate monorepo workspace links inside `node_modules`. It does not automatically allow internal links or resolve their targets. A previous development version added a `scope` hint by resolving targets; this was withdrawn due to the risk of SMB/UNC network access on Windows. Review the link separately and use your own trust policy; the scanner does not grant permission.

## Why does a .git file generate a finding?

Git linked worktrees and submodules may store a **file** named `.git` pointing to metadata elsewhere. Reparse Lens does not read that pointer's content, so `GITDIR_FILE_NOT_INSPECTED` is unresolved and leads to `INCOMPLETE`. A root `.git` directory is recognized and its internals excluded with a warning; nested `.git` directories remain in scan scope.

## Are Windows filename warnings security vulnerabilities?

Not inherently. `--portable` flags names with possible Windows device-name/trailing-dot/conflicting-character problems and case collisions. These are **compatibility heuristics**, not proof of exploitation. Their presence currently produces `INCOMPLETE` under report schema v1; a future version may distinguish portability from scan coverage.

## How can I use the CLI in scripts?

```sh
node src/cli.mjs scan . --json --max-findings 100
```

Check the process exit code **and** the `status`, `warnings` and `authorization` fields. Interpret exit 0 only as completion of implemented checks, exit 2 as an observed link/escape, exit 3 as incomplete coverage, and exit 64 as invalid invocation or scan-level failure. Do not map any status to automatic execution authorization.

## How can I scan a directory whose name starts with a hyphen?

Put options before the `--` terminator:

```sh
node src/cli.mjs scan --json -- -workspace
```

## What are the limits and memory implications?

The default budgets are 30,000 entries, depth 64 and 1,000 displayed findings. `--max-findings` limits output but does not stop scanning early. Even if a link finding is omitted from the normal finding list, a blocking link is retained in the result classification. Entry limits bound work, but the pending directory stack and per-directory case-folding map may still use memory; the scanner is **not** a constant-memory proof.

## Does it read source code or access the network?

The `scan` and `doctor` commands do not intentionally read file bodies, run Git, invoke agents, send telemetry or connect to a service. `npm test` creates/deletes temporary synthetic fixtures. The operating system or a cloud/UNC/mapped filesystem provider may nevertheless generate network or disk activity when resolving metadata. This tool is **not** a network or filesystem sandbox.

## Is a successful scan safe against concurrent changes?

No. `lstat`, `realpath` and directory enumeration occur at different times. Another process could replace an entry between checks (TOCTOU). Never use the result to authorize subsequent file operations.

## Can I use it without npm, admin rights or an installation?

Yes, with an existing Node.js 22+ runtime. Download a source ZIP, extract it, and run:

```sh
node src/cli.mjs --help
node src/cli.mjs scan .
```

The npm preview declares security-relevant dual-use functionality in `package.json` and the published root `DISCLOSURE`. The `0.1.0-preview.2` package is published on npm with the `preview` dist-tag. Direct publication required an authorized npm session with interactive 2FA and cannot be performed through the former token-only CI shortcut. Install it with `npm install -g reparse-lens@preview` or use the GitHub source release.

## How do I report a bug safely?

Include OS/filesystem, Node version, command, expected status/exit, observed status/exit, and a reproducible **synthetic** tree. Remove usernames, real workspace names, tokens and private data. Use the private contact in [SECURITY.md](../SECURITY.md) for vulnerabilities.

## What has been tested, and what remains unknown?

For the original 2026-10-21 preview release, 27 test cases ran successfully in GitHub Actions on Node 22/24 × Windows, Ubuntu and macOS with all six jobs successful; platform fixture SKIPs remain explicit coverage gaps. A real Windows host also confirmed a recognized junction is blocked and not intentionally traversed; the release-candidate scanner, CLI and test sources were synchronized with the release branch.

For the local post-merge security correction on 2026-10-22, 36/36 tests passed on Linux Node 22.16 and syntax checks passed. This later hotfix has **not** completed a new Windows/macOS CI matrix, Windows SMB authentication test, or npm release; the cross-platform 33-test CI previously completed for PR #4 verifies the earlier source only.

Unknown: complete Windows-native reparse-tag coverage, atomic traversal/no-follow handle guarantees, unrestricted cloud/UNC cases, and an external independent security certification. These are disclosed scope limits, not claims of completed protection. See the [technical design](../README.md#technical-design), [Threat model](THREAT_MODEL.md) and [Release checklist](../RELEASE_CHECKLIST.md).

