# Reparse Lens

**See filesystem entries that Git status may miss.** Reparse Lens is a dependency-free Node.js command-line inspector for workspace links and metadata anomalies. It can detect ordinary symlinks and Windows junctions even when they are empty, ignored or untracked by Git. It also reports unresolved Git metadata pointers, hardlink ambiguity and optional Windows filename compatibility issues.

**Release stage:** `0.1.0-preview.2` — experimental, **advisory only**. Reparse Lens is **not** a sandbox, access-control mechanism, antivirus product, complete NTFS reparse-point scanner or permission decision. Every scan result sets `authorization: false`.

## Start in five minutes

Requires **Node.js 22 or newer**. Download and extract the source ZIP or clone the GitHub repository. From the extracted project directory, run the CLI directly. No `npm install`, administrator rights or external service is required for ordinary local scans.

**Windows PowerShell:**

```powershell
node .\src\cli.mjs --help
node .\src\cli.mjs doctor --json
node .\src\cli.mjs scan "C:\Projects\MyRepository"
node .\src\cli.mjs scan "C:\Projects\MyRepository" --json
```

**macOS / Linux:**

```sh
node ./src/cli.mjs doctor
node ./src/cli.mjs scan "$HOME/projects/my-repository"
node ./src/cli.mjs scan . --portable --json
```

The tool is intentionally conservative. A clean Windows workspace normally yields **`INCOMPLETE` / exit 3**, not exit 0, because native inspection of every Windows reparse tag is not implemented. A detected junction is **`BLOCKED` / exit 2**. Neither status changes user or agent permissions.

## CLI reference

| Invocation | Behaviour |
| --- | --- |
| `scan [directory]` | Metadata scan of the selected root; defaults to the current directory |
| `scan [directory] --json` | Machine-readable JSON report (`schemaVersion: 1`) |
| `scan [directory] --portable` | Also flag potential Windows filename collisions and reserved names |
| `scan [directory] --max-entries N` | Set maximum inspected entries (default 30,000; maximum 1,000,000) |
| `scan [directory] --max-depth N` | Set maximum directory depth (default 64; maximum 256) |
| `scan [directory] --max-findings N` | Set displayed finding limit (default 1,000; maximum 100,000) |
| `scan [options] -- <directory>` | End option parsing so a directory can start with `-` |
| `doctor [--json]` | Show runtime/platform capability information |
| `--help`, `--version` | Show usage and version |

For a directory literally named `-workspace`, use `node src/cli.mjs scan --json -- -workspace`. Place all options before `--`; exactly one directory argument is accepted after it.

### Exit codes

| Exit | Status | Meaning |
| ---: | --- | --- |
| `0` | `ADVISORY` | Implemented metadata checks completed; **not** proof of safety |
| `2` | `BLOCKED` | Recognized link or path escape detected |
| `3` | `INCOMPLETE` | Unresolved finding, I/O/budget issue or known coverage limitation |
| `64` | — | Invalid CLI arguments, or an unexpected scan-level failure |

Avoid treating any exit code as permission to let an automation read, execute, modify or delete files. Treat statuses as review signals.

## Reading the report

The JSON report contains `schemaVersion`, `status`, `authorization`, `platform`, `entriesChecked`, `excludedGitInternals`, `scanComplete`, `scanLimit`, `limits`, `portabilityChecked`, `summary`, `findings` and `warnings`. See the [JSON interface reference](docs/JSON_API.md) for field meanings, finding shapes and scripting guidance.

Each finding has a diagnostic `code` and a bounded displayed `path`; some include `detail` for a sanitized I/O error. The `summary` counts `linksAndEscapes`, `portability`, `gitMetadata` and `other` findings, plus `totalFindings`, `shownFindings` and `omittedFindings`.

Notable codes include:

- `LINK_FOUND`, `ROOT_IS_LINK`, `ROOT_ANCESTOR_LINK`, `DIRECTORY_ESCAPE`, `FILE_ESCAPE` — recognized links or path escapes.
- `GITDIR_FILE_NOT_INSPECTED` — a `.git` file may be a legitimate Git worktree/submodule pointer; its contents were intentionally not read.
- `MULTIPLE_HARDLINKS_UNRESOLVED`, `ROOT_NOT_DIRECTORY`, `SCAN_ENTRY_LIMIT`, `SCAN_DEPTH_LIMIT` — unresolved coverage or scan limits.
- `WINDOWS_NAME_NOT_PORTABLE`, `WINDOWS_NAME_COLLISION_POSSIBLE` — optional compatibility heuristics, **not** confirmed security issues.

To bound CI report size:

```sh
node ./src/cli.mjs scan . --portable --max-findings 100 --json
```

The scanner still counts findings discovered within the scan-entry/depth budgets. `FINDINGS_TRUNCATED` indicates some details were omitted, and a detected blocking link still makes the result `BLOCKED`. A display limit is not a traversal limit.

## Technical design

```text
CLI arguments (src/cli.mjs)
          |
          v
scanWorkspace(root, options) (src/scanner.mjs)
          |
          +-- validate limits and root / parent metadata
          +-- lstatSync + realpathSync.native snapshot
          +-- incremental opendirSync/readSync enumeration
          +-- inspect directory entries; do not follow recognized links
          +-- count findings and enforce entry/depth/output limits
          |
          v
advisory JSON/human report + exit code (authorization:false)
```

The scanner uses an explicit pending-directory stack rather than recursively invoking itself. It checks the selected root and each parent separately to distinguish root links from linked ancestors. For each enumerated entry it calls `lstatSync`, checks known links, resolves paths using `realpathSync.native`, and queues only directories considered in scope at the time of checking. File **contents are not parsed**.

A root `.git` directory is detected, then its internals are excluded with a warning. Nested `.git` directories are scanned. Git worktree `.git` files are reported as unresolved, without reading their content. `--portable` performs heuristic reserved-name and case-collision checks on each enumerated directory.

**Important boundary:** A sequence of metadata checks is not atomic. Files may be swapped between checks (TOCTOU); unfamiliar Windows reparse tags, cloud placeholders, network/UNC mounts and hardlink targets are not exhaustively classified. A directory pending stack can also grow with discovered subdirectories, so the entry limit bounds enumeration work but is not a constant-memory guarantee. See [Threat model](docs/THREAT_MODEL.md) for failure modes and the [Developer FAQ](docs/FAQ.md) for practical interpretation.

The `scan` and `doctor` commands do not intentionally read file bodies, launch Git/agents, send telemetry or write to the scanned tree. The test suite **does** create and remove disposable fixtures. Scanning a remote, cloud-backed or mapped filesystem may nevertheless cause operating-system/provider I/O outside the CLI's control.

## Installing the preview

**GitHub Release:** download the Source code ZIP for `v0.1.0-preview.2` from the [Releases page](https://github.com/Sharifi2220/reparse-lens/releases), extract it and run `node src/cli.mjs --help`. This requires Node.js 22+. GitHub automatically supplies source ZIP and tar.gz archives; no binary `.exe` is included.

**npm (only after registry publication):** run `npm install -g reparse-lens@preview` and then `reparse-lens --version`. The `preview` dist-tag intentionally separates this experimental build from a future stable `latest` release. No privileged native installer is needed.

## Develop and verify

```sh
npm run check
npm test
npm pack --dry-run --json --ignore-scripts
```

The public npm package preview contains exactly ten files: `DISCLOSURE`, `LICENSE`, `README.md`, `SECURITY.md`, `docs/FAQ.md`, `docs/JSON_API.md`, `docs/THREAT_MODEL.md`, `package.json`, `src/cli.mjs` and `src/scanner.mjs`. This list is separate from the larger public GitHub source repository (which also contains tests, CI and contribution materials). Internal validation notes and local development instructions are excluded.

**Verification as of 2026-10-21:** The 25-case preview test suite ran in a six-job GitHub Actions matrix (Node 22/24 on Windows, Ubuntu and macOS), all jobs successful: per job Windows 21 PASS / 4 SKIP, Ubuntu 25 PASS / 0 SKIP, macOS 24 PASS / 1 SKIP. Windows Node 24 host acceptance also reported 21 PASS / 4 SKIP and a real junction detected as `BLOCKED`; a clean Windows control remained `INCOMPLETE`. Skips are coverage gaps, not passing tests. These are dated evidence for the tested revision; rerun CI after changing the release candidate.

See [Contributing](CONTRIBUTING.md), [Security reporting](SECURITY.md), the [JSON interface reference](docs/JSON_API.md) and the [Release checklist](RELEASE_CHECKLIST.md). The preview package has a deliberately restricted nine-file npm allowlist. **npm registry publication is separate from the GitHub source release.** Until a verified npm package exists, use the GitHub source ZIP/CLI. After npm publication, install the prerelease explicitly with `npm install -g reparse-lens@preview` (not `@latest`).

## npm dual-use content and publishing

The npm package declares `contentPolicy.class: dual-use` and includes a root [DISCLOSURE](DISCLOSURE) explaining its legitimate use, foreseeable misuse and known limits. This is a transparency declaration under the [npm Dual-Use Content Policy](https://docs.npmjs.com/policies/dual-use/), not a classification as malware or proof of security. **Direct publication requires interactive 2FA**. The repository's manual npm workflow checks package contents only and does not publish or handle tokens. Publishing to the `preview` dist-tag is a separate authenticated step; until a registry entry is independently verified, use the GitHub source archive.

## License, support and references

Licensed under [Mozilla Public License 2.0](LICENSE), which permits commercial use subject to its terms. This project does not promise a commercial service, security certification or support SLA.

General questions and confidential vulnerability reports: GitHub's private vulnerability reporting channel. Do not send real credentials, personal filesystem inventories or private workspace content.

Primary documentation: [Node.js filesystem API](https://nodejs.org/api/fs.html) · [Git status](https://git-scm.com/docs/git-status) · [Git worktrees](https://git-scm.com/docs/git-worktree) · [Microsoft Windows reparse tags](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags) · [Windows filename rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
