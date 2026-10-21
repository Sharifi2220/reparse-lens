# Technical design and threat model — Reparse Lens 0.1.0-preview.2

## Purpose and boundary

Reparse Lens is an offline-by-design, dependency-free Node.js **metadata inspector** for selected workspaces. It supplements Git inventory, which may miss empty, ignored and untracked link entries. The tool reports recognizable filesystem links, unexpected canonical paths, ambiguous metadata, and opt-in Windows filename portability issues.

It does **not** enforce an access-control policy, sandbox another process, verify all native Windows reparse tags, prevent time-of-check/time-of-use races, read file contents or authorize agent actions. Every emitted report includes `authorization: false`.

## Source layout and data flow

| File | Responsibility |
| --- | --- |
| `src/cli.mjs` | Parse commands and limits, render human/JSON output, map scan status to process exit code |
| `src/scanner.mjs` | Validate root, incrementally enumerate filesystem metadata, classify findings, record incomplete coverage |
| `test/scanner.test.mjs` | Synthetic cross-platform regression tests; fixture creation/teardown |
| `package.json` | Node 22+ engine, CLI entry point, script commands and explicit npm file allowlist |
| `docs/JSON_API.md` | Stable schema-v1 field reference and integration guidance for JSON consumers |
| `SECURITY.md` | Supported security claims and private vulnerability reporting |

The scanner uses built-in `node:fs` and `node:path`: `lstatSync`, `realpathSync.native`, `opendirSync`/`readSync`, `resolve`, `relative` and path-root utilities.

1. **Validate inputs.** Root is required; scan limits must be safe positive integers. Defaults: maxEntries 30,000; maxDepth 64; maxFindings 1,000. Hard maxima: 1,000,000; 256; 100,000.
2. **Validate root and its ancestors.** The scanner checks parent path components using `lstatSync` and separately classifies a selected root that is itself a link or not a directory. It then obtains a canonical root path.
3. **Walk incrementally.** An explicit LIFO stack holds pending directory paths. Each pending directory is rechecked via `lstatSync` and `realpathSync.native` immediately before `opendirSync`. Entries are consumed incrementally via `readSync`, rather than materializing the entire directory into an array.
4. **Classify each entry.** Recognized symlinks or Windows junctions are recorded without following their targets. In-scope directories are queued; regular files are checked for canonical escapes and link-count ambiguity. Other types and failed metadata calls produce findings.
5. **Treat Git metadata cautiously.** A top-level `.git` directory is recognized then excluded with an explicit warning. Nested `.git` directories are scanned. A `.git` **file** can be a legitimate worktree/submodule redirect and is not parsed; it produces `GITDIR_FILE_NOT_INSPECTED`.
6. **Optionally test portability.** `--portable` checks reserved Windows-like names, forbidden characters/trailing dots/spaces and per-directory heuristic Unicode NFC/uppercase collisions. These are not security proofs.
7. **Report without authorizing.** Findings are counted by category. The human or JSON output is a bounded diagnostic snapshot, never an execution permit.

## Status and result model

Report `schemaVersion: 1` is unchanged. Key fields are `status`, `authorization`, `platform`, `entriesChecked`, `excludedGitInternals`, `limits`, `portabilityChecked`, `findings`, `warnings` and `summary`. Category counters in `summary` are `linksAndEscapes`, `portability`, `gitMetadata`, `other`, plus `totalFindings`, `shownFindings`, `omittedFindings`.

| Condition | Outcome | CLI exit |
| --- | --- | --- |
| A recognized link or path escape was observed | `BLOCKED` | 2 |
| At least one nonblocking unresolved finding or observed coverage gap | `INCOMPLETE` | 3 |
| Otherwise clean implemented checks on non-Windows | `ADVISORY` | 0 |
| Otherwise clean Windows scan | `INCOMPLETE` because native tag coverage is unverified | 3 |
| Invalid CLI syntax or unexpected scan-level failure | No report status guaranteed | 64 |

For reporting budgets, `--max-findings` limits the stored/displayed finding list but continues scanning within entry/depth budgets. A recognized blocked finding changes `status` even when a list is full; the implementation retains one visible blocking finding. A positive `omittedFindings` also adds `FINDINGS_TRUNCATED`. The pending work stack and optional per-directory folded-name map still use memory: **bounded enumeration does not imply constant memory**.

The following warning strings explicitly convey limitations: `SNAPSHOT_ONLY`, `NOT_AN_EXECUTION_AUTHORIZATION`, `TOCTOU_NOT_PREVENTED`, and on Windows `WINDOWS_REPARSE_TAG_COVERAGE_UNVERIFIED`. Other warnings describe omitted top-level Git internals or truncated output.

## Threats, mitigations and residual risk

| Scenario | Implemented evidence | Remaining limit |
| --- | --- | --- |
| Empty/ignored/untracked junction in a workspace | Inspect actual filesystem metadata; known link -> `LINK_FOUND`, `BLOCKED` | Other Windows provider tags may not be recognized |
| Symlink at selected root or linked parent | Separate `ROOT_IS_LINK` and `ROOT_ANCESTOR_LINK` checks | Races between check and later use remain |
| Directory or file resolves outside canonical root | `realpathSync.native` and relative containment checks | Checks are not atomic; mount/provider behavior varies |
| Inaccessible or changed entry | Diagnostic finding with sanitized I/O code; `INCOMPLETE` | Some paths may disappear or change after reporting |
| Hardlinked file in scope | `MULTIPLE_HARDLINKS_UNRESOLVED` when nlink > 1 | Does not locate hardlink aliases or track contents |
| `.git` pointer file | Explicit unresolved `GITDIR_FILE_NOT_INSPECTED` | No parsing or validation of worktree target |
| Excessive tree or finding output | Entry/depth/finding budgets; truncate displayed reports | Pending stack memory, slow I/O and FS-provider behavior are not hard runtime guarantees |
| Windows filename collision | Optional portability heuristic | False positives/negatives; no cross-filesystem canonical equivalence proof |

**Known non-goals / unresolved risks:** Windows `FILE_ATTRIBUTE_REPARSE_POINT` tag-by-tag inspection, `FSCTL_GET_REPARSE_POINT`, no-follow Windows handles, descriptor-relative atomic traversal, control of other processes, Cloud/UNC providers, external mounts, cross-volume targets, symlink policy for otherwise legitimate development workspaces and full Git metadata semantics.

On Linux/macOS, a clean `ADVISORY` still means only that implemented metadata checks finished. It does not establish safety against any of the above threats.

## Privacy and operational considerations

The scanner does not intentionally read regular file bodies or send telemetry. It does inspect entry **names and metadata**, which can be sensitive; displayed path labels have length and control-character constraints but should still be treated as potentially private. Share only redacted or synthetic reports. Tests create disposable fixtures. Local OS/filesystem drivers may perform network I/O while satisfying metadata queries on cloud, UNC or mapped roots, even when the CLI has no network client.

Do not point this experimental inspector at privileged or sensitive trees without understanding platform effects. It is not a reason to relax permissions, Defender settings, network policy, symlink privileges or repository safety controls.

## Verification and evidence limits

As of 2026-10-21, the 27-case source passed GitHub Actions run `39624538818` on Node 22 and 24 under Windows/Ubuntu/macOS (six successful jobs with documented fixture SKIPs). Windows Node 24 host tests also confirmed a real NTFS junction as `BLOCKED` with no target traversal in that test. This does **not** establish native tag completeness, atomic traversal, a security certification or correctness for all host filesystems.

Any source or workflow change requires fresh verification. The preview remains experimental; before a stable/safety-sensitive release, independently review native tag/handle behavior, threats to the checking process and unresolved platform fixtures.

## Primary references

- [Node.js fs API](https://nodejs.org/api/fs.html)
- [Git worktrees](https://git-scm.com/docs/git-worktree) and [Git status](https://git-scm.com/docs/git-status)
- [Microsoft: reparse point tags](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags)
- [Microsoft: FSCTL_GET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_reparse_point)
- [Microsoft: filename naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- [MITRE CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
