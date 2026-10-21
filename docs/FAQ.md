# Reparse Lens — Developer FAQ


**Status: 0.1.0-dev, experimental and advisory only.** Reparse Lens does not authorize a coding agent, grant filesystem permissions, sandbox a process, fix Git, or certify the safety of a workspace.


## I see BLOCKED, but this link is legitimate. Is it an attack?


Not necessarily. Reparse Lens currently reports detectable symlinks/junctions conservatively, including internal monorepo links such as `node_modules/my-workspace-package`. It does not follow the target while enumerating. Review the link and the consumer's trust policy separately. A future version may classify internal, external and unknown targets without automatically granting access.


## My Windows tree has no findings. Why INCOMPLETE / exit 3?


Windows has many NTFS reparse tag types. This Node.js-only version cannot prove complete native tag inspection, so even a clean Windows scan remains INCOMPLETE. An observed junction still yields BLOCKED / exit 2. Do not treat INCOMPLETE as a tool crash or authorization.


## Why is my .git file reported?


Git worktrees and submodules can contain a legitimate `.git` *file* redirecting to Git metadata elsewhere. Reparse Lens deliberately does not read or validate that pointer; it reports `GITDIR_FILE_NOT_INSPECTED` and INCOMPLETE. Root `.git` directory internals are excluded by default with a warning, and nested `.git` directories are traversed.


## Are Windows filename reports security findings?


No. `--portable` reports potential portability conflicts: reserved Windows names, trailing dots/spaces, forbidden characters and possible case-folding collisions. These signals are heuristic and can be false positives. In JSON v1 they still affect INCOMPLETE; a future version may separate portability and scan-coverage statuses.


## Does the scanner read source code or connect to a server?


The `scan` and `doctor` commands do not intentionally read file bodies, invoke Git or coding agents, execute subprocesses, send telemetry or perform network requests. The test suite writes and removes synthetic fixtures. Do not mistake this design goal for an OS-enforced guarantee against other processes or TOCTOU changes.


## Can I scan a large repo without producing massive CI logs?


Use:


```sh
node src/cli.mjs scan . --json --max-entries 30000 --max-depth 64 --max-findings 100
```


The scanner keeps the scan-entry and depth budgets separate from the displayed-finding budget. The JSON `summary` reports totals across grouped categories, including `omittedFindings`. When the displayed list is truncated, `FINDINGS_TRUNCATED` is present. A recognized link remains BLOCKED even if its individual finding was omitted.


## How do exit codes work?


| Exit | Meaning |
|---|---|
| 0 | ADVISORY: implemented checks completed; NEVER security approval |
| 2 | BLOCKED: detectable link or path escape |
| 3 | INCOMPLETE: information or coverage gap, including an otherwise clean Windows scan |
| 64 | Invalid invocation |


## How do I install without npm or admin access?


Download a release/source ZIP once available, extract it, install an existing Node.js 22+ runtime if needed, and run `node src/cli.mjs --help` and `node src/cli.mjs scan <folder>`. No `npm install` is necessary to use the current source CLI.


## How do I send a useful bug report?


Use a fresh synthetic directory tree, state the OS and filesystem type, Node.js version, `doctor --json` result, command, observed exit code and expected result. Strip personal directory names, secrets and workspace contents. For potentially exploitable vulnerabilities, follow SECURITY.md and private reporting rather than posting sensitive exploit steps publicly.


## What is still missing before stable release?


Native Windows reparse-tag testing, actual Windows/macOS GitHub CI evidence, ZIP usability checks, independent security review, and real user feedback. No public GitHub/npm release has yet been verified by this documentation.