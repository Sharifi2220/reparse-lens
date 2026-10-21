# Reparse Lens — Developer FAQ

**Current stage:** `0.1.0-preview.2`, experimental and advisory-only. A scan is a snapshot of selected metadata, **never** permission for an agent or script to operate on a workspace. See the [JSON interface reference](JSON_API.md) before integrating reports into scripts.

## What problem does it solve?

Git tracks or reports a different view from the underlying filesystem. An empty, ignored or untracked directory junction may not appear in `git status`, yet still redirect filesystem access. Reparse Lens checks filesystem metadata directly and reports recognized links, possible scope escapes and unresolved cases.

## Why does a clean Windows scan return INCOMPLETE / exit 3?

Node-based metadata checks cannot prove coverage of all native NTFS reparse tags. A clean Windows result therefore stays `INCOMPLETE`, while a recognized junction is `BLOCKED` / exit 2. This is deliberate, not an installation problem.

## Does BLOCKED mean a link is malicious?

No. The scanner conservatively reports recognized links, including legitimate monorepo workspace links inside `node_modules`. It does not automatically allow internal links or follow their targets. Review the link separately and use your own trust policy; the scanner does not grant permission.

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

The npm preview declares security-relevant dual-use functionality in `package.json` and the published root `DISCLOSURE`. This does **not** mean the package is already on npm. Direct publication requires an authorized npm session with interactive 2FA, and cannot be performed through the former token-only CI shortcut. Download the GitHub source release until the registry page is verified; after publication use `npm install -g reparse-lens@preview`.

## How do I report a bug safely?

Include OS/filesystem, Node version, command, expected status/exit, observed status/exit, and a reproducible **synthetic** tree. Remove usernames, real workspace names, tokens and private data. Use the private contact in [SECURITY.md](../SECURITY.md) for vulnerabilities.

## What has been tested, and what remains unknown?

On 2026-10-21, 27 test cases ran successfully in GitHub Actions on Node 22/24 × Windows, Ubuntu and macOS with all six jobs successful; platform fixture SKIPs remain explicit coverage gaps. A real Windows host also confirmed a recognized junction is blocked and not intentionally traversed; the release-candidate scanner, CLI and test sources were synchronized with the release branch.

Unknown: complete Windows-native reparse-tag coverage, atomic traversal/no-follow handle guarantees, unrestricted cloud/UNC cases, and an external independent security certification. These are disclosed scope limits, not claims of completed protection. See the [technical design](../README.md#technical-design), [Threat model](THREAT_MODEL.md) and [Release checklist](../RELEASE_CHECKLIST.md).

