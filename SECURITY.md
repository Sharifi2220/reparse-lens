# Security policy — Reparse Lens

## Scope and supported expectations

Reparse Lens `0.1.0-preview.2` is an experimental **metadata-only advisory inspector**. It is **not** a sandbox, access-control boundary, malware detector, comprehensive NTFS reparse-tag auditor or guarantee that a directory is safe. **All reports set `authorization: false`**, even when the status is `ADVISORY`.

The source `scan` and `doctor` commands do not intentionally execute Git or coding agents, read file bodies, change scanned files or send telemetry. The tests create temporary synthetic files. Filesystem/OS providers may perform their own I/O, including network access for mapped, UNC or cloud-backed paths; this program does not enforce a network isolation policy.

## Trust and limitations

- **Windows reparse tags:** Node's `lstatSync` / `realpathSync.native` can recognize ordinary links and junctions but do not provide a verified inventory of every NTFS reparse tag. Clean Windows scans remain `INCOMPLETE` / exit 3. Recognized links yield `BLOCKED` / exit 2.
- **Time of check vs use:** Enumeration, `lstatSync` and realpath checks are not atomic. Another process can replace entries before or after checks (TOCTOU / CWE-367). Reparse Lens cannot prevent such swaps or authorize later operations.
- **Hardlinks and Git metadata:** A multi-linked file is reported without reconstructing all aliases. A `.git` file is not parsed; root `.git` directory internals are omitted with a warning. Git configuration/hooks are not executed or vetted.
- **Provider and platform differences:** Cloud placeholders, UNC/network mounts, mount points, filesystem case rules, permissions, inaccessible directories and unknown entry types can reduce coverage. `--portable` name checks are heuristics and may produce false positives.
- **Output budgets:** `--max-findings` bounds displayed findings, not scan coverage. An observed blocking link remains `BLOCKED` even when report entries are omitted. Entry/depth limits and I/O failures produce incomplete results.

Never wire `ADVISORY`, `BLOCKED` or `INCOMPLETE` directly to a coding agent's authorization decision. Never describe passing CI as a security certification.

## Verified testing (2026-10-21)

On the tested preview revision, `npm run check` and `npm test` completed with 27 test cases and no failures on the local Windows Node.js 24.15.0 host; fixture skips remain coverage gaps. A real NTFS junction was recognized as `BLOCKED` / exit 2, and a clean Windows tree stayed `INCOMPLETE` / exit 3. GitHub Actions run `39624538818` passed all six Node 22/24 jobs across Windows, Ubuntu and macOS. These results apply to the tested source revision; later documentation/code commits need their own CI check.

The four Windows SKIPs are intentionally uncreatable portability/symlink fixtures in that runner environment, **not** passing security checks. Unknown Windows-native reparse tags, TOCTOU, full remote-filesystem coverage and independent security validation remain unverified.

## Dual-use declaration

Because filesystem scope mapping may be relevant to security research, the npm preview explicitly declares `contentPolicy.class: dual-use` and ships a root [DISCLOSURE](DISCLOSURE). This declaration describes legitimate defensive uses and limitations; it is not authorization to scan third-party systems. Under npm policy, a direct publish of a declared dual-use package must enforce interactive 2FA (or use a separately approved staged-and-promoted route). No direct token-bypass/OIDC publish workflow is used. See the [npm policy](https://docs.npmjs.com/policies/dual-use/).

## Report a vulnerability privately

Send a concise report to **GitHub's private vulnerability reporting channel**. Include the version, OS/filesystem, Node.js version, command, expected/actual result, and a **synthetic** minimal reproduction. Omit real credentials, private paths, personal data and customer workspaces.

Do **not** publish sensitive exploit details or live secrets in GitHub issues. If GitHub private vulnerability reporting is enabled, it may be used as another private route. This project does not promise a response SLA or bounty.

For the machine-readable contract, see [JSON interface](docs/JSON_API.md). For source-level boundaries, see [README](README.md) and [Threat model](docs/THREAT_MODEL.md). For Git for Windows issues, see the upstream [security policy](https://github.com/git-for-windows/git/security/policy).
