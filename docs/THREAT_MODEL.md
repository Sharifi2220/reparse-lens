# Threat model — Reparse Lens 0.1.0-dev








Purpose: detect observable filesystem links and metadata scope anomalies that a Git-only inventory may miss, including empty ignored Windows directory junctions. Non-goal: agent containment or permission enforcement.








Trust boundary: the selected root and OS filesystem metadata are read-only inputs; the scanner reads metadata but not file contents. It does not execute Git or other subprocesses, make requests, or change OS privileges. Findings contain relative paths, never reported target contents.








Current design: bounded incremental directory enumeration, lstat checks for recognizable links, realpath canonicalization, root ancestor validation, entry/depth budgets, hardlink alias warnings, failed-I/O reporting. Root .git internals are intentionally excluded after validating the .git entry itself; nested .git folders are scanned.








Status semantics: BLOCKED for recognized link/scope escape; INCOMPLETE when a scan cannot establish coverage (including clean Windows because native NTFS reparse-tag coverage is unverified); ADVISORY on a completed non-Windows metadata scan. All statuses carry authorization=false.








Outstanding risks: reparse points unrecognized by Node may still redirect traversal; Windows FILE_ATTRIBUTE_REPARSE_POINT and tag inspection via native Win32 is not implemented. Concurrent replacement after lstat/readdir can bypass a snapshot (TOCTOU). Hardlinks and special mounts cannot be fully mapped. Remote/cloud filesystems, inaccessible directory trees and rogue processes are not controlled.








Suggested native follow-up: independent Win32 FILE_ATTRIBUTE_REPARSE_POINT / FSCTL_GET_REPARSE_POINT probe with handles opened without following links; revalidate immediately before traversal and consider descriptor/handle-relative isolation for enforcement. Unit tests are not a substitute for actual Windows integration tests.








References:
https://git-scm.com/docs/git-status
https://nodejs.org/api/fs.html
https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_reparse_point
https://github.com/anthropics/claude-code/security/advisories/GHSA-vp62-r36r-9xqp




## Research review 2026-10-21
- Microsoft states Windows reparse tags may implement junctions, symlinks, volume mounts, cloud/other filesystem providers; Node lstat/realpath cannot establish completeness. A native Win32 tag adapter with no-follow handle semantics remains NOT IMPLEMENTED.
- Git worktree documentation explicitly permits a root .git FILE pointing to metadata elsewhere. The scanner marks GITDIR_FILE_NOT_INSPECTED and does not read its contents. This is an unresolved metadata relationship, not proof of maliciousness.
- Microsoft Windows naming rules cover reserved DOS device names, trailing period/space, forbidden characters and typical case-insensitivity. Opt-in --portable warns on these and possible case-fold collisions. These are compatibility signals, NOT exploit findings and NOT exhaustive Unicode/filesystem equivalence checks.
- Independent advisories: GHSA-vp62-r36r-9xqp (symlink sandbox issue), GHSA-5j29-h97v-84ch (write-time TOCTOU) and GHSA-7835-87q9-rgvv (Git worktree path confusion) demonstrate related risk classes; Reparse Lens does not claim to fix those bugs.
- Scan output statuses remain advisory-only; reporting Windows clean as INCOMPLETE is deliberate until independent native tag coverage exists.
References:
https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
https://git-scm.com/docs/git-worktree
https://github.com/anthropics/claude-code/security/advisories/GHSA-5j29-h97v-84ch
https://github.com/advisories/GHSA-7835-87q9-rgvv


## Bounded reporting and CI contract (0.1.0-dev)
The metadata-only scanner keeps a bounded list of findings (--max-findings, default 1000, maximum 100000). It still enumerates all entries allowed by max-entries/max-depth, maintains aggregate counts and records whether any observed finding is a link or path escape, even when the individual finding is omitted. This prevents report size growing proportionally to all anomalies.


The JSON schemaVersion remains 1. New additive summary keys: linksAndEscapes, portability, gitMetadata, other, totalFindings, shownFindings and omittedFindings. If findings are omitted, FINDINGS_TRUNCATED is added to warnings; no implicit PASS or rights are granted. A link found after output truncation remains BLOCKED, code 2. Existing status semantics are maintained for compatibility; in particular portability-only findings still produce INCOMPLETE, although they are not proof of exploitation. A future major schema may separate portability from coverage with tests and a migration note.


Windows-native reparse tag identification remains unimplemented. Do not interpret a clean report, a grouped severity count or a Git status result as a sandbox permission. Full Git metadata content and TOCTOU remain out of scope.