# Security policy — Reparse Lens
















Reparse Lens 0.1.0-dev is experimental. It is **not** a sandbox, authorization mechanism, malware scanner, complete NTFS reparse auditor, or guarantee of no network activity or writes by other processes. A clean ADVISORY result does not authorize any coding agent.
















Known limitations: incomplete Windows-native reparse-tag classification, TOCTOU and concurrent file swaps, untrusted ancestors or mounts, hardlink aliases, cloud/network filesystems, provider-specific metadata, and root .git internal exclusions. The scanner may not reliably recognize every Windows redirection and must not be used as an execution boundary.
















Do not disclose secrets, private directory names, reproduction payloads with real user data, or executable exploit chains in public issues. Send security reports privately to [akkbkk10@gmail.com](mailto:akkbkk10@gmail.com), including only a synthetic reproduction, version, OS and Node.js version. Do not send credentials or private workspace contents. If GitHub private vulnerability reporting is enabled later, it may be used as an alternative. For Git for Windows vulnerabilities follow https://github.com/git-for-windows/git/security/policy.
















Testing: current synced suite has 19 synthetic tests (Linux Node.js 22.16: 19 PASS, 0 FAIL, 0 SKIP, npm run check EXIT 0); independent native Windows reparse/junction testing is still required. A nested .git pointer regression was added on 2026-10-21. Green CI alone does not certify security.








## Additional v0.1.0-dev diagnostic features
Optional --portable checks Windows filename hazards and case collisions; doctor reports platform/Node coverage. No IO security guarantee arises from these commands. Git linked-worktree .git files are NOT parsed, and remain INCOMPLETE. A successful Linux scan is not a sandbox authorization.


## Finding output limits
The optional --max-findings option limits emitted finding objects, but scanning and grouped summary counts continue until scan-entry/depth limits apply. A detected link remains BLOCKED even if its individual finding is not displayed. A nonzero summary.omittedFindings adds FINDINGS_TRUNCATED. This is a bounded reporting feature, not an authorization decision.
