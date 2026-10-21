# Contributing — Reparse Lens








The project is a small advisory scanner, not a sandbox. We welcome reproducible, non-sensitive bug reports and small contributions after the public repository is opened. Follow the security disclosure instructions in SECURITY.md for vulnerabilities.


General project questions and contribution coordination: [akkbkk10@gmail.com](mailto:akkbkk10@gmail.com). Use the private security-reporting route in SECURITY.md for vulnerabilities.








## Development








Use an official Node.js 22 or 24 runtime. No runtime dependencies or package installation are needed. Run `npm test` and `npm run check`. Keep all tests synthetic: create fixtures only in the project's dedicated temporary test folders and check that teardown never traverses symlink targets.








## Patch guidelines








- Keep scanning metadata-only and offline; no Git execution, agent invocation, file-body reads, networking or silent configuration changes.
- Reject or mark INCOMPLETE for unreadable entries, unknown native reparse behavior, hardlinks and exhausted scan budgets.
- Do not claim an OS sandbox or full TOCTOU protection; Windows-native proof must be separate.
- Include a failing regression fixture and exact expected exit code. If the test needs privileges, document its SKIP/UNKNOWN state; do not silently claim PASS.
- Avoid new dependencies unless the problem and supply-chain impact are evaluated.
- Source under MPL-2.0. Preserve authorship notices and license text. Never contribute code copied from unrelated private projects.








## Security / review








Do not open public issues exposing user data, credentials, private paths or exploit details. Independent review and Windows acceptance are required before calling a version stable.




## Updated local checks
Run `node src/cli.mjs doctor --json`, `node src/cli.mjs scan . --portable --json`, `npm test`, and `npm run check`. On Linux the synchronized 19-case suite passed; Windows-specific SKIP/UNKNOWN outcomes must be reported explicitly and never called full security approval. Avoid exposing internal project paths or private directories in bug reports.
