# Reparse Lens




**See the filesystem paths that Git status does not show.** Reparse Lens is an offline, zero-dependency command-line inspector for Windows junctions, POSIX symlinks, hardlink ambiguity, linked Git worktree metadata, and portable filenames. Designed for developers, CI maintainers, and people using coding agents.




**Version: 0.1.0-dev — experimental, advisory only.** Not an agent sandbox, access-control layer, antivirus product, or guarantee that a workspace is safe. A clean scan never authorizes an agent to read, write, or execute.




## Five-minute quick start




Requires **Node.js 22+**. Download the repository ZIP and extract it, or clone the repo after publication. No dependencies, account, admin rights, `npm install`, or network connection are needed to run the source CLI.




**Windows PowerShell** (from the extracted `reparse-lens` folder):




```powershell
node .\src\cli.mjs doctor
node .\src\cli.mjs scan "C:\Projects\MyRepository"
node .\src\cli.mjs scan "C:\Projects\MyRepository" --json
```




**macOS / Linux:**




```sh
node ./src/cli.mjs doctor
node ./src/cli.mjs scan "$HOME/projects/my-repository"
```




**Portability audit**: report names that might conflict with normal Windows file handling (reserved names, trailing period/space, characters, possible case collisions). These are compatibility **warnings**, not proven attacks.




```sh
node ./src/cli.mjs scan . --portable
node ./src/cli.mjs scan . --portable --json
```




## Commands




| Command | Purpose |
|---|---|
| `scan [directory]` | Inspect a directory (defaults to current directory) including ignored/empty entries |
| `scan [directory] --json` | Emit machine-readable output for scripts |
| `scan [directory] --portable` | Add cross-platform Windows filename checks |
| `scan [directory] --max-entries N --max-depth N` | Change bounded scan limits |
| `scan [directory] --max-findings N` | Limit displayed findings without hiding overall counts or link-based BLOCKED results |
| `doctor [--json]` | Display runtime/feature diagnostics; does not modify files |
| `--help`, `--version` | Show built-in help and version |




The CLI name reserved in `package.json` is `reparse-lens` for a future distribution. **No npm package is published**; use `node src/cli.mjs` until a public package is independently checked and released.




## Interpreting results




| Status | Exit | Interpretation |
|---|---:|---|
| `ADVISORY` | 0 | Implemented metadata checks completed, **not a safety approval** |
| `BLOCKED` | 2 | A detectable link or workspace path escape was found |
| `INCOMPLETE` | 3 | A budget, I/O, portability or hardlink ambiguity, or unsupported check prevents coverage |
| Invalid command | 64 | Fix command syntax with `--help` |




**Windows always returns `INCOMPLETE` for an otherwise clean scan in 0.1.0-dev**, because comprehensive detection of NTFS reparse tags is not implemented. An observed Windows junction can still produce `BLOCKED`. This difference is intentional: a test of one junction type cannot prove detection of every reparse type.




Findings include links (`LINK_FOUND`), escaped canonical paths, unreadable entries, exceeded limits, `MULTIPLE_HARDLINKS_UNRESOLVED`, `GITDIR_FILE_NOT_INSPECTED`, and optional `WINDOWS_NAME_NOT_PORTABLE` / `WINDOWS_NAME_COLLISION_POSSIBLE`. A `.git` *file* can be the normal pointer of a linked Git worktree; its contents are not read, so Reparse Lens reports that it has not validated this pointer. The scanner does not assume such a file is malicious.




Root `.git` directory contents are intentionally excluded and reported. Nested `.git` directories are included in the scan. Defaults: 30,000 entries, 64 directory levels, and 1,000 displayed findings. Errors and limits never turn into a clean result.




### Handling large outputs in CI




```sh
node ./src/cli.mjs scan . --portable --max-findings 100 --json
```




`summary` reports counts grouped by `linksAndEscapes`, `portability`, `gitMetadata`, and `other`. It also reports `totalFindings`, `shownFindings`, and `omittedFindings`. When some findings cannot be displayed, `FINDINGS_TRUNCATED` is included in `warnings`, but totals and a detected link-based `BLOCKED` result remain intact. The JSON `schemaVersion: 1` and existing `status`/exit codes remain unchanged. This is an output-size control, not proof of a complete security audit. A normal in-project symlink is currently reported as `BLOCKED`; no automatic safe-link policy is implemented.




## Privacy and limitations




The `scan` and `doctor` commands use local metadata and do not intentionally read file bodies, modify the scanned directory, run Git or AI agents, or connect to the internet. The **test suite** writes and removes its own synthetic fixtures under `test/`.




Snapshot scanning cannot prevent TOCTOU swaps or writes by another process. Windows reparse tags, volume mount points, cloud placeholders, UNC/network mounts, hardlink targets and Git configuration/hook execution are not exhaustively covered. A path may change after scanning. This product must never be described or used as a permission boundary. See [SECURITY.md](SECURITY.md), [Threat model](docs/THREAT_MODEL.md) and [Developer FAQ](docs/FAQ.md).




## Developers




```sh
npm test
npm run check
npm pack --dry-run --json --ignore-scripts
```




A GitHub Actions matrix is prepared for Node 22/24 on Windows, macOS and Linux. Its results are not yet an independent Windows security certification. Windows-only fixtures that cannot be created must be reported as `SKIP`/`UNKNOWN`, not passed.




## License and sustainability


## Contact


For general project questions, bug reports and security reports, contact [akkbkk10@gmail.com](mailto:akkbkk10@gmail.com). Please send sensitive security details privately and do not include credentials, private paths or user data.




[MPL-2.0](LICENSE). Commercial use is permitted under the license terms. Sponsorship or support may be offered later; payments are not required and no passive revenue is guaranteed. The planned public product/repository name is **Reparse Lens** (`reparse-lens`), pending final npm/brand checks.




## Primary references




[Git status](https://git-scm.com/docs/git-status) · [Git worktrees](https://git-scm.com/docs/git-worktree) · [Node.js filesystem](https://nodejs.org/api/fs.html) · [Windows file names](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file) · [Windows reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-tags)
