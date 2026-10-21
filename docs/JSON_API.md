# JSON interface — Reparse Lens

This document describes the machine-readable contract emitted by:

```sh
node src/cli.mjs scan <directory> --json
```

The current contract is `schemaVersion: 1`. It is designed for diagnostics and CI reporting, not for granting permission to read, execute, modify or delete anything.

## Example

An abbreviated clean report looks like this:

```json
{
  "schemaVersion": 1,
  "status": "ADVISORY",
  "authorization": false,
  "platform": "linux",
  "entriesChecked": 2,
  "excludedGitInternals": 0,
  "scanComplete": true,
  "scanLimit": null,
  "limits": {
    "maxEntries": 30000,
    "maxDepth": 64,
    "maxFindings": 1000
  },
  "portabilityChecked": false,
  "summary": {
    "linksAndEscapes": 0,
    "portability": 0,
    "gitMetadata": 0,
    "other": 0,
    "totalFindings": 0,
    "shownFindings": 0,
    "omittedFindings": 0
  },
  "findings": [],
  "warnings": []
}
```

Paths in findings are bounded, display-oriented labels relative to the selected root where possible. They are not safe to use as authorization inputs or as a promise that the same path still refers to the same object.

## Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schemaVersion` | number | JSON contract version. Current value is `1`. |
| `status` | string | `ADVISORY`, `BLOCKED` or `INCOMPLETE`. |
| `authorization` | boolean | Always `false`. This tool never authorizes a later operation. |
| `platform` | string | Node.js `process.platform`, for example `win32`, `linux` or `darwin`. |
| `entriesChecked` | number | Entries inspected within the entry budget. |
| `excludedGitInternals` | number | Root `.git` directories recognized and intentionally not enumerated. |
| `scanComplete` | boolean | Whether the directory/depth budgets completed without stopping the traversal. This does not mean the result is safe. |
| `scanLimit` | object or null | When a budget stops traversal, contains `kind` (`entries` or `depth`), `limit`, and the next `nextPath` that was not inspected. |
| `limits` | object | Effective `maxEntries`, `maxDepth` and `maxFindings` values. |
| `portabilityChecked` | boolean | Whether `--portable` heuristics were enabled. |
| `summary` | object | Category counters and finding-output counts. |
| `findings` | array | Bounded list of diagnostic finding objects. |
| `warnings` | array | Machine-readable limitations such as `FINDINGS_TRUNCATED` or unverified Windows coverage. |

## Finding objects

Every finding has a `code` and a bounded `path`. Some I/O findings also include a sanitized `detail` value containing an error code such as `ENOENT` or `EACCES`.

Common codes include:

| Code | Interpretation |
| --- | --- |
| `LINK_FOUND` | A recognized symbolic link or junction was observed. |
| `ROOT_IS_LINK` | The selected root itself is a recognized link. |
| `ROOT_ANCESTOR_LINK` | A parent component of the selected root is a recognized link. |
| `DIRECTORY_ESCAPE` / `FILE_ESCAPE` | A resolved entry is outside the canonical scan root. |
| `GITDIR_FILE_NOT_INSPECTED` | A `.git` file was found; its contents were deliberately not read. |
| `MULTIPLE_HARDLINKS_UNRESOLVED` | A regular file has more than one link; aliases were not reconstructed. |
| `WINDOWS_NAME_NOT_PORTABLE` | `--portable` found a possible Windows naming incompatibility. |
| `WINDOWS_NAME_COLLISION_POSSIBLE` | `--portable` found a case/Unicode collision heuristic. |
| `SCAN_ENTRY_LIMIT` / `SCAN_DEPTH_LIMIT` | A configured scan budget was reached. |
| `ROOT_UNAVAILABLE` / `UNREADABLE_DIRECTORY` / `ENTRY_CHANGED_OR_UNREADABLE` | Metadata could not be read consistently. |

The exact list is intentionally extensible. Consumers should handle unknown finding codes conservatively and should not assume that an unrecognized code is harmless.

## Status and process exit

| Process exit | `status` | Consumer guidance |
| ---: | --- | --- |
| `0` | `ADVISORY` | Implemented checks completed without a reported finding on a non-Windows platform. Not proof of safety. |
| `2` | `BLOCKED` | A recognized link or path escape was observed. Review before any separate operation. |
| `3` | `INCOMPLETE` | Coverage, I/O, budget, portability or metadata uncertainty remains. |
| `64` | none guaranteed | Invalid arguments or an unexpected scan-level failure. |

When `summary.omittedFindings` is positive, the displayed array is truncated and `warnings` contains `FINDINGS_TRUNCATED`. When an entry/depth budget stops traversal, `scanComplete` is `false`, `scanLimit` describes the limit and next uninspected path, and `warnings` contains `SCAN_LIMIT_REACHED`. The main `status` can still be `BLOCKED`; consumers must inspect `scanComplete` independently. A blocking observation remains reflected in `status` and is retained in the visible findings when possible.

## Integration rules

1. Parse JSON only when the process exits with a report-producing code (`0`, `2` or `3`).
2. Require `schemaVersion === 1` or route newer versions to an explicit compatibility path.
3. Treat `authorization: false` as mandatory and do not map `ADVISORY` to permission.
4. Use `status`, `warnings`, `summary` and individual `code` values for review/reporting, not as a substitute for an OS sandbox or policy engine.
5. Do not use reported paths for a later file operation without a separate, trusted validation step; metadata checks are not atomic and do not prevent TOCTOU races.
6. Preserve SKIP/INCOMPLETE evidence in CI summaries. A clean result on one host does not establish complete NTFS, cloud, UNC or mount-point coverage.

For the CLI and architecture, see the [README](../README.md). For residual risk and non-goals, see the [threat model](THREAT_MODEL.md) and [security policy](../SECURITY.md).

