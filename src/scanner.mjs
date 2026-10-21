// SPDX-License-Identifier: MPL-2.0
// Advisory workspace filesystem scanner. NOT a sandbox or access-control gate.
import { lstatSync, opendirSync, realpathSync } from 'node:fs';
import { resolve, relative, isAbsolute, parse, sep } from 'node:path';


const DEFAULTS = Object.freeze({ maxEntries: 30000, maxDepth: 64, maxFindings: 1000 });
const BLOCKING_CODES = new Set([
  'ROOT_IS_LINK', 'ROOT_ANCESTOR_LINK', 'LINK_FOUND', 'DIRECTORY_ESCAPE',
  'FILE_ESCAPE', 'DIRECTORY_CHANGED_OR_ESCAPED'
]);
const PORTABILITY_CODES = new Set(['WINDOWS_NAME_NOT_PORTABLE', 'WINDOWS_NAME_COLLISION_POSSIBLE']);
function findingCategory(code) {
  if (BLOCKING_CODES.has(code)) return 'linksAndEscapes';
  if (PORTABILITY_CODES.has(code)) return 'portability';
  if (code === 'GITDIR_FILE_NOT_INSPECTED') return 'gitMetadata';
  return 'other';
}
const WINDOWS_RESERVED = /^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i;
/** Portability diagnostics are compatibility hints, NOT claims of a security exploit. */
function windowsNameIssues(name) {
  const issues = [];
  if (/[<>:"/\\|?*\u0000-\u001f]/u.test(name) || WINDOWS_RESERVED.test(name) || /[. ]$/u.test(name))
    issues.push('WINDOWS_NAME_NOT_PORTABLE');
  return issues;
}


function inside(root, target) {
  const r = relative(root, target);
  return r === '' || (r !== '..' && !r.startsWith('..' + sep) && !isAbsolute(r));
}
function label(parts) {
  return parts.join('/').replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, 500);
}
function errorCode(error) {
  const code = error && typeof error.code === 'string' ? error.code : 'UNKNOWN';
  return /^(EACCES|EPERM|ENOENT|ELOOP|ENOTDIR|EIO|EBUSY|EMFILE|ENFILE)$/.test(code) ? code : 'UNKNOWN_IO_ERROR';
}
function validLimit(value, fallback, maximum) {
  const n = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(n) || n < 1 || n > maximum) throw new TypeError('INVALID_SCAN_LIMIT');
  return n;
}


/**
 * Scan a selected folder without reading file contents, executing programs,
 * writing files, following known links, or making network requests.
 * Result is evidence about one moment in time, NEVER execution authorization.
 */
export function scanWorkspace(selectedRoot, options = {}) {
  const maxEntries = validLimit(options.maxEntries, DEFAULTS.maxEntries, 1000000);
  const maxFindings = validLimit(options.maxFindings, DEFAULTS.maxFindings, 100000);
  if (options.portable !== undefined && typeof options.portable !== 'boolean') throw new TypeError('INVALID_PORTABLE_OPTION');
  const portable = options.portable === true;
  const maxDepth = validLimit(options.maxDepth, DEFAULTS.maxDepth, 256);
  if (typeof selectedRoot !== 'string' || !selectedRoot.trim()) throw new TypeError('ROOT_REQUIRED');
  const findings = [];
  let omittedFindings = 0;
  let blockedObserved = false;
  let displayedBlocked = false;
  const findingCounts = { linksAndEscapes: 0, portability: 0, gitMetadata: 0, other: 0 };
  function recordFinding(finding) {
    findingCounts[findingCategory(finding.code)] += 1;
    if (BLOCKING_CODES.has(finding.code)) blockedObserved = true;
    if (findings.length < maxFindings) {
      findings.push(finding);
      if (BLOCKING_CODES.has(finding.code)) displayedBlocked = true;
    } else {
      // Preserve one observed blocking path, even if earlier warnings filled the report.
      if (BLOCKING_CODES.has(finding.code) && !displayedBlocked) {
        findings[0] = finding;
        displayedBlocked = true;
      }
      omittedFindings += 1;
    }
  }
  const warnings = ['SNAPSHOT_ONLY', 'NOT_AN_EXECUTION_AUTHORIZATION', 'TOCTOU_NOT_PREVENTED'];
  let checkedEntries = 0;
  let excludedGitInternals = 0;
  let canonicalRoot;
  try {
    // Reject redirected ancestors before treating a path as the selected root.
    // This is a metadata snapshot and does not eliminate concurrent changes.
    const requested = resolve(selectedRoot);
    const volume = parse(requested).root;
    let ancestor = volume;
    const parts = relative(volume, requested).split(sep).filter(Boolean);
    for (const part of parts) {
      ancestor = resolve(ancestor, part);
      if (lstatSync(ancestor).isSymbolicLink()) {
        recordFinding({ code: 'ROOT_ANCESTOR_LINK', path: '.' });
        return report();
      }
    }
    const rootEntry = lstatSync(requested);
    if (rootEntry.isSymbolicLink()) {
      recordFinding({ code: 'ROOT_IS_LINK', path: '.' });
      return report();
    }
    if (!rootEntry.isDirectory()) throw new TypeError('ROOT_NOT_DIRECTORY');
    canonicalRoot = realpathSync.native(resolve(selectedRoot));
  } catch (e) {
    recordFinding({ code: 'ROOT_UNAVAILABLE', path: '.', detail: errorCode(e) });
    return report();
  }


  const pending = [{ absolute: canonicalRoot, parts: [], depth: 0 }];
  while (pending.length) {
    const current = pending.pop();
    let dir;
    try {
      // Recheck immediately before enumeration; still not atomic against races.
      const currentStat = lstatSync(current.absolute);
      if (currentStat.isSymbolicLink() || !currentStat.isDirectory() ||
          !inside(canonicalRoot, realpathSync.native(current.absolute))) {
        recordFinding({ code: 'DIRECTORY_CHANGED_OR_ESCAPED', path: label(current.parts) || '.' });
        continue;
      }
      // Incremental enumeration avoids unbounded allocation before limits apply.
      dir = opendirSync(current.absolute);
      const foldedNames = portable ? new Map() : null;
      let entry;
      while ((entry = dir.readSync()) !== null) {
        const parts = [...current.parts, entry.name];
        const shown = label(parts);
        checkedEntries += 1;
        if (checkedEntries > maxEntries) {
          recordFinding({ code: 'SCAN_ENTRY_LIMIT', path: shown });
          pending.length = 0;
          break;
        }
        if (portable) {
          for (const code of windowsNameIssues(entry.name)) recordFinding({ code, path: shown });
          const folded = entry.name.normalize('NFC').toUpperCase();
          const previous = foldedNames.get(folded);
          if (previous !== undefined && previous !== entry.name) {
            recordFinding({ code: 'WINDOWS_NAME_COLLISION_POSSIBLE', path: shown });
          } else foldedNames.set(folded, entry.name);
        }
        const absolute = resolve(current.absolute, entry.name);
        try {
          const stat = lstatSync(absolute);
          if (stat.isSymbolicLink() || entry.isSymbolicLink()) {
            recordFinding({ code: 'LINK_FOUND', path: shown });
            continue;
          }
          if (stat.isDirectory()) {
            const resolved = realpathSync.native(absolute);
            if (!inside(canonicalRoot, resolved)) {
              recordFinding({ code: 'DIRECTORY_ESCAPE', path: shown });
              continue;
            }
            if (parts.length === 1 && entry.name === '.git') {
              excludedGitInternals += 1;
              continue;
            }
            if (current.depth + 1 > maxDepth) {
              recordFinding({ code: 'SCAN_DEPTH_LIMIT', path: shown });
              continue;
            }
            pending.push({ absolute, parts, depth: current.depth + 1 });
            continue;
          }
          if (stat.isFile()) {
            // Linked Git worktrees use a .git file pointing to metadata elsewhere.
            // Its contents are deliberately not read by this metadata-only scanner.
            if (entry.name === '.git') {
              recordFinding({ code: 'GITDIR_FILE_NOT_INSPECTED', path: shown });
            }
            if (!inside(canonicalRoot, realpathSync.native(absolute))) {
              recordFinding({ code: 'FILE_ESCAPE', path: shown });
            } else if (stat.nlink > 1) {
              recordFinding({ code: 'MULTIPLE_HARDLINKS_UNRESOLVED', path: shown });
            }
            continue;
          }
          recordFinding({ code: 'UNSUPPORTED_ENTRY_TYPE', path: shown });
        } catch (e) {
          recordFinding({ code: 'ENTRY_CHANGED_OR_UNREADABLE', path: shown, detail: errorCode(e) });
        }
      }
    } catch (e) {
      recordFinding({ code: 'UNREADABLE_DIRECTORY', path: label(current.parts) || '.', detail: errorCode(e) });
    } finally {
      if (dir) {
        try { dir.closeSync(); } catch (e) {
          recordFinding({ code: 'DIRECTORY_CLOSE_FAILED', path: label(current.parts) || '.', detail: errorCode(e) });
        }
      }
    }
  }
  return report();


  function report() {
    const hasBlocked = blockedObserved;
    // Built-in Node metadata does not establish coverage of all NTFS reparse tags.
    if (process.platform === 'win32') warnings.push('WINDOWS_REPARSE_TAG_COVERAGE_UNVERIFIED');
    if (excludedGitInternals) warnings.push('ROOT_GIT_INTERNALS_NOT_SCANNED');
    if (omittedFindings) warnings.push('FINDINGS_TRUNCATED');
    const status = hasBlocked ? 'BLOCKED' : (findings.length || omittedFindings || process.platform === 'win32' ? 'INCOMPLETE' : 'ADVISORY');
    return {
      schemaVersion: 1, status, authorization: false, platform: process.platform,
      entriesChecked: checkedEntries, excludedGitInternals,
      limits: { maxEntries, maxDepth, maxFindings }, portabilityChecked: portable,
      summary: { ...findingCounts, totalFindings: findings.length + omittedFindings,
        shownFindings: findings.length, omittedFindings }, findings, warnings
    };
  }
}