// SPDX-License-Identifier: MPL-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, linkSync, readdirSync, realpathSync, readFileSync
} from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { scanWorkspace } from '../src/scanner.mjs';

const testParent = dirname(fileURLToPath(import.meta.url));
function withFixture(work) {
  const base = mkdtempSync(join(realpathSync.native(tmpdir()), 'reparse-lens-fixture-'));
  const root = join(base, 'repo');
  mkdirSync(root);
  try { return work(root, base); }
  finally { rmSync(base, { recursive: true, force: true }); }
}
const cleanStatus = process.platform === 'win32' ? 'INCOMPLETE' : 'ADVISORY';

test('clean tree is advisory, not authorization', () => withFixture(root => {
  mkdirSync(join(root, 'empty'));
  writeFileSync(join(root, 'safe.txt'), 'fixture');
  const r = scanWorkspace(root);
  assert.equal(r.status, cleanStatus);
  assert.equal(r.authorization, false);
  assert.deepEqual(r.findings, []);
  assert.ok(r.entriesChecked >= 2);
}));

test('hidden ignored empty directory still consumes scan budget', () => withFixture(root => {
  mkdirSync(join(root, '.hidden'));
  mkdirSync(join(root, '.hidden', 'empty'));
  const r = scanWorkspace(root, { maxEntries: 1 });
  assert.equal(r.status, 'INCOMPLETE');
  assert.ok(r.findings.some(f => f.code === 'SCAN_ENTRY_LIMIT'));
  assert.equal(r.entriesChecked, 1);
  assert.equal(r.scanComplete, false);
  assert.equal(r.scanLimit.kind, 'entries');
  assert.equal(r.scanLimit.limit, 1);
  assert.ok(r.scanLimit.nextPath);
  assert.ok(r.warnings.includes('SCAN_LIMIT_REACHED'));
}));

test('blocked result exposes incomplete scan coverage independently', t => withFixture((root, base) => {
  const outside = join(base, 'outside');
  mkdirSync(outside);
  try {
    for (const name of ['00-link', '01-link'])
      symlinkSync(outside, join(root, name), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('Host cannot create a link fixture; combined budget coverage remains open');
      return;
    }
    throw e;
  }
  const r = scanWorkspace(root, { maxEntries: 1 });
  assert.equal(r.status, 'BLOCKED');
  assert.equal(r.entriesChecked, 1);
  assert.equal(r.scanComplete, false);
  assert.deepEqual(r.scanLimit.kind, 'entries');
  assert.equal(r.scanLimit.limit, 1);
  assert.ok(r.scanLimit.nextPath);
  assert.ok(r.warnings.includes('SCAN_LIMIT_REACHED'));
  assert.ok(r.findings.some(f => f.code === 'LINK_FOUND'));
  assert.equal(r.authorization, false);
}));

test('depth ceiling never produces a clean result', () => withFixture(root => {
  mkdirSync(join(root, 'deep'));
  mkdirSync(join(root, 'deep', 'deeper'));
  const r = scanWorkspace(root, { maxDepth: 1 });
  assert.equal(r.status, 'INCOMPLETE');
  assert.ok(r.findings.some(f => f.code === 'SCAN_DEPTH_LIMIT'));
}));

test('only root .git internals are excluded, with warning', () => withFixture(root => {
  mkdirSync(join(root, '.git'));
  mkdirSync(join(root, '.git', 'objects'));
  mkdirSync(join(root, 'nested'));
  mkdirSync(join(root, 'nested', '.git'));
  writeFileSync(join(root, 'nested', '.git', 'file'), 'fixture');
  const r = scanWorkspace(root);
  assert.equal(r.excludedGitInternals, 1);
  assert.ok(r.entriesChecked >= 4);
  assert.ok(r.warnings.includes('ROOT_GIT_INTERNALS_NOT_SCANNED'));
}));

test('hardlink aliases are unresolved, never silently accepted', t => withFixture(root => {
  writeFileSync(join(root, 'a.txt'), 'data');
  try {
    linkSync(join(root, 'a.txt'), join(root, 'b.txt'));
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('Host cannot create a hardlink fixture; hardlink coverage remains open');
      return;
    }
    throw e;
  }
  const r = scanWorkspace(root);
  assert.equal(r.status, 'INCOMPLETE');
  assert.ok(r.findings.some(f => f.code === 'MULTIPLE_HARDLINKS_UNRESOLVED'));
}));

test('invalid root and limits fail without unsafe PASS', () => withFixture(root => {
  assert.equal(scanWorkspace(join(root, 'missing')).status, 'INCOMPLETE');
  assert.throws(() => scanWorkspace(root, { maxEntries: 0 }), /INVALID_SCAN_LIMIT/);
  assert.throws(() => scanWorkspace(root, { maxDepth: 999 }), /INVALID_SCAN_LIMIT/);
}));

test('link or Windows junction is detected even if empty and untracked', t => withFixture((root, base) => {
  const outside = join(base, 'outside');
  mkdirSync(outside);
  const link = join(root, 'ignored-empty');
  try {
    symlinkSync(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('Host cannot create a link fixture; security acceptance remains open');
      return;
    }
    throw e;
  }
  const r = scanWorkspace(root);
  assert.equal(r.status, 'BLOCKED');
  assert.ok(r.findings.some(f => f.code === 'LINK_FOUND' || f.code === 'DIRECTORY_ESCAPE'));
  assert.equal(r.authorization, false);
}));

test('file content is not needed to identify risky entries', () => withFixture(root => {
  writeFileSync(join(root, 'regular-file'), 'SYNTHETIC_SECRET_DO_NOT_OUTPUT');
  const text = JSON.stringify(scanWorkspace(root));
  assert.equal(text.includes('SYNTHETIC_SECRET_DO_NOT_OUTPUT'), false);
}));

test('portable scan reports Windows reserved and trailing-dot names on POSIX', t => withFixture(root => {
  if (process.platform === 'win32') { t.skip('Windows forbids the fixture'); return; }
  writeFileSync(join(root, 'NUL.txt'), 'fixture');
  writeFileSync(join(root, 'trailing.'), 'fixture');
  const result = scanWorkspace(root, { portable: true });
  assert.equal(result.status, 'INCOMPLETE');
  assert.equal(result.portabilityChecked, true);
  assert.equal(result.findings.filter(f => f.code === 'WINDOWS_NAME_NOT_PORTABLE').length, 2);
}));

test('portable mode flags cross-platform case collisions', t => withFixture(root => {
  if (process.platform === 'win32') { t.skip('Case-sensitive Windows fixture not available'); return; }
  writeFileSync(join(root, 'Foo'), 'fixture');
  writeFileSync(join(root, 'foo'), 'fixture');
  // macOS and other hosts may use a case-insensitive filesystem.
  const names = readdirSync(root);
  if (!(names.includes('Foo') && names.includes('foo'))) {
    t.skip('Fixture filesystem does not distinguish case variants');
    return;
  }
  const result = scanWorkspace(root, { portable: true });
  assert.equal(result.status, 'INCOMPLETE');
  assert.ok(result.findings.some(f => f.code === 'WINDOWS_NAME_COLLISION_POSSIBLE'));
  assert.equal(scanWorkspace(root).status, 'ADVISORY');
}));

test('linked worktree .git pointer is disclosed as uninspected', () => withFixture(root => {
  writeFileSync(join(root, '.git'), 'gitdir: ../external');
  const result = scanWorkspace(root);
  assert.equal(result.status, 'INCOMPLETE');
  assert.ok(result.findings.some(f => f.code === 'GITDIR_FILE_NOT_INSPECTED'));
}));

test('portable option must be strictly boolean', () => withFixture(root => {
  assert.throws(() => scanWorkspace(root, { portable: 'yes' }), /INVALID_PORTABLE_OPTION/);
}));

test('CLI doctor reports transparent platform limits without scanning', () => {
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, 'doctor', '--json'], { encoding: 'utf8' });
  assert.equal(res.status, 0);
  const doctor = JSON.parse(res.stdout);
  assert.equal(doctor.authorization, false);
  assert.equal(doctor.nativeWindowsReparseTags, false);
  assert.equal(doctor.platform, process.platform);
});

test('CLI clean scan JSON and missing-root have distinct exit codes', () => withFixture(root => {
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  const clean = spawnSync(process.execPath, [cli, 'scan', root, '--portable', '--json'], { encoding: 'utf8' });
  assert.equal(clean.status, process.platform === 'win32' ? 3 : 0);
  const report = JSON.parse(clean.stdout);
  assert.equal(report.portabilityChecked, true);
  assert.equal(report.authorization, false);
  const missing = spawnSync(process.execPath, [cli, 'scan', join(root, 'missing'), '--json'], { encoding: 'utf8' });
  assert.equal(missing.status, 3);
  assert.ok(JSON.parse(missing.stdout).findings.some(f => f.code === 'ROOT_UNAVAILABLE'));
  const invalid = spawnSync(process.execPath, [cli, 'scan', root, '--bad'], { encoding: 'utf8' });
  assert.equal(invalid.status, 64);
}));

test('nested gitfile is reported as uninspected rather than silently accepted', () => withFixture(root => {
  mkdirSync(join(root, 'vendor'));
  writeFileSync(join(root, 'vendor', '.git'), 'gitdir: ../../outside');
  const report = scanWorkspace(root);
  assert.equal(report.status, 'INCOMPLETE');
  assert.ok(report.findings.some(f => f.code === 'GITDIR_FILE_NOT_INSPECTED' && f.path === 'vendor/.git'));
}));

test('bounded findings output preserves total counts and never reports advisory', () => withFixture(root => {
  for (const folder of ['alpha', 'beta', 'gamma']) {
    mkdirSync(join(root, folder));
    writeFileSync(join(root, folder, '.git'), 'gitdir: ../metadata');
  }
  const r = scanWorkspace(root, { maxFindings: 1 });
  assert.equal(r.status, 'INCOMPLETE');
  assert.equal(r.findings.length, 1);
  assert.equal(r.summary.gitMetadata, 3);
  assert.equal(r.summary.totalFindings, 3);
  assert.equal(r.summary.omittedFindings, 2);
  assert.ok(r.warnings.includes('FINDINGS_TRUNCATED'));
  assert.equal(r.authorization, false);
}));

test('link after finding-output truncation is still BLOCKED', t => withFixture((root, base) => {
  for (const folder of ['alpha', 'beta']) {
    mkdirSync(join(root, folder));
    writeFileSync(join(root, folder, '.git'), 'gitdir: ../metadata');
  }
  mkdirSync(join(base, 'outside'));
  try {
    symlinkSync(join(base, 'outside'), join(root, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('link fixture unavailable; not a Windows acceptance'); return;
    }
    throw e;
  }
  const r = scanWorkspace(root, { portable: true, maxFindings: 1 });
  assert.equal(r.status, 'BLOCKED');
  assert.equal(r.summary.linksAndEscapes, 1);
  assert.ok(r.findings.some(f => f.code === 'LINK_FOUND'), 'A blocking link remains visible');
  assert.equal(r.summary.totalFindings, 3);
  assert.equal(r.authorization, false);
}));

test('invalid maxFindings is rejected before scanning', () => withFixture(root => {
  assert.throws(() => scanWorkspace(root, { maxFindings: 0 }), /INVALID_SCAN_LIMIT/);
  assert.throws(() => scanWorkspace(root, { maxFindings: 100001 }), /INVALID_SCAN_LIMIT/);
}));

test('CLI output limit and grouped findings remain machine readable', () => withFixture(root => {
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  for (const folder of ['alpha', 'beta']) {
    mkdirSync(join(root, folder));
    writeFileSync(join(root, folder, '.git'), 'gitdir: ../metadata');
  }
  const res = spawnSync(process.execPath, [cli, 'scan', root, '--portable', '--max-findings', '1', '--json'], { encoding: 'utf8' });
  assert.equal(res.status, 3);
  const data = JSON.parse(res.stdout);
  assert.equal(data.findings.length, 1);
  assert.equal(data.summary.totalFindings, 2);
  assert.equal(data.summary.omittedFindings, 1);
  assert.ok(data.warnings.includes('FINDINGS_TRUNCATED'));
}));

test('human report separates budget coverage from BLOCKED status', t => withFixture((root, base) => {
  const outside = join(base, 'outside');
  mkdirSync(outside);
  try {
    for (const name of ['00-link', '01-link'])
      symlinkSync(outside, join(root, name), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('Host cannot create a link fixture; human coverage output remains open');
      return;
    }
    throw e;
  }
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, 'scan', root, '--max-entries', '1'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.match(res.stdout, /Scan coverage: INCOMPLETE/);
  assert.match(res.stdout, /next path not checked:/);
}));


test('CLI double-dash allows option-looking directory names, even --help', () => withFixture((root, base) => {
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  mkdirSync(join(base, '-repo'));
  mkdirSync(join(base, '--help'));
  for (const directory of ['-repo', '--help']) {
    const res = spawnSync(process.execPath, [cli, 'scan', '--json', '--', directory],
      { cwd: base, encoding: 'utf8' });
    assert.equal(res.status, process.platform === 'win32' ? 3 : 0, res.stderr);
    assert.equal(JSON.parse(res.stdout).authorization, false);
  }
  const bad = spawnSync(process.execPath, [cli, 'scan', '--', '-repo', '--json'],
    { cwd: base, encoding: 'utf8' });
  assert.equal(bad.status, 64, 'only one positional directory allowed');
}));

test('regular file selected as root yields ROOT_NOT_DIRECTORY', () => withFixture(root => {
  const regularFile = join(root, 'file.txt');
  writeFileSync(regularFile, 'fixture');
  const r = scanWorkspace(regularFile);
  assert.equal(r.status, 'INCOMPLETE');
  assert.deepEqual(r.findings.map(f => f.code), ['ROOT_NOT_DIRECTORY']);
}));

test('selected link root is ROOT_IS_LINK rather than ancestor', t => withFixture((root, base) => {
  const link = join(base, 'selected-link');
  try {
    symlinkSync(root, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('symbolic link fixtures not supported'); return;
    }
    throw e;
  }
  const r = scanWorkspace(link);
  assert.equal(r.status, 'BLOCKED');
  assert.deepEqual(r.findings.map(f => f.code), ['ROOT_IS_LINK']);
}));

test('selected path with linked ancestor reports ROOT_ANCESTOR_LINK', t => withFixture((root, base) => {
  const link = join(base, 'parent-link');
  mkdirSync(join(root, 'child'));
  try {
    symlinkSync(root, link, process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('symbolic link fixtures not supported'); return;
    }
    throw e;
  }
  const r = scanWorkspace(join(link, 'child'));
  assert.equal(r.status, 'BLOCKED');
  assert.deepEqual(r.findings.map(f => f.code), ['ROOT_ANCESTOR_LINK']);
  assert.equal(r.scanComplete, false);
  assert.equal(r.coverage.enumeration, 'not-started');
  assert.ok(r.findings[0].ancestor, 'linked ancestor location is reported');
}));

test('Windows console device names receive portability diagnostics', t => withFixture(root => {
  if (process.platform === 'win32') { t.skip('Windows disallows console device test fixture'); return; }
  writeFileSync(join(root, 'CONIN$'), 'fixture');
  writeFileSync(join(root, 'CONOUT$.txt'), 'fixture');
  const r = scanWorkspace(root, { portable: true });
  assert.equal(r.summary.portability, 2);
  assert.equal(r.status, 'INCOMPLETE');
}));

test('reported filename truncation preserves Unicode codepoints and sanitizes C1 controls', t => withFixture(root => {
  if (process.platform === 'win32') { t.skip('cross-platform long unicode fixture tested on POSIX'); return; }
  const first = 'a'.repeat(240);
  const second = 'b'.repeat(240);
  mkdirSync(join(root, first));
  mkdirSync(join(root, first, second));
  const longName = 'c'.repeat(17) + '😀' + '.';
  writeFileSync(join(root, first, second, longName), 'fixture');
  writeFileSync(join(root, 'control\u009b.'), 'fixture');
  const r = scanWorkspace(root, { portable: true });
  const f = r.findings.find(x => x.path.includes('a'.repeat(20)));
  assert.ok(f, JSON.stringify(r.findings));
  assert.ok(f.path.includes('😀'), f.path);
  assert.ok(f.path.endsWith('…'), f.path);
  assert.ok(!/[\ud800-\udfff]/u.test(f.path.replaceAll('😀', '')));
  assert.ok(r.findings.some(x => x.path.includes('control?')));
  assert.ok(!JSON.stringify(r).includes('\u009b'));
}));

test('link target metadata classifies scope without allowing links', t => withFixture((root, base) => {
  mkdirSync(join(root, 'inside'));
  mkdirSync(join(base, 'outside'));
  try {
    symlinkSync(join(root, 'inside'), join(root, 'internal-link'), process.platform === 'win32' ? 'junction' : 'dir');
    symlinkSync(join(base, 'outside'), join(root, 'external-link'), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (e) {
    if (['EPERM', 'EACCES', 'ENOTSUP', 'EOPNOTSUPP'].includes(e?.code)) {
      t.skip('Host does not support synthetic links'); return;
    }
    throw e;
  }
  const report = scanWorkspace(root);
  assert.equal(report.status, 'BLOCKED');
  assert.equal(report.authorization, false);
  assert.equal(report.coverage.enumeration, 'complete');
  assert.equal(report.findings.find(f => f.path === 'internal-link')?.scope, 'internal');
  assert.equal(report.findings.find(f => f.path === 'external-link')?.scope, 'external');
}));

test('bidi-control path labels are sanitized', t => withFixture(root => {
  if (process.platform === 'win32') { t.skip('Fixture name not portable to Windows'); return; }
  writeFileSync(join(root, 'rtl\u200f.'), 'fixture');
  writeFileSync(join(root, 'arabic\u061c.'), 'fixture');
  const report = scanWorkspace(root, { portable: true });
  assert.ok(report.findings.some(f => f.path === 'rtl?.'));
  assert.ok(report.findings.some(f => f.path === 'arabic?.'));
  assert.doesNotMatch(JSON.stringify(report), /[\u200e\u200f\u061c]/u);
}));

test('CLI version is read from package.json', () => {
  const manifest = JSON.parse(readFileSync(join(testParent, '..', 'package.json'), 'utf8'));
  const res = spawnSync(process.execPath, [join(testParent, '..', 'src', 'cli.mjs'), '--version'], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.trim(), manifest.version);
});

test('coverage distinguishes enumeration from Windows tag checks', () => withFixture(root => {
  const report = scanWorkspace(root);
  assert.equal(report.coverage.enumeration, 'complete');
  assert.equal(report.coverage.windowsNativeReparseTags,
    process.platform === 'win32' ? 'unverified' : 'not-applicable');
  assert.equal(report.authorization, false);
  assert.equal(report.status, process.platform === 'win32' ? 'INCOMPLETE' : 'ADVISORY');
}));

test('unavailable roots never count as fully enumerated', () => withFixture(root => {
  const report = scanWorkspace(join(root, 'missing'));
  assert.equal(report.scanComplete, false);
  assert.equal(report.coverage.enumeration, 'not-started');
  assert.equal(report.status, 'INCOMPLETE');
}));

test('out-of-range CLI scan option remains usage error 64', () => {
  const cli = join(testParent, '..', 'src', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, 'scan', '.', '--max-entries', '1000001'], { encoding: 'utf8' });
  assert.equal(res.status, 64, res.stderr);
});

