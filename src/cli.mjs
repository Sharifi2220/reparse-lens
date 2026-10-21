#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Advisory workspace scanner. This is not an authorization boundary.
import { scanWorkspace } from './scanner.mjs';

const VERSION = '0.1.0-dev';
const HELP = [
  'Reparse Lens ' + VERSION,
  '',
  'Usage:',
  '  reparse-lens scan [directory] [--json] [--portable] [--max-entries N] [--max-depth N] [--max-findings N]',
  '  reparse-lens scan -- <directory-starting-with-a-hyphen>',
  '  reparse-lens --help',
  '  reparse-lens --version',
  '  reparse-lens doctor [--json]',
  '',
  'Examples:',
  '  node src/cli.mjs scan .',
  '  node src/cli.mjs scan "C:\\Projects\\my-app" --json',
  '  node src/cli.mjs scan -- -my-project',
  '',
  'Exit codes:',
  '  0  ADVISORY: checks completed, NOT a security approval',
  '  2  BLOCKED: link or escape detected',
  '  3  INCOMPLETE: coverage could not be established',
  '  64 invalid command',
  '',
  'Findings are grouped in the JSON summary. --max-findings limits output size.',
  '',
  'Portable mode checks Windows reserved names and possible case collisions.',
  'No Git or coding agent is executed.',
  ''
].join('\n');

function parseArgs(argv) {
  if (argv.length === 0 || (argv.length === 1 && ['--help','-h','help'].includes(argv[0])))
    return { action: 'help' };
  if (argv.length === 1 && ['--version','-V','version'].includes(argv[0]))
    return { action: 'version' };
  if (argv[0] === 'doctor') {
    if (argv.length > 2 || (argv.length === 2 && argv[1] !== '--json')) throw new TypeError('USAGE: doctor [--json]');
    return { action: 'doctor', json: argv[1] === '--json' };
  }
  if (argv[0] !== 'scan') throw new TypeError('Unknown command. Run reparse-lens --help.');
  let directory;
  let json = false;
  const options = {};
  let optionsEnded = false;
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (!optionsEnded && arg === '--') {
      optionsEnded = true;
      continue;
    }
    if (!optionsEnded && (arg === '--help' || arg === '-h')) return { action: 'help' };
    if (!optionsEnded && arg === '--portable') {
      if (options.portable) throw new TypeError('--portable specified twice');
      options.portable = true;
    } else if (!optionsEnded && arg === '--json') {
      if (json) throw new TypeError('--json specified twice');
      json = true;
    } else if (!optionsEnded && (arg === '--max-entries' || arg === '--max-depth' || arg === '--max-findings')) {
      const raw = argv[++i];
      if (!raw || !/^[1-9]\d*$/.test(raw)) throw new TypeError('Positive integer required for ' + arg);
      const key = arg === '--max-entries' ? 'maxEntries' : arg === '--max-depth' ? 'maxDepth' : 'maxFindings';
      if (options[key] !== undefined) throw new TypeError(arg + ' specified twice');
      options[key] = Number(raw);
    } else if (!optionsEnded && arg.startsWith('-')) {
      throw new TypeError('Unknown option: ' + arg);
    } else if (directory !== undefined) {
      throw new TypeError('Only one directory can be scanned');
    } else {
      directory = arg;
    }
  }
  return { action: 'scan', directory: directory || '.', options, json };
}

function humanReport(report) {
  const lines = [
    'Reparse Lens — ' + report.status,
    'Checked: ' + report.entriesChecked + ' entries on ' + report.platform,
    'Findings: ' + report.summary.linksAndEscapes + ' links/escapes, ' +
      report.summary.portability + ' portability, ' + report.summary.gitMetadata +
      ' git metadata, ' + report.summary.other + ' other'
  ];
  if (!report.findings.length) lines.push('No links or escapes detected by the checks performed.');
  else for (const f of report.findings)
    lines.push('  ' + f.code + ': ' + f.path + (f.detail ? ' (' + f.detail + ')' : ''));
  if (report.summary.omittedFindings)
    lines.push('Output limited: ' + report.summary.omittedFindings + ' additional findings not listed.');
  if (report.status === 'BLOCKED')
    lines.push('Action: inspect the listed paths. A link or path escape was detected.');
  if (report.status === 'INCOMPLETE')
    lines.push('Action: review warnings and failures; the scan cannot establish full coverage.');
  if (report.status === 'INCOMPLETE' && report.platform === 'win32' &&
      report.warnings.includes('WINDOWS_REPARSE_TAG_COVERAGE_UNVERIFIED'))
    lines.push('Windows note: INCOMPLETE is expected even for a clean tree until native reparse-tag coverage is verified.');
  if (report.warnings.length) lines.push('Limitations: ' + report.warnings.join(', '));
  lines.push('Not an access-control decision. Does not authorize any agent to read, write, or execute.');
  return lines.join('\n') + '\n';
}

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.action === 'help') process.stdout.write(HELP);
  else if (args.action === 'version') process.stdout.write(VERSION + '\n');
  else if (args.action === 'doctor') {
    const diagnostic = { version: VERSION, node: process.versions.node, platform: process.platform,
      scanKind: 'advisory-metadata-only', authorization: false,
      nativeWindowsReparseTags: false, gitInvoked: false, networkInvoked: false };
    process.stdout.write(args.json ? JSON.stringify(diagnostic, null, 2) + '\n' :
      'Reparse Lens ' + VERSION + '\nNode: ' + diagnostic.node + '\nOS: ' + diagnostic.platform +
      '\nNative Windows reparse tag inspection: NOT IMPLEMENTED\nAdvisory only; no authorization.\n');
  }
  else {
    const result = scanWorkspace(args.directory, args.options);
    process.stdout.write(args.json ? JSON.stringify(result, null, 2) + '\n' : humanReport(result));
    process.exitCode = result.status === 'BLOCKED' ? 2 : result.status === 'INCOMPLETE' ? 3 : 0;
  }
} catch (e) {
  process.stderr.write('REPARSE_LENS: ' + (e instanceof TypeError ? e.message : 'Unexpected scan failure') + '\n');
  process.exitCode = 64;
}
