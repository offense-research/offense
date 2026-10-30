import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const config = path.join(root, 'agent/scan-rules.yml');
const rules = parse(readFileSync(config, 'utf8')).rules;
const legacy = [
  'purple.js.dynamic-eval', 'purple.js.shell-exec',
  'purple.python.shell-execution', 'purple.python.unsafe-deserialization',
  'purple.js.tls-verification-disabled'
];
const expectedNew = ['js', 'python'].flatMap(language =>
  ['sql-injection', 'command-injection', 'path-traversal', 'ssrf'].map(kind => `purple.${language}.request-${kind}`));

test('the curated bundle preserves original checks and keeps new detections bounded to request-to-sink flows', () => {
  const byId = new Map(rules.map(rule => [rule.id, rule]));
  assert.equal(byId.size, rules.length);
  for (const id of legacy) assert.ok(byId.has(id));
  for (const id of expectedNew) {
    const rule = byId.get(id);
    assert.ok(rule, id);
    assert.equal(rule.mode, 'taint', id);
    assert.ok(rule['pattern-sources'].length > 0, id);
    assert.ok(rule['pattern-sinks'].length > 0, id);
    assert.match(rule.metadata.coverage, /within-file analysis only/);
    assert.match(rule.metadata.remediation, /test/i);
    assert.ok(!rule.message.includes('$'), 'Raw metavariable content must not be interpolated into findings');
    assert.ok(!rule.metadata.remediation.includes('$'));
    const sanitizerText = JSON.stringify(rule['pattern-sanitizers'] || []);
    assert.ok(!/sanitize|normalize|basename|new URL|urlparse/.test(sanitizerText), 'Parsing and helper names cannot establish a security boundary');
  }
});

const image = process.env.PURPLE_OPENGREP_TEST_IMAGE;
function scan(directory, extraArgs = []) {
  const args = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '1g', '--cpus', '2',
    '--tmpfs', '/tmp:rw,exec,size=512m', '-e', 'HOME=/tmp', '-e', 'SEMGREP_SEND_METRICS=off',
    '-e', 'SEMGREP_ENABLE_VERSION_CHECK=0',
    '--mount', `type=bind,source=${config},target=/opt/purple/test-rules.yml,readonly`,
    '--mount', `type=bind,source=${directory},target=/fixtures,readonly`,
    '--entrypoint', '/usr/local/bin/opengrep', image, 'scan',
    '--config', '/opt/purple/test-rules.yml', '--taint-intrafile', '--json',
    '--disable-version-check', '--no-git-ignore', '--x-ignore-semgrepignore-files', '--disable-nosem',
    '--jobs', '2', '--timeout', '10', '--max-memory', '512', ...extraArgs, '/fixtures'];
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024 });
  assert.ifError(result.error);
  let report;
  try { report = JSON.parse(result.stdout); }
  catch { assert.fail(`Actual scanner did not return JSON (status ${result.status}): ${result.stderr.slice(-2000)}`); }
  return { report, status: result.status };
}

test('real pinned Opengrep finds request-to-sink vulnerabilities and accepts safe controls', { skip: !image }, () => {
  const directory = path.join(root, 'test/fixtures/opengrep');
  const expected = [];
  for (const file of readdirSync(directory).filter(name => name.startsWith('vulnerable.'))) {
    const lines = readFileSync(path.join(directory, file), 'utf8').split('\n');
    for (let index = 0; index < lines.length; index++) {
      const match = lines[index].match(/ruleid: (purple\.[\w.-]+)/);
      if (match) expected.push(`${match[1]}:${file}:${index + 2}`);
    }
  }
  const { report, status } = scan(directory);
  assert.equal(status, 0);
  assert.equal(report.version, '1.32.0');
  assert.deepEqual(report.errors, []);
  const actual = report.results.filter(item => /purple\.(?:js|python)\.request-/.test(item.check_id))
    .map(item => `${item.check_id.match(/purple\.(?:js|python)\.request-[\w-]+$/)[0]}:${path.basename(item.path)}:${item.start.line}`);
  assert.deepEqual([...new Set(actual)].sort(), expected.sort(), 'Every intended risk must be found, with no findings on safe controls');
  assert.ok(!report.results.some(item => path.basename(item.path).startsWith('safe.')), 'All rules must accept the safe regression controls');
  for (const id of legacy) assert.ok(report.results.some(item => item.check_id.endsWith(id)), `Original behavior retained: ${id}`);
  assert.ok(report.paths.scanned.some(file => file.endsWith('.ts')), 'TypeScript fixture must be scanned');
});

test('real Opengrep exposes invalid source as a coverage error rather than a clean result', { skip: !image }, () => {
  const { report } = scan(path.join(root, 'test/fixtures/opengrep-invalid'));
  assert.ok(report.errors.length > 0, 'The runner must receive the parser failure so it can keep the result partial');
});
