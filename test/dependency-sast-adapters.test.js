import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runOsvScanner, freshOsvDatabase } from '../agent/osv-scanner.mjs';
import { runSemgrep } from '../agent/semgrep.mjs';
import { runScan } from '../agent/scan-runner.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'offense-adapter-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = path.join(root, 'source'), cacheDir = path.join(root, 'cache');
  await mkdir(source);
  const ecosystems = {};
  for (const name of ['npm', 'PyPI']) {
    await mkdir(path.join(cacheDir, 'osv-scalibr', name), { recursive: true });
    await writeFile(path.join(cacheDir, 'osv-scalibr', name, 'all.zip'), Buffer.alloc(1024));
    ecosystems[name] = { size: 1024, sha256: 'a'.repeat(64), source: `https://osv-vulnerabilities.storage.googleapis.com/${name}/all.zip` };
  }
  const metadata = { schemaVersion: 1, downloadedAt: new Date().toISOString(), ecosystems };
  await writeFile(path.join(cacheDir, 'metadata.json'), JSON.stringify(metadata));
  return { root, source, cacheDir, metadata };
}
const advisory = (id = 'GHSA-fixture-test-1234') => ({ id, aliases: ['CVE-2026-12345'],
  summary: 'PRIVATE_SOURCE_CANARY', details: 'PRIVATE_SOURCE_CANARY', database_specific: { severity: 'HIGH' },
  affected: [{ package: { name: 'fixture-dep', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }, { fixed: '2.0.1' }] },
    { type: 'GIT', events: [{ fixed: 'c45d7c49ea75133e52ab22a8e9e13173938e36ff' }] }] },
    { package: { name: 'different-package', ecosystem: 'npm' }, ranges: [{ events: [{ fixed: '9.9.9' }] }] }] });
function osvResponse(args, overrides = {}) {
  return { status: 1, stdout: JSON.stringify({ results: [{ source: { path: args[args.indexOf('-L') + 1] },
    packages: [{ package: { name: 'fixture-dep', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/fixture-dep@1.0.0?source=PUBLIC_REGISTRY' },
      vulnerabilities: [advisory()], groups: [{ ids: ['GHSA-fixture-test-1234'], aliases: ['CVE-2026-12345'], max_severity: '8.1' }], ...overrides }] }] }), stderr: '' };
}

test('OSV matches offline with a fixed DB, ignores uploaded config and strips report source or registry data', async t => {
  const f = await fixture(t);
  await writeFile(path.join(f.source, 'package-lock.json'), '{}');
  await writeFile(path.join(f.source, 'osv-scanner.toml'), 'PRIVATE_SOURCE_CANARY');
  let workingDirectory;
  const report = await runOsvScanner({ root: f.source, files: ['package-lock.json', 'osv-scanner.toml'], cacheDir: f.cacheDir,
    execute(binary, args, options) {
      assert.equal(binary, '/usr/local/bin/osv-scanner');
      for (const flag of ['--offline', '--no-resolve', '--all-packages', '--all-vulns', '--no-ignore']) assert.ok(args.includes(flag));
      assert.ok(!args.includes('--download-offline-databases'));
      assert.equal(args[args.indexOf('--local-db-path') + 1], f.cacheDir);
      assert.equal(options.env.GITHUB_TOKEN, undefined); assert.equal(options.env.HTTP_PROXY, undefined);
      assert.equal(options.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, f.cacheDir);
      workingDirectory = options.cwd;
      const lock = args[args.indexOf('-L') + 1];
      assert.equal(existsSync(path.join(path.dirname(lock), 'osv-scanner.toml')), false);
      assert.equal(existsSync(path.join(options.cwd, 'source')), false);
      assert.equal(readFileSync(args[args.indexOf('--config') + 1], 'utf8'), '');
      return osvResponse(args);
    } });
  assert.equal(report.status, 'complete'); assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].file, 'package-lock.json'); assert.equal(report.findings[0].line, null);
  assert.equal(report.findings[0].severity, 'HIGH');
  assert.deepEqual(report.findings[0].fixedVersions, ['1.2.3', '2.0.1']);
  assert.ok(!JSON.stringify(report).includes('9.9.9')); assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
  assert.ok(!JSON.stringify(report).includes('c45d7c49ea75133e52ab22a8e9e13173938e36ff'));
  assert.ok(!JSON.stringify(report).includes('purl')); assert.equal(existsSync(workingDirectory), false);
  assert.equal(report.findings[0].verification, 'scanner_finding');
});

test('OSV refuses stale, future, missing, resized or symlinked database metadata instead of clean findings', async t => {
  const f = await fixture(t); await writeFile(path.join(f.source, 'package-lock.json'), '{}');
  const invoke = () => runOsvScanner({ root: f.source, files: ['package-lock.json'], cacheDir: f.cacheDir,
    execute() { assert.fail('Invalid database must not execute'); } });
  await writeFile(path.join(f.cacheDir, 'metadata.json'), JSON.stringify({ ...f.metadata, downloadedAt: new Date(Date.now() - 8 * 86400000).toISOString() }));
  assert.equal((await invoke()).status, 'failed');
  await writeFile(path.join(f.cacheDir, 'metadata.json'), JSON.stringify({ ...f.metadata, downloadedAt: new Date(Date.now() + 86400000).toISOString() }));
  assert.equal((await invoke()).status, 'failed');
  await writeFile(path.join(f.cacheDir, 'metadata.json'), JSON.stringify(f.metadata));
  await writeFile(path.join(f.cacheDir, 'osv-scalibr/npm/all.zip'), 'truncated');
  assert.equal((await invoke()).status, 'failed');
  assert.equal(await freshOsvDatabase('/missing-cache'), null);
});

test('OSV reports local or private packages as incomplete, and execution or parsing failures are never clean', async t => {
  const f = await fixture(t); await writeFile(path.join(f.source, 'package-lock.json'), '{}');
  const options = { root: f.source, files: ['package-lock.json'], cacheDir: f.cacheDir };
  const local = await runOsvScanner({ ...options, execute: (_binary, args) => osvResponse(args, {
    package: { name: 'fixture-dep', version: '1.0.0', ecosystem: 'npm', purl: 'pkg:npm/fixture-dep@1.0.0?source=LOCAL' }, vulnerabilities: [], groups: [] }) });
  assert.equal(local.status, 'partial'); assert.equal(local.coverage.unscannablePackages, 1); assert.equal(local.findings.length, 0);
  for (const response of [{ status: 127, stdout: '{}' }, { status: 0, stdout: 'invalid' }, { status: 0, stdout: '{}' }, { status: 0, error: new Error('PRIVATE_SOURCE_CANARY') }]) {
    const checked = await runOsvScanner({ ...options, execute: () => response });
    assert.equal(checked.status, 'failed'); assert.ok(!JSON.stringify(checked).includes('PRIVATE_SOURCE_CANARY'));
  }
  const unsupported = await runOsvScanner({ ...options, files: ['README.md'], execute() { assert.fail('Unsupported inputs must not execute'); } });
  assert.equal(unsupported.status, 'partial');
});

test('Semgrep uses only the fixed OSS rules and isolates credentials, config, ignores and source-bearing JSON', async t => {
  const f = await fixture(t); await writeFile(path.join(f.source, 'app.py'), 'app.run(debug=True)');
  await writeFile(path.join(f.source, '.semgrepignore'), 'app.py');
  const report = await runSemgrep({ root: f.source, files: ['app.py', '.semgrepignore'], execute(binary, args, options) {
    assert.equal(binary, '/opt/purple/semgrep/bin/semgrep');
    for (const flag of ['--oss-only', '--metrics=off', '--disable-nosem', '--no-git-ignore', '--x-ignore-semgrepignore-files']) assert.ok(args.includes(flag));
    assert.equal(args[args.indexOf('--config') + 1], '/opt/purple/agent/semgrep-rules.yml');
    assert.equal(options.env.SEMGREP_APP_TOKEN, undefined); assert.equal(options.env.OTEL_SDK_DISABLED, 'true');
    assert.equal(options.env.SEMGREP_SEND_METRICS, 'off');
    assert.equal(existsSync(path.join(path.dirname(args.at(-1)), '.semgrepignore')), false);
    return { status: 0, stdout: JSON.stringify({ results: [{ check_id: 'operator.offense.python.flask-debug-enabled', path: args.at(-1),
      start: { line: 1 }, extra: { lines: 'PRIVATE_SOURCE_CANARY', message: 'PRIVATE_SOURCE_CANARY', metavars: { token: 'PRIVATE_SOURCE_CANARY' } } }], errors: [] }) };
  } });
  assert.equal(report.status, 'complete'); assert.equal(report.findings[0].ruleId, 'offense.python.flask-debug-enabled');
  assert.equal(report.findings[0].file, 'app.py'); assert.equal(report.findings[0].verification, 'scanner_finding');
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
});

test('Semgrep invalid output, coverage errors, unknown rules or out-of-scope paths cannot report clean', async t => {
  const f = await fixture(t); await writeFile(path.join(f.source, 'app.py'), 'safe = 1');
  const options = { root: f.source, files: ['app.py'] };
  for (const response of [{ status: 2, stdout: '{}' }, { status: 0, stdout: 'invalid' }, { status: 0, stdout: '{}' }])
    assert.equal((await runSemgrep({ ...options, execute: () => response })).status, 'failed');
  const partial = await runSemgrep({ ...options, execute: () => ({ status: 0, stdout: JSON.stringify({ results: [
    { check_id: 'unknown-rule', path: '/private/file.py', extra: { lines: 'PRIVATE_SOURCE_CANARY' } }], errors: [{ message: 'PRIVATE_SOURCE_CANARY' }] }) }) });
  assert.equal(partial.status, 'partial'); assert.equal(partial.findings.length, 0);
  assert.ok(!JSON.stringify(partial).includes('PRIVATE_SOURCE_CANARY'));
  assert.equal((await runSemgrep({ ...options, files: ['README.md'], execute() { assert.fail('Unsupported input should not execute'); } })).status, 'partial');
});

test('adapters reject symlinks and unsafe paths before running a scanner', async t => {
  const f = await fixture(t); await writeFile(path.join(f.root, 'outside.py'), 'PRIVATE_SOURCE_CANARY');
  await symlink(path.join(f.root, 'outside.py'), path.join(f.source, 'app.py'));
  assert.equal((await runSemgrep({ root: f.source, files: ['app.py'], execute() { assert.fail('Symlink should not execute'); } })).status, 'failed');
  await assert.rejects(runSemgrep({ root: f.source, files: ['../outside.py'] }), /bounded relative/);
  await assert.rejects(runOsvScanner({ root: f.source, files: ['../package-lock.json'] }), /bounded relative/);
});

test('shared scan runner dispatches both tools and retains fixed versions and isolated file locations', async t => {
  const f = await fixture(t);
  const report = await runScan({ tools: ['semgrep', 'osv-scanner'], files: [
    { path: 'app.py', content: 'safe = 1' }, { path: 'package-lock.json', content: '{}' }] }, {
    root: f.root, osvCacheDir: f.cacheDir, execute(binary, args) {
      if (binary.includes('semgrep')) return { status: 0, stdout: JSON.stringify({ results: [], errors: [] }) };
      assert.equal(binary, '/usr/local/bin/osv-scanner'); return osvResponse(args);
    } });
  assert.equal(report.status, 'completed'); assert.deepEqual(report.tools.map(tool => tool.name), ['semgrep', 'osv-scanner']);
  assert.equal(report.findings[0].file, 'package-lock.json'); assert.deepEqual(report.findings[0].fixedVersions, ['1.2.3', '2.0.1']);
  assert.equal(report.tools[0].coverage.profile, 'offense-additional-sast-v1');
});
