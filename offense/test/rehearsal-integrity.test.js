import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runUpgradeRehearsal } from '../tools/rehearsal-runner.mjs';

// Dependency-free fixtures use real npm frozen installs and git checkouts,
// without accessing a package registry or customer credentials.
async function fixture(action) {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-check-integrity-'));
  const source = path.join(root, 'source');
  await mkdir(source);
  try {
    const script = `const fs=require('node:fs');const path=require('node:path');const assert=require('node:assert/strict');
      assert.equal(require('./lib.cjs'),7);${action}`;
    const manifest = { name: 'purple-integrity-fixture', version: '1.0.0', scripts: { test: 'node check.cjs', typecheck: 'node second.cjs' } };
    await writeFile(path.join(source, '.gitignore'), 'node_modules/\n');
    await writeFile(path.join(source, 'package.json'), JSON.stringify(manifest));
    await writeFile(path.join(source, 'package-lock.json'), JSON.stringify({ name: manifest.name, version: manifest.version,
      lockfileVersion: 3, requires: true, packages: { '': { name: manifest.name, version: manifest.version } } }));
    await writeFile(path.join(source, 'check.cjs'), script);
    await writeFile(path.join(source, 'second.cjs'), "require('node:assert/strict').equal(require('./lib.cjs'),7);\n");
    await writeFile(path.join(source, 'lib.cjs'), 'module.exports=7;\n');
    for (const args of [['init'], ['add', '.'], ['-c', 'user.name=Purple fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'fixture']]) {
      execFileSync('git', args, { cwd: source, stdio: 'pipe' });
    }
    return await runUpgradeRehearsal({ root, revision: 'a'.repeat(40), scenarios: [{ rationale: 'Exercise repository-check integrity.', changes: [] }] });
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('unchanged tracked application and test files permit baseline/candidate compatibility checks', { timeout: 60000 }, async () => {
  const result = await fixture('');
  assert.equal(result.baseline.integrityVersion, 2);
  assert.equal(result.scenarios[0].integrityVersion, 2);
  assert.equal(result.baseline.integrity, true);
  assert.deepEqual(result.baseline.changedTrackedFiles, []);
  assert.equal(result.baseline.trackedFilesChecked, 6);
  assert.equal(result.scenarios[0].status, 'tests_passed');
  assert.equal(result.scenarios[0].checks.length, 2);
  for (const command of [...result.baseline.checks, ...result.scenarios[0].checks]) {
    assert.equal(command.exitCode, 0); assert.equal(command.signal, null); assert.equal(command.truncated, false);
  }
});

test('rehearsal HOME and npm cache are private per-run directories inside the supplied work root', { timeout: 60000 }, async () => {
  const result = await fixture(`
    const home=process.env.HOME,cache=process.env.npm_config_cache;
    assert.equal(path.dirname(path.dirname(home)),path.dirname(process.cwd()));
    assert.equal(path.dirname(cache),path.dirname(home));
    assert.match(path.basename(path.dirname(home)),/^\\.purple-rehearsal-runtime-/);
    assert.equal(fs.statSync(home).mode&0o777,0o700);
    assert.equal(fs.statSync(cache).mode&0o777,0o700);
    assert.equal(process.env.OPENROUTER_API_KEY,undefined);
    assert.equal(process.env.HTTP_PROXY,undefined);
    assert.equal(process.env.NODE_EXTRA_CA_CERTS,undefined);
  `);
  assert.equal(result.scenarios[0].status, 'tests_passed');
});

test('explicit legacy isolation and proxy requests fail rather than silently running without their policy', async () => {
  const previousIsolation = process.env.PURPLE_FIX_ISOLATE_COMMANDS, previousProxy = process.env.PURPLE_FIX_EGRESS_PROXY;
  try {
    delete process.env.PURPLE_FIX_EGRESS_PROXY;
    process.env.PURPLE_FIX_ISOLATE_COMMANDS = '1';
    await assert.rejects(runUpgradeRehearsal({ root: '/nonexistent-fixture' }), /legacy repository isolation adapter is unsupported/);
    delete process.env.PURPLE_FIX_ISOLATE_COMMANDS;
    await assert.rejects(runUpgradeRehearsal({ root: '/nonexistent-fixture', repositoryIsolationPath: 'file:///nonexistent-adapter.mjs' }), /legacy repository isolation adapter is unsupported/);
    process.env.PURPLE_FIX_EGRESS_PROXY = 'http://synthetic-proxy:8080';
    await assert.rejects(runUpgradeRehearsal({ root: '/nonexistent-fixture' }), /legacy egress proxy adapter is unsupported/);
  } finally {
    if (previousIsolation === undefined) delete process.env.PURPLE_FIX_ISOLATE_COMMANDS; else process.env.PURPLE_FIX_ISOLATE_COMMANDS = previousIsolation;
    if (previousProxy === undefined) delete process.env.PURPLE_FIX_EGRESS_PROXY; else process.env.PURPLE_FIX_EGRESS_PROXY = previousProxy;
  }
});

test('a zero-exit baseline script rewriting application source blocks every candidate success claim', { timeout: 60000 }, async () => {
  const result = await fixture("if(path.basename(process.cwd())==='source')fs.writeFileSync('lib.cjs','module.exports=8;\\n');");
  assert.equal(result.baseline.checks[0].passed, true, 'The command itself exits zero.');
  assert.equal(result.baseline.integrityVersion, 2);
  assert.equal(result.baseline.integrity, false);
  assert.deepEqual(result.baseline.changedTrackedFiles, ['lib.cjs']);
  assert.equal(result.baseline.checks.length, 1, 'Do not run further checks against rewritten code.');
  assert.equal(result.scenarios[0].status, 'baseline_failed');
});

test('a candidate script rewriting tracked tests cannot report tests_passed or run the altered next check', { timeout: 60000 }, async () => {
  const result = await fixture("if(path.basename(process.cwd()).startsWith('candidate-'))fs.writeFileSync('second.cjs','process.exit(0);\\n');");
  const candidate = result.scenarios[0];
  assert.equal(result.baseline.integrity, true);
  assert.equal(result.baseline.checks.length, 2);
  assert.equal(candidate.checks[0].passed, true);
  assert.equal(candidate.integrityVersion, 2);
  assert.equal(candidate.integrity, false);
  assert.deepEqual(candidate.changedTrackedFiles, ['second.cjs']);
  assert.equal(candidate.changedTrackedFilesCount, 1);
  assert.equal(candidate.checks.length, 1);
  assert.equal(candidate.status, 'checks_failed');
});

test('deleting a tracked source path records the integrity failure rather than losing the simulation report', { timeout: 60000 }, async () => {
  const result = await fixture("if(path.basename(process.cwd()).startsWith('candidate-'))fs.unlinkSync('lib.cjs');");
  const candidate = result.scenarios[0];
  assert.equal(candidate.integrityVersion, 2);
  assert.equal(candidate.integrity, false);
  assert.deepEqual(candidate.changedTrackedFiles, ['lib.cjs']);
  assert.equal(candidate.status, 'checks_failed');
});

test('over-budget command output is explicit incomplete evidence even if the script would exit zero', { timeout: 60000 }, async () => {
  const result = await fixture("if(path.basename(process.cwd()).startsWith('candidate-'))process.stdout.write('x'.repeat(600001));");
  const candidate = result.scenarios[0], command = candidate.checks[0];
  assert.equal(result.baseline.integrity, true);
  assert.equal(command.truncated, true);
  assert.ok(command.outputBytes > 500000);
  assert.equal(command.passed, false);
  assert.notEqual(candidate.status, 'tests_passed');
});

