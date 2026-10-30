// Operator-only synthetic fixture. No credentials, models, network or customer data.
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { verifyPatch } from './verify-patch.mjs';
const exec = promisify(execFile), root = await mkdtemp(path.join(tmpdir(), 'purple-gate-fixture-'));
const observer = fileURLToPath(new URL('./test-observer.mjs', import.meta.url));
const contract = { confirmed: true, summary: 'Tenant ownership check.', testPaths: ['test/security.test.mjs'], normal: ['npm', 'test'],
  securityTests: [{ file: 'test/security.test.mjs', name: 'cross-tenant read is forbidden', invariant: 'A tenant cannot read documents belonging to another tenant.', operator: 'strictEqual', expected: 403, vulnerableActual: 200 }] };
const security = "import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/access.mjs';test('cross-tenant read is forbidden',()=>assert.equal(read('beta','alpha'),403));";
const reports = [];
try {
  for (const mode of ['valid', 'import_error', 'wrong_assertion', 'baseline_normal_failure', 'patched_normal_failure', 'skipped', 'crash']) {
    const baseline = path.join(root, mode, 'baseline'), candidate = path.join(root, mode, 'candidate');
    await mkdir(path.join(baseline, 'src'), { recursive: true }); await mkdir(path.join(baseline, 'test'));
    await writeFile(path.join(baseline, 'package.json'), JSON.stringify({ type: 'module', scripts: { test: 'node --test test/normal.test.mjs' } }));
    await writeFile(path.join(baseline, 'src/access.mjs'), 'export const read=(a,b)=>200;');
    await writeFile(path.join(baseline, 'test/normal.test.mjs'), `import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/access.mjs';test('owner read works',()=>assert.equal(read('alpha','alpha'),${mode === 'baseline_normal_failure' ? 999 : 200}));`);
    const git = args => exec('git', args, { cwd: baseline });
    await git(['init', '-q']); await git(['add', '.']); await git(['-c', 'user.name=Purple Fixture', '-c', 'user.email=fixture@purple.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'baseline']);
    await git(['clone', '-q', '--no-hardlinks', baseline, candidate]);
    await writeFile(path.join(candidate, 'src/access.mjs'), mode === 'patched_normal_failure' ? 'export const read=(a,b)=>403;' : 'export const read=(a,b)=>a===b?200:403;');
    const code = mode === 'import_error' ? "import './missing.mjs';" : mode === 'skipped' ? "import{test}from'node:test';test('cross-tenant read is forbidden',{skip:true},()=>{});" : mode === 'crash' ? 'process.exit(1);' : security;
    await writeFile(path.join(candidate, 'test/security.test.mjs'), code);
    await exec('git', ['add', '-N', '.'], { cwd: candidate });
    async function command(directory, args) {
      try { const result = await exec(args[0], args.slice(1), { cwd: directory, env: { PATH: process.env.PATH, HOME: root }, timeout: 8000, maxBuffer: 128000 }); return { code: 0, passed: true, stdout: result.stdout }; }
      catch (error) { return { code: typeof error.code === 'number' ? error.code : null, passed: false, timedOut: Boolean(error.killed), signal: error.signal }; }
    }
    const plan = mode === 'wrong_assertion' ? { ...contract, securityTests: [{ ...contract.securityTests[0], vulnerableActual: 500 }] } : contract;
    const result = await verifyPatch({ baseline, candidate, plan, command, observer });
    if (result.verified !== (mode === 'valid')) throw new Error(`Verification gate self-test failed: ${mode}`);
    reports.push({ case: mode, verified: result.verified, blocker: result.blocker || null,
      ...(mode === 'valid' ? { baselineNormal: result.baselineNormal.summary.passed, baselineFailure: result.baselineReproduction.classification,
        patchedSecurity: result.patchedReproduction.summary.passed, patchedNormal: result.patchedNormal.summary.passed } : {}) });
  }
  console.log(JSON.stringify({ passed: true, gateVersion: 2, syntheticOnly: true, cases: reports }));
} finally { await rm(root, { recursive: true, force: true }); }
