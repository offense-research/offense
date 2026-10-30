import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, copyFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { verifyPatch } from '../agent/verify-patch.mjs';
import { verificationQualified } from '../agent/verification-gate.mjs';
const exec = promisify(execFile), observer = fileURLToPath(new URL('../agent/test-observer.mjs', import.meta.url));
export const plan = { confirmed: true, summary: 'Enforce tenant ownership.', testPaths: ['test/security.test.mjs'],
  securityTests: [{ file: 'test/security.test.mjs', name: 'cross-tenant read is forbidden', invariant: 'A tenant cannot read documents belonging to another tenant.', operator: 'strictEqual', expected: 403, vulnerableActual: 200 }],
  reproduction: ['node', '--test', 'test/security.test.mjs'], normal: ['npm', 'test'] };
const regression = "import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/access.mjs';test('cross-tenant read is forbidden',()=>assert.equal(read('beta','alpha'),403));";
async function fixture(t, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-gate-')); t.after(() => rm(root, { recursive: true, force: true }));
  const baseline = path.join(root, 'baseline'), candidate = path.join(root, 'candidate');
  await mkdir(path.join(baseline, 'src'), { recursive: true }); await mkdir(path.join(baseline, 'test'));
  await writeFile(path.join(baseline, 'package.json'), JSON.stringify({ type: 'module', scripts: { test: 'node --test test/normal.test.mjs' } }));
  await writeFile(path.join(baseline, 'src/access.mjs'), 'export const read=(actor,owner)=>200;');
  await writeFile(path.join(baseline, 'test/normal.test.mjs'), options.normal || "import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/access.mjs';test('owner access works',()=>assert.equal(read('alpha','alpha'),200));");
  const git = (args, cwd = baseline) => exec('git', args, { cwd });
  await git(['init', '-q']); await git(['add', '.']); await git(['-c', 'user.name=Fixture', '-c', 'user.email=test@purple.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'baseline']);
  await git(['clone', '-q', '--no-hardlinks', baseline, candidate], root);
  await writeFile(path.join(candidate, 'src/access.mjs'), options.patch || 'export const read=(actor,owner)=>actor===owner?200:403;');
  await writeFile(path.join(candidate, 'test/security.test.mjs'), options.regression || regression);
  await git(['add', '-N', '.'], candidate);
  async function command(directory, args) {
    try {
      const result = await exec(args[0], args.slice(1), { cwd: directory, env: { PATH: process.env.PATH, HOME: root }, timeout: options.timeout || 5000, maxBuffer: 150000 });
      return { code: 0, passed: true, stdout: result.stdout, output: result.stdout };
    } catch (error) { return { code: typeof error.code === 'number' ? error.code : null, passed: false, timedOut: Boolean(error.killed), signal: error.signal, output: error.stderr || error.message }; }
  }
  return { root, baseline, candidate, command, observer };
}

test('real security assertion fails on baseline, passes after patch, and identical normal tests pass twice', async t => {
  const result = await verifyPatch({ ...await fixture(t), plan });
  assert.equal(result.verified, true, result.blocker); assert.equal(result.gateVersion, 2);
  assert.equal(result.baselineReproduction.classification, 'security_assertion_failure');
  assert.equal(result.baselineReproduction.tests[0].assertion.actual, 200);
  assert.equal(result.baselineNormal.summary.passed, 1); assert.equal(result.patchedNormal.summary.passed, 1);
  assert.equal(verificationQualified(result), true);
  const forged = structuredClone(result); forged.baselineReproduction.tests[0].assertion.actual = 500;
  assert.equal(verificationQualified(forged), false);
});

test('missing imports, thrown setup errors, unrelated assertions, crashes and skips never reproduce a vulnerability', async t => {
  for (const code of [
    "import './missing.mjs';",
    "import{test}from'node:test';test('cross-tenant read is forbidden',()=>{throw Error('database unavailable')});",
    "import{test}from'node:test';import assert from'node:assert/strict';test('cross-tenant read is forbidden',()=>assert.equal('missing setup','ready'));",
    "import{before,test}from'node:test';import assert from'node:assert/strict';before(()=>assert.equal(200,403));test('cross-tenant read is forbidden',()=>{});",
    "process.exit(1);",
    "import{test}from'node:test';test('cross-tenant read is forbidden',{skip:true},()=>{});",
    "import{test}from'node:test';test('cross-tenant read is forbidden',{todo:true},()=>{});",
    "// no tests"
  ]) {
    const result = await verifyPatch({ ...await fixture(t, { regression: code }), plan });
    assert.equal(result.verified, false, code); assert.ok(result.blocker); assert.equal(verificationQualified(result), false);
  }
});

test('timeouts, normal baseline failure, skipped normals, zero tests and normal regressions block verification', async t => {
  const cases = [
    { regression: "import{test}from'node:test';test('cross-tenant read is forbidden',()=>new Promise(()=>setInterval(()=>{},50)));", timeout: 300 },
    { normal: "import{test}from'node:test';test('broken setup',()=>{throw Error('normal failure')});" },
    { normal: "import{test}from'node:test';test('skipped',{skip:true},()=>{});" },
    { normal: '// no tests' },
    { normal: "console.log(JSON.stringify({protocolVersion:2,complete:true,summary:{passed:1,failed:0}}));process.exit(0);" },
    { patch: 'export const read=(actor,owner)=>403;' }
  ];
  for (const options of cases) assert.equal((await verifyPatch({ ...await fixture(t, options), plan })).verified, false, JSON.stringify(options));
});

test('a passing baseline, wrong expected failure, extra failing security test and altered normal tests block verification', async t => {
  assert.equal((await verifyPatch({ ...await fixture(t, { regression: regression.replace(",403)", ",200)") }), plan })).verified, false);
  assert.equal((await verifyPatch({ ...await fixture(t), plan: { ...plan, securityTests: [{ ...plan.securityTests[0], vulnerableActual: 500 }] } })).verified, false);
  const extra = regression + "test('unexpected failure',()=>assert.equal(1,2));";
  assert.equal((await verifyPatch({ ...await fixture(t, { regression: extra }), plan })).verified, false);
  const changed = await fixture(t); await writeFile(path.join(changed.candidate, 'test/normal.test.mjs'), "import{test}from'node:test';test('weakened',()=>{});");
  assert.match((await verifyPatch({ ...changed, plan })).blocker, /normal test changed/);
});

export async function verifiedFixture(t) { return verifyPatch({ ...await fixture(t), plan }); }
