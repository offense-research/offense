import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { runDependencyFix, verifyDependencyFix, dependencyFixReviewWarnings } from '../agent/dependency-fix.mjs';
import { collectMetadata } from '../public/skills/purple/scripts/purple.mjs';
import { fingerprintCheckout, createDependencyPrHandoff } from '../agent/pr-handoff.mjs';
import { verifiedEvidence } from './helpers/verification-evidence.js';

async function fixture({ broken = false, checks = true, rootCheck = false, ignoredRepair = false } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-fix-fixture-')), directory = path.join(root, 'repo'), output = path.join(root, 'report');
  await mkdir(directory);
  await writeFile(path.join(directory, '.gitignore'), 'node_modules/\n.generated-helper.cjs\n');
  await writeFile(path.join(directory, 'package.json'), JSON.stringify({ name: 'dependency-fix-fixture', version: '1.0.0',
    dependencies: { lodash: '3.10.1' }, scripts: checks ? { test: rootCheck ? 'node check.cjs' : 'node --test test/*.test.cjs' } : {} }));
  await writeFile(path.join(directory, 'app.cjs'), broken ? `throw new Error('Original application broken');\n` : ignoredRepair ? `const _=require('lodash');module.exports=items=>_.pluck?_.pluck(items,'name'):require('./.generated-helper.cjs')(items);\n` : `const _=require('lodash');module.exports=items=>_.pluck(items,'name');\n`);
  await mkdir(path.join(directory, 'test'));
  await writeFile(path.join(directory, rootCheck ? 'check.cjs' : 'test/app.test.cjs'), `const test=require('node:test');const assert=require('node:assert/strict');const names=require('${rootCheck ? './app.cjs' : '../app.cjs'}');test('names remain available',()=>{assert.deepEqual(names([{name:'Alice'},{name:'Bob'}]),['Alice','Bob']);assert.equal(process.env.OPENROUTER_API_KEY,undefined);assert.equal(process.env.GITHUB_TOKEN,undefined);});\n`);
  const run = argv => execFileSync(argv[0], argv.slice(1), { cwd: directory, encoding: 'utf8', stdio: 'pipe' });
  run(['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
  run(['git', 'init']); run(['git', 'add', '.']); run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'Original fixture']);
  const revision = run(['git', 'rev-parse', 'HEAD']).trim(), metadata = await collectMetadata(directory);
  const finding = { id: 'GHSA-synthetic-lodash', package: 'lodash', version: '3.10.1', severity: 'HIGH', summary: 'Synthetic advisory metadata for orchestration fixture' };
  const scan = { repositoryRevision: revision, metadataFingerprint: metadata.fingerprint, warnings: [],
    vulnerabilityCheck: { status: 'complete', checkedAt: Date.now(), findings: [finding] },
    plans: [{ name: 'lodash', currentVersion: '3.10.1', targetVersion: '4.17.21', considered: [{ version: '4.17.21', advisories: 0 }], parentOptions: [] }] };
  const scanFile = path.join(root, 'scan.json'); await writeFile(scanFile, JSON.stringify(scan));
  async function analyze(candidate, options) {
    const meta = await collectMetadata(candidate), lock = JSON.parse(await readFile(path.join(candidate, 'package-lock.json'), 'utf8'));
    const old = lock.packages['node_modules/lodash']?.version === '3.10.1';
    const fresh = { metadataFingerprint: meta.fingerprint, repositoryRevision: revision, warnings: [], vulnerabilityCheck: { status: 'complete', checkedAt: Date.now(), findings: old ? [finding] : [] } };
    await mkdir(options.output, { recursive: true }); const json = path.join(options.output, 'scan.json'); await writeFile(json, JSON.stringify(fresh));
    return { json, warnings: 0 };
  }
  return { root, directory, output, scanFile, scan, analyze, revision, run, async cleanup() { await rm(root, { recursive: true, force: true }); } };
}

test('dependency fix repairs a real breaking API upgrade, independently verifies, and produces a bound PR handoff', { timeout: 180000 }, async () => {
  const f = await fixture(); let calls = 0;
  f.scan.plans[0].steps = [{ from: '3.10.1', to: '4.0.0', deprecated: 'Intermediate release notice' },
    { from: '4.17.20', to: '4.17.21', deprecated: 'Synthetic fixture deprecation warning' }];
  await writeFile(f.scanFile, JSON.stringify(f.scan));
  const before = await fingerprintCheckout(f.directory);
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true, apiKey: 'must-not-reach-tests', model: 'fixture-model', repository: 'fixture/repo' }, {
      analyze: f.analyze,
      agent: async input => {
        calls++; assert.equal(input.apiKey, 'must-not-reach-tests'); assert.equal(input.task.type, 'dependency_fix');
        assert.equal(input.feedback.candidate.checks[0].passed, false);
        assert.match(input.feedback.candidate.checks[0].output, /pluck/);
        await writeFile(path.join(input.candidateDirectory, 'app.cjs'), `const _=require('lodash');module.exports=items=>_.map(items,'name');\n`);
        return { status: 'completed', summary: 'Migrate the removed pluck API to map.', usage: { providerCostUsd: 0 }, runtime: { name: 'hermes', revision: 'fixture' } };
      }
    });
    assert.equal(report.status, 'ready_for_review'); assert.equal(report.publishEligible, true); assert.equal(calls, 1);
    assert.equal(report.checklist.length, 1); assert.equal(report.checklist[0].status, 'remediated');
    assert.equal(report.baseline.checks[0].passed, true); assert.equal(report.candidate.checks[0].passed, true);
    assert.equal(report.baseline.checks[0].directory, report.candidate.checks[0].directory);
    assert.equal(report.finalScan.status, 'complete'); assert.equal(report.newAdvisories.length, 0);
    assert.equal(report.verification, 'compatibility_and_advisory_checks'); assert.equal(report.securityVerification, null);
    assert.equal(report.needsMaintainerReview, true); assert.equal(report.reviewWarnings.length, 1);
    assert.deepEqual(report.reviewWarnings[0], { type: 'deprecated_target', package: 'lodash', version: '4.17.21', source: 'dependency', message: 'Synthetic fixture deprecation warning' });
    assert.match(report.checklist[0].reason, /Needs maintainer review:.*Synthetic fixture deprecation warning/);
    assert.match(await readFile(report.reportPath, 'utf8'), /Maintainer review required/);
    assert.match(await readFile(report.handoff.bodyPath, 'utf8'), /Synthetic fixture deprecation warning/);
    assert.match(await readFile(report.patch.path, 'utf8'), /_.map/);
    assert.equal(await fingerprintCheckout(f.directory), before, 'the user checkout is untouched');
    const saved = JSON.parse(await readFile(report.evidencePath, 'utf8')); assert.deepEqual(saved, JSON.parse(JSON.stringify(report)));
    const handoff = JSON.parse(await readFile(report.handoff.manifestPath, 'utf8')); assert.equal(handoff.patchSha256, report.patch.sha256);
    assert.ok(!JSON.stringify(report).includes('must-not-reach-tests'));
    const verified = await verifyDependencyFix({ reportFile: report.evidencePath, sandboxed: true }, { analyze: f.analyze });
    assert.equal(verified.status, 'ready_for_review'); assert.equal(verified.publishEligible, true); assert.notEqual(verified.evidencePath, report.evidencePath);
    assert.equal(verified.needsMaintainerReview, true); assert.deepEqual(verified.reviewWarnings, report.reviewWarnings);
    assert.match(await readFile(verified.reportPath, 'utf8'), /Synthetic fixture deprecation warning/);
    assert.equal(await readFile(report.evidencePath, 'utf8'), JSON.stringify(saved, null, 2)+'\n', 're-verification preserves original evidence');
    // Rechecking compatibility must not refresh an earlier exploit regression
    // into a new security-verification claim when that regression did not run.
    const historicalDirectory = path.join(f.root, 'historical-report'); await mkdir(historicalDirectory);
    const historical = structuredClone(report);
    historical.verification = 'security_regression_verified'; historical.securityVerification = verifiedEvidence();
    historical.evidencePath = path.join(historicalDirectory, 'fix.json'); historical.reportPath = path.join(historicalDirectory, 'fix.md');
    historical.handoff = { bodyPath: path.join(historicalDirectory, 'pr-body.md'), manifestPath: path.join(historicalDirectory, 'pr-handoff.json') };
    await writeFile(historical.evidencePath, JSON.stringify(historical));
    await createDependencyPrHandoff({ report: historical, outputDirectory: historicalDirectory });
    const historicalVerified = await verifyDependencyFix({ reportFile: historical.evidencePath, sandboxed: true }, { analyze: f.analyze });
    assert.equal(historicalVerified.status, 'ready_for_review');
    assert.equal(historicalVerified.verification, 'compatibility_and_advisory_checks'); assert.equal(historicalVerified.securityVerification, null);
    assert.equal(historicalVerified.historicalSecurityVerification.status, 'not_rerun');
    assert.equal(historicalVerified.historicalSecurityVerification.finishedAt, historical.finishedAt);
    assert.deepEqual(historicalVerified.historicalSecurityVerification.evidence, historical.securityVerification);
    assert.doesNotMatch(await readFile(historicalVerified.handoff.bodyPath, 'utf8'), /A separate security regression passed/);
    await writeFile(path.join(report.candidateDirectory, 'app.cjs'), 'module.exports=()=>[];\n');
    await assert.rejects(verifyDependencyFix({ reportFile: report.evidencePath, sandboxed: true }, { analyze: f.analyze }), /evidence changed/);
  } finally { await f.cleanup(); }
});

test('maintenance warnings cover only selected dependency and parent targets and deduplicate repeated steps', () => {
  const target = { to: '2.0.0', deprecated: 'Selected release is deprecated.' };
  const warnings = dependencyFixReviewWarnings({ name: 'leaf', targetVersion: '2.0.0', steps: [{ to: '1.5.0', deprecated: 'Unselected intermediate.' }, target, target],
    parentOptions: [{ parent: 'parent', version: '3.0.0', steps: [{ to: '3.0.0', deprecated: 'Parent release is deprecated.' }] },
      { parent: 'unselected-parent', version: null, steps: [{ to: '9.0.0', deprecated: 'Not a chosen target.' }] }] });
  assert.deepEqual(warnings, [
    { type: 'deprecated_target', package: 'leaf', version: '2.0.0', source: 'dependency', message: 'Selected release is deprecated.' },
    { type: 'deprecated_target', package: 'parent', version: '3.0.0', source: 'parent', message: 'Parent release is deprecated.' }
  ]);
});

test('a broken original baseline blocks agent calls and retains every advisory', { timeout: 120000 }, async () => {
  const f = await fixture({ broken: true }); let calls = 0;
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true }, { analyze: f.analyze, agent: async () => { calls++; } });
    assert.equal(report.status, 'blocked'); assert.equal(report.publishEligible, false); assert.equal(calls, 0);
    assert.equal(report.checklist.length, 1); assert.equal(report.checklist[0].status, 'blocked');
    assert.match(report.blockers.join(' '), /Original installation\/checks/);
  } finally { await f.cleanup(); }
});

test('an ignored helper cannot make an incomplete reviewable patch qualify as passing', { timeout: 120000 }, async () => {
  const f = await fixture({ ignoredRepair: true }); let calls = 0;
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true, maxAttempts: 1 }, { analyze: f.analyze, agent: async input => {
      calls++;
      await writeFile(path.join(input.candidateDirectory, '.generated-helper.cjs'), 'module.exports=items=>items.map(item=>item.name);\n');
      return { status: 'completed', summary: 'An ignored artifact pretends to repair the upgrade.', runtime: { name: 'hermes' } };
    } });
    assert.equal(calls, 1); assert.equal(report.publishEligible, false); assert.notEqual(report.status, 'ready_for_review');
    assert.equal(report.candidate.checks[0].passed, false); assert.match(report.candidate.checks[0].output, /generated-helper/);
    await assert.rejects(readFile(path.join(report.candidateDirectory, '.generated-helper.cjs')), { code: 'ENOENT' });
    assert.doesNotMatch(await readFile(report.patch.path, 'utf8'), /module\.exports=items=>items\.map/);
  } finally { await f.cleanup(); }
});

test('agent test weakening cannot qualify a dependency fix even if its self-reported status says verified', { timeout: 120000 }, async () => {
  const f = await fixture();
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true }, { analyze: f.analyze, agent: async input => {
      await writeFile(path.join(input.candidateDirectory, 'test/app.test.cjs'), `require('node:test')('fake pass',()=>{});\n`);
      return { status: 'verified', summary: 'All done', runtime: { name: 'hermes' } };
    } });
    assert.notEqual(report.status, 'ready_for_review'); assert.equal(report.publishEligible, false);
    assert.match(report.blockers.join(' '), /existing test/);
  } finally { await f.cleanup(); }
});

test('a repair cannot weaken a later check and restore it before the final fingerprint', { timeout: 120000 }, async () => {
  const f = await fixture();
  try {
    const file = path.join(f.directory, 'package.json');
    const manifest = JSON.parse(await readFile(file, 'utf8'));
    const originalTest = await readFile(path.join(f.directory, 'test/app.test.cjs'), 'utf8');
    manifest.scripts.typecheck = 'node restore.cjs';
    await writeFile(file, JSON.stringify(manifest));
    await writeFile(path.join(f.directory, 'restore.cjs'), `require('node:fs').writeFileSync('test/app.test.cjs',${JSON.stringify(originalTest)});\n`);
    f.run(['git', 'add', '.']);
    f.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'Add second check']);
    f.scan.repositoryRevision = f.run(['git', 'rev-parse', 'HEAD']).trim();
    f.scan.metadataFingerprint = (await collectMetadata(f.directory)).fingerprint;
    await writeFile(f.scanFile, JSON.stringify(f.scan));
    const report = await runDependencyFix({ ...f, sandboxed: true, maxAttempts: 1 }, { analyze: f.analyze, agent: async input => {
      await writeFile(path.join(input.candidateDirectory, 'app.cjs'), `require('node:fs').writeFileSync('test/app.test.cjs','process.exit(0);\\n');module.exports=items=>items.map(item=>item.name);\n`);
      return { status: 'completed', runtime: { name: 'hermes' } };
    } });
    assert.equal(report.publishEligible, false);
    assert.equal(report.candidate.integrity, false);
    assert.equal(report.candidate.checks.length, 1, 'The restore command must never run after a check rewrites tests.');
    assert.equal(report.candidate.checks[0].passed, true, 'A zero exit code is not enough.');
  } finally { await f.cleanup(); }
});

test('custom original check entry points are protected even without a conventional test filename', { timeout: 120000 }, async () => {
  const f = await fixture({ rootCheck: true });
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true }, { analyze: f.analyze, agent: async input => {
      assert.ok(input.task.protectedPaths.includes('check.cjs'));
      await writeFile(path.join(input.candidateDirectory, 'check.cjs'), 'process.exit(0);\n');
      return { status: 'completed', summary: 'Pretended to repair by weakening verification', runtime: { name: 'hermes' } };
    } });
    assert.equal(report.publishEligible, false); assert.match(report.blockers.join(' '), /existing test or repository execution policy/);
  } finally { await f.cleanup(); }
});

test('failed advisory service and bounded unsuccessful repairs remain explicit blockers', { timeout: 180000 }, async () => {
  const f = await fixture(); let calls = 0;
  try {
    const report = await runDependencyFix({ ...f, sandboxed: true, maxAttempts: 2 }, { analyze: async () => { throw new Error('OSV unavailable'); }, agent: async () => { calls++; return { status: 'completed', summary: 'No working source repair yet', runtime: { name: 'hermes' } }; } });
    assert.equal(calls, 2); assert.equal(report.status, 'blocked'); assert.equal(report.publishEligible, false);
    assert.equal(report.finalScan.status, 'failed'); assert.ok(report.checklist.every(item => item.status === 'blocked'));
    assert.match(report.blockers.join(' '), /complete current candidate/);
  } finally { await f.cleanup(); }
});

test('unfixed plans do not silently drop advisory checklist rows and no-target scans avoid the model', { timeout: 30000 }, async () => {
  const f = await fixture(); let calls = 0;
  try {
    f.scan.plans = []; f.scan.vulnerabilityCheck.findings.push({ id: 'GHSA-other-low', package: 'lodash', version: '3.10.1', severity: 'LOW' });
    await writeFile(f.scanFile, JSON.stringify(f.scan));
    const report = await runDependencyFix({ ...f, sandboxed: true }, { agent: async () => { calls++; } });
    assert.equal(report.status, 'blocked'); assert.equal(calls, 0); assert.equal(report.checklist.length, 2);
    assert.equal(report.checklist[0].status, 'blocked'); assert.equal(report.checklist[1].status, 'deferred');
    f.scan.vulnerabilityCheck.findings = []; await writeFile(f.scanFile, JSON.stringify(f.scan));
    const empty = await runDependencyFix({ ...f, output: path.join(f.root, 'empty-report'), sandboxed: true }, { agent: async () => { calls++; } });
    assert.equal(empty.status, 'no_changes'); assert.equal(empty.publishEligible, false); assert.equal(calls, 0);
  } finally { await f.cleanup(); }
});

test('fix refuses non-isolated execution, dirty sources, stale scans and missing checks', { timeout: 120000 }, async () => {
  const f = await fixture({ checks: false });
  try {
    await assert.rejects(runDependencyFix({ ...f }), /isolated/);
    const noChecks = await runDependencyFix({ ...f, sandboxed: true }); assert.equal(noChecks.status, 'blocked'); assert.match(noChecks.blockers.join(' '), /no baseline checks/);
    await writeFile(path.join(f.directory, 'new-uncommitted.txt'), 'keep this\n');
    const dirty = await runDependencyFix({ ...f, output: path.join(f.root, 'dirty-report'), sandboxed: true }); assert.equal(dirty.status, 'blocked'); assert.match(dirty.blockers.join(' '), /clean isolated/);
    await rm(path.join(f.directory, 'new-uncommitted.txt'));
    f.scan.repositoryRevision = 'f'.repeat(40); await writeFile(f.scanFile, JSON.stringify(f.scan));
    const stale = await runDependencyFix({ ...f, output: path.join(f.root, 'stale-report'), sandboxed: true }); assert.equal(stale.status, 'blocked'); assert.match(stale.blockers.join(' '), /another repository revision/);
  } finally { await f.cleanup(); }
});
