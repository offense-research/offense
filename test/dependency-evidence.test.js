import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { inspectSources, reviewFindings, advisoryFingerprint, findingKey, triage } from '../public/skills/purple/scripts/evidence.mjs';
import { collectMetadata } from '../public/skills/purple/scripts/purple.mjs';

const finding = { package: 'semver', version: '7.5.1', id: 'GHSA-test', severity: 'HIGH', summary: 'Affected parser',
  fixedVersions: ['7.5.2'], advisory: { modified: '2026-10-01', details: 'Untrusted input reaches the affected parser.' } };
const now = 1700000000000;
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-evidence-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo'); await mkdir(repo);
  await writeFile(path.join(repo, 'package.json'), JSON.stringify({ dependencies: { semver: '7.5.1' } }));
  await writeFile(path.join(repo, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
    '': { dependencies: { semver: '7.5.1' } }, 'node_modules/semver': { version: '7.5.1' }
  } }));
  await writeFile(path.join(repo, 'index.js'), "import semver from 'semver';\nexport const parse = input => semver.valid(input);\n");
  execFileSync('git', ['init', '-q', repo]);
  execFileSync('git', ['add', '.'], { cwd: repo });
  execFileSync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture'], { cwd: repo });
  const metadata = await collectMetadata(repo);
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
  const scan = { repositoryRevision: revision, metadataFingerprint: metadata.fingerprint, warnings: [],
    vulnerabilityCheck: { status: 'complete', checkedAt: now, findings: [finding] } };
  const reports = path.join(root, 'scan'); await mkdir(reports);
  const scanFile = path.join(reports, 'scan.json');
  await writeFile(scanFile, JSON.stringify(scan)); await writeFile(path.join(reports, 'remediation.md'), 'Upgrade semver to checked 7.5.2.');
  return { root, repo, scan, scanFile };
}
function decision(scan, source) {
  return { key: findingKey(finding), status: 'not_affected', assessedBy: 'test reviewer',
    reason: 'Reviewed parser call only accepts a constant owned by the application.',
    prerequisites: 'The advisory requires attacker-controlled input reaching the parser.',
    repositoryRevision: scan.repositoryRevision, metadataFingerprint: scan.metadataFingerprint, sourceFingerprint: source.fingerprint,
    advisoryFingerprint: advisoryFingerprint(finding), reviewedAt: now, expiresAt: now + 86400000,
    evidence: source.references.semver.filter(ref => ref.path === 'index.js') };
}

test('source hints retain unknown reachability even with imports, comments, dev-only or missing references', async t => {
  const { repo, scan } = await fixture(t);
  await writeFile(path.join(repo, 'comments.js'), "// import semver from 'semver';\n");
  const source = await inspectSources(repo, [finding, { ...finding, package: 'not-imported' }]);
  assert.ok(source.references.semver.some(ref => ref.path === 'index.js'));
  assert.ok(source.references.semver.some(ref => ref.path === 'comments.js'));
  assert.equal(source.references['not-imported'].length, 0);
  const results = reviewFindings({ ...scan, vulnerabilityCheck: { findings: [finding, { ...finding, package: 'not-imported', kind: 'development' }] } }, source, [], now);
  assert.ok(results.every(item => item.status === 'needs_review' && item.reachability === 'unknown'));
});

test('assessments require pinned, unexpired, complete evidence and never become verified findings', async t => {
  const { repo, scan } = await fixture(t), source = await inspectSources(repo, [finding]);
  const valid = decision(scan, source);
  const assessed = reviewFindings(scan, source, [valid], now)[0];
  assert.equal(assessed.status, 'not_affected'); assert.equal(assessed.verification, 'reviewer_assessment_only');
  for (const patch of [
    { sourceFingerprint: 'stale' }, { metadataFingerprint: 'stale' }, { repositoryRevision: 'stale' }, { advisoryFingerprint: 'stale' },
    { expiresAt: now }, { expiresAt: now + 31 * 86400000 }, { reviewedAt: now + 1 }, { reason: 'unlikely' },
    { prerequisites: '' }, { assessedBy: '' }, { status: 'verified_fixed' }, { evidence: [] },
    { evidence: [{ path: 'index.js', line: 900, sha256: valid.evidence[0].sha256 }] },
    { evidence: [{ path: 'index.js', line: 1, sha256: 'wrong' }] }
  ]) assert.equal(reviewFindings(scan, source, [{ ...valid, ...patch }], now)[0].status, 'needs_review', JSON.stringify(patch));
  assert.equal(reviewFindings({ ...scan, warnings: ['partial'] }, source, [valid], now)[0].status, 'needs_review');
  assert.equal(reviewFindings(scan, { ...source, warnings: ['partial'] }, [valid], now)[0].status, 'needs_review');
  assert.equal(reviewFindings({ ...scan, vulnerabilityCheck: { findings: [{ ...finding, advisory: {} }] } }, source, [{ ...valid, advisoryFingerprint: advisoryFingerprint({ ...finding, advisory: {} }) }], now)[0].status, 'needs_review');
  assert.throws(() => reviewFindings(scan, source, [valid, valid], now), /duplicate/);
  assert.throws(() => reviewFindings(scan, source, [{ ...valid, key: 'unknown' }], now), /unknown/);
  const withAnalysis = { ...source, reachability: { analysisFingerprint: 'first', findings: [] } };
  assert.equal(reviewFindings(scan, withAnalysis, [valid], now)[0].status, 'needs_review');
  assert.equal(reviewFindings(scan, withAnalysis, [{ ...valid, analysisFingerprint: 'first' }], now)[0].status, 'not_affected');
  assert.equal(reviewFindings(scan, withAnalysis, [{ ...valid, analysisFingerprint: 'other' }], now)[0].status, 'needs_review');
  const changedAdvisory = { ...finding, advisory: { ...finding.advisory, details: 'New prerequisites.' } };
  assert.equal(reviewFindings({ ...scan, vulnerabilityCheck: { findings: [changedAdvisory] } }, source, [valid], now)[0].status, 'needs_review');
  await writeFile(path.join(repo, 'index.js'), 'export const parse = input => input;');
  assert.equal(reviewFindings(scan, await inspectSources(repo, [finding]), [valid], now)[0].status, 'needs_review');
});

test('source coverage avoids dependencies and symlinks, records limits, and binds unseen config changes', async t => {
  const { repo } = await fixture(t);
  const first = await inspectSources(repo, [finding]);
  await mkdir(path.join(repo, 'node_modules'));
  await writeFile(path.join(repo, 'node_modules/secret.js'), 'must never inspect');
  assert.equal((await inspectSources(repo, [finding])).fingerprint, first.fingerprint);
  await writeFile(path.join(repo, 'wrangler.toml'), 'name = "worker"');
  assert.notEqual((await inspectSources(repo, [finding])).fingerprint, first.fingerprint);
  await symlink('/etc/passwd', path.join(repo, 'outside.js'));
  await writeFile(path.join(repo, 'huge.js'), 'x'.repeat(1_000_001));
  const partial = await inspectSources(repo, [finding]);
  assert.ok(partial.warnings.some(item => item.includes('symlink')));
  assert.ok(partial.warnings.some(item => item.includes('byte limit')));
  assert.ok(!partial.files.some(item => item.path.includes('outside') || item.path.includes('huge')));
  await writeFile(path.join(repo, 'many.js'), Array(35).fill("// require('semver')").join('\n'));
  const bounded = await inspectSources(repo, [finding]);
  assert.equal(bounded.references.semver.length, 30);
  assert.ok(bounded.warnings.some(item => item.includes('reference limit')));
});

test('triage creates a complete repo handoff, preserves failed simulation and rejects stale simulation evidence', async t => {
  const { repo, scan, scanFile, root } = await fixture(t);
  const initial = await triage(repo, { scanFile, now });
  assert.equal(initial.needs_review, 1);
  const template = JSON.parse(await readFile(initial.decisionsTemplate));
  assert.equal(template[0].status, 'needs_review');
  const source = await inspectSources(repo, [finding]), decisionsFile = path.join(root, 'decisions.json');
  const initialReport = JSON.parse(await readFile(initial.evidence));
  await writeFile(decisionsFile, JSON.stringify([{ ...decision(scan, source), analysisFingerprint: initialReport.analysisFingerprint }]));
  const rehearsal = { revision: scan.repositoryRevision, metadataFingerprint: scan.metadataFingerprint, sourceFingerprint: source.fingerprint,
    status: 'baseline_failed', verification: 'compatibility_rehearsal_only', result: { baseline: { checks: [{ passed: false }] }, scenarios: [] },
    remainingAdvisories: [finding], newAdvisories: [] };
  const rehearsalFile = path.join(root, 'rehearsal.json'); await writeFile(rehearsalFile, JSON.stringify(rehearsal));
  const reviewed = await triage(repo, { scanFile, decisionsFile, rehearsalFile, now });
  assert.equal(reviewed.not_affected, 1);
  const handoff = await readFile(reviewed.handoff, 'utf8');
  assert.match(handoff, /Upgrade semver to checked 7.5.2/); assert.match(handoff, /baseline_failed/); assert.match(handoff, /GHSA-test/);
  assert.match(handoff, /No matches are hidden/);
  await writeFile(rehearsalFile, JSON.stringify({ ...rehearsal, sourceFingerprint: 'stale' }));
  await assert.rejects(triage(repo, { scanFile, rehearsalFile, now }), /stale/);
  await assert.rejects(triage(repo, { scanFile, output: path.join(repo, 'reports'), now }), /outside/);
  await assert.rejects(triage(repo, { scanFile, now: now + 86400001 }), /24 hours/);
  await writeFile(path.join(repo, 'package.json'), '{"dependencies":{"semver":"7.5.2"}}');
  await assert.rejects(triage(repo, { scanFile, now }), /stale/);
});
