import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm, chmod } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { collectLocalEvidence, assessVerificationRecord, loadReviewedEvidence } from '../scripts/offense-local-evidence.mjs';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';

const execute = promisify(execFile);
const hash = value => createHash('sha256').update(value).digest('hex');
const now = Date.now(), revision = 'a'.repeat(40), baselineRevision = 'b'.repeat(40), metadataFingerprint = 'c'.repeat(64);
const finding = { advisoryId: 'GHSA-example', package: { ecosystem: 'npm', name: 'example', installedVersion: '1.0.0' } };
const normalCheck = () => ({ id: 'test', workspace: '.', command: ['npm', 'test'], exitCode: 0, setupPassed: true, timedOut: false, truncated: false, artifactVerified: true });
function reviewedRecord() {
  return { schemaVersion: 'offense.verification.v1', repositoryRevision: revision, baselineRevision, metadataFingerprint,
    reviewedBy: 'Local security reviewer', reviewedAt: now - 1000, expiresAt: now + 86400000,
    findings: [{ advisoryId: 'GHSA-example', package: 'example', version: '1.0.0', behaviorChanges: [], testCoverageReviewed: true,
      normalChecks: { baseline: [normalCheck()], candidate: [normalCheck()] }, securityRegression: {
        assertionId: 'reject-oversize', assertion: 'Oversized inputs are rejected before visiting array elements.',
        advisoryPrerequisites: 'An attacker can submit an oversized array to the affected validator.',
        reviewedFailureReason: 'The original validator visits every element instead of rejecting the configured size limit.', testArtifactVerified: true,
        baseline: { ...normalCheck(), id: 'security', command: ['node', '--test', 'security.test.mjs'], exitCode: 1, failureKind: 'security_assertion', assertionMarkerVerified: true },
        candidate: { ...normalCheck(), id: 'security', command: ['node', '--test', 'security.test.mjs'], assertionMarkerVerified: true },
      } }] };
}
const context = overrides => ({ repositoryRevision: revision, metadataFingerprint, worktreeClean: true, findings: [finding], now, ...overrides });
async function fixture(t) {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'offense-local-evidence-')), root = path.join(outer, 'repo');
  await mkdir(root); t.after(() => rm(outer, { recursive: true, force: true }));
  return { outer, root, async put(relative, contents) { const file = path.join(root, relative); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, contents); return file; } };
}

test('local inventory keeps uncovered archives, conditional Python and URL requirements visible without returning credentials', async t => {
  const { root, put } = await fixture(t);
  await put('package.json', '{"dependencies":{"example":"^1"}}');
  await put('archived/demo/package.json', '{}');
  await put('tools/requirements.txt', '# comment\nPillow==12.3.0\nPillow>=12\nexample @ https://user:secret@registry.test/private\nother==1.0; python_version < "3.12"\n');
  await put('tools/pyproject.toml', '[project]\nname="private-project"\n');
  await put('yarn.lock', 'unsupported');
  await put('node_modules/hidden/requirements.txt', 'secret==1.0');
  const result = await collectLocalEvidence(root, { coveredManifests: ['package.json'], supportedLockfiles: ['package-lock.json'] });
  assert.equal(result.coverage.status, 'partial');
  assert.deepEqual(result.coverage.uncoveredManifests.map(item => [item.path, item.scope]), [['archived/demo/package.json', 'review_scope']]);
  const requirements = result.coverage.unsupportedFiles.find(item => item.path === 'tools/requirements.txt');
  assert.equal(requirements.exactPins, 1); assert.equal(requirements.unresolvedDeclarations, 3); assert.equal(requirements.status, 'not_scanned');
  assert.match(requirements.nextStep, /establish resolved versions/);
  assert.ok(result.coverage.warnings.includes('yarn.lock: unsupported lockfile; not scanned.'));
  assert.doesNotMatch(JSON.stringify(result), /user:secret|registry\.test|private-project|hidden\/requirements/);
  assert.ok(result.coverage.tasks.some(item => item.kind === 'resolve_manifest'));
});

test('pnpm patch declarations retain reviewed identity and content hashes without trusting them as mitigation', async t => {
  const { root, put } = await fixture(t), patch = 'local patch content';
  await put('package.json', JSON.stringify({ pnpm: { patchedDependencies: { 'example@1.0.0': 'patches/example.patch', '@scope/tool@2.0.0': '../outside.patch' } } }));
  await put('pnpm-workspace.yaml', 'patchedDependencies:\n  example@1.0.0: patches/example.patch\n');
  await put('patches/example.patch', patch);
  const result = await collectLocalEvidence(root, { coveredManifests: ['package.json'] });
  assert.equal(result.patches.length, 2);
  assert.equal(result.patches[0].sha256, hash(patch)); assert.equal(result.patches[0].status, 'unverified');
  assert.equal(result.patches[1].path, null); assert.match(result.patches[1].blocker, /unsupported/);
  assert.doesNotMatch(JSON.stringify(result), /local patch content/);
  assert.match(result.patches[0].nextStep, /patch declaration or hash alone/);
});

test('patch-package scoped packages are recognized and symlinked artifacts never read', async t => {
  const { root, outer, put } = await fixture(t);
  await put('package.json', '{"devDependencies":{"patch-package":"8.0.0"}}');
  await put('patches/@scope+tool+2.0.0.patch', 'scoped patch');
  await writeFile(path.join(outer, 'outside.patch'), 'must not read');
  await symlink(path.join(outer, 'outside.patch'), path.join(root, 'patches/example+1.0.0.patch'));
  const result = await collectLocalEvidence(root, { coveredManifests: ['package.json'] });
  assert.equal(result.patches.length, 1); assert.equal(result.patches[0].package, '@scope/tool'); assert.equal(result.patches[0].version, '2.0.0');
  assert.doesNotMatch(JSON.stringify(result), /must not read/);
});

test('a reviewed record distinguishes security regression, compatibility and patch mitigation while retaining advisory matches', () => {
  let record = reviewedRecord(), result = assessVerificationRecord(record, context());
  assert.equal(result.findings[0].status, 'security_regression_verified'); assert.equal(result.confirmedVulnerabilities, 0);
  assert.equal(result.findings[0].advisoryMatchRetained, true);
  delete record.findings[0].securityRegression;
  result = assessVerificationRecord(record, context());
  assert.equal(result.findings[0].status, 'compatibility_verified'); assert.equal(result.status, 'needs_review');
  record = reviewedRecord(); record.findings[0].patch = { path: 'patches/example.patch', sha256: 'd'.repeat(64), installedIdentityVerified: true, appliedFilesVerified: true };
  result = assessVerificationRecord(record, context({ patches: [{ package: 'example', version: '1.0.0', path: 'patches/example.patch', sha256: 'd'.repeat(64) }] }));
  assert.equal(result.findings[0].status, 'mitigation_verified'); assert.equal(result.counts.mitigation_verified, 1);
});

test('setup failures, wrong assertions, missing evidence and generic crashes never establish a reproduced security fix', () => {
  for (const mutation of [item => item.securityRegression.baseline.failureKind = 'setup_error', item => item.securityRegression.baseline.exitCode = 2,
    item => item.securityRegression.baseline.setupPassed = false, item => item.securityRegression.baseline.assertionMarkerVerified = false,
    item => item.securityRegression.baseline.signal = 'SIGABRT', item => item.securityRegression.baseline.truncated = true,
    item => item.securityRegression.candidate.exitCode = 1, item => item.securityRegression.testArtifactVerified = false,
    item => item.securityRegression.advisoryPrerequisites = '', item => item.securityRegression.reviewedFailureReason = 'setup error']) {
    const record = reviewedRecord(); mutation(record.findings[0]);
    const result = assessVerificationRecord(record, context()); assert.equal(result.findings[0].status, 'compatibility_verified', mutation.toString());
    assert.equal(result.confirmedVulnerabilities, 0);
  }
});

test('normal checks need exact baseline/candidate parity, actual exit status and reviewed behavior/test coverage', () => {
  for (const mutation of [item => item.normalChecks.baseline = [], item => item.normalChecks.candidate[0].command = ['npm', 'run', 'build'],
    item => item.normalChecks.candidate[0].workspace = 'other-workspace', item => delete item.normalChecks.candidate[0].exitCode,
    item => item.normalChecks.baseline[0].artifactVerified = false, item => item.testCoverageReviewed = false,
    item => delete item.behaviorChanges, item => item.behaviorChanges.push({ description: 'Iframe test now uses a mock', verification: '' })]) {
    const record = reviewedRecord(); mutation(record.findings[0]);
    assert.equal(assessVerificationRecord(record, context()).findings[0].status, 'advisory_match', mutation.toString());
  }
});

test('stale commits, changed lockfiles, dirty worktrees and expired reviews cannot borrow prior verification', () => {
  const record = reviewedRecord();
  for (const change of [{ repositoryRevision: 'e'.repeat(40) }, { metadataFingerprint: 'e'.repeat(64) }, { currentMetadataFingerprint: 'e'.repeat(64) },
    { worktreeClean: false }, { worktreeClean: null }, { now: now + 2 * 86400000 }]) {
    const result = assessVerificationRecord(record, context(change)); assert.equal(result.findings[0].status, 'advisory_match'); assert.equal(result.status, 'needs_review');
  }
  record.findings.push(structuredClone(record.findings[0]));
  assert.match(assessVerificationRecord(record, context()).findings[0].blockers.join(' '), /Duplicate/);
});

test('unreviewed patches, malformed rows and absent advisory identities remain explicit without crashing', () => {
  let record = reviewedRecord(); record.findings[0].patch = { path: 'patches/example.patch', sha256: 'd'.repeat(64) };
  const result = assessVerificationRecord(record, context({ patches: [{ package: 'example', version: '1.0.0', path: 'patches/example.patch', sha256: 'd'.repeat(64) }] }));
  assert.equal(result.findings[0].status, 'compatibility_verified'); assert.match(result.findings[0].blockers.join(' '), /installed package identity/);
  record = reviewedRecord(); record.findings = [null, {}, []];
  assert.equal(assessVerificationRecord(record, context()).findings[0].status, 'advisory_match');
  record = reviewedRecord(); record.findings[0].version = '2.0.0';
  assert.ok(assessVerificationRecord(record, context()).warnings.some(value => value.includes('absent or different')));
});

async function artifactFixture(t) {
  const fixtureData = await fixture(t), { root, outer, put } = fixtureData;
  const lock = JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { example: '1.0.0' } }, 'node_modules/example': { version: '1.0.0' } } });
  await put('package.json', '{"pnpm":{"patchedDependencies":{"example@1.0.0":"patches/example.patch"}}}');
  await put('package-lock.json', lock); await put('patches/example.patch', 'reviewed patch'); await put('.gitignore', 'node_modules/\n');
  await put('node_modules/example/package.json', '{"name":"example","version":"1.0.0"}');
  await put('node_modules/example/index.js', 'export const sizeGuard = true;');
  const git = args => execute('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'user.name=Offense test', '-c', 'user.email=offense-test@example.invalid', ...args], { cwd: root });
  await git(['init', '-q']); await git(['add', '.']); await git(['commit', '-qm', 'Synthetic reviewed fixture']);
  const identity = await collectLocalEvidence(root, { coveredManifests: ['package.json'] });
  const fingerprint = hash(JSON.stringify(sanitizeLockfiles([{ path: 'package-lock.json', content: lock }]).files));
  const evidenceRoot = path.join(outer, 'evidence'); await mkdir(evidenceRoot);
  async function evidenceArtifact(name, contents, base = evidenceRoot) {
    const filename = path.join(base, name); await mkdir(path.dirname(filename), { recursive: true }); await writeFile(filename, contents);
    return { path: name, sha256: hash(contents) };
  }
  const record = reviewedRecord(); record.repositoryRevision = identity.repositoryRevision; record.metadataFingerprint = fingerprint;
  const item = record.findings[0];
  for (const phase of ['baseline', 'candidate']) {
    item.normalChecks[phase][0].log = await evidenceArtifact(`${phase}/normal.log`, 'normal tests passed');
    item.securityRegression[phase].log = await evidenceArtifact(`${phase}/security.log`, `OFFENSE_SECURITY_ASSERTION_${phase === 'baseline' ? 'FAILED' : 'PASSED'} reject-oversize\n`);
  }
  item.securityRegression.test = await evidenceArtifact('security.test.mjs', 'assert.rejects(() => handleOversizedInput());');
  item.patch = { path: 'patches/example.patch', sha256: hash('reviewed patch'),
    installedManifest: { path: 'node_modules/example/package.json', sha256: hash(await readFile(path.join(root, 'node_modules/example/package.json'))) },
    appliedFiles: [{ path: 'node_modules/example/index.js', sha256: hash(await readFile(path.join(root, 'node_modules/example/index.js'))) }] };
  const evidenceFile = path.join(evidenceRoot, 'verification.json');
  await writeFile(evidenceFile, JSON.stringify(record));
  return { ...fixtureData, record, evidenceFile, evidenceRoot, fingerprint, identity, git };
}

test('explicit local evidence validates artifact bytes and applied patch files, never taking claimed verification booleans on trust', async t => {
  const f = await artifactFixture(t);
  let result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], now });
  assert.equal(result.findings[0].status, 'mitigation_verified'); assert.equal(result.confirmedVulnerabilities, 0);
  await f.put('node_modules/example/index.js', 'export const sizeGuard = false;');
  f.record.findings[0].patch.appliedFilesVerified = true;
  await writeFile(f.evidenceFile, JSON.stringify(f.record));
  result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], now });
  assert.equal(result.findings[0].status, 'compatibility_verified'); assert.match(result.findings[0].blockers.join(' '), /applied-file integrity/);
});

test('changed logs and a setup failure lacking the exact security marker cannot become mitigation proof', async t => {
  const f = await artifactFixture(t);
  const logPath = path.join(f.evidenceRoot, 'baseline/security.log');
  await writeFile(logPath, 'MODULE_NOT_FOUND before tests started');
  f.record.findings[0].securityRegression.baseline.log.sha256 = hash('MODULE_NOT_FOUND before tests started');
  f.record.findings[0].securityRegression.baseline.assertionMarkerVerified = true;
  await writeFile(f.evidenceFile, JSON.stringify(f.record));
  let result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], now });
  assert.equal(result.findings[0].status, 'compatibility_verified');
  await writeFile(path.join(f.evidenceRoot, 'candidate/normal.log'), 'normal test failures');
  result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], now });
  assert.equal(result.findings[0].status, 'advisory_match');
});

test('loader rechecks current metadata and commit cleanliness instead of trusting stale inventory', async t => {
  const f = await artifactFixture(t);
  await f.put('package-lock.json', '{"lockfileVersion":3,"packages":{"node_modules/example":{"version":"2.0.0"}}}');
  const result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], localEvidence: f.identity, now });
  assert.equal(result.findings[0].status, 'advisory_match');
  assert.match(result.warnings.join(' '), /changed after the hosted audit/); assert.match(result.warnings.join(' '), /Commit reviewed changes/);
});

test('artifact traversal and symlinks are refused even when their claimed hash matches', async t => {
  const f = await artifactFixture(t), item = f.record.findings[0];
  await writeFile(path.join(f.outer, 'outside.log'), 'normal tests passed');
  await symlink(path.join(f.outer, 'outside.log'), path.join(f.evidenceRoot, 'linked.log'));
  for (const relative of ['../outside.log', 'linked.log']) {
    item.normalChecks.candidate[0].log = { path: relative, sha256: hash('normal tests passed') };
    await writeFile(f.evidenceFile, JSON.stringify(f.record));
    const result = await loadReviewedEvidence(f.root, f.evidenceFile, { metadataFingerprint: f.fingerprint, findings: [finding], now });
    assert.equal(result.findings[0].status, 'advisory_match');
  }
});

test('read-only repository identity disables repository-configured fsmonitor execution', async t => {
  const f = await artifactFixture(t), marker = path.join(f.outer, 'fsmonitor-executed'), hook = path.join(f.outer, 'fsmonitor.sh');
  await writeFile(hook, `#!/bin/sh\nprintf executed > '${marker}'\n`); await chmod(hook, 0o700);
  await f.git(['config', 'core.fsmonitor', hook]);
  const inventory = await collectLocalEvidence(f.root, { coveredManifests: ['package.json'] });
  assert.equal(inventory.repositoryRevision, f.identity.repositoryRevision); assert.equal(inventory.worktreeClean, true);
  await assert.rejects(readFile(marker), error => error.code === 'ENOENT');
});

test('raw blob identity never executes configured clean filters and still distinguishes clean and changed files', async t => {
  const f = await artifactFixture(t), marker = path.join(f.outer, 'clean-filter-executed'), filter = path.join(f.outer, 'clean-filter.sh');
  await f.put('.gitattributes', '*.txt filter=evil\n'); await f.put('tracked.txt', 'before!!\n');
  await f.git(['add', '.gitattributes', 'tracked.txt']); await f.git(['commit', '-qm', 'Declare synthetic clean filter']);
  await writeFile(filter, `#!/bin/sh\nprintf executed > '${marker}'\ncat\n`); await chmod(filter, 0o700);
  await f.git(['config', 'filter.evil.clean', `sh '${filter}'`]);
  const clean = await collectLocalEvidence(f.root, { coveredManifests: ['package.json'] });
  assert.equal(clean.worktreeClean, true); assert.equal(clean.worktreeIdentityMethod, 'read_only_index_tree_and_raw_blob_hashes');
  await assert.rejects(readFile(marker), error => error.code === 'ENOENT');
  await f.put('tracked.txt', 'changed!\n');
  const changed = await collectLocalEvidence(f.root, { coveredManifests: ['package.json'] });
  assert.equal(changed.worktreeClean, false); assert.equal(changed.worktreeReason, 'raw_tracked_content_differs_from_commit');
  await assert.rejects(readFile(marker), error => error.code === 'ENOENT');
  await f.put('tracked.txt', 'before!!\n');
  assert.equal((await collectLocalEvidence(f.root, { coveredManifests: ['package.json'] })).worktreeClean, true);
  await assert.rejects(readFile(marker), error => error.code === 'ENOENT');
});

test('raw identity refuses staged changes, untracked files, tracked symlinks and repository subdirectory scope', async t => {
  const f = await artifactFixture(t);
  await f.put('untracked.js', 'uncommitted source');
  assert.equal((await collectLocalEvidence(f.root)).worktreeReason, 'untracked_files_present');
  await f.git(['add', 'untracked.js']);
  assert.equal((await collectLocalEvidence(f.root)).worktreeReason, 'index_differs_from_commit');
  await f.git(['commit', '-qm', 'Commit synthetic source']);
  await symlink('untracked.js', path.join(f.root, 'linked.js')); await f.git(['add', 'linked.js']); await f.git(['commit', '-qm', 'Track synthetic symlink']);
  const linked = await collectLocalEvidence(f.root);
  assert.equal(linked.worktreeClean, null); assert.equal(linked.worktreeReason, 'symlink_or_submodule_requires_review');
  await mkdir(path.join(f.root, 'subproject'));
  const subproject = await collectLocalEvidence(path.join(f.root, 'subproject'));
  assert.equal(subproject.worktreeClean, null); assert.equal(subproject.worktreeReason, 'selected_directory_is_not_the_repository_root');
});
