import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, lstat, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { prepareSourceRelease } from '../scripts/prepare-source-release.mjs';

test('source export excludes private history, hashes exact bytes and fails closed on unsafe inputs', async t => {
  const scratch = await mkdtemp(path.join(tmpdir(), 'offense-export-test-'));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const candidate = path.join(scratch, 'candidate');
  const result = await prepareSourceRelease(candidate);
  assert.equal(result.publicationApproved, false);
  const manifest = JSON.parse(await readFile(path.join(candidate, 'SOURCE-RELEASE.json')));
  const planning = await import(pathToFileURL(path.join(candidate, 'shared/offense-planning.js')).href);
  assert.match(planning.targetSelectionEvidence({ targetVersion: '1.0.1' }).reason, /not established/);
  assert.equal(manifest.releaseType, 'source-only');
  assert.equal(manifest.publicationApproved, false);
  assert.equal(manifest.artifactPublicationApproved, false);
  assert.equal(manifest.hostedComplianceVerified, false);
  assert.ok(!manifest.blockers.includes('artwork-license-approval'));
  assert.ok(!manifest.blockers.includes('project-rules-provenance'));
  assert.ok(!manifest.blockers.includes('copyleft-compliance-review'));
  for (const blocker of ['private-security-reporting', 'exact-snapshot-publication-approval']) {
    assert.ok(manifest.blockers.includes(blocker));
  }
  const deferred = ['agent/mobsf-offline-policy.py', 'agent/assessment-network-tls.py',
    'agent/assessment-network.mjs', 'agent/assessment-offline.mjs',
    'agent/assessment-mobile.Dockerfile', 'agent/assessment-mobile.Dockerfile.dockerignore',
    'agent/assessment-network.Dockerfile', 'agent/assessment-network.Dockerfile.dockerignore',
    'agent/assessment-offline.Dockerfile', 'agent/assessment-offline.Dockerfile.dockerignore',
    'test/assessment-network.test.js', 'test/assessment-network-tls.test.js',
    'test/assessment-offline.test.js', 'test/mobsf-offline-policy.test.js', 'test/discovery-trust.test.js'];
  for (const file of deferred) {
    assert.ok(manifest.excludedPaths.includes(file));
    await assert.rejects(lstat(path.join(candidate, file)), { code: 'ENOENT' });
  }
  for (const file of ['licenses/GPL-3.0.txt', 'licenses/AGPL-3.0.txt']) {
    assert.deepEqual(await readFile(path.join(candidate, file)), await readFile(new URL(`../${file}`, import.meta.url)));
  }
  for (const file of manifest.files) {
    assert.equal(createHash('sha256').update(await readFile(path.join(candidate, file.path))).digest('hex'), file.sha256);
  }
  for (const omitted of ['.git', '.env', 'docs/e2e', 'docs/support', 'docs/remediation', 'config/cloudflare-agent-clients.json',
    'public/downloads/offense-cli.tgz', 'site/public/figma', 'site/src/reference-diagrams.js'])
    await assert.rejects(lstat(path.join(candidate, omitted)), { code: 'ENOENT' });
  assert.equal(JSON.parse(await readFile(path.join(candidate, 'package.json'))).private, true);
  assert.equal(JSON.parse(await readFile(path.join(candidate, 'site/wrangler.jsonc'))).account_id, undefined);
  await assert.rejects(prepareSourceRelease(candidate), { code: 'EEXIST' });
  const run = promisify(execFile);
  const exportedScript = path.join(candidate, 'scripts/prepare-source-release.mjs');
  const output = path.join(scratch, 'reexport');
  const allowedPath = path.join(candidate, 'config/source-release-files.json');
  const allowed = await readFile(allowedPath);
  for (const forbidden of ['../escape', 'scanner.tar', 'scanner.tar.gz', 'scanner.whl', 'scanner.exe', ...deferred,
    { source: 'agent/mobsf-offline-policy.py', destination: 'agent/renamed-policy.py' },
    { source: 'agent/assessment-network-tls.py', destination: 'agent/renamed-tls.py' }]) {
    await writeFile(allowedPath, JSON.stringify([...JSON.parse(allowed), forbidden]));
    await assert.rejects(run(process.execPath, [exportedScript, output]), /Forbidden source-release path/);
    await assert.rejects(lstat(output), { code: 'ENOENT' });
  }
  for (const license of ['licenses/GPL-3.0.txt', 'licenses/AGPL-3.0.txt']) {
    await writeFile(allowedPath, JSON.stringify(JSON.parse(allowed).filter(entry => entry !== license)));
    await assert.rejects(run(process.execPath, [exportedScript, output]), /Missing release resource: licenses\//);
    await assert.rejects(lstat(output), { code: 'ENOENT' });
  }
  await writeFile(allowedPath, allowed);
  const source = path.join(candidate, 'docs/public-readme.md'), original = await readFile(source);
  await rm(source); await symlink(path.join(scratch, 'outside'), source);
  await assert.rejects(run(process.execPath, [exportedScript, output]), /Release symlink/);
  await rm(source); await writeFile(source, original);
  const synthetic = 'gh' + 'p_' + 'z9'.repeat(20);
  await writeFile(source, synthetic);
  await assert.rejects(run(process.execPath, [exportedScript, output]), error => {
    assert.ok(!error.stderr.includes(synthetic));
    return /Potential credential requires review/.test(error.stderr);
  });
  await assert.rejects(lstat(output), { code: 'ENOENT' });
});
