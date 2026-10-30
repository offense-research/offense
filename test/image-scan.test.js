import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { runImageScan, verifyImageArchive } from '../agent/image-scan.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-image-scan-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifactPath = path.join(root, 'image.tar'), bytes = Buffer.from('synthetic-image-archive');
  await writeFile(artifactPath, bytes);
  return { root, artifactPath, reportPath: path.join(root, 'trivy.json'),
    sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length };
}

test('image adapter verifies bytes then calls offline Trivy image scan with fixed arguments', async t => {
  const input = await fixture(t);
  let invoked = 0;
  const result = await runImageScan({ ...input, execute(command, args, options) {
    invoked++;
    assert.equal(command, 'trivy');
    assert.deepEqual(args.slice(0, 3), ['image', '--input', input.artifactPath]);
    for (const flag of ['--offline-scan', '--skip-db-update', '--skip-java-db-update']) assert.ok(args.includes(flag));
    assert.deepEqual(args.slice(args.indexOf('--scanners'), args.indexOf('--scanners') + 2), ['--scanners', 'vuln']);
    assert.ok(options.timeout <= 210000);
    assert.deepEqual(options.stdio, ['ignore', 'ignore', 'ignore']);
    writeFileSync(input.reportPath, JSON.stringify({ SchemaVersion: 2, ArtifactType: 'container_image', Results: [{ Target: 'image', Vulnerabilities: [] }] }));
    return { status: 0 };
  } });
  assert.equal(invoked, 1);
  assert.equal(result.complete, true);
  assert.equal(result.report.Results.length, 1);
});

test('image adapter rejects digest or size mismatch before invoking Trivy', async t => {
  const input = await fixture(t);
  const execute = () => { throw new Error('Trivy should not run'); };
  await assert.rejects(runImageScan({ ...input, sha256: '0'.repeat(64), execute }), /checksum/);
  await assert.rejects(runImageScan({ ...input, size: input.size + 1, execute }), /size/);
  await assert.rejects(verifyImageArchive(input.artifactPath, { sha256: input.sha256, size: 80 * 1024 * 1024 + 1 }), /metadata/);
});

test('nonzero scanner exit or malformed report never yields a complete image result', async t => {
  const input = await fixture(t);
  const run = async (content, status) => runImageScan({ ...input, execute() {
    writeFileSync(input.reportPath, content);
    return { status };
  } });
  assert.equal((await run(JSON.stringify({ SchemaVersion: 2, ArtifactType: 'container_image', Results: [] }), 2)).complete, false);
  await assert.rejects(run('{"SchemaVersion":2}', 0), /invalid/);
  assert.ok((await readFile(input.artifactPath)).length > 0);
});

test('package-free container images can have no Results array', async t => {
  const input = await fixture(t);
  const result = await runImageScan({ ...input, execute() {
    writeFileSync(input.reportPath, JSON.stringify({ SchemaVersion: 2, ArtifactType: 'container_image' }));
    return { status: 0 };
  } });
  assert.equal(result.complete, true);
  assert.equal(result.report.Results, undefined);
});
