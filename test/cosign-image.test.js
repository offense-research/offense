import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { runCosignImage } from '../agent/cosign-image.mjs';

function entry(name, content = '', type = '0') {
  const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const header = Buffer.alloc(512);
  header.write(name, 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  header.write('00000000000\0', 136);
  header.fill(32, 148, 156);
  header.write(type, 156);
  header.write('ustar\0', 257);
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}

function archive(extra = []) {
  const manifest = JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json' });
  const hash = createHash('sha256').update(manifest).digest('hex');
  const data = Buffer.concat([
    entry('oci-layout', '{"imageLayoutVersion":"1.0.0"}'),
    entry('index.json', JSON.stringify({ schemaVersion: 2, manifests: [{ digest: `sha256:${hash}` }] })),
    entry(`blobs/sha256/${hash}`, manifest),
    ...extra,
    Buffer.alloc(1024)
  ]);
  return { bytes: gzipSync(data), digest: `sha256:${hash}` };
}

test('Cosign verifies exact signer policy and digest, returning no raw certificate data', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-cosign-test-'));
  try {
    const { bytes, digest } = archive(), archivePath = path.join(root, 'saved-image.tar.gz');
    const reportPath = path.join(root, 'result.json');
    await writeFile(archivePath, bytes);
    const identity = 'https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main';
    const issuer = 'https://token.actions.githubusercontent.com';
    const secret = 'raw-certificate-must-not-escape';
    const result = await runCosignImage({ archivePath, expectedDigest: digest, expectedIdentity: identity,
      expectedIssuer: issuer, reportPath, tempRoot: root, execute: (binary, args) => {
        assert.ok(args.includes('--local-image'));
        assert.ok(args.includes('--offline=true'));
        assert.ok(args.includes('--check-claims=true'));
        assert.ok(args.includes(`--certificate-identity=${identity}`));
        assert.ok(args.includes(`--certificate-oidc-issuer=${issuer}`));
        assert.ok(!args.some(arg => arg.includes('regexp')));
        return { status: 0, stdout: JSON.stringify([{ critical: { image: { 'docker-manifest-digest': digest } }, cert: secret }]) };
      } });
    assert.equal(result.status, 'complete');
    assert.equal(result.verified.digest, digest);
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.ok(!(await readFile(reportPath, 'utf8')).includes(secret));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Cosign rejects an unsafe archive before executing the verifier', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-cosign-unsafe-'));
  try {
    const { digest } = archive();
    const archivePath = path.join(root, 'archive.tar.gz');
    await writeFile(archivePath, gzipSync(Buffer.concat([entry('../outside', 'unsafe'), Buffer.alloc(1024)])));
    const result = await runCosignImage({ archivePath, expectedDigest: digest, expectedIdentity: 'user@example.com',
      expectedIssuer: 'https://example.com', tempRoot: root,
      execute: () => { throw new Error('Verifier must not see unsafe archives'); } });
    assert.equal(result.status, 'failed');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Cosign refuses success when the verified claim does not match the requested digest', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-cosign-digest-'));
  try {
    const { bytes, digest } = archive(), archivePath = path.join(root, 'archive.tar.gz');
    await writeFile(archivePath, bytes);
    const result = await runCosignImage({ archivePath, expectedDigest: digest, expectedIdentity: 'user@example.com',
      expectedIssuer: 'https://example.com', tempRoot: root,
      execute: () => ({ status: 0, stdout: JSON.stringify([{ critical: { image: { 'docker-manifest-digest': `sha256:${'0'.repeat(64)}` } } }]) }) });
    assert.equal(result.status, 'failed');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Cosign rejects wildcard signer policies', async () => {
  await assert.rejects(runCosignImage({ archivePath: '/tmp/image.tgz', expectedDigest: `sha256:${'a'.repeat(64)}`,
    expectedIdentity: '*', expectedIssuer: 'https://example.com' }), /exact signer/);
});
