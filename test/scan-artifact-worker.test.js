import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { uploadScanArtifact } from '../workers/artifact-upload.js';
import { scanController, validateScanArtifact, scanRunnerInput } from '../workers/scan-container.js';

class TestFixedLengthStream {
  constructor(size) {
    assert.ok(Number.isSafeInteger(size) && size > 0);
    const stream = new TransformStream();
    this.readable = stream.readable;
    this.writable = stream.writable;
  }
}
const upload = (request, env, state) => uploadScanArtifact(request, env, state,
  { fixedLengthStream: TestFixedLengthStream });

const content = Buffer.from('safe synthetic image archive bytes');
const sha256 = createHash('sha256').update(content).digest('hex');
const checksum = Uint8Array.from(Buffer.from(sha256, 'hex')).buffer;
const artifact = { kind: 'image-tar', objectKey: `scan/${'a'.repeat(16)}/${'b'.repeat(32)}`, size: content.byteLength, sha256 };
const token = `purple_scan_${'a'.repeat(64)}`;

function uploadRequest(overrides = {}) {
  return new Request(overrides.url || 'https://app.example.com/v1/artifacts', { method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream',
      'content-length': String(content.byteLength), 'x-purple-artifact-kind': 'image-tar',
      'x-content-sha256': sha256, ...overrides.headers }, body: overrides.body || content });
}

test('artifact upload authenticates before body, checks R2 digest and finishes the reservation', async () => {
  const calls = [];
  const bucket = { async put(key, stream, options) {
    calls.push('put'); assert.equal(key, artifact.objectKey);
    assert.equal(Buffer.from(options.sha256).toString('hex'), sha256);
    const received = Buffer.from(await new Response(stream).arrayBuffer());
    assert.deepEqual(received, content);
    return { size: received.byteLength, checksums: { sha256: checksum } };
  }, async delete() { calls.push('delete'); } };
  const state = { async beginArtifactUpload(receivedToken, metadata) {
    calls.push('begin'); assert.equal(receivedToken, token); assert.equal(metadata.sha256, sha256);
    return { id: 'c'.repeat(32), objectKey: artifact.objectKey };
  }, async finishArtifactUpload(receivedToken, id, size) {
    calls.push('finish'); assert.equal(receivedToken, token); assert.equal(id, 'c'.repeat(32)); assert.equal(size, content.byteLength);
    return { id, kind: 'image-tar', size, sha256 };
  }, async abandonArtifactUpload() { calls.push('abandon'); } };
  const response = await upload(uploadRequest(), { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state);
  assert.equal(response.status, 201);
  assert.deepEqual(calls, ['begin', 'put', 'finish']);
  assert.equal((await response.json()).sha256, sha256);
});

test('artifact upload rejects unauthorized requests without consuming bytes and cleans failed uploads', async () => {
  const unauthorized = uploadRequest();
  let writes = 0;
  const bucket = { async put() { writes++; }, async delete() { writes++; } };
  const state = { async beginArtifactUpload() { throw Object.assign(new Error('secret internal detail'), { status: 401 }); } };
  const denied = await upload(unauthorized, { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state);
  assert.equal(denied.status, 401); assert.equal(unauthorized.bodyUsed, false); assert.equal(writes, 0);
  assert.ok(!(await denied.text()).includes('secret internal detail'));

  const calls = [];
  const shortRequest = uploadRequest({ headers: { 'content-length': String(content.byteLength + 1) } });
  const cleanup = { async beginArtifactUpload() { return { id: 'c'.repeat(32), objectKey: artifact.objectKey }; },
    async abandonArtifactUpload() { calls.push('abandon'); } };
  const failedBucket = { async put(_key, stream) { await new Response(stream).arrayBuffer(); },
    async delete(key) { assert.equal(key, artifact.objectKey); calls.push('delete'); } };
  const failed = await upload(shortRequest, { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: failedBucket }, cleanup);
  assert.equal(failed.status, 400); assert.deepEqual(calls, ['delete', 'abandon']);
  assert.equal((await upload(uploadRequest({ headers: { origin: 'https://evil.example' } }),
    { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state)).status, 404);
  assert.equal((await upload(uploadRequest({ url: 'https://ingest.example.com/v1/artifacts' }),
    { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state)).status, 404);
  assert.equal((await upload(uploadRequest({ url: 'https://app.example.com:444/v1/artifacts' }),
    { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state)).status, 404);
  assert.equal((await upload(uploadRequest({ headers: { 'x-purple-artifact-kind': 'unknown' } }),
    { PUBLIC_URL: 'https://app.example.com', SCAN_ARTIFACTS: bucket }, state)).status, 400);
});

test('agent transfers and verifies an artifact before starting its offline scanner', async () => {
  const operations = [];
  const kv = new Map();
  let transferred, runnerInput;
  const container = { images: { scan: 'scanner-image' }, start(options) {
    operations.push('start'); assert.equal(options.enableInternet, false);
  }, async setInactivityTimeout() {}, async exec(argv, options = {}) {
    if (argv[0] === 'mkdir') return { output: async () => ({ exitCode: 0 }) };
    if (argv[0] === 'dd') {
      transferred = Buffer.from(await new Response(options.stdin).arrayBuffer());
      operations.push('copy'); return { output: async () => ({ exitCode: 0 }) };
    }
    if (argv[0] === 'sha256sum') return { output: async () => ({ exitCode: 0,
      stdout: new TextEncoder().encode(`${createHash('sha256').update(transferred).digest('hex')}  ${argv[1]}\n`) }) };
    runnerInput = JSON.parse(await new Response(options.stdin).text()); operations.push('runner');
    return { output: async () => ({ exitCode: 0 }) };
  }, async destroy() { operations.push('destroy'); } };
  const bucket = { async get(key) { assert.equal(key, artifact.objectKey);
    return { size: content.byteLength, body: new Response(content).body };
  }, async delete(key) { assert.equal(key, artifact.objectKey); operations.push('delete'); } };
  const ctx = { container, storage: { kv: { get: key => kv.get(key), put: (key, value) => kv.set(key, value) }, async setAlarm() {} } };
  const input = { files: [], tools: ['trivy-image'], artifact };
  assert.equal((await scanController(ctx, { SCAN_ARTIFACTS: bucket }).start(input)).status, 'running');
  assert.deepEqual(transferred, content);
  assert.deepEqual(operations, ['start', 'copy', 'delete', 'runner']);
  assert.deepEqual(runnerInput.artifact, { kind: 'image-tar', size: content.byteLength,
    sha256, path: '/tmp/purple-scan/artifact' });
  assert.deepEqual(runnerInput.files, []);
  assert.equal(kv.get('scan').status, 'running');
});

test('agent rejects forged artifact metadata and fails closed on R2 checksum mismatch', async () => {
  assert.throws(() => validateScanArtifact({ files: [], tools: ['trivy-image'],
    artifact: { ...artifact, objectKey: '../secrets' } }), /Invalid scanner artifact/);
  assert.throws(() => validateScanArtifact({ files: [], tools: ['gitleaks-history'], artifact }), /Invalid scanner artifact/);
  const packageArtifact = { ...artifact, kind: 'package-archive', packageName: '@purple/example', packageVersion: '1.2.3' };
  assert.equal(validateScanArtifact({ files: [], tools: ['guarddog-npm'], artifact: packageArtifact }).packageName, '@purple/example');
  assert.deepEqual(scanRunnerInput([], ['guarddog-npm'], packageArtifact).artifact, {
    kind: 'package-archive', size: content.byteLength, sha256, path: '/tmp/purple-scan/artifact',
    packageName: '@purple/example', packageVersion: '1.2.3'
  });
  assert.throws(() => validateScanArtifact({ files: [], tools: ['guarddog-npm'],
    artifact: { ...packageArtifact, packageVersion: '1.2.3; touch /tmp/owned' } }), /Invalid scanner package coordinates/);
  const signer = { ...artifact, kind: 'cosign-save', expectedDigest: `sha256:${sha256}`,
    expectedIdentity: 'https://github.com/purple/repo/.github/workflows/release.yml@refs/heads/main',
    expectedIssuer: 'https://token.actions.githubusercontent.com' };
  assert.equal(validateScanArtifact({ files: [], tools: ['cosign-image'], artifact: signer }).expectedIdentity, signer.expectedIdentity);
  assert.equal(scanRunnerInput([], ['cosign-image'], signer).artifact.expectedDigest, signer.expectedDigest);
  assert.throws(() => validateScanArtifact({ files: [], tools: ['cosign-image'],
    artifact: { ...signer, expectedIdentity: '.*' } }), /Invalid image signer policy/);
  assert.throws(() => validateScanArtifact({ files: [], tools: ['cosign-image'],
    artifact: { ...signer, expectedIssuer: 'http://issuer.example.com' } }), /Invalid image signer policy/);
  const har = { ...artifact, kind: 'web-har', target: 'https://example.com' };
  assert.equal(validateScanArtifact({ files: [], tools: ['zap-passive-har'], artifact: har }).target, har.target);
  assert.equal(scanRunnerInput([], ['zap-passive-har'], har).artifact.target, har.target);
  assert.throws(() => validateScanArtifact({ files: [], tools: ['zap-passive-har'],
    artifact: { ...har, target: 'https://127.0.0.1' } }), /Invalid passive web scan origin/);
  let started = false, destroyed = false, deleted = false;
  const ctx = { container: { images: { scan: 'scanner-image' }, start() { started = true; },
    async setInactivityTimeout() {}, async destroy() { destroyed = true; } },
    storage: { kv: { get: () => null, put() {} }, async setAlarm() {} } };
  const bucket = { async get() { return { size: content.byteLength, checksums: { sha256: Buffer.alloc(32) }, body: new Response(content).body }; },
    async delete() { deleted = true; } };
  await assert.rejects(scanController(ctx, { SCAN_ARTIFACTS: bucket }).start({ files: [], tools: ['trivy-image'], artifact }), /isolated scanner/);
  assert.equal(started, true); assert.equal(destroyed, true); assert.equal(deleted, true);
});
