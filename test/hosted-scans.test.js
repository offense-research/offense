import { request as httpRequest } from 'node:http';
import { createHash } from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import express from 'express';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { sourceFiles } from '../server/scan-input.js';
import { normalizeFindings } from '../agent/scan-runner.mjs';
import { scanController } from '../workers/scan-container.js';
import { uploadScanArtifact } from '../workers/artifact-upload.js';

class TestFixedLengthStream {
  constructor() {
    const stream = new TransformStream();
    this.readable = stream.readable;
    this.writable = stream.writable;
  }
}
const upload = (request, env, state) => uploadScanArtifact(request, env, state,
  { fixedLengthStream: TestFixedLengthStream });

const source = { files: [{ path: 'src/app.js', content: 'eval(request.input)' }] };
function fixture(options = {}) {
  const db = options.db || new DatabaseSync(':memory:'); let result = { status: 'running' }, calls = 0, destroyed = 0;
  const sandbox = { async start(input) { calls++; assert.equal(input.files[0].content, source.files[0].content); return { status: 'running' }; },
    async get() { return result; }, async destroy() { destroyed++; } };
  const scans = createHostedScans(db, { sandbox, encrypt: value => `encrypted:${Buffer.from(value).toString('base64')}`, decrypt: value => Buffer.from(value.slice(10), 'base64').toString(), ...options });
  const key = scans.issueKey('workspace-a', 'developer-a'), principal = scans.authenticate(key.token);
  return { db, scans, key, principal, finish: value => { result = value; }, calls: () => calls, destroyed: () => destroyed };
}

test('source validation blocks traversal, filesystem collisions, duplicate paths and oversized/binary uploads', () => {
  for (const name of ['../escape', '/root/key', '.git/config', 'a//b', 'a/../b', 'a\\b', 'a\u0000b']) assert.throws(() => sourceFiles([{ path: name, content: 'x' }]));
  assert.throws(() => sourceFiles([{ path: 'a', content: 'x' }, { path: 'a/b', content: 'x' }]));
  assert.throws(() => sourceFiles([source.files[0], source.files[0]]));
  assert.throws(() => sourceFiles([{ path: 'x', content: '\0' }]));
  assert.throws(() => sourceFiles([{ path: 'x', content: 'x'.repeat(262145) }]));
});

test('jobs survive restart, encrypt queued source, deduplicate submissions, preserve usage and isolate tenants', async () => {
  const f = fixture();
  assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM scan_keys').all()).includes(f.key.token));
  const job = f.scans.create(f.principal, source, 'request-0001');
  assert.equal(f.scans.create(f.principal, source, 'request-0001').id, job.id);
  assert.throws(() => f.scans.create(f.principal, { files: [{ path: 'src/app.js', content: 'changed' }] }, 'request-0001'), /different source/);
  assert.equal(f.scans.get(job.id, 'workspace-b'), null);
  assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM scan_sources').all()).includes('eval('));
  await f.scans.dispatch(); assert.equal(f.calls(), 1);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
  f.finish({ status: 'completed', tools: ['opengrep', 'trivy-vuln', 'gitleaks'].map(name => ({ name, status: 'complete' })), findings: [] });
  await f.scans.dispatch();
  const reloaded = fixture({ db: f.db });
  assert.equal(reloaded.scans.get(job.id, 'workspace-a').status, 'completed');
  assert.deepEqual(reloaded.scans.get(job.id, 'workspace-a').selectedTools, ['opengrep', 'trivy-vuln', 'gitleaks']);
  assert.equal(reloaded.scans.get(job.id, 'workspace-a').usage.files, 1);
  assert.equal(f.destroyed(), 1);
});

test('selected tools persist, bind idempotency, and validate SBOM input', async () => {
  const f = fixture();
  const selected = { ...source, tools: ['trivy-config', 'opengrep'] };
  const job = f.scans.create(f.principal, selected, 'selection-0001');
  assert.deepEqual(job.selectedTools, ['opengrep', 'trivy-config']);
  assert.equal(f.scans.create(f.principal, { ...source, tools: ['opengrep', 'trivy-config'] }, 'selection-0001').id, job.id);
  assert.throws(() => f.scans.create(f.principal, { ...source, tools: ['opengrep'] }, 'selection-0001'), /different source files or tools/);
  await f.scans.dispatch();
  assert.deepEqual(f.scans.get(job.id, 'workspace-a').selectedTools, ['opengrep', 'trivy-config']);
  for (const tools of [[], ['unknown'], ['opengrep', 'opengrep'], ['trivy-sbom', 'gitleaks']]) {
    assert.throws(() => f.scans.create(f.principal, { ...source, tools }, `invalid-${Math.random()}`));
  }
  assert.throws(() => f.scans.create(f.principal, { files: [{ path: 'bill.json', content: '{}' }], tools: ['trivy-sbom'] }, 'sbom-invalid'), /CycloneDX or SPDX/);
  const sbom = { files: [{ path: 'bill.cdx.json', content: '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' }], tools: ['trivy-sbom'] };
  const second = f.scans.create(f.principal, sbom, 'sbom-valid01');
  assert.deepEqual(second.selectedTools, ['trivy-sbom']);
});

test('a self-hosted runtime disables unsupported tools before quotes or source retention', () => {
  const db = new DatabaseSync(':memory:');
  try {
    const f = fixture({ db, sandbox: { tools: ['opengrep', 'zizmor'] }, metering: createScanMetering(db) });
    assert.deepEqual(f.scans.tools('workspace-a').tools.filter(tool => tool.availability === 'available').map(tool => tool.id).sort(), ['opengrep', 'zizmor']);
    assert.throws(() => f.scans.quote({ tools: ['trivy-vuln'], inputBytes: 10, fileCount: 1 }, 'workspace-a'), /not enabled/);
    assert.throws(() => f.scans.create(f.principal, { ...source, tools: ['trivy-vuln'] }, 'unsupported-source'), /not enabled/);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
    assert.equal(f.scans.quote({ tools: ['opengrep'], inputBytes: 10, fileCount: 1 }, 'workspace-a').maximumMicros, 0);
    assert.equal(f.scans.create(f.principal, { ...source, tools: ['opengrep'] }, 'supported-source').status, 'queued');
  } finally { db.close(); }
});

test('revocation, deadlines, partial scans and failed container starts never become clean results', async () => {
  let timestamp = 1000000;
  const f = fixture({ now: () => timestamp });
  const job = f.scans.create(f.principal, source, 'request-0002');
  f.db.prepare('UPDATE scan_keys SET revoked_at = 1').run();
  assert.equal(f.scans.authenticate(f.key.token), null);
  await f.scans.dispatch(); assert.equal(f.scans.get(job.id, 'workspace-a').status, 'failed');
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
  const other = f.scans.issueKey('workspace-a', 'developer-a'), principal = f.scans.authenticate(other.token);
  const partial = f.scans.create(principal, source, 'request-0003'); await f.scans.dispatch();
  f.finish({ status: 'partial', tools: [{ name: 'trivy', status: 'failed' }], findings: [] });
  await f.scans.dispatch(); assert.equal(f.scans.get(partial.id, 'workspace-a').status, 'partial');
  const expired = f.scans.create(principal, source, 'request-0004'); timestamp += 31 * 60000;
  await f.scans.dispatch(); assert.equal(f.scans.get(expired.id, 'workspace-a').status, 'failed');
});

test('workflow scan selection persists, quotes explicitly, and remains outside confirmed discovery metrics', async () => {
  const f = fixture();
  const input = { files: [{ path: '.github/workflows/ci.yml', content: 'name: ci\non: push\njobs: {}\n' }], tools: ['zizmor'] };
  const job = f.scans.create(f.principal, input, 'workflow-tool-001');
  assert.deepEqual(job.selectedTools, ['zizmor']);
  assert.equal(f.scans.create(f.principal, input, 'workflow-tool-001').id, job.id);
  const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
  const meter = createScanMetering(f.db, { enabled: true, priceByToolMicros: prices });
  assert.equal(meter.quote({ tools: ['zizmor'], inputBytes: Buffer.byteLength(input.files[0].content), fileCount: 1 }).maximumMicros, 25000);
  const tables = f.db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(row => row.name);
  assert.ok(!tables.includes('vulnerability_discoveries'));
  f.db.close();
});

test('API authenticates before parsing uploads and exposes no cookies or cross-workspace findings', async t => {
  const f = fixture(), app = express(); registerScanApi(app, { scans: f.scans });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/scans`;
  const headers = { authorization: `Bearer ${f.key.token}`, 'content-type': 'application/json', 'idempotency-key': 'request-0005' };
  assert.equal((await fetch(`http://127.0.0.1:${server.address().port}/v1/tools`)).status, 401);
  const catalog = await (await fetch(`http://127.0.0.1:${server.address().port}/v1/tools`, { headers })).json();
  assert.equal(catalog.schemaVersion, 2);
  assert.deepEqual(catalog.tools.map(tool => tool.id), ['opengrep', 'trivy-vuln', 'gitleaks', 'trivy-config', 'trivy-sbom',
    'trivy-image', 'gitleaks-history', 'guarddog-npm', 'guarddog-pypi', 'spectral-owasp', 'cosign-image', 'zap-passive-har', 'zizmor', 'osv-scanner', 'semgrep',
    'k8s-deprecations', 'k8s-manifest-validate',
    'nuclei', 'prowler-cloudflare', 'schemathesis', 'zap-api', 'sslyze', 'katana', 'httpx', 'openssf-scorecard',
    'checkov', 'trufflehog-verified', 'mobsf-static']);
  assert.equal(catalog.limits.totalBytes, 4 * 1024 * 1024);
  assert.equal((await fetch(url, { method: 'POST', body: '{invalid' })).status, 401);
  assert.equal((await fetch(url, { method: 'POST', headers: { ...headers, origin: 'https://other.test' }, body: JSON.stringify(source) })).status, 403);
  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(source) });
  assert.equal(response.status, 202); assert.equal(response.headers.get('set-cookie'), null);
  const job = await response.json(), other = f.scans.issueKey('workspace-b', 'developer-b');
  assert.equal((await fetch(`${url}/${job.id}`, { headers: { authorization: `Bearer ${other.token}` } })).status, 404);
  assert.equal((await fetch(url, { method: 'POST', headers, body: JSON.stringify({ files: [{ path: 'x', content: 'x'.repeat(7_000_000) }] }) })).status, 413);
});

function artifactFixture() {
  const db = new DatabaseSync(':memory:'), objects = new Map(), deleted = [], starts = [];
  let timestamp = 1000, result = { status: 'running' }, destroys = 0, failDelete = false;
  const bucket = {
    async put(key, bytes) { objects.set(key, bytes); },
    async head(key) { const bytes = objects.get(key); return bytes ? { size: bytes.length } : null; },
    async delete(key) { if (failDelete) throw new Error('temporary bucket error'); deleted.push(key); objects.delete(key); }
  };
  const sandbox = { async start(input) { starts.push(input); return { status: 'running' }; },
    async get() { return result; }, async destroy() { destroys++; } };
  const metering = createScanMetering(db, { now: () => timestamp });
  const scans = createHostedScans(db, { sandbox, artifacts: bucket,
    encrypt: value => value, decrypt: value => value, metering, now: () => timestamp });
  const first = scans.issueKey('workspace-a', 'developer-a'), principal = scans.authenticate(first.token);
  return { db, bucket, objects, deleted, starts, scans, metering, first, principal,
    clock(value) { timestamp = value; }, finish(value) { result = value; }, failDeletes(value) { failDelete = value; },
    destroys: () => destroys };
}

function stagedArtifact(f, key = f.first, metadata = { kind: 'image-tar', size: 4, sha256: 'a'.repeat(64) }) {
  const begun = f.scans.beginArtifactUpload(key.token, metadata);
  return { ...f.scans.finishArtifactUpload(key.token, begun.id, metadata.size), objectKey: begun.objectKey };
}

test('binary artifact jobs preserve tenant, key, idempotency and quota boundaries', async () => {
  const f = artifactFixture();
  const image = stagedArtifact(f);
  await f.bucket.put(image.objectKey, Buffer.from('test'));
  const otherWorkspace = f.scans.issueKey('workspace-b', 'developer-b');
  const secondKey = f.scans.issueKey('workspace-a', 'developer-c');
  assert.throws(() => f.scans.finishArtifactUpload(otherWorkspace.token, image.id, image.size), error => error.status === 409);
  assert.throws(() => f.scans.create(f.scans.authenticate(otherWorkspace.token),
    { artifactId: image.id, tools: ['trivy-image'] }, 'artifact-job-b01'), error => error.status === 404);
  assert.throws(() => f.scans.create(f.scans.authenticate(secondKey.token),
    { artifactId: image.id, tools: ['trivy-image'] }, 'artifact-job-b02'), error => error.status === 404);
  assert.throws(() => f.scans.create(f.principal,
    { artifactId: image.id, files: [], tools: ['trivy-image'] }, 'artifact-job-b03'), /artifact/);
  const job = f.scans.create(f.principal, { artifactId: image.id, tools: ['trivy-image'] }, 'artifact-job-a01');
  assert.equal(job.usage.inputBytes, image.size);
  assert.equal(job.metering.chargeMicros, 0);
  assert.equal(f.scans.create(f.principal, { artifactId: image.id, tools: ['trivy-image'] }, 'artifact-job-a01').id, job.id);
  assert.throws(() => f.scans.create(f.principal, { artifactId: image.id, tools: ['trivy-image'] }, 'artifact-job-a02'), /already used/);
  assert.equal(f.scans.get(job.id, 'workspace-b'), null);
  await f.scans.dispatch();
  assert.equal(f.starts.length, 1);
  assert.deepEqual(f.starts[0].files, []);
  assert.deepEqual(f.starts[0].tools, ['trivy-image']);
  assert.equal(f.starts[0].artifact.kind, 'image-tar');
  assert.equal(f.starts[0].artifact.sha256, image.sha256);
  assert.equal(f.starts[0].artifact.objectKey, image.objectKey);
  f.finish({ status: 'completed', tools: [{ name: 'trivy-image', status: 'complete', durationMs: 120 }], findings: [] });
  await f.scans.dispatch();
  assert.equal(f.scans.get(job.id, 'workspace-a').status, 'completed');
  assert.equal(f.metering.usage(job.id).chargeMicros, 0);
  assert.equal(f.destroys(), 1);
  assert.deepEqual(f.deleted, [image.objectKey]);
  assert.equal(f.objects.has(image.objectKey), false);
});

test('artifact upload quotas, expiry and failed deletion remain fail closed and retryable', async () => {
  const f = artifactFixture();
  const one = f.scans.beginArtifactUpload(f.first.token, { kind: 'git-bundle', size: 2, sha256: 'b'.repeat(64) });
  const two = f.scans.beginArtifactUpload(f.first.token, { kind: 'image-tar', size: 2, sha256: 'c'.repeat(64) });
  await f.bucket.put(one.objectKey, Buffer.from('aa'));
  await f.bucket.put(two.objectKey, Buffer.from('bb'));
  assert.throws(() => f.scans.beginArtifactUpload(f.first.token,
    { kind: 'image-tar', size: 2, sha256: 'd'.repeat(64) }), error => error.status === 429);
  assert.throws(() => f.scans.finishArtifactUpload(f.first.token, one.id, 3), /invalid or expired/);
  const ready = f.scans.finishArtifactUpload(f.first.token, one.id, 2);
  assert.equal(ready.kind, 'git-bundle');
  assert.throws(() => f.scans.finishArtifactUpload(f.first.token, one.id, 2), /invalid or expired/);
  f.failDeletes(true);
  f.clock(1000 + 31 * 60_000);
  assert.throws(() => f.scans.create(f.principal,
    { artifactId: one.id, tools: ['gitleaks-history'] }, 'expired-bundle-01'), /expired/);
  await f.scans.dispatch();
  assert.equal(f.deleted.length, 0);
  f.failDeletes(false);
  await f.scans.dispatch();
  assert.deepEqual(new Set(f.deleted), new Set([one.objectKey, two.objectKey]));
  assert.equal(f.objects.size, 0);
});

test('package artifact jobs bind exact package coordinates to idempotency and dispatch', async () => {
  const f = artifactFixture();
  const archive = stagedArtifact(f, f.first, { kind: 'package-archive', size: 4, sha256: 'd'.repeat(64) });
  assert.throws(() => f.scans.create(f.principal,
    { artifactId: archive.id, tools: ['guarddog-npm'], packageName: 'example', packageVersion: 'latest*' }, 'package-job-001'), /exact package/);
  const input = { artifactId: archive.id, tools: ['guarddog-npm'], packageName: '@example/package', packageVersion: '1.2.3' };
  const job = f.scans.create(f.principal, input, 'package-job-001');
  assert.equal(f.scans.create(f.principal, input, 'package-job-001').id, job.id);
  assert.throws(() => f.scans.create(f.principal,
    { ...input, packageVersion: '1.2.4' }, 'package-job-001'), error => error.status === 409);
  await f.scans.dispatch();
  assert.equal(f.starts[0].artifact.packageName, '@example/package');
  assert.equal(f.starts[0].artifact.packageVersion, '1.2.3');
  assert.deepEqual(f.starts[0].tools, ['guarddog-npm']);
});

test('Cosign jobs require an exact digest and signer policy bound to the scan', async () => {
  const f = artifactFixture();
  const archive = stagedArtifact(f, f.first, { kind: 'cosign-save', size: 4, sha256: 'e'.repeat(64) });
  const policy = { artifactId: archive.id, tools: ['cosign-image'], expectedDigest: `sha256:${'a'.repeat(64)}`,
    expectedIdentity: 'https://github.com/example/repo/.github/workflows/release.yml@refs/heads/main',
    expectedIssuer: 'https://token.actions.githubusercontent.com' };
  assert.throws(() => f.scans.create(f.principal, { ...policy, expectedIdentity: '.*' }, 'cosign-job-001'), /exact image digest/);
  const job = f.scans.create(f.principal, policy, 'cosign-job-001');
  assert.equal(f.scans.create(f.principal, policy, 'cosign-job-001').id, job.id);
  assert.throws(() => f.scans.create(f.principal,
    { ...policy, expectedDigest: `sha256:${'b'.repeat(64)}` }, 'cosign-job-001'), error => error.status === 409);
  await f.scans.dispatch();
  assert.deepEqual(f.starts[0].artifact.expectedDigest, policy.expectedDigest);
  assert.deepEqual(f.starts[0].artifact.expectedIdentity, policy.expectedIdentity);
  assert.deepEqual(f.starts[0].artifact.expectedIssuer, policy.expectedIssuer);
});

test('passive HAR jobs require a canonical HTTPS origin and keep it with the artifact', async () => {
  const f = artifactFixture();
  const archive = stagedArtifact(f, f.first, { kind: 'web-har', size: 4, sha256: 'f'.repeat(64) });
  assert.throws(() => f.scans.create(f.principal,
    { artifactId: archive.id, tools: ['zap-passive-har'], target: 'http://127.0.0.1' }, 'har-job-001'), /public HTTPS origin/);
  const input = { artifactId: archive.id, tools: ['zap-passive-har'], target: 'https://example.com' };
  const job = f.scans.create(f.principal, input, 'har-job-001');
  assert.equal(f.scans.create(f.principal, input, 'har-job-001').id, job.id);
  assert.throws(() => f.scans.create(f.principal,
    { ...input, target: 'https://other.example.com' }, 'har-job-001'), error => error.status === 409);
  await f.scans.dispatch();
  assert.equal(f.starts[0].artifact.target, 'https://example.com');
});

test('revoking an artifact scan key before dispatch fails the job and removes its bytes', async () => {
  const f = artifactFixture();
  const image = stagedArtifact(f);
  await f.bucket.put(image.objectKey, Buffer.from('test'));
  const job = f.scans.create(f.principal, { artifactId: image.id, tools: ['trivy-image'] }, 'revoked-artifact-01');
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(1001, f.first.id);
  await f.scans.dispatch();
  assert.equal(f.scans.get(job.id, 'workspace-a').status, 'failed');
  assert.equal(f.starts.length, 0);
  assert.equal(f.db.prepare('SELECT status FROM scan_artifacts WHERE id = ?').get(image.id).status, 'abandoned');
  assert.equal(f.metering.usage(job.id).chargeMicros, 0);
  await f.scans.dispatch();
  assert.deepEqual(f.deleted, [image.objectKey]);
  assert.equal(f.objects.size, 0);
});

test('raw artifact upload authenticates first, verifies R2 checksum and cleans mismatches', async () => {
  const f = artifactFixture(), bytes = Buffer.from('synthetic-container-archive');
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const bucket = {
    objects: new Map(), deletes: [], corrupt: false, puts: 0,
    async put(key, stream) {
      this.puts++;
      const chunks = [];
      for await (const chunk of stream) chunks.push(Buffer.from(chunk));
      const stored = Buffer.concat(chunks);
      this.objects.set(key, stored);
      const digest = this.corrupt ? '0'.repeat(64) : createHash('sha256').update(stored).digest('hex');
      return { size: stored.length, checksums: { sha256: Uint8Array.from(Buffer.from(digest, 'hex')).buffer } };
    },
    async delete(key) { this.deletes.push(key); this.objects.delete(key); }
  };
  const env = { PUBLIC_URL: 'https://app.example.test', SCAN_ARTIFACTS: bucket };
  const state = { beginArtifactUpload: (token, metadata) => f.scans.beginArtifactUpload(token, metadata),
    finishArtifactUpload: (token, id, size) => f.scans.finishArtifactUpload(token, id, size),
    async abandonArtifactUpload(token, id) { f.scans.abandonArtifactUpload(token, id); } };
  const request = (token = f.first.token, headers = {}) => new Request('https://app.example.test/v1/artifacts', {
    method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/octet-stream',
      'content-length': String(bytes.length), 'x-purple-artifact-kind': 'image-tar',
      'x-content-sha256': sha256, ...headers }, body: bytes
  });
  assert.equal((await upload(request('wrong'), env, state)).status, 401);
  assert.equal(bucket.puts, 0);
  assert.equal((await upload(request(f.first.token, { origin: 'https://evil.test' }), env, state)).status, 404);
  assert.equal(bucket.puts, 0);
  bucket.corrupt = true;
  const mismatch = await upload(request(), env, state);
  assert.equal(mismatch.status, 400);
  assert.equal(bucket.objects.size, 0);
  assert.equal(bucket.deletes.length, 1);
  bucket.corrupt = false;
  const accepted = await upload(request(), env, state);
  assert.equal(accepted.status, 201);
  const artifact = await accepted.json();
  assert.equal(artifact.kind, 'image-tar');
  assert.equal(artifact.sha256, sha256);
  assert.equal(f.db.prepare('SELECT status FROM scan_artifacts WHERE id = ?').get(artifact.id).status, 'ready');
  assert.equal(bucket.objects.size, 1);
});

test('quote and usage endpoints use the scanner ledger and workspace key', async t => {
  const db = new DatabaseSync(':memory:'), f = fixture({ db, metering: createScanMetering(db) });
  const app = express(); registerScanApi(app, { scans: f.scans });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const headers = { authorization: `Bearer ${f.key.token}`, 'content-type': 'application/json' };
  assert.equal((await fetch(`${base}/v1/usage`)).status, 401);
  const quoteResponse = await fetch(`${base}/v1/quotes`, { method: 'POST', headers,
    body: JSON.stringify({ tools: ['trivy-config'], inputBytes: 80, fileCount: 1 }) });
  assert.equal(quoteResponse.status, 200);
  assert.deepEqual((await quoteResponse.json()).toolIds, ['trivy-config']);
  const job = f.scans.create(f.principal, { ...source, tools: ['trivy-config'] }, 'usage-00001');
  const usage = await (await fetch(`${base}/v1/usage`, { headers })).json();
  assert.equal(usage.enabled, false);
  assert.equal(usage.jobs[0].id, job.id);
  assert.equal(usage.jobs[0].metering.state, 'unbilled');
  const catalog = await (await fetch(`${base}/v1/tools`, { headers })).json();
  assert.equal(catalog.billing.enabled, false);
  assert.equal(catalog.tools.find(tool => tool.id === 'trivy-config').basePriceMicros, 0);
  assert.equal(catalog.tools.find(tool => tool.id === 'trivy-config').additionalMiBPriceMicros, 0);
});

test('paid scans require an exact quote bound to server prices before reserving credit', () => {
  const db = new DatabaseSync(':memory:');
  const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  const f = fixture({ db, metering: meter });
  meter.recordVerifiedPurchase({ workspaceId: 'workspace-a', paymentId: 'pay_paid_quote_fixture', amountMicros: 10_000_000 });
  const input = { ...source, tools: ['opengrep'] };
  const quote = f.scans.quote({ tools: input.tools, inputBytes: Buffer.byteLength(source.files[0].content), fileCount: 1 });
  assert.equal(quote.maximumMicros, 25_000);
  assert.throws(() => f.scans.create(f.principal, input, 'paid-quote-1'), /fresh quote/);
  assert.throws(() => f.scans.create(f.principal, { ...input, maxChargeMicros: 0 }, 'paid-quote-2'), /fresh quote/);
  assert.throws(() => f.scans.create(f.principal, { ...input, maxChargeMicros: 50_000 }, 'paid-quote-old'), /fresh quote/);
  const created = f.scans.create(f.principal, { ...input, maxChargeMicros: quote.maximumMicros }, 'paid-quote-3');
  assert.equal(created.metering.quote.maximumMicros, 25_000);
  assert.equal(meter.status('workspace-a').reservedMicros, 25_000);
  assert.equal(f.scans.create(f.principal, input, 'paid-quote-3').id, created.id);
});

test('a completed report missing a selected tool becomes partial coverage', async () => {
  const f = fixture();
  const job = f.scans.create(f.principal, source, 'coverage-0001');
  await f.scans.dispatch();
  f.finish({ status: 'completed', tools: [{ name: 'opengrep', status: 'complete' }], findings: [] });
  await f.scans.dispatch();
  const result = f.scans.get(job.id, 'workspace-a');
  assert.equal(result.status, 'partial');
  assert.match(result.warnings[0], /selected scanner/);
});

test('redaction allowlist drops secret values, snippets, scanner metadata and unsafe paths', () => {
  const secret = 'synthetic-secret-value';
  const findings = normalizeFindings('gitleaks', [{ RuleID: 'example', File: '/tmp/purple-scan/source/key.txt', StartLine: 3, Secret: secret, Match: secret, Fingerprint: secret }]);
  assert.equal(findings[0].file, 'key.txt'); assert.equal(findings[0].line, 3);
  assert.ok(!JSON.stringify(findings).includes(secret));
  assert.deepEqual(normalizeFindings('gitleaks', [{ File: '../outside', Secret: secret }]), []);
});

test('container starts once with no network, runs fixed argv, and destroys itself on cleanup', async () => {
  const store = new Map(); let starts = 0, destroyed = 0, alarm;
  const ctx = { storage: { kv: { get: key => store.get(key), put: (key, value) => store.set(key, value) }, async setAlarm(value) { alarm = value; }, async deleteAlarm() { alarm = null; } },
    container: { images: { scan: 'pinned-scan-image' }, running: false,
      start(options) { starts++; assert.equal(options.enableInternet, false); assert.equal(options.image, 'pinned-scan-image'); this.running = true; },
      async setInactivityTimeout() {}, async exec(argv, options) { assert.deepEqual(argv.slice(0, 4), ['timeout', '--kill-after=5', '660', 'node']); assert.ok(options.stdin); },
      async destroy() { this.running = false; destroyed++; } } };
  const controller = scanController(ctx);
  await controller.start(source); await controller.start(source);
  assert.equal(starts, 1); assert.ok(alarm);
  await controller.destroy(); assert.equal(destroyed, 1); assert.equal(alarm, null);
});

test('workspace queue quotas and durable cleanup retries bound repeated execution', async () => {
  let failures = 1, destroys = 0;
  const db = new DatabaseSync(':memory:');
  const scans = createHostedScans(db, { encrypt: x => x, decrypt: x => x, sandbox: {
    async start() { return { status: 'running' }; },
    async get() { return { status: 'completed', tools: [], findings: [] }; },
    async destroy() { destroys++; if (failures--) throw new Error('Temporary cleanup failure'); }
  } });
  const key = scans.issueKey('w', 'u'), principal = scans.authenticate(key.token);
  scans.create(principal, source, 'queue-0001'); scans.create(principal, source, 'queue-0002');
  assert.throws(() => scans.create(principal, source, 'queue-0003'), error => error.status === 429);
  await scans.dispatch(); await scans.dispatch();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_cleanup').get().n, 1);
  await scans.dispatch();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM scan_cleanup').get().n, 0);
  assert.equal(destroys, 2);
});

test('real app key issuance uses workspace login and origin protection; bearer routes do not create sessions', async t => {
  const { createWorkerApp } = await import('../workers/app-api.js');
  const db = new DatabaseSync(':memory:');
  const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://app.example.test', PURPLE_INGEST_URL: 'https://ingest.example.test' }, schedule() {} });
  db.prepare('INSERT INTO users VALUES (?, ?, ?, ?)').run('u1', '1234', 'fixture-owner', 1);
  db.prepare('INSERT INTO workspaces VALUES (?, ?, ?, ?)').run('w1', '{"company":"Fixture"}', 1, 1);
  db.prepare('INSERT INTO memberships VALUES (?, ?, ?)').run('u1', 'w1', 'owner');
  const session = 'a'.repeat(64);
  db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(session, '{"userId":"u1","workspaceId":"w1"}', 1);
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}`, headers = { cookie: `purple_session=${session}`, 'content-type': 'application/json' };
  const rejected = await fetch(`${url}/v1/scans`, { method: 'POST' }); assert.equal(rejected.status, 401); assert.equal(rejected.headers.get('set-cookie'), null);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1);
  assert.equal((await fetch(`${url}/api/scan-keys`, { method: 'POST', headers: { ...headers, origin: 'https://attacker.test' }, body: '{}' })).status, 403);
  const created = await fetch(`${url}/api/scan-keys`, { method: 'POST', headers, body: '{}' }); assert.equal(created.status, 201);
  const key = await created.json(); assert.match(key.token, /^offense_sk_[a-f0-9]{64}$/);
  const list = await (await fetch(`${url}/api/scan-keys`, { headers })).json(); assert.equal(list.keys.length, 1); assert.ok(!JSON.stringify(list).includes(key.token));
  const ingestStatus = await new Promise((resolve, reject) => { const req = httpRequest(`${url}/v1/scans`, { method: 'POST', headers: { Host: 'ingest.example.test', authorization: `Bearer ${key.token}` } }, res => { res.resume(); resolve(res.statusCode); }); req.on('error', reject); req.end(); });
  assert.equal(ingestStatus, 404);
  assert.equal((await fetch(`${url}/api/scan-keys/${key.id}`, { method: 'DELETE', headers })).status, 204);
  assert.equal((await fetch(`${url}/v1/scans`, { method: 'POST', headers: { authorization: `Bearer ${key.token}` } })).status, 401);
});
