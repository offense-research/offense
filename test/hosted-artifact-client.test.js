import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { hostedArtifactScan } from '../public/skills/purple/scripts/hosted-artifact-scan.mjs';

test('preview hashes a regular image artifact without using the network or a scan key', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-artifact-client-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'image.tar'), bytes = Buffer.from('synthetic-image-bytes');
  await writeFile(file, bytes);
  const preview = await hostedArtifactScan(file, { tool: 'trivy-image', preview: true,
    fetchImpl() { throw new Error('Preview must stay offline'); } });
  assert.equal(preview.kind, 'image-tar');
  assert.equal(preview.bytes, bytes.length);
  assert.equal(preview.sha256, createHash('sha256').update(bytes).digest('hex'));
  await assert.rejects(hostedArtifactScan(file, { tool: 'guarddog-npm', preview: true }), /exact package name and version/);
  await assert.rejects(hostedArtifactScan(file, { tool: 'cosign-image', preview: true,
    expectedDigest: `sha256:${'a'.repeat(64)}`, expectedIdentity: 'ci@example.test',
    expectedIssuer: 'http://issuer.example.test' }), /exact image digest/);
  const cosign = await hostedArtifactScan(file, { tool: 'cosign-image', preview: true,
    expectedDigest: `sha256:${'a'.repeat(64)}`, expectedIdentity: 'ci@example.test',
    expectedIssuer: 'https://issuer.example.test' });
  assert.equal(cosign.kind, 'cosign-save');
});

test('artifact helper streams bytes, polls the authenticated job and drops raw scanner fields', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-artifact-client-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'history.bundle'), output = path.join(root, 'report');
  const bytes = Buffer.from('synthetic-git-bundle'); await writeFile(file, bytes);
  const key = `purple_scan_${'a'.repeat(64)}`, rawSecret = 'secret-value-that-must-not-be-saved';
  const artifactId = 'b'.repeat(32), scanId = 'c'.repeat(32); const calls = [];
  let shownQuote;
  const fetchImpl = async (url, request) => {
    calls.push(url.pathname);
    assert.equal(request.headers.authorization, `Bearer ${key}`);
    if (url.pathname === '/v1/quotes') {
      assert.deepEqual(JSON.parse(request.body), { tools: ['gitleaks-history'], inputBytes: bytes.length, fileCount: 1 });
      return Response.json({ billable: true, maximumMicros: 100_000, prices: [] });
    }
    if (url.pathname === '/v1/usage') return Response.json({ enabled: true, availableMicros: 200_000 });
    if (url.pathname === '/v1/artifacts') {
      assert.equal(url.pathname, '/v1/artifacts');
      assert.equal(request.method, 'POST');
      assert.equal(request.headers['content-length'], String(bytes.length));
      assert.equal(request.headers['x-purple-artifact-kind'], 'git-bundle');
      assert.equal(request.headers['x-content-sha256'], createHash('sha256').update(bytes).digest('hex'));
      const chunks = [];
      for await (const chunk of request.body) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), bytes);
      return Response.json({ id: artifactId }, { status: 201 });
    }
    if (url.pathname === '/v1/scans') {
      assert.equal(url.pathname, '/v1/scans');
      assert.deepEqual(JSON.parse(request.body), { artifactId, tools: ['gitleaks-history'], maxChargeMicros: 100_000 });
      assert.ok(request.headers['idempotency-key']);
      return Response.json({ id: scanId, status: 'queued', selectedTools: ['gitleaks-history'], findings: [] }, { status: 202 });
    }
    assert.equal(url.pathname, `/v1/scans/${scanId}`);
    return Response.json({ id: scanId, status: 'completed', selectedTools: ['gitleaks-history'],
      tools: [{ name: 'gitleaks-history', status: 'complete', durationMs: 9, raw: rawSecret }],
      findings: [{ id: 'finding', tool: 'gitleaks-history', file: 'key.txt', line: 1,
        commit: 'd'.repeat(40), ruleId: 'generic-api-key', severity: 'HIGH',
        title: 'Potential exposed credential', remediation: 'Rotate it.', Secret: rawSecret, Match: rawSecret }],
      coverage: { scope: 'All refs in submitted bundle.' } });
  };
  const result = await hostedArtifactScan(file, { tool: 'gitleaks-history', key, api: 'https://api.example.test',
    output, pollMs: 1, fetchImpl, onQuote: quote => { shownQuote = quote; } });
  assert.equal(result.status, 'completed');
  assert.equal(result.findings, 1);
  assert.deepEqual(calls, ['/v1/quotes', '/v1/usage', '/v1/artifacts', '/v1/scans', `/v1/scans/${scanId}`]);
  assert.equal(shownQuote.maximumMicros, 100_000);
  const json = await readFile(result.json, 'utf8'), markdown = await readFile(result.report, 'utf8');
  assert.ok(json.includes('key.txt'));
  assert.ok(json.includes('d'.repeat(40)));
  assert.ok(!json.includes(rawSecret) && !markdown.includes(rawSecret));
  assert.ok(!json.includes(key) && !markdown.includes(key));
});

test('passive HAR upload requires a public origin and strips captured credentials before upload', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-har-client-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'capture.har'), output = path.join(root, 'report');
  const secret = 'private-session-token';
  await writeFile(file, JSON.stringify({ log: { entries: [{
    request: { method: 'GET', url: `https://example.com/private?token=${secret}`,
      headers: [{ name: 'Authorization', value: `Bearer ${secret}` }], cookies: [{ name: 'session', value: secret }] },
    response: { status: 200, headers: [{ name: 'Set-Cookie', value: `session=${secret}; Secure; HttpOnly` },
      { name: 'Content-Security-Policy', value: "default-src 'self'" }],
      content: { text: secret } }
  }] } }));
  for (const target of ['http://example.com', 'https://127.0.0.1', 'https://internal.local', 'https://example.com/path',
    'https://example.com:8443']) {
    await assert.rejects(hostedArtifactScan(file, { tool: 'zap-passive-har', target, preview: true }), /public HTTPS origin/);
  }
  const preview = await hostedArtifactScan(file, { tool: 'zap-passive-har', target: 'https://example.com', preview: true,
    fetchImpl() { throw new Error('Preview must stay offline'); } });
  assert.equal(preview.kind, 'web-har');
  assert.equal(preview.target, 'https://example.com');
  assert.equal(preview.capturedResponses, 1);
  const calls = [];
  const result = await hostedArtifactScan(file, { tool: 'zap-passive-har', target: 'https://example.com',
    key: `purple_scan_${'b'.repeat(64)}`, api: 'https://api.example.org', output, pollMs: 1,
    fetchImpl: async (url, request) => {
      calls.push(url.pathname);
      if (url.pathname === '/v1/quotes') {
        const input = JSON.parse(request.body);
        assert.deepEqual(input.tools, ['zap-passive-har']);
        assert.equal(input.fileCount, 1);
        assert.ok(input.inputBytes > 0);
        return Response.json({ billable: false, maximumMicros: 0, prices: [] });
      }
      if (url.pathname === '/v1/usage') return Response.json({ enabled: false, availableMicros: 0 });
      if (url.pathname === '/v1/artifacts') {
        assert.equal(url.pathname, '/v1/artifacts');
        assert.equal(request.headers['x-purple-artifact-kind'], 'web-har');
        const chunks = []; for await (const chunk of request.body) chunks.push(chunk);
        const bytes = Buffer.concat(chunks), text = bytes.toString('utf8');
        assert.equal(Number(request.headers['content-length']), bytes.length);
        assert.equal(request.headers['x-content-sha256'], createHash('sha256').update(bytes).digest('hex'));
        assert.ok(!text.includes(secret) && !text.includes('/private'));
        const parsed = JSON.parse(text);
        assert.equal(parsed.log.entries[0].request.headers.length, 0);
        assert.match(JSON.stringify(parsed.log.entries[0].response.headers), /purple_redacted=redacted; Secure; HttpOnly/);
        return Response.json({ id: 'e'.repeat(32) }, { status: 201 });
      }
      if (url.pathname === '/v1/scans') {
        assert.deepEqual(JSON.parse(request.body), { artifactId: 'e'.repeat(32), tools: ['zap-passive-har'],
          target: 'https://example.com', maxChargeMicros: 0 });
        return Response.json({ id: 'f'.repeat(32), status: 'queued', selectedTools: ['zap-passive-har'] }, { status: 202 });
      }
      return Response.json({ id: 'f'.repeat(32), status: 'completed', selectedTools: ['zap-passive-har'],
        tools: [{ name: 'zap-passive-har', status: 'complete' }], findings: [],
        coverage: { scope: 'One sanitized captured response; no live requests.' } });
    } });
  assert.equal(result.status, 'completed');
  assert.deepEqual(calls, ['/v1/quotes', '/v1/usage', '/v1/artifacts', '/v1/scans', `/v1/scans/${'f'.repeat(32)}`]);
  const saved = await readFile(result.json, 'utf8');
  assert.ok(!saved.includes(secret));
  assert.ok((await readFile(file, 'utf8')).includes(secret), 'The source HAR stays local and unchanged.');
});

test('artifact helper rejects insufficient scanner credit before artifact upload', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-artifact-credit-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'image.tar'); await writeFile(file, 'synthetic-image-bytes');
  const calls = []; let shownQuote;
  await assert.rejects(hostedArtifactScan(file, { tool: 'trivy-image', key: `purple_scan_${'a'.repeat(64)}`,
    api: 'https://api.example.test', onQuote: quote => { shownQuote = quote; },
    fetchImpl: async url => {
      calls.push(url.pathname);
      if (url.pathname === '/v1/quotes') return Response.json({ billable: true, maximumMicros: 100_000, prices: [] });
      if (url.pathname === '/v1/usage') return Response.json({ enabled: true, availableMicros: 50_000 });
      throw new Error('Artifact must not be uploaded with insufficient credit.');
    } }), /Add scanner credit/);
  assert.deepEqual(calls, ['/v1/quotes', '/v1/usage']);
  assert.equal(shownQuote.maximumMicros, 100_000);
});
