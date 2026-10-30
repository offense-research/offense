import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile, symlink } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { hostedAssessment } from '../public/skills/purple/scripts/hosted-assessment.mjs';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';

const scanKey = `purple_scan_${'a'.repeat(64)}`, jobId = 'b'.repeat(32), artifactId = 'c'.repeat(32);
const toolIds = ['nuclei', 'prowler-cloudflare', 'schemathesis', 'zap-api', 'sslyze', 'checkov', 'trufflehog-verified', 'mobsf-static',
  'openssf-scorecard', 'katana', 'httpx'];
const source = { files: [{ path: 'main.tf', content: 'resource "fixture" "example" {}' }], bytes: 30, omitted: [] };
const collectSourceImpl = async () => source;
const noNetwork = () => { throw new Error('Unexpected network request'); };
async function temporary(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-assessment-client-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
function fixture({ tool, calls, quote = {}, usage = {}, create, poll, upload } = {}) {
  return async (url, request) => {
    calls.push(url.pathname);
    assert.equal(request.headers.authorization, `Bearer ${scanKey}`);
    assert.equal(request.redirect, 'error');
    if (url.pathname === '/v1/tools') return Response.json({ tools: toolIds.map(id => ({ id, billingUnit: 'bounded_assessment' })) });
    if (url.pathname === '/v1/quotes') {
      const sent = JSON.parse(request.body);
      assert.deepEqual(sent.tools, [tool]); assert.equal(sent.fileCount, 1);
      assert.equal(typeof sent.inputBytes, 'number');
      assert.equal(request.body.includes('resource'), false);
      return Response.json({ currency: 'usd', billable: true, maximumMicros: 100_000, toolIds: [tool],
        prices: [{ tool, unit: 'bounded_assessment', maximumMicros: 100_000 }], ...quote });
    }
    if (url.pathname === '/v1/usage') return Response.json({ enabled: true, availableMicros: 10_000_000, ...usage });
    if (url.pathname === '/v1/artifacts') {
      if (upload) await upload(request);
      return Response.json({ id: artifactId }, { status: 201 });
    }
    if (url.pathname === '/v1/scans') {
      assert.ok(request.headers['idempotency-key']);
      if (create) await create(JSON.parse(request.body));
      return Response.json({ id: jobId, status: 'queued', selectedTools: [tool] }, { status: 202 });
    }
    assert.equal(url.pathname, `/v1/scans/${jobId}`);
    return Response.json(poll || { id: jobId, status: 'completed', selectedTools: [tool], findings: [],
      tools: [{ name: tool, status: 'complete', durationMs: 10 }], coverage: { scope: 'Synthetic bounded assessment.' } });
  };
}

test('preview is the default, stays offline, and shows dimensions rather than source or credentials', async t => {
  const root = await temporary(t), schema = path.join(root, 'openapi.json'), mobile = path.join(root, 'app.apk');
  await writeFile(schema, JSON.stringify({ openapi: '3.0.3', paths: { '/health': { get: { responses: { 200: { description: 'OK' } } } } } }));
  await writeFile(mobile, 'synthetic mobile bytes');
  const options = { fetchImpl: noNetwork, collectSourceImpl, key: undefined };
  for (const tool of toolIds) {
    const result = await hostedAssessment({ ...options, tool, target: 'https://example.com', repository: 'fixture/public-repository', schema, artifact: mobile,
      format: 'apk', accountId: 'd'.repeat(32), tokenEnv: 'CF_TEST_TOKEN', env: { CF_TEST_TOKEN: 'secret-value' } });
    assert.equal(result.mode, 'preview');
    assert.equal(result.networkRequests, 0);
    assert.equal(JSON.stringify(result).includes('resource'), false);
    assert.equal(JSON.stringify(result).includes('secret-value'), false);
    assert.equal(result.budgetSeconds, tool === 'mobsf-static' ? 480 : 120);
  }
  const cli = execFileSync(process.execPath, ['public/skills/purple/scripts/hosted-assessment.mjs', '--tool', 'nuclei',
    '--target', 'https://example.com', '--api', 'http://127.0.0.1:1'], { cwd: new URL('..', import.meta.url), encoding: 'utf8',
    env: { ...process.env, PURPLE_SCAN_KEY: '' } });
  assert.equal(JSON.parse(cli).mode, 'preview');
});

test('unsupported tools, private targets and missing explicit testing confirmations fail before network access', async t => {
  const root = await temporary(t), schema = path.join(root, 'schema.json');
  await writeFile(schema, JSON.stringify({ openapi: '3.1.0', paths: { '/': { get: {} } } }));
  await assert.rejects(hostedAssessment({ tool: 'arbitrary-shell', preview: true, fetchImpl: noNetwork }), /supported assessment tool/);
  for (const target of ['http://example.com', 'https://127.0.0.1', 'https://metadata.internal', 'https://example.com:8443', 'https://example.com/path'])
    await assert.rejects(hostedAssessment({ tool: 'nuclei', target, preview: true, fetchImpl: noNetwork }), /public HTTPS origin/);
  await assert.rejects(hostedAssessment({ tool: 'schemathesis', schema, target: 'https://example.com', run: true, fetchImpl: noNetwork }), /confirm-active-testing/);
  await assert.rejects(hostedAssessment({ tool: 'trufflehog-verified', run: true, collectSourceImpl, fetchImpl: noNetwork }), /confirm-live-verification/);
  await assert.rejects(hostedAssessment({ tool: 'prowler-cloudflare', accountId: 'd'.repeat(32), tokenEnv: 'PURPLE_SCAN_KEY', preview: true }), /separate read-only/);
  await assert.rejects(hostedAssessment({ tool: 'checkov', run: true, key: '', collectSourceImpl, fetchImpl: noNetwork }), /PURPLE_SCAN_KEY/);
});

test('discovery previews require one public origin and scorecard accepts only an explicit owner/repository', async () => {
  for (const tool of ['katana', 'httpx']) {
    const preview = await hostedAssessment({ tool, target: 'https://example.com', fetchImpl: noNetwork });
    assert.equal(preview.ownershipRequired, true); assert.equal(preview.networkRequests, 0);
    for (const target of ['http://example.com', 'https://127.0.0.1', 'https://example.com/private', 'https://user:secret@example.com'])
      await assert.rejects(hostedAssessment({ tool, target, fetchImpl: noNetwork }), /public HTTPS origin/);
  }
  const preview = await hostedAssessment({ tool: 'openssf-scorecard', repository: 'fixture/project', fetchImpl: noNetwork,
    collectSourceImpl: () => { throw new Error('Public scorecard must not collect a checkout.'); } });
  assert.equal(preview.repository, 'fixture/project'); assert.equal(preview.publicRepositoryOnly, true);
  assert.equal(preview.source, 'published-scorecard'); assert.equal(preview.networkRequests, 0);
  for (const repository of [undefined, 'https://github.com/fixture/project', 'fixture/project?token=secret', '../project', 'fixture/..', 'fixture/project/extra'])
    await assert.rejects(hostedAssessment({ tool: 'openssf-scorecard', repository, fetchImpl: noNetwork }), /owner\/repo/);
  await assert.rejects(hostedAssessment({ tool: 'openssf-scorecard', repository: `fixture/${scanKey}`, key: scanKey, fetchImpl: noNetwork }), /scan key appears/);
});

test('discovered endpoints and service metadata persist separately from vulnerabilities with raw fields omitted', async t => {
  const root = await temporary(t);
  for (const tool of ['katana', 'httpx']) {
    const calls = [], kind = tool === 'katana' ? 'endpoint' : 'service';
    const result = await hostedAssessment({ tool, target: 'https://example.com', run: true, key: scanKey,
      output: path.join(root, tool), pollMs: 1, fetchImpl: fixture({ tool, calls, create(body) {
        assert.deepEqual(body, { tools: [tool], target: 'https://example.com', maxChargeMicros: 100_000 });
      }, poll: { id: jobId, status: 'completed', selectedTools: [tool], findings: [],
        observations: [{ kind, tool, url: 'https://example.com/api/items?token=must-not-persist#private', method: 'GET',
          statusCode: 200, contentType: 'application/json', contentLength: 123, technologies: ['Example'], raw: 'must-not-persist',
          body: 'must-not-persist', headers: { authorization: 'must-not-persist' } },
        { kind, tool, url: 'https://127.0.0.1/private', method: 'GET', statusCode: 200 },
        { kind, tool, url: 'https://example.com/api', method: 'POST', statusCode: 200 }],
        coverage: { scope: 'One verified origin; discovery observations only.' } } }) });
    assert.equal(result.findings, 0); assert.equal(result.observations, 1);
    const saved = await readFile(result.json, 'utf8'), report = JSON.parse(saved);
    assert.equal(report.confirmedVulnerabilities, 0); assert.equal(report.observations[0].url, 'https://example.com/api/items');
    assert.ok(!saved.includes('must-not-persist')); assert.ok(!saved.includes('headers')); assert.ok(!saved.includes('body'));
    assert.match(await readFile(result.report, 'utf8'), /Observations \(not vulnerability findings\)/);
    assert.deepEqual(calls, ['/v1/tools', '/v1/quotes', '/v1/usage', '/v1/scans', `/v1/scans/${jobId}`]);
  }
});

test('public scorecard submits no checkout or provider credential and preserves dated score evidence', async t => {
  const root = await temporary(t), calls = [], commit = 'a'.repeat(40);
  const result = await hostedAssessment({ tool: 'openssf-scorecard', repository: 'fixture/project', run: true, key: scanKey,
    output: path.join(root, 'scorecard'), pollMs: 1, collectSourceImpl: () => { throw new Error('Do not collect source.'); },
    fetchImpl: fixture({ tool: 'openssf-scorecard', calls, create(body) {
      assert.deepEqual(body, { tools: ['openssf-scorecard'], repository: 'fixture/project', maxChargeMicros: 100_000 });
    }, poll: { id: jobId, status: 'completed', selectedTools: ['openssf-scorecard'], findings: [], observations: [
      { kind: 'supply-chain-score', tool: 'openssf-scorecard', source: 'published-scorecard', repository: 'fixture/project',
        score: 6.3, assessedAt: '2026-10-28', commit, checks: [{ name: 'Code-Review', score: 8, raw: 'omitted' },
          { name: 'Invalid', score: 100 }], raw: 'must-not-persist' }
    ], coverage: { scope: 'Published scorecard snapshot; no fresh scan.' } } }) });
  assert.equal(result.findings, 0); assert.equal(result.observations, 1);
  const saved = await readFile(result.json, 'utf8'), report = JSON.parse(saved);
  assert.equal(report.confirmedVulnerabilities, 0); assert.equal(report.observations[0].score, 6.3);
  assert.deepEqual(report.observations[0].checks, [{ name: 'Code-Review', score: 8 }]);
  assert.equal(report.observations[0].commit, commit); assert.match(report.clientCoverage.scope, /no fresh or private-repository scan/);
  assert.ok(!saved.includes('must-not-persist')); assert.match(await readFile(result.report, 'utf8'), /6.3\/10.*2026-10-28/);
});

test('remote schema references and symlink artifacts are rejected locally', async t => {
  const root = await temporary(t), schema = path.join(root, 'schema.json'), mobile = path.join(root, 'app.apk');
  await writeFile(schema, JSON.stringify({ openapi: '3.0.3', paths: { '/': { get: {} } }, components: { schemas: { X: { $ref: 'https://example.com/remote.json' } } } }));
  await assert.rejects(hostedAssessment({ tool: 'zap-api', target: 'https://example.com', schema, preview: true, fetchImpl: noNetwork }), /Remote references/);
  await writeFile(mobile, 'test'); await symlink(mobile, path.join(root, 'linked.apk'));
  await assert.rejects(hostedAssessment({ tool: 'mobsf-static', artifact: path.join(root, 'linked.apk'), format: 'apk', preview: true }), /symlink/);
});

test('mismatched quotes and insufficient credit stop before any source, token or artifact upload', async t => {
  const root = await temporary(t);
  for (const changes of [{ quote: { toolIds: ['nuclei'] } }, { quote: { prices: [{ tool: 'checkov', unit: 'other', maximumMicros: 100_000 }] } },
    { quote: { maximumMicros: 100_001 } }, { usage: { enabled: false } }, { usage: { availableMicros: 0 } }, { usage: { blocked: true } }]) {
    const calls = [];
    await assert.rejects(hostedAssessment({ tool: 'checkov', run: true, key: scanKey, collectSourceImpl,
      output: path.join(root, `report-${Math.random().toString(16).slice(2)}`), fetchImpl: fixture({ tool: 'checkov', calls, ...changes }) }), /quote|credit|payment review/);
    assert.deepEqual(calls, ['/v1/tools', '/v1/quotes', '/v1/usage']);
  }
  const calls = [];
  await assert.rejects(hostedAssessment({ tool: 'checkov', run: true, key: scanKey, output: path.join(root, 'unauthorized'),
    collectSourceImpl, fetchImpl: async (url, request) => { calls.push(url.pathname); assert.equal(request.headers.authorization, `Bearer ${scanKey}`); return Response.json({}, { status: 401 }); } }), /HTTP 401/);
  assert.deepEqual(calls, ['/v1/tools']);
});

test('source assessment submits the quoted cap and polls into private filtered reports', async t => {
  const root = await temporary(t), calls = [], secret = 'must-not-persist', output = path.join(root, 'result');
  const result = await hostedAssessment({ tool: 'checkov', key: scanKey, run: true, collectSourceImpl, output, pollMs: 1,
    fetchImpl: fixture({ tool: 'checkov', calls, create(body) {
      assert.deepEqual(body.files, source.files); assert.equal(body.maxChargeMicros, 100_000);
    }, poll: { id: jobId, status: 'completed', selectedTools: ['checkov'], confirmedVulnerabilities: 99,
      findings: [{ id: 'finding', tool: 'checkov', ruleId: 'CKV_TEST', severity: 'HIGH', file: 'main.tf', line: 1,
        title: `Review infrastructure ${scanKey}`, remediation: 'Review the configuration.', raw: secret }],
      tools: [{ name: 'checkov', status: 'complete', raw: secret }], coverage: { scope: 'Uploaded infrastructure.', raw: secret } } }) });
  assert.equal(result.status, 'completed'); assert.equal(result.findings, 1);
  assert.deepEqual(calls, ['/v1/tools', '/v1/quotes', '/v1/usage', '/v1/scans', `/v1/scans/${jobId}`]);
  const report = await readFile(result.json, 'utf8');
  assert.equal(JSON.parse(report).confirmedVulnerabilities, 0);
  assert.ok(!report.includes(secret) && !report.includes(scanKey));
  assert.equal((await stat(output)).mode & 0o777, 0o700);
  assert.equal((await stat(result.json)).mode & 0o777, 0o600);
});

test('Cloudflare token stays out of quote and reports and is submitted only after quote acceptance', async t => {
  const root = await temporary(t), calls = [], token = 'fixture_cf_token_12345678901234567890';
  await hostedAssessment({ tool: 'prowler-cloudflare', run: true, key: scanKey, accountId: 'd'.repeat(32),
    tokenEnv: 'CF_AUDIT_TOKEN', env: { CF_AUDIT_TOKEN: token }, output: path.join(root, 'cloud'), pollMs: 1,
    fetchImpl: fixture({ tool: 'prowler-cloudflare', calls, create(body) {
      assert.equal(body.accountId, 'd'.repeat(32)); assert.equal(body.apiToken, token); assert.equal(body.files, undefined);
    }, poll: { id: jobId, status: 'completed', selectedTools: ['prowler-cloudflare'], credentials: { apiToken: token },
      findings: [{ title: token, remediation: scanKey }], coverage: { scope: 'One account.' } } }) }).then(async result => {
      assert.ok(!(await readFile(result.json, 'utf8')).includes(token));
      assert.ok(!(await readFile(result.report, 'utf8')).includes(scanKey));
    });
});

test('mobile artifact is hashed, quoted, streamed and then referenced by ID', async t => {
  const root = await temporary(t), file = path.join(root, 'app.apk'), bytes = Buffer.from('synthetic apk fixture'), calls = [];
  await writeFile(file, bytes);
  await hostedAssessment({ tool: 'mobsf-static', run: true, key: scanKey, artifact: file, format: 'apk',
    output: path.join(root, 'mobile'), pollMs: 1, fetchImpl: fixture({ tool: 'mobsf-static', calls,
      async upload(request) {
        assert.equal(request.headers['x-purple-artifact-kind'], 'mobile-app');
        assert.equal(request.headers['content-length'], String(bytes.length));
        assert.equal(request.headers['x-content-sha256'], createHash('sha256').update(bytes).digest('hex'));
        const chunks = []; for await (const chunk of request.body) chunks.push(chunk);
        assert.deepEqual(Buffer.concat(chunks), bytes);
      }, create(body) { assert.deepEqual(body, { tools: ['mobsf-static'], format: 'apk', artifactId, maxChargeMicros: 100_000 }); }
    }) });
  assert.deepEqual(calls, ['/v1/tools', '/v1/quotes', '/v1/usage', '/v1/artifacts', '/v1/scans', `/v1/scans/${jobId}`]);
});

test('ownership challenge and verification are separate authenticated operations', async t => {
  const root = await temporary(t), calls = [], token = 'a'.repeat(32);
  const challenge = { origin: 'https://example.com', recordName: '_purple-scan.example.com',
    recordValue: `purple-scan-verification=${token}`, token, signature: 'd'.repeat(64), expiresAt: Date.now() + 600_000 };
  const result = await hostedAssessment({ challenge: true, target: 'https://example.com', key: scanKey,
    output: path.join(root, 'proof'), fetchImpl: async (url, request) => {
      calls.push(url.pathname); assert.equal(request.headers.authorization, `Bearer ${scanKey}`);
      assert.deepEqual(JSON.parse(request.body), { target: 'https://example.com' }); return Response.json(challenge);
    } });
  assert.equal(result.recordName, challenge.recordName);
  const verified = await hostedAssessment({ verifyTarget: result.challengeFile, key: scanKey,
    fetchImpl: async (url, request) => {
      calls.push(url.pathname); assert.deepEqual(JSON.parse(request.body), { challenge });
      return Response.json({ origin: challenge.origin, verifiedAt: Date.now(), expiresAt: Date.now() + 300_000 });
    } });
  assert.equal(verified.origin, 'https://example.com');
  assert.deepEqual(calls, ['/v1/targets/challenge', '/v1/targets/verify']);
});

test('resuming needs no source, quote or second charge and rejects a changed job ID', async t => {
  const root = await temporary(t), calls = [];
  const result = await hostedAssessment({ scanId: jobId, key: scanKey, output: path.join(root, 'resume'),
    collectSourceImpl: () => { throw new Error('Must not collect source'); }, fetchImpl: async url => {
      calls.push(url.pathname); return Response.json({ id: jobId, status: 'completed', selectedTools: ['nuclei'], findings: [] });
    } });
  assert.equal(result.status, 'completed'); assert.deepEqual(calls, [`/v1/scans/${jobId}`]);
  await assert.rejects(hostedAssessment({ scanId: jobId, key: scanKey, output: path.join(root, 'bad-resume'),
    fetchImpl: async () => Response.json({ id: 'e'.repeat(32), status: 'completed' }) }), /invalid job metadata/);
});

test('client and real local HTTP handlers agree on bounded quotes, encrypted input, polling and a single settled charge', async t => {
  const root = await temporary(t), db = new DatabaseSync(':memory:');
  const prices = JSON.parse(await readFile(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  let starts = 0;
  const scans = createHostedScans(db, { metering: meter, assessmentTools: ['checkov'],
    encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString(),
    sandbox: {
      async start(input) {
        starts++; assert.equal(input.assessment.tool, 'checkov');
        assert.deepEqual(input.assessment.files, source.files); return { status: 'running' };
      },
      async get() { return { status: 'completed', tools: [{ name: 'checkov', status: 'complete' }], findings: [], coverage: { scope: 'Synthetic offline infrastructure scan.' } }; },
      async destroy() {}
    }
  });
  const key = scans.issueKey('client-test-workspace', 'client-test-user');
  meter.recordVerifiedPurchase({ workspaceId: 'client-test-workspace', paymentId: 'fixture_purchase_123', amountMicros: 10_000_000 });
  const app = express(); registerScanApi(app, { scans, dispatch: () => { void scans.dispatch(); } });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const api = `http://127.0.0.1:${server.address().port}`;
    const result = await hostedAssessment({ tool: 'checkov', run: true, key: key.token, api, collectSourceImpl,
      output: path.join(root, 'real-http'), pollMs: 1, timeoutMs: 5000 });
    assert.equal(result.status, 'completed'); assert.equal(starts, 1);
    assert.equal(meter.status('client-test-workspace').balanceMicros, 9_950_000);
    assert.equal(meter.usage(result.id).chargeMicros, 50_000);
    const resumed = await hostedAssessment({ scanId: result.id, key: key.token, api, output: path.join(root, 'real-http-resume') });
    assert.equal(resumed.status, 'completed'); assert.equal(starts, 1);
    assert.equal(meter.status('client-test-workspace').balanceMicros, 9_950_000);
  } finally {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close();
  }
});
