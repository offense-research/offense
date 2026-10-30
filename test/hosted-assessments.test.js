import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import express from 'express';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { assessmentInput } from '../server/assessment-input.js';
import { ASSESSMENT_TOOLS } from '../shared/assessment-tools.js';
import { scanController, validateAssessmentRequest } from '../workers/scan-container.js';

const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const inputFiles = [{ path: 'infra/main.tf', content: 'resource "aws_s3_bucket" "test" {}' }];
function fixture(t) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let timestamp = Date.now(), proofValue, sent;
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices, now: () => timestamp });
  let result = { status: 'running' };
  const scans = createHostedScans(db, { encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString(),
    assessmentTools: ASSESSMENT_TOOLS.map(tool => tool.id),
    targetSigningKey: 'x'.repeat(64), metering: meter, now: () => timestamp,
    artifacts: { delete: async () => {} }, resolvers: { resolveTxt: async () => [proofValue], resolveAddresses: async () => ['8.8.8.8'] },
    sandbox: { start: async value => { sent = value; return { status: 'running' }; }, get: async () => result, destroy: async () => {} } });
  const key = scans.issueKey('workspace-a', 'user-a'), principal = scans.authenticate(key.token);
  meter.recordVerifiedPurchase({ workspaceId: 'workspace-a', paymentId: 'payment-fixture-01', amountMicros: 10_000_000 });
  return { scans, meter, key, principal, db, sent: () => sent, finish: value => { result = value; },
    advance: ms => { timestamp += ms; }, verify: async () => {
      const challenge = scans.targetChallenge('workspace-a', 'https://example.com'); proofValue = challenge.recordValue;
      await scans.verifyTarget('workspace-a', challenge); return challenge;
    } };
}

test('all assessments quote flat bounded jobs, including large mobile artifacts', t => {
  const f = fixture(t);
  assert.equal(ASSESSMENT_TOOLS.length, 11);
  for (const tool of ASSESSMENT_TOOLS) {
    const bytes = tool.id === 'mobsf-static' ? 80 * 1024 * 1024 : 2 * 1024 * 1024;
    const quote = f.scans.quote({ tools: [tool.id], inputBytes: bytes, fileCount: 1 });
    assert.equal(quote.prices[0].unit, 'bounded_assessment');
    assert.equal(quote.maximumMicros, prices[tool.id].baseMicros);
    assert.equal(quote.prices[0].additionalMiBUnits, 0);
  }
  assert.throws(() => f.scans.quote({ tools: ['checkov', 'nuclei'], inputBytes: 1, fileCount: 1 }), /one selected tool/);
});

test('assessment submissions reserve once, encrypt source, dispatch the dedicated adapter, and settle once', async t => {
  const f = fixture(t), quote = f.scans.quote({ tools: ['checkov'], inputBytes: 100, fileCount: 1 });
  const input = { tools: ['checkov'], files: inputFiles, maxChargeMicros: quote.maximumMicros };
  assert.throws(() => f.scans.create(f.principal, { ...input, maxChargeMicros: 1 }, 'assessment-checkov01'), /fresh quote/);
  const job = f.scans.create(f.principal, input, 'assessment-checkov01');
  assert.equal(f.scans.create(f.principal, input, 'assessment-checkov01').id, job.id);
  assert.equal(f.meter.status('workspace-a').reservedMicros, 50000);
  assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM scan_sources').all()).includes('aws_s3_bucket'));
  await f.scans.dispatch();
  assert.equal(f.sent().assessment.tool, 'checkov'); assert.deepEqual(f.sent().files, []);
  assert.equal(f.sent().assessment.files[0].path, inputFiles[0].path);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
  f.finish({ status: 'completed', tools: [{ name: 'checkov', status: 'complete', durationMs: 100 }], findings: [], confirmedVulnerabilities: 0 });
  await f.scans.dispatch(); await f.scans.dispatch();
  assert.equal(f.scans.get(job.id, 'workspace-a').metering.chargeMicros, 50000);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 9_950_000);
  assert.equal(f.scans.get(job.id, 'workspace-b'), null);
});

test('target proof is workspace-bound, expires, and supplies only server-resolved public addresses', async t => {
  const f = fixture(t), input = { tools: ['nuclei'], target: 'https://example.com', maxChargeMicros: 250000 };
  assert.throws(() => f.scans.create(f.principal, { ...input, verified: true, resolvedAddresses: ['127.0.0.1'] }, 'unverified-001'), /Verify ownership/);
  const challenge = await f.verify();
  await assert.rejects(f.scans.verifyTarget('workspace-b', challenge), /invalid or expired/);
  const job = f.scans.create(f.principal, { ...input, options: { maxRequests: 1000000, resolvedAddresses: ['127.0.0.1'] } }, 'verified-001');
  await f.scans.dispatch();
  assert.deepEqual(f.sent().assessment.options.resolvedAddresses, ['8.8.8.8']);
  assert.equal(f.sent().assessment.options.maxRequests, 200);
  assert.equal(f.scans.get(job.id, 'workspace-a').status, 'running');
  f.advance(6 * 60_000);
  assert.throws(() => f.scans.create(f.principal, input, 'expired-proof01'), /Verify ownership/);
});

test('cloud credentials stay encrypted until dispatch, disappear from storage, and failed scans release the hold', async t => {
  const f = fixture(t), token = 'cloudflare-token-fixture-private-123456';
  const input = { tools: ['prowler-cloudflare'], accountId: 'a'.repeat(32), apiToken: token, maxChargeMicros: 250000 };
  const job = f.scans.create(f.principal, input, 'cloud-account01');
  assert.ok(!JSON.stringify(f.scans.get(job.id, 'workspace-a')).includes(token));
  assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM scan_sources').all()).includes(token));
  await f.scans.dispatch(); assert.equal(f.sent().assessment.credentials.apiToken, token);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_sources').get().n, 0);
  f.finish({ status: 'partial', tools: [{ name: 'prowler-cloudflare', status: 'partial' }], findings: [] });
  await f.scans.dispatch();
  assert.equal(f.scans.get(job.id, 'workspace-a').metering.chargeMicros, 0);
  assert.equal(f.meter.status('workspace-a').reservedMicros, 0);
});

test('active API and secret verification require explicit opt-in and reject remote schema inputs', () => {
  const proof = { origin: 'https://example.com', addresses: ['8.8.8.8'] };
  const schema = { openapi: '3.0.3', paths: { '/test': { get: { responses: { 200: { description: 'ok' } } } } } };
  const input = { target: proof.origin, files: [{ path: 'openapi.json', content: JSON.stringify(schema) }] };
  assert.throws(() => assessmentInput('schemathesis', input, { verifiedTarget: proof }), /confirmActiveTesting/);
  assert.equal(assessmentInput('schemathesis', { ...input, confirmActiveTesting: true }, { verifiedTarget: proof }).tool, 'schemathesis');
  schema.components = { schemas: { external: { $ref: 'http://169.254.169.254/metadata' } } };
  assert.throws(() => assessmentInput('zap-api', { ...input, confirmActiveTesting: true, files: [{ path: 'a.json', content: JSON.stringify(schema) }] }, { verifiedTarget: proof }), /Remote references/);
  assert.throws(() => assessmentInput('trufflehog-verified', { files: inputFiles }), /confirmLiveVerification/);
  assert.throws(() => validateAssessmentRequest({ tools: ['nuclei'], assessment: { tool: 'nuclei', options: { target: proof.origin, resolvedAddresses: ['127.0.0.1'] } } }), /Verify ownership/);
});

test('assessment Worker uses dedicated images, denies ordinary internet, and makes network failures partial', async () => {
  const memory = new Map(), calls = [];
  const ctx = { storage: { kv: { get: key => memory.get(key), put: (key, value) => memory.set(key, value) }, setAlarm: async () => {} },
    exports: { AssessmentOutbound: value => value }, container: { running: true, images: { 'assessment-network': 'network-image' },
      start: opts => { assert.equal(opts.enableInternet, false); assert.equal(opts.image, 'network-image'); },
      setInactivityTimeout: async () => {}, interceptAllOutboundHttp: async () => {}, interceptOutboundHttps: async () => {},
      exec: async (argv, options) => { calls.push(argv); if (options?.stdin) {
        const payload = JSON.parse(await new Response(options.stdin).text()); assert.equal(payload.tool, 'nuclei');
      }
      return { output: async () => ({ exitCode: 0, stdout: new TextEncoder().encode(JSON.stringify({ status: 'completed', tools: [{ name: 'nuclei', status: 'complete' }], findings: [] })) }) }; }
    } };
  const assessment = assessmentInput('nuclei', { target: 'https://example.com' }, { verifiedTarget: { origin: 'https://example.com', addresses: ['8.8.8.8'] } });
  let warmed = false, warmStarted = false, releaseWarm;
  const ready = new Promise(resolve => { releaseWarm = resolve; });
  const launch = scanController(ctx, { ASSESSMENT_EGRESS_URL: 'https://gateway.example/', ASSESSMENT_EGRESS_KEY: 'private-fixture-key' }, {
    warmGateway: async options => {
      assert.equal(memory.get('assessment-policy').tool, 'nuclei');
      assert.equal(options.gatewayURL, 'https://gateway.example/');
      assert.equal(options.key, 'private-fixture-key');
      assert.ok(options.signal instanceof AbortSignal);
      assert.equal(calls.length, 0);
      warmStarted = true;
      await ready;
      warmed = true;
    }
  }).start({ id: 'a'.repeat(32), tools: ['nuclei'], files: [], assessment });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(warmStarted, true); assert.equal(warmed, false); assert.equal(calls.length, 0);
  releaseWarm(); await launch;
  assert.equal(warmed, true);
  assert.ok(calls.some(argv => argv.includes('/opt/purple/agent/assessment-tunnel-proxy.mjs')));
  assert.ok(calls.some(argv => argv.includes('/opt/purple/agent/assessment-network.mjs')));
  memory.set('assessment-connections', 1); memory.set('assessment-network-failures', 1);
  assert.equal((await scanController(ctx).get()).status, 'partial');
  memory.set('assessment-network-failures', 0);
  memory.set('assessment-active-count', 1);
  assert.equal((await scanController(ctx).get()).status, 'running');
  memory.set('assessment-active-count', 0);
  assert.equal((await scanController(ctx).get()).status, 'completed');
});

test('gateway readiness failures stop the engine and VM setup failures abort pending warmup', async () => {
  for (const failure of ['warmup', 'vm_setup']) {
    const memory = new Map(); let destroyed = false, engineCalls = 0, warmupAborted = false, warmupSettled = false;
    const ctx = { storage: { kv: { get: key => memory.get(key), put: (key, value) => memory.set(key, value) }, setAlarm: async () => {} },
      exports: { AssessmentOutbound: value => value }, container: { images: { 'assessment-network': 'network-image' },
        start: options => { assert.equal(options.enableInternet, false); },
        setInactivityTimeout: async () => {
          // Let an early warmup rejection occur before VM setup resolves.
          await new Promise(resolve => setImmediate(resolve));
          if (failure === 'vm_setup') throw Error('PRIVATE_VM_DETAILS');
        },
        exec: async () => { engineCalls++; }, destroy: async () => { destroyed = true; }
      } };
    const assessment = assessmentInput('nuclei', { target: 'https://example.com' }, {
      verifiedTarget: { origin: 'https://example.com', addresses: ['8.8.8.8'] }
    });
    const controller = scanController(ctx, {}, { warmGateway: async ({ signal }) => {
      assert.equal(memory.get('assessment-policy').tool, 'nuclei');
      if (failure === 'warmup') { warmupSettled = true; throw Error('PRIVATE_WARMUP_DETAILS'); }
      await new Promise((resolve, reject) => signal.addEventListener('abort', () => {
        warmupAborted = true; warmupSettled = true; reject(Error('PRIVATE_ABORT_DETAILS'));
      }, { once: true }));
    } });
    await assert.rejects(controller.start({ id: 'b'.repeat(32), tools: ['nuclei'], files: [], assessment }), /Could not start the isolated scanner/);
    assert.equal(destroyed, true); assert.equal(engineCalls, 0); assert.equal(warmupSettled, true);
    assert.equal(warmupAborted, failure === 'vm_setup');
    assert.equal(memory.get('scan').status, 'failed');
    assert.equal(JSON.stringify(memory.get('scan')).includes('PRIVATE_'), false);
  }
});

test('target API authenticates before DNS and refuses browser origins', async t => {
  const f = fixture(t), app = express(); registerScanApi(app, { scans: f.scans });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/targets/challenge`;
  const headers = { authorization: `Bearer ${f.key.token}`, 'content-type': 'application/json' };
  assert.equal((await fetch(url, { method: 'POST', body: '{bad' })).status, 401);
  assert.equal((await fetch(url, { method: 'POST', headers: { ...headers, origin: 'https://example.com' }, body: '{}' })).status, 403);
  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify({ target: 'https://example.com' }) });
  assert.equal(response.status, 200); assert.equal(response.headers.get('set-cookie'), null);
  assert.equal((await response.json()).recordName, '_purple-scan.example.com');
});
