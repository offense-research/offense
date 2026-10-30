import test from 'node:test';
import assert from 'node:assert/strict';
import { signAssessmentWarmup, verifyAssessmentWarmup } from '../workers/assessment-egress-warmup.js';
import { signAssessmentTunnel, verifyAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { warmAssessmentGateway } from '../workers/assessment-egress-client.js';
import { assessmentEgressRequest } from '../workers/assessment-egress-controller.js';

const key = 'synthetic-gateway-warmup-key-'.repeat(3);

test('readiness capabilities are short lived, tamper proof and cannot authorize a target tunnel', () => {
  const now = () => 1_800_000_000_000, token = signAssessmentWarmup(key, now);
  assert.equal(verifyAssessmentWarmup(token, key, now).expiresAt, now() + 30_000);
  assert.throws(() => verifyAssessmentWarmup(token, key, () => now() + 30_000));
  assert.throws(() => verifyAssessmentWarmup(token, key + 'wrong', now));
  assert.throws(() => verifyAssessmentWarmup(token + 'x', key, now));
  assert.throws(() => verifyAssessmentTunnel(token, key, now));
  assert.throws(() => verifyAssessmentWarmup(signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key, now), key, now));
});

test('public readiness authorization happens before obtaining a DO or waking a VM', async () => {
  let lookups = 0;
  const env = { ASSESSMENT_EGRESS_KEY: key, GATEWAY: { getByName() { lookups++; assert.fail('Invalid readiness must not wake a VM.'); } } };
  for (const token of ['invalid', signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)]) {
    const request = new Request('https://gateway.example/warm', { method: 'POST', body: 'must remain unread', headers: {
      'x-purple-egress-authorization': token
    } });
    assert.equal((await assessmentEgressRequest(request, env)).status, 403); assert.equal(request.bodyUsed, false);
  }
  assert.equal(lookups, 0);
});

test('valid readiness requests route to only the named gateway without a destination or request body', async () => {
  let forwarded;
  const request = new Request('https://gateway.example/warm', { method: 'POST', headers: {
    'x-purple-egress-authorization': signAssessmentWarmup(key)
  } });
  const result = await assessmentEgressRequest(request, { ASSESSMENT_EGRESS_KEY: key, GATEWAY: {
    getByName(name) { assert.equal(name, 'gateway-v1'); return { fetch(value) { forwarded = value; return Response.json({ ready: true }); } }; }
  } });
  assert.equal(forwarded.body, null); assert.equal(new URL(forwarded.url).pathname, '/warm'); assert.deepEqual(await result.json(), { ready: true });
});

test('the client awaits bounded authenticated readiness before returning and never follows redirects', async () => {
  let ready; const gate = new Promise(resolve => { ready = resolve; }); let returned = false;
  const result = warmAssessmentGateway({ gatewayURL: 'https://gateway.example/', key, fetcher: async (url, options) => {
    assert.equal(url.href, 'https://gateway.example/warm'); assert.equal(options.method, 'POST');
    assert.equal(options.body, undefined); assert.equal(options.redirect, 'manual');
    assert.ok(options.signal instanceof AbortSignal);
    verifyAssessmentWarmup(options.headers['x-purple-egress-authorization'], key);
    await gate; return Response.json({ ready: true });
  } }).then(value => { returned = true; return value; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(returned, false);
  ready(); assert.deepEqual(await result, { ready: true });
});

test('readiness client rejects missing configuration, redirects, failed or unbounded readiness responses', async () => {
  for (const gatewayURL of [undefined, 'http://gateway.example/', 'https://user@gateway.example/', 'https://gateway.example/path']) {
    let called = false;
    await assert.rejects(warmAssessmentGateway({ gatewayURL, key, fetcher: () => { called = true; } }), /did not become ready/);
    assert.equal(called, false);
  }
  for (const response of [new Response('redirect', { status: 302 }), new Response('unavailable', { status: 503 }),
    Response.json({ ready: false }), new Response('x'.repeat(1025))]) {
    await assert.rejects(warmAssessmentGateway({ gatewayURL: 'https://gateway.example/', key, fetcher: async () => response }), /did not become ready/);
  }
});

test('caller cancellation aborts and settles readiness without starting a separate target request', async () => {
  const abort = new AbortController(); let cancellation;
  const result = warmAssessmentGateway({ gatewayURL: 'https://gateway.example/', key, signal: abort.signal,
    fetcher: async (_url, options) => {
      cancellation = options.signal;
      await new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Error('Synthetic cancellation.')), { once: true }));
    } });
  abort.abort(); await assert.rejects(result, /did not become ready/); assert.equal(cancellation.aborted, true);
  let called = false;
  await assert.rejects(warmAssessmentGateway({ gatewayURL: 'https://gateway.example/', key, signal: abort.signal,
    fetcher: async () => { called = true; } }));
  assert.equal(called, false);
});
