import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { SCAN_WHOP_WEBHOOK_EVENTS } from '../shared/scan-webhook-events.js';
import { updateScanWhopEvents } from '../scripts/update-scan-whop-events.mjs';
import { WHOP_API_VERSION } from '../server/whop-billing.js';

const env = Object.freeze({
  PURPLE_SECRETS_SOURCE: 'infisical', PURPLE_SECRETS_ENVIRONMENT: 'prod',
  SCAN_WHOP_WEBHOOK_ID: 'hook_synthetic', SCAN_WHOP_WEBHOOK_SECRET: 'ws_synthetic_signing_secret',
  WHOP_API_KEY: 'synthetic-api-key-not-a-real-credential'
});
const originalEvents = ['payment.succeeded', 'refund.created', 'refund.updated', 'dispute.created', 'dispute.updated'];
const current = (overrides = {}) => ({
  id: env.SCAN_WHOP_WEBHOOK_ID, url: 'https://offense.sh/api/scanner-billing/whop/webhook',
  enabled: true, child_resource_events: false, api_version: 'v1', api_version_date: WHOP_API_VERSION,
  webhook_secret: env.SCAN_WHOP_WEBHOOK_SECRET, events: [...originalEvents], ...overrides
});
const response = data => new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json' } });
function mocked(...results) {
  const calls = [];
  return { calls, fetchImpl: async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(results.length, 'Unexpected additional provider call');
    const result = results.shift();
    if (result instanceof Error) throw result;
    return result instanceof Response ? result : response(result);
  } };
}
function publicProof(proof) {
  const serialized = JSON.stringify(proof);
  for (const privateValue of [env.WHOP_API_KEY, env.SCAN_WHOP_WEBHOOK_SECRET, env.SCAN_WHOP_WEBHOOK_ID,
    'https://offense.sh', 'https://app.purpleteam.sh']) assert.equal(serialized.includes(privateValue), false);
}

test('scanner setup uses the shared payment and saved-method event contract', async () => {
  assert.deepEqual(SCAN_WHOP_WEBHOOK_EVENTS, [...originalEvents, 'payment.failed', 'payment.requires_action',
    'payment.canceled', 'setup_intent.succeeded', 'setup_intent.requires_action', 'setup_intent.canceled']);
  assert.ok(Object.isFrozen(SCAN_WHOP_WEBHOOK_EVENTS));
  const source = await readFile(new URL('../scripts/setup-scan-whop-webhook.mjs', import.meta.url), 'utf8');
  assert.match(source, /import \{ SCAN_WHOP_WEBHOOK_EVENTS \} from '\.\.\/shared\/scan-webhook-events\.js'/);
  assert.match(source, /const events = SCAN_WHOP_WEBHOOK_EVENTS;/);
});

test('default check is read-only, reports the six missing events, and exposes no credentials', async () => {
  const mock = mocked(current());
  const proof = await updateScanWhopEvents({ env, ...mock });
  assert.equal(mock.calls.length, 1);
  assert.equal(mock.calls[0].method, 'GET');
  assert.equal(mock.calls[0].body, undefined);
  assert.equal(proof.mode, 'read_only');
  assert.equal(proof.ready, false);
  assert.equal(proof.changed, false);
  assert.equal(proof.signingSecretVerified, true);
  assert.deepEqual(proof.missingEvents, SCAN_WHOP_WEBHOOK_EVENTS.slice(5));
  publicProof(proof);
});

test('explicit apply changes only event subscriptions, keeps other events, and verifies readback', async () => {
  const existing = current({ events: [...originalEvents, 'account.updated'] });
  const expected = [...existing.events, ...SCAN_WHOP_WEBHOOK_EVENTS.slice(5)];
  const mock = mocked(existing, { ...existing, events: expected }, { ...existing, events: expected });
  const proof = await updateScanWhopEvents({ env, apply: true, ...mock });
  assert.deepEqual(mock.calls.map(call => call.method), ['GET', 'PATCH', 'GET']);
  assert.deepEqual(JSON.parse(mock.calls[1].body), { events: expected });
  for (const call of mock.calls) {
    assert.equal(call.url, 'https://api.whop.com/api/v1/webhooks/hook_synthetic');
    assert.equal(call.headers.authorization, `Bearer ${env.WHOP_API_KEY}`);
    assert.equal(call.headers['Api-Version-Date'], '2026-10-15-1');
    assert.equal(call.redirect, 'error');
  }
  assert.equal(proof.ready, true);
  assert.equal(proof.changed, true);
  assert.equal(proof.settingsPreserved, true);
  assert.equal(proof.endpointKind, 'canonical');
  assert.deepEqual(proof.events, expected);
  publicProof(proof);
});

test('existing legacy endpoint is preserved and already-ready apply never PATCHes', async () => {
  const hook = current({ url: 'https://app.purpleteam.sh/api/scanner-billing/whop/webhook', events: SCAN_WHOP_WEBHOOK_EVENTS });
  const mock = mocked(hook);
  const proof = await updateScanWhopEvents({ env, apply: true, ...mock });
  assert.equal(proof.endpointKind, 'legacy');
  assert.equal(proof.ready, true);
  assert.equal(proof.changed, false);
  assert.deepEqual(mock.calls.map(call => call.method), ['GET']);
  publicProof(proof);
});

test('unowned endpoints, unsafe settings and secret mismatches are rejected before any update', async t => {
  const variants = [
    { id: 'hook_someone_else' }, { url: 'https://other.example/api/scanner-billing/whop/webhook' },
    { url: current().url + '/' }, { url: current().url + '?extra=true' },
    { enabled: false }, { child_resource_events: true }, { api_version_date: 'different' }, { api_version: 'v2' },
    { webhook_secret: 'ws_other' }, { secret: 'ws_other' }, { events: ['payment.succeeded\nunsafe'] }, { events: null }
  ];
  for (const overrides of variants) await t.test(Object.keys(overrides).join(','), async () => {
    const mock = mocked(current(overrides));
    await assert.rejects(updateScanWhopEvents({ env, apply: true, ...mock }));
    assert.deepEqual(mock.calls.map(call => call.method), ['GET']);
  });
});

test('readback must preserve endpoint, settings, saved secret and every prior subscription', async t => {
  const existing = current({ events: [...originalEvents, 'account.updated'] });
  const updated = current({ events: [...SCAN_WHOP_WEBHOOK_EVENTS, 'account.updated'] });
  for (const overrides of [
    { url: 'https://app.purpleteam.sh/api/scanner-billing/whop/webhook' }, { enabled: false },
    { child_resource_events: true }, { api_version_date: 'changed' }, { webhook_secret: 'ws_changed' },
    { events: [...SCAN_WHOP_WEBHOOK_EVENTS] }, { events: originalEvents }
  ]) await t.test(Object.keys(overrides).join(','), async () => {
    const mock = mocked(existing, updated, { ...updated, ...overrides });
    await assert.rejects(updateScanWhopEvents({ env, apply: true, ...mock }));
    assert.deepEqual(mock.calls.map(call => call.method), ['GET', 'PATCH', 'GET']);
    assert.deepEqual(Object.keys(JSON.parse(mock.calls[1].body)), ['events']);
  });
  const mismatchedPatch = mocked(existing, { ...updated, webhook_secret: 'ws_changed' });
  await assert.rejects(updateScanWhopEvents({ env, apply: true, ...mismatchedPatch }), { code: 'signing_secret_mismatch' });
  assert.equal(mismatchedPatch.calls.length, 2);
});

test('production always requires vault scope and valid existing credentials', async t => {
  for (const overrides of [
    { PURPLE_SECRETS_SOURCE: undefined }, { PURPLE_SECRETS_ENVIRONMENT: 'dev' },
    { SCAN_WHOP_WEBHOOK_ID: undefined }, { SCAN_WHOP_WEBHOOK_SECRET: undefined }, { WHOP_API_KEY: undefined },
    { SCAN_WHOP_WEBHOOK_ID: 'hook_bad/id' }, { WHOP_API_KEY: 'bad key' }, { WHOP_SANDBOX: 'yes' }
  ]) await t.test(Object.keys(overrides).join(','), async () => {
    const mock = mocked();
    await assert.rejects(updateScanWhopEvents({ env: { ...env, ...overrides }, ...mock }));
    assert.equal(mock.calls.length, 0);
  });
  await assert.rejects(updateScanWhopEvents({ env, apply: 'yes', ...mocked() }), { code: 'invalid_option' });
});

test('sandbox selects its own API host without bypassing endpoint ownership', async () => {
  const sandbox = { ...env, WHOP_SANDBOX: 'true', PURPLE_SECRETS_SOURCE: undefined, PURPLE_SECRETS_ENVIRONMENT: undefined };
  const mock = mocked(current());
  const proof = await updateScanWhopEvents({ env: sandbox, ...mock });
  assert.equal(mock.calls[0].url, 'https://sandbox-api.whop.com/api/v1/webhooks/hook_synthetic');
  assert.equal(proof.environment, 'sandbox');
  const unowned = mocked(current({ url: 'https://other.example' }));
  await assert.rejects(updateScanWhopEvents({ env: sandbox, apply: true, ...unowned }));
  assert.equal(unowned.calls.length, 1);
});

test('unavailable signing-secret field is represented honestly rather than exposed or rotated', async () => {
  const hook = current();
  delete hook.webhook_secret;
  const mock = mocked(hook);
  const proof = await updateScanWhopEvents({ env, ...mock });
  assert.equal(proof.signingSecretVerified, false);
  assert.equal(mock.calls.length, 1);
  publicProof(proof);
});

test('documented null signing secrets allow event-only updates without claiming secret verification', async () => {
  const existing = current({ webhook_secret: null });
  const updated = current({ webhook_secret: null, events: [...SCAN_WHOP_WEBHOOK_EVENTS] });
  const mock = mocked(existing, updated, updated);
  const proof = await updateScanWhopEvents({ env, apply: true, ...mock });
  assert.equal(proof.signingSecretVerified, false);
  assert.equal(proof.ready, true);
  assert.equal(proof.changed, true);
  assert.deepEqual(mock.calls.map(call => call.method), ['GET', 'PATCH', 'GET']);
  assert.deepEqual(JSON.parse(mock.calls[1].body), { events: [...SCAN_WHOP_WEBHOOK_EVENTS] });
  publicProof(proof);
});

test('hidden secrets do not bypass validation of any visible or malformed secret field', async () => {
  for (const overrides of [
    { webhook_secret: '', secret: null }, { webhook_secret: '********', secret: null },
    { webhook_secret: 'ws_other', secret: null }, { webhook_secret: 123, secret: null },
    { webhook_secret: {}, secret: null }, { webhook_secret: null, secret: 'ws_other' },
    { webhook_secret: null, secret: false }
  ]) {
    const mock = mocked(current(overrides));
    await assert.rejects(updateScanWhopEvents({ env, apply: true, ...mock }), { code: 'signing_secret_mismatch' });
    assert.deepEqual(mock.calls.map(call => call.method), ['GET']);
  }
  const mock = mocked(current({ webhook_secret: null, secret: env.SCAN_WHOP_WEBHOOK_SECRET }));
  assert.equal((await updateScanWhopEvents({ env, ...mock })).signingSecretVerified, true);
});

test('provider failures and malformed responses are scrubbed with no automatic mutation retry', async t => {
  const privateResponse = `provider included ${env.WHOP_API_KEY} and ${env.SCAN_WHOP_WEBHOOK_SECRET}`;
  for (const result of [new Error(privateResponse), new Response(privateResponse, { status: 403 }),
    new Response(privateResponse), response(['not-a-webhook']), new Response('x'.repeat(262145))]) {
    await t.test(result instanceof Error ? 'network failure' : `response ${result.status}`, async () => {
      const mock = mocked(result);
      await assert.rejects(updateScanWhopEvents({ env, apply: true, ...mock }), cause => {
        assert.equal(cause.message.includes(env.WHOP_API_KEY), false);
        assert.equal(cause.message.includes(env.SCAN_WHOP_WEBHOOK_SECRET), false);
        return true;
      });
      assert.equal(mock.calls.length, 1);
    });
  }
  const uncertainPatch = mocked(current(), new Error(privateResponse));
  await assert.rejects(updateScanWhopEvents({ env, apply: true, ...uncertainPatch }), {
    code: 'update_outcome_unknown', message: 'Webhook update outcome is unknown. Run the read-only check before retrying.'
  });
  assert.deepEqual(uncertainPatch.calls.map(call => call.method), ['GET', 'PATCH']);
});
