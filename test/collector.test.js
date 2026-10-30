import test from 'node:test';
import assert from 'node:assert/strict';
import collector from '../workers/collector.js';
import forwarder from '../workers/forwarder.js';
import { installCollector, syncCollectorSources, updateCollector, updateForwarder } from '../server/cloudflare-installer.js';
import { DatabaseSync } from 'node:sqlite';
import { createEventStore } from '../server/event-store.js';

test('collector only enqueues allowlisted data with a source Worker', async () => {
  const sent = [];
  await collector.tail([{
    scriptName: 'checkout', eventTimestamp: Date.now(), outcome: 'exception',
    event: { request: { method: 'POST', url: 'https://example.com/?token=secret', headers: { authorization: 'secret', 'cf-ray': '57d55f210d7b95f3' } }, response: { status: 500 } },
    logs: [{ level: 'error', message: ['password=secret'] }],
    exceptions: [{ name: 'TypeError', message: 'private customer data' }, { name: 'secret-error', message: 'private customer data' }]
  }], { PURPLE_EVENTS: { sendBatch: async batch => sent.push(...batch) } });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].body.sourceWorker, 'checkout');
  assert.equal(sent[0].body.responseStatus, 500);
  assert.equal(sent[0].body.requestId, '57d55f210d7b95f3');
  assert.deepEqual(sent[0].body.logLevels, ['error']);
  assert.deepEqual(sent[0].body.logs, [{ level: 'error', message: 'password=[REDACTED]' }]);
  assert.deepEqual(sent[0].body.exceptionNames, ['TypeError', 'Error']);
  assert.equal(JSON.stringify(sent).includes('secret'), false);
  assert.equal(JSON.stringify(sent).includes('private customer data'), false);
});

test('collector keeps useful logs while redacting nested secrets and URLs', async () => {
  const sent = [];
  await collector.tail([{
    scriptName: 'orders', eventTimestamp: Date.now(), outcome: 'ok',
    logs: [
      { level: 'info', message: ['Order accepted', { orderId: 42, customer: { email: 'user@example.com', apiKey: 'sk-secretvalue123' } }] },
      { level: 'warn', message: ['GET https://example.com/orders?token=private Bearer abc123 token=private'] }
    ]
  }], { PURPLE_EVENTS: { sendBatch: async batch => sent.push(...batch) } });
  assert.equal(sent[0].body.sourceWorker, 'orders');
  assert.match(sent[0].body.logs[0].message, /Order accepted/);
  assert.match(sent[0].body.logs[0].message, /orderId.*42/);
  assert.equal(JSON.stringify(sent).includes('user@example.com'), false);
  assert.equal(JSON.stringify(sent).includes('sk-secretvalue123'), false);
  assert.equal(JSON.stringify(sent).includes('example.com'), false);
  assert.equal(JSON.stringify(sent).includes('abc123'), false);
  assert.equal(JSON.stringify(sent).includes('private'), false);
});

test('collector skips its own ingestion requests when Purple tails the app Worker', async () => {
  const sent = [];
  const event = url => ({ scriptName: 'purple-app', eventTimestamp: Date.now(), outcome: 'ok',
    event: { request: { method: 'POST', url }, response: { status: 200 } } });
  await collector.tail([
    event('https://ingest.purpleteam.sh/api/ingest'),
    event('https://app.purpleteam.sh/api/state')
  ], { PURPLE_EVENTS: { sendBatch: async batch => sent.push(...batch) } });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].body.sourceWorker, 'purple-app');
  assert.equal(sent[0].body.requestMethod, 'POST');
});

test('forwarder authenticates and retries failed delivery', async () => {
  const original = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => { request = { url, options }; return { ok: false, status: 503 }; };
  try {
    await assert.rejects(forwarder.queue({ messages: [{ id: 'queue-123', body: { schema: 'purple.tail.v1' } }] }, { PURPLE_INGEST_URL: 'https://purple.example/api/ingest', PURPLE_INGEST_TOKEN: 'token' }), /503/);
    assert.equal(request.options.headers.Authorization, 'Bearer token');
    assert.equal(JSON.parse(request.options.body).events[0].queueMessageId, 'queue-123');
  } finally { globalThis.fetch = original; }
});

test('backend stores batches atomically and deduplicates retried Queue messages', () => {
  const db = new DatabaseSync(':memory:');
  // Exercise migration of databases created before batch ingestion existed.
  db.exec('CREATE TABLE events (id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, received_at INTEGER NOT NULL, payload TEXT NOT NULL)');
  const store = createEventStore(db);
  const event = { schema: 'purple.tail.v1', sourceWorker: 'checkout', timestamp: new Date().toISOString(), logs: [{ level: 'info', message: 'done' }] };
  const first = store.receiveBatch('workspace-a', [{ ...event, queueMessageId: 'message-1' }, { ...event, queueMessageId: 'message-2' }]);
  assert.deepEqual({ accepted: first.accepted, duplicates: first.duplicates }, { accepted: 2, duplicates: 0 });
  const retry = store.receiveBatch('workspace-a', [{ ...event, queueMessageId: 'message-1' }, { ...event, queueMessageId: 'message-2' }]);
  assert.deepEqual({ accepted: retry.accepted, duplicates: retry.duplicates }, { accepted: 0, duplicates: 2 });
  assert.equal(db.prepare('SELECT count(*) AS count FROM events').get().count, 2);
  assert.equal(db.prepare('SELECT analysis_status AS status FROM events LIMIT 1').get().status, 'pending');
  assert.equal(db.prepare('SELECT status FROM ingest_batches WHERE id = ?').get(retry.batchId).status, 'duplicate');
  assert.equal(store.recentBatches('workspace-a').length, 2);
  assert.equal(store.recentBatches('workspace-b').length, 0);
  assert.throws(() => store.receiveBatch('workspace-a', [{ ...event, queueMessageId: 'message-3' }, { schema: 'purple.tail.v1' }]), /slice/);
  assert.equal(db.prepare('SELECT count(*) AS count FROM events').get().count, 2);
  assert.equal(store.recentBatches('workspace-a').length, 2);
  db.close();
});

test('installer creates resources and preserves existing tail consumers', async () => {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const route = new URL(url).pathname;
    const method = options.method || 'GET';
    calls.push({ route, method, body: options.body });
    let result = {};
    if (route.endsWith('/workers/scripts') && method === 'GET') result = [{ id: 'checkout' }];
    if (route.endsWith('/queues') && method === 'POST') result = { queue_id: 'queue-123' };
    if (route.endsWith('/checkout/script-settings') && method === 'GET') result = { tail_consumers: [{ service: 'existing-tail' }] };
    return { ok: true, json: async () => ({ success: true, result }) };
  };
  try {
    const install = { queue: 'purple-events-test', collector: 'purple-collector-test', forwarder: 'purple-forwarder-test', attached: [] };
    let saves = 0;
    await installCollector({ token: 'test-token', accountId: 'abc', sources: ['checkout'], install, ingestUrl: 'https://purple.example/api/ingest', ingestToken: 'test-secret', save: () => saves++ });
    assert.equal(install.status, 'installed');
    assert.equal(install.attached[0], 'checkout');
    assert.ok(saves >= 5);
    const patch = calls.find(call => call.route.endsWith('/checkout/script-settings') && call.method === 'PATCH');
    assert.deepEqual(JSON.parse(patch.body).tail_consumers, [{ service: 'existing-tail' }, { service: 'purple-collector-test' }]);
    const collectorUpload = calls.find(call => call.route.endsWith('/purple-collector-test'));
    assert.deepEqual(JSON.parse(collectorUpload.body.get('metadata')).bindings, [{ name: 'PURPLE_EVENTS', type: 'queue', queue_name: 'purple-events-test' }]);
    await updateCollector('test-token', { ...install, accountId: 'abc' });
    assert.equal(calls.filter(call => call.route.endsWith('/purple-collector-test') && call.method === 'PUT').length, 2);
    await updateForwarder('test-token', { ...install, accountId: 'abc' }, 'https://purple.example/api/ingest', 'test-secret');
    assert.equal(calls.filter(call => call.route.endsWith('/purple-forwarder-test') && call.method === 'PUT').length, 2);
  } finally { globalThis.fetch = original; }
});

test('collector source changes attach new Workers and leave other tail consumers intact', async () => {
  const original = globalThis.fetch;
  const settings = {
    checkout: [{ service: 'audit' }, { service: 'purple-collector-test' }],
    payments: [{ service: 'analytics' }]
  };
  globalThis.fetch = async (url, options = {}) => {
    const route = new URL(url).pathname;
    const source = route.match(/\/workers\/scripts\/([^/]+)\/script-settings$/)?.[1];
    if (route.endsWith('/workers/scripts')) return { ok: true, json: async () => ({ success: true, result: [{ id: 'checkout' }, { id: 'payments' }] }) };
    if (source) {
      if (options.method === 'PATCH') settings[source] = JSON.parse(options.body).tail_consumers;
      return { ok: true, json: async () => ({ success: true, result: { tail_consumers: settings[source] } }) };
    }
    throw new Error(`Unexpected Cloudflare route: ${route}`);
  };
  try {
    const install = { accountId: 'abc', status: 'installed', collector: 'purple-collector-test', sources: ['checkout'], attached: ['checkout'] };
    let saves = 0;
    await syncCollectorSources('test-token', install, ['payments'], () => saves++);
    assert.deepEqual(settings.checkout, [{ service: 'audit' }]);
    assert.deepEqual(settings.payments, [{ service: 'analytics' }, { service: 'purple-collector-test' }]);
    assert.deepEqual(install.sources, ['payments']);
    assert.deepEqual(install.attached, ['payments']);
    assert.ok(saves >= 2);
    await assert.rejects(syncCollectorSources('test-token', install, ['missing'], () => {}), /no longer available/);
    assert.deepEqual(install.sources, ['payments']);
  } finally { globalThis.fetch = original; }
});
