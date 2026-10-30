import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createClickHouse } from '../server/clickhouse.js';
import { createEventStore } from '../server/event-store.js';

test('ClickHouse export writes sanitized events and scopes searches to a workspace', async () => {
  const calls = [];
  const clickhouse = createClickHouse({ url: 'https://clickhouse.example:8443', user: 'purple', password: 'secret' }, async (url, options) => {
    calls.push({ url: new URL(url), options });
    return { ok: true, text: async () => String(options.body).startsWith('SELECT')
      ? JSON.stringify({ event_id: 1, received_at_ms: 1000, payload: JSON.stringify({ sourceWorker: 'checkout', requestId: '57d55f210d7b95f3' }) }) + '\n' : '' };
  });
  const row = { id: 1, workspaceId: 'workspace-a', receivedAt: 1000,
    payload: JSON.stringify({ sourceWorker: 'checkout', timestamp: '2026-10-20T17:00:00.000Z', requestId: '57d55f210d7b95f3', logs: [{ level: 'info', message: 'safe log' }] }) };
  await clickhouse.insert([row]);
  assert.match(calls[0].options.body, /ORDER BY \(workspace_id, source_worker, occurred_at, event_id\)/);
  const insert = calls[1];
  assert.match(insert.url.searchParams.get('insert_deduplication_token'), /^[a-f0-9]{64}$/);
  assert.equal(JSON.parse(insert.options.body).workspace_id, 'workspace-a');
  assert.equal(JSON.parse(insert.options.body).request_id, '57d55f210d7b95f3');
  assert.equal(JSON.parse(insert.options.body).log_text, 'safe log');
  const results = await clickhouse.search('workspace-a', { worker: 'checkout', requestId: '57d55f210d7b95f3', from: 1000, to: 2000 });
  assert.equal(results[0].sourceWorker, 'checkout');
  const search = calls[2];
  assert.match(search.options.body, /workspace_id = \{workspace:String\}/);
  assert.equal(search.url.searchParams.get('param_workspace'), 'workspace-a');
  assert.equal(search.url.searchParams.get('param_request_id'), '57d55f210d7b95f3');
  assert.equal(search.url.searchParams.get('param_from'), '1000');
});

test('SQLite keeps unexported events until ClickHouse acknowledges them', () => {
  const db = new DatabaseSync(':memory:');
  const store = createEventStore(db);
  const event = { schema: 'purple.tail.v1', sourceWorker: 'checkout', timestamp: '2026-10-20T17:00:00Z', queueMessageId: 'queue-1', requestId: '57d55f210d7b95f3' };
  store.receiveBatch('workspace-a', [event]);
  const pending = store.pendingExport();
  assert.equal(pending.length, 1);
  assert.equal(JSON.parse(pending[0].payload).requestId, '57d55f210d7b95f3');
  store.receiveBatch('workspace-a', [event]);
  assert.equal(store.pendingExport().length, 1);
  store.markExported(pending);
  assert.equal(store.pendingExport().length, 0);
  db.close();
});

test('a failed ClickHouse insert leaves the SQLite outbox available for retry', async () => {
  const db = new DatabaseSync(':memory:');
  const store = createEventStore(db);
  store.receiveBatch('workspace-a', [{ schema: 'purple.tail.v1', sourceWorker: 'api', queueMessageId: 'queue-2' }]);
  const clickhouse = createClickHouse({ url: 'https://clickhouse.example:8443', password: 'secret' }, async () => ({ ok: false, status: 503, text: async () => 'unavailable' }));
  await assert.rejects(clickhouse.insert(store.pendingExport()), /503/);
  assert.equal(store.pendingExport().length, 1);
  db.close();
});
