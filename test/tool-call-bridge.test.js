import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createToolCallMetrics } from '../server/tool-call-metrics.js';
import { createToolCallBridge, withArtifactCallMetrics } from '../workers/tool-call-bridge.js';
import { createWorkerApp } from '../workers/app-api.js';

function fixture(t, options = {}) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let clock = Date.UTC(2026, 9, 28, 12);
  const store = createToolCallMetrics({ db, now: () => clock });
  const bridge = createToolCallBridge(store, { now: () => clock, ...options });
  const state = { beginArtifactCallMetrics: bridge.begin, finishArtifactCallMetrics: bridge.finish };
  return { db, store, bridge, state, advance: value => { clock += value; } };
}

test('one outer artifact request produces one request count, with no scan or internal-RPC inflation', async t => {
  const f = fixture(t);
  const response = await withArtifactCallMetrics(f.state, async () => new Response('fixture', { status: 403 }));
  assert.equal(response.status, 403);
  const usage = f.store.read({ scope: 'requests' });
  assert.equal(usage.lifetime.total, 1); assert.equal(usage.lifetime.rejected, 1);
  assert.equal(usage.lifetime.unfinished, 0); assert.equal(f.store.read().lifetime.total, 0);
  assert.equal(usage.breakdown[0].endpoint, 'POST /v1/artifacts');
  assert.deepEqual(f.db.prepare('SELECT DISTINCT operation,endpoint FROM tool_call_days').all().map(row => ({ ...row })),
    [{ operation: 'artifact_upload', endpoint: 'POST /v1/artifacts' }]);
});

test('ephemeral completion handles are idempotent, bounded, and never persisted', t => {
  const f = fixture(t, { maximum: 1, ttl: 1000 });
  const ticket = f.bridge.begin(); assert.match(ticket, /^[a-f0-9]{32}$/);
  assert.equal(f.bridge.begin(), null);
  assert.equal(f.bridge.finish(ticket, 201), true); assert.equal(f.bridge.finish(ticket, 500), false);
  const next = f.bridge.begin(); f.advance(1001); f.bridge.begin();
  assert.equal(f.bridge.finish(next, 200), false);
  const usage = f.store.read({ scope: 'requests' });
  assert.equal(usage.lifetime.total, 4); assert.equal(usage.lifetime.completed, 1); assert.equal(usage.lifetime.unfinished, 3);
  assert.equal(JSON.stringify(f.db.prepare('SELECT * FROM tool_call_days').all()).includes(ticket), false);
  assert.equal(JSON.stringify(f.db.prepare('SELECT * FROM tool_call_meta').all()).includes(ticket), false);
});

test('upload exceptions count as failed and telemetry failures preserve the original upload behavior', async t => {
  const f = fixture(t), error = new Error('synthetic upload error');
  await assert.rejects(withArtifactCallMetrics(f.state, async () => { throw error; }), value => value === error);
  assert.equal(f.store.read({ scope: 'requests' }).lifetime.failed, 1);
  const unavailable = { beginArtifactCallMetrics() { throw Error('synthetic counter unavailable'); } };
  const response = await withArtifactCallMetrics(unavailable, async () => new Response('accepted', { status: 201 }));
  assert.equal(response.status, 201);
  const finishUnavailable = { beginArtifactCallMetrics: f.bridge.begin, finishArtifactCallMetrics() { throw Error('synthetic finish unavailable'); } };
  assert.equal((await withArtifactCallMetrics(finishUnavailable, async () => new Response('accepted', { status: 201 }))).status, 201);
  assert.equal(f.store.read({ scope: 'requests' }).lifetime.unfinished, 1);
});

test('the existing operator key can read count-only telemetry, with strict query scope and no self-counting', async t => {
  const db = new DatabaseSync(':memory:');
  const { app, toolCallMetrics } = createWorkerApp({ db, env: { OPERATIONS_METRICS_KEY: 'operator-fixture-only' }, schedule() {} });
  const ticket = toolCallMetrics.start({ kind: 'tool', channel: 'mcp', operation: 'audit' }); ticket.finish({ status: 'completed' });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await new Promise(resolve => server.close(resolve)); db.close(); });
  const base = `http://127.0.0.1:${server.address().port}/api/internal/tool-calls`;
  for (const headers of [{}, { authorization: 'Bearer wrong' }, { cookie: 'purple_session=fixture-only' }])
    assert.equal((await fetch(base, { headers })).status, 401);
  const headers = { authorization: 'Bearer operator-fixture-only' };
  const response = await fetch(base, { headers });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  const data = await response.json(); assert.equal(data.lifetime.total, 1);
  for (const query of ['?workspace=other', '?days=1', '?scope=other', '?scope=tools&scope=requests'])
    assert.equal((await fetch(base + query, { headers })).status, 400);
  assert.equal((await fetch(base + '?scope=requests', { headers }).then(r => r.json())).lifetime.total, 0);
  assert.equal((await fetch(base + '?key=operator-fixture-only')).status, 401);
});
