import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync, backup } from 'node:sqlite';
import express from 'express';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createToolCallMetrics, registerToolCallMetrics, markToolCallOutcome, toolCallOperation } from '../server/tool-call-metrics.js';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 28, 14);
const descriptor = { kind: 'tool', channel: 'mcp', operation: 'audit' };
function fixture(t, now = NOW) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const clock = { value: now };
  const store = createToolCallMetrics({ db, now: () => clock.value });
  return { db, store, clock };
}
async function serve(t, app) {
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return 'http://127.0.0.1:' + server.address().port;
}

test('durable start cohorts count attempts separately from terminal outcomes and never count finishes twice', t => {
  const { store, db } = fixture(t);
  const call = store.start(descriptor);
  assert.equal(store.read().lifetime.total, 1);
  assert.equal(store.read().lifetime.unfinished, 1);
  assert.equal(call.finish({ status: 'nonsense' }), false);
  assert.equal(call.finish({ status: 'completed' }), true);
  assert.equal(call.finish({ status: 'failed' }), false);
  assert.deepEqual(store.read().lifetime, { total: 1, completed: 1, failed: 0, rejected: 0, unfinished: 0 });
  const second = createToolCallMetrics({ db, now: () => NOW + 1000 });
  assert.equal(second.read().lifetime.total, 1);
  assert.equal(second.read().coverage.trackingStartedAt, NOW);
});

test('one direct security HTTP request counts once in each separate scope, while metadata requests never inflate tool calls', async t => {
  const { store } = fixture(t);
  const app = express(); app.use(store.middleware());
  app.post('/api/offense/audit', (req, res) => res.json({ fixture: true }));
  app.get('/v1/catalog', (req, res) => res.json({ tools: [] }));
  const base = await serve(t, app);
  assert.equal((await fetch(base + '/api/offense/audit', { method: 'POST' })).status, 200);
  assert.equal((await fetch(base + '/v1/catalog')).status, 200);
  assert.equal(store.read({ scope: 'tools' }).lifetime.total, 1);
  const requests = store.read({ scope: 'requests' });
  assert.equal(requests.lifetime.total, 2);
  assert.deepEqual(requests.breakdown.map(row => row.endpoint).sort(), ['GET /v1/catalog', 'POST /api/offense/audit']);
});

test('MCP transport messages and actual security actions remain different counters, including HTTP-200 RPC failures', async t => {
  const { store } = fixture(t);
  const app = express(); app.use(store.middleware());
  app.post('/mcp', (req, res) => {
    const call = store.start(descriptor);
    call.finish({ status: 'rejected' });
    markToolCallOutcome(req, 'rejected');
    res.json({ error: { code: -32602 } });
  });
  const base = await serve(t, app);
  assert.equal((await fetch(base + '/mcp', { method: 'POST' })).status, 200);
  assert.deepEqual(store.read().lifetime, { total: 1, completed: 0, failed: 0, rejected: 1, unfinished: 0 });
  assert.deepEqual(store.read({ scope: 'requests' }).lifetime, { total: 1, completed: 0, failed: 0, rejected: 1, unfinished: 0 });
  assert.equal(store.read().breakdown[0].endpoint, 'offense.audit_dependencies');
  assert.equal(store.read({ scope: 'requests' }).breakdown[0].endpoint, 'POST /mcp');
  assert.equal(toolCallOperation('offense.security_call'), 'hosted_scan');
  assert.equal(toolCallOperation('offense.audit_dependencies'), 'audit');
  assert.equal(toolCallOperation('offense.account'), null);
  assert.equal(markToolCallOutcome({}, 'failed'), false);
});

test('failed, malformed and repeated idempotent submission attempts count as calls even when no new job exists', async t => {
  const { store } = fixture(t);
  const app = express(); app.use(store.middleware()); app.use(express.json());
  app.post('/v1/call/:tool', (req, res) => res.status(req.body.fail ? 503 : 202).json({ id: 'same-job' }));
  app.use((error, req, res, next) => res.status(400).end());
  const base = await serve(t, app);
  for (let i = 0; i < 2; i++) await fetch(base + '/v1/call/opengrep', { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': 'same-request' }, body: '{}' });
  await fetch(base + '/v1/call/opengrep', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
  await fetch(base + '/v1/call/opengrep', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"fail":true}' });
  assert.deepEqual(store.read().lifetime, { total: 4, completed: 2, failed: 1, rejected: 1, unfinished: 0 });
  assert.equal(store.read({ scope: 'requests' }).lifetime.total, 4);
});

test('HTTP path/query/body secrets and unknown endpoints are never stored as labels', async t => {
  const { store, db } = fixture(t);
  const app = express(); app.use(store.middleware()); app.use((req, res) => res.status(404).end());
  const base = await serve(t, app);
  for (const pathname of ['/health', '/api/state', '/api/auth/github/start', '/api/scanner-billing/whop/webhook', '/api/operator/tool-calls', '/assets/private.js', '/v1/random-private-company', '/mcp/private-token']) {
    await fetch(base + pathname);
  }
  await fetch(base + '/v1/scans/' + 'a'.repeat(32) + '?token=PRIVATE_QUERY_VALUE');
  await fetch(base + '/v1/call/private-company-name', { method: 'POST', body: 'PRIVATE_SOURCE_TEXT' });
  const rows = db.prepare('SELECT * FROM tool_call_days').all();
  const serialized = JSON.stringify(rows);
  assert.equal(rows.length, 3, 'Result request plus hosted request and hosted tool cohort.');
  assert.ok(!/PRIVATE|private-company|token|aaaaaaaa/.test(serialized));
  assert.ok(serialized.includes('GET /v1/scans/:id'));
  assert.ok(serialized.includes('POST /v1/call/:tool'));
  assert.deepEqual(Object.keys(rows[0]).sort(), ['day', 'kind', 'channel', 'operation', 'endpoint', 'started', 'completed', 'failed', 'rejected'].sort());
});

test('invalid caller labels cannot add cardinality, poison counters, or include sensitive attributes', t => {
  const { store, db } = fixture(t);
  for (const input of [null, {}, { ...descriptor, operation: 'private-repo' }, { ...descriptor, endpoint: 'https://user:secret@host/' },
    { ...descriptor, kind: 'request' }, { ...descriptor, channel: 'browser' }, { kind: 'tool', channel: 'http', operation: 'catalog', endpoint: 'GET /v1/catalog' }]) {
    assert.equal(store.start(input).finish({ status: 'completed' }), false);
  }
  store.start({ ...descriptor, source: 'NOT_STORED', token: 'NOT_STORED', requestId: 'NOT_STORED' }).finish({ status: 'completed' });
  assert.equal(store.read().lifetime.total, 1);
  assert.ok(!JSON.stringify(db.prepare('SELECT * FROM tool_call_days').all()).includes('NOT_STORED'));
});

test('UTC start-day cohorts preserve cross-midnight finishes and missing historical days stay unknown', t => {
  const start = Date.UTC(2026, 9, 27, 23, 59, 59), { store, clock } = fixture(t, start);
  const call = store.start(descriptor);
  clock.value = start + 2000; call.finish({ status: 'completed' });
  const result = store.read({ days: 7 });
  assert.equal(result.series.at(-2).completed, 1);
  assert.equal(result.series.at(-1).total, 0);
  assert.equal(result.series.at(-3).tracked, false); assert.equal(result.series.at(-3).total, null);
  assert.equal(result.today.total, 0); assert.equal(result.yesterday.total, 1);
  assert.deepEqual(result.change, { absolute: null, percent: null, comparable: false }, 'The first tracked day is incomplete.');
});

test('daily growth uses a completely observed prior day and never invents a percent from zero', t => {
  const { store, clock } = fixture(t, NOW - 3 * DAY);
  store.start(descriptor).finish({ status: 'completed' });
  clock.value = NOW;
  store.start(descriptor).finish({ status: 'completed' });
  let result = store.read();
  assert.deepEqual(result.change, { absolute: 1, percent: null, comparable: true });
  clock.value = NOW + DAY;
  for (let i = 0; i < 3; i++) store.start(descriptor).finish({ status: 'completed' });
  result = store.read();
  assert.deepEqual(result.change, { absolute: 2, percent: 200, comparable: true });
  assert.equal(result.lifetime.total, 5);
});

test('read windows are bounded while lifetime is durable and reads do not modify storage', t => {
  const { store, clock, db } = fixture(t, NOW - 100 * DAY);
  store.start(descriptor).finish({ status: 'completed' }); clock.value = NOW;
  store.start(descriptor).finish({ status: 'failed' });
  const changes = db.prepare('SELECT total_changes() AS n').get().n;
  for (const days of [7, 30, 90]) {
    const result = store.read({ days });
    assert.equal(result.series.length, days); assert.equal(result.totals.total, 1); assert.equal(result.lifetime.total, 2);
  }
  assert.equal(db.prepare('SELECT total_changes() AS n').get().n, changes);
  for (const options of [{ days: 0 }, { days: '7' }, { scope: 'workspace' }, { scope: 'all' }]) assert.throws(() => store.read(options), error => error.status === 400);
});

test('recording failure never fails the product request and unavailable measurements are never reported as zero', async t => {
  const { store, db } = fixture(t);
  db.exec("CREATE TRIGGER fail_calls BEFORE INSERT ON tool_call_days BEGIN SELECT RAISE(ABORT, 'PRIVATE_STORAGE_DETAIL'); END;");
  const app = express(); app.use(store.middleware()); app.post('/api/offense/audit', (req, res) => res.json({ okay: true }));
  const base = await serve(t, app);
  assert.equal((await fetch(base + '/api/offense/audit', { method: 'POST' })).status, 200);
  const result = store.read();
  assert.equal(result.coverage.available, false); assert.equal(result.lifetime.total, null); assert.deepEqual(result.breakdown, []);
  assert.ok(!JSON.stringify(result).includes('PRIVATE_STORAGE_DETAIL'));
});

test('a failed terminal write is not retried and initialization failure stays inert', t => {
  const { store, db } = fixture(t);
  const ticket = store.start(descriptor);
  db.exec("CREATE TRIGGER fail_finish BEFORE UPDATE ON tool_call_days BEGIN SELECT RAISE(ABORT, 'failure'); END;");
  assert.equal(ticket.finish({ status: 'completed' }), false);
  db.exec('DROP TRIGGER fail_finish');
  assert.equal(ticket.finish({ status: 'completed' }), false);
  assert.equal(db.prepare('SELECT started,completed FROM tool_call_days').get().completed, 0);
  assert.equal(store.read().coverage.available, false);
  const broken = createToolCallMetrics({ db: { exec() { throw Error('storage unavailable'); } }, now: () => NOW });
  assert.equal(broken.start(descriptor).finish({ status: 'failed' }), false);
  assert.equal(broken.read().lifetime.total, null);
});

test('a persisted recording warning survives a healthy restart without hiding usable recorded counts', t => {
  const { store, db, clock } = fixture(t, NOW - 3 * DAY);
  store.start(descriptor).finish({ status: 'completed' });
  db.exec("CREATE TRIGGER fail_call_start BEFORE INSERT ON tool_call_days BEGIN SELECT RAISE(ABORT, 'synthetic outage'); END;");
  clock.value = NOW - 2 * DAY;
  store.start(descriptor).finish({ status: 'completed' });
  assert.equal(store.read().coverage.available, false);
  assert.equal(store.read().coverage.hasRecordingGap, true);
  db.exec('DROP TRIGGER fail_call_start');
  // A new database facade models the fresh connection on a process restart;
  // persisted rows remain the same while the process-local WeakSet is reset.
  const reopened = { exec: sql => db.exec(sql), prepare: sql => db.prepare(sql) };
  const recovered = createToolCallMetrics({ db: reopened, now: () => NOW });
  recovered.start(descriptor).finish({ status: 'completed' });
  const result = recovered.read();
  assert.equal(result.coverage.available, true);
  assert.equal(result.coverage.hasRecordingGap, true);
  assert.equal(result.coverage.recordingFailedAt, NOW - 2 * DAY);
  assert.equal(result.lifetime.total, 2);
  assert.equal(result.today.total, 1);
  assert.equal(result.change.comparable, false);
  assert.match(result.coverage.reason, /accepted counter records/);
});

test('corrupted dimensions or counters make the aggregate unavailable without exposing stored labels', t => {
  const { store, db } = fixture(t);
  store.start(descriptor).finish({ status: 'completed' });
  db.prepare("UPDATE tool_call_days SET endpoint = 'PRIVATE_STORED_CONTEXT'").run();
  const result = store.read();
  assert.equal(result.coverage.available, false); assert.equal(result.totals.total, null);
  assert.ok(!JSON.stringify(result).includes('PRIVATE_STORED_CONTEXT'));
});

test('binary-upload bridge labels are request-only and do not inflate security actions', t => {
  const { store } = fixture(t);
  const upload = { kind: 'request', channel: 'http', operation: 'artifact_upload', endpoint: 'POST /v1/artifacts' };
  store.start(upload).finish({ status: 'completed' });
  store.start({ ...upload, kind: 'tool' }).finish({ status: 'completed' });
  assert.equal(store.read({ scope: 'requests' }).lifetime.total, 1);
  assert.equal(store.read().lifetime.total, 0);
});

test('a SQLite backup and restore preserve counts and the original coverage start', async t => {
  const { store, db } = fixture(t);
  store.start(descriptor).finish({ status: 'completed' });
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-call-metrics-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'counts.sqlite'); await backup(db, file);
  const restored = new DatabaseSync(file); t.after(() => restored.close());
  const loaded = createToolCallMetrics({ db: restored, now: () => NOW + DAY }).read();
  assert.equal(loaded.lifetime.total, 1); assert.equal(loaded.coverage.trackingStartedAt, NOW);
});

test('operator API strictly gates company aggregates and rejects caller-selected identities or invalid windows', async t => {
  const { store } = fixture(t); store.start(descriptor).finish({ status: 'completed' });
  const app = express();
  app.use((req, res, next) => { if (req.get('x-fixture-user')) req.authUser = { githubId: req.get('x-fixture-user') }; next(); });
  registerToolCallMetrics(app, { store, operatorIds: '123' });
  const base = await serve(t, app);
  assert.equal((await fetch(base + '/api/operator/tool-calls')).status, 401);
  assert.equal((await fetch(base + '/api/operator/tool-calls', { headers: { 'x-fixture-user': '999' } })).status, 403);
  for (const query of ['days=1', 'days=7&days=30', 'scope=company', 'workspace=private', 'days=90&scope=tools&user=123']) {
    assert.equal((await fetch(base + '/api/operator/tool-calls?' + query, { headers: { 'x-fixture-user': '123' } })).status, 400, query);
  }
  const response = await fetch(base + '/api/operator/tool-calls?days=7&scope=tools', { headers: { 'x-fixture-user': '123' } });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('vary'), 'Cookie'); assert.equal((await response.json()).lifetime.total, 1);
});
