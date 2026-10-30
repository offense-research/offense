import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { once } from 'node:events';
import { usageMetrics, registerUsageMetrics } from '../server/usage-metrics.js';
import { createScanMetering } from '../server/scan-metering.js';
import { readFileSync } from 'node:fs';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

const DAY = 86_400_000, NOW = Date.UTC(2026, 9, 26, 12);
const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));

function fixture(t, now = NOW) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  db.exec(`CREATE TABLE scan_usage_jobs(job_id TEXT PRIMARY KEY, workspace_id TEXT, created_at INTEGER,
    started_at INTEGER, finished_at INTEGER, status TEXT, input_bytes INTEGER, file_count INTEGER, tool_count INTEGER,
    queue_ms INTEGER, execution_ms INTEGER, container_ms INTEGER, findings_count INTEGER,
    outbound_connections INTEGER, network_failures INTEGER);
    CREATE TABLE scan_usage_tools(job_id TEXT, tool_id TEXT, status TEXT, duration_ms INTEGER,
      findings_count INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, unknown INTEGER,
      PRIMARY KEY(job_id,tool_id));
    CREATE TABLE scan_usage_activity(day TEXT, workspace_id TEXT, tool_id TEXT, kind TEXT, count INTEGER,
      PRIMARY KEY(day,workspace_id,tool_id,kind));
    CREATE TABLE scan_usage_meta(key TEXT PRIMARY KEY,value INTEGER);
    CREATE TABLE scan_jobs(id TEXT PRIMARY KEY,workspace_id TEXT,created_at INTEGER);`);
  db.prepare('INSERT INTO scan_usage_meta VALUES (?,?)').run('tracking_started_at', now - DAY);
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices, now: () => now });
  function job(id, { workspace = 'tenant-a', createdAt = now, status = 'completed', bytes = 100,
    queue = 100, execution = 1000, container = 1200, findings = 1, connections = null, failures = null,
    tools = ['checkov'] } = {}) {
    db.prepare('INSERT INTO scan_usage_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, workspace, createdAt,
      status === 'queued' ? null : createdAt + (queue ?? 0), ['completed', 'partial', 'failed'].includes(status) ? createdAt + (queue ?? 0) + (execution ?? 0) : null,
      status, bytes, 1, tools.length, queue, execution, container, findings, connections, failures);
    db.prepare('INSERT INTO scan_jobs VALUES(?,?,?)').run(id, workspace, createdAt);
    const put = db.prepare('INSERT INTO scan_usage_tools VALUES(?,?,?,?,?,?,?,?,?,?)');
    for (const tool of tools) put.run(id, tool, status === 'completed' ? 'complete' : status, execution, findings,
      findings === null ? null : 0, findings, findings === null ? null : 0, findings === null ? null : 0, findings === null ? null : 0);
  }
  return { db, meter, job, read: options => usageMetrics(db, { now: () => now, ...options }) };
}

test('UTC calendar cohorts, exact outcomes, nullable measurements and nearest-rank latency stay distinct', t => {
  const f = fixture(t);
  f.job('a'.repeat(32), { createdAt: NOW - 6 * DAY, queue: 100, execution: 1000, connections: 5, failures: 0 });
  f.job('b'.repeat(32), { createdAt: NOW - DAY, status: 'partial', queue: 200, execution: 2000, findings: 2, connections: 4, failures: 1 });
  f.job('c'.repeat(32), { status: 'failed', queue: null, execution: null, container: null, findings: null });
  f.job('d'.repeat(32), { status: 'queued', queue: null, execution: null, container: null, findings: null });
  f.job('e'.repeat(32), { createdAt: NOW - 7 * DAY, bytes: 9999, findings: 999 });
  f.job('f'.repeat(32), { createdAt: NOW + DAY, bytes: 9999, findings: 999 });
  const metrics = f.read({ days: 7 });
  assert.equal(metrics.timezone, 'UTC'); assert.equal(metrics.series.length, 7);
  assert.equal(metrics.series[0].date, '2026-10-20'); assert.equal(metrics.series.at(-1).date, '2026-10-26');
  assert.deepEqual([metrics.totals.jobs, metrics.totals.completed, metrics.totals.partial, metrics.totals.failed, metrics.totals.active], [4, 1, 1, 1, 1]);
  assert.equal(metrics.totals.successRate, 1 / 3);
  assert.equal(metrics.totals.inputBytes, 400); assert.equal(metrics.totals.findings, 3);
  assert.equal(metrics.totals.findingsSamples, 2); assert.equal(metrics.totals.confirmedVulnerabilities, 0);
  assert.equal(metrics.totals.outboundConnections, 9); assert.equal(metrics.totals.networkFailures, 1);
  assert.deepEqual(metrics.latency.queue, { samples: 2, p50Ms: 100, p95Ms: 200 });
  assert.deepEqual(metrics.latency.execution, { samples: 2, p50Ms: 1000, p95Ms: 2000 });
  assert.equal(metrics.totals.containerDurationMs, 2400); assert.equal(metrics.totals.containerDurationSamples, 2);
  assert.equal(metrics.tools[0].id, 'checkov'); assert.equal(metrics.tools[0].jobs, 4);
  assert.equal(metrics.tools[0].findings, 3); assert.equal(metrics.tools[0].severity.high, 3);
  assert.equal(metrics.series[1].jobs, 0); assert.equal(metrics.series[1].findings, 0);
});

test('per-workspace aggregates never reveal another tenant or its identities', t => {
  const f = fixture(t);
  f.job('a'.repeat(32));
  f.job('b'.repeat(32), { workspace: 'customer-name-private-token', bytes: 900000, findings: 999, tools: ['sslyze'] });
  const scoped = f.read({ workspaceId: 'tenant-a' });
  assert.equal(scoped.totals.jobs, 1); assert.equal(scoped.totals.inputBytes, 100); assert.equal(scoped.totals.findings, 1);
  assert.equal(scoped.totals.activeWorkspaces, undefined); assert.equal(scoped.tools.length, 1);
  for (const secret of ['tenant-a', 'customer-name-private-token', 'a'.repeat(32), 'b'.repeat(32), '900000'])
    assert.ok(!JSON.stringify(scoped).includes(secret), secret);
  const operator = f.read(); assert.equal(operator.totals.activeWorkspaces, 2); assert.equal(operator.totals.jobs, 2);
});

test('usage money comes from idempotent debits and refunds, while credit purchases and held balances stay separate', t => {
  const f = fixture(t), id = 'a'.repeat(32);
  f.job(id, { tools: ['opengrep', 'checkov'] });
  f.meter.recordVerifiedPurchase({ workspaceId: 'tenant-a', paymentId: 'payment-fixture-01', amountMicros: 10_000_000 });
  f.meter.recordVerifiedPurchase({ workspaceId: 'tenant-a', paymentId: 'payment-fixture-01', amountMicros: 10_000_000 });
  const quote = f.meter.quote({ tools: ['opengrep', 'checkov'], inputBytes: 100, fileCount: 1 });
  f.meter.reserve({ jobId: id, workspaceId: 'tenant-a', quote });
  const complete = { jobId: id, status: 'completed', tools: [{ name: 'opengrep', status: 'complete' }, { name: 'checkov', status: 'complete' }] };
  f.meter.settle(complete); f.meter.settle(complete);
  const reservedId = 'b'.repeat(32);
  f.meter.reserve({ jobId: reservedId, workspaceId: 'tenant-a', quote });
  let metrics = f.read({ workspaceId: 'tenant-a' });
  assert.equal(metrics.billing.chargesMicros, 75000); assert.equal(metrics.billing.netUsageMicros, 75000);
  assert.equal(metrics.billing.topUpsMicros, 10_000_000); assert.equal(metrics.billing.reservedMicros, 75000);
  assert.equal(metrics.billing.balanceMicros, 9_925_000); assert.equal(metrics.billing.availableMicros, 9_850_000);
  assert.equal(metrics.tools.find(tool => tool.id === 'checkov').netUsageMicros, 50000);
  assert.equal(metrics.tools.find(tool => tool.id === 'opengrep').netUsageMicros, 25000);
  f.meter.release(id); f.meter.release(id);
  metrics = f.read({ workspaceId: 'tenant-a' });
  assert.equal(metrics.billing.refundsMicros, 75000); assert.equal(metrics.billing.netUsageMicros, 0);
  assert.equal(metrics.tools.find(tool => tool.id === 'checkov').netUsageMicros, 0);
  assert.equal(metrics.billing.topUpsMicros, 10_000_000);
  assert.equal(metrics.billing.attributedUsageMicros, 0); assert.equal(metrics.billing.unattributedUsageMicros, 0);
});

test('posted-period refunds can be negative consumption without relabeling them as purchases or dropping old jobs', t => {
  const f = fixture(t), id = 'a'.repeat(32);
  f.job(id, { createdAt: NOW - 40 * DAY });
  f.db.prepare('INSERT INTO scan_meter_jobs VALUES(?,?,?,?,?,?,?,?,?)').run(id, 'tenant-a', 'released', JSON.stringify({ maximumMicros: 100000,
    prices: [{ tool: 'checkov', maximumMicros: 100000 }] }), 0, 100000, null, NOW - 40 * DAY, NOW);
  f.db.prepare('INSERT INTO scan_wallet_entries VALUES(?,?,?,?,?)').run(`usage:${id}`, 'tenant-a', -100000, 'usage', NOW - 40 * DAY);
  f.db.prepare('INSERT INTO scan_wallet_entries VALUES(?,?,?,?,?)').run(`refund:${id}`, 'tenant-a', 100000, 'refund', NOW);
  const metrics = f.read({ days: 7 });
  assert.equal(metrics.totals.jobs, 0); assert.equal(metrics.billing.chargesMicros, 0);
  assert.equal(metrics.billing.refundsMicros, 100000); assert.equal(metrics.billing.netUsageMicros, -100000);
  assert.equal(metrics.billing.topUpsMicros, 0); assert.equal(metrics.tools[0].jobs, 0);
  assert.equal(metrics.tools[0].netUsageMicros, -100000); assert.equal(metrics.series.at(-1).netUsageMicros, -100000);
});

test('missing history and expired raw report measurements remain explicitly unknown', t => {
  const f = fixture(t);
  f.job('a'.repeat(32), { findings: null, queue: null, execution: null, container: null });
  f.db.prepare('INSERT INTO scan_jobs VALUES(?,?,?)').run('legacy', 'tenant-a', NOW - DAY);
  const metrics = f.read();
  assert.equal(metrics.totals.findings, null); assert.equal(metrics.totals.containerDurationMs, null);
  assert.equal(metrics.totals.outboundConnections, null); assert.equal(metrics.tools[0].severity.high, null);
  assert.equal(metrics.latency.execution.samples, 0); assert.equal(metrics.latency.execution.p95Ms, null);
  assert.equal(metrics.coverage.legacyJobsMissing, 1); assert.equal(metrics.coverage.complete, false);
  assert.equal(metrics.series.at(-2).jobs, null); assert.equal(metrics.series.at(-2).findings, null);
  const empty = new DatabaseSync(':memory:'); t.after(() => empty.close());
  const absent = usageMetrics(empty, { now: () => NOW });
  assert.equal(absent.coverage.available, false); assert.equal(absent.totals.jobs, null);
  assert.equal(absent.billing.chargesMicros, null); assert.equal(absent.series[0].jobs, null);
});

test('aggregate authenticated quote activity is scoped and does not invent pre-tracking events', t => {
  const f = fixture(t);
  for (const [workspace, kind, count] of [['tenant-a', 'quote_issued', 3], ['tenant-a', 'quote_denied', 2],
    ['tenant-a', 'submission_denied', 1], ['tenant-b', 'quote_issued', 100]]) {
    f.db.prepare('INSERT INTO scan_usage_activity VALUES(?,?,?,?,?)').run('2026-10-26', workspace, 'checkov', kind, count);
  }
  const scoped = f.read({ workspaceId: 'tenant-a', days: 7 });
  assert.deepEqual(scoped.activity, { quotesIssued: 3, quotesDenied: 2, submissionsDenied: 1 });
  assert.equal(scoped.series[0].activity.quotesIssued, null);
  assert.equal(scoped.series.at(-1).activity.quotesIssued, 3);
  assert.equal(f.read().activity.quotesIssued, 103);
});

test('read-only aggregation leaves wallet rows, reports and jobs unchanged', t => {
  const f = fixture(t); f.job('a'.repeat(32));
  const before = f.db.prepare('SELECT total_changes() AS value').get().value;
  f.read(); f.read({ days: 7 }); f.read({ workspaceId: 'tenant-a', days: 90 });
  assert.equal(f.db.prepare('SELECT total_changes() AS value').get().value, before);
});

test('legacy debits without surviving quotes keep exact totals but withhold per-tool money', t => {
  const f = fixture(t); f.job('a'.repeat(32));
  f.db.prepare('INSERT INTO scan_wallet_entries VALUES(?,?,?,?,?)').run('legacy-usage', 'tenant-a', -100000, 'usage', NOW);
  f.db.prepare('INSERT INTO scan_wallet_entries VALUES(?,?,?,?,?)').run('legacy-other', 'tenant-b', -999999, 'usage', NOW);
  const metrics = f.read({ workspaceId: 'tenant-a' });
  assert.equal(metrics.billing.chargesMicros, 100000); assert.equal(metrics.billing.netUsageMicros, 100000);
  assert.equal(metrics.billing.unattributedUsageMicros, 100000); assert.equal(metrics.billing.allocationComplete, false);
  assert.equal(metrics.tools[0].netUsageMicros, null);
});

test('secured routes reject anonymous users, nonoperators, invalid windows and caller-selected tenants', async t => {
  const f = fixture(t, Date.now()); f.job('a'.repeat(32)); f.job('b'.repeat(32), { workspace: 'tenant-b', findings: 99 });
  const app = express();
  app.use((req, _res, next) => {
    const user = req.get('x-fixture-user');
    req.authUser = user ? { githubId: user } : null;
    req.workspaceId = user ? 'tenant-a' : null; next();
  });
  registerUsageMetrics(app, { db: f.db, operatorIds: '1234' });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const route of ['/api/scanner-usage', '/api/operator/usage']) assert.equal((await fetch(base + route)).status, 401);
  assert.equal((await fetch(base + '/api/operator/usage', { headers: { 'x-fixture-user': '9999' } })).status, 403);
  const headers = { 'x-fixture-user': '1234' };
  for (const query of ['?days=1', '?days=7.0', '?days=7&days=30', '?workspaceId=tenant-b', '?days=7&tenant=tenant-b'])
    assert.equal((await fetch(base + '/api/scanner-usage' + query, { headers })).status, 400);
  const scopedResponse = await fetch(base + '/api/scanner-usage?days=7', { headers });
  assert.equal(scopedResponse.status, 200); assert.equal(scopedResponse.headers.get('cache-control'), 'no-store');
  assert.equal(scopedResponse.headers.get('vary'), 'Cookie');
  const scoped = await scopedResponse.json(); assert.equal(scoped.totals.jobs, 1); assert.equal(scoped.totals.findings, 1);
  assert.equal(JSON.stringify(scoped).includes('tenant-b'), false);
  const operator = await (await fetch(base + '/api/operator/usage?days=7', { headers })).json();
  assert.equal(operator.totals.jobs, 2); assert.equal(operator.totals.findings, 100);
});

test('real app session middleware scopes workspace usage and gates company usage by operator ID', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const { app } = createWorkerApp({ db, env: { OPERATIONS_GITHUB_IDS: '1234' }, schedule: () => {} });
  const accounts = createAccounts(db), at = Date.now();
  for (const [letter, githubId, findingCount] of [['a', 1234, 1], ['b', 5678, 99]]) {
    const user = accounts.upsertUser(githubId, `private-login-${letter}`), workspace = `private-workspace-${letter}`;
    accounts.createWorkspace(user.id, workspace, { company: `Private company ${letter}`, privateToken: 'PRIVATE_USAGE_MARKER' });
    db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(letter.repeat(64), JSON.stringify({ userId: user.id, workspaceId: workspace }), at);
    db.prepare('INSERT INTO scan_usage_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(letter.repeat(32), workspace, at, at, at, 'completed', 100, 1, 1, 0, 0, null, findingCount, null, null);
    db.prepare('INSERT INTO scan_usage_tools VALUES(?,?,?,?,?,?,?,?,?,?)')
      .run(letter.repeat(32), 'checkov', 'complete', 100, findingCount, 0, findingCount, 0, 0, 0);
  }
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = (route, letter) => fetch(base + route, { headers: letter ? { cookie: `purple_session=${letter.repeat(64)}` } : {} });
  assert.equal((await get('/api/scanner-usage')).status, 401);
  assert.equal((await fetch(base + '/api/operator/usage', { headers: { 'x-fixture-user': '1234' } })).status, 401);
  assert.equal((await get('/api/operator/usage', 'b')).status, 403);
  const customer = await (await get('/api/scanner-usage?days=7', 'b')).json();
  assert.equal(customer.scope, 'workspace'); assert.equal(customer.totals.jobs, 1); assert.equal(customer.totals.findings, 99);
  assert.equal(customer.totals.activeWorkspaces, undefined);
  const operator = await (await get('/api/operator/usage?days=7', 'a')).json();
  assert.equal(operator.scope, 'operator'); assert.equal(operator.totals.jobs, 2); assert.equal(operator.totals.findings, 100);
  assert.equal(operator.totals.activeWorkspaces, 2);
  assert.equal((await get('/api/scanner-usage?workspaceId=private-workspace-a', 'b')).status, 400);
  for (const response of [customer, operator]) for (const marker of ['private-workspace', 'private-login', 'Private company', 'PRIVATE_USAGE_MARKER'])
    assert.ok(!JSON.stringify(response).includes(marker));
});
