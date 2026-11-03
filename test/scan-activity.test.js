import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createHostedScans } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { scanActivity, registerScanActivity } from '../server/scan-activity.js';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

const DAY = 86_400_000, NOW = Date.UTC(2026, 9, 27, 12);
const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const id = n => n.toString(16).padStart(32, '0');

function fixture(t) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices, now: () => NOW });
  const scans = createHostedScans(db, { metering: meter, now: () => NOW });
  db.prepare("UPDATE scan_usage_meta SET value = ? WHERE key = 'tracking_started_at'").run(NOW - 365 * DAY);
  const first = scans.issueKey('tenant-a', 'private-user-a'), second = scans.issueKey('tenant-a', 'private-user-a');
  const foreign = scans.issueKey('tenant-b', 'private-user-b');
  function job(n, { workspace = 'tenant-a', key = first.id, at = NOW, status = 'completed',
    findings = 1, tools = ['opengrep'], fact = true, meterState = 'settled' } = {}) {
    const jobId = id(n);
    db.prepare(`INSERT INTO scan_jobs(id, workspace_id, user_id, key_id, idempotency_key, fingerprint,
      status, created_at, updated_at, started_at, finished_at, input_bytes, file_count, result, error)
      VALUES (?, ?, 'PRIVATE_USER', ?, ?, 'PRIVATE_FINGERPRINT', ?, ?, ?, ?, ?, 100, 1, 'PRIVATE_REPORT', 'PRIVATE_ERROR')`)
      .run(jobId, workspace, key, jobId, status, at, at, at, ['completed', 'partial', 'failed'].includes(status) ? at : null);
    if (fact) {
      db.prepare('INSERT INTO scan_usage_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(jobId, workspace, at, at, at, status, 100, 1, tools.length, 100, 1000, 1200, findings, null, null);
      for (const tool of tools) db.prepare('INSERT INTO scan_usage_tools VALUES (?,?,?,?,?,?,?,?,?,?)')
        .run(jobId, tool, status === 'completed' ? 'complete' : status, 1000, findings, 0, findings, 0, 0, 0);
    }
    if (meterState) db.prepare('INSERT INTO scan_meter_jobs VALUES (?,?,?,?,?,?,?,?,?)')
      .run(jobId, workspace, meterState, JSON.stringify({ maximumMicros: 50_000, prices: [{ tool: 'opengrep', maximumMicros: 50_000 }] }),
        meterState === 'reserved' ? 50_000 : 0, meterState === 'settled' ? 50_000 : 0, null, at, at);
    return jobId;
  }
  function entry(entryId, workspace, amount, kind, at = NOW) {
    db.prepare('INSERT INTO scan_wallet_entries VALUES (?,?,?,?,?)').run(entryId, workspace, amount, kind, at);
  }
  return { db, meter, scans, first, second, foreign, job, entry,
    read: options => scanActivity(db, { workspaceId: 'tenant-a', days: 7, now: NOW, ...options }) };
}

test('activity totals, UTC cohorts and actual key rankings include revoked keys without exposing secrets', t => {
  const f = fixture(t);
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(NOW, f.first.id);
  const a = f.job(1), b = f.job(2, { at: NOW - DAY, key: f.second.id, status: 'failed', findings: 0, meterState: 'released' });
  f.job(3, { key: f.first.id, at: NOW - 2 * DAY, status: 'running', findings: null, meterState: 'reserved' });
  f.job(4, { workspace: 'tenant-b', key: f.foreign.id, findings: 999 });
  f.entry('welcome:private-identity', 'tenant-a', 10_000_000, 'welcome');
  f.entry('purchase:private-provider-id', 'tenant-a', 10_000_000, 'purchase');
  f.entry(`usage:${a}`, 'tenant-a', -50_000, 'usage');
  const data = f.read();
  assert.equal(data.schemaVersion, 1); assert.equal(data.scope, 'workspace'); assert.equal(data.timezone, 'UTC');
  assert.deepEqual(data.summary, { spendMicros: 50_000, jobs: 3, completed: 1, successRate: .5, findings: 1, findingsSamples: 2 });
  assert.equal(data.topKeys.length, 2);
  assert.deepEqual(data.topKeys[0], { id: f.first.id, revoked: true, hostedJobs: 2, netUsageMicros: 50_000, lastUsedAt: NOW });
  assert.equal(data.topKeys[1].id, f.second.id); assert.equal(data.coverage.keyAttributionComplete, true);
  assert.equal(data.coverage.unattributedKeySpendMicros, 0);
  assert.equal(data.series.length, 7); assert.equal(data.series.at(-1).netUsageMicros, 50_000);
  assert.equal(data.recentJobs.length, 3); assert.equal(data.recentJobs[0].id, a);
  assert.equal(data.recentJobs[0].keyId, f.first.id); assert.deepEqual(data.recentJobs[0].tools, [{ id: 'opengrep', name: 'Source code security' }]);
  assert.equal(data.recentJobs.find(row => row.id === b).netUsageMicros, 0);
  assert.equal(data.recentJobs.find(row => row.status === 'running').netUsageMicros, null);
  assert.equal(data.coverage.current.findingsComplete, false); assert.equal(data.comparison.findings.comparable, false);
  const serialized = JSON.stringify(data);
  for (const marker of ['tenant-a', 'tenant-b', 'PRIVATE_USER', 'PRIVATE_REPORT', 'PRIVATE_ERROR', 'PRIVATE_FINGERPRINT',
    'private-provider-id', 'private-identity', f.foreign.id, id(4), f.first.token,
    createHash('sha256').update(f.first.token).digest('hex')]) assert.ok(!serialized.includes(marker), marker);
});

test('calendar boundaries select the current partial day and the preceding complete UTC window', t => {
  const f = fixture(t), today = Math.floor(NOW / DAY) * DAY, startAt = today - 6 * DAY;
  f.job(1, { at: startAt }); f.job(2, { at: NOW });
  f.job(3, { at: startAt - 1 }); f.job(4, { at: startAt - 7 * DAY });
  f.job(5, { at: startAt - 7 * DAY - 1 }); f.job(6, { at: NOW + 1 });
  const data = f.read();
  assert.deepEqual(data.period, { startAt, endAt: NOW });
  assert.deepEqual(data.previousPeriod, { startAt: startAt - 7 * DAY, endAt: startAt - 1 });
  assert.equal(data.summary.jobs, 2); assert.equal(data.previous.jobs, 2);
  assert.deepEqual(data.comparison.jobs, { absolute: 0, percent: 0, comparable: true });
  assert.match(data.definitions.period, /today so far.*preceding complete/);
});

test('posted refunds for older submissions reduce period spend and remain attributed to the original revoked key', t => {
  const f = fixture(t), jobId = f.job(1, { at: NOW - 40 * DAY, meterState: 'released' });
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(NOW, f.first.id);
  f.entry(`usage:${jobId}`, 'tenant-a', -50_000, 'usage', NOW - 40 * DAY);
  f.entry(`refund:${jobId}`, 'tenant-a', 50_000, 'refund');
  const data = f.read();
  assert.equal(data.summary.jobs, 0); assert.equal(data.summary.spendMicros, -50_000);
  assert.deepEqual(data.topKeys, [{ id: f.first.id, revoked: true, hostedJobs: 0, netUsageMicros: -50_000, lastUsedAt: null }]);
  assert.equal(data.coverage.keyAttributionComplete, true); assert.equal(data.series.at(-1).netUsageMicros, -50_000);
  assert.equal(data.recentJobs.length, 0);
  assert.equal(data.comparison.spendMicros.percent, null, 'Do not invent percent change from a zero baseline or negative net spend.');
});

test('unknown or cross-workspace attribution never assigns another account key or offsets missing allocation silently', t => {
  const f = fixture(t), malformed = f.job(1, { key: f.foreign.id });
  f.entry(`usage:${malformed}`, 'tenant-a', -50_000, 'usage');
  f.entry('legacy-usage-private', 'tenant-a', -90_000, 'usage');
  f.entry(`usage:${id(99)}`, 'tenant-b', -999_999, 'usage');
  const data = f.read();
  assert.equal(data.summary.spendMicros, 140_000); assert.equal(data.coverage.keyAttributionComplete, false);
  assert.equal(data.coverage.unattributedKeySpendMicros, 140_000);
  assert.deepEqual(data.topKeys, []); assert.equal(data.recentJobs[0].keyId, null);
  assert.ok(!JSON.stringify(data).includes(f.foreign.id));
});

test('history, sample and zero-baseline comparisons stay explicitly unavailable rather than guessed', t => {
  const f = fixture(t);
  f.job(1, { findings: null });
  f.db.prepare("UPDATE scan_usage_meta SET value = ? WHERE key = 'tracking_started_at'").run(NOW - DAY);
  const data = f.read();
  assert.equal(data.summary.findings, null); assert.equal(data.coverage.current.windowComplete, false);
  assert.equal(data.coverage.previous.windowComplete, false); assert.equal(data.coverage.comparisonAvailable, false);
  assert.deepEqual(data.comparison.jobs, { absolute: null, percent: null, comparable: false });
  assert.equal(data.comparison.findings.comparable, false);
  f.db.prepare("UPDATE scan_usage_meta SET value = ? WHERE key = 'tracking_started_at'").run(NOW - 365 * DAY);
  const tracked = f.read();
  assert.deepEqual(tracked.comparison.jobs, { absolute: 1, percent: null, comparable: true });
});

test('unobserved empty chart days stay unknown without erasing measured backfill or posted spend', t => {
  const f = fixture(t), historical = f.job(1, { at: NOW - 4 * DAY, findings: 2 });
  f.db.prepare("UPDATE scan_usage_meta SET value = ? WHERE key = 'tracking_started_at'").run(NOW - DAY);
  f.entry(`usage:${historical}`, 'tenant-a', -50_000, 'usage', NOW - 3 * DAY);
  const data = f.read();
  const unobserved = data.series.find(row => row.date === '2026-10-24');
  assert.equal(unobserved.jobs, null); assert.equal(unobserved.findings, null);
  assert.equal(unobserved.completed, null); assert.equal(unobserved.inputBytes, null);
  assert.equal(unobserved.netUsageMicros, 50_000, 'Actual posted spend survives an unobserved empty run cohort.');
  const recorded = data.series.find(row => row.date === '2026-10-23');
  assert.equal(recorded.jobs, 1); assert.equal(recorded.findings, 2); assert.equal(recorded.netUsageMicros, 0);
  assert.equal(data.series.find(row => row.date === '2026-10-26').jobs, null,
    'The partially observed tracking-start day cannot prove a full-day zero.');
  assert.equal(data.series.at(-1).jobs, 0, 'An observed empty day remains a measured zero.');
  assert.equal(data.summary.spendMicros, 50_000);
  f.db.prepare("DELETE FROM scan_usage_meta WHERE key = 'tracking_started_at'").run();
  const undated = f.read();
  assert.equal(undated.series.at(-1).jobs, null);
  assert.equal(undated.series.find(row => row.date === '2026-10-23').jobs, 1);
  assert.equal(undated.series.find(row => row.date === '2026-10-24').netUsageMicros, 50_000);
});

test('missing storage returns unknown metrics and no invented key names, spend or report details', t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const data = scanActivity(db, { workspaceId: 'tenant-a', now: NOW });
  assert.equal(data.summary.jobs, null); assert.equal(data.summary.spendMicros, null);
  assert.equal(data.summary.findings, null); assert.equal(data.coverage.current.available, false);
  assert.equal(data.coverage.keyMetadataAvailable, false); assert.equal(data.coverage.keyAttributionComplete, false);
  assert.deepEqual(data.topKeys, []); assert.deepEqual(data.recentJobs, []);
  assert.equal(data.comparison.spendMicros.comparable, false);
});

test('recent calls retain unknown charges when a settled meter has no surviving debit', t => {
  const f = fixture(t), jobId = f.job(1);
  const data = f.read();
  assert.equal(data.recentJobs[0].id, jobId);
  assert.equal(data.recentJobs[0].netUsageMicros, null);
  assert.equal(data.summary.spendMicros, 0, 'The wallet remains authoritative for posted period totals.');
  // Restoring the real ledger debit supplies the job amount, rather than
  // reconstructing a financial transaction from its reserved quote.
  f.entry(`usage:${jobId}`, 'tenant-a', -50_000, 'usage');
  assert.equal(f.read().recentJobs[0].netUsageMicros, 50_000);
});

test('recent calls and top API keys are bounded and the endpoint makes no writes', t => {
  const f = fixture(t);
  for (let i = 1; i <= 40; i++) {
    const key = i <= 2 ? f.first.id : id(i + 100);
    if (i > 2) f.db.prepare('INSERT INTO scan_keys VALUES (?,?,?,?,?,NULL)').run(key, 'tenant-a', 'PRIVATE_USER', `PRIVATE_HASH_${i}`, NOW);
    f.job(i, { key, at: NOW - i });
  }
  const before = f.db.prepare('SELECT total_changes() AS value').get().value;
  const data = f.read(); f.read({ days: 30 }); f.read({ days: 90 });
  assert.equal(data.topKeys.length, 10); assert.equal(data.recentJobs.length, 25);
  assert.equal(data.recentJobs[0].id, id(1)); assert.equal(data.recentJobs.at(-1).id, id(25));
  assert.equal(f.db.prepare('SELECT total_changes() AS value').get().value, before);
});

test('route strictly scopes cookie principals, rejects extra queries and withholds storage errors', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: NOW });
  const f = fixture(t); f.job(1); f.job(2, { workspace: 'tenant-b', key: f.foreign.id, findings: 999 });
  const app = express();
  app.use((req, _res, next) => { if (req.get('x-fixture-user')) { req.authUser = { id: 'a' }; req.workspaceId = 'tenant-a'; } next(); });
  let broken = false;
  registerScanActivity(app, { db: { prepare(...args) {
    if (broken) throw new Error('PRIVATE_SQL_STORAGE_ERROR');
    return f.db.prepare(...args);
  } } });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}/api/scanner-activity`, headers = { 'x-fixture-user': 'a' };
  assert.equal((await fetch(base)).status, 401);
  for (const query of ['?days=1', '?days=7.0', '?days=7&days=30', '?workspaceId=tenant-b', '?days=7&keyId=private'])
    assert.equal((await fetch(base + query, { headers })).status, 400);
  const response = await fetch(base + '?days=7', { headers });
  assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('vary'), 'Cookie');
  const data = await response.json(); assert.equal(data.summary.jobs, 1); assert.equal(data.summary.findings, 1);
  broken = true;
  // Close failures are sanitized; the callback must never expose SQL or values.
  const failed = await fetch(base, { headers }); assert.equal(failed.status, 500);
  assert.deepEqual(await failed.json(), { error: 'Account activity is temporarily unavailable.' });
});

test('real app session guards allow only its own workspace activity', async t => {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const { app } = createWorkerApp({ db, env: {}, schedule: () => {} }), accounts = createAccounts(db), at = Date.now();
  for (const [letter, githubId, findings] of [['a', 1234, 1], ['b', 5678, 99]]) {
    const user = accounts.upsertUser(githubId, `PRIVATE_LOGIN_${letter}`), workspace = `PRIVATE_WORKSPACE_${letter}`;
    accounts.createWorkspace(user.id, workspace, {});
    db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(letter.repeat(64), JSON.stringify({ userId: user.id, workspaceId: workspace }), at);
    db.prepare('INSERT INTO scan_usage_jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(letter.repeat(32), workspace, at, at, at,
      'completed', 100, 1, 1, 0, 0, null, findings, null, null);
    db.prepare('INSERT INTO scan_usage_tools VALUES (?,?,?,?,?,?,?,?,?,?)').run(letter.repeat(32), 'opengrep', 'complete', 0, findings, 0, findings, 0, 0, 0);
  }
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}/api/scanner-activity`, headers = { cookie: `purple_session=${'b'.repeat(64)}` };
  assert.equal((await fetch(base)).status, 401);
  const response = await fetch(base + '?days=7', { headers }); assert.equal(response.status, 200);
  const data = await response.json(); assert.equal(data.summary.jobs, 1); assert.equal(data.summary.findings, 99);
  assert.equal((await fetch(base + '?workspaceId=PRIVATE_WORKSPACE_a', { headers })).status, 400);
  for (const marker of ['PRIVATE_LOGIN', 'PRIVATE_WORKSPACE', 'a'.repeat(32)]) assert.ok(!JSON.stringify(data).includes(marker));
});
