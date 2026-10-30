import { verifiedEvidence } from './helpers/verification-evidence.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createDiscoveryDashboard, discoveryDay, discoveryGrowth, isMetricsOperator } from '../server/discovery-dashboard.js';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

function discovery(db, id, timestamp, isTest = 0) {
  db.prepare(`INSERT INTO vulnerability_discoveries (session_id, fingerprint, investigation_id, agent_run_id, repository,
    source_worker, severity, summary, commit_sha, discovered_at, is_test, verification)
    VALUES (?, ?, ?, ?, 'private/repo', 'private-worker', 'HIGH', 'private evidence', 'sha', ?, ?, ?)`)
    .run(id % 2 ? 'a' : 'b', `fingerprint-${id}`, id, id, timestamp, isTest, JSON.stringify(verifiedEvidence()));
}
function snapshot(db, repository, count, status = 'complete') {
  db.prepare(`INSERT OR REPLACE INTO dependency_snapshots VALUES ('a', ?, 1, 'sha', 1, ?)`).run(repository, JSON.stringify({
    vulnerabilityCheck: { status, checkedAt: 123, findings: Array.from({ length: count }, (_, i) => ({ id: `GHSA-${i}` })) }
  }));
}

test('daily metrics persist real observations, preserve gaps and calculate growth across Eastern midnight', () => {
  const db = new DatabaseSync(':memory:');
  createWorkerApp({ db, env: {}, schedule: () => {} });
  let clock = Date.parse('2026-10-22T03:55:00Z'); // October 21, 11:55pm ET.
  let dashboard = createDiscoveryDashboard(db, { now: () => clock });
  discovery(db, 1, Date.parse('2026-10-20T18:00:00Z'));
  discovery(db, 2, Date.parse('2026-10-21T18:00:00Z'));
  discovery(db, 3, Date.parse('2026-10-21T19:00:00Z'), 1);
  snapshot(db, 'customer/repo', 2); snapshot(db, 'imranye/purple-e2e-fixture', 1);
  let result = dashboard.read({ days: 7 });
  assert.equal(result.summary.confirmed.total, 2);
  assert.equal(result.summary.confirmed.excludedFixtures, 1);
  assert.equal(result.summary.advisories.total, 2);
  assert.equal(result.summary.advisories.change, null);
  assert.equal(result.series.at(-2).advisoryMatches, null, 'No fabricated totals before tracking began.');
  const firstObserved = db.prepare('SELECT first_observed_at FROM discovery_metric_days').get().first_observed_at;
  clock += 61_000; dashboard.capture();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM discovery_metric_days').get().n, 1);
  assert.equal(db.prepare('SELECT first_observed_at FROM discovery_metric_days').get().first_observed_at, firstObserved);
  clock = Date.parse('2026-10-22T04:05:00Z');
  discovery(db, 4, clock - 1000); snapshot(db, 'customer/repo', 5);
  result = dashboard.read({ days: 7 });
  assert.equal(result.series.at(-1).date, '2026-10-22');
  assert.deepEqual({ total: result.summary.confirmed.total, change: result.summary.confirmed.change, percent: result.summary.confirmed.percent }, { total: 3, change: 1, percent: 50 });
  assert.equal(result.summary.advisories.change, 3); assert.equal(result.summary.advisories.percent, 150);
  assert.equal(dashboard.read({ includeTests: true }).summary.confirmed.total, 4);
  assert.equal(dashboard.read({ includeTests: true }).summary.advisories.total, 6);
  dashboard = createDiscoveryDashboard(db, { now: () => clock });
  assert.equal(dashboard.read().historyStartedAt, firstObserved, 'Restart retains the observation history.');
  clock = Date.parse('2026-10-23T16:00:00Z'); snapshot(db, 'customer/repo', 0);
  result = dashboard.read(); assert.equal(result.summary.advisories.change, -5); assert.equal(result.summary.advisories.percent, -100);
  clock = Date.parse('2026-10-25T16:00:00Z');
  result = dashboard.read(); assert.equal(result.series.at(-2).advisoryMatches, null); assert.equal(result.summary.advisories.change, null);
  clock = Date.parse('2026-10-26T16:00:00Z'); snapshot(db, 'customer/repo', 0, 'failed');
  result = dashboard.read(); assert.equal(result.summary.advisories.failedScans, 1); assert.equal(result.summary.advisories.change, null);
  assert.equal(result.series.at(-1).advisoryComplete, false);
  clock = Date.parse('2026-10-27T16:00:00Z'); snapshot(db, 'second/repo', 3);
  result = dashboard.read(); assert.equal(result.summary.advisories.change, 3, 'Stable partial coverage still measures known-match growth.');
  assert.equal(result.summary.advisories.percent, null);
  clock = Date.parse('2026-10-28T16:00:00Z'); snapshot(db, 'customer/repo', 5); snapshot(db, 'second/repo', 0, 'failed');
  result = dashboard.read(); assert.equal(result.summary.advisories.failedScans, 1);
  assert.equal(result.summary.advisories.change, null, 'Different failed repositories with the same failure count are not comparable.');
  assert.throws(() => dashboard.read({ days: 999 }), /7, 30 or 90/);
  db.close();
});

test('growth handles zero baselines and calendar dates handle daylight saving time', () => {
  assert.deepEqual(discoveryGrowth(0, 0), { change: 0, percent: 0 });
  assert.deepEqual(discoveryGrowth(3, 0), { change: 3, percent: null });
  assert.deepEqual(discoveryGrowth(3, null), { change: null, percent: null });
  assert.equal(discoveryDay(Date.parse('2026-11-01T03:30:00Z')), '2026-10-31');
  assert.equal(discoveryDay(Date.parse('2026-11-01T05:30:00Z')), '2026-11-01');
  assert.equal(discoveryDay(Date.parse('2026-11-01T06:30:00Z')), '2026-11-01');
  assert.equal(isMetricsOperator({ githubId: '123', login: 'changed-name' }, '123, 456'), true);
  assert.equal(isMetricsOperator({ githubId: '999', login: 'owner' }, '123'), false);
  assert.equal(isMetricsOperator({ githubId: '123' }, ''), false);
});

test('company dashboard authorizes immutable operator IDs and exposes aggregates only', async () => {
  const db = new DatabaseSync(':memory:'); let server;
  try {
    const { app } = createWorkerApp({ db, env: { OPERATIONS_GITHUB_IDS: '1234' }, schedule: () => {} });
    const accounts = createAccounts(db);
    for (const [cookie, githubId] of [['a', 1234], ['b', 5678]]) {
      const user = accounts.upsertUser(githubId, 'same-login');
      const workspaceId = `private-${cookie}`;
      accounts.createWorkspace(user.id, workspaceId, { company: 'Private company name', openrouter: { secret: 'private-credential' } });
      db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(cookie.repeat(64), JSON.stringify({ userId: user.id, workspaceId }), Date.now());
    }
    discovery(db, 1, Date.now() - 1000); snapshot(db, 'private/repo', 2);
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    const get = (path, cookie) => fetch(base + path, { headers: cookie ? { cookie: `purple_session=${cookie.repeat(64)}` } : {} });
    assert.equal((await get('/api/operator/discoveries')).status, 401);
    assert.equal((await get('/api/operator/discoveries?operatorId=1234', 'b')).status, 403);
    assert.equal((await get('/api/operator/discoveries?days=999', 'a')).status, 400);
    assert.equal((await get('/api/operator/discoveries?includeTests=yes', 'a')).status, 400);
    const response = await get('/api/operator/discoveries?days=7', 'a'); assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const result = await response.json(); assert.equal(result.summary.confirmed.total, 1); assert.equal(result.summary.advisories.total, 2);
    for (const secret of ['Private company name', 'private-credential', 'private/repo', 'private evidence', 'private-worker']) assert.ok(!JSON.stringify(result).includes(secret));
    assert.equal((await (await get('/api/state', 'a')).json()).config.operations, true);
    assert.equal((await (await get('/api/state', 'b')).json()).config.operations, false);
  } finally { if (server) await new Promise(resolve => server.close(resolve)); db.close(); }
});

test('dashboard sign-in returns only to the allowlisted metrics page and needs no workspace setup', async () => {
  const db = new DatabaseSync(':memory:'), originalFetch = globalThis.fetch; let server;
  try {
    const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://purple.test', OPERATIONS_GITHUB_IDS: '1234',
      ENCRYPTION_KEY: 'a'.repeat(64), GITHUB_APP_SLUG: 'purple', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret' }, schedule: () => {} });
    globalThis.fetch = async (url, options) => {
      if (String(url).includes('github.com/login/oauth/access_token')) return Response.json({ access_token: 'test-token' });
      if (String(url) === 'https://api.github.com/user') return Response.json({ id: 1234, login: 'operator' });
      if (String(url).startsWith('https://api.github.com/user/installations')) return Response.json({ installations: [] });
      return originalFetch(url, options);
    };
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const returnTo of ['/metrics', 'https://evil.test', '//evil.test', '/metrics?redirect=evil']) {
      const start = await originalFetch(`${base}/api/auth/github/start?returnTo=${encodeURIComponent(returnTo)}`, { redirect: 'manual' });
      const cookie = start.headers.get('set-cookie').split(';')[0];
      const state = new URL(start.headers.get('location')).searchParams.get('state');
      const finish = await originalFetch(`${base}/api/github/callback?state=${encodeURIComponent(state)}&code=test`, { headers: { cookie }, redirect: 'manual' });
      assert.equal(finish.status, 302);
      assert.equal(finish.headers.get('location'), returnTo === '/metrics' ? '/metrics' : '/?signed_in=1');
      const rotated = finish.headers.get('set-cookie').split(';')[0];
      const metrics = await originalFetch(base + '/api/operator/discoveries', { headers: { cookie: rotated } });
      assert.equal(metrics.status, 200);
    }
  } finally { globalThis.fetch = originalFetch; if (server) await new Promise(resolve => server.close(resolve)); db.close(); }
});
