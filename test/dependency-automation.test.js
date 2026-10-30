import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyMapper } from '../server/dependency-mapper.js';
import { createDependencyMonitor } from '../server/dependency-monitor.js';
import { registerDependencyRoutes } from '../server/dependency-routes.js';
import { defaultAutomationPolicy } from '../shared/offense-policy.js';

const day = 86400000;
function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE workspaces (id TEXT PRIMARY KEY, data TEXT NOT NULL)');
  let time = Date.now(), revision = 'first', access = true, providerFailure = false, scopeWarning = false;
  let accessCalls = 0, revisionCalls = 0, advisoryCalls = 0, scanCalls = 0;
  let accessCallback = null, revisionCallback = null;
  const session = { github: { installationId: 123, account: 'owner' },
    dependencyRepositories: { repo: { repository: 'owner/repo', installationId: 123 } } };
  for (const id of ['customer', 'other']) db.prepare('INSERT INTO workspaces VALUES (?, ?)').run(id, JSON.stringify(session));
  const github = {
    async repositories() { accessCalls++; await accessCallback?.(); return access ? [{ fullName: 'owner/repo' }] : []; },
    async dependencyRevision() { revisionCalls++; await revisionCallback?.(); return revision; },
    async dependencyFiles() { scanCalls++; return { revision, warnings: scopeWarning ? ['Coverage needs review.'] : [], files: [
      { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: {
        '': { dependencies: { example: '*' } }, 'node_modules/example': { version: '1.0.0' }
      } }) }
    ] }; }
  };
  const mapper = createDependencyMapper(db, github, async packages => {
    advisoryCalls++;
    if (providerFailure) throw new Error('DO-NOT-STORE provider secret or raw response');
    return { status: 'complete', checkedAt: time, checkedPackages: packages.length, skippedPackages: 0,
      findings: [{ package: 'example', version: '1.0.0', id: 'TEST-ONLY', severity: 'HIGH' }] };
  });
  const args = { github, mapper, runner: { mappings: () => [] }, now: () => time };
  const monitor = createDependencyMonitor(db, args);
  // The second workspace exists for isolation checks, but is not enrolled yet.
  db.prepare('UPDATE workspaces SET data = ? WHERE id = ?').run('{}', 'other');
  const setPolicy = policy => monitor.configure('customer', 'owner/repo', 123, { ...defaultAutomationPolicy(), ...policy });
  return { db, session, github, mapper, monitor, args, setPolicy,
    row: (id = 'customer') => monitor.status(id)[0], snapshot: () => mapper.snapshots('customer')[0],
    advance: (milliseconds = 301000) => { time += milliseconds; }, change: value => { revision = value; },
    fail: value => { providerFailure = value; }, warning: () => { scopeWarning = true; }, revoke: () => { access = false; },
    onAccess: callback => { accessCallback = callback; }, onRevision: callback => { revisionCallback = callback; },
    counts: () => ({ accessCalls, revisionCalls, advisoryCalls, scanCalls }), time: () => time };
}

test('default automation scans initially, polls changes without rescanning and rechecks advisories daily', async t => {
  const f = fixture(); t.after(() => f.db.close());
  assert.equal(f.row().policy.schedule, 'daily'); assert.equal(f.row().latestRun, null);
  await f.monitor.dispatch();
  assert.equal(f.row().latestRun.trigger, 'initial'); assert.equal(f.row().latestRun.status, 'completed');
  assert.equal(f.row().latestRun.advisoryMatches, 1);
  const checked = f.snapshot().vulnerabilityCheck.checkedAt;
  f.advance(); await f.monitor.dispatch();
  assert.equal(f.counts().advisoryCalls, 1); assert.equal(f.row().recentRuns.length, 1);
  assert.equal(f.snapshot().vulnerabilityCheck.checkedAt, checked);
  f.advance(day); await f.monitor.dispatch();
  assert.equal(f.counts().advisoryCalls, 2); assert.equal(f.counts().scanCalls, 1);
  assert.equal(f.row().latestRun.trigger, 'scheduled');
  assert.equal(f.row().latestRun.coverageStatus, 'complete'); assert.equal(f.row().latestRun.durationMs, 0);
});

test('change-only automation ignores implicit six-hour advisory age and scans a changed commit', async t => {
  const f = fixture(); t.after(() => f.db.close()); f.setPolicy({ schedule: 'off' });
  await f.monitor.dispatch(); f.advance(2 * day); await f.monitor.dispatch();
  assert.equal(f.counts().advisoryCalls, 1, 'Polling cannot bypass the chosen schedule.');
  f.change('second'); f.advance(); await f.monitor.dispatch();
  assert.equal(f.counts().advisoryCalls, 2); assert.equal(f.counts().scanCalls, 2);
  assert.equal(f.row().latestRun.trigger, 'dependency_change'); assert.equal(f.snapshot().revision, 'second');
});

test('daily and weekly schedule-only policies do not poll changed commits before their cadence', async t => {
  for (const [schedule, interval] of [['daily', day], ['weekly', 7 * day]]) {
    const f = fixture(); t.after(() => f.db.close()); f.setPolicy({ onChange: false, schedule });
    await f.monitor.dispatch(); const calls = f.counts().accessCalls;
    f.change('scheduled-head'); f.advance(interval - 1000); await f.monitor.dispatch();
    assert.equal(f.counts().accessCalls, calls); assert.equal(f.counts().advisoryCalls, 1);
    assert.equal(f.row().nextCheckAt, f.snapshot().vulnerabilityCheck.checkedAt + interval);
    f.advance(1001); await f.monitor.dispatch();
    assert.equal(f.snapshot().revision, 'scheduled-head'); assert.equal(f.row().latestRun.trigger, 'scheduled');
    assert.equal(f.counts().advisoryCalls, 2);
  }
});

test('paused and integration-only settings perform no hosted background work and survive restart', async t => {
  const f = fixture(); t.after(() => f.db.close());
  f.setPolicy({ enabled: false }); await f.monitor.dispatch();
  assert.equal(f.row().status, 'paused'); assert.equal(f.row().nextCheckAt, null); assert.equal(f.counts().accessCalls, 0);
  let restored = createDependencyMonitor(f.db, f.args);
  assert.equal(restored.status('customer')[0].policy.enabled, false);
  f.setPolicy({ onChange: false, schedule: 'off', preDeploy: true, postDeploy: true, agentRun: true });
  await restored.dispatch(); assert.equal(f.row().status, 'manual'); assert.equal(f.row().nextCheckAt, null);
  assert.equal(f.counts().accessCalls, 0, 'Saving external lifecycle choices does not wire a deployment or agent host.');
  assert.equal(f.row().recentRuns.length, 0);
});

test('an advisory-provider failure retains prior results and records a bounded, tenant-scoped retry', async t => {
  const f = fixture(); t.after(() => f.db.close()); await f.monitor.dispatch();
  const previous = f.snapshot(); f.fail(true); f.advance(day); await f.monitor.dispatch();
  assert.equal(f.row().status, 'retrying'); assert.equal(f.row().latestRun.status, 'failed');
  assert.equal(f.row().latestRun.errorCode, 'provider_failure'); assert.equal(f.row().latestRun.advisoryMatches, null);
  assert.equal(f.snapshot().vulnerabilityCheck.checkedAt, previous.vulnerabilityCheck.checkedAt);
  assert.deepEqual(f.snapshot().vulnerabilityCheck.findings, previous.vulnerabilityCheck.findings);
  assert.doesNotMatch(JSON.stringify(f.monitor.status('customer')), /DO-NOT-STORE|raw response/);
  const calls = f.counts().advisoryCalls; await createDependencyMonitor(f.db, f.args).dispatch();
  assert.equal(f.counts().advisoryCalls, calls); assert.deepEqual(f.monitor.status('other'), []);
  f.fail(false); f.advance(); await f.monitor.dispatch(); assert.equal(f.row().latestRun.status, 'completed');
  assert.equal(f.row().recentRuns.length, 3);
});

test('an initially unavailable provider does not save an empty clean report and retries after restart', async t => {
  const f = fixture(); t.after(() => f.db.close()); f.fail(true); await f.monitor.dispatch();
  assert.equal(f.snapshot(), undefined); assert.equal(f.row().latestRun.status, 'failed');
  const restarted = createDependencyMonitor(f.db, f.args); await restarted.dispatch();
  assert.equal(f.counts().advisoryCalls, 1); f.fail(false); f.advance(); await restarted.dispatch();
  assert.equal(f.row().latestRun.status, 'completed'); assert.equal(f.row().latestRun.trigger, 'initial');
});

test('incomplete coverage is recorded as partial instead of a successful complete scan', async t => {
  const f = fixture(); t.after(() => f.db.close()); f.warning(); await f.monitor.dispatch();
  assert.equal(f.row().latestRun.status, 'partial'); assert.equal(f.row().latestRun.coverageStatus, 'partial');
  assert.equal(f.row().latestRun.advisoryMatches, 1); assert.equal(f.row().status, 'watching');
});

test('enrollment and pause changes during provider I/O prevent starting a scan', async t => {
  for (const boundary of ['access', 'revision']) {
    const f = fixture(); t.after(() => f.db.close());
    if (boundary === 'revision') { await f.monitor.dispatch(); f.change('second'); f.advance(); }
    const before = f.counts().advisoryCalls;
    const pause = () => f.setPolicy({ enabled: false });
    if (boundary === 'access') f.onAccess(pause); else f.onRevision(pause);
    await f.monitor.dispatch(); assert.equal(f.counts().advisoryCalls, before); assert.equal(f.row().status, 'paused');
  }
  const removed = fixture(); t.after(() => removed.db.close());
  removed.onAccess(() => removed.db.prepare('UPDATE workspaces SET data = ? WHERE id = ?').run('{}', 'customer'));
  await removed.monitor.dispatch(); assert.equal(removed.counts().advisoryCalls, 0); assert.deepEqual(removed.monitor.status('customer'), []);
});

test('restart retires interrupted facts without treating downtime as measured execution', async t => {
  const f = fixture(); t.after(() => f.db.close()); await f.monitor.dispatch();
  const run = f.row().latestRun;
  f.db.prepare("UPDATE dependency_automation_runs SET status = 'running', finished_at = NULL, duration_ms = NULL WHERE id = ?").run(run.id);
  f.db.prepare("UPDATE dependency_monitor SET status = 'checking'").run(); f.advance();
  const restarted = createDependencyMonitor(f.db, f.args);
  const recovered = restarted.status('customer')[0];
  assert.equal(recovered.latestRun.status, 'interrupted'); assert.equal(recovered.latestRun.errorCode, 'interrupted');
  assert.equal(recovered.latestRun.durationMs, null); assert.equal(recovered.status, 'retrying');
  await restarted.dispatch(); assert.equal(restarted.status('customer')[0].status, 'watching');
  assert.equal(f.counts().advisoryCalls, 1, 'An interrupted observation does not fabricate a reason to rescan unchanged metadata.');
});

test('locked oldest repositories cannot starve another enrolled repository', async t => {
  const f = fixture(); t.after(() => f.db.close());
  const names = ['owner/one', 'owner/two', 'owner/three', 'owner/four'];
  f.session.dependencyRepositories = Object.fromEntries(names.map(repository => [repository, { repository, installationId: 123 }]));
  f.db.prepare('UPDATE workspaces SET data = ? WHERE id = ?').run(JSON.stringify(f.session), 'customer');
  f.github.repositories = async () => names.map(fullName => ({ fullName }));
  for (const repository of names.slice(0, 3)) f.mapper.repositoryLocks.add(`customer:123:${repository}`);
  await f.monitor.dispatch();
  assert.equal(f.counts().advisoryCalls, 1); assert.equal(f.mapper.snapshots('customer')[0].repository, 'owner/four');
  assert.equal(f.monitor.status('customer').find(row => row.repository === 'owner/four').latestRun.status, 'completed');
});

test('automation configuration route requires enrollment, current access and strict scoped input', async t => {
  const f = fixture(); t.after(() => f.db.close());
  const handlers = new Map(), app = Object.fromEntries(['get', 'post', 'delete'].map(method => [method, (route, handler) => handlers.set(`${method}:${route}`, handler)]));
  registerDependencyRoutes(app, { github: f.github, mapper: f.mapper, monitor: f.monitor, runner: f.args.runner });
  async function request(body, workspace = 'customer') {
    let status = 200, result;
    const response = { status(value) { status = value; return this; }, json(value) { result = value; return this; } };
    try { await handlers.get('post:/api/dependencies/automation')({ body, sessionId: workspace,
      session: JSON.parse(f.db.prepare('SELECT data FROM workspaces WHERE id = ?').get(workspace).data) }, response); }
    catch (error) { status = error.status || 500; }
    return { status, result };
  }
  const body = { repository: 'owner/repo', installationId: 123, policy: { enabled: false } };
  assert.equal((await request({ ...body, workspaceId: 'other' })).status, 400);
  assert.equal((await request({ ...body, repository: 'owner/private' })).status, 403);
  assert.equal((await request({ ...body, installationId: 999 })).status, 403);
  assert.equal((await request({ ...body, policy: { schedule: 'every-second' } })).status, 400);
  assert.equal((await request(body, 'other')).status, 403);
  const saved = await request(body); assert.equal(saved.status, 200); assert.equal(saved.result.policy.enabled, false);
  assert.equal(saved.result.monitoring.status, 'paused'); assert.equal(saved.result.monitoring.repository, 'owner/repo');
  f.revoke(); assert.equal((await request({ ...body, policy: { enabled: true } })).status, 403);
  assert.equal(f.row().policy.enabled, false);
});
