import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyMapper } from '../server/dependency-mapper.js';
import { createDependencyMonitor } from '../server/dependency-monitor.js';
import { mergeDependencySnapshot } from '../src/rehearsal-evidence.js';
import { promptEvidenceVersion } from '../src/prompt-evidence.js';

function fixture() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE workspaces (id TEXT PRIMARY KEY, data TEXT NOT NULL)');
  let time = Date.now(), revision = 'before', accessible = true, offline = false, calls = 0;
  const session = { github: { installationId: 123, account: 'owner' },
    dependencyRepositories: { repo: { repository: 'owner/repo', installationId: 123 } } };
  db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('customer', JSON.stringify(session));
  const github = {
    repositories: async () => { calls++; if (offline) throw new Error('provider unavailable'); return accessible ? [{ fullName: 'owner/repo' }] : []; },
    dependencyRevision: async () => revision,
    dependencyFiles: async () => ({ revision, warnings: [], files: [{ path: 'package-lock.json', content: JSON.stringify({
      lockfileVersion: 3, packages: { '': { dependencies: { example: '*' } },
        'node_modules/example': { version: revision === 'before' ? '1.0.0' : '2.0.0' } }
    }) }] })
  };
  const mapper = createDependencyMapper(db, github, async packages => ({ status: 'complete', checkedAt: time,
    findings: packages.some(item => item.version === '1.0.0') ? [{ id: 'TEST-ADVISORY' }] : [] }));
  const args = { github, mapper, runner: { mappings: () => [] }, now: () => time };
  return { db, mapper, args, monitor: createDependencyMonitor(db, args), session,
    advance: () => { time += 301_000; }, change: () => { revision = 'after'; },
    revoke: () => { accessible = false; }, fail: () => { offline = true; }, recover: () => { offline = false; }, calls: () => calls };
}

test('background monitor scans without a browser or model key, rescans changed commits and invalidates old simulation evidence', async () => {
  const f = fixture();
  try {
    await f.monitor.dispatch();
    const before = f.mapper.snapshots('customer')[0];
    assert.equal(before.vulnerabilityCheck.findings.length, 1);
    assert.equal(f.monitor.status('customer')[0].status, 'watching');
    f.change(); f.advance();
    // Recreate the scheduler to exercise persistent scheduling after isolate restart.
    await createDependencyMonitor(f.db, f.args).dispatch();
    const after = f.mapper.snapshots('customer')[0];
    assert.equal(after.revision, 'after');
    assert.equal(after.vulnerabilityCheck.findings.length, 0);
    assert.deepEqual(f.mapper.snapshots('another-customer'), []);
    const previous = { ...before, rehearsal: { id: 'simulation', repository: before.repository,
      installationId: before.installationId, revision: before.revision, scannedAt: before.scannedAt,
      advisoryCheckedAt: before.vulnerabilityCheck.checkedAt, status: 'completed' } };
    const merged = mergeDependencySnapshot(previous, after);
    assert.equal(merged.rehearsal.stale, true);
    assert.notEqual(promptEvidenceVersion(previous), promptEvidenceVersion(merged));
  } finally { f.db.close(); }
});

test('failures retain results, retries are durable and revoked/removed repos cannot trigger a rescan', async () => {
  const f = fixture();
  try {
    await f.monitor.dispatch();
    f.advance(); f.fail(); f.change();
    await f.monitor.dispatch();
    assert.equal(f.monitor.status('customer')[0].status, 'retrying');
    assert.equal(f.mapper.snapshots('customer')[0].revision, 'before');
    const calls = f.calls();
    await createDependencyMonitor(f.db, f.args).dispatch();
    assert.equal(f.calls(), calls);
    f.advance(); f.recover(); f.revoke();
    await f.monitor.dispatch();
    assert.equal(f.monitor.status('customer')[0].status, 'access_required');
    assert.equal(f.mapper.snapshots('customer')[0].revision, 'before');
    f.advance();
    f.db.prepare('UPDATE workspaces SET data = ?').run('{}');
    const beforeRemoval = f.calls();
    await f.monitor.dispatch();
    assert.equal(f.calls(), beforeRemoval);
  } finally { f.db.close(); }
});

test('background sync shares repository locks with interactive operations', async () => {
  const f = fixture();
  try {
    f.mapper.repositoryLocks.add('customer:123:owner/repo');
    await f.monitor.dispatch();
    assert.equal(f.calls(), 0);
    f.mapper.repositoryLocks.clear();
    await Promise.all([f.monitor.dispatch(), f.monitor.dispatch()]);
    assert.equal(f.calls(), 1);
  } finally { f.db.close(); }
});

test('prompt version changes when simulation completes or fails, not for progress updates', () => {
  const snapshot = { revision: 'a', scannedAt: 1, vulnerabilityCheck: { checkedAt: 2 },
    rehearsal: { id: 'r', status: 'running', updatedAt: 3 } };
  assert.equal(promptEvidenceVersion(snapshot), promptEvidenceVersion({ ...snapshot, rehearsal: { ...snapshot.rehearsal, updatedAt: 4 } }));
  for (const status of ['completed', 'failed']) assert.notEqual(promptEvidenceVersion(snapshot),
    promptEvidenceVersion({ ...snapshot, rehearsal: { ...snapshot.rehearsal, status, updatedAt: 5 } }));
});
