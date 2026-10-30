import { verifiedEvidence } from './helpers/verification-evidence.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createWorkerApp } from '../workers/app-api.js';
import { operationsMetrics } from '../server/operations-metrics.js';

test('operator metrics count all workspaces, deduplicate CVEs and require a separate operator key', async () => {
  const db = new DatabaseSync(':memory:'); let server;
  try {
    const { app } = createWorkerApp({ db, env: { OPERATIONS_METRICS_KEY: 'operator-test-key' }, schedule: () => {} });
    const putWorkspace = db.prepare('INSERT INTO workspaces VALUES (?, ?, ?, ?)');
    for (const [id, name] of [['a', 'Alpha'], ['b', 'Beta'], ['c', 'Not scanned']]) {
      putWorkspace.run(id, JSON.stringify({ company: name, cloudflare: { accessToken: 'secret-must-not-appear' } }), 1, 1);
    }
    const putSnapshot = db.prepare('INSERT INTO dependency_snapshots VALUES (?, ?, ?, ?, ?, ?)');
    const finding = (id, cves, severity) => ({ id, cves, severity });
    const first = finding('GHSA-one', ['CVE-2026-1111'], 'HIGH'), second = finding('GHSA-two', [], 'MODERATE');
    putSnapshot.run('a', 'org/first', 1, 'a', 100, JSON.stringify({ vulnerabilityCheck: { status: 'complete', checkedAt: 100, findings: [first, first, second] } }));
    putSnapshot.run('a', 'org/failed', 1, 'a', 101, JSON.stringify({ vulnerabilityCheck: { status: 'failed', checkedAt: 101, findings: [] } }));
    putSnapshot.run('b', 'org/second', 2, 'b', 102, JSON.stringify({ vulnerabilityCheck: { status: 'complete', checkedAt: 102,
      findings: [first, finding('GHSA-three', ['CVE-2026-2222', 'CVE-2026-1111'], 'CRITICAL')] } }));
    for (const [index, id, isTest] of [[1, 'a', 1], [2, 'a', 0], [3, 'b', 0]]) {
      db.prepare(`INSERT INTO vulnerability_discoveries
        (session_id, fingerprint, investigation_id, agent_run_id, repository, source_worker, severity, summary, commit_sha, discovered_at, is_test, verification)
        VALUES (?, ?, ?, ?, 'org/private', 'private-worker', 'HIGH', 'private-evidence', 'sha', 1, ?, ?)`).run(id, `fingerprint-${index}`, index, index, isTest, JSON.stringify(verifiedEvidence()));
    }
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const url = `http://127.0.0.1:${server.address().port}/api/internal/metrics`;
    for (const headers of [{}, { cookie: 'purple_session=workspace-cookie' }, { authorization: 'Bearer wrong-key' }]) {
      assert.equal((await fetch(url, { headers })).status, 401);
    }
    assert.equal((await fetch(url + '?key=operator-test-key')).status, 401);
    const response = await fetch(url, { headers: { authorization: 'Bearer operator-test-key' } });
    assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
    const result = await response.json();
    assert.deepEqual(result.totals, { workspaces: 3, scannedWorkspaces: 2, repositories: 3, findings: 5,
      uniqueAdvisories: 3, uniqueCVEs: 2, confirmed: { total: 3, customer: 2, test: 1 } });
    assert.deepEqual(result.workspaces.find(w => w.id === 'a').scans.severity, { HIGH: 2, MODERATE: 1 });
    assert.equal(result.workspaces.find(w => w.id === 'a').scans.failed, 1);
    assert.equal(result.workspaces.find(w => w.id === 'c').scans.repositories, 0);
    assert.equal(result.workspaces.find(w => w.id === 'a').scans.lastCheckedAt, 101);
    assert.equal(result.repositoryOwners[0].owner, 'org');
    assert.equal(result.repositoryOwners[0].findings, 5);
    assert.equal(result.repositoryOwners[0].uniqueCVEs, 2);
    assert.equal(result.repositoryOwners[0].failed, 1);
    for (const secret of ['secret-must-not-appear', 'org/private', 'private-evidence', 'operator-test-key']) assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM dependency_snapshots').get().count, 3);
    const disabled = createWorkerApp({ db, env: {}, schedule: () => {} }).app;
    await new Promise(resolve => server.close(resolve));
    server = disabled.listen(0, '127.0.0.1'); await once(server, 'listening');
    assert.equal((await fetch(`http://127.0.0.1:${server.address().port}/api/internal/metrics`, { headers: { authorization: 'Bearer operator-test-key' } })).status, 401);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});

test('organization breakdown deduplicates a repository scanned in multiple workspaces using the latest snapshot', () => {
  const db = new DatabaseSync(':memory:');
  try {
    createWorkerApp({ db, env: {}, schedule() {} });
    const put = db.prepare('INSERT INTO dependency_snapshots VALUES (?, ?, ?, ?, ?, ?)');
    const check = (at, findings) => JSON.stringify({ vulnerabilityCheck: { status: 'complete', checkedAt: at, findings } });
    put.run('a', 'Org/Project', 1, 'old', 1, check(1, [{ id: 'old', severity: 'CRITICAL', cves: ['CVE-old'] }]));
    put.run('b', 'org/project', 1, 'new', 2, check(2, [{ id: 'new', severity: 'HIGH', cves: ['CVE-new'] }]));
    put.run('a', 'Personal/Other', 2, 'new', 2, check(2, []));
    const result = operationsMetrics(db);
    assert.equal(result.totals.repositories, 3);
    assert.equal(result.repositoryOwners.length, 2);
    const org = result.repositoryOwners.find(item => item.owner === 'org');
    assert.equal(org.repositories, 1);
    assert.equal(org.findings, 1);
    assert.deepEqual(org.severity, { HIGH: 1 });
    assert.equal(org.uniqueCVEs, 1);
    assert.equal(result.repositoryOwners.find(item => item.owner === 'personal').findings, 0);
  } finally { db.close(); }
});
