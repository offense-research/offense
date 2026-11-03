import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createEventStore } from '../server/event-store.js';
import { createAccounts } from '../server/accounts.js';
import { createAgentRunner as nodeRunner } from '../server/agent-runner.js';
import { createAgentRunner as workerRunner } from '../workers/agent-runner.js';
import { verifiedEvidence } from './helpers/verification-evidence.js';

for (const [runtime, createRunner] of [['Node', nodeRunner], ['Worker', workerRunner]]) {
  function fixture(t) {
    const db = new DatabaseSync(':memory:');
    t.after(() => db.close());
    const events = createEventStore(db);
    createAccounts(db);
    const github = { repositories: async () => [
      { fullName: 'org/old', sizeKb: 1 }, { fullName: 'org/new', sizeKb: 250000 },
      { fullName: 'org/large', sizeKb: 250001 }
    ] };
    const store = createRunner(db, { github });
    function investigation(workspace, worker, rule = 'worker_exception') {
      events.receiveBatch(workspace, [{ sourceWorker: worker, queueMessageId: `${workspace}-${worker}`,
        outcome: 'exception', exceptionNames: ['TypeError'] }]);
      const id = events.investigations(workspace).find(item => item.sourceWorker === worker).id;
      db.prepare('UPDATE investigations SET rule_id = ? WHERE id = ?').run(rule, id);
      return id;
    }
    return { db, store, investigation };
  }

  test(`${runtime}: mapping authorization and size checks precede the linked shortcut`, async t => {
    const { db, store } = fixture(t);
    await store.setMapping('a', 'api', 'org/old', 1);
    const before = db.prepare('SELECT * FROM worker_repositories').all();
    await assert.rejects(store.setMapping('a', 'api', 'org/missing', 2, { onlyIfUnlinked: true }), /not available/);
    await assert.rejects(store.setMapping('a', 'api', 'org/large', 2, { onlyIfUnlinked: true }), /250 MB/);
    await store.setMapping('a', 'api', 'org/new', 2, { onlyIfUnlinked: true });
    assert.deepEqual(db.prepare('SELECT * FROM worker_repositories').all(), before);
    assert.deepEqual(store.mappings('b'), []);
    await store.setMapping('a', 'api', 'org/new', 2);
    assert.deepEqual(store.mappings('a').map(row => ({ ...row })), [{ sourceWorker: 'api', repository: 'org/new', installationId: 2 }]);
    const unavailable = createRunner(db, {});
    await assert.rejects(unavailable.setMapping('a', '', null, 1), /not configured/);
  });

  test(`${runtime}: reads and queued relink/unlink respect workspace and worker boundaries`, async t => {
    const { db, store, investigation } = fixture(t);
    const queued = investigation('a', 'api');
    const running = investigation('a', 'running');
    const otherWorker = investigation('a', 'other');
    const otherTenant = investigation('b', 'api');
    for (const [workspace, worker] of [['a', 'api'], ['a', 'running'], ['a', 'other'], ['b', 'api']]) {
      await store.setMapping(workspace, worker, 'org/old', 1);
    }
    store.enqueueMapped();
    db.prepare("UPDATE investigations SET source_worker = 'api' WHERE id = ?").run(running);
    db.prepare("UPDATE agent_runs SET status = 'running', patch = 'patch' WHERE investigation_id = ?").run(running);
    assert.equal(store.run('b', running), null);
    assert.equal(store.patch('b', running), null);
    assert.equal(store.patch('a', running), 'patch');
    assert.equal(store.run('a', running).hasPatch, true);
    await store.setMapping('a', 'api', 'org/new', 2);
    assert.equal(store.run('a', queued).repository, 'org/new');
    for (const [workspace, id] of [['a', running], ['a', otherWorker], ['b', otherTenant]]) {
      assert.equal(store.run(workspace, id).repository, 'org/old');
    }
    await store.setMapping('a', 'api', null, 2);
    assert.equal(store.run('a', queued), null);
    assert.equal(store.run('a', running).status, 'running');
    assert.equal(store.run('a', otherWorker).status, 'queued');
    assert.equal(store.run('b', otherTenant).status, 'queued');
  });

  test(`${runtime}: retry clears evidence, uses the current mapping and requires an open mapped investigation`, async t => {
    const { db, store, investigation } = fixture(t);
    const id = investigation('a', 'api');
    await store.setMapping('a', 'api', 'org/old', 1);
    store.enqueueMapped();
    db.prepare(`UPDATE agent_runs SET status = 'verified', error = 'old', result = 'old', patch = 'old',
      verification = '{}', commit_sha = 'old', started_at = 1, finished_at = 2`).run();
    if (runtime === 'Worker') db.prepare("UPDATE agent_runs SET attempt_id = 'previous'").run();
    assert.equal(store.run('a', id).needsReverification, true);
    assert.equal(store.retry('b', id), false);
    db.prepare("UPDATE investigations SET status = 'closed' WHERE id = ?").run(id);
    assert.equal(store.retry('a', id), false);
    assert.equal(store.run('a', id).status, 'verification_failed');
    db.prepare("UPDATE investigations SET status = 'open' WHERE id = ?").run(id);
    await store.setMapping('a', 'api', null, 1);
    assert.equal(store.retry('a', id), false);
    await store.setMapping('a', 'api', 'org/new', 2);
    assert.equal(store.retry('a', id), true);
    const row = db.prepare('SELECT * FROM agent_runs').get();
    assert.equal(row.repository, 'org/new');
    assert.equal(row.installation_id, 2);
    assert.equal(row.status, 'queued');
    for (const field of ['error', 'result', 'patch', 'verification', 'commit_sha', 'started_at', 'finished_at']) assert.equal(row[field], null, field);
    if (runtime === 'Worker') assert.equal(row.attempt_id, 'previous');
    for (const status of ['queued', 'running', 'completed', 'verified']) {
      db.prepare('UPDATE agent_runs SET status = ?, verification = ?').run(status, JSON.stringify(verifiedEvidence()));
      assert.equal(store.retry('a', id), false, status);
    }
    db.prepare("UPDATE agent_runs SET status = 'failed'").run();
    assert.equal(store.retry('a', id), true);
  });

  test(`${runtime}: enqueue is idempotent for eligible rules and removes only closed queued work`, async t => {
    const { db, store, investigation } = fixture(t);
    const rules = ['suspicious_request', 'repeated_auth_failure', 'worker_exception', 'resource_limit', 'server_error_burst'];
    const ids = [];
    for (const rule of [...rules, 'unsupported']) {
      ids.push(investigation('a', rule, rule));
      await store.setMapping('a', rule, 'org/old', 1);
    }
    const unmapped = investigation('b', 'unmapped');
    store.enqueueMapped();
    const before = db.prepare('SELECT * FROM agent_runs ORDER BY id').all();
    assert.equal(before.length, 5);
    assert.equal(store.run('a', ids[5]), null);
    assert.equal(store.run('b', unmapped), null);
    store.enqueueMapped();
    assert.deepEqual(db.prepare('SELECT * FROM agent_runs ORDER BY id').all(), before);
    db.prepare("UPDATE investigations SET status = 'closed' WHERE id IN (?, ?)").run(ids[0], ids[1]);
    db.prepare("UPDATE agent_runs SET status = 'running' WHERE investigation_id = ?").run(ids[1]);
    store.enqueueMapped();
    assert.equal(store.run('a', ids[0]), null);
    assert.equal(store.run('a', ids[1]).status, 'running');
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM agent_runs').get().count, 4);
  });
}
