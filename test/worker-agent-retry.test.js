import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createEventStore } from '../server/event-store.js';
import { createAccounts } from '../server/accounts.js';
import { createAgentRunner } from '../workers/agent-runner.js';

test('a failed investigation retry receives a fresh container attempt and polling uses that attempt', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    const store = createEventStore(db);
    createAccounts(db);
    db.prepare('INSERT INTO workspaces VALUES (?, ?, ?, ?)').run('workspace', JSON.stringify({
      github: { account: 'org', installationId: 1 }, openrouter: { secret: 'encrypted' }
    }), 1, 1);
    store.receiveBatch('workspace', [{ sourceWorker: 'api', queueMessageId: 'fixture', outcome: 'exception', exceptionNames: ['TypeError'] }]);
    const id = store.investigations('workspace')[0].id;
    const attempts = [];
    let polls = 0;
    const runner = createAgentRunner(db, {
      github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => 'github-fixture' },
      decrypt: () => 'openrouter-fixture', sandbox: {
        startInvestigation: async input => { attempts.push(input); return { status: 'running' }; },
        getInvestigation: async (runId, attemptId) => {
          assert.equal(runId, attempts.at(-1).runId);
          assert.equal(attemptId, attempts.at(-1).attemptId);
          return ++polls === 1 ? { status: 'failed', error: 'fixture failure' } : { status: 'completed', summary: 'Reviewed without a finding' };
        }
      }
    });
    await runner.setMapping('workspace', 'api', 'org/repo', 1);
    runner.enqueueMapped();
    await runner.processOne(); await runner.pollRunning();
    assert.equal(runner.run('workspace', id).status, 'failed');
    assert.equal(runner.retry('other-workspace', id), false);
    assert.equal(runner.retry('workspace', id), true);
    await runner.processOne(); await runner.pollRunning();
    assert.equal(attempts[0].runId, attempts[1].runId);
    assert.notEqual(attempts[0].attemptId, attempts[1].attemptId);
    assert.match(attempts[1].attemptId, /^[a-f0-9]{32}$/);
    assert.equal(runner.run('workspace', id).status, 'completed');
  } finally { db.close(); }
});

test('the production runner rejects raw exit-code confirmations and accepts only qualified structured evidence', async () => {
  const { verifiedEvidence } = await import('./helpers/verification-evidence.js');
  for (const strong of [false, true]) {
    const db = new DatabaseSync(':memory:');
    try {
      const store = createEventStore(db); createAccounts(db);
      db.prepare('INSERT INTO workspaces VALUES (?, ?, ?, ?)').run('workspace', JSON.stringify({ github: { account: 'org', installationId: 1 }, openrouter: { secret: 'fixture' } }), 1, 1);
      store.receiveBatch('workspace', [{ sourceWorker: 'api', queueMessageId: 'fixture', outcome: 'exception', exceptionNames: ['TypeError'] }]);
      const id = store.investigations('workspace')[0].id;
      const legacy = { verified: true, baselineNormal: { code: 0 }, baselineReproduction: { code: 1 }, patchedReproduction: { code: 0 }, patchedNormal: { code: 0 } };
      const runner = createAgentRunner(db, {
        github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => 'fixture' }, decrypt: () => 'fixture',
        sandbox: { startInvestigation: async () => ({ status: 'running' }), getInvestigation: async () => ({ status: 'verified', commitSha: 'a'.repeat(40),
          summary: 'Tenant ownership fix', patch: 'diff --git a/auth.js b/auth.js\n-old\n+fixed', verification: strong ? verifiedEvidence() : legacy }) }
      });
      await runner.setMapping('workspace', 'api', 'org/repo', 1); runner.enqueueMapped(); await runner.processOne(); await runner.pollRunning();
      assert.equal(runner.run('workspace', id).status, strong ? 'verified' : 'verification_failed');
      assert.equal(runner.vulnerabilities.metrics().total, strong ? 1 : 0);
      if (!strong) {
        db.prepare("UPDATE agent_runs SET status='verified', verification=? WHERE investigation_id=?").run(JSON.stringify(legacy), id);
        assert.equal(runner.run('workspace', id).needsReverification, true); assert.equal(runner.retry('workspace', id), true);
      } else assert.equal(runner.retry('workspace', id), false);
    } finally { db.close(); }
  }
});
