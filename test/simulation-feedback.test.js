import { passingUpgradeEvidence } from './fixtures/upgrade-evidence.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createAccounts } from '../server/accounts.js';
import { createUpgradeRehearsals, proposeTrialRehearsal } from '../server/upgrade-rehearsal.js';
import { readRehearsal, rehearsalOutboundAllowed } from '../workers/rehearsal-lifecycle.js';
import { simulationSummary } from '../src/simulation-summary.js';

const change = { name: 'example', currentVersion: '1.0.0', targetVersion: '1.0.1' };
const plan = { ...change, impact: { paths: [['app', 'example']], parents: [] }, steps: [], parentOptions: [] };
const snapshot = { repository: 'org/repo', installationId: 1, revision: 'a'.repeat(40), scannedAt: 1,
  files: ['package-lock.json'], graph: { nodes: [{}] }, vulnerabilityCheck: { status: 'complete', checkedAt: 2,
    findings: [{ id: 'advisory', package: 'example', version: '1.0.0' }] } };

test('workspace creation is automatic, idempotent, and preserves pending connections and existing names', () => {
  const db = new DatabaseSync(':memory:');
  try {
    const accounts = createAccounts(db), user = accounts.upsertUser(123, 'startup');
    accounts.updateAccountConnections(user.id, data => { data.github = { installationId: 1 }; });
    const first = accounts.ensureWorkspace(user.id);
    assert.equal(JSON.parse(first.data).company, 'startup');
    assert.equal(JSON.parse(first.data).github.installationId, 1);
    assert.equal(accounts.ensureWorkspace(user.id).id, first.id);
    accounts.updateWorkspace(first.id, data => { data.company = 'Existing customer name'; });
    assert.equal(JSON.parse(accounts.ensureWorkspace(user.id).data).company, 'Existing customer name');
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM workspaces').get().count, 1);
    assert.throws(() => accounts.ensureWorkspace('someone-else'), /Sign in/);
  } finally { db.close(); }
});

test('first simulation needs no model key, persists quota, deduplicates retries and runs the existing sandbox', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
    const session = { github: { installationId: 1, account: 'org' } };
    db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
    let tokenCalls = 0, sandboxCalls = 0;
    const options = { mapper: { snapshots: id => id === 'workspace' ? [snapshot] : [], upgradePlan: async () => plan },
      github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => { tokenCalls++; return 'checkout-only'; } },
      decrypt: () => { throw new Error('Trial must not decrypt a model key'); },
      propose: () => { throw new Error('Trial must not call a model'); },
      sandbox: { start: async input => { sandboxCalls++; assert.equal(input.githubToken, 'checkout-only'); assert.deepEqual(input.scenarios[0].changes, [change]); return { status: 'running' }; },
        get: async () => ({ status: 'completed', revision: snapshot.revision, scenarios: [{ status: 'tests_passed', resolvedPackages: [{ name: 'example', version: '1.0.1' }] }] }) },
      check: async () => ({ status: 'complete', findings: [] }) };
    const service = createUpgradeRehearsals(db, options);
    assert.equal(service.entitlement('workspace').available, true);
    const first = service.start('workspace', 'org/repo', 1, session);
    assert.equal(first.trial, true);
    assert.equal(service.start('workspace', 'org/repo', 1, session).id, first.id);
    await service.dispatch();
    assert.deepEqual(service.latest('workspace', 'org/repo', 1).impact[0].paths, [['app', 'example']]);
    await service.dispatch();
    const recreated = createUpgradeRehearsals(db, options);
    assert.equal(recreated.entitlement('workspace').used, true);
    assert.equal(recreated.start('workspace', 'org/repo', 1, session).id, first.id, 'completed evidence is reusable');
    snapshot.scannedAt++;
    assert.equal(recreated.start('workspace', 'org/repo', 1, session).id, first.id, 'an unchanged scan refresh reuses the same evidence');
    const revision = snapshot.revision; snapshot.revision = 'b'.repeat(40);
    assert.throws(() => recreated.start('workspace', 'org/repo', 1, session), error => error.status === 402);
    snapshot.revision = revision;
    assert.throws(() => recreated.start('other', 'org/repo', 1, session), /complete npm dependency scan/);
    assert.equal(tokenCalls, 1); assert.equal(sandboxCalls, 1);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM upgrade_rehearsals').get().count, 1);
  } finally { db.close(); }
});

test('keyless planning rejects missing targets and deduplicates conflicting target versions', () => {
  assert.throws(() => proposeTrialRehearsal([]), /No checked/);
  const prediction = proposeTrialRehearsal([plan, plan, { ...plan, targetVersion: '2.0.0' }]);
  assert.deepEqual(prediction.scenarios[0].changes, [change]);
  assert.equal(prediction.usage.costUsd, 0);
});

function sandboxContext(result, overrides = {}) {
  const values = new Map([['rehearsal', { status: 'running', startedAt: Date.now() }]]);
  const events = [];
  const ctx = { storage: { kv: { get: key => values.get(key), put: (key, value) => { values.set(key, value); events.push('saved'); } },
    deleteAlarm: async () => { events.push('alarm deleted'); } },
    container: { running: true, exec: async () => ({ output: async () => ({ exitCode: 0, stdout: new TextEncoder().encode(JSON.stringify(result)) }) }),
      destroy: async () => { events.push('destroyed'); ctx.container.running = false; } } };
  Object.assign(ctx.container, overrides);
  return { ctx, events, values };
}

test('sandbox retains results before destroying code and repeated reads need no container', async () => {
  const result = { status: 'completed', revision: 'abc', scenarios: [] };
  const { ctx, events } = sandboxContext(result);
  assert.deepEqual(await readRehearsal(ctx), result);
  assert.deepEqual(events, ['saved', 'destroyed', 'alarm deleted']);
  assert.deepEqual(await readRehearsal(ctx), result);
});

test('sandbox destroys code on timeout, invalid results and retries failed cleanup', async () => {
  const timeout = sandboxContext({}); timeout.values.set('rehearsal', { status: 'running', startedAt: 0 });
  assert.equal((await readRehearsal(timeout.ctx)).status, 'failed');
  assert.ok(timeout.events.includes('destroyed'));
  const invalid = sandboxContext({}, { exec: async () => ({ output: async () => ({ exitCode: 0, stdout: new TextEncoder().encode('{') }) }) });
  assert.equal((await readRehearsal(invalid.ctx)).status, 'failed');
  assert.ok(invalid.events.includes('destroyed'));
  const retry = sandboxContext({ status: 'completed' });
  retry.ctx.container.destroy = async () => { throw new Error('temporary cleanup failure'); };
  await assert.rejects(readRehearsal(retry.ctx), /cleanup failure/);
  retry.ctx.container.destroy = async () => { retry.events.push('retried'); retry.ctx.container.running = false; };
  assert.equal((await readRehearsal(retry.ctx)).status, 'completed');
  assert.ok(retry.events.includes('retried'));
});

test('repository commands cannot reach GitHub, a model provider, arbitrary hosts or plaintext registries after checkout', () => {
  for (const url of ['https://github.com/a', 'https://openrouter.ai/api', 'https://evil.test', 'http://registry.npmjs.org/x', 'https://registry.npmjs.org.evil.test/x']) assert.equal(rehearsalOutboundAllowed(url), false);
  assert.equal(rehearsalOutboundAllowed('https://registry.npmjs.org/example'), true);
});

test('summary distinguishes failing baselines, stale reports and advisory blockers from verified candidates', () => {
  const good = passingUpgradeEvidence({changes:[change]});
  assert.equal(simulationSummary(good).verified, true);
  const baseline = structuredClone(good); baseline.result.baseline.checks[0].passed = false;
  assert.equal(simulationSummary(baseline).verified, false);
  assert.match(simulationSummary(baseline).nextStep, /original repository/);
  assert.equal(simulationSummary({ ...good, stale: true }).verified, false);
  const missingBaseline = structuredClone(good); delete missingBaseline.result.baseline;
  assert.equal(simulationSummary(missingBaseline).verified, false);
  const missing = structuredClone(good); delete missing.result.scenarios[0].vulnerabilityCheck;
  assert.equal(simulationSummary(missing).verified, false);
  const advisories = structuredClone(good); advisories.result.scenarios[0].remainingAdvisories = 1;
  assert.equal(simulationSummary(advisories).verified, false);
});

test('starting a fresh simulation is explicit while retries and saved-report reads remain deduplicated',()=>{
  const db=new DatabaseSync(':memory:');try{
    db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY,data TEXT)');
    const session={github:{installationId:1,account:'org'},openrouter:{secret:'encrypted'}};
    const service=createUpgradeRehearsals(db,{mapper:{snapshots:()=>[snapshot]},github:{},decrypt:()=>{},sandbox:{}});
    const first=service.start('workspace','org/repo',1,session),row=db.prepare('SELECT data FROM upgrade_rehearsals WHERE id=?').get(first.id),saved=JSON.parse(row.data);
    db.prepare("UPDATE upgrade_rehearsals SET status='completed',data=? WHERE id=?").run(JSON.stringify({...saved,status:'completed'}),first.id);
    assert.equal(service.start('workspace','org/repo',1,session).id,first.id,'reading a saved completed report must not spend more usage');
    const next=service.start('workspace','org/repo',1,session,{refresh:true});assert.notEqual(next.id,first.id);
    assert.equal(service.start('workspace','org/repo',1,session,{refresh:true}).id,next.id,'repeated clicks reuse an already running job');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM upgrade_rehearsals').get().n,2);
  }finally{db.close();}
});
