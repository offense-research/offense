import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createHostedScans, registerScanKeys } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';

const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url)));
const START = Date.UTC(2026, 9, 27, 12);

function keyList(db, scans) {
  let get;
  registerScanKeys({ get(path, handler) { assert.equal(path, '/api/scan-keys'); get = handler; }, post() {}, delete() {} }, { db, scans });
  return workspaceId => {
    let response;
    get({ workspaceId }, { json(value) { response = JSON.parse(JSON.stringify(value)); } });
    return response.keys;
  };
}

function fixture(t, { metered = true } = {}) {
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let clock = START, report = { status: 'running' };
  const meter = metered ? createScanMetering(db, { enabled: true, priceByToolMicros: prices, now: () => clock }) : null;
  const scans = createHostedScans(db, { metering: meter, now: () => clock,
    sandbox: { async start() { return { status: 'running' }; }, async get() { return report; }, async destroy() {} },
    encrypt: value => Buffer.from(value).toString('base64'), decrypt: value => Buffer.from(value, 'base64').toString() });
  const key = scans.issueKey('workspace-a', 'user-a');
  if (meter) meter.recordVerifiedPurchase({ workspaceId: 'workspace-a', paymentId: 'key-metrics-test-credit', amountMicros: 1_000_000 });
  return { db, scans, meter, key, list: keyList(db, scans), advance(ms) { clock += ms; },
    finish(value) { report = value; }, now: () => clock,
    submit(idempotencyKey) { return scans.create(scans.authenticate(key.token), {
      files: [{ path: 'example.js', content: 'eval(input);' }], tools: ['opengrep'], maxChargeMicros: 25_000
    }, idempotencyKey); } };
}

test('key listing follows real queued, settled and refunded usage without counting retries twice', async t => {
  const f = fixture(t);
  assert.deepEqual(f.list('workspace-a'), [{ id: f.key.id, createdAt: START, lastScanAt: null, scanCount: 0, spendMicros: 0 }]);
  f.advance(100);
  const first = f.submit('key-metrics-first');
  assert.equal(f.submit('key-metrics-first').id, first.id);
  assert.deepEqual(f.list('workspace-a')[0], { id: f.key.id, createdAt: START, lastScanAt: START + 100, scanCount: 1, spendMicros: 0 });
  await f.scans.dispatch();
  f.advance(100);
  f.finish({ status: 'completed', tools: [{ name: 'opengrep', status: 'complete' }], findings: [] });
  await f.scans.dispatch();
  assert.equal(f.meter.usage(first.id).state, 'settled');
  assert.equal(f.list('workspace-a')[0].spendMicros, 25_000);
  f.advance(100);
  f.submit('key-metrics-pending');
  assert.deepEqual(f.list('workspace-a')[0], { id: f.key.id, createdAt: START, lastScanAt: START + 300, scanCount: 2, spendMicros: 25_000 });
  f.meter.release(first.id);
  assert.equal(f.meter.usage(first.id).state, 'released');
  assert.equal(f.list('workspace-a')[0].spendMicros, 0);
  // Expiring report contents leaves the recorded submission and net spend intact.
  f.db.prepare('UPDATE scan_jobs SET result = NULL WHERE id = ?').run(first.id);
  assert.equal(f.list('workspace-a')[0].scanCount, 2);
});

function insertJob(db, { id, workspace, key, at }) {
  db.prepare(`INSERT INTO scan_jobs (id, workspace_id, user_id, key_id, idempotency_key, fingerprint,
    status, created_at, updated_at, input_bytes, file_count, result, error)
    VALUES (?, ?, 'synthetic-user', ?, ?, 'PRIVATE_FINGERPRINT', 'completed', ?, ?, 1, 1, 'PRIVATE_PAYLOAD', 'PRIVATE_ERROR')`)
    .run(id, workspace, key, id, at, at);
}

function insertCharge(db, { id, workspace, amount, state = 'settled' }) {
  db.prepare(`INSERT INTO scan_meter_jobs (job_id, workspace_id, state, quote_json,
    reserve_micros, charge_micros, created_at, updated_at) VALUES (?, ?, ?, '{}', 0, ?, ?, ?)`)
    .run(id, workspace, state, amount, START, START);
}

test('key metrics isolate workspace and key for jobs, meter rows and key visibility', t => {
  const f = fixture(t);
  f.advance(1);
  const second = f.scans.issueKey('workspace-a', 'user-a');
  const foreign = f.scans.issueKey('workspace-b', 'user-b');
  const revoked = f.scans.issueKey('workspace-a', 'user-a');
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(START, revoked.id);
  insertJob(f.db, { id: 'local-paid', workspace: 'workspace-a', key: f.key.id, at: START + 10 });
  insertCharge(f.db, { id: 'local-paid', workspace: 'workspace-a', amount: 50_000 });
  // A malformed cross-workspace job must not affect this key's count or latest scan.
  insertJob(f.db, { id: 'foreign-job', workspace: 'workspace-b', key: f.key.id, at: START + 100_000 });
  insertCharge(f.db, { id: 'foreign-job', workspace: 'workspace-b', amount: 900_000 });
  // A malformed cross-workspace meter row must not affect the local job's spend.
  insertJob(f.db, { id: 'foreign-charge', workspace: 'workspace-a', key: f.key.id, at: START + 20 });
  insertCharge(f.db, { id: 'foreign-charge', workspace: 'workspace-b', amount: 800_000 });
  insertJob(f.db, { id: 'second-key-job', workspace: 'workspace-a', key: second.id, at: START + 30 });
  insertCharge(f.db, { id: 'second-key-job', workspace: 'workspace-a', amount: 20_000 });
  const keys = f.list('workspace-a');
  assert.equal(keys.length, 2);
  assert.equal(keys[0].id, second.id);
  assert.deepEqual(keys.find(key => key.id === f.key.id), { id: f.key.id, createdAt: START,
    lastScanAt: START + 20, scanCount: 2, spendMicros: 50_000 });
  assert.equal(keys[0].scanCount, 1); assert.equal(keys[0].spendMicros, 20_000);
  assert.deepEqual(f.list('workspace-b').map(key => key.id), [foreign.id]);
  assert.deepEqual(f.list('workspace-missing'), []);
  const serialized = JSON.stringify(keys);
  for (const secret of [f.key.token, foreign.token, createHash('sha256').update(f.key.token).digest('hex'),
    'PRIVATE_FINGERPRINT', 'PRIVATE_PAYLOAD', 'PRIVATE_ERROR']) assert.ok(!serialized.includes(secret));
  assert.deepEqual(Object.keys(keys[0]).sort(), ['createdAt', 'id', 'lastScanAt', 'scanCount', 'spendMicros']);
});

test('missing job or metering storage remains unknown while known empty usage is zero', t => {
  const f = fixture(t, { metered: false });
  assert.deepEqual(f.list('workspace-a')[0], { id: f.key.id, createdAt: START,
    lastScanAt: null, scanCount: 0, spendMicros: null });
  f.db.exec('DROP TABLE scan_jobs');
  assert.deepEqual(f.list('workspace-a')[0], { id: f.key.id, createdAt: START,
    lastScanAt: null, scanCount: null, spendMicros: null });
});

test('released, reserved and unbilled meter states never appear as settled key spend', t => {
  const f = fixture(t);
  for (const [index, state] of ['reserved', 'released', 'unbilled'].entries()) {
    const id = 'not-settled-' + index;
    insertJob(f.db, { id, workspace: 'workspace-a', key: f.key.id, at: START + index });
    insertCharge(f.db, { id, workspace: 'workspace-a', state, amount: 900_000 });
  }
  assert.equal(f.list('workspace-a')[0].scanCount, 3);
  assert.equal(f.list('workspace-a')[0].spendMicros, 0);
});
