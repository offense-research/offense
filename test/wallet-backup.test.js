import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createAccounts } from '../server/accounts.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createWelcomeCredit, WELCOME_CREDIT_MICROS } from '../server/welcome-credit.js';
import { createToolCallMetrics } from '../server/tool-call-metrics.js';
import { exportD1, FINANCIAL_TABLES, OPTIONAL_TABLES, TABLES } from '../scripts/export-d1.mjs';
import { importWorkerState } from '../scripts/import-worker-state.mjs';

const key = 'synthetic-migration-key-' + 'a'.repeat(40);
async function fixture(t, { complete = true } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-wallet-backup-'));
  const filename = path.join(directory, 'source.sqlite');
  const db = new DatabaseSync(filename);
  t.after(async () => { if (db.isOpen) db.close(); await rm(directory, { recursive: true, force: true }); });
  if (complete) {
    const accounts = createAccounts(db);
    const user = accounts.upsertUser(12345, 'synthetic-owner');
    accounts.createWorkspace(user.id, 'workspace-one', { company: 'Synthetic workspace' });
    createScanMetering(db);
    createWelcomeCredit(db, { now: () => 100 }).grantForUser(user.id, 'workspace-one');
    const calls = createToolCallMetrics({ db, now: () => Date.UTC(2026, 0, 1) });
    calls.start({ kind: 'tool', channel: 'mcp', operation: 'audit' }).finish({ status: 'completed' });
    calls.start({ kind: 'tool', channel: 'mcp', operation: 'audit' }).finish({ status: 'rejected' });
    db.prepare('INSERT INTO scan_wallet_entries VALUES (?, ?, ?, ?, ?)').run('purchase:synthetic', 'workspace-one', 5_000_000, 'purchase', 101);
    db.exec(`CREATE TABLE scan_auto_topup_orders(id TEXT PRIMARY KEY, workspace_id TEXT, status TEXT, payment_id TEXT, consent_id TEXT);
      CREATE TABLE scan_auto_topup_events(id TEXT PRIMARY KEY, payment_id TEXT, processed_at INTEGER);
      CREATE TABLE scan_auto_topup_preferences(workspace_id TEXT PRIMARY KEY, enabled INTEGER, consent_id TEXT, member_id TEXT, payment_method_id TEXT);`);
    db.prepare('INSERT INTO scan_auto_topup_orders VALUES(?,?,?,?,?)').run('auto-order-one', 'workspace-one', 'pending', 'pay_synthetic', 'consent-one');
    db.prepare('INSERT INTO scan_auto_topup_events VALUES(?,?,?)').run('event-one', 'pay_synthetic', null);
    db.prepare('INSERT INTO scan_auto_topup_preferences VALUES(?,?,?,?,?)').run('workspace-one', 1, 'consent-one', 'mber_synthetic', 'payt_synthetic');
  }
  for (const table of TABLES.filter(table => complete || !OPTIONAL_TABLES.includes(table))) {
    if (!db.prepare('SELECT 1 FROM sqlite_master WHERE type = ? AND name = ?').get('table', table)) {
      db.exec(`CREATE TABLE "${table}"(id TEXT PRIMARY KEY, value TEXT)`);
    }
  }
  return { db, filename, directory };
}
function replica(source) {
  const db = new DatabaseSync(':memory:');
  for (const table of TABLES) {
    const row = source.prepare('SELECT sql FROM sqlite_master WHERE type = ? AND name = ?').get('table', table);
    if (row) db.exec(row.sql);
  }
  return db;
}
const options = filename => ({ databasePath: filename, destination: 'https://worker.example', key, log() {}, sleep: async () => {} });

test('financial backup and Worker import retain welcome claims, paid funds and pending auto-top-up identities', async t => {
  const source = await fixture(t), restored = replica(source.db), sqlRestored = replica(source.db);
  t.after(() => { restored.close(); sqlRestored.close(); });
  const originalClaim = { ...source.db.prepare("SELECT * FROM scan_wallet_entries WHERE kind = 'welcome'").get() };
  const exported = await exportD1(source.filename, path.join(source.directory, 'export'));
  assert.equal(exported.counts.scan_auto_topup_preferences, 1);
  assert.equal(exported.counts.scan_auto_topup_orders, 1);
  assert.equal(exported.counts.scan_auto_topup_events, 1);
  assert.equal(exported.counts.tool_call_days, 1);
  sqlRestored.exec(await readFile(exported.dataSql, 'utf8'));
  assert.deepEqual({ ...sqlRestored.prepare("SELECT * FROM scan_wallet_entries WHERE kind = 'welcome'").get() }, originalClaim);

  const requests = [];
  const result = await importWorkerState({ ...options(exported.snapshot), reset: true, fetchImpl: async (url, request) => {
    assert.equal(url.href, 'https://worker.example/api/internal/import');
    assert.equal(request.redirect, 'error');
    const payload = JSON.parse(request.body); requests.push(payload);
    if (payload.reset) for (const table of [...TABLES].reverse()) restored.exec(`DELETE FROM "${table}"`);
    else for (const row of payload.rows) {
      const columns = Object.keys(row);
      restored.prepare(`INSERT OR REPLACE INTO "${payload.table}" (${columns.map(name => `"${name}"`).join(',')}) VALUES (${columns.map(() => '?').join(',')})`)
        .run(...columns.map(name => row[name]));
    }
    return new Response('{}', { status: 200 });
  } });
  assert.equal(result.counts.scan_wallet_entries, 2);
  for (const replica of [restored, sqlRestored]) {
    const calls = createToolCallMetrics({ db: replica, now: () => Date.UTC(2026, 0, 2) }).read();
    assert.equal(calls.lifetime.total, 2);
    assert.equal(calls.lifetime.completed, 1);
    assert.equal(calls.lifetime.rejected, 1);
    assert.equal(calls.coverage.trackingStartedAt, Date.UTC(2026, 0, 1));
  }
  assert.deepEqual({ ...restored.prepare("SELECT * FROM scan_wallet_entries WHERE kind = 'welcome'").get() }, originalClaim);
  const userId = restored.prepare('SELECT id FROM users').get().id;
  assert.equal(createWelcomeCredit(restored).grantForUser(userId, 'workspace-one').granted, false);
  assert.equal(restored.prepare('SELECT SUM(amount_micros) AS amount FROM scan_wallet_entries').get().amount, WELCOME_CREDIT_MICROS + 5_000_000);
  assert.deepEqual({ ...restored.prepare('SELECT * FROM scan_auto_topup_preferences').get() },
    { workspace_id: 'workspace-one', enabled: 1, consent_id: 'consent-one', member_id: 'mber_synthetic', payment_method_id: 'payt_synthetic' });
  assert.deepEqual({ ...restored.prepare('SELECT * FROM scan_auto_topup_orders').get() },
    { id: 'auto-order-one', workspace_id: 'workspace-one', status: 'pending', payment_id: 'pay_synthetic', consent_id: 'consent-one' });
  const order = requests.findIndex(payload => payload.table === 'scan_auto_topup_orders');
  const event = requests.findIndex(payload => payload.table === 'scan_auto_topup_events');
  const preferences = requests.findIndex(payload => payload.table === 'scan_auto_topup_preferences');
  assert.ok(order > 0 && event > 0 && preferences > order && preferences > event);
});

test('old backups can merge optional data but cannot reset unrepresented financial state', async t => {
  const source = await fixture(t, { complete: false });
  let calls = 0;
  const fetchImpl = async () => { calls++; return new Response('{}'); };
  await assert.rejects(importWorkerState({ ...options(source.filename), reset: true, fetchImpl }), /complete financial backup/);
  assert.equal(calls, 0);
  const merged = await importWorkerState({ ...options(source.filename), fetchImpl });
  assert.ok(merged.skipped.includes('scan_wallet_entries'));
  assert.ok(merged.skipped.includes('scan_auto_topup_preferences'));
});

test('preflight rejects late oversized UTF-8 rows before a reset or any batch is sent', async t => {
  const source = await fixture(t);
  source.db.prepare('UPDATE scan_auto_topup_preferences SET consent_id = ?').run('é'.repeat(100_000));
  for (const reset of [false, true]) {
    let calls = 0;
    await assert.rejects(importWorkerState({ ...options(source.filename), reset,
      fetchImpl: async () => { calls++; return new Response('{}'); } }), /too large.*Nothing was sent/);
    assert.equal(calls, 0);
  }
});

test('export, importer and Worker allowlists cover the same financial tables', async () => {
  const worker = await readFile(new URL('../workers/app-staging.js', import.meta.url), 'utf8');
  const declaration = worker.match(/const importTables = new Set\(\[([\s\S]*?)\]\);/)[1];
  const accepted = [...declaration.matchAll(/'([^']+)'/g)].map(match => match[1]);
  assert.equal(new Set(TABLES).size, TABLES.length);
  for (const table of FINANCIAL_TABLES) assert.ok(TABLES.includes(table) && accepted.includes(table), table);
  assert.deepEqual(new Set(TABLES), new Set(accepted));
  const final = TABLES.indexOf('scan_auto_topup_preferences');
  for (const table of ['scan_auto_topup_orders', 'scan_auto_topup_events', 'scan_wallet_entries']) assert.ok(final > TABLES.indexOf(table));
});
