import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync, backup } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createAccounts } from '../server/accounts.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createWelcomeCredit, WELCOME_CREDIT_MICROS } from '../server/welcome-credit.js';
import { createToolGateway, registerOffensePlatform } from '../server/offense-platform.js';
import { createHostedScans, registerScanApi } from '../server/hosted-scans.js';

const rates = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
const claimId = id => 'welcome:v1:' + createHash('sha256').update(String(id)).digest('hex');
function fixture(t, { enabled = true } = {}) {
  const db = new DatabaseSync(':memory:'), accounts = createAccounts(db);
  t.after(() => db.close());
  const meter = createScanMetering(db, { enabled, priceByToolMicros: rates, now: () => 1000 });
  const first = accounts.upsertUser(123456, 'first-owner'), second = accounts.upsertUser(987654, 'second-owner');
  accounts.createWorkspace(first.id, 'first-workspace', { company: 'First' });
  accounts.createWorkspace(second.id, 'second-workspace', { company: 'Second' });
  const welcome = createWelcomeCredit(db, { now: () => 1000 });
  const grants = () => db.prepare("SELECT * FROM scan_wallet_entries WHERE kind='welcome'").all();
  return { db, accounts, meter, first, second, welcome, grants };
}

test('a verified user receives exactly $5 of welcome credit, separately from purchase revenue', t => {
  const f = fixture(t);
  assert.equal(f.welcome.statusForUser(f.first.id, 'first-workspace').claimed, false);
  assert.equal(f.grants().length, 0, 'Inspecting eligibility never issues credit.');
  const result = f.welcome.grantForUser(f.first.id, 'first-workspace');
  assert.deepEqual(result, { amountMicros: 5_000_000, currency: 'usd', claimed: true,
    appliedToCurrentWorkspace: true, grantedAt: 1000, granted: true });
  assert.equal(f.meter.status('first-workspace').availableMicros, 5_000_000);
  assert.equal(f.db.prepare("SELECT COALESCE(SUM(amount_micros),0) AS n FROM scan_wallet_entries WHERE kind='purchase'").get().n, 0);
  assert.equal(f.grants().length, 1);
  assert.deepEqual(Object.keys(result).sort(), ['amountMicros', 'appliedToCurrentWorkspace', 'claimed', 'currency', 'granted', 'grantedAt']);
  assert.equal(f.grants()[0].id, claimId(123456));
  assert.equal(JSON.stringify(result).includes(f.first.id), false);
});

test('existing $10 grants remain usable and cannot be reclaimed after the new-user amount changes', t => {
  const f = fixture(t);
  f.db.prepare("INSERT INTO scan_wallet_entries VALUES (?, 'first-workspace', 10000000, 'welcome', 500)").run(claimId(123456));
  const before = f.grants();
  assert.deepEqual(f.welcome.grantForUser(f.first.id, 'first-workspace'), {
    amountMicros: 10_000_000, currency: 'usd', claimed: true, appliedToCurrentWorkspace: true, grantedAt: 500, granted: false
  });
  assert.equal(f.welcome.statusForUser(f.first.id, 'first-workspace').amountMicros, 10_000_000);
  f.accounts.createWorkspace(f.first.id, 'another-workspace', {});
  assert.equal(f.welcome.grantForUser(f.first.id, 'another-workspace').granted, false);
  assert.equal(f.meter.status('another-workspace').balanceMicros, 0);
  assert.deepEqual(f.grants(), before);
  assert.equal(f.meter.status('first-workspace').balanceMicros, 10_000_000);
  assert.equal(f.welcome.grantForUser(f.second.id, 'second-workspace').amountMicros, 5_000_000);
  assert.equal(f.meter.status('second-workspace').availableMicros, 5_000_000);
});

test('relogin, renamed GitHub handles, more workspaces and recreated local user IDs cannot claim twice', t => {
  const f = fixture(t);
  f.welcome.grantForUser(f.first.id, 'first-workspace');
  for (let i = 0; i < 5; i++) assert.equal(f.welcome.grantForUser(f.first.id, 'first-workspace').granted, false);
  const renamed = f.accounts.upsertUser(123456, 'renamed-owner');
  assert.equal(renamed.id, f.first.id);
  assert.equal(f.welcome.grantForUser(renamed.id, 'first-workspace').granted, false);
  f.accounts.createWorkspace(f.first.id, 'another-workspace', {});
  const secondWorkspace = f.welcome.grantForUser(f.first.id, 'another-workspace');
  assert.equal(secondWorkspace.granted, false); assert.equal(secondWorkspace.appliedToCurrentWorkspace, false);
  assert.equal(f.meter.status('another-workspace').availableMicros, 0);
  f.db.prepare('DELETE FROM memberships WHERE user_id = ?').run(f.first.id);
  f.db.prepare('DELETE FROM users WHERE id = ?').run(f.first.id);
  const recreated = f.accounts.upsertUser(123456, 'same-github-identity');
  assert.notEqual(recreated.id, f.first.id);
  f.accounts.createWorkspace(recreated.id, 'recreated-workspace', {});
  assert.equal(f.welcome.grantForUser(recreated.id, 'recreated-workspace').granted, false);
  assert.equal(f.grants().length, 1);
  assert.equal(f.meter.status('first-workspace').balanceMicros, WELCOME_CREDIT_MICROS);
});

test('eligibility requires stored numeric GitHub identity and current user/workspace membership', t => {
  const f = fixture(t);
  for (const [user, workspace] of [[null, 'first-workspace'], ['anonymous', 'first-workspace'],
    [f.first.id, 'second-workspace'], [f.first.id, 'missing'], [f.first.id, null], [123456, 'first-workspace']]) {
    assert.throws(() => f.welcome.grantForUser(user, workspace), error => error.code === 'welcome_credit_ineligible');
  }
  for (const githubId of ['anonymous', '-1', '0', '0123456', '9007199254740992']) {
    f.db.prepare('UPDATE users SET github_id = ? WHERE id = ?').run(githubId, f.first.id);
    assert.throws(() => f.welcome.grantForUser(f.first.id, 'first-workspace'), error => error.status === 403);
  }
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_wallet_entries').get().n, 0);
});

test('distinct verified users can each receive one grant, including when they share an account', t => {
  const f = fixture(t, { enabled: false });
  f.db.prepare("INSERT INTO memberships VALUES (?, 'first-workspace', 'member')").run(f.second.id);
  f.welcome.grantForUser(f.first.id, 'first-workspace');
  f.welcome.grantForUser(f.second.id, 'first-workspace');
  assert.equal(f.meter.status('first-workspace').balanceMicros, 10_000_000);
  assert.equal(f.welcome.grantForUser(f.second.id, 'second-workspace').granted, false);
  assert.equal(f.meter.status('second-workspace').balanceMicros, 0);
  assert.equal(f.grants().length, 2);
});

test('welcome credit funds ordinary reservations and settlement/refund remains idempotent', t => {
  const f = fixture(t);
  f.welcome.grantForUser(f.first.id, 'first-workspace');
  const jobId = 'a'.repeat(32), quote = f.meter.quote({ tools: ['opengrep'], inputBytes: 44, fileCount: 1 });
  f.meter.reserve({ jobId, workspaceId: 'first-workspace', quote });
  assert.equal(f.meter.status('first-workspace').availableMicros, WELCOME_CREDIT_MICROS - quote.maximumMicros);
  for (let i = 0; i < 2; i++) f.meter.settle({ jobId, status: 'completed', tools: [{ name: 'opengrep', status: 'complete' }] });
  assert.equal(f.meter.status('first-workspace').balanceMicros, WELCOME_CREDIT_MICROS - 25_000);
  f.meter.release(jobId); f.meter.release(jobId);
  assert.equal(f.meter.status('first-workspace').balanceMicros, WELCOME_CREDIT_MICROS);
  assert.equal(f.grants().length, 1);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='refund'").get().n, 1);
});

test('credits do not unlock a workspace blocked for payment review', t => {
  const f = fixture(t);
  f.meter.block('first-workspace');
  f.welcome.grantForUser(f.first.id, 'first-workspace');
  const status = f.meter.status('first-workspace');
  assert.equal(status.balanceMicros, WELCOME_CREDIT_MICROS); assert.equal(status.blocked, true);
  const quote = f.meter.quote({ tools: ['opengrep'], inputBytes: 44, fileCount: 1 });
  assert.throws(() => f.meter.reserve({ jobId: 'b'.repeat(32), workspaceId: 'first-workspace', quote }), /payment review/);
});

test('a failed grant rolls back cleanly and invalid historical claim rows are never silently corrected', t => {
  const f = fixture(t);
  f.db.exec("CREATE TRIGGER deny_welcome BEFORE INSERT ON scan_wallet_entries BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;");
  assert.throws(() => f.welcome.grantForUser(f.first.id, 'first-workspace'), error => error.status === 503 && !error.message.includes('synthetic'));
  assert.equal(f.grants().length, 0);
  f.db.exec('DROP TRIGGER deny_welcome');
  assert.equal(f.welcome.grantForUser(f.first.id, 'first-workspace').granted, true);
  for (const [field, badValue] of [['amount_micros', 1], ['kind', 'purchase'], ['workspace_id', ''], ['created_at', -1]]) {
    const id = claimId(123456), before = f.db.prepare('SELECT * FROM scan_wallet_entries WHERE id = ?').get(id);
    f.db.prepare(`UPDATE scan_wallet_entries SET ${field} = ? WHERE id = ?`).run(badValue, id);
    const corrupt = f.db.prepare('SELECT * FROM scan_wallet_entries WHERE id = ?').get(id);
    assert.throws(() => f.welcome.grantForUser(f.first.id, 'first-workspace'), error => error.code === 'welcome_credit_unavailable');
    assert.deepEqual(f.db.prepare('SELECT * FROM scan_wallet_entries WHERE id = ?').get(id), corrupt);
    f.db.prepare(`UPDATE scan_wallet_entries SET ${field} = ? WHERE id = ?`).run(before[field], id);
  }
  assert.equal(f.grants().length, 1);
});

test('a SQLite backup/restore and service recreation preserve the one-time entitlement', async t => {
  const f = fixture(t), directory = await mkdtemp(path.join(os.tmpdir(), 'offense-welcome-backup-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  f.welcome.grantForUser(f.first.id, 'first-workspace');
  const destination = path.join(directory, 'wallet.sqlite');
  await backup(f.db, destination); await chmod(destination, 0o600);
  const restored = new DatabaseSync(destination); t.after(() => restored.close());
  const welcome = createWelcomeCredit(restored, { now: () => 2000 });
  assert.equal(welcome.grantForUser(f.first.id, 'first-workspace').granted, false);
  assert.equal(restored.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind='welcome'").get().n, 1);
  assert.equal(createScanMetering(restored).status('first-workspace').balanceMicros, WELCOME_CREDIT_MICROS);
});

test('real key authentication initializes only valid member principals and new keys do not earn another grant', t => {
  const f = fixture(t), calls = [];
  const scans = createHostedScans(f.db, { metering: f.meter,
    onAuthenticatedPrincipal(value) { calls.push(value); f.welcome.grantForUser(value.userId, value.workspaceId); } });
  const first = scans.issueKey('first-workspace', f.first.id), second = scans.issueKey('first-workspace', f.first.id);
  const otherWorkspace = scans.issueKey('second-workspace', f.first.id);
  assert.equal(scans.authenticate('not-a-key'), null);
  assert.equal(scans.authenticate('offense_sk_' + 'a'.repeat(64)), null);
  f.db.prepare('UPDATE scan_keys SET revoked_at = 1000 WHERE id = ?').run(first.id);
  assert.equal(scans.authenticate(first.token), null);
  assert.equal(scans.authenticate(otherWorkspace.token), null);
  assert.deepEqual(calls, []); assert.equal(f.grants().length, 0);
  const gateway = createToolGateway({ scans, billing: { status: workspace => f.meter.status(workspace) },
    accounts: f.accounts, baseUrl: 'https://offense.test' });
  assert.equal(gateway.account(second.token).billing.balanceMicros, WELCOME_CREDIT_MICROS);
  f.db.prepare('UPDATE scan_keys SET revoked_at = NULL WHERE id = ?').run(first.id);
  assert.equal(scans.authenticate(first.token).id, first.id);
  assert.equal(f.grants().length, 1);
  for (const value of calls) assert.deepEqual(value, { userId: f.first.id, workspaceId: 'first-workspace' });
  assert.equal(JSON.stringify(calls).includes(first.token), false);
  assert.equal(JSON.stringify(calls).includes(second.token), false);
  f.db.prepare('DELETE FROM memberships WHERE user_id = ? AND workspace_id = ?').run(f.first.id, 'first-workspace');
  const before = calls.length;
  assert.equal(scans.authenticate(first.token), null); assert.equal(calls.length, before);
});

test('direct SDK scan and artifact authentication receive welcome funds before their own transactions', t => {
  const f = fixture(t);
  const scans = createHostedScans(f.db, { metering: f.meter, artifacts: {}, sandbox: {},
    encrypt: value => 'synthetic:' + value, decrypt: value => value.slice(10),
    onAuthenticatedPrincipal: ({ userId, workspaceId }) => f.welcome.grantForUser(userId, workspaceId) });
  const key = scans.issueKey('first-workspace', f.first.id);
  const input = { files: [{ path: 'example.js', content: 'const fixture = true;' }], tools: ['opengrep'], maxChargeMicros: 25_000 };
  const principal = scans.authenticate(key.token);
  const scan = scans.create(principal, input, 'welcome-direct-sdk-01');
  assert.equal(scan.status, 'queued');
  assert.equal(f.meter.status('first-workspace').availableMicros, WELCOME_CREDIT_MICROS - 25_000);
  assert.equal(scans.create(scans.authenticate(key.token), input, 'welcome-direct-sdk-01').id, scan.id);
  const artifactKey = scans.issueKey('second-workspace', f.second.id);
  const artifact = scans.beginArtifactUpload(artifactKey.token, { kind: 'image-tar', size: 2, sha256: 'b'.repeat(64) });
  assert.equal(f.meter.status('second-workspace').availableMicros, WELCOME_CREDIT_MICROS);
  assert.equal(scans.finishArtifactUpload(artifactKey.token, artifact.id, 2).id, artifact.id);
  const abandoned = scans.beginArtifactUpload(artifactKey.token, { kind: 'image-tar', size: 2, sha256: 'c'.repeat(64) });
  scans.abandonArtifactUpload(artifactKey.token, abandoned.id);
  assert.equal(f.db.prepare('SELECT status FROM scan_artifacts WHERE id = ?').get(abandoned.id).status, 'abandoned');
  assert.equal(f.grants().length, 2);
});

test('welcome initialization failures stay server errors rather than invalid-key responses on both API surfaces', t => {
  const f = fixture(t);
  const scans = createHostedScans(f.db, { metering: f.meter,
    onAuthenticatedPrincipal: ({ userId, workspaceId }) => f.welcome.grantForUser(userId, workspaceId) });
  const key = scans.issueKey('first-workspace', f.first.id);
  f.db.prepare("INSERT INTO scan_wallet_entries VALUES (?, 'first-workspace', 1, 'welcome', 1000)").run(claimId(123456));
  assert.throws(() => scans.authenticate(key.token), error => error.status === 503);
  const gateway = createToolGateway({ scans, billing: {}, accounts: f.accounts, baseUrl: 'https://offense.test' });
  assert.throws(() => gateway.authenticate(key.token), error => error.status === 503);
  const captured = () => {
    const routes = new Map();
    return { routes, get(route, ...handlers) { routes.set(route, handlers); }, post() {}, use() {} };
  };
  const legacy = captured(), platform = captured();
  registerScanApi(legacy, { scans }); registerOffensePlatform(platform, { gateway, scans, billing: {}, baseUrl: 'https://offense.test' });
  for (const [app, route] of [[legacy, '/v1/tools'], [platform, '/v1/account']]) {
    const req = { get: header => header === 'authorization' ? 'Bearer ' + key.token : undefined };
    const res = { set() { return this; }, status(value) { this.statusCode = value; return this; },
      json(value) { this.body = value; return this; } };
    app.routes.get(route)[0](req, res, () => assert.fail('Failed credit initialization must not continue.'));
    assert.equal(res.statusCode, 503);
    assert.equal(JSON.stringify(res.body).includes(key.token), false);
    assert.equal(JSON.stringify(res.body).includes('invalid_api_key'), false);
  }
  assert.equal(f.db.prepare('SELECT amount_micros FROM scan_wallet_entries WHERE id = ?').get(claimId(123456)).amount_micros, 1);
});
