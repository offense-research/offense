import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import express from 'express';
import { createAccounts } from '../server/accounts.js';
import { createHostedScans } from '../server/hosted-scans.js';
import { createCliAuth, registerCliAuthPublic, registerCliAuthBrowser } from '../server/cli-auth.js';

const hash = value => createHash('sha256').update(value).digest('hex');
const ORIGIN = 'https://offense.test';
function fixture(t, filename = ':memory:') {
  const db = new DatabaseSync(filename), accounts = createAccounts(db);
  const first = accounts.upsertUser(1, 'first'), second = accounts.upsertUser(2, 'second');
  accounts.createWorkspace(first.id, 'account-one', { company: 'First account' });
  accounts.createWorkspace(second.id, 'account-two', { company: 'Second account' });
  db.exec('CREATE TABLE IF NOT EXISTS issued_keys (id TEXT PRIMARY KEY, workspace_id TEXT, user_id TEXT, token_hash TEXT)');
  let clock = Date.parse('2026-10-27T12:00:00Z'), issueFailure = false;
  const issued = [];
  const scans = { issueKey(workspace, user, options) {
    assert.equal(options.inTransaction, true, 'Key insertion must be part of the authorization transaction.');
    const id = randomBytes(16).toString('hex'), token = 'offense_sk_' + randomBytes(32).toString('hex');
    db.prepare('INSERT INTO issued_keys VALUES (?,?,?,?)').run(id, workspace, user, hash(token));
    if (issueFailure) throw Error('PRIVATE_DB_ERROR_MUST_NOT_ESCAPE');
    issued.push(token); return { id, token };
  } };
  let auth = createCliAuth({ db, scans, baseUrl: ORIGIN, now: () => clock });
  t.after(() => { try { db.close(); } catch {} });
  return { db, accounts, first, second, scans, issued, get auth() { return auth; },
    restart() { auth = createCliAuth({ db, scans, baseUrl: ORIGIN, now: () => clock }); },
    advance(ms) { clock += ms; }, failIssue(value) { issueFailure = value; },
    a: { userId: first.id, workspaceId: 'account-one' }, b: { userId: second.id, workspaceId: 'account-two' } };
}
const rejects = (action, code, status) => assert.throws(action, error => error.code === code && (status === undefined || error.status === status));

test('device login stores only hashes, binds approval and returns one API key only to the polling CLI', t => {
  const f = fixture(t), begin = f.auth.start({ source: 'PRIVATE_IP_VALUE' });
  assert.match(begin.device_code, /^[a-f0-9]{64}$/);
  assert.match(begin.user_code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
  assert.equal(begin.verification_uri, ORIGIN + '/device');
  assert.equal(begin.verification_uri_complete, ORIGIN + '/device#code=' + begin.user_code);
  assert.equal(begin.interval, 5); assert.equal(begin.expires_in, 600);
  const inspect = f.auth.inspect(begin.user_code.toLowerCase(), f.a);
  assert.equal(inspect.status, 'pending'); assert.deepEqual(inspect.workspace, { id: 'account-one', name: 'First account' });
  const approval = f.auth.approve(begin.user_code, true, f.a);
  assert.equal(approval.status, 'approved');
  assert.ok(!JSON.stringify(approval).includes('access_token'));
  const result = f.auth.poll(begin.device_code, { source: 'PRIVATE_IP_VALUE' });
  assert.equal(result.token_type, 'Bearer'); assert.equal(result.scope, 'tools:call account:read billing:checkout');
  assert.equal(result.workspace.id, 'account-one'); assert.equal(f.issued.length, 1);
  rejects(() => f.auth.poll(begin.device_code), 'access_denied');
  const stored = JSON.stringify({ devices: f.db.prepare('SELECT * FROM cli_auth_devices').all(), limits: f.db.prepare('SELECT * FROM cli_auth_limits').all(), keys: f.db.prepare('SELECT * FROM issued_keys').all() });
  for (const secret of [begin.device_code, begin.user_code, begin.user_code.replace('-', ''), result.access_token, 'PRIVATE_IP_VALUE'])
    assert.ok(!stored.includes(secret), 'Raw authorization codes, API keys and request identity must not be stored.');
  assert.equal(f.db.prepare('SELECT status FROM cli_auth_devices').get().status, 'consumed');
});

test('pending polling enforces durable minimum intervals and slow_down without issuing keys', t => {
  const f = fixture(t), begin = f.auth.start();
  rejects(() => f.auth.poll(begin.device_code), 'authorization_pending', 400);
  rejects(() => f.auth.poll(begin.device_code), 'slow_down', 400);
  assert.equal(f.db.prepare('SELECT poll_interval FROM cli_auth_devices').get().poll_interval, 10);
  f.restart(); f.advance(9000);
  rejects(() => f.auth.poll(begin.device_code), 'slow_down');
  f.advance(15000);
  rejects(() => f.auth.poll(begin.device_code), 'authorization_pending');
  assert.equal(f.issued.length, 0);
  f.auth.approve(begin.user_code, true, f.a); f.advance(15000);
  assert.equal(f.auth.poll(begin.device_code).workspace.id, 'account-one');
});

test('a consumed device cannot replay across recreation and concurrent polls issue exactly one key', async t => {
  const f = fixture(t), begin = f.auth.start();
  f.auth.approve(begin.user_code, true, f.a);
  const results = await Promise.allSettled([Promise.resolve().then(() => f.auth.poll(begin.device_code)), Promise.resolve().then(() => f.auth.poll(begin.device_code))]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM issued_keys').get().n, 1);
  f.restart();
  rejects(() => f.auth.poll(begin.device_code), 'access_denied');
  assert.equal(f.auth.approve(begin.user_code, true, f.a).completed, true);
  rejects(() => f.auth.approve(begin.user_code, false, f.a), 'invalid_request');
});

test('actual database reconnection retains approved requests without persisting the future API key', t => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'offense-cli-auth-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, 'auth.sqlite');
  let db = new DatabaseSync(filename);
  const accounts = createAccounts(db), user = accounts.upsertUser(3, 'account-owner');
  accounts.createWorkspace(user.id, 'durable-account', { company: 'Durable' });
  const scans = { issueKey: () => ({ id: 'new-key', token: 'offense_sk_' + 'a'.repeat(64) }) };
  let auth = createCliAuth({ db, scans, baseUrl: ORIGIN });
  const begin = auth.start(); auth.approve(begin.user_code, true, { userId: user.id, workspaceId: 'durable-account' }); db.close();
  db = new DatabaseSync(filename); t.after(() => db.close());
  auth = createCliAuth({ db, scans, baseUrl: ORIGIN });
  assert.equal(auth.poll(begin.device_code).key_id, 'new-key');
  assert.equal(db.prepare('SELECT status FROM cli_auth_devices').get().status, 'consumed');
});

test('decline and expiry cannot create keys, and expired inspection remains truthful', t => {
  const f = fixture(t), declined = f.auth.start();
  f.auth.approve(declined.user_code, false, f.a);
  rejects(() => f.auth.poll(declined.device_code), 'access_denied', 403);
  assert.equal(f.auth.approve(declined.user_code, true, f.a).status, 'denied');
  const expired = f.auth.start(); f.advance(600000);
  assert.equal(f.auth.inspect(expired.user_code, f.a).status, 'expired');
  rejects(() => f.auth.approve(expired.user_code, true, f.a), 'expired_token');
  rejects(() => f.auth.poll(expired.device_code), 'expired_token');
  assert.equal(f.issued.length, 0);
});

test('approval is bound to the current account and fresh membership is required before key issuance', t => {
  const f = fixture(t), begin = f.auth.start();
  f.auth.approve(begin.user_code, true, f.a);
  rejects(() => f.auth.inspect(begin.user_code, f.b), 'access_denied');
  rejects(() => f.auth.approve(begin.user_code, false, f.b), 'access_denied');
  rejects(() => f.auth.approve(begin.user_code, true, { userId: f.first.id, workspaceId: 'account-two' }), 'access_denied');
  f.db.prepare('DELETE FROM memberships WHERE user_id = ? AND workspace_id = ?').run(f.first.id, 'account-one');
  rejects(() => f.auth.poll(begin.device_code), 'access_denied');
  assert.equal(f.db.prepare('SELECT status FROM cli_auth_devices').get().status, 'denied');
  assert.equal(f.issued.length, 0);
});

test('key insertion failures roll back both key and consumption and reveal no internal error', t => {
  const f = fixture(t), begin = f.auth.start(); f.auth.approve(begin.user_code, true, f.a); f.failIssue(true);
  rejects(() => f.auth.poll(begin.device_code), 'temporarily_unavailable', 503);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM issued_keys').get().n, 0);
  assert.equal(f.db.prepare('SELECT status FROM cli_auth_devices').get().status, 'approved');
  f.failIssue(false);
  assert.equal(f.auth.poll(begin.device_code).token_type, 'Bearer');
});

test('device creation and code guessing are durably rate limited', t => {
  const f = fixture(t);
  for (let i = 0; i < 5; i++) f.auth.start({ source: 'one-client' });
  rejects(() => f.auth.start({ source: 'one-client' }), 'slow_down', 429);
  f.restart(); rejects(() => f.auth.start({ source: 'one-client' }), 'slow_down', 429);
  for (let i = 0; i < 20; i++) rejects(() => f.auth.inspect('ABCD-EFGH', f.a), 'invalid_request');
  rejects(() => f.auth.inspect('ABCD-EFGH', f.a), 'slow_down', 429);
  for (let i = 0; i < 10; i++) rejects(() => f.auth.poll('f'.repeat(64), { source: 'guessing-client' }), 'invalid_grant');
  rejects(() => f.auth.poll('f'.repeat(64), { source: 'guessing-client' }), 'slow_down', 429);
});

test('browser authorization requires sign-in, exact origin and rejects caller-selected accounts', async t => {
  const f = fixture(t), app = express();
  registerCliAuthPublic(app, { auth: f.auth });
  app.use((req, res, next) => {
    if (req.get('x-test-user') === 'first') { req.authUser = f.first; req.workspaceId = 'account-one'; }
    next();
  });
  registerCliAuthBrowser(app, { auth: f.auth });
  const server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (route, body = {}, headers = {}) => fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  assert.equal((await post('/v1/auth/device', {}, { origin: 'https://other.test' })).status, 403);
  assert.equal((await post('/v1/auth/device', { workspace_id: 'account-two' })).status, 400);
  const initial = await post('/v1/auth/device'); assert.equal(initial.status, 200);
  assert.equal(initial.headers.get('cache-control'), 'no-store');
  const begin = await initial.json();
  assert.equal((await post('/api/cli/device/inspect', { user_code: begin.user_code }, { origin: ORIGIN })).status, 401);
  assert.equal((await post('/api/cli/device/inspect', { user_code: begin.user_code }, { 'x-test-user': 'first' })).status, 403);
  const browser = { origin: ORIGIN, 'x-test-user': 'first' };
  assert.equal((await post('/api/cli/device/approve', { user_code: begin.user_code, approved: true, workspace_id: 'account-two' }, browser)).status, 400);
  const inspected = await post('/api/cli/device/inspect', { user_code: begin.user_code }, browser);
  assert.equal(inspected.status, 200); assert.equal((await inspected.json()).workspace.id, 'account-one');
  const approved = await post('/api/cli/device/approve', { user_code: begin.user_code, approved: true }, browser);
  assert.equal(approved.status, 200); assert.ok(!(await approved.text()).includes('access_token'));
  const token = await post('/v1/auth/device/token', { device_code: begin.device_code });
  assert.equal(token.status, 200); assert.equal(token.headers.get('cache-control'), 'no-store');
  const value = await token.json(); assert.equal(value.workspace.id, 'account-one');
  const replay = await post('/v1/auth/device/token', { device_code: begin.device_code });
  assert.equal(replay.status, 403); assert.equal((await replay.json()).error, 'access_denied');
  const malformed = await fetch(base + '/api/cli/device/inspect', { method: 'POST', headers: { 'content-type': 'application/json', ...browser }, body: '{PRIVATE_BAD_JSON' });
  assert.equal(malformed.status, 400);
  const malformedBody = await malformed.json();
  assert.equal(malformedBody.error, 'invalid_request'); assert.ok(!JSON.stringify(malformedBody).includes('PRIVATE_BAD_JSON'));
});

test('approval origins are explicit server configuration and development origins require a local server', t => {
  const f = fixture(t);
  const configured = createCliAuth({ db: f.db, scans: f.scans, baseUrl: ORIGIN, allowedOrigins: ['https://legacy.test'] });
  assert.deepEqual([...configured.origins], [ORIGIN, 'https://legacy.test']);
  assert.equal(configured.origins.has('https://legacy.test.attacker.test'), false);
  assert.equal(configured.origins.has('null'), false);
  assert.throws(() => createCliAuth({ db: f.db, scans: f.scans, baseUrl: ORIGIN, allowedOrigins: ['https://legacy.test/anything'] }), /explicit trusted/);
  assert.throws(() => createCliAuth({ db: f.db, scans: f.scans, baseUrl: ORIGIN, allowedOrigins: ['http://localhost:5173'] }), /explicit trusted/);
  const local = createCliAuth({ db: f.db, scans: f.scans, baseUrl: 'http://127.0.0.1:3217', allowedOrigins: ['http://localhost:5173'] });
  assert.equal(local.origins.has('http://localhost:5173'), true);
});

test('migration matches runtime schema and issued real keys retain normal revocation behavior', t => {
  const f = fixture(t);
  f.db.exec(readFileSync(new URL('../migrations/0009_cli_auth.sql', import.meta.url), 'utf8'));
  const scans = createHostedScans(f.db);
  const auth = createCliAuth({ db: f.db, scans, baseUrl: ORIGIN });
  const begin = auth.start(); auth.approve(begin.user_code, true, f.a);
  const key = auth.poll(begin.device_code);
  assert.equal(scans.authenticate(key.access_token).workspace_id, 'account-one');
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(Date.now(), key.key_id);
  assert.equal(scans.authenticate(key.access_token), null);
  rejects(() => auth.poll(begin.device_code), 'access_denied');
});

test('approval cannot switch away from the account shown during inspection', t => {
  const f = fixture(t), begin = f.auth.start();
  f.accounts.createWorkspace(f.first.id, 'other-owned-account', {company:'Another account'});
  f.auth.inspect(begin.user_code, f.a);
  rejects(() => f.auth.approve(begin.user_code,true,{userId:f.first.id,workspaceId:'other-owned-account'}),'access_denied',403);
  assert.equal(f.issued.length,0);
  rejects(() => f.auth.poll(begin.device_code),'authorization_pending',400);
});
