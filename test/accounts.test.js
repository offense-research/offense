import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createAccounts } from '../server/accounts.js';
import { createEventStore } from '../server/event-store.js';

function database() {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE sessions (id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)');
  db.exec('CREATE TABLE ingest_tokens (token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, created_at INTEGER NOT NULL)');
  createEventStore(db);
  return db;
}

test('a signed-in user can open the claimed phone workspace on another device', () => {
  const db = database();
  const accounts = createAccounts(db);
  const user = accounts.upsertUser(12345, 'purple-owner');
  const phoneSession = 'phone-session';
  const phoneData = { company: 'Purple Labs', github: { installationId: 123 }, collectorInstall: { status: 'installed' } };
  db.prepare('INSERT INTO ingest_tokens VALUES (?, ?, ?)').run('token-hash', phoneSession, Date.now());
  const events = createEventStore(db);
  events.receiveBatch(phoneSession, [{ schema: 'purple.tail.v1', sourceWorker: 'api', queueMessageId: 'event-1' }]);
  accounts.claimLegacy(user.id, phoneSession, phoneData);
  const computerUser = accounts.upsertUser(12345, 'purple-owner-renamed');
  const computerWorkspace = accounts.workspaceForUser(computerUser.id);
  assert.equal(computerUser.id, user.id);
  assert.equal(computerWorkspace.id, phoneSession);
  assert.deepEqual(JSON.parse(computerWorkspace.data), phoneData);
  assert.equal(db.prepare('SELECT session_id FROM ingest_tokens').get().session_id, computerWorkspace.id);
  assert.equal(db.prepare('SELECT session_id FROM events').get().session_id, computerWorkspace.id);
  db.close();
});

test('only an unclaimed personal installation with one matching session can be recovered', () => {
  const db = database();
  const accounts = createAccounts(db);
  const legacy = { company: 'Purple', github: { account: 'owner', installationId: 42 }, collectorInstall: { status: 'installed' } };
  db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run('phone', JSON.stringify(legacy), Date.now());
  assert.equal(accounts.unclaimedPersonalInstall('owner', 42).id, 'phone');
  assert.equal(accounts.unclaimedPersonalInstall('someone-else', 42), null);
  assert.equal(accounts.unclaimedPersonalInstall('owner', 43), null);
  db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run('other-browser', JSON.stringify(legacy), Date.now());
  assert.equal(accounts.unclaimedPersonalInstall('owner', 42), null);
  db.close();
});

test('claiming a phone workspace replaces an empty computer workspace and preserves its logs', () => {
  const db = database();
  const accounts = createAccounts(db);
  const user = accounts.upsertUser(67890, 'owner');
  accounts.createWorkspace(user.id, 'computer-workspace', { company: 'Temporary' });
  db.prepare('INSERT INTO ingest_tokens VALUES (?, ?, ?)').run('token-hash', 'phone-session', Date.now());
  const events = createEventStore(db);
  events.receiveBatch('phone-session', [{ schema: 'purple.tail.v1', sourceWorker: 'api', queueMessageId: 'event-1' }]);
  db.prepare('UPDATE events SET exported_at = ?').run(Date.now());
  const claimed = accounts.claimLegacy(user.id, 'phone-session', { company: 'Real workspace', cloudflare: { name: 'Account' } });
  assert.equal(claimed.id, 'computer-workspace');
  assert.equal(db.prepare('SELECT session_id FROM ingest_tokens').get().session_id, claimed.id);
  assert.equal(db.prepare('SELECT session_id FROM events').get().session_id, claimed.id);
  assert.equal(db.prepare('SELECT exported_at FROM events').get().exported_at, null);
  assert.equal(db.prepare('SELECT session_id FROM ingest_batches').get().session_id, claimed.id);
  assert.throws(() => accounts.claimLegacy(user.id, 'another-phone', { company: 'Other' }), /already owns/);
  db.close();
});

test('a full phone install replaces a partial signed-in workspace without losing fresh Cloudflare access', () => {
  const db = database();
  const accounts = createAccounts(db);
  const user = accounts.upsertUser(13579, 'owner');
  accounts.createWorkspace(user.id, 'computer-workspace', {
    company: 'Purple', cloudflare: { accounts: [{ id: 'account-1', name: 'Cloudflare' }], accessToken: 'fresh-token' }
  });
  const phoneData = {
    company: 'Purple', cloudflare: { accounts: [{ id: 'account-1', name: 'Cloudflare' }], accessToken: 'old-token' },
    github: { installationId: 123 }, openrouter: { secret: 'encrypted-key' },
    collectorInstall: { status: 'installed', accountId: 'account-1' }
  };
  const claimed = accounts.claimLegacy(user.id, 'phone-session', phoneData);
  assert.equal(claimed.id, 'computer-workspace');
  assert.equal(JSON.parse(claimed.data).cloudflare.accessToken, 'fresh-token');
  assert.equal(JSON.parse(claimed.data).collectorInstall.status, 'installed');
  assert.throws(() => accounts.claimLegacy(user.id, 'other-session', phoneData), /already owns/);
  db.close();
});

test('returning users default to their configured workspace rather than an older empty workspace', () => {
  const db = database();
  try {
    const accounts = createAccounts(db), user = accounts.upsertUser(24680, 'returning-user');
    accounts.createWorkspace(user.id, 'old-empty', { company: 'Draft' });
    accounts.createWorkspace(user.id, 'connected', { company: 'Real', cloudflare: { name: 'CF' }, github: { installationId: 42 }, openrouter: { secret: 'encrypted' }, collectorInstall: { status: 'installed' } });
    assert.equal(accounts.workspaceForUser(user.id).id, 'connected');
    assert.equal(accounts.workspaceForUser(user.id, 'old-empty').id, 'old-empty');
    const other = accounts.upsertUser(24681, 'other-user');
    assert.equal(accounts.workspaceForUser(other.id, 'connected'), undefined);
  } finally { db.close(); }
});

test('stale token refresh cannot erase independently saved connections, Worker selections or mappings', async () => {
  const { createJsonDraft } = await import('../server/json-draft.js');
  const db = database();
  try {
    const accounts = createAccounts(db), user = accounts.upsertUser(24682, 'concurrent-user');
    const initial = { company: 'Real', cloudflare: { accessToken: 'old', expiresAt: 1 }, collectorInstall: { status: 'installing', sources: ['api'] } };
    accounts.createWorkspace(user.id, 'workspace', initial);
    const draft = () => createJsonDraft(JSON.parse(accounts.workspaceForUser(user.id).data), (data, baseline) => accounts.saveWorkspace('workspace', data, baseline));
    const refreshing = draft(), installing = draft();
    const heldInstall = installing.value.collectorInstall;
    refreshing.value.cloudflare.accessToken = 'fresh'; refreshing.value.cloudflare.expiresAt = 2;
    refreshing.save();
    installing.value.openrouter = { secret: 'encrypted' };
    heldInstall.status = 'installed'; installing.save();
    assert.equal(installing.value.collectorInstall, heldInstall);
    assert.equal(installing.value.cloudflare.accessToken, 'fresh');
    heldInstall.sources.push('links'); installing.save();
    const stored = JSON.parse(accounts.workspaceForUser(user.id).data);
    assert.equal(stored.openrouter.secret, 'encrypted');
    assert.equal(stored.cloudflare.accessToken, 'fresh');
    assert.deepEqual(stored.collectorInstall.sources, ['api', 'links']);
    assert.ok(db.prepare('SELECT COUNT(*) AS count FROM workspace_revisions WHERE workspace_id = ?').get('workspace').count >= 3);
  } finally { db.close(); }
});

test('a stale reconnect cannot resurrect a disconnected credential and revisions preserve the original state', async () => {
  const { createJsonDraft } = await import('../server/json-draft.js');
  const db = database();
  try {
    const accounts = createAccounts(db), user = accounts.upsertUser(24683, 'conflicting-user');
    const initial = { company: 'Real', cloudflare: { accessToken: 'encrypted' } };
    accounts.createWorkspace(user.id, 'workspace', initial);
    const draft = () => createJsonDraft(JSON.parse(accounts.workspaceForUser(user.id).data), (data, baseline) => accounts.saveWorkspace('workspace', data, baseline));
    const stale = draft(), current = draft();
    delete current.value.cloudflare; current.save();
    stale.value.cloudflare.accessToken = 'stale-replacement';
    assert.throws(() => stale.save(), error => error.status === 409);
    assert.equal(JSON.parse(accounts.workspaceForUser(user.id).data).cloudflare, undefined);
    assert.deepEqual(JSON.parse(db.prepare('SELECT data FROM workspace_revisions WHERE workspace_id = ?').get('workspace').data), initial);
  } finally { db.close(); }
});

test('GitHub connected before company setup survives a new device and transfers only to its owner workspace', () => {
  const db = database();
  try {
    let accounts = createAccounts(db);
    const user = accounts.upsertUser(5421262, 'first-login-user');
    const other = accounts.upsertUser(5421263, 'other-user');
    accounts.updateAccountConnections(user.id, data => {
      data.github = { account: 'first-login-user', installationId: 42 };
      data.githubAuthorization = { userId: user.id, secret: 'encrypted-oauth' };
    });
    accounts = createAccounts(db);
    const otherWorkspace = accounts.createWorkspace(other.id, 'other-workspace', { company: 'Other' });
    assert.equal(JSON.parse(otherWorkspace.data).github, undefined);
    const created = accounts.createWorkspace(user.id, 'customer-workspace', { company: 'Customer' });
    assert.equal(JSON.parse(created.data).github.installationId, 42);
    assert.equal(JSON.parse(created.data).githubAuthorization.secret, 'encrypted-oauth');
    assert.equal(accounts.workspaceForUser(user.id).id, 'customer-workspace');
    assert.equal(db.prepare('SELECT data FROM account_connections WHERE user_id = ?').get(user.id), undefined);
  } finally { db.close(); }
});
