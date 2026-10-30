import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createAccounts } from '../server/accounts.js';
import { createContactEmails, normalizeContactEmail } from '../server/contact-emails.js';
import { createWorkerApp } from '../workers/app-api.js';

function fixture() {
  const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys = ON');
  const accounts = createAccounts(db), user = accounts.upsertUser(1, 'customer');
  return { db, user, contacts: createContactEmails(db) };
}

test('contact emails validate before persistence and normalize domains', () => {
  assert.equal(normalizeContactEmail(' Customer+purple@EXAMPLE.COM '), 'Customer+purple@example.com');
  for (const value of [null, {}, 'no-at', 'a@localhost', 'a@@example.com', 'a\r\n@example.com', '.a@example.com', 'a..b@example.com', 'a@-example.com', 'x'.repeat(65)+'@example.com']) assert.equal(normalizeContactEmail(value), null);
  const { db, user, contacts } = fixture();
  try {
    assert.throws(() => contacts.save(user.id, { email: 'bad', productUpdates: false }), error => error.status === 400);
    assert.throws(() => contacts.save(user.id, { email: 'hello@example.com', productUpdates: 'true' }), error => error.status === 400);
    assert.equal(contacts.get(user.id).email, '');
  } finally { db.close(); }
});

test('GitHub suggestions never become a saved address or product consent and preserve manual preferences', () => {
  const { db, user, contacts } = fixture();
  try {
    contacts.suggestFromGitHub(user.id, null);
    contacts.suggestFromGitHub(user.id, '123@users.noreply.github.com');
    assert.equal(contacts.get(user.id).suggestedEmail, '');
    contacts.suggestFromGitHub(user.id, 'github@example.com');
    let value = contacts.get(user.id);
    assert.equal(value.email, ''); assert.equal(value.suggestedEmail, 'github@example.com');
    assert.equal(value.productUpdates, false); assert.equal(value.verified, false);
    contacts.save(user.id, { email: 'preferred@example.com', productUpdates: true });
    contacts.suggestFromGitHub(user.id, 'other@example.com');
    value = contacts.get(user.id);
    assert.equal(value.email, 'preferred@example.com'); assert.equal(value.suggestedEmail, '');
    assert.equal(value.productUpdates, true); assert.ok(value.consentUpdatedAt);
    assert.equal(db.prepare('SELECT consent_version FROM user_contacts WHERE user_id = ?').get(user.id).consent_version, 'product-updates-v1');
    contacts.save(user.id, { email: 'preferred@example.com', productUpdates: false });
    assert.equal(contacts.get(user.id).productUpdates, false);
  } finally { db.close(); }
});

test('dismissal persists and removing an address revokes consent and prevents automatic reacquisition', () => {
  const { db, user, contacts } = fixture();
  try {
    assert.ok(contacts.dismiss(user.id).dismissedAt);
    assert.ok(createContactEmails(db).get(user.id).dismissedAt);
    contacts.save(user.id, { email: 'hello@example.com', productUpdates: true });
    const removed = contacts.remove(user.id);
    assert.equal(removed.email, ''); assert.equal(removed.suggestedEmail, ''); assert.equal(removed.productUpdates, false);
    contacts.suggestFromGitHub(user.id, 'hello@example.com');
    assert.equal(contacts.get(user.id).suggestedEmail, '');
  } finally { db.close(); }
});

test('contact API requires login, enforces origin and scopes email to the signed-in person', async () => {
  const db = new DatabaseSync(':memory:'); let server;
  try {
    const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://purple.test' }, schedule: () => {} });
    const accounts = createAccounts(db), alice = accounts.upsertUser(10, 'alice'), bob = accounts.upsertUser(11, 'bob');
    const aliceCookie = 'a'.repeat(64), bobCookie = 'b'.repeat(64);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(aliceCookie, JSON.stringify({ userId: alice.id }), Date.now());
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(bobCookie, JSON.stringify({ userId: bob.id }), Date.now());
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const address = `http://127.0.0.1:${server.address().port}`;
    const send = (path, options = {}) => fetch(address + path, options);
    const input = { email: 'alice@example.com', productUpdates: true, userId: bob.id };
    assert.equal((await send('/api/account/email', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input) })).status, 401);
    assert.equal((await send('/api/account/email', { method: 'POST', headers: { cookie: `purple_session=${aliceCookie}`, origin: 'https://evil.test', 'content-type': 'application/json' }, body: JSON.stringify(input) })).status, 403);
    const saved = await send('/api/account/email', { method: 'POST', headers: { cookie: `purple_session=${aliceCookie}`, 'content-type': 'application/json' }, body: JSON.stringify(input) });
    assert.equal(saved.status, 200); assert.equal((await saved.json()).contact.email, 'alice@example.com');
    const state = await send('/api/state', { headers: { cookie: `purple_session=${bobCookie}` } }).then(r => r.json());
    assert.equal(state.contact.email, ''); assert.equal(JSON.stringify(state).includes('alice@example.com'), false);
    const ownState = await send('/api/state', { headers: { cookie: `purple_session=${aliceCookie}` } }).then(r => r.json());
    assert.equal(ownState.contact.email, 'alice@example.com');
    const removed = await send('/api/account/email', { method: 'DELETE', headers: { cookie: `purple_session=${aliceCookie}` } }).then(r => r.json());
    assert.equal(removed.contact.email, ''); assert.equal(removed.contact.productUpdates, false);
    const dismissed = await send('/api/account/email/dismiss', { method: 'POST', headers: { cookie: `purple_session=${bobCookie}` } }).then(r => r.json());
    assert.ok(dismissed.contact.dismissedAt);
  } finally {
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});
