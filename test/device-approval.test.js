import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createAccounts } from '../server/accounts.js';
import { createCliAuth } from '../server/cli-auth.js';
import { DEVICE_PERMISSION_LABELS, validateDeviceApprovalRequest } from '../src/device-approval.js';

const CODE = 'ABCD-EFGH';
const NOW = Date.parse('2026-10-27T12:00:00Z');
const request = changes => ({ user_code: CODE, status: 'pending', expiresAt: NOW + 60_000,
  workspace: { id: 'account-one', name: 'First account' },
  scopes: Object.keys(DEVICE_PERMISSION_LABELS), ...changes });
const rejects = (data, expected) => assert.throws(() => validateDeviceApprovalRequest(data, CODE, NOW),
  error => error.code === expected);

test('actual backend inspection expires with a specific message instead of unsupported permissions', t => {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const accounts = createAccounts(db), user = accounts.upsertUser(1, 'fixture-owner');
  accounts.createWorkspace(user.id, 'account-one', { company: 'First account' });
  let clock = NOW, issued = 0;
  const auth = createCliAuth({ db, baseUrl: 'https://offense.test', now: () => clock,
    scans: { issueKey() { issued++; throw Error('Inspection must not issue a key.'); } } });
  const begin = auth.start();
  const principal = { userId: user.id, workspaceId: 'account-one' };
  const pending = auth.inspect(begin.user_code, principal);
  assert.equal(validateDeviceApprovalRequest(pending, begin.user_code, clock), pending);
  assert.equal(pending.status, 'pending');
  clock += begin.expires_in * 1000;
  const expired = auth.inspect(begin.user_code, principal);
  assert.equal(expired.status, 'expired');
  assert.throws(() => validateDeviceApprovalRequest(expired, begin.user_code, clock), error =>
    error.code === 'expired_token' && /This request expired/.test(error.message) && !/permissions/.test(error.message));
  assert.equal(issued, 0);
});

test('server-expired and elapsed responses never become consent requests', () => {
  rejects(request({ status: 'expired' }), 'expired_token');
  rejects(request({ expiresAt: NOW }), 'expired_token');
  rejects(request({ expiresAt: NOW - 1 }), 'expired_token');
  // Expired state still fails closed if other response fields are absent.
  rejects({ user_code: CODE, status: 'expired', expiresAt: NOW - 1 }, 'expired_token');
  rejects(request({ status: 'expired', scopes: ['admin:all'] }), 'expired_token');
});

test('only the exact supported permissions can enter the consent UI', () => {
  for (const scopes of [undefined, null, {}, 'tools:call account:read billing:checkout', [],
    ['tools:call', 'account:read'], ['tools:call', 'account:read', 'tools:call'],
    ['tools:call', 'account:read', 'admin:all'], [...Object.keys(DEVICE_PERMISSION_LABELS), 'admin:all'],
    ['tools:call', 'account:read', {}]]) rejects(request({ scopes }), 'unsupported_permissions');
  const reordered = request({ scopes: Object.keys(DEVICE_PERMISSION_LABELS).reverse() });
  assert.equal(validateDeviceApprovalRequest(reordered, CODE, NOW), reordered);
});

test('malformed response fields and mismatched codes do not blame the client permissions', () => {
  for (const data of [null, undefined, [], 'invalid']) rejects(data, 'invalid_request');
  rejects(request({ user_code: 'JKLM-NPQR' }), 'request_mismatch');
  for (const expiresAt of [undefined, null, String(NOW + 60_000), NaN, Infinity, NOW + 0.5, -1]) {
    rejects(request({ expiresAt }), 'invalid_request');
  }
  for (const workspace of [undefined, null, [], {}, { id: 42, name: 'Account' }, { id: '', name: 'Account' }, { id: 'account-one', name: 42 }]) {
    rejects(request({ workspace }), 'invalid_request');
  }
  rejects(request({ status: 'unknown' }), 'invalid_request');
});

test('known terminal states preserve their response and still require valid permissions', () => {
  for (const status of ['approved', 'denied']) {
    const data = request({ status });
    assert.equal(validateDeviceApprovalRequest(data, CODE, NOW), data);
    rejects(request({ status, scopes: ['admin:all'] }), 'unsupported_permissions');
  }
});
