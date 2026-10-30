import test from 'node:test';
import assert from 'node:assert/strict';
import { issueWebTargetChallenge, verifyWebTargetChallenge, webScanOrigin,
  webScanUrlInScope, publicWebScanAddress } from '../server/web-scan-target.js';

const key = Buffer.alloc(32, 7);
const now = () => 1_800_000_000_000;

test('web target proof binds workspace, exact origin, DNS TXT and public addresses', async () => {
  const challenge = issueWebTargetChallenge({ target: 'https://app.example.com/', workspaceId: 'ws_123', key, now,
    random: () => Buffer.alloc(24, 2) });
  const seen = [];
  const args = { challenge, workspaceId: 'ws_123', key, now,
    async resolveTxt(name) { seen.push(name); return [[challenge.recordValue.slice(0, 15), challenge.recordValue.slice(15)]]; },
    async resolveAddresses(name) { seen.push(name); return [{ address: '8.8.8.8' }, { address: '2606:4700:4700::1111' }]; } };
  const verified = await verifyWebTargetChallenge(args);
  assert.equal(verified.origin, 'https://app.example.com');
  assert.deepEqual(seen, ['_purple-scan.app.example.com', 'app.example.com']);
  assert.deepEqual(verified.addresses, ['8.8.8.8', '2606:4700:4700::1111']);
  await assert.rejects(verifyWebTargetChallenge({ ...args, workspaceId: 'ws_other' }), /invalid or expired/);
  await assert.rejects(verifyWebTargetChallenge({ ...args, now: () => challenge.expiresAt }), /invalid or expired/);
  await assert.rejects(verifyWebTargetChallenge({ ...args, challenge: { ...challenge, origin: 'https://other.example.com' } }), /invalid or expired/);
  await assert.rejects(verifyWebTargetChallenge({ ...args, resolveTxt: async () => [['wrong']] }), /does not publish/);
  await assert.rejects(verifyWebTargetChallenge({ ...args, resolveAddresses: async () => ['8.8.8.8', '127.0.0.1'] }), /public addresses/);
});

test('web target intake rejects local and ambiguous targets and scopes redirects to one origin', () => {
  assert.equal(webScanOrigin('https://EXAMPLE.com'), 'https://example.com');
  for (const target of ['http://example.com', 'https://localhost', 'https://127.0.0.1', 'https://[::1]',
    'https://example.local', 'https://example.com:444', 'https://user:pass@example.com',
    'https://example.com/private', 'https://example.com/?next=https://internal', 'https://example.com.#fragment']) {
    assert.throws(() => webScanOrigin(target), /public HTTPS origin/, target);
  }
  assert.equal(webScanUrlInScope('https://example.com/docs?a=1', 'https://example.com'), true);
  assert.equal(webScanUrlInScope('https://example.com.evil.org/', 'https://example.com'), false);
  assert.equal(webScanUrlInScope('http://example.com/', 'https://example.com'), false);
  assert.equal(webScanUrlInScope('https://example.com:444/', 'https://example.com'), false);
});

test('public IP filter rejects internal, documentation, transition and mapped addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(publicWebScanAddress(ip), true, ip);
  for (const ip of ['0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
    '172.16.1.1', '192.168.1.1', '192.0.2.1', '198.18.0.1', '198.51.100.2', '203.0.113.2',
    '224.0.0.1', '::1', 'fe80::1', 'fc00::1', '2001:db8::1', '2002::1', '::ffff:127.0.0.1',
    'fe80::1%eth0', 'not-an-ip']) assert.equal(publicWebScanAddress(ip), false, ip);
});
