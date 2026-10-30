import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, lstat, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { once } from 'node:events';
import express from 'express';
import { createOffenseCli } from '../scripts/offense-cli.mjs';
import { createAccounts } from '../server/accounts.js';
import { createHostedScans } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createScanWhopBilling } from '../server/scan-whop-billing.js';
import { createCliAuth, registerCliAuthPublic, registerCliAuthBrowser } from '../server/cli-auth.js';
import { createToolGateway, registerOffensePlatform } from '../server/offense-platform.js';

async function fixture(t, { manualApproval = false } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-cli-auth-real-'));
  const db = new DatabaseSync(':memory:'), accounts = createAccounts(db);
  const user = accounts.upsertUser(424242, 'synthetic-owner');
  accounts.createWorkspace(user.id, 'synthetic-account', { company: 'Synthetic account' });
  const meter = createScanMetering(db);
  const scans = createHostedScans(db, { metering: meter });
  const app = express(), server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  let clock = Date.now(), device, approved = false, approvalRequests = 0;
  const auth = createCliAuth({ db, scans, baseUrl: base, now: () => clock });
  const billing = createScanWhopBilling(db, { meter, enabled: false, publicUrl: base,
    provider: { checkout() { throw Error('No payment provider may be called by authentication tests.'); }, payment() { throw Error('No payment provider may be called by authentication tests.'); } } });
  const gateway = createToolGateway({ scans, billing, accounts, baseUrl: base });
  const routes = [], stdout = [], stderr = [], opened = [];
  app.use((req, res, next) => { routes.push(req.path); next(); });
  registerCliAuthPublic(app, { auth });
  registerOffensePlatform(app, { gateway, scans, billing, baseUrl: base });
  // A synthetic signed-in browser fixture, never a production cookie or login.
  app.use((req, res, next) => {
    if (req.get('cookie') === 'offense_fixture_session=synthetic-browser') {
      req.authUser = user; req.workspaceId = 'synthetic-account';
    }
    next();
  });
  registerCliAuthBrowser(app, { auth });
  async function approveFromBrowser(address) {
    const url = new URL(address);
    assert.equal(url.origin, base); assert.equal(url.pathname, '/device'); assert.equal(url.search, '');
    const code = new URLSearchParams(url.hash.slice(1)).get('code');
    assert.equal(code, device.user_code);
    assert.ok(!address.includes(device.device_code), 'The secret polling code must never enter a browser URL.');
    const post = (route, body) => fetch(base + route, { method: 'POST', headers: {
      'content-type': 'application/json', origin: base, cookie: 'offense_fixture_session=synthetic-browser'
    }, body: JSON.stringify(body) });
    const inspected = await post('/api/cli/device/inspect', { user_code: code });
    assert.equal(inspected.status, 200);
    assert.equal((await inspected.json()).workspace.id, 'synthetic-account');
    const approval = await post('/api/cli/device/approve', { user_code: code, approved: true });
    assert.equal(approval.status, 200);
    const body = await approval.json(); assert.equal(body.status, 'approved');
    assert.equal(body.workspace.id, 'synthetic-account'); assert.equal(body.access_token, undefined);
    approved = true; approvalRequests++;
  }
  const cli = createOffenseCli({ env: { OFFENSE_CONFIG_DIR: directory, OFFENSE_API_URL: base },
    fetchImpl: async (url, request) => {
      const response = await fetch(url, request);
      const route = new URL(url).pathname;
      if (route === '/v1/auth/device' && response.ok) device = await response.clone().json();
      if (manualApproval && !approved && route === '/v1/auth/device/token') {
        assert.equal(response.status, 400);
        assert.equal((await response.clone().json()).error, 'authorization_pending');
        await approveFromBrowser(device.verification_uri_complete);
      }
      return response;
    },
    output: value => stdout.push(value), diagnostic: value => stderr.push(value),
    sleep: async ms => { clock += ms; }, now: () => clock,
    openBrowser: async url => { assert.equal(manualApproval, false); opened.push(url); await approveFromBrowser(url); }
  });
  return { cli, db, scans, directory, base, routes, stdout, stderr, opened,
    get device() { return device; }, get approvalRequests() { return approvalRequests; },
    result: () => JSON.parse(stdout.at(-1)), config: async () => JSON.parse(await readFile(path.join(directory, 'config.json'), 'utf8')) };
}

test('real CLI login accepts the backend fragment URL, saves the issued key privately and authenticates whoami', async t => {
  const f = await fixture(t);
  assert.equal(await f.cli.run(['login']), 0);
  assert.equal(f.opened.length, 1); assert.equal(f.approvalRequests, 1);
  assert.ok(f.opened[0].includes('#code='));
  assert.equal(f.result().signedIn, true);
  const cfg = await f.config();
  assert.equal(cfg.endpoint, f.base); assert.match(cfg.apiKey, /^offense_sk_[a-f0-9]{64}$/);
  const principal = f.scans.authenticate(cfg.apiKey);
  assert.equal(principal.workspace_id, 'synthetic-account'); assert.equal(principal.id, cfg.keyId);
  assert.equal((await lstat(f.directory)).mode & 0o077, 0);
  assert.equal((await lstat(path.join(f.directory, 'config.json'))).mode & 0o077, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_keys').get().n, 1);
  assert.equal(f.db.prepare('SELECT status FROM cli_auth_devices').get().status, 'consumed');
  assert.equal(await f.cli.run(['whoami']), 0);
  assert.equal(f.result().signedIn, true); assert.equal(f.result().account.workspace.id, 'synthetic-account');
  assert.equal(f.result().account.user.login, 'synthetic-owner');
  assert.ok(f.routes.includes('/v1/account'));
  for (const secret of [cfg.apiKey, f.device.device_code]) {
    assert.ok(!(f.stdout.join('') + f.stderr.join('')).includes(secret));
    assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM cli_auth_devices').all()).includes(secret));
    assert.ok(!JSON.stringify(f.db.prepare('SELECT * FROM scan_keys').all()).includes(secret));
  }
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_jobs').get().n, 0);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_wallet_entries').get().n, 0);
});

test('real no-browser login handles authorization_pending, then uses the same backend key and respects revocation', async t => {
  const f = await fixture(t, { manualApproval: true });
  assert.equal(await f.cli.run(['login', '--no-browser']), 0);
  assert.equal(f.opened.length, 0); assert.equal(f.approvalRequests, 1);
  assert.equal(f.routes.filter(route => route === '/v1/auth/device/token').length, 2);
  const cfg = await f.config();
  assert.equal(await f.cli.run(['whoami']), 0);
  assert.equal(f.result().account.workspace.id, 'synthetic-account');
  f.db.prepare('UPDATE scan_keys SET revoked_at = ? WHERE id = ?').run(Date.now(), cfg.keyId);
  assert.equal(await f.cli.run(['whoami']), 1);
  const error = JSON.parse(f.stderr.at(-1));
  assert.equal(error.error.status, 401);
  assert.ok(!(f.stdout.join('') + f.stderr.join('')).includes(cfg.apiKey));
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_keys').get().n, 1);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_jobs').get().n, 0);
});
