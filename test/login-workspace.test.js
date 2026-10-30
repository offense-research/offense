import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createWorkerApp } from '../workers/app-api.js';
import { createAccounts } from '../server/accounts.js';

test('second GitHub login preserves connections added while installation lookup is in flight', async () => {
  const db = new DatabaseSync(':memory:');
  const originalFetch = globalThis.fetch;
  let server, finishLookup, lookupStarted;
  const started = new Promise(resolve => { lookupStarted = resolve; });
  const lookup = new Promise(resolve => { finishLookup = resolve; });
  try {
    const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://purple.test', ENCRYPTION_KEY: 'a'.repeat(64),
      GITHUB_APP_SLUG: 'purple', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret' }, schedule: () => {} });
    const accounts = createAccounts(db), user = accounts.upsertUser(98765, 'returning-customer');
    accounts.createWorkspace(user.id, 'customer-workspace', { company: 'Customer' });
    const sessionId = 'b'.repeat(64);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(sessionId, JSON.stringify({ userId: user.id, workspaceId: 'customer-workspace', githubLoginState: 'login-state', githubLoginStarted: Date.now() }), Date.now());
    globalThis.fetch = async (url, options) => {
      const address = String(url);
      if (address.includes('github.com/login/oauth/access_token')) return Response.json({ access_token: 'test-token' });
      if (address === 'https://api.github.com/user') return Response.json({ id: 98765, login: 'returning-customer' });
      if (address.startsWith('https://api.github.com/user/installations')) { lookupStarted(); return lookup; }
      return originalFetch(url, options);
    };
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    // A pre-existing session receives credit without another OAuth login.
    for (let attempt = 0; attempt < 2; attempt++) {
      const billingResponse = await originalFetch(`http://127.0.0.1:${server.address().port}/api/scanner-billing`, {
        headers: { cookie: `purple_session=${sessionId}` }
      });
      assert.equal(billingResponse.status, 200);
      const { billing } = await billingResponse.json();
      assert.equal(billing.welcomeCreditMicros, 5_000_000);
      assert.equal(billing.availableMicros, 5_000_000);
    }
    const response = originalFetch(`http://127.0.0.1:${server.address().port}/api/github/callback?state=login-state&code=test-code`, {
      headers: { cookie: `purple_session=${sessionId}` }, redirect: 'manual'
    });
    await started;
    accounts.updateWorkspace('customer-workspace', data => {
      data.cloudflare = { accessToken: 'encrypted-cf' }; data.openrouter = { secret: 'encrypted-or' };
      data.collectorInstall = { status: 'installed', sources: ['api', 'links'] };
    });
    finishLookup(Response.json({ installations: [] }));
    const result = await response;
    assert.equal(result.status, 302);
    assert.match(result.headers.get('location'), /signed_in=1/);
    const saved = JSON.parse(accounts.workspaceForUser(user.id).data);
    assert.equal(saved.cloudflare.accessToken, 'encrypted-cf');
    assert.equal(saved.openrouter.secret, 'encrypted-or');
    assert.deepEqual(saved.collectorInstall.sources, ['api', 'links']);
    assert.ok(saved.githubAuthorization.secret);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM memberships WHERE user_id = ?').get(user.id).count, 1);
    assert.equal(db.prepare('SELECT data FROM sessions WHERE id = ?').get(sessionId), undefined);
  } finally {
    globalThis.fetch = originalFetch;
    finishLookup?.(Response.json({ installations: [] }));
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});

test('first login automatically creates one named workspace and retains authorization even if discovery fails', async () => {
  const db = new DatabaseSync(':memory:');
  const originalFetch = globalThis.fetch;
  let server;
  try {
    const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://purple.test', ENCRYPTION_KEY: 'a'.repeat(64),
      GITHUB_APP_SLUG: 'purple', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret' }, schedule: () => {} });
    const sessionId = 'c'.repeat(64);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(sessionId, JSON.stringify({ githubLoginState: 'first-state', githubLoginStarted: Date.now() }), Date.now());
    globalThis.fetch = async (url, options) => {
      const address = String(url);
      if (address.includes('github.com/login/oauth/access_token')) return Response.json({ access_token: 'test-token' });
      if (address === 'https://api.github.com/user') return Response.json({ id: 98766, login: 'first-customer', email: 'founder@example.com' });
      if (address.startsWith('https://api.github.com/user/installations')) return Response.json({ message: 'Temporarily unavailable' }, { status: 503 });
      return originalFetch(url, options);
    };
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const address = `http://127.0.0.1:${server.address().port}`;
    const signedIn = await originalFetch(`${address}/api/github/callback?state=first-state&code=test-code`, {
      headers: { cookie: `purple_session=${sessionId}` }, redirect: 'manual'
    });
    assert.equal(signedIn.status, 302);
    const cookie = signedIn.headers.get('set-cookie').split(';')[0];
    const user = db.prepare('SELECT id FROM users WHERE github_id = ?').get('98766');
    const first = createAccounts(db).workspaceForUser(user.id);
    const pending = JSON.parse(first.data);
    assert.equal(pending.company, 'first-customer');
    const stateBeforeRename = await (await originalFetch(`${address}/api/state`, { headers: { cookie } })).json();
    assert.equal(stateBeforeRename.workspaceId, first.id);
    assert.equal(stateBeforeRename.company, 'first-customer');
    assert.equal(stateBeforeRename.contact.suggestedEmail, 'founder@example.com');
    assert.equal(stateBeforeRename.contact.email, '');
    assert.equal(stateBeforeRename.contact.productUpdates, false);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM memberships WHERE user_id = ?').get(user.id).count, 1);
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await originalFetch(`${address}/api/scanner-billing`, { headers: { cookie } });
      assert.equal(response.status, 200);
      const { billing } = await response.json();
      assert.equal(billing.welcomeCreditMicros, 5_000_000);
      assert.equal(billing.availableMicros, 5_000_000);
    }
    assert.ok(pending.githubAuthorization.secret);
    assert.equal(pending.githubAuthorization.userId, user.id);
    const created = await originalFetch(`${address}/api/company`, { method: 'POST',
      headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ company: 'First company' }) });
    assert.equal(created.status, 200);
    const state = await created.json();
    assert.ok(state.workspaceId);
    const workspace = JSON.parse(db.prepare('SELECT data FROM workspaces WHERE id = ?').get(state.workspaceId).data);
    assert.equal(workspace.githubAuthorization.secret, pending.githubAuthorization.secret);
    assert.equal(db.prepare('SELECT user_id FROM account_connections WHERE user_id = ?').get(user.id), undefined);
    assert.equal(JSON.stringify(state).includes(pending.githubAuthorization.secret), false);
  } finally {
    globalThis.fetch = originalFetch;
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});

test('Workers sign-in sends the User-Agent GitHub requires for OAuth, identity and installation requests', async () => {
  const db = new DatabaseSync(':memory:'), originalFetch = globalThis.fetch;
  let server;
  const calls = [];
  try {
    const { app } = createWorkerApp({ db, env: { PUBLIC_URL: 'https://purple.test', ENCRYPTION_KEY: 'a'.repeat(64),
      GITHUB_APP_SLUG: 'purple', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret' }, schedule: () => {} });
    const sessionId = 'd'.repeat(64);
    db.prepare('INSERT INTO sessions VALUES (?, ?, ?)').run(sessionId, JSON.stringify({ githubLoginState: 'ua-state', githubLoginStarted: Date.now() }), Date.now());
    globalThis.fetch = async (url, options) => {
      const address = String(url);
      if (new URL(address).hostname.endsWith('github.com')) {
        const headers = new Headers(options?.headers);
        calls.push({ path: new URL(address).pathname, userAgent: headers.get('user-agent') });
        // Cloudflare fetch supplies no default UA. Reproduce GitHub's actual
        // plain-text response, which previously became "Provider returned 403".
        if (!headers.get('user-agent')) return new Response('Request forbidden by administrative rules. Please make sure your request has a User-Agent header.', { status: 403 });
        if (address.includes('/login/oauth/access_token')) return Response.json({ access_token: 'fixture-token' });
        assert.equal(headers.get('authorization'), 'Bearer fixture-token');
        if (address.endsWith('/user')) return Response.json({ id: 98767, login: 'workers-customer' });
        if (address.includes('/user/installations')) return Response.json({ installations: [{ id: 123, app_slug: 'purple', account: { login: 'customer-org', type: 'Organization' } }] });
        throw new Error('Unexpected GitHub request');
      }
      return originalFetch(url, options);
    };
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    const response = await originalFetch(`${base}/api/github/callback?state=ua-state&code=fixture-code`, {
      headers: { cookie: `purple_session=${sessionId}` }, redirect: 'manual'
    });
    assert.equal(response.status, 302);
    assert.match(response.headers.get('location'), /signed_in=1/);
    assert.equal(calls.length, 3); assert.ok(calls.every(call => call.userAgent === 'purple'));
    const cookie = response.headers.get('set-cookie').split(';')[0];
    const state = await originalFetch(base + '/api/state', { headers: { cookie } }).then(r => r.json());
    assert.equal(state.user.login, 'workers-customer');
    const created = await originalFetch(base + '/api/company', { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ company: 'UA regression' }) }).then(r => r.json());
    assert.equal(created.github.account, 'customer-org'); assert.equal(created.cloudflare, null);
    assert.equal(db.prepare('SELECT data FROM sessions WHERE id = ?').get(sessionId), undefined);
  } finally {
    globalThis.fetch = originalFetch;
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});
