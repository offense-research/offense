import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { once } from 'node:events';
import { createWorkerApp } from '../workers/app-api.js';

test('GitHub sign-in returns to billing without requiring repository installation and rejects external destinations', async () => {
  const db = new DatabaseSync(':memory:'), originalFetch = globalThis.fetch;
  let server;
  try {
    const { app } = createWorkerApp({ db, env: {
      PUBLIC_URL: 'https://purple.test', ENCRYPTION_KEY: 'a'.repeat(64),
      GITHUB_APP_SLUG: 'purple', GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret'
    }, schedule: () => {} });
    globalThis.fetch = async (url, options) => {
      if (String(url).includes('github.com/login/oauth/access_token')) return Response.json({ access_token: 'fixture-token' });
      if (String(url) === 'https://api.github.com/user') return Response.json({ id: 123456, login: 'billing-customer' });
      if (String(url).startsWith('https://api.github.com/user/installations')) return Response.json({ installations: [] });
      return originalFetch(url, options);
    };
    server = app.listen(0, '127.0.0.1'); await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const destination of ['/billing', '/activity', '/usage', '/metrics', '/legacy', 'https://attacker.example/', '//attacker.example/', '/billing?next=https://attacker.example/']) {
      const started = await originalFetch(`${base}/api/auth/github/start?returnTo=${encodeURIComponent(destination)}`, { redirect: 'manual' });
      assert.equal(started.status, 302);
      const state = new URL(started.headers.get('location')).searchParams.get('state');
      const signedIn = await originalFetch(`${base}/api/github/callback?state=${state}&code=fixture-code`, {
        headers: { cookie: started.headers.get('set-cookie').split(';')[0] }, redirect: 'manual'
      });
      assert.equal(signedIn.status, 302);
      assert.equal(signedIn.headers.get('location'), ['/billing', '/activity', '/usage', '/metrics', '/legacy'].includes(destination) ? destination : '/?signed_in=1');
      const cookie = signedIn.headers.get('set-cookie').split(';')[0];
      const account = await originalFetch(`${base}/api/state`, { headers: { cookie } }).then(r => r.json());
      assert.equal(account.user.login, 'billing-customer');
      assert.ok(account.workspaceId);
      assert.equal(account.github, null);
      const billing = await originalFetch(`${base}/api/scanner-billing`, { headers: { cookie } });
      assert.equal(billing.status, 200);
      assert.equal(typeof (await billing.json()).billing.balanceMicros, 'number');
    }
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM workspaces').get().n, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (server) await new Promise(resolve => server.close(resolve));
    db.close();
  }
});
