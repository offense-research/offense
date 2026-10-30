import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import worker from '../workers/fallback.js';

function fixture() {
  const requests = [];
  const response = new Response('internal app', { headers: { 'x-app': 'fixture' } });
  const env = { OFFENSE_APP: { fetch(request) { requests.push(request); return Promise.resolve(response); } } };
  return { requests, response, env };
}

test('the fallback forwards exact app pages and one optional trailing slash', async () => {
  const app = fixture();
  for (const path of ['/account', '/app', '/activity', '/usage', '/billing', '/device', '/login', '/metrics', '/skill', '/health', '/legacy']) {
    for (const suffix of ['', '/']) {
      const request = new Request(`https://offense.sh${path}${suffix}`);
      assert.equal(await worker.fetch(request, app.env), app.response, path + suffix);
      assert.equal(app.requests.at(-1), request);
    }
  }
  assert.equal(app.requests.length, 22);
});

test('API and asset namespaces and exact MCP endpoint use the internal service', async () => {
  const app = fixture();
  for (const path of ['/api/auth/github/callback', '/v1/account', '/assets/app.js', '/skills/offense/SKILL.md', '/mcp']) {
    assert.equal(await worker.fetch(new Request(`https://offense.sh${path}`), app.env), app.response, path);
  }
  assert.equal(app.requests.length, 5);
});

test('payment return queries do not widen path matching and are forwarded intact', async () => {
  const app = fixture();
  const request = new Request('https://offense.sh/account?payment=success&checkout_id=test-checkout');
  assert.equal(await worker.fetch(request, app.env), app.response);
  assert.equal(app.requests[0].url, request.url);
  const denied = await worker.fetch(new Request('https://offense.sh/account-evil?returnTo=/account'), app.env);
  assert.equal(denied.status, 404);
  assert.equal(app.requests.length, 1);
});

test('unlisted app-shaped paths and marketing misses never reach the app', async () => {
  const app = fixture();
  for (const path of ['/', '/legacy-evil', '/legacy/settings', '/activity-evil', '/activity/settings', '/usage//', '/admin', '/admin/users', '/account-evil', '/account/settings', '/account//', '/app-evil', '/mcp/', '/mcp-evil', '/api', '/api-evil', '/v1', '/v1-evil', '/skillz/setup', '/assets-evil/app.js', '/random-page']) {
    const response = await worker.fetch(new Request(`https://offense.sh${path}`), app.env);
    assert.equal(response.status, 404, path);
    assert.equal(await response.text(), 'Not found', path);
  }
  assert.equal(app.requests.length, 0);
});

test('host, authorization, cookies, method, and body go only to the configured service unchanged', async () => {
  const app = fixture();
  const request = new Request('https://www.offense.sh/api/cli/device/inspect?fixture=1', {
    method: 'POST',
    headers: { authorization: 'Bearer fixture-only', cookie: 'session=fixture-only', 'content-type': 'application/json' },
    body: JSON.stringify({ user_code: 'ABCD-EFGH' }),
  });
  const response = await worker.fetch(request, app.env);
  assert.equal(response, app.response);
  assert.equal(app.requests[0], request);
  assert.equal(request.url, 'https://www.offense.sh/api/cli/device/inspect?fixture=1');
  assert.equal(request.method, 'POST');
  assert.equal(request.headers.get('authorization'), 'Bearer fixture-only');
  assert.equal(request.headers.get('cookie'), 'session=fixture-only');
  assert.equal(request.bodyUsed, false);
  assert.deepEqual(await app.requests[0].json(), { user_code: 'ABCD-EFGH' });
  assert.equal(app.requests.length, 1);
});

test('configuration keeps static assets first and binds only the existing app service', () => {
  const config = JSON.parse(readFileSync(new URL('../wrangler.jsonc', import.meta.url), 'utf8'));
  assert.notEqual(config.assets.run_worker_first, true);
  assert.equal(config.assets.not_found_handling, 'none');
  assert.deepEqual(config.services, [{ binding: 'OFFENSE_APP', service: 'purple-app' }]);
  // The source-release example has no operator account or production routes.
  if (config.routes) assert.deepEqual(config.routes.map(route => route.pattern), ['offense.sh/*', 'www.offense.sh/*']);
  assert.equal(config.assets.directory, './dist');
  const example = JSON.parse(readFileSync(new URL('../wrangler.example.jsonc', import.meta.url), 'utf8'));
  assert.equal(example.account_id, undefined);
  assert.equal(example.routes, undefined);
  assert.deepEqual(example.services, config.services);
});
