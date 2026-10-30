import test from 'node:test';
import assert from 'node:assert/strict';
import { createCloudflareAuth } from '../server/cloudflare-auth.js';

test('expired Cloudflare access rotates once and persists refreshed credentials for concurrent requests', async () => {
  let requests = 0, saves = 0;
  const auth = createCloudflareAuth({ clientId: 'client', clientSecret: 'secret', encrypt: value => `encrypted:${value}`,
    decrypt: value => value.slice(10), fetchImpl: async (_url, options) => {
      requests++;
      assert.equal(options.body.get('grant_type'), 'refresh_token');
      assert.equal(options.body.get('refresh_token'), 'old-refresh');
      await new Promise(resolve => setTimeout(resolve, 5));
      return Response.json({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600 });
    } });
  const a = { accessToken: 'encrypted:old', refreshToken: 'encrypted:old-refresh', expiresAt: 1 }, b = { ...a };
  assert.deepEqual(await Promise.all([auth.accessToken('workspace', a, () => saves++), auth.accessToken('workspace', b, () => saves++)]), ['fresh-access', 'fresh-access']);
  assert.equal(requests, 1); assert.equal(saves, 2);
  assert.equal(a.refreshToken, 'encrypted:fresh-refresh'); assert.deepEqual(a, b);
  assert.equal(await auth.accessToken('workspace', a, () => saves++), 'fresh-access');
  assert.equal(requests, 1);
});

test('a rejected Cloudflare refresh preserves the saved connection and asks for reauthorization', async () => {
  const connection = { accessToken: 'old', refreshToken: 'old-refresh', expiresAt: 1 };
  const auth = createCloudflareAuth({ encrypt: value => value, decrypt: value => value,
    fetchImpl: async () => Response.json({ error: 'invalid_grant' }, { status: 400 }) });
  await assert.rejects(auth.accessToken('workspace', connection, () => assert.fail('must not overwrite credentials')), /Reconnect Cloudflare/);
  assert.deepEqual(connection, { accessToken: 'old', refreshToken: 'old-refresh', expiresAt: 1 });
});
