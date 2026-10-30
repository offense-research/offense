import test from 'node:test';
import assert from 'node:assert/strict';
import { legacyClientAsset } from '../workers/client-assets.js';

test('legacy public downloads retain bytes and never forward credentials or query secrets', async () => {
  let calls = 0;
  const result = await legacyClientAsset(new Request('https://app.purpleteam.sh/skills/offense/scripts/cli.mjs?token=PRIVATE', {
    headers: { authorization: 'Bearer PRIVATE', cookie: 'purple_session=PRIVATE', origin: 'https://app.purpleteam.sh' }
  }), async (url, options) => {
    calls++;
    assert.equal(url.href, 'https://offense.sh/skills/offense/scripts/cli.mjs');
    assert.equal([...options.headers].length, 0);
    assert.equal(options.redirect, 'manual');
    return new Response('exact client bytes', { headers: { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=300' } });
  });
  assert.equal(await result.text(), 'exact client bytes');
  assert.equal(calls, 1);
});

test('canonical missing routes cannot loop, non-assets cannot proxy, and media retains range requests', async () => {
  const forbidden = () => { throw Error('Unexpected request'); };
  for (const url of ['https://offense.sh/downloads/missing.tgz', 'https://app.purpleteam.sh/api/state'])
    assert.equal((await legacyClientAsset(new Request(url), forbidden)).status, 404);
  const response = await legacyClientAsset(new Request('https://app.purpleteam.sh/share/preview.mp4', {
    headers: { range: 'bytes=0-9', authorization: 'Bearer PRIVATE' }
  }), async (url, options) => {
    assert.equal(url.origin, 'https://offense.sh');
    assert.deepEqual([...options.headers], [['range', 'bytes=0-9']]);
    return new Response('0123456789', { status: 206 });
  });
  assert.equal(response.status, 206);
});
