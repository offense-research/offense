import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readFile } from 'node:fs/promises';
import { assetBody, staticAssetResponse } from '../workers/static-assets.js';

test('packaged compressed scripts and uncompressed binary assets return their original bytes', async () => {
  const sources = [Buffer.from([0, 1, 127, 128, 255]), Buffer.from('Purple ✳ hello\n'),
    await readFile(new URL('../public/skills/purple/scripts/syntax.mjs', import.meta.url))];
  for (const original of sources) {
    for (const encoded of [original.toString('base64'), { gzip: gzipSync(original).toString('base64') }]) {
      const response = new Response(assetBody(encoded));
      assert.equal(response.headers.get('content-encoding'), null);
      assert.ok(Buffer.from(await response.arrayBuffer()).equals(original));
    }
  }
});

test('skill release manifests have JSON MIME and bypass stale shared-cache responses', async () => {
  const bytes = await readFile(new URL('../public/skills/offense/manifest.json', import.meta.url));
  const assets = { '/index.html': Buffer.from('<html/>').toString('base64'), '/skills/offense/manifest.json': { gzip: gzipSync(bytes).toString('base64') } };
  const response = staticAssetResponse(assets, '/skills/offense/manifest.json', new Request('https://purple.test/skills/offense/manifest.json'));
  assert.equal(response.status, 200); assert.match(response.headers.get('content-type'), /^application\/json/);
  assert.equal(response.headers.get('cache-control'), 'no-store'); assert.ok(Buffer.from(await response.arrayBuffer()).equals(bytes));
});

test('SDK downloads return original archive bytes, download headers and bounded caching', async () => {
  const archive = Buffer.from([31, 139, 8, 0, 255, 1]);
  const assets = { '/index.html': Buffer.from('<html/>').toString('base64'), '/downloads/offense-sdk.tgz': archive.toString('base64'),
    '/downloads/offense-automation.mjs': Buffer.from('console.log("ready")').toString('base64') };
  for (const [file, mime] of [['offense-sdk.tgz', 'application/gzip'], ['offense-automation.mjs', 'application/javascript']]) {
    const response = staticAssetResponse(assets, `/downloads/${file}`, new Request(`https://purple.test/downloads/${file}`));
    assert.equal(response.status, 200); assert.ok(response.headers.get('content-type').startsWith(mime));
    assert.equal(response.headers.get('content-disposition'), `attachment; filename="${file}"`);
    assert.equal(response.headers.get('cache-control'), 'public, max-age=300');
    if (file.endsWith('.tgz')) assert.deepEqual(Buffer.from(await response.arrayBuffer()), archive);
  }
  assert.equal(staticAssetResponse(assets, '/downloads/missing.mjs', new Request('https://purple.test/downloads/missing.mjs')).status, 404);
});

test('public video supports full, bounded, suffix and open-ended playback ranges', async () => {
  const original = Buffer.from('0123456789');
  const assets = { '/index.html': Buffer.from('<html/>').toString('base64'), '/share/demo.mp4': original.toString('base64') };
  for (const [range, status, content, expectedRange] of [
    [null, 200, '0123456789', null], ['bytes=2-5', 206, '2345', 'bytes 2-5/10'],
    ['bytes=7-', 206, '789', 'bytes 7-9/10'], ['bytes=-3', 206, '789', 'bytes 7-9/10'],
    ['bytes=0-999', 206, '0123456789', 'bytes 0-9/10']
  ]) {
    const response = staticAssetResponse(assets, '/share/demo.mp4', new Request('https://purple.test/share/demo.mp4', { headers: range ? { range } : {} }));
    assert.equal(response.status, status); assert.equal(response.headers.get('content-type'), 'video/mp4');
    assert.equal(response.headers.get('content-range'), expectedRange);
    assert.equal(response.headers.get('accept-ranges'), 'bytes');
    assert.equal(Number(response.headers.get('content-length')), content.length);
    assert.equal(await response.text(), content);
  }
  const head = staticAssetResponse(assets, '/share/demo.mp4', new Request('https://purple.test/share/demo.mp4', { method: 'HEAD', headers: { range: 'bytes=2-5' } }));
  assert.equal(head.status, 200); assert.equal(head.headers.get('content-length'), '10'); assert.equal(await head.text(), '');
});

test('invalid video ranges and missing share media never return the app HTML', async () => {
  const assets = { '/index.html': Buffer.from('<html/>').toString('base64'), '/share/demo.mp4': Buffer.from('0123456789').toString('base64') };
  for (const range of ['bytes=99-', 'bytes=5-2', 'bytes=-0', 'bytes=-', 'bytes=0-1,4-5', 'nonsense']) {
    const response = staticAssetResponse(assets, '/share/demo.mp4', new Request('https://purple.test/share/demo.mp4', { headers: { range } }));
    assert.equal(response.status, 416, range); assert.equal(response.headers.get('content-range'), 'bytes */10');
  }
  assert.equal(staticAssetResponse(assets, '/share/missing.mp4', new Request('https://purple.test/share/missing.mp4')).status, 404);
  const app = staticAssetResponse(assets, '/skill', new Request('https://purple.test/skill'));
  assert.equal(app.status, 200); assert.match(app.headers.get('content-type'), /text\/html/); assert.equal(await app.text(), '<html/>');
});
