import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));

// Resolve through Miniflare so these checks cover the client used by Wrangler,
// including a nested installation instead of an unrelated root Undici copy.
const setup = String.raw`
  import assert from 'node:assert/strict';
  import { createRequire } from 'node:module';
  import { once } from 'node:events';
  const require = createRequire(import.meta.url);
  const miniflareRequire = createRequire(require.resolve('miniflare'));
  const { Client, fetch } = miniflareRequire('undici');
`;

function runIsolated(source) {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', setup + source], {
    cwd: projectRoot,
    encoding: 'utf8',
    timeout: 8_000,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test('Miniflare fetch survives an early close after rejecting excessive encodings', () => {
  runIsolated(String.raw`
    import { createServer } from 'node:net';
    let resolveClosed;
    const maliciousSocketClosed = new Promise(resolve => { resolveClosed = resolve; });
    const server = createServer(socket => {
      socket.once('data', request => {
        if (request.toString().startsWith('GET /normal ')) {
          socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
        } else {
          socket.once('close', resolveClosed);
          socket.end('HTTP/1.1 200 OK\r\nContent-Encoding: gzip, gzip, gzip, gzip, gzip, gzip\r\nContent-Length: 1\r\nConnection: close\r\n\r\n');
        }
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = 'http://127.0.0.1:' + server.address().port;
    const client = new Client(origin);
    try {
      assert.equal(await (await fetch(origin + '/normal', { dispatcher: client })).text(), 'ok');
      await assert.rejects(fetch(origin + '/attack', { dispatcher: client }), error => {
        assert.match(error.cause?.message ?? '', /content-encoding/);
        return true;
      });
      await maliciousSocketClosed;
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(await (await fetch(origin + '/normal', { dispatcher: client })).text(), 'ok');
    } finally {
      await client.close();
      await new Promise(resolve => server.close(resolve));
    }
  `);
});

test('Miniflare fetch rejects tampered responses with mixed-case integrity algorithms', () => {
  runIsolated(String.raw`
    import { createServer } from 'node:http';
    import { createHash } from 'node:crypto';
    const original = 'expected content';
    const digest = createHash('sha256').update(original).digest('base64');
    const server = createServer((request, response) => {
      response.end(request.url === '/normal' ? original : 'tampered content');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const origin = 'http://127.0.0.1:' + server.address().port;
    const client = new Client(origin);
    try {
      for (const algorithm of ['sha256', 'SHA256', 'Sha256']) {
        const integrity = algorithm + '-' + digest;
        const response = await fetch(origin + '/normal', { dispatcher: client, integrity });
        assert.equal(await response.text(), original);
        await assert.rejects(fetch(origin + '/attack', { dispatcher: client, integrity }), error => {
          assert.match(error.cause?.message ?? '', /integrity mismatch/);
          return true;
        });
      }
    } finally {
      await client.close();
      await new Promise(resolve => server.close(resolve));
    }
  `);
});

test('Miniflare dispatches normal Worker requests with its resolved HTTP client', () => {
  runIsolated(String.raw`
    import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
    const options = convertV4MiniflareOptions({ workers: [{
      name: 'undici-security-smoke',
      compatibilityDate: '2026-10-19',
      modules: true,
      script: 'export default {async fetch(request) {return Response.json({method:request.method,path:new URL(request.url).pathname,body:await request.text()})}}',
    }] });
    options.telemetry = { enabled: false };
    const miniflare = new Miniflare(options);
    try {
      const get = await miniflare.dispatchFetch('http://worker.test/health');
      assert.equal(get.status, 200);
      assert.deepEqual(await get.json(), { method: 'GET', path: '/health', body: '' });
      const post = await miniflare.dispatchFetch('http://worker.test/echo', {
        method: 'POST', body: 'normal request',
      });
      assert.equal(post.status, 200);
      assert.deepEqual(await post.json(), { method: 'POST', path: '/echo', body: 'normal request' });
    } finally {
      await miniflare.dispose();
    }
  `);
});
