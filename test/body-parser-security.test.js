import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Keep a decoder's uncaught error inside a disposable process, so this
// regression detects a process crash without taking down the test runner.
const scenario = String.raw`
  import assert from 'node:assert/strict';
  import http from 'node:http';
  import { once } from 'node:events';
  import { gzipSync, deflateSync } from 'node:zlib';
  import express from 'express';

  const [encoding, attack] = process.argv.slice(1);
  const expected = { message: 'compressed requests still work' };
  const compress = encoding === 'gzip' ? gzipSync : deflateSync;
  const frame = compress(Buffer.from(JSON.stringify(expected)));
  const suffix = attack === 'trailing' ? Buffer.concat([
    Buffer.of(0), Buffer.alloc(100 * 1024, 0x58)
  ]) : Buffer.alloc(0);
  const app = express();
  app.use(express.json());
  app.post('/', (req, res) => {
    assert.deepEqual(req.body, expected);
    process.stdout.write('decoded-valid-frame\n');
    res.json(req.body);
  });
  app.get('/health', (_req, res) => res.end('healthy'));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  process.stdout.write('local-server-ready\n');
  const port = server.address().port;

  try {
    const response = await new Promise((resolve, reject) => {
      const request = http.request({ host: '127.0.0.1', port, path: '/',
        method: 'POST', agent: false,
        headers: { 'content-type': 'application/json',
          'content-encoding': encoding, 'content-length': frame.length + suffix.length }
      }, response => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', chunk => { body += chunk; });
        response.on('error', reject);
        response.on('end', () => resolve({ status: response.statusCode, body }));
      });
      request.on('error', reject);
      request.setTimeout(2000, () => request.destroy(new Error('request timeout')));
      request.end(Buffer.concat([frame, suffix]));
    });
    assert.equal(response.status, 200);
    assert.deepEqual(JSON.parse(response.body), expected);
    // Allow errors from the finished decoder to surface before checking liveness.
    await new Promise(resolve => setTimeout(resolve, 150));
    const health = await fetch('http://127.0.0.1:' + port + '/health');
    assert.equal(await health.text(), 'healthy');
    process.stdout.write('survived-and-served-health-check\n');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
`;

for (const encoding of ['gzip', 'deflate']) {
  for (const mode of ['valid', 'trailing']) {
    test(`compressed JSON (${encoding}, ${mode}) keeps the HTTP process alive`, () => {
      const child = spawnSync(process.execPath, ['--input-type=module', '-e', scenario, encoding, mode], {
        cwd: new URL('..', import.meta.url), encoding: 'utf8', timeout: 8000,
      });
      assert.ifError(child.error);
      assert.match(child.stdout, /local-server-ready/, `fixture did not start: ${child.stderr}`);
      assert.equal(child.status, 0,
        `HTTP process failed after ${mode} ${encoding} request:\n${child.stdout}\n${child.stderr}`);
      assert.match(child.stdout, /decoded-valid-frame/);
      assert.match(child.stdout, /survived-and-served-health-check/);
    });
  }
}
