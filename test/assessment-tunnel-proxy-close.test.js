import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { startAssessmentTunnelProxy } from '../agent/assessment-tunnel-proxy.mjs';

async function fixture(t, { drainTimeoutMs = 200, neverEnd = false, abortResponse = false, maxBytes } = {}) {
  const sockets = new Set(), timers = new Set(); let first = true, done;
  const completed = new Promise(resolve => { done = resolve; });
  const later = (action, delay) => { const timer = setTimeout(action, delay); timers.add(timer); };
  const gateway = http.createServer((request, response) => {
    response.writeHead(200); response.flushHeaders();
    response.once('close', () => done({ complete: response.writableFinished, at: Date.now() }));
    request.on('data', () => { if (first) { first = false; response.write('initial TLS record'); } });
    request.once('end', () => {
      later(() => response.write('late target TLS record'), 20);
      later(() => response.write('another late target TLS record'), 45);
      if (abortResponse) later(() => response.destroy(), 70);
      else if (!neverEnd) later(() => response.end('target TLS EOF'), 90);
    });
  }).listen(0, '127.0.0.1');
  gateway.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  await once(gateway, 'listening');
  const proxy = await startAssessmentTunnelProxy({ port: 0, drainTimeoutMs, ...(maxBytes ? { maxBytes } : {}),
    request: (options, callback) => http.request({ ...options, hostname: '127.0.0.1', port: gateway.address().port }, callback) });
  t.after(async () => { for (const timer of timers) clearTimeout(timer); await proxy.close(); for (const socket of sockets) socket.destroy(); await new Promise(resolve => gateway.close(resolve)); });
  return { proxy, completed };
}

async function client(proxy, mode) {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port: proxy.port, method: 'CONNECT', path: 'example.com:443' });
    request.on('error', reject);
    request.once('connect', (response, socket) => {
      assert.equal(response.statusCode, 200); let closedAt, bytes = '';
      socket.on('error', () => {});
      socket.on('data', chunk => {
        bytes += chunk;
        if (!closedAt) { closedAt = Date.now(); if (mode === 'close') { socket.destroy(); resolve({ closedAt }); } else socket.end(); }
      });
      socket.once('end', () => { socket.destroy(); resolve({ closedAt, bytes }); });
      socket.write('synthetic TLS client hello');
    });
    request.end();
  });
}

test('normal local TLS half-close preserves all delayed upstream response bytes', async t => {
  const f = await fixture(t);
  const result = await client(f.proxy, 'fin'), end = await f.completed;
  assert.equal(end.complete, true); assert.match(result.bytes, /initial TLS record.*late target TLS record.*target TLS EOF/);
});

test('a scanner closing after its TLS result drains a delayed HTTP response without aborting the gateway', async t => {
  const f = await fixture(t);
  await client(f.proxy, 'close'); assert.equal((await f.completed).complete, true);
});

test('a locally closed scanner cannot leave its gateway HTTP response draining indefinitely', async t => {
  const f = await fixture(t, { neverEnd: true, drainTimeoutMs: 120 });
  const started = await client(f.proxy, 'close'), end = await f.completed;
  assert.equal(end.complete, false); assert.ok(end.at - started.closedAt >= 100); assert.ok(end.at - started.closedAt < 1000);
});

test('a genuinely truncated upstream HTTP response remains an aborted connection', async t => {
  const f = await fixture(t, { abortResponse: true });
  await client(f.proxy, 'fin'); assert.equal((await f.completed).complete, false);
});

test('byte budget violations remain failures while a closed scanner response is draining', async t => {
  const f = await fixture(t, { maxBytes: 80 });
  await client(f.proxy, 'close'); assert.equal((await f.completed).complete, false);
});
