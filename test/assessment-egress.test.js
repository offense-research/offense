import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { once } from 'node:events';
import { signAssessmentTunnel, verifyAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { assessmentNetworkPolicy, assessmentDestination } from '../workers/assessment-egress.js';
import { startAssessmentEgressGateway } from '../server/assessment-egress-gateway.mjs';
import { startAssessmentTunnelProxy } from '../agent/assessment-tunnel-proxy.mjs';

const key = 'independent-assessment-key-'.repeat(3);

test('egress capabilities bind exact public IP, port and expiry and reject tampering', () => {
  const now = () => 1_800_000_000_000;
  const token = signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key, now);
  assert.equal(verifyAssessmentTunnel(token, key, now).address, '8.8.8.8');
  assert.throws(() => verifyAssessmentTunnel(token, key + 'wrong', now), /Unauthorized/);
  assert.throws(() => verifyAssessmentTunnel(token, key, () => now() + 30001), /Unauthorized/);
  assert.throws(() => verifyAssessmentTunnel(token.replace('example', 'other') + 'x', key, now), /Unauthorized/);
  for (const address of ['127.0.0.1', '169.254.169.254', '::1', '10.1.2.3'])
    assert.throws(() => signAssessmentTunnel({ host: 'example.com', address }, key, now));
});

test('target network scope pins verified IPs while provider scope admits only fixed APIs', async () => {
  const policy = assessmentNetworkPolicy({ tool: 'nuclei', options: { target: 'https://example.com', resolvedAddresses: ['8.8.8.8'] } });
  assert.equal(await assessmentDestination(policy, 'example.com', { resolveAddresses() { assert.fail('Pinned addresses must not be re-resolved.'); } }), '8.8.8.8');
  await assert.rejects(assessmentDestination(policy, 'example.com.evil.org'), /outside/);
  await assert.rejects(assessmentDestination({ ...policy, expiresAt: 1 }, 'example.com'), /outside/);
  assert.throws(() => assessmentNetworkPolicy({ tool: 'nuclei', options: { target: 'https://example.com', resolvedAddresses: ['127.0.0.1'] } }), /addresses/);
  const cloud = assessmentNetworkPolicy({ tool: 'prowler-cloudflare' });
  await assert.rejects(assessmentDestination(cloud, 'evil.org'), /outside/);
  await assert.rejects(assessmentDestination(cloud, 'api.cloudflare.com', { resolveAddresses: async () => ['8.8.8.8', '10.0.0.1'] }), /public IPs/);
});

test('gateway authenticates before dialing, rejects replay, and dials literal approved IP', async t => {
  let calls = 0;
  const echo = net.createServer(socket => socket.pipe(socket)); echo.listen(0, '127.0.0.1'); await once(echo, 'listening');
  t.after(() => echo.close());
  const gateway = await startAssessmentEgressGateway({ key, port: 0, connect: options => {
    calls++; assert.deepEqual(options, { host: '8.8.8.8', port: 443, family: 4 });
    return net.connect({ host: '127.0.0.1', port: echo.address().port });
  } }); t.after(() => gateway.close());
  const url = `http://127.0.0.1:${gateway.port}/tunnel`;
  assert.equal((await fetch(url, { method: 'POST', body: 'invalid' })).status, 404); assert.equal(calls, 0);
  assert.equal((await fetch(url, { method: 'POST', headers: { 'x-purple-egress-authorization': 'bad' }, body: 'invalid' })).status, 403);
  const token = signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key);
  const body = await new Promise((resolve, reject) => {
    const req = http.request(url, { method: 'POST', headers: { 'x-purple-egress-authorization': token } }, res => {
      let received = '';
      res.on('data', chunk => { received += chunk; if (received === 'duplex-test') { resolve(received); req.destroy(); res.destroy(); } });
      res.on('error', () => {});
      // The response headers must arrive before the request body is finished.
      req.write('duplex-test');
    });
    req.on('error', error => { if (error.code !== 'ECONNRESET') reject(error); });
    req.flushHeaders();
  });
  assert.equal(body, 'duplex-test'); assert.equal(calls, 1);
  assert.equal((await fetch(url, { method: 'POST', headers: { 'x-purple-egress-authorization': token }, body: 'replay' })).status, 403);
});

test('isolated proxy passes CONNECT through fixed gateway and blocks other ports and plain HTTP', async t => {
  const seen = [], sockets = new Set();
  const gateway = http.createServer((req, res) => {
    assert.equal(req.url, '/tunnel'); seen.push(req.headers['x-purple-target-host']);
    res.writeHead(200); res.flushHeaders(); req.pipe(res);
  }); gateway.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  gateway.listen(0, '127.0.0.1'); await once(gateway, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); gateway.close(); });
  const proxy = await startAssessmentTunnelProxy({ port: 0, request: (options, callback) => {
    assert.equal(options.hostname, 'purple-assessment-egress.invalid');
    return http.request({ ...options, hostname: '127.0.0.1', port: gateway.address().port }, callback);
  } }); t.after(() => proxy.close());
  const result = await new Promise((resolve, reject) => {
    const client = http.request({ hostname: '127.0.0.1', port: proxy.port, method: 'CONNECT', path: 'example.com:443' });
    client.on('connect', (response, socket) => {
      assert.equal(response.statusCode, 200);
      socket.on('data', bytes => { resolve(bytes.toString()); socket.destroy(); }); socket.write('opaque-tls-fixture');
    }); client.on('error', reject); client.end();
  });
  assert.equal(result, 'opaque-tls-fixture'); assert.deepEqual(seen, ['example.com']);
  const response = await fetch(`http://127.0.0.1:${proxy.port}/test`); assert.equal(response.status, 403);
  const denied = await new Promise((resolve, reject) => {
    const client = http.request({ hostname: '127.0.0.1', port: proxy.port, method: 'CONNECT', path: 'example.com:22' });
    client.on('connect', response => resolve(response.statusCode)); client.on('error', reject); client.end();
  }); assert.equal(denied, 403); assert.deepEqual(seen, ['example.com']);
});

test('gateway preserves a complete large response through graceful upstream EOF', async t => {
  const sockets = new Set(), expected = Buffer.alloc(256 * 1024, 'x');
  const origin = net.createServer(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {}); socket.resume(); socket.end(expected);
  }).listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); origin.close(); });
  const gateway = await startAssessmentEgressGateway({ key, port: 0,
    connect: () => net.connect(origin.address().port, '127.0.0.1') });
  t.after(() => gateway.close());
  const response = await fetch(`http://127.0.0.1:${gateway.port}/tunnel`, { method: 'POST', body: 'fixture',
    headers: { 'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key) } });
  assert.equal(response.status, 200);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), expected);
});

async function peerTermination(t, { reset, alert }) {
  const sockets = new Set(), expected = alert ? Buffer.from([21, 3, 3, 0, 2, 2, 70]) : Buffer.alloc(0);
  let rejectProbe;
  const origin = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket));
    socket.once('data', () => {
      if (reset) {
        if (alert) { socket.write(expected); rejectProbe = () => socket.resetAndDestroy(); }
        else socket.resetAndDestroy();
      } else socket.end(expected);
    });
  }).listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); origin.close(); });
  const gateway = await startAssessmentEgressGateway({ key, port: 0,
    connect: () => net.connect(origin.address().port, '127.0.0.1') });
  t.after(() => gateway.close());
  const actual = await new Promise((resolve, reject) => {
    const token = signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key);
    const request = http.request(`http://127.0.0.1:${gateway.port}/tunnel`, { method: 'POST', headers: {
      'x-purple-egress-authorization': token
    } }, response => {
      assert.equal(response.statusCode, 200); const chunks = [];
      response.on('data', chunk => { chunks.push(chunk); if (reset && Buffer.concat(chunks).length === expected.length) rejectProbe?.(); });
      response.on('error', reject);
      response.on('end', () => { assert.equal(response.complete, true); resolve(Buffer.concat(chunks)); request.destroy(); });
      request.write(Buffer.from([22, 3, 1, 0, 1, 0]));
    });
    request.on('error', error => { if (error.code !== 'ECONNRESET') reject(error); });
    request.flushHeaders();
  });
  assert.deepEqual(actual, expected);
}

test('target TLS protocol-version alert and graceful EOF are conveyed as complete gateway HTTP framing', async t => {
  await peerTermination(t, { reset: false, alert: true });
});

test('target reset after an alert preserves the alert and finishes gateway framing while upload remains open', async t => {
  await peerTermination(t, { reset: true, alert: true });
});

test('a connected target rejecting a TLS probe by reset produces clean byte EOF for scanner interpretation', async t => {
  await peerTermination(t, { reset: true, alert: false });
});

test('pre-connect refusal remains a complete 502 response', async t => {
  const gateway = await startAssessmentEgressGateway({ key, port: 0, connect: () => {
    const socket = new net.Socket(); queueMicrotask(() => socket.destroy(Object.assign(new Error('Synthetic dial refusal.'), { code: 'ECONNREFUSED' }))); return socket;
  } });
  t.after(() => gateway.close());
  const response = await fetch(`http://127.0.0.1:${gateway.port}/tunnel`, { method: 'POST', body: 'synthetic', headers: {
    'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)
  } });
  assert.equal(response.status, 502); await response.text();
});

test('byte budget exhaustion still aborts gateway framing instead of reporting clean peer EOF', async t => {
  const sockets = new Set();
  const origin = net.createServer(socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); socket.resume();
    socket.write(Buffer.alloc(8 * 1024 * 1024 + 1));
  }).listen(0, '127.0.0.1');
  await once(origin, 'listening');
  t.after(() => { for (const socket of sockets) socket.destroy(); origin.close(); });
  const gateway = await startAssessmentEgressGateway({ key, port: 0, connect: () => net.connect(origin.address().port, '127.0.0.1') });
  t.after(() => gateway.close());
  const complete = await new Promise((resolve, reject) => {
    const request = http.request(`http://127.0.0.1:${gateway.port}/tunnel`, { method: 'POST', headers: {
      'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)
    } }, response => {
      assert.equal(response.statusCode, 200); response.resume();
      response.once('end', () => resolve(response.complete)); response.once('aborted', () => resolve(response.complete));
      response.on('error', () => {});
    });
    request.on('error', reject); request.end('synthetic');
  });
  assert.equal(complete, false);
});
