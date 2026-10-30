import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { once } from 'node:events';
import { Readable, Writable } from 'node:stream';
import { startAssessmentEgressGateway } from '../server/assessment-egress-gateway.mjs';
import { signAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { connectAssessmentGateway } from '../workers/assessment-egress-socket.js';
import { assessmentTunnel } from '../workers/assessment-egress.js';

const key = 'synthetic-raw-transport-key-'.repeat(3);
const encode = value => new TextEncoder().encode(value);
function request(body) {
  return new Request('http://container/tunnel', { method: 'POST', body, duplex: 'half', headers: {
    'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)
  } });
}
function socketPort(port) {
  return { connect(address, options) {
    assert.equal(address, '127.0.0.1:8788'); assert.equal(options.allowHalfOpen, true);
    const socket = net.connect({ port, host: '127.0.0.1', allowHalfOpen: true });
    socket.on('error', () => {});
    return { opened: once(socket, 'connect'), readable: Readable.toWeb(socket), writable: Writable.toWeb(socket),
      close: async () => { socket.destroy(); } };
  } };
}

test('raw container transport preserves binary duplex bytes through the actual HMAC Node gateway before upload EOF', async t => {
  const echoSockets = new Set();
  const echo = net.createServer(socket => { echoSockets.add(socket); socket.on('error', () => {}); socket.pipe(socket); });
  echo.listen(0, '127.0.0.1'); await once(echo, 'listening');
  const gateway = await startAssessmentEgressGateway({ key, port: 0,
    connect: options => { assert.equal(options.host, '8.8.8.8'); assert.equal(options.port, 443);
      return net.connect({ host: '127.0.0.1', port: echo.address().port }); } });
  t.after(async () => { await gateway.close(); for (const socket of echoSockets) socket.destroy(); await new Promise(resolve => echo.close(resolve)); });
  const pending = [], abort = new AbortController(); let failures = 0;
  const upload = new TransformStream(), writer = upload.writable.getWriter();
  const response = await connectAssessmentGateway(socketPort(gateway.port), request(upload.readable), {
    signal: abort.signal, waitUntil: promise => pending.push(promise), onFailure: async () => { failures++; }
  });
  assert.equal(response.status, 200);
  const reader = response.body.getReader();
  const hello = new Uint8Array([22, 3, 3, 0, 9, 0, 255, 13, 10, 0, 128]);
  await writer.write(hello);
  assert.deepEqual((await reader.read()).value, hello);
  await writer.write(encode('another TLS-shaped record while body is open'));
  assert.equal(new TextDecoder().decode((await reader.read()).value), 'another TLS-shaped record while body is open');
  assert.equal(failures, 0);
  abort.abort(); await Promise.all(pending); await reader.cancel().catch(() => {});
});

function syntheticPort(response, { fragmented = false } = {}) {
  let cancelled = false;
  const bytes = encode(response);
  return { get cancelled() { return cancelled; }, connect() {
    let index = 0;
    return { opened: Promise.resolve(), readable: new ReadableStream({ pull(controller) {
      if (index === bytes.length) return controller.close();
      const end = fragmented ? index + 1 : bytes.length;
      controller.enqueue(bytes.subarray(index, end)); index = end;
    } }), writable: new WritableStream(), close: async () => { cancelled = true; } };
  } };
}
function options() { return { signal: new AbortController().signal, waitUntil() {}, onFailure: async () => {} }; }

test('raw transport decodes fragmented chunk headers and data with strict framing', async () => {
  const port = syntheticPort('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n', { fragmented: true });
  const response = await connectAssessmentGateway(port, request('fixture'), options());
  assert.equal(await response.text(), 'onetwo'); assert.equal(port.cancelled, true);
});

test('raw transport rejects non-200, conflicting framing, oversized headers and truncated bodies', async () => {
  for (const response of [
    'HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n',
    `HTTP/1.1 200 OK\r\nLong: ${'x'.repeat(8200)}\r\n\r\n`
  ]) {
    const port = syntheticPort(response);
    await assert.rejects(connectAssessmentGateway(port, request('fixture'), options()), /did not complete/);
    assert.equal(port.cancelled, true);
  }
  for (const response of [
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc',
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n800001\r\n'
  ]) {
    const port = syntheticPort(response);
    const result = await connectAssessmentGateway(port, request('fixture'), options());
    await assert.rejects(result.text(), /did not complete/); assert.equal(port.cancelled, true);
  }
});

test('raw transport cancellation closes the local socket and records failure', async () => {
  const port = syntheticPort('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'); let failures = 0;
  const response = await connectAssessmentGateway(port, request('fixture'), { ...options(), onFailure: async () => { failures++; } });
  await response.body.cancel(); assert.equal(port.cancelled, true); assert.equal(failures, 1);
});

test('normal raw response EOF closes the shared lifecycle before cancelling an open upload', async () => {
  const port = syntheticPort('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\n');
  let failures = 0; const pending = [];
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; } });
  const upload = new TransformStream();
  const result = await connectAssessmentGateway(port, request(tunnel.wrap(upload.readable, 'request')), {
    signal: tunnel.signal, waitUntil: promise => pending.push(promise), onFailure: tunnel.fail
  });
  assert.equal(await new Response(tunnel.wrap(result.body, 'response')).text(), 'one');
  assert.equal((await tunnel.finished).failed, false); await Promise.all(pending); assert.equal(failures, 0);
});

test('a target rejecting a TLS probe by reset reaches raw tunnel EOF without a gateway failure', async t => {
  const originSockets = new Set();
  const origin = net.createServer(socket => {
    originSockets.add(socket); socket.on('error', () => {}); socket.once('data', () => socket.resetAndDestroy());
  }).listen(0, '127.0.0.1');
  await once(origin, 'listening');
  const gateway = await startAssessmentEgressGateway({ key, port: 0,
    connect: () => net.connect(origin.address().port, '127.0.0.1') });
  t.after(async () => { await gateway.close(); for (const socket of originSockets) socket.destroy(); await new Promise(resolve => origin.close(resolve)); });
  let failures = 0; const pending = [];
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; } });
  const upload = new TransformStream(), writer = upload.writable.getWriter();
  const result = await connectAssessmentGateway(socketPort(gateway.port), request(tunnel.wrap(upload.readable, 'request')), {
    signal: tunnel.signal, waitUntil: promise => pending.push(promise), onFailure: tunnel.fail
  });
  await writer.write(new Uint8Array([22, 3, 1, 0, 1, 0]));
  assert.equal((await new Response(tunnel.wrap(result.body, 'response')).arrayBuffer()).byteLength, 0);
  assert.equal((await tunnel.finished).failed, false); await Promise.all(pending); assert.equal(failures, 0);
});
