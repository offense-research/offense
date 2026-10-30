import test from 'node:test';
import assert from 'node:assert/strict';
import { assessmentGatewayStream } from '../workers/assessment-egress-client.js';
import { assessmentWebSocket } from '../workers/assessment-egress-websocket.js';
import { assessmentTunnel } from '../workers/assessment-egress.js';
import { verifyAssessmentTunnel } from '../shared/assessment-egress-auth.js';

const key = 'synthetic-assessment-egress-key-'.repeat(3);
function pair() {
  class Socket extends EventTarget {
    accept() { assert.equal(this.binaryType, 'arraybuffer'); this.accepted = true; }
    send(data) { queueMicrotask(() => this.peer.dispatchEvent(new MessageEvent('message', { data }))); }
    close() { if (this.closed) return; this.closed = true; queueMicrotask(() => {
      this.dispatchEvent(new Event('close')); this.peer.dispatchEvent(new Event('close'));
    }); }
  }
  const client = new Socket(), server = new Socket(); client.peer = server; server.peer = client;
  return { client, server };
}

test('agent gateway upgrade authenticates and returns TLS response bytes before upload EOF', async () => {
  const { client, server } = pair(), upload = new TransformStream(), waits = [];
  let failures = 0;
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; }, timeoutMs: 1000 });
  const remote = assessmentWebSocket(server), received = remote.readable.getReader(), sent = remote.writable.getWriter();
  const response = await assessmentGatewayStream({ gatewayURL: 'https://gateway.example/', key,
    host: 'app.purpleteam.sh', address: '104.21.1.2', body: upload.readable, tunnel, waitUntil: p => waits.push(p),
    fetcher: async (url, options) => {
      assert.equal(url.href, 'https://gateway.example/tunnel');
      assert.equal(options.method, 'GET'); assert.equal(options.body, undefined);
      assert.equal(options.redirect, 'manual'); assert.equal(options.headers.Upgrade, 'websocket');
      const authorization = verifyAssessmentTunnel(options.headers['x-purple-egress-authorization'], key);
      assert.equal(authorization.host, 'app.purpleteam.sh'); assert.equal(authorization.address, '104.21.1.2');
      return { status: 101, webSocket: client };
    } });
  assert.equal(client.accepted, true);
  const writer = upload.writable.getWriter(), reader = response.getReader();
  const writing = writer.write(new Uint8Array([0x16, 0, 0xff]));
  assert.deepEqual((await received.read()).value, new Uint8Array([0x16, 0, 0xff]));
  await writing;
  const reply = sent.write(new Uint8Array([0x17, 0xff, 0]));
  assert.deepEqual((await reader.read()).value, new Uint8Array([0x17, 0xff, 0]));
  await reply;
  // Upload is deliberately still open when the first response arrives.
  await writer.close(); assert.equal((await received.read()).done, true);
  await sent.close(); assert.equal((await reader.read()).done, true);
  await Promise.all(waits);
  assert.equal((await tunnel.finished).failed, false); assert.equal(failures, 0);
});

test('denied upgrades and redirects do not consume TLS input or accept a socket', async () => {
  for (const status of [200, 302, 403]) {
    const upload = new TransformStream();
    const tunnel = assessmentTunnel({ onFailure: async () => {}, timeoutMs: 1000 });
    let accepted = false;
    await assert.rejects(assessmentGatewayStream({ gatewayURL: 'https://gateway.example/', key,
      host: 'app.purpleteam.sh', address: '104.21.1.2', body: upload.readable, tunnel, waitUntil: () => {},
      fetcher: async () => ({ status, webSocket: { accept() { accepted = true; } } }) }));
    assert.equal(upload.readable.locked, false); assert.equal(accepted, false);
    await tunnel.fail();
  }
});

test('failed upgrades retain only a fixed gateway reason and exclude private provider error text', async () => {
  for (const [supplied, expected] of [['socket_open', 'socket_open'], ['PRIVATE_PROVIDER_URL_TOKEN', 'unknown']]) {
    const tunnel = assessmentTunnel({ onFailure: async () => {}, timeoutMs: 1000 });
    await assert.rejects(assessmentGatewayStream({ gatewayURL: 'https://gateway.example/', key,
      host: 'app.purpleteam.sh', address: '104.21.1.2', body: new ReadableStream(), tunnel, waitUntil: () => {},
      fetcher: async () => ({ status: 502, headers: new Headers({ 'x-purple-egress-failure': supplied }) }) }), error => {
      assert.equal(error.reason, expected);
      assert.equal(error.message, 'Assessment egress upgrade failed.');
      assert.equal(JSON.stringify(error).includes('PRIVATE_'), false);
      return true;
    });
    await tunnel.fail();
  }
});

test('a complete buffered response survives peer EOF and close during an upload awaiting credit', async () => {
  const { client, server } = pair(), waits = [];
  let failures = 0, cancelled = false;
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; }, timeoutMs: 1000 });
  const upload = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(192 * 1024)); },
    cancel() { cancelled = true; } });
  const remote = assessmentWebSocket(server);
  const response = await assessmentGatewayStream({ gatewayURL: 'https://gateway.example/', key,
    host: 'app.purpleteam.sh', address: '104.21.1.2', body: upload, tunnel, waitUntil: p => waits.push(p),
    fetcher: async () => ({ status: 101, webSocket: client }) });
  // Do not consume the remote upload: its automatic first-frame credit leaves
  // the next frame pending. Do not consume the response before socket close.
  await new Promise(resolve => setImmediate(resolve));
  const writer = remote.writable.getWriter(), alert = new Uint8Array([21, 3, 3, 0, 2, 2, 40]);
  await writer.write(alert); await writer.close(); remote.close();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(failures, 0);
  const reader = response.getReader();
  assert.deepEqual((await reader.read()).value, alert);
  assert.equal((await reader.read()).done, true);
  await Promise.all(waits);
  assert.equal((await tunnel.finished).failed, false);
  assert.equal(failures, 0); assert.equal(cancelled, true);
});

test('an unexpected peer close still records one failure and cancels an upload awaiting credit', async () => {
  const { client, server } = pair(), waits = [];
  let failures = 0, cancelled = false;
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; }, timeoutMs: 1000 });
  const upload = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(192 * 1024)); },
    cancel() { cancelled = true; } });
  const response = await assessmentGatewayStream({ gatewayURL: 'https://gateway.example/', key,
    host: 'app.purpleteam.sh', address: '104.21.1.2', body: upload, tunnel, waitUntil: p => waits.push(p),
    fetcher: async () => ({ status: 101, webSocket: client }) });
  await new Promise(resolve => setImmediate(resolve));
  server.close();
  assert.equal((await tunnel.finished).failed, true);
  await assert.rejects(response.getReader().read());
  await Promise.all(waits);
  assert.equal(failures, 1); assert.equal(cancelled, true);
});

test('invalid gateway destinations are rejected before fetch', async () => {
  for (const gatewayURL of ['http://gateway.example/', 'https://user@gateway.example/', 'https://gateway.example/path', 'https://gateway.example/?redirect=1']) {
    let fetched = false;
    await assert.rejects(assessmentGatewayStream({ gatewayURL, fetcher: async () => { fetched = true; } }));
    assert.equal(fetched, false);
  }
});
