import test from 'node:test';
import assert from 'node:assert/strict';
import { assessmentTunnel, ASSESSMENT_FAILURE_REASONS } from '../workers/assessment-egress.js';
import { assessmentWebSocket } from '../workers/assessment-egress-websocket.js';
import { connectAssessmentGateway } from '../workers/assessment-egress-socket.js';
import { signAssessmentTunnel } from '../shared/assessment-egress-auth.js';

const open = () => new ReadableStream({ start() {} });
const bytes = value => new TextEncoder().encode(value);

test('first-cause reasons distinguish stream cancellation, source errors, byte budget and deadline', async () => {
  for (const direction of ['request', 'response']) {
    const recorded = [];
    const tunnel = assessmentTunnel({ onFailure: async (...args) => { recorded.push(args); } });
    await tunnel.wrap(open(), direction).cancel(); await tunnel.fail('websocket_closed'); await tunnel.finished;
    assert.equal(recorded.length, 1); assert.equal(recorded[0][0], `${direction}_cancelled`);
    assert.ok(recorded[0][1].durationMs >= 0 && recorded[0][1].durationMs <= 60000);
    const failures = [];
    const broken = assessmentTunnel({ onFailure: async reason => { failures.push(reason); } });
    const stream = broken.wrap(new ReadableStream({ pull(controller) { controller.error(Error('Private upstream value.')); } }), direction);
    await assert.rejects(new Response(stream).text()); await broken.finished;
    assert.deepEqual(failures, [`${direction}_stream_error`]);
  }
  const budgets = [], budget = assessmentTunnel({ onFailure: async reason => { budgets.push(reason); }, limitBytes: 1 });
  await assert.rejects(new Response(budget.wrap(new Response('two').body, 'response')).text()); await budget.finished;
  assert.deepEqual(budgets, ['byte_budget']);
  const deadlines = [], deadline = assessmentTunnel({ onFailure: async reason => { deadlines.push(reason); }, timeoutMs: 5 });
  await deadline.finished; assert.deepEqual(deadlines, ['connection_deadline']);
});

function pair() {
  const sockets = [new EventTarget(), new EventTarget()];
  for (const [socket, remote] of [[sockets[0], sockets[1]], [sockets[1], sockets[0]]]) {
    socket.frames = []; socket.send = value => { socket.frames.push(value); queueMicrotask(() => remote.dispatchEvent(new MessageEvent('message', { data: value }))); };
    socket.close = () => { if (socket.closed) return; socket.closed = remote.closed = true;
      queueMicrotask(() => { socket.dispatchEvent(new Event('close')); remote.dispatchEvent(new Event('close')); }); };
  }
  return sockets;
}

test('a gateway failure crosses WebSocket boundaries as one fixed reason before cleanup cancellation', async () => {
  const [serverSocket, clientSocket] = pair(), reasons = [];
  const server = assessmentTunnel({ onFailure: async () => {} });
  const client = assessmentTunnel({ onFailure: async reason => { reasons.push(reason); } });
  assessmentWebSocket(serverSocket, { role: 'gateway', signal: server.signal, onFailure: server.fail });
  assessmentWebSocket(clientSocket, { signal: client.signal, onFailure: client.fail });
  await server.fail('socket_framing'); await client.finished;
  assert.deepEqual(reasons, ['socket_framing']); assert.ok(serverSocket.frames.includes('fail:socket_framing'));
  assert.equal(clientSocket.frames.filter(value => value === 'fail:socket_framing').length, 0);
});

test('private error strings never become persisted reasons or peer control frames', async () => {
  const secret = 'PRIVATE-URL-TOKEN-SHOULD-NOT-APPEAR', captured = [];
  const tunnel = assessmentTunnel({ onFailure: async (...args) => { captured.push(args); } });
  await tunnel.fail(Error(secret)); await tunnel.finished;
  assert.equal(captured[0][0], 'unknown'); assert.ok(!JSON.stringify(captured).includes(secret));
  const [attacker, remote] = pair(), failures = [];
  assessmentWebSocket(remote, { onFailure: async reason => { failures.push(reason); } });
  attacker.send('fail:' + secret); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(failures, ['websocket_protocol']);
  assert.ok(remote.frames.every(value => typeof value !== 'string' || !value.includes(secret)));
  assert.ok(failures.every(value => ASSESSMENT_FAILURE_REASONS.includes(value)));
});

test('malformed gateway chunk framing is recorded before cleanup cancels the still-open upload', async () => {
  const reasons = [], waits = [], tunnel = assessmentTunnel({ onFailure: async reason => { reasons.push(reason); } });
  const key = 'synthetic-reason-test-key-'.repeat(3);
  const request = new Request('http://container/tunnel', { method: 'POST', duplex: 'half',
    body: tunnel.wrap(open(), 'request'), headers: {
      'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)
    } });
  const port = { connect: () => ({ opened: Promise.resolve(), close: async () => {}, writable: new WritableStream(),
    readable: new ReadableStream({ start(controller) { controller.enqueue(bytes('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc')); controller.close(); } }) }) };
  const response = await connectAssessmentGateway(port, request, { signal: tunnel.signal, onFailure: tunnel.fail, waitUntil: promise => waits.push(promise) });
  await assert.rejects(response.text()); await tunnel.finished; await Promise.all(waits);
  assert.deepEqual(reasons, ['socket_framing']);
});
