import test from 'node:test';
import assert from 'node:assert/strict';
import { assessmentWebSocket } from '../workers/assessment-egress-websocket.js';
import { assessmentTunnel } from '../workers/assessment-egress.js';

export function pair() {
  const a = new EventTarget(), b = new EventTarget();
  for (const [socket, remote] of [[a, b], [b, a]]) {
    socket.binaryType = 'blob';
    socket.frames = []; socket.closed = false; socket.accept = () => {};
    socket.send = value => {
      if (socket.closed) throw Error('Synthetic socket closed.');
      const data = typeof value === 'string' ? value : remote.binaryType === 'arraybuffer' ? new Uint8Array(value).buffer : new Blob([value]);
      socket.frames.push(data);
      queueMicrotask(() => remote.dispatchEvent(new MessageEvent('message', { data })));
    };
    socket.close = () => { if (socket.closed) return; socket.closed = true; remote.closed = true;
      queueMicrotask(() => { socket.dispatchEvent(new Event('close')); remote.dispatchEvent(new Event('close')); }); };
  }
  return [a, b];
}

test('WebSocket credit bounds frames and preserves binary bidirectional traffic before either half closes', async () => {
  const [a, b] = pair(); let failures = 0;
  const left = assessmentWebSocket(a, { onFailure: async () => { failures++; } }), right = assessmentWebSocket(b);
  assert.equal(a.binaryType, 'arraybuffer'); assert.equal(b.binaryType, 'arraybuffer');
  assert.equal(right.remoteEOF, false);
  const writer = left.writable.getWriter(), reader = right.readable.getReader();
  const bytes = new Uint8Array(192 * 1024).map((_, index) => index % 251);
  let finished = false; const writing = writer.write(bytes).then(() => { finished = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(finished, false);
  assert.ok(a.frames.filter(value => typeof value !== 'string').length <= 2);
  let offset = 0;
  while (offset < bytes.length) { const { value } = await reader.read(); assert.deepEqual(value, bytes.subarray(offset, offset + value.length)); offset += value.length; }
  await writing; await writer.close(); assert.equal((await reader.read()).done, true); assert.equal(right.remoteEOF, true);
  assert.throws(() => { right.remoteEOF = false; }, TypeError);
  const back = right.writable.getWriter(), incoming = left.readable.getReader();
  await back.write(new Uint8Array([22, 3, 3, 255])); await back.close();
  assert.deepEqual((await incoming.read()).value, new Uint8Array([22, 3, 3, 255]));
  assert.equal((await incoming.read()).done, true); assert.equal(failures, 0);
  left.close(); right.close();
});

test('normal EOF marker and immediate socket closure preserve buffered bytes without a network failure', async () => {
  const [a, b] = pair(); let failures = 0;
  const left = assessmentWebSocket(a), right = assessmentWebSocket(b, { onFailure: async () => { failures++; } });
  const writer = left.writable.getWriter();
  await writer.write(new Uint8Array([1, 2, 3])); await writer.close(); left.close();
  await new Promise(resolve => setImmediate(resolve));
  const reader = right.readable.getReader(); assert.deepEqual((await reader.read()).value, new Uint8Array([1, 2, 3]));
  assert.equal((await reader.read()).done, true); assert.equal(failures, 0);
});

test('unexpected text, duplicate EOF, oversized frames and credit flooding fail closed', async () => {
  for (const messages of [['unexpected'], ['ack'], ['eof', 'eof'], [new Uint8Array(65537)],
    Array.from({ length: 5 }, () => new Uint8Array(65536))]) {
    const [a, b] = pair(); let failures = 0;
    const peer = assessmentWebSocket(b, { onFailure: async () => { failures++; } });
    for (const data of messages) a.send(data);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(failures, 1); assert.equal(b.closed, true);
    await peer.readable.cancel().catch(() => {});
  }
});

test('aggregate byte budget counts both directions and abort releases a pending credit wait', async () => {
  const [a, b] = pair(); let failures = 0;
  const abort = new AbortController();
  const peer = assessmentWebSocket(a, { signal: abort.signal, onFailure: async () => { failures++; } });
  const writer = peer.writable.getWriter(); const pending = writer.write(new Uint8Array([1]));
  await new Promise(resolve => setImmediate(resolve)); abort.abort();
  await assert.rejects(pending); assert.equal(failures, 0); assert.equal(a.closed, true);

  const [c, d] = pair(), one = assessmentWebSocket(c), two = assessmentWebSocket(d);
  const consume = two.readable.pipeTo(new WritableStream());
  const send = one.writable.getWriter();
  await assert.rejects(send.write(new Uint8Array(8 * 1024 * 1024 + 1)), /did not complete/);
  await assert.rejects(consume); one.close(); two.close(); b.close();
});

test('gateway sends response EOF before lifecycle cleanup and the client records no failure', async () => {
  const [a, b] = pair(); let failures = 0;
  const serverTunnel = assessmentTunnel({ onFailure: async () => { failures++; } });
  const clientTunnel = assessmentTunnel({ onFailure: async () => { failures++; } });
  const server = assessmentWebSocket(a, { signal: serverTunnel.signal, onFailure: serverTunnel.fail });
  const client = assessmentWebSocket(b, { signal: clientTunnel.signal, onFailure: clientTunnel.fail });
  const source = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array([1, 2, 3])); controller.close(); } });
  const pumping = source.pipeTo(server.writable).then(() => serverTunnel.close(), () => serverTunnel.fail());
  assert.deepEqual(new Uint8Array(await new Response(clientTunnel.wrap(client.readable, 'response')).arrayBuffer()), new Uint8Array([1, 2, 3]));
  await pumping; assert.equal((await clientTunnel.finished).failed, false); assert.equal((await serverTunnel.finished).failed, false); assert.equal(failures, 0);
});
