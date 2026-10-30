const FRAME_BYTES = 64 * 1024;
const error = () => new Error('Assessment WebSocket transport did not complete.');
import { ASSESSMENT_FAILURE_REASONS, assessmentFailureReason } from './assessment-egress-failure.js';

// Binary frames carry raw TLS bytes. Acknowledging each consumed frame keeps
// both peers bounded even though WebSocket.send() has no backpressure API.
// The only text frames are fixed flow-control/half-close protocol markers.
export function assessmentWebSocket(socket, { signal, onFailure = async () => {}, role = 'client' } = {}) {
  // New Workers compatibility dates default binary delivery to Blob. Select
  // ArrayBuffer explicitly so the bounded synchronous handler stays valid.
  socket.binaryType = 'arraybuffer';
  let controller, queued = 0, bytes = 0, remoteEOF = false, stopped = false, failure, acknowledge;
  const queue = [];
  const notify = reason => { if (!stopped) try { socket.send(`fail:${assessmentFailureReason(reason)}`); } catch {} };
  const abort = () => { if (signal?.reason?.assessmentFailureReason) notify(signal.reason.assessmentFailureReason); stop(); };
  const stop = (preserveRead = false) => {
    if (stopped) return;
    stopped = true; signal?.removeEventListener('abort', abort);
    acknowledge?.reject(error()); acknowledge = null;
    if (!preserveRead) try { controller.error(error()); } catch {}
    try { socket.close(1000, 'Assessment transport closed'); } catch {}
  };
  const fail = (reason = 'websocket_protocol', echo = true) => {
    if (failure || stopped) return failure;
    reason = assessmentFailureReason(reason);
    failure = Promise.resolve().then(() => onFailure(reason)).catch(() => {});
    if (echo) notify(reason);
    stop(); try { controller.error(error()); } catch {}
    return failure;
  };
  function drain() {
    if (stopped || !controller) return;
    while (queue.length && controller.desiredSize > 0) {
      const value = queue.shift(); queued -= value.byteLength; controller.enqueue(value); socket.send('ack');
    }
    if (remoteEOF && !queue.length) try { controller.close(); } catch {}
  }
  const readable = new ReadableStream({ start(value) { controller = value; }, pull: drain,
    async cancel() { await fail(role === 'gateway' ? 'request_cancelled' : 'response_cancelled'); } });
  socket.addEventListener('message', event => {
    if (stopped) return;
    try {
      const data = event.data;
      if (typeof data === 'string' && data.startsWith('fail:') && ASSESSMENT_FAILURE_REASONS.includes(data.slice(5))) {
        void fail(data.slice(5), false); return;
      }
      if (data === 'ack') {
        if (!acknowledge) throw error();
        const receipt = acknowledge; acknowledge = null; receipt.resolve(); return;
      }
      if (data === 'eof') { if (remoteEOF) throw error(); remoteEOF = true; drain(); return; }
      const value = data instanceof ArrayBuffer ? new Uint8Array(data) : ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : null;
      if (remoteEOF || !value || !value.byteLength || value.byteLength > FRAME_BYTES || (queued += value.byteLength) > 2 * FRAME_BYTES) throw error();
      if ((bytes += value.byteLength) > 8 * 1024 * 1024) { void fail('byte_budget'); return; }
      queue.push(value); drain();
    } catch { void fail(); }
  });
  socket.addEventListener('error', () => { void fail('websocket_error'); });
  socket.addEventListener('close', () => {
    if (!stopped && (!remoteEOF || queue.length)) void fail('websocket_closed');
    else if (!stopped) stop(true);
  });
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) stop();
  const writable = new WritableStream({
    async write(value) {
      if (stopped || !(value instanceof Uint8Array)) throw error();
      for (let offset = 0; offset < value.byteLength; offset += FRAME_BYTES) {
        const chunk = value.subarray(offset, offset + FRAME_BYTES);
        if ((bytes += chunk.byteLength) > 8 * 1024 * 1024) { await fail('byte_budget'); throw error(); }
        const receipt = new Promise((resolve, reject) => { acknowledge = { resolve, reject }; });
        void receipt.catch(() => {});
        try { socket.send(chunk); await receipt; }
        catch { await fail('websocket_write'); throw error(); }
      }
    },
    close() { if (!stopped) socket.send('eof'); },
    async abort() { await fail(role === 'gateway' ? 'response_stream_error' : 'request_stream_error'); }
  });
  return { readable, writable, close: () => stop(), get remoteEOF() { return remoteEOF; } };
}
