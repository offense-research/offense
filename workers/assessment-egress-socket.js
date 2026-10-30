const encode = value => new TextEncoder().encode(value);
const reasons = { gateway_socket_open: 'socket_open', gateway_socket_request_headers: 'socket_upload',
  gateway_socket_response_headers: 'socket_headers', gateway_socket_protocol: 'socket_framing' };
const fail = (phase = 'gateway_socket_protocol', reason = reasons[phase] || 'socket_framing') =>
  Object.assign(new Error('Assessment gateway transport did not complete.'), { phase, reason });
const MAX_BYTES = 8 * 1024 * 1024;

// A bound container port supports raw TCP. Encode its fixed HTTP request here
// so request framing cannot depend on a Fetcher's handling of an open body.
// The only destination selectable by this code is the trusted local gateway.
export async function connectAssessmentGateway(port, request, { signal, waitUntil, onFailure }) {
  const token = request.headers.get('x-purple-egress-authorization');
  if (!/^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/.test(token || '') || token.length > 2048) throw fail();
  let socket;
  try { socket = port.connect('127.0.0.1:8788', { secureTransport: 'off', allowHalfOpen: true }); }
  catch { throw fail('gateway_socket_open'); }
  let phase = 'gateway_socket_open';
  let reader, writer, uploadReader, closed = false, stopped = false, failure;
  const recordFailure = reason => {
    if (!failure) {
      try { failure = Promise.resolve(onFailure(reason)).catch(() => {}); }
      catch { failure = Promise.resolve(); }
    }
    return failure;
  };
  const stop = () => {
    if (stopped) return;
    stopped = true; closed = true; signal.removeEventListener('abort', stop);
    void socket.close().catch(() => {});
    void uploadReader?.cancel().catch(() => {});
  };
  signal.addEventListener('abort', stop, { once: true });
  void socket.closed?.catch(() => {});
  if (signal.aborted) { stop(); throw fail(); }
  try {
    await socket.opened;
    phase = 'gateway_socket_request_headers';
    reader = socket.readable.getReader(); writer = socket.writable.getWriter();
    await writer.write(encode(`POST /tunnel HTTP/1.1\r\nHost: container\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nx-purple-egress-authorization: ${token}\r\nConnection: close\r\n\r\n`));
    const upload = (async () => {
      uploadReader = request.body.getReader(); let bytes = 0;
      try {
        for (;;) {
          const { done, value } = await uploadReader.read();
          if (done) break;
          if (!(value instanceof Uint8Array) || (bytes += value.byteLength) > MAX_BYTES) throw fail();
          if (!value.byteLength) continue;
          await writer.write(encode(`${value.byteLength.toString(16)}\r\n`));
          await writer.write(value); await writer.write(encode('\r\n'));
        }
        await writer.write(encode('0\r\n\r\n'));
      } finally { uploadReader.releaseLock(); uploadReader = null; }
    })().catch(async () => { if (!closed) { const recorded = recordFailure('socket_upload'); stop(); await recorded; } });
    // Reading the response must run concurrently with uploading: TLS waits for
    // server bytes before it can produce the rest of the open request body.
    waitUntil(upload);
    let pending = new Uint8Array(), offset = 0;
    async function available() {
      if (offset < pending.byteLength) return;
      const result = await reader.read();
      if (result.done || !(result.value instanceof Uint8Array) || result.value.byteLength > MAX_BYTES + 16384) throw fail();
      pending = result.value; offset = 0;
      if (!pending.byteLength) return available();
    }
    async function line(limit) {
      const bytes = []; let cr = false;
      for (;;) {
        await available(); const byte = pending[offset++];
        if (cr) { if (byte !== 10) throw fail(); return new TextDecoder().decode(new Uint8Array(bytes)); }
        if (byte === 13) { cr = true; continue; }
        if (byte < 32 || byte > 126 || bytes.length >= limit) throw fail();
        bytes.push(byte);
      }
    }
    phase = 'gateway_socket_response_headers';
    const status = await line(256);
    if (!/^HTTP\/1\.[01] 200(?: |$)/.test(status)) throw fail();
    const headers = new Map(); let headerBytes = status.length + 2;
    for (;;) {
      const value = await line(8192); headerBytes += value.length + 2;
      if (headerBytes > 16384) throw fail();
      if (!value) break;
      const match = value.match(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+):\s*(.*)$/);
      if (!match || headers.has(match[1].toLowerCase())) throw fail();
      headers.set(match[1].toLowerCase(), match[2].trim());
    }
    if (headers.get('transfer-encoding')?.toLowerCase() !== 'chunked' || headers.has('content-length')) throw fail();
    let remaining = 0, total = 0, needsTerminator = false;
    const body = new ReadableStream({
      async pull(controller) {
        try {
          if (!remaining) {
            if (needsTerminator && await line(0) !== '') throw fail();
            const size = await line(16);
            if (!/^[a-fA-F0-9]{1,8}$/.test(size)) throw fail();
            remaining = Number.parseInt(size, 16);
            if ((total += remaining) > MAX_BYTES) throw fail('gateway_socket_protocol', 'byte_budget');
            if (!remaining) {
              let trailers = 0;
              for (;;) { const value = await line(8192); if ((trailers += value.length + 2) > 16384) throw fail(); if (!value) break; }
              // Let the caller observe normal EOF and close its lifecycle
              // before aborting the still-open upload. Cancelling it here
              // would incorrectly turn a successful response into a failure.
              controller.close(); closed = true; void socket.close().catch(() => {}); return;
            }
            needsTerminator = true;
          }
          await available();
          const count = Math.min(remaining, pending.byteLength - offset);
          controller.enqueue(pending.subarray(offset, offset + count)); offset += count; remaining -= count;
        } catch (error) { const recorded = !closed ? recordFailure(error.reason || 'socket_framing') : Promise.resolve();
          stop(); controller.error(fail()); await recorded; }
      },
      async cancel() { const recorded = !closed ? recordFailure('response_cancelled') : Promise.resolve(); stop(); await recorded; }
    });
    return new Response(body, { headers: { 'content-type': 'application/octet-stream' } });
  } catch { const error = fail(phase); const recorded = recordFailure(error.reason); stop(); await recorded; throw error; }
}
