import { signAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { assessmentWebSocket } from './assessment-egress-websocket.js';
import { assessmentFailureReason } from './assessment-egress-failure.js';
import { signAssessmentWarmup } from './assessment-egress-warmup.js';

// Prepare only the trusted gateway process before a scanner's own connection
// timeout begins. This endpoint has no destination and never dials a target.
export async function warmAssessmentGateway({ gatewayURL, key, signal, fetcher = fetch }) {
  try {
    const gateway = new URL(gatewayURL);
    if (gateway.protocol !== 'https:' || gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== '/')
      throw new Error();
    if (signal?.aborted) throw new Error();
    const deadline = AbortSignal.timeout(65_000), cancellation = signal ? AbortSignal.any([signal, deadline]) : deadline;
    const response = await fetcher(new URL('/warm', gateway), { method: 'POST', redirect: 'manual',
      headers: { 'x-purple-egress-authorization': signAssessmentWarmup(key) }, signal: cancellation });
    if (response.status !== 200 || !response.body) { await response.body?.cancel(); throw new Error(); }
    const reader = response.body.getReader(), chunks = []; let bytes = 0;
    try {
      for (;;) {
        const result = await reader.read(); if (result.done) break;
        if ((bytes += result.value.byteLength) > 1024) { await reader.cancel(); throw new Error(); }
        chunks.push(result.value);
      }
    } finally { reader.releaseLock(); }
    const body = new Uint8Array(bytes); let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    if (JSON.parse(new TextDecoder().decode(body))?.ready !== true) throw new Error();
    return { ready: true };
  } catch { throw new Error('Assessment gateway did not become ready.'); }
}

// The public Worker boundary uses a WebSocket upgrade so request and response
// TLS bytes can flow independently before either direction reaches EOF.
export async function assessmentGatewayStream({ gatewayURL, key, host, address, body, tunnel, waitUntil,
  fetcher = fetch }) {
  const gateway = new URL(gatewayURL);
  if (gateway.protocol !== 'https:' || gateway.username || gateway.password || gateway.search || gateway.hash || gateway.pathname !== '/')
    throw new Error('Invalid egress gateway.');
  const response = await fetcher(new URL('/tunnel', gateway), { method: 'GET', redirect: 'manual',
    headers: { Upgrade: 'websocket', 'x-purple-egress-authorization': signAssessmentTunnel({ host, address }, key) },
    signal: tunnel.signal });
  if (response.status !== 101 || !response.webSocket) {
    const error = new Error('Assessment egress upgrade failed.');
    error.reason = assessmentFailureReason(response.headers?.get('x-purple-egress-failure'));
    throw error;
  }
  // Workers compatibility dates from 2026-03-17 default binary events to Blob.
  // Raw TLS frames must arrive as ArrayBuffer before accepting the socket.
  response.webSocket.binaryType = 'arraybuffer';
  response.webSocket.accept();
  const peer = assessmentWebSocket(response.webSocket, { signal: tunnel.signal, onFailure: tunnel.fail });
  // A server may finish its response while the scanner is still uploading.
  // Its valid EOF can close the socket with an outgoing ACK still pending;
  // preserve the buffered response rather than turning that normal half-close
  // into a failure. Both stream adapters still record genuine source/protocol
  // errors through the shared lifecycle.
  waitUntil(tunnel.wrap(body, 'request').pipeTo(peer.writable, { preventCancel: true })
    .catch(() => peer.remoteEOF ? undefined : tunnel.fail('websocket_write')));
  return tunnel.wrap(peer.readable, 'response');
}
