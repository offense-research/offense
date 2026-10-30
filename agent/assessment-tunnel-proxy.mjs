import http from 'node:http';
import { Transform } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ASSESSMENT_GATEWAY = 'purple-assessment-egress.invalid';
// The VM has no internet route. Only this fixed HTTP endpoint is intercepted by
// the Worker; its job-scoped policy authorizes and pins each remote TCP socket.
export async function startAssessmentTunnelProxy({ port = 8799, gateway = ASSESSMENT_GATEWAY,
  request = http.request, maxConnections = 200, maxBytes = 64 * 1024 * 1024, drainTimeoutMs = 5000 } = {}) {
  if (!Number.isSafeInteger(drainTimeoutMs) || drainTimeoutMs < 1 || drainTimeoutMs > 5000) throw new Error('Invalid assessment drain deadline.');
  let opened = 0, bytes = 0;
  const sockets = new Set();
  const server = http.createServer({ maxHeaderSize: 8192 }, (_req, res) => {
    res.writeHead(403, { connection: 'close' }); res.end('HTTPS CONNECT required.');
  });
  server.maxConnections = 8;
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('connect', (incoming, client, head) => {
    if (!/^[a-z0-9.-]+:443$/.test(incoming.url || '') || ++opened > maxConnections ||
        incoming.headers['content-length'] || incoming.headers['transfer-encoding']) {
      client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return;
    }
    const hostname = incoming.url.slice(0, -4);
    client.pause();
    const upstream = request({ hostname: gateway, port: 80, method: 'POST', path: '/tunnel',
      headers: { 'x-purple-target-host': hostname, 'content-type': 'application/octet-stream' },
      agent: false, timeout: 15000 });
    let responseStream, upload, download, draining, finished = false, closed = false;
    const finish = () => { if (closed) return; closed = true; finished = true; clearTimeout(draining);
      upstream.destroy(); client.destroy(); upload?.destroy(); download?.destroy(); };
    upstream.on('error', finish); upstream.on('timeout', finish);
    client.once('close', () => {
      if (finished) { upstream.destroy(); return; }
      if (!responseStream) return finish();
      // A TLS engine may close once it has its probe result, before the
      // target's last TLS records and gateway HTTP EOF arrive. End its upload
      // and drain the bounded response instead of cancelling a valid tunnel.
      client.unpipe(upload);
      if (!upload.writableEnded) upload.end();
      download.unpipe(client); download.resume();
      draining = setTimeout(finish, drainTimeoutMs);
    });
    const limiter = () => new Transform({ transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maxBytes) { callback(new Error('Assessment byte budget exceeded.')); finish(); }
      else callback(null, chunk);
    } }).on('error', finish);
    upstream.once('response', response => {
      if (response.statusCode !== 200) { response.resume(); client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); upstream.end(); return; }
      responseStream = response;
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      client.setTimeout(30000, finish); upstream.setTimeout(30000, finish);
      if (head.length) upstream.write(head);
      upload = limiter(); download = limiter();
      client.pipe(upload).pipe(upstream);
      response.pipe(download).pipe(client);
      response.on('error', finish);
      response.once('end', () => { finished = true; clearTimeout(draining); });
      client.resume();
    });
    upstream.flushHeaders();
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { server, port: server.address().port, close: async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startAssessmentTunnelProxy();
}
