import http from 'node:http';
import net from 'node:net';
import { Transform } from 'node:stream';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { verifyAssessmentTunnel } from '../shared/assessment-egress-auth.js';

// Run only this trusted image behind the authenticated WebSocket Worker (or a
// compatible frontend). Normal container TCP can reach Cloudflare IPs without
// granting scanner VMs general network access.
export async function startAssessmentEgressGateway({ key, host = '127.0.0.1', port = 8788,
  connect = options => net.connect(options), now = Date.now } = {}) {
  if (typeof key !== 'string' || key.length < 32) throw new Error('Set a separate assessment egress key of at least 32 characters.');
  const used = new Map(), sockets = new Set(); let active = 0;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 0, headersTimeout: 10000 }, (req, res) => {
    if (req.method !== 'POST' || req.url !== '/tunnel' || !req.headers['x-purple-egress-authorization']) {
      res.writeHead(404); res.end(); return;
    }
    let claims;
    try {
      claims = verifyAssessmentTunnel(req.headers['x-purple-egress-authorization'], key, now);
      for (const [nonce, expiry] of used) if (expiry <= now()) used.delete(nonce);
      if (used.has(claims.nonce) || used.size >= 10000 || active >= 64) throw new Error();
      used.set(claims.nonce, claims.expiresAt);
    } catch { res.writeHead(403); res.end(); return; }
    let upstream, timer, upload, download, connected = false, ending = false, closed = false, bytes = 0; active++;
    const stopUpload = () => { req.unpipe(upload); req.pause(); upload?.unpipe(upstream); upload?.destroy(); };
    const cleanup = hard => {
      if (closed) return;
      closed = true; active--; clearTimeout(timer); stopUpload(); upstream?.destroy(); download?.destroy();
      // A finished response must retain its final HTTP chunk. Destroying its
      // request/socket here can reset a peer that still has an open upload.
      // Connection: close lets Node finish that response gracefully instead.
      if (hard) { req.destroy(); res.destroy(); }
    };
    const abort = () => cleanup(true);
    const dialFailed = () => {
      if (closed || ending) return;
      ending = true; stopUpload(); res.writeHead(502, { connection: 'close' }); res.end();
    };
    const peerClosed = () => {
      if (closed || ending) return;
      if (!connected) return dialFailed();
      ending = true; stopUpload(); upstream.unpipe(download);
      // A target may reject a TLS version/cipher with an alert, EOF or RST.
      // Preserve all bytes already received and convey peer EOF to the engine;
      // it remains responsible for judging whether its probe was complete.
      // End through the transform so buffered bytes drain before the final
      // HTTP chunk. Gateway/byte-budget faults still abort the HTTP framing.
      if (!download.writableEnded) download.end();
    };
    const limiter = () => new Transform({ transform(chunk, _encoding, callback) {
      if ((bytes += chunk.length) > 8 * 1024 * 1024) { callback(new Error('Tunnel byte budget exceeded.')); abort(); }
      else callback(null, chunk);
    } }).on('error', abort);
    res.once('finish', () => cleanup(false));
    res.once('close', () => { if (!res.writableFinished) abort(); });
    req.once('aborted', abort);
    try { upstream = connect({ host: claims.address, port: 443, family: net.isIP(claims.address) }); }
    catch { dialFailed(); return; }
    timer = setTimeout(abort, 150000);
    upstream.once('error', error => {
      if (!connected) dialFailed();
      else if (error.code === 'ECONNRESET') peerClosed();
      else abort();
    });
    upstream.once('connect', () => {
      if (closed) return;
      connected = true;
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no', connection: 'close' });
      res.flushHeaders();
      upload = limiter(); download = limiter();
      req.pipe(upload).pipe(upstream);
      upstream.pipe(download).pipe(res);
    });
    // A normal readable end lets pipe() drain and end the response itself.
    upstream.once('end', () => { if (!closed) { ending = true; stopUpload(); } });
    upstream.once('close', peerClosed);
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => socket.destroy());
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return { server, port: server.address().port, close: async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await startAssessmentEgressGateway({ key: process.env.ASSESSMENT_EGRESS_KEY,
    host: process.env.ASSESSMENT_EGRESS_BIND || '127.0.0.1', port: Number(process.env.ASSESSMENT_EGRESS_PORT || 8788) });
}
