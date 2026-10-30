import { createHash } from 'node:crypto';
import { verifyAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { assessmentTunnel } from './assessment-egress.js';
import { connectAssessmentGateway } from './assessment-egress-socket.js';
import { assessmentWebSocket } from './assessment-egress-websocket.js';
import { verifyAssessmentWarmup } from './assessment-egress-warmup.js';
import { assessmentFailureReason } from './assessment-egress-failure.js';

const IDLE_MS = 5 * 60_000;
const CONNECTION_MS = 60_000;
const MAX_ACTIVE = 64;
const MAX_NONCES = 10_000;
const forbidden = () => new Response('Assessment gateway authorization failed.', { status: 403 });
const configured = env => typeof env.ASSESSMENT_EGRESS_KEY === 'string' && env.ASSESSMENT_EGRESS_KEY.length >= 32;
const upgrade = request => request.method === 'GET' && request.headers.get('upgrade')?.toLowerCase() === 'websocket';
function privateDiagnostic(error, key) {
  let message = String(error?.message || '');
  for (const value of new Set([key, JSON.stringify(key).slice(1, -1)])) message = message.replaceAll(value, '[private runtime key]');
  return message.slice(0, 600);
}

// Validate at the public edge before obtaining a DO or waking a container. The
// DO and the Node gateway both verify again at their own execution boundaries.
export async function assessmentEgressRequest(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === '/health' && request.method === 'GET') return Response.json({
    ok: configured(env), service: 'purple-assessment-egress'
  }, { status: configured(env) ? 200 : 503, headers: { 'cache-control': 'no-store' } });
  const statusRequest = url.pathname === '/status' && request.method === 'GET';
  const warmRequest = url.pathname === '/warm' && request.method === 'POST';
  if (!(url.pathname === '/tunnel' && (request.method === 'POST' || upgrade(request))) && !statusRequest && !warmRequest || url.search) return new Response('Not found', { status: 404 });
  if (!configured(env)) return new Response('Assessment gateway unavailable.', { status: 503 });
  try { (warmRequest ? verifyAssessmentWarmup : verifyAssessmentTunnel)(request.headers.get('x-purple-egress-authorization'), env.ASSESSMENT_EGRESS_KEY); }
  catch { return forbidden(); }
  const length = request.headers.get('content-length');
  if (warmRequest && length !== null && length !== '0') return new Response('Warmup accepts no input.', { status: 413 });
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > 8 * 1024 * 1024))
    return new Response('Assessment tunnel size exceeds its limit.', { status: 413 });
  try {
    // Declarative exports provision a new namespace at activation. Using the
    // loopback export avoids an explicit binding to a namespace that does not
    // exist yet during the gateway's initial version upload.
    const gateway = ctx?.exports?.AssessmentEgressGateway || env.GATEWAY;
    const stub = gateway.getByName('gateway-v1');
    return statusRequest ? Response.json(await stub.status(), { headers: { 'cache-control': 'no-store' } }) : await stub.fetch(request);
  }
  catch (error) {
    if (statusRequest) return Response.json({ available: false, phase: 'routing',
      diagnostic: privateDiagnostic(error, env.ASSESSMENT_EGRESS_KEY)
    }, { status: 503, headers: { 'cache-control': 'no-store' } });
    return new Response('Assessment gateway unavailable.', { status: 503 });
  }
}

// This VM runs only the fixed HMAC gateway, never scanner/customer code. Its
// literal-IP TCP connections need normal container egress to reach Cloudflare
// destinations that the Workers sockets API cannot connect to.
export function createAssessmentEgressController(ctx, env, { now = Date.now, wait = ms => new Promise(resolve => setTimeout(resolve, ms)), openTunnel = connectAssessmentGateway,
  createPair = () => new WebSocketPair(), upgradeResponse = socket => new Response(null, { status: 101, webSocket: socket }) } = {}) {
  const sql = ctx.storage.sql;
  sql.exec(`CREATE TABLE IF NOT EXISTS assessment_gateway_nonces (
    nonce TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, active_until INTEGER NOT NULL
  )`).toArray();
  let starting;
  const prune = () => sql.exec('DELETE FROM assessment_gateway_nonces WHERE expires_at <= ? AND active_until <= ?', now(), now()).toArray();
  function reserve(claims) {
    return ctx.storage.transactionSync(() => {
      prune();
      if (sql.exec('SELECT nonce FROM assessment_gateway_nonces WHERE nonce = ?', claims.nonce).toArray().length) return 403;
      if (sql.exec('SELECT COUNT(*) AS count FROM assessment_gateway_nonces WHERE active_until > ?', now()).one().count >= MAX_ACTIVE ||
          sql.exec('SELECT COUNT(*) AS count FROM assessment_gateway_nonces').one().count >= MAX_NONCES) return 429;
      sql.exec('INSERT INTO assessment_gateway_nonces VALUES (?, ?, ?)', claims.nonce, claims.expiresAt, now() + CONNECTION_MS).toArray();
      return null;
    });
  }
  const release = nonce => sql.exec('UPDATE assessment_gateway_nonces SET active_until = 0 WHERE nonce = ?', nonce).toArray();
  async function startAndWait() {
    let phase = 'container_metadata';
    try {
    const container = ctx.container;
    // Image aliases may be opaque runtime capabilities. The deployer supplies
    // their public reviewed digest so upgrades have a stable identity.
    const imageDigest = env.ASSESSMENT_EGRESS_IMAGE_DIGEST || (typeof container.images.egress === 'string' ? container.images.egress : null);
    if (typeof imageDigest !== 'string' || !imageDigest) throw new Error('The reviewed gateway image identity is unavailable.');
    const fingerprint = createHash('sha256').update(env.ASSESSMENT_EGRESS_KEY).update('\0').update(imageDigest).digest('hex');
    if (container.running && ctx.storage.kv.get('gateway-runtime-fingerprint') !== fingerprint) await container.destroy();
    if (!container.running) {
      phase = 'container_start';
      container.start({ image: container.images.egress, instance: 'lite', enableInternet: true,
        env: { ASSESSMENT_EGRESS_KEY: env.ASSESSMENT_EGRESS_KEY, ASSESSMENT_EGRESS_BIND: '0.0.0.0', ASSESSMENT_EGRESS_PORT: '8788' } });
      ctx.storage.kv.put('gateway-runtime-fingerprint', fingerprint);
      ctx.storage.kv.put('gateway-runtime-image-digest', imageDigest);
    }
    phase = 'inactivity_timeout';
    await container.setInactivityTimeout(IDLE_MS);
    // The fixed gateway intentionally has no public health endpoint. A 404
    // from its port proves readiness without creating a TCP tunnel.
    const port = container.getTcpPort(8788);
    phase = 'port_readiness';
    for (let attempt = 0; attempt < 50; attempt++) {
      try {
        const response = await port.fetch('http://container/health', { signal: AbortSignal.timeout(1000) });
        await response.body?.cancel();
        if (response.status === 404) return;
      } catch { /* Bounded startup polling; no scanner or destination request. */ }
      await wait(200);
    }
    throw new Error('Assessment gateway did not become ready.');
    } catch (error) {
      ctx.storage.kv.put('gateway-last-failure', { phase,
        diagnostic: privateDiagnostic(error, env.ASSESSMENT_EGRESS_KEY) });
      throw new Error('Assessment gateway startup failed.');
    }
  }
  async function fetch(request) {
    const url = new URL(request.url);
    const warmRequest = request.method === 'POST' && url.pathname === '/warm';
    const websocket = upgrade(request);
    if (!warmRequest && (!(request.method === 'POST' || websocket) || url.pathname !== '/tunnel') || url.search) return new Response('Not found', { status: 404 });
    if (!configured(env)) return new Response('Assessment gateway unavailable.', { status: 503 });
    if (warmRequest && request.headers.has('content-length') && request.headers.get('content-length') !== '0')
      return new Response('Warmup accepts no input.', { status: 413 });
    let claims;
    try { claims = (warmRequest ? verifyAssessmentWarmup : verifyAssessmentTunnel)(request.headers.get('x-purple-egress-authorization'), env.ASSESSMENT_EGRESS_KEY, now); }
    catch { return forbidden(); }
    let rejected;
    try { rejected = reserve(claims); }
    catch { return new Response('Assessment gateway unavailable.', { status: 503 }); }
    if (rejected) return new Response(rejected === 403 ? 'Assessment tunnel was already used.' : 'Assessment gateway capacity reached.', { status: rejected });
    if (warmRequest) {
      try {
        starting ??= startAndWait().finally(() => { starting = undefined; });
        await starting;
        return Response.json({ ready: true }, { headers: { 'cache-control': 'no-store' } });
      } catch { return new Response('Assessment gateway did not become ready.', { status: 503 }); }
      finally { release(claims.nonce); }
    }
    let peer;
    const tunnel = assessmentTunnel({ onFailure: async () => {}, onClose: async () => { peer?.close(); release(claims.nonce); } });
    // A receipt remains active until response EOF/cancellation/failure. Keeping
    // that lifetime under waitUntil also makes cancellation release capacity.
    ctx.waitUntil(tunnel.finished);
    try {
      starting ??= startAndWait().finally(() => { starting = undefined; });
      await starting;
      if (tunnel.signal.aborted) throw new Error('Assessment gateway startup exceeded the tunnel lifetime.');
      let client;
      if (websocket) {
        const pair = createPair(); client = pair[0]; const server = pair[1];
        server.binaryType = 'arraybuffer'; server.accept();
        peer = assessmentWebSocket(server, { signal: tunnel.signal, onFailure: tunnel.fail, role: 'gateway' });
      }
      const forwarded = new Request('http://container/tunnel', { method: 'POST',
        headers: { 'content-type': 'application/octet-stream', 'transfer-encoding': 'chunked',
          'x-purple-egress-authorization': request.headers.get('x-purple-egress-authorization') },
        body: tunnel.wrap(peer?.readable || request.body, 'request'), signal: tunnel.signal, duplex: 'half' });
      const response = await openTunnel(ctx.container.getTcpPort(8788), forwarded, {
        signal: tunnel.signal, waitUntil: promise => ctx.waitUntil(promise), onFailure: tunnel.fail
      });
      if (response.status !== 200 || !response.body) { await response.body?.cancel(); throw new Error('Assessment gateway could not open the tunnel.'); }
      if (peer) {
        // The adapter counts aggregate bytes and applies one-frame credit.
        // Send its EOF marker before closing the shared tunnel lifetime.
        ctx.waitUntil(response.body.pipeTo(peer.writable).then(() => tunnel.close(), () => tunnel.fail()));
        return upgradeResponse(client);
      }
      return new Response(tunnel.wrap(response.body, 'response'), { headers: {
        'content-type': 'application/octet-stream', 'cache-control': 'no-store', 'x-accel-buffering': 'no'
      } });
    } catch (error) {
      ctx.storage.kv.put('gateway-last-failure', { phase: /^gateway_socket_[a-z_]+$/.test(error?.phase || '') ? error.phase : 'tunnel_transport',
        diagnostic: 'Bounded assessment transport failed.' });
      const reason = assessmentFailureReason(error?.reason || 'gateway_unavailable');
      await tunnel.fail(reason);
      return new Response('Assessment gateway tunnel unavailable.', { status: 502, headers: { 'x-purple-egress-failure': reason } });
    }
  }
  async function status() {
    let nativeImageDigest = null;
    try {
      const inspected = await ctx.container?.inspect?.();
      if (typeof inspected?.image === 'string') nativeImageDigest = inspected.image.match(/sha256:[a-f0-9]{64}/)?.[0] || null;
    } catch { /* Status never starts a container or exposes platform errors. */ }
    return { available: true, running: ctx.container?.running === true, imageAliases: Object.keys(ctx.container?.images || {}).slice(0, 10),
      runtimeImageDigest: ctx.storage.kv.get('gateway-runtime-image-digest') || null, nativeImageDigest,
      activeConnections: sql.exec('SELECT COUNT(*) AS count FROM assessment_gateway_nonces WHERE active_until > ?', now()).one().count,
      retainedNonces: sql.exec('SELECT COUNT(*) AS count FROM assessment_gateway_nonces').one().count,
      lastFailure: ctx.storage.kv.get('gateway-last-failure') || null };
  }
  return { fetch, prune, status };
}
