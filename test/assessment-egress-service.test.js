import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFile } from 'node:fs/promises';
import { signAssessmentTunnel } from '../shared/assessment-egress-auth.js';
import { assessmentEgressRequest, createAssessmentEgressController } from '../workers/assessment-egress-controller.js';
import { assessmentWebSocket } from '../workers/assessment-egress-websocket.js';
import { signAssessmentWarmup } from '../workers/assessment-egress-warmup.js';

const key = 'synthetic-gateway-key-'.repeat(4);
const bytes = value => new TextEncoder().encode(value);
const authorized = (body = 'fixture', token = signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key)) =>
  new Request('https://gateway.example/tunnel', { method: 'POST', body, duplex: 'half',
    headers: { 'x-purple-egress-authorization': token } });

function fixture(t, { portFetch, createPair, upgradeResponse } = {}) {
  const db = new DatabaseSync(':memory:'), kv = new Map(), starts = [], pending = [], timeouts = [];
  let forwards = 0;
  const container = { running: false, images: { egress: 'registry/synthetic@sha256:fixture' },
    start(input) { starts.push(input); this.running = true; }, async destroy() { this.running = false; },
    async setInactivityTimeout(value) { timeouts.push(value); },
    getTcpPort(port) { assert.equal(port, 8788); return { async fetch(input) {
      const request = typeof input === 'string' ? new Request(input) : input;
      if (new URL(request.url).pathname === '/health') return new Response(null, { status: 404 });
      forwards++;
      return portFetch ? portFetch(request) : new Response('result');
    } }; }
  };
  const ctx = { container, waitUntil(promise) { pending.push(promise); }, storage: { kv: {
    get: name => kv.get(name), put: (name, value) => kv.set(name, value)
  }, transactionSync(action) { db.exec('BEGIN'); try { const result = action(); db.exec('COMMIT'); return result; } catch (error) { db.exec('ROLLBACK'); throw error; } },
  sql: { exec(query, ...values) {
    const statement = db.prepare(query), rows = statement.all(...values);
    return { toArray: () => rows, one: () => rows[0] };
  } } } };
  const controller = createAssessmentEgressController(ctx, { ASSESSMENT_EGRESS_KEY: key }, {
    wait: async () => {}, openTunnel: (port, request) => port.fetch(request), createPair, upgradeResponse
  });
  t.after(async () => { await Promise.allSettled(pending); db.close(); });
  return { db, ctx, container, starts, pending, timeouts, controller, forwards: () => forwards };
}

test('public gateway rejects unauthenticated requests before DO lookup, body reads or VM startup', async () => {
  let lookups = 0;
  const env = { ASSESSMENT_EGRESS_KEY: key, GATEWAY: { getByName() { lookups++; assert.fail('Unauthorized request reached the container.'); } } };
  const invalid = authorized('private body', 'invalid');
  assert.equal((await assessmentEgressRequest(invalid, env)).status, 403);
  assert.equal(invalid.bodyUsed, false); assert.equal(lookups, 0);
  assert.equal((await assessmentEgressRequest(new Request('https://gateway.example/tunnel'), env)).status, 404);
  assert.equal((await assessmentEgressRequest(new Request('https://gateway.example/health'), env)).status, 200);
  assert.equal((await assessmentEgressRequest(new Request('https://gateway.example/health'), {})).status, 503);
  assert.equal(lookups, 0);
});

test('authenticated public traffic uses only the named gateway and forwards its stream unchanged', async () => {
  const request = authorized(); let observed;
  const result = await assessmentEgressRequest(request, { ASSESSMENT_EGRESS_KEY: key, GATEWAY: {
    getByName(name) { assert.equal(name, 'gateway-v1'); return { fetch(input) { observed = input; return new Response('stream'); } }; }
  } });
  assert.equal(observed, request); assert.equal(await result.text(), 'stream');
});

test('WebSocket upgrade authentication happens before DO lookup or container startup', async () => {
  let lookups = 0;
  const request = new Request('https://gateway.example/tunnel', { headers: { upgrade: 'websocket', 'x-purple-egress-authorization': 'invalid' } });
  const result = await assessmentEgressRequest(request, { ASSESSMENT_EGRESS_KEY: key, GATEWAY: {
    getByName() { lookups++; throw Error('Must not wake a gateway.'); }
  } });
  assert.equal(result.status, 403); assert.equal(lookups, 0);
});

test('authenticated gateway upgrade returns a binary duplex channel and releases its durable receipt after EOF', async t => {
  const sockets = [new EventTarget(), new EventTarget()];
  for (const [socket, remote] of [[sockets[0], sockets[1]], [sockets[1], sockets[0]]]) {
    socket.accept = () => { if (socket === sockets[1]) assert.equal(socket.binaryType, 'arraybuffer'); };
    socket.send = data => queueMicrotask(() => remote.dispatchEvent(new MessageEvent('message', {
      data: typeof data === 'string' ? data : new Uint8Array(data)
    })));
    socket.close = () => { if (socket.closed) return; socket.closed = remote.closed = true;
      queueMicrotask(() => { socket.dispatchEvent(new Event('close')); remote.dispatchEvent(new Event('close')); }); };
  }
  const f = fixture(t, { createPair: () => sockets, upgradeResponse: webSocket => ({ status: 101, webSocket }),
    portFetch: request => new Response(request.body) });
  const response = await f.controller.fetch(new Request('https://gateway.example/tunnel', { headers: {
    upgrade: 'websocket', 'x-purple-egress-authorization': authorized().headers.get('x-purple-egress-authorization')
  } }));
  assert.equal(response.status, 101); assert.equal(response.webSocket, sockets[0]);
  let failures = 0;
  const client = assessmentWebSocket(response.webSocket, { onFailure: async () => { failures++; } });
  const writer = client.writable.getWriter(), reader = client.readable.getReader();
  await writer.write(bytes('TLS bytes while upload remains open'));
  assert.equal(new TextDecoder().decode((await reader.read()).value), 'TLS bytes while upload remains open');
  await writer.close(); assert.equal((await reader.read()).done, true); await Promise.all(f.pending);
  assert.equal(failures, 0); assert.equal(f.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
});

test('a new declarative gateway uses its loopback export without a pre-provisioned namespace binding', async () => {
  let calls = 0;
  const response = await assessmentEgressRequest(authorized(), { ASSESSMENT_EGRESS_KEY: key }, { exports: {
    AssessmentEgressGateway: { getByName(name) {
      calls++; assert.equal(name, 'gateway-v1'); return { fetch: () => new Response('export-routed') };
    } }
  } });
  assert.equal(await response.text(), 'export-routed'); assert.equal(calls, 1);
});

test('operational status requires a valid capability and never starts a container', async t => {
  const f = fixture(t);
  const response = await assessmentEgressRequest(new Request('https://gateway.example/status', { headers: {
    'x-purple-egress-authorization': authorized().headers.get('x-purple-egress-authorization')
  } }), { ASSESSMENT_EGRESS_KEY: key }, { exports: { AssessmentEgressGateway: {
    getByName: () => ({ status: f.controller.status })
  } } });
  assert.equal(response.status, 200); assert.equal((await response.json()).running, false); assert.equal(f.starts.length, 0);
  assert.equal((await assessmentEgressRequest(new Request('https://gateway.example/status'), { ASSESSMENT_EGRESS_KEY: key })).status, 403);
});

test('authenticated startup diagnostics redact raw and JSON-escaped runtime keys', async () => {
  const specialKey = 'synthetic-key-with-"quote"-and-\\slash-'.repeat(2);
  const response = await assessmentEgressRequest(new Request('https://gateway.example/status', { headers: {
    'x-purple-egress-authorization': signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, specialKey)
  } }), { ASSESSMENT_EGRESS_KEY: specialKey }, { exports: { AssessmentEgressGateway: {
    getByName() { throw new Error(`Rejected ${specialKey} ${JSON.stringify(specialKey)}`); }
  } } });
  const text = await response.text();
  assert.equal(response.status, 503); assert.ok(!text.includes(specialKey));
  assert.ok(!text.includes(JSON.stringify(specialKey).slice(1, -1))); assert.match(text, /private runtime key/);
});

test('a valid tunnel starts only the trusted fixed image, injects its key privately and releases capacity at EOF', async t => {
  const f = fixture(t), request = authorized();
  const response = await f.controller.fetch(request);
  assert.equal(response.status, 200); assert.equal(await response.text(), 'result');
  await Promise.all(f.pending);
  assert.equal(f.starts.length, 1); assert.equal(f.forwards(), 1);
  assert.equal(f.starts[0].enableInternet, true); assert.equal(f.starts[0].image, f.container.images.egress);
  assert.deepEqual(f.starts[0].env, { ASSESSMENT_EGRESS_KEY: key, ASSESSMENT_EGRESS_BIND: '0.0.0.0', ASSESSMENT_EGRESS_PORT: '8788' });
  assert.equal(f.timeouts[0], 300_000);
  assert.equal(f.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
});

test('readiness starts only the fixed gateway without dialing any target and rejects replay', async t => {
  const f = fixture(t), token = signAssessmentWarmup(key);
  const request = () => new Request('https://gateway.example/warm', { method: 'POST', headers: {
    'x-purple-egress-authorization': token
  } });
  const response = await f.controller.fetch(request());
  assert.equal(response.status, 200); assert.deepEqual(await response.json(), { ready: true });
  assert.equal(f.starts.length, 1); assert.equal(f.forwards(), 0);
  assert.equal(f.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
  assert.equal((await f.controller.fetch(request())).status, 403); assert.equal(f.forwards(), 0);
});

test('concurrent readiness shares one fixed gateway startup and startup failure releases its receipt', async t => {
  const f = fixture(t), warm = () => new Request('https://gateway.example/warm', { method: 'POST', headers: {
    'x-purple-egress-authorization': signAssessmentWarmup(key)
  } });
  const results = await Promise.all([f.controller.fetch(warm()), f.controller.fetch(warm())]);
  assert.deepEqual(results.map(result => result.status), [200, 200]); assert.equal(f.starts.length, 1); assert.equal(f.forwards(), 0);
  const broken = fixture(t); broken.container.start = () => { throw Error('Synthetic fixed image startup failure.'); };
  assert.equal((await broken.controller.fetch(warm())).status, 503);
  assert.equal(broken.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
  assert.equal(broken.forwards(), 0);
});

test('durable nonce receipts reject replay even after controller reconstruction', async t => {
  const f = fixture(t), token = signAssessmentTunnel({ host: 'example.com', address: '8.8.8.8' }, key);
  await (await f.controller.fetch(authorized('first', token))).text(); await Promise.all(f.pending);
  const second = createAssessmentEgressController(f.ctx, { ASSESSMENT_EGRESS_KEY: key });
  const replay = authorized('private repeat body', token);
  assert.equal((await second.fetch(replay)).status, 403); assert.equal(replay.bodyUsed, false); assert.equal(f.forwards(), 1);
});

test('a reviewed fixed-image change restarts the trusted VM while keeping durable replay receipts', async t => {
  const f = fixture(t); let destroyed = 0;
  f.container.destroy = async () => { destroyed++; f.container.running = false; };
  const token = authorized().headers.get('x-purple-egress-authorization');
  await (await f.controller.fetch(authorized('first', token))).text(); await Promise.all(f.pending);
  f.container.images.egress = 'registry/synthetic@sha256:reviewed-new-image';
  await (await f.controller.fetch(authorized())).text(); await Promise.all(f.pending);
  assert.equal(destroyed, 1); assert.equal(f.starts.length, 2); assert.equal(f.starts[1].image, f.container.images.egress);
  assert.equal((await f.controller.fetch(authorized('replay', token))).status, 403);
});

test('opaque runtime image capabilities use the deployer-provided public digest for restart identity', async t => {
  const f = fixture(t), capability = {};
  f.container.images.egress = capability;
  const env = { ASSESSMENT_EGRESS_KEY: key, ASSESSMENT_EGRESS_IMAGE_DIGEST: 'sha256:' + 'a'.repeat(64) };
  const controller = createAssessmentEgressController(f.ctx, env, { wait: async () => {}, openTunnel: (port, request) => port.fetch(request) });
  await (await controller.fetch(authorized())).text(); await Promise.all(f.pending);
  assert.equal(f.starts[0].image, capability); assert.equal((await controller.status()).runtimeImageDigest, env.ASSESSMENT_EGRESS_IMAGE_DIGEST);
  env.ASSESSMENT_EGRESS_IMAGE_DIGEST = 'sha256:' + 'b'.repeat(64);
  await (await controller.fetch(authorized())).text(); await Promise.all(f.pending);
  assert.equal(f.starts.length, 2); assert.equal((await controller.status()).runtimeImageDigest, env.ASSESSMENT_EGRESS_IMAGE_DIGEST);
});

test('persistent concurrent receipt limit rejects excess connections before container startup', async t => {
  const f = fixture(t), now = Date.now();
  for (let index = 0; index < 64; index++) f.db.prepare('INSERT INTO assessment_gateway_nonces VALUES(?,?,?)')
    .run(index.toString(16).padStart(32, '0'), now + 30_000, now + 60_000);
  const request = authorized();
  assert.equal((await f.controller.fetch(request)).status, 429); assert.equal(request.bodyUsed, false);
  assert.equal(f.starts.length, 0);
});

test('nonce retention is bounded and expired inactive receipts are pruned before accepting a fresh tunnel', async t => {
  const f = fixture(t), now = Date.now();
  f.db.exec('BEGIN');
  const insert = f.db.prepare('INSERT INTO assessment_gateway_nonces VALUES(?,?,?)');
  for (let index = 0; index < 10_000; index++) insert.run(index.toString(16).padStart(32, '0'), now + 30_000, 0);
  f.db.exec('COMMIT');
  assert.equal((await f.controller.fetch(authorized())).status, 429); assert.equal(f.starts.length, 0);
  f.db.prepare('UPDATE assessment_gateway_nonces SET expires_at = ?').run(now - 1);
  const response = await f.controller.fetch(authorized());
  assert.equal(await response.text(), 'result'); await Promise.all(f.pending);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS count FROM assessment_gateway_nonces').get().count, 1);
});

test('duplex forwarding returns response headers and bytes before request-body EOF', async t => {
  const f = fixture(t, { portFetch(request) {
    assert.equal(request.headers.get('transfer-encoding'), 'chunked');
    assert.equal(request.headers.get('content-length'), null);
    const reader = request.body.getReader();
    return new Response(new ReadableStream({
      async pull(controller) { const result = await reader.read(); if (result.done) controller.close(); else controller.enqueue(result.value); },
      cancel() { return reader.cancel(); }
    }));
  } });
  const upload = new TransformStream(), writer = upload.writable.getWriter();
  const response = await f.controller.fetch(authorized(upload.readable));
  assert.equal(response.status, 200);
  const reader = response.body.getReader(), read = reader.read();
  await writer.write(bytes('client hello before EOF'));
  assert.equal(new TextDecoder().decode((await read).value), 'client hello before EOF');
  await writer.close(); assert.equal((await reader.read()).done, true);
  await Promise.all(f.pending);
  assert.equal(f.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
});

test('response cancellation and upstream failures release persistent capacity and expose no private errors', async t => {
  const f = fixture(t, { portFetch() { return new Response(new ReadableStream({ start() {} })); } });
  const response = await f.controller.fetch(authorized());
  await response.body.cancel(); await Promise.all(f.pending);
  assert.equal(f.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
  const failed = fixture(t, { portFetch() { throw new Error('PRIVATE-GATEWAY-DETAIL'); } });
  const error = await failed.controller.fetch(authorized());
  assert.equal(error.status, 502); assert.doesNotMatch(await error.text(), /PRIVATE-GATEWAY-DETAIL/);
  await Promise.all(failed.pending);
  assert.equal(failed.db.prepare('SELECT active_until FROM assessment_gateway_nonces').get().active_until, 0);
});

test('the gateway image has no scanner/customer commands and scanner containers remain isolated', async () => {
  const config = JSON.parse(await readFile(new URL('../wrangler.egress.production.jsonc', import.meta.url), 'utf8'));
  assert.equal(config.name, 'purple-assessment-egress');
  assert.equal(config.containers[0].images.egress.dockerfile, './agent/assessment-egress.Dockerfile');
  const dockerfile = await readFile(new URL('../agent/assessment-egress.Dockerfile', import.meta.url), 'utf8');
  assert.match(dockerfile, /USER gateway/); assert.match(dockerfile, /assessment-egress-gateway\.mjs/);
  assert.doesNotMatch(dockerfile, /scan-runner|assessment-network\.mjs/);
  const scanner = await readFile(new URL('../workers/scan-container.js', import.meta.url), 'utf8');
  assert.match(scanner, /enableInternet: false/);
});
