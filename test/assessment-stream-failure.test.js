import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFile } from 'node:fs/promises';
import { assessmentTunnel } from '../workers/assessment-egress.js';
import { scanController } from '../workers/scan-container.js';
import { createScanMetering } from '../server/scan-metering.js';

const bytes = value => new TextEncoder().encode(value);
function source() {
  let controller, cancellations = 0;
  const stream = new ReadableStream({ start(value) { controller = value; }, cancel() { cancellations++; } });
  return { stream, push: value => controller.enqueue(bytes(value)), end: () => controller.close(),
    error: () => controller.error(new Error('raw-private-credential')), cancelled: () => cancellations };
}
function lifecycle(options = {}) {
  let failures = 0, closes = 0;
  const tunnel = assessmentTunnel({ onFailure: async () => { failures++; }, onClose: async () => { closes++; }, ...options });
  return { tunnel, failures: () => failures, closes: () => closes };
}

for (const direction of ['request', 'response']) test(`a late ${direction} body error records one failure and closes both directions`, async () => {
  const f = lifecycle(), outgoing = source(), incoming = source();
  const request = f.tunnel.wrap(outgoing.stream, 'request').getReader();
  const response = f.tunnel.wrap(incoming.stream, 'response').getReader();
  const selected = direction === 'request' ? { source: outgoing, reader: request, peer: response } : { source: incoming, reader: response, peer: request };
  selected.source.push('initial');
  assert.equal(new TextDecoder().decode((await selected.reader.read()).value), 'initial');
  selected.source.error();
  await assert.rejects(selected.reader.read(), error => {
    assert.equal(error.message, 'Assessment tunnel did not complete.');
    assert.equal(f.failures(), 1); return true;
  });
  await assert.rejects(selected.peer.read(), /did not complete/);
  assert.deepEqual(await f.tunnel.finished, { failed: true, failureRecorded: true });
  assert.equal(f.closes(), 1); assert.equal(f.tunnel.signal.aborted, true);
  await f.tunnel.fail(); await f.tunnel.close(); assert.equal(f.failures(), 1); assert.equal(f.closes(), 1);
});

test('duplex byte limit counts upload and download together and makes the connection incomplete', async () => {
  const f = lifecycle({ limitBytes: 5 }), outgoing = source(), incoming = source();
  const upload = f.tunnel.wrap(outgoing.stream, 'request').getReader();
  const download = f.tunnel.wrap(incoming.stream, 'response').getReader();
  outgoing.push('123'); await upload.read(); incoming.push('456');
  await assert.rejects(download.read(), /did not complete/);
  await assert.rejects(upload.read(), /did not complete/);
  assert.equal((await f.tunnel.finished).failed, true); assert.equal(f.failures(), 1); assert.equal(f.closes(), 1);
});

test('consumer cancellation records failure and cancels the peer source', async () => {
  const f = lifecycle(), outgoing = source(), incoming = source();
  const upload = f.tunnel.wrap(outgoing.stream, 'request').getReader();
  const download = f.tunnel.wrap(incoming.stream, 'response').getReader();
  await download.cancel('private-upstream-reason');
  await assert.rejects(upload.read(), /did not complete/);
  assert.equal((await f.tunnel.finished).failed, true);
  assert.equal(outgoing.cancelled(), 1); assert.equal(incoming.cancelled(), 1);
  assert.equal(f.failures(), 1); assert.equal(f.closes(), 1);
});

test('idle tunnel deadline closes a raw socket and rejects pending reads', async () => {
  const f = lifecycle({ timeoutMs: 15 }), outgoing = source(), incoming = source();
  const upload = f.tunnel.wrap(outgoing.stream, 'request').getReader();
  const download = f.tunnel.wrap(incoming.stream, 'response').getReader();
  const reads = [assert.rejects(upload.read(), /did not complete/), assert.rejects(download.read(), /did not complete/)];
  assert.equal((await f.tunnel.finished).failed, true); await Promise.all(reads);
  assert.equal(f.tunnel.signal.aborted, true); assert.equal(f.failures(), 1); assert.equal(f.closes(), 1);
});

test('request completion preserves the response and normal response EOF closes without a failure', async () => {
  const f = lifecycle(), outgoing = source(), incoming = source();
  const upload = new Response(f.tunnel.wrap(outgoing.stream, 'request')).text();
  outgoing.push('upload'); outgoing.end();
  assert.equal(await upload, 'upload'); assert.equal(f.closes(), 0);
  const download = new Response(f.tunnel.wrap(incoming.stream, 'response')).text();
  incoming.push('download'); incoming.end();
  assert.equal(await download, 'download');
  assert.deepEqual(await f.tunnel.finished, { failed: false, failureRecorded: false });
  await f.tunnel.close(); await f.tunnel.fail();
  assert.equal(f.failures(), 0); assert.equal(f.closes(), 1);
});

test('an upload sink failure follows the same once-only failure and cleanup path', async () => {
  const f = lifecycle(), outgoing = source(), incoming = source();
  const download = f.tunnel.wrap(incoming.stream, 'response').getReader();
  const piping = f.tunnel.wrap(outgoing.stream, 'request').pipeTo(new WritableStream({
    write() { throw new Error('private-socket-error'); }
  })).catch(() => f.tunnel.fail());
  outgoing.push('upload'); await piping;
  await assert.rejects(download.read(), /did not complete/);
  assert.equal((await f.tunnel.finished).failed, true); assert.equal(f.failures(), 1); assert.equal(f.closes(), 1);
});

test('failure notification rejection still closes streams and is surfaced through the lifecycle result', async () => {
  let calls = 0, closes = 0;
  const tunnel = assessmentTunnel({ onFailure: async () => { calls++; throw new Error('private-provider-error'); }, onClose: async () => { closes++; } });
  const raw = source(), wrapped = tunnel.wrap(raw.stream, 'response').getReader();
  raw.error(); await assert.rejects(wrapped.read(), /did not complete/);
  assert.deepEqual(await tunnel.finished, { failed: true, failureRecorded: false });
  assert.equal(calls, 1); assert.equal(closes, 1);
});

test('late response failure downgrades an otherwise complete scanner report and releases its real billing reservation', async () => {
  const memory = new Map([
    ['scan', { status: 'running', startedAt: Date.now() }],
    ['assessment-policy', { tool: 'nuclei' }], ['assessment-connections', 1]
  ]);
  const ctx = { storage: { kv: { get: key => memory.get(key), put: (key, value) => memory.set(key, value) } }, container: {
    running: true, exec: async () => ({ output: async () => ({ exitCode: 0,
      stdout: new TextEncoder().encode(JSON.stringify({ status: 'completed', findings: [], tools: [{ name: 'nuclei', status: 'complete' }] })) }) })
  } };
  const db = new DatabaseSync(':memory:');
  try {
    const prices = JSON.parse(await readFile(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
    const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
    meter.recordVerifiedPurchase({ workspaceId: 'late-tunnel-fixture', paymentId: 'fixture_purchase_late_failure', amountMicros: 10_000_000 });
    const quote = meter.quote({ tools: ['nuclei'], inputBytes: 1, fileCount: 1 }), jobId = 'f'.repeat(32);
    meter.reserve({ jobId, workspaceId: 'late-tunnel-fixture', quote });
    assert.equal(meter.status('late-tunnel-fixture').reservedMicros, 250_000);
    const tunnel = assessmentTunnel({ onFailure: async () => {
      memory.set('assessment-network-failures', (memory.get('assessment-network-failures') || 0) + 1);
    } });
    const raw = source(), reader = tunnel.wrap(raw.stream, 'response').getReader();
    raw.push('received-before-failure'); await reader.read(); raw.error();
    await assert.rejects(reader.read(), /did not complete/); await tunnel.finished;
    const result = await scanController(ctx).get();
    assert.equal(result.status, 'partial'); assert.equal(result.tools[0].status, 'partial');
    meter.settle({ jobId, status: result.status, tools: result.tools });
    assert.equal(meter.usage(jobId).chargeMicros, 0);
    assert.equal(meter.status('late-tunnel-fixture').reservedMicros, 0);
    assert.equal(meter.status('late-tunnel-fixture').balanceMicros, 10_000_000);
  } finally { db.close(); }
});
