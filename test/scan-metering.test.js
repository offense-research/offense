import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createScanMetering } from '../server/scan-metering.js';

const job = n => n.toString(16).padStart(32, '0');
const rates = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
const complete = names => names.map(name => ({ name, status: 'complete', durationMs: 123 }));

test('scanner quote reserves bounded prepaid credit and settles only once', () => {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: rates, now: () => 100 });
  meter.recordVerifiedPurchase({ workspaceId: 'w1', paymentId: 'pay_fixture_1', amountMicros: 200_000 });
  meter.recordVerifiedPurchase({ workspaceId: 'w1', paymentId: 'pay_fixture_1', amountMicros: 200_000 });
  assert.equal(meter.status('w1').balanceMicros, 200_000);
  assert.equal(meter.quote({ tools: ['opengrep', 'gitleaks'], inputBytes: 1_048_576, fileCount: 2 }).maximumMicros, 50_000);
  const quote = meter.quote({ tools: ['opengrep', 'gitleaks'], inputBytes: 1_048_577, fileCount: 2 });
  assert.equal(quote.inputMiB, 2);
  assert.equal(quote.maximumMicros, 60_000);
  assert.equal(quote.prices[0].basePriceMicros, 25_000);
  assert.equal(quote.prices[0].additionalMiBPriceMicros, 5_000);
  meter.reserve({ jobId: job(1), workspaceId: 'w1', quote });
  meter.reserve({ jobId: job(1), workspaceId: 'w1', quote });
  assert.equal(meter.status('w1').availableMicros, 140_000);
  assert.equal(meter.usage(job(1)).state, 'reserved');
  meter.settle({ jobId: job(1), status: 'completed', tools: complete(quote.toolIds) });
  meter.settle({ jobId: job(1), status: 'completed', tools: complete(quote.toolIds) });
  assert.equal(meter.status('w1').balanceMicros, 140_000);
  assert.equal(meter.usage(job(1)).chargeMicros, 60_000);
  assert.deepEqual(meter.usage(job(1)).reportedTools.map(item => item.durationMs), [123, 123]);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind = 'usage'").get().n, 1);
  meter.release(job(1)); meter.release(job(1));
  assert.equal(meter.status('w1').balanceMicros, 200_000);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE kind = 'refund'").get().n, 1);
});

test('scanner meter rejects underfunded, tampered and cross-workspace reservations', () => {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: rates });
  const quote = meter.quote({ tools: ['trivy-config'], inputBytes: 1, fileCount: 1 });
  assert.throws(() => meter.reserve({ jobId: job(2), workspaceId: 'w1', quote }), error => error.status === 402);
  meter.recordVerifiedPurchase({ workspaceId: 'w1', paymentId: 'pay_fixture_2', amountMicros: 100_000 });
  assert.throws(() => meter.reserve({ jobId: job(2), workspaceId: 'w1', quote: { ...quote, maximumMicros: 0 } }), /price changed/);
  meter.reserve({ jobId: job(2), workspaceId: 'w1', quote });
  assert.throws(() => meter.reserve({ jobId: job(2), workspaceId: 'w2', quote }), /identity was reused/);
  assert.throws(() => meter.recordVerifiedPurchase({ workspaceId: 'w2', paymentId: 'pay_fixture_2', amountMicros: 20_000 }), /identity was reused/);
  assert.throws(() => meter.quote({ tools: ['opengrep', 'opengrep'], inputBytes: 1, fileCount: 1 }), /distinct/);
  assert.throws(() => meter.quote({ tools: ['unknown'], inputBytes: 1, fileCount: 1 }), /supported/);
});

test('partial scans release held credit and disabled billing still records usage', () => {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: rates });
  meter.recordVerifiedPurchase({ workspaceId: 'w', paymentId: 'pay_fixture_3', amountMicros: 100_000 });
  const quote = meter.quote({ tools: ['trivy-vuln'], inputBytes: 20, fileCount: 1 });
  meter.reserve({ jobId: job(3), workspaceId: 'w', quote });
  meter.settle({ jobId: job(3), status: 'partial', tools: [{ name: 'trivy-vuln', status: 'partial', durationMs: 9 }] });
  assert.equal(meter.status('w').availableMicros, 100_000);
  assert.equal(meter.usage(job(3)).chargeMicros, 0);
  assert.equal(meter.usage(job(3)).state, 'released');

  const free = createScanMetering(db);
  const freeQuote = free.quote({ tools: ['opengrep'], inputBytes: 5, fileCount: 1 });
  free.reserve({ jobId: job(4), workspaceId: 'w2', quote: freeQuote });
  free.settle({ jobId: job(4), status: 'completed', tools: complete(['opengrep']) });
  assert.equal(free.usage(job(4)).chargeMicros, 0);
  assert.equal(free.usage(job(4)).reportedTools[0].durationMs, 123);
});

test('every artifact and OpenAPI tool has a bounded, complete-only charge', () => {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: rates });
  meter.recordVerifiedPurchase({ workspaceId: 'w-new', paymentId: 'pay_fixture_new_tools', amountMicros: 5_000_000 });
  for (const [index, tool] of ['trivy-image', 'gitleaks-history', 'guarddog-npm', 'guarddog-pypi', 'spectral-owasp', 'cosign-image', 'zap-passive-har'].entries()) {
    const inputBytes = tool === 'spectral-owasp' ? 1024 : tool === 'zap-passive-har' ? 2 * 1024 * 1024 : 6 * 1024 * 1024;
    const quote = meter.quote({ tools: [tool], inputBytes, fileCount: 1 });
    assert.equal(quote.maximumMicros, rates[tool].baseMicros + (quote.inputMiB - 1) * rates[tool].additionalMiBMicros);
    assert.ok(quote.maximumMicros > 0);
    meter.reserve({ jobId: job(10 + index), workspaceId: 'w-new', quote });
    meter.settle({ jobId: job(10 + index), status: 'completed', tools: complete([tool]) });
    assert.equal(meter.usage(job(10 + index)).chargeMicros, quote.maximumMicros);
  }
  assert.ok(meter.status('w-new').balanceMicros < 5_000_000);
  assert.throws(() => meter.quote({ tools: ['trivy-image'], inputBytes: 80 * 1024 * 1024 + 1, fileCount: 1 }), /dimensions/);
  assert.throws(() => meter.quote({ tools: ['spectral-owasp'], inputBytes: 4 * 1024 * 1024 + 1, fileCount: 1 }), /dimensions/);
  assert.throws(() => meter.quote({ tools: ['zap-passive-har'], inputBytes: 2 * 1024 * 1024 + 1, fileCount: 1 }), /dimensions/);
});
