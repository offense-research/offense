import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { hostedScanTools } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createScanWhopBilling, createScanWhopProvider, SCAN_PRODUCT } from '../server/scan-whop-billing.js';

const secret = 'ws_fixture_scan_secret';
const prices = Object.fromEntries(hostedScanTools().tools.map(tool => [tool.id,
  { baseMicros: 20_000, additionalMiBMicros: tool.billingUnit === 'bounded_assessment' ? 0 : 1_000 }]));
let eventId = 0;
function signed(type, data) {
  const id = `scan_msg_${++eventId}`, timestamp = String(Math.floor(Date.now() / 1000));
  const raw = Buffer.from(JSON.stringify({ type, data }));
  return [raw, { 'webhook-id': id, 'webhook-timestamp': timestamp,
    'webhook-signature': 'v1,' + createHmac('sha256', secret).update(`${id}.${timestamp}.`).update(raw).digest('base64') }];
}
function fixture(extra = {}) {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices });
  let payment, checkoutCalls = 0, paymentCalls = 0, checkoutError = false, paymentError = false;
  let lastCheckoutOrderId, lastReturnUrl;
  let time = Date.now();
  const provider = {
    async checkout(orderId, returnUrl) { checkoutCalls++; lastCheckoutOrderId = orderId; lastReturnUrl = returnUrl;
      if (checkoutError) throw new Error('uncertain checkout response');
      return { id: `ch_${orderId}`, account_id: 'biz_scanfixture', purchase_url: 'https://whop.com/checkout/scan-fixture',
        plan: { currency: 'usd', initial_price: 10, plan_type: 'one_time' } }; },
    async payment() { paymentCalls++; if (paymentError) throw new Error('transient provider failure'); return payment; }
  };
  const billing = createScanWhopBilling(db, { meter, provider, apiKey: 'test-key', webhookSecret: secret,
    assessmentTools: hostedScanTools().tools.filter(tool => tool.billingUnit === 'bounded_assessment').map(tool => tool.id),
    enabled: true, publicUrl: 'https://app.example.test', now: () => time, ...extra });
  async function buy() {
    const order = await billing.checkout('workspace-a', 'user-a');
    payment = { id: 'pay_scanfixture', account_id: 'biz_scanfixture', checkout_configuration_id: `ch_${order.orderId}`,
      status: 'paid', currency: 'usd', total: { amount: '10.00', currency: 'usd' },
      refunded_amount: { amount: '0.00', currency: 'usd' }, metadata: { purple_order_id: order.orderId, purple_product: SCAN_PRODUCT } };
    return order;
  }
  return { db, meter, billing, buy,
    get payment() { return payment; }, get checkoutCalls() { return checkoutCalls; }, get paymentCalls() { return paymentCalls; },
    get lastCheckoutOrderId() { return lastCheckoutOrderId; }, get lastReturnUrl() { return lastReturnUrl; },
    set checkoutError(value) { checkoutError = value; }, set paymentError(value) { paymentError = value; },
    advance(ms = 60_001) { time += ms; } };
}

test('signed scanner payment is acknowledged before readback and credited once after reconciliation', async () => {
  const f = fixture();
  const order = await f.buy();
  assert.deepEqual(await f.billing.checkout('workspace-a', 'user-a'), order);
  assert.equal(f.checkoutCalls, 1);
  assert.equal(f.lastReturnUrl, 'https://app.example.test/account?scannerPayment=returned');
  const event = signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata });
  assert.deepEqual(f.billing.webhook(...event), { queued: true });
  assert.deepEqual(f.billing.webhook(...event), { queued: false });
  assert.equal(f.paymentCalls, 0);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
  assert.equal(f.billing.status('workspace-a').pendingPayments, 1);
  assert.equal(f.db.prepare('SELECT processed_at FROM scan_billing_events').get().processed_at, null);
  assert.deepEqual(await f.billing.dispatch(), { processed: 1, pending: 0 });
  assert.equal(f.paymentCalls, 1);
  assert.equal(f.db.prepare('SELECT outcome FROM scan_billing_events WHERE id = ?').get(event[1]['webhook-id']).outcome, 'credited');
  assert.equal(f.meter.status('workspace-a').balanceMicros, 10_000_000);
  assert.equal(f.billing.status('workspace-a').pendingPayments, 0);
  assert.equal(f.meter.status('workspace-b').balanceMicros, 0);
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id }));
  await f.billing.dispatch();
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_wallet_entries').get().n, 1);
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name = 'wallet_entries'").get().n, 0);
});

test('scanner payment readback retries after provider failure and pending status', async () => {
  const f = fixture(); await f.buy();
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id }));
  f.paymentError = true;
  assert.deepEqual(await f.billing.dispatch(), { processed: 0, pending: 1 });
  assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
  f.paymentError = false;
  f.advance();
  f.payment.status = 'pending';
  assert.deepEqual(await f.billing.dispatch(), { processed: 0, pending: 1 });
  f.advance();
  f.payment.status = 'paid';
  assert.deepEqual(await f.billing.dispatch(), { processed: 1, pending: 0 });
  assert.equal(f.db.prepare('SELECT attempts FROM scan_billing_events').get().attempts, 3);
  assert.equal(f.meter.status('workspace-a').balanceMicros, 10_000_000);
});

test('paid scanner orders with mismatched amount or identity enter explicit review without credit', async () => {
  for (const mismatch of [
    { currency: 'eur' }, { account_id: 'biz_other' },
    { checkout_configuration_id: 'ch_other' }, { total: { amount: '9.99', currency: 'usd' } },
    { refunded_amount: { amount: '1.00', currency: 'usd' } },
    { metadata: { purple_product: 'other-product' } }
  ]) {
    const f = fixture(); const order = await f.buy();
    Object.assign(f.payment, mismatch);
    if (mismatch.metadata) f.payment.metadata.purple_order_id = order.orderId;
    f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id }));
    assert.deepEqual(await f.billing.dispatch(), { processed: 1, pending: 0 });
    assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders').get().status, 'review');
    assert.equal(f.db.prepare("SELECT outcome FROM scan_billing_events WHERE type = 'payment.succeeded'").get().outcome, 'review');
    assert.equal(f.meter.status('workspace-a').blocked, true);
    assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
  }
});

test('a paid scanner event with no matching order remains queryable for operator review', async () => {
  const f = fixture(); await f.buy();
  f.payment.metadata.purple_order_id = 'missing_order';
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata }));
  assert.deepEqual(await f.billing.dispatch(), { processed: 1, pending: 0 });
  assert.equal(f.db.prepare("SELECT outcome FROM scan_billing_events WHERE type = 'payment.succeeded'").get().outcome, 'unmatched');
  assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
});

test('a second paid payment for one scanner order enters review without adding another credit', async () => {
  const f = fixture(); await f.buy();
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata }));
  await f.billing.dispatch();
  f.payment.id = 'pay_secondfixture';
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata }));
  await f.billing.dispatch();
  assert.equal(f.meter.status('workspace-a').balanceMicros, 10_000_000);
  assert.equal(f.meter.status('workspace-a').blocked, true);
  assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders').get().status, 'review');
});

test('payments for another Whop product do not enter the scanner reconciliation queue', () => {
  const f = fixture();
  const result = f.billing.webhook(...signed('payment.succeeded', { id: 'pay_modelwallet',
    metadata: { purple_order_id: 'some_other_order', purple_product: 'hosted-model-balance-v2' } }));
  assert.deepEqual(result, { queued: false });
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_billing_events').get().n, 0);
});

test('refund or dispute freezes a known scanner wallet immediately, including before paid reconciliation', async () => {
  for (const reversalType of ['refund.created', 'dispute.created']) {
    const f = fixture(); await f.buy();
    f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id }));
    f.billing.webhook(...signed(reversalType, { payment_id: f.payment.id,
      payment: { id: f.payment.id, metadata: f.payment.metadata } }));
    assert.equal(f.meter.status('workspace-a').blocked, true);
    await f.billing.dispatch();
    assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
    assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders').get().status, 'review');
  }
  const f = fixture(); await f.buy();
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id }));
  await f.billing.dispatch();
  f.billing.webhook(...signed('refund.created', { payment_id: f.payment.id }));
  assert.equal(f.meter.status('workspace-a').blocked, true);
  const quote = f.meter.quote({ tools: ['opengrep'], inputBytes: 5, fileCount: 1 });
  assert.throws(() => f.meter.reserve({ jobId: 'a'.repeat(32), workspaceId: 'workspace-a', quote }), error => error.status === 409);
  await assert.rejects(f.billing.checkout('workspace-a', 'user-a'), error => error.status === 409);
});

test('a dispute with no payment metadata freezes by signed success association, in either delivery order', async () => {
  for (const disputeFirst of [false, true]) {
    const f = fixture(); await f.buy();
    const success = signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata });
    const dispute = signed('dispute.created', { payment: { id: f.payment.id } });
    if (disputeFirst) { f.billing.webhook(...dispute); f.billing.webhook(...success); }
    else { f.billing.webhook(...success); f.billing.webhook(...dispute); }
    assert.equal(f.meter.status('workspace-a').blocked, true);
    await f.billing.dispatch();
    assert.equal(f.meter.status('workspace-a').balanceMicros, 0);
    assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders').get().status, 'review');
  }
});

test('uncertain checkout response reuses the same order and Whop idempotency identity', async () => {
  const f = fixture();
  f.checkoutError = true;
  await assert.rejects(f.billing.checkout('workspace-a', 'user-a'));
  const original = f.db.prepare('SELECT id FROM scan_wallet_orders').get().id;
  f.checkoutError = false;
  const order = await f.billing.checkout('workspace-a', 'user-a');
  assert.equal(order.orderId, original);
  assert.equal(f.lastCheckoutOrderId, original);
  assert.equal(f.checkoutCalls, 2);
  assert.equal(f.db.prepare('SELECT COUNT(*) AS n FROM scan_wallet_orders').get().n, 1);
});

test('one workspace shares a pending checkout and abandons it after 20 minutes', async () => {
  const f = fixture();
  const first = await f.billing.checkout('workspace-a', 'user-a');
  assert.deepEqual(await f.billing.checkout('workspace-a', 'user-b'), first);
  assert.equal(f.checkoutCalls, 1);
  assert.equal(f.billing.status('workspace-a').pendingPurchases, 1);
  f.advance(20 * 60_000 + 1);
  const second = await f.billing.checkout('workspace-a', 'user-b');
  assert.notEqual(second.orderId, first.orderId);
  assert.equal(f.checkoutCalls, 2);
  assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders WHERE id = ?').get(first.orderId).status, 'abandoned');
});

test('late valid payments still receive credit even if another load has reached the cap', async () => {
  const f = fixture(); const first = await f.buy();
  f.advance(20 * 60_000 + 1);
  await f.billing.checkout('workspace-a', 'user-b');
  f.billing.webhook(...signed('payment.succeeded', { id: f.payment.id, metadata: f.payment.metadata }));
  await f.billing.dispatch();
  assert.equal(f.db.prepare('SELECT status FROM scan_wallet_orders WHERE id = ?').get(first.orderId).status, 'paid');
  assert.equal(f.meter.status('workspace-a').balanceMicros, 10_000_000);

  const over = fixture(); const late = await over.buy();
  over.advance(20 * 60_000 + 1);
  await over.billing.checkout('workspace-a', 'user-b');
  for (let i = 0; i < 5; i++) over.meter.recordVerifiedPurchase({ workspaceId: 'workspace-a',
    paymentId: `pay_prior_${i}`, amountMicros: 10_000_000 });
  over.billing.webhook(...signed('payment.succeeded', { id: over.payment.id, metadata: over.payment.metadata }));
  await over.billing.dispatch();
  assert.equal(over.db.prepare('SELECT status FROM scan_wallet_orders WHERE id = ?').get(late.orderId).status, 'paid');
  assert.equal(over.billing.status('workspace-a').reviewPurchases, 0);
  assert.equal(over.meter.status('workspace-a').blocked, false);
  assert.equal(over.meter.status('workspace-a').balanceMicros, 60_000_000);
  await assert.rejects(over.billing.checkout('workspace-a', 'user-a'), error => error.status === 409);
});

test('new scanner checkout is capped at $50 of prepaid credit', async () => {
  const f = fixture();
  for (let i = 0; i < 5; i++) f.meter.recordVerifiedPurchase({ workspaceId: 'workspace-a',
    paymentId: `pay_prior_${i}`, amountMicros: 10_000_000 });
  await assert.rejects(f.billing.checkout('workspace-a', 'user-a'), error => error.status === 409);
  assert.equal(f.checkoutCalls, 0);
});

test('scanner status exposes a fixed $10 load and the per-tool first and additional MiB prices', () => {
  const f = fixture();
  const status = f.billing.status('workspace-a');
  assert.equal(status.purchaseCents, 1000);
  assert.equal(status.maxBalanceMicros, 50_000_000);
  assert.equal(status.pendingPurchases, 0);
  assert.equal(status.pendingPayments, 0);
  assert.equal(status.prices.length, hostedScanTools().tools.length);
  assert.deepEqual(status.prices.find(price => price.id === 'opengrep'), {
    id: 'opengrep', name: 'Source code security', unit: 'first_mib_plus_additional_started_mib', basePriceMicros: 20_000, additionalMiBPriceMicros: 1_000
  });
  assert.equal(status.prices.find(price => price.id === 'nuclei').unit, 'bounded_assessment');
});

test('legacy scanner event table upgrades in place without losing queued events', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE scan_billing_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, payment_id TEXT NOT NULL, created_at INTEGER NOT NULL)');
  db.prepare('INSERT INTO scan_billing_events VALUES (?, ?, ?, ?)').run('old-event', 'payment.succeeded', 'pay_old', 1);
  const meter = createScanMetering(db);
  createScanWhopBilling(db, { meter });
  assert.equal(db.prepare('SELECT id, processed_at, attempts FROM scan_billing_events').get().id, 'old-event');
  assert.equal(db.prepare('SELECT attempts FROM scan_billing_events').get().attempts, 0);
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE name = 'scan_billing_events_pending'").get());
});

test('additive D1 scanner payment migration preserves existing event rows', () => {
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE scan_billing_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, payment_id TEXT NOT NULL, created_at INTEGER NOT NULL)');
  db.prepare('INSERT INTO scan_billing_events VALUES (?, ?, ?, ?)').run('old-event', 'payment.succeeded', 'pay_old', 1);
  db.exec(readFileSync(new URL('../migrations/0004_scan_payment_reconciliation.sql', import.meta.url), 'utf8'));
  assert.equal(db.prepare('SELECT attempts FROM scan_billing_events WHERE id = ?').get('old-event').attempts, 0);
  assert.equal(db.prepare('SELECT processed_at FROM scan_billing_events WHERE id = ?').get('old-event').processed_at, null);
  assert.equal(db.prepare('SELECT outcome FROM scan_billing_events WHERE id = ?').get('old-event').outcome, null);
});

test('scanner purchase path remains disabled without explicit scanner terms and funding configuration', async () => {
  const db = new DatabaseSync(':memory:');
  const meter = createScanMetering(db);
  const billing = createScanWhopBilling(db, { meter, enabled: true, apiKey: 'test', webhookSecret: secret });
  assert.equal(billing.status('w').checkoutEnabled, false);
  await assert.rejects(billing.checkout('w', 'u'), error => error.status === 503);
});

test('Whop scanner checkout sends separate product, $10 fixed price and idempotency key', async () => {
  let request;
  const provider = createScanWhopProvider({ apiKey: 'fixture-key', fetchImpl: async (url, options) => {
    request = { url, ...options, body: JSON.parse(options.body) };
    return { ok: true, json: async () => ({ id: 'ch_test' }) };
  } });
  await provider.checkout('order_fixture', 'https://app.example.test/return');
  assert.equal(request.url, 'https://api.whop.com/api/v1/checkout_configurations');
  assert.equal(request.headers['Idempotency-Key'], 'purple-scan-checkout-order_fixture');
  assert.equal(request.body.plan.initial_price, 10);
  assert.equal(request.body.plan.currency, 'usd');
  assert.equal(request.body.plan.plan_type, 'one_time');
  assert.equal(request.body.metadata.purple_product, SCAN_PRODUCT);
  assert.match(request.body.plan.description, /scanner credit/i);
  assert.ok(!request.body.plan.description.includes('OpenRouter'));
});
