import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { createAccounts } from '../server/accounts.js';
import { hostedScanTools } from '../server/hosted-scans.js';
import { createScanMetering } from '../server/scan-metering.js';
import { createScanWhopBilling, createScanWhopProvider, registerScanBillingRoutes } from '../server/scan-whop-billing.js';
import { AUTO_TOPUP_CONSENT, AUTO_TOPUP_PRODUCT, AUTO_TOPUP_SCHEMA, createScanAutoTopUp } from '../server/scan-auto-topup.js';
import { WHOP_API_VERSION } from '../server/whop-billing.js';

const workspace = 'workspace-a', otherWorkspace = 'workspace-b', secret = 'ws_auto_fixture_secret';
let eventCounter = 0;
function signed(type, data) {
  const id = `auto_msg_${++eventCounter}`, timestamp = String(Math.floor(Date.now() / 1000));
  const raw = Buffer.from(JSON.stringify({ type, data }));
  return [raw, { 'webhook-id': id, 'webhook-timestamp': timestamp,
    'webhook-signature': 'v1,' + createHmac('sha256', secret).update(`${id}.${timestamp}.`).update(raw).digest('base64') }];
}
function fixture() {
  const db = new DatabaseSync(':memory:'), accounts = createAccounts(db);
  const user = accounts.upsertUser('100', 'owner'), otherUser = accounts.upsertUser('200', 'other');
  accounts.createWorkspace(user.id, workspace, {}); accounts.createWorkspace(otherUser.id, otherWorkspace, {});
  let time = Date.now(), sequence = 0, setupCalls = 0, postCalls = 0, reads = 0;
  let setupHook, topUpHook, paymentHook, paymentStatus = 'paid';
  const payments = new Map(), setups = new Map();
  const prices = Object.fromEntries(hostedScanTools().tools.map(tool => [tool.id, { baseMicros: 1_000_000, additionalMiBMicros: 0 }]));
  const meter = createScanMetering(db, { enabled: true, priceByToolMicros: prices, now: () => time });
  const metadata = id => ({ purple_order_id: id, purple_product: AUTO_TOPUP_PRODUCT, offense_consent_version: AUTO_TOPUP_CONSENT });
  const provider = {
    async checkout() { throw new Error('Manual checkout is not part of this fixture.'); },
    async setupCheckout(id, url) {
      setupCalls++;
      const receipt = { id: `sint_${id}`, status: 'succeeded', checkout_configuration_id: `ch_${id}`,
        account_id: 'biz_fixture', member_id: 'mber_fixture', payment_method_id: 'payt_fixture', metadata: metadata(id) };
      setups.set(receipt.id, receipt);
      if (setupHook) await setupHook(id, receipt, url);
      return { id: `ch_${id}`, account_id: receipt.account_id, mode: 'setup', purchase_url: `https://whop.com/checkout/${id}` };
    },
    async setupIntent(id) { reads++; return structuredClone(setups.get(id)); },
    async topUp(id, saved) {
      postCalls++;
      const receipt = { id: `pay_auto${++sequence}`, status: paymentStatus, account_id: saved.account_id, member_id: saved.member_id,
        payment_method_id: saved.payment_method_id, metadata: metadata(id), currency: 'usd', total: { amount: '10.00', currency: 'usd' }, refunded_amount: '0' };
      payments.set(receipt.id, receipt);
      if (topUpHook) return topUpHook(id, saved, receipt);
      return { id: receipt.id };
    },
    async payment(id) { reads++; if (paymentHook) return paymentHook(id); return structuredClone(payments.get(id)); }
  };
  const billing = createScanWhopBilling(db, { meter, provider, apiKey: 'fixture', webhookSecret: secret, enabled: true,
    publicUrl: 'https://offense.example', now: () => time });
  const auto = createScanAutoTopUp(db, { meter, provider, configured: true, publicUrl: 'https://offense.example', now: () => time });
  function seed(amount = 10_000_000) { meter.recordVerifiedPurchase({ workspaceId: workspace, paymentId: `pay_seed${++sequence}`, amountMicros: amount }); }
  function spend(amount) { db.prepare("INSERT INTO scan_wallet_entries VALUES (?,?,?,'charge',?)").run(`test_spend_${++sequence}`, workspace, -amount, time); }
  async function consent() {
    const order = await billing.setupAuto(workspace, user.id);
    const receipt = setups.get(`sint_${order.orderId}`);
    billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata }));
    await billing.dispatch();
    return receipt;
  }
  function autoOrder() { return db.prepare("SELECT * FROM scan_auto_topup_orders WHERE kind = 'topup' ORDER BY created_at DESC,id DESC LIMIT 1").get(); }
  return { db, meter, accounts, user, otherUser, provider, billing, auto, setups, payments, consent, seed, spend, metadata, autoOrder,
    advance(ms = 60_001) { time += ms; },
    get setupCalls() { return setupCalls; }, get postCalls() { return postCalls; }, get reads() { return reads; },
    set setupHook(fn) { setupHook = fn; }, set topUpHook(fn) { topUpHook = fn; }, set paymentHook(fn) { paymentHook = fn; },
    set paymentStatus(status) { paymentStatus = status; } };
}

test('automatic credit is off by default and status only discloses policy and owner permission', async () => {
  const f = fixture();
  assert.deepEqual(f.billing.status(workspace, f.user.id).autoTopUp, { available: true, canManage: true, enabled: false,
    pendingSetup: false, amountCents: 1000, thresholdMicros: 2_000_000, dailyLimitCents: 2000,
    consentVersion: AUTO_TOPUP_CONSENT, pending: false, error: null });
  assert.equal(f.billing.status(workspace).autoTopUp.canManage, false);
  assert.equal(f.billing.status(workspace, f.otherUser.id).autoTopUp.canManage, false);
  await assert.rejects(f.billing.setupAuto(workspace, f.otherUser.id), { status: 403 });
  assert.throws(() => f.billing.disableAuto(workspace, f.otherUser.id), { status: 403 });
  await assert.rejects(f.billing.setupAuto(otherWorkspace, f.user.id), { status: 403 });
  await f.billing.dispatch(); assert.equal(f.setupCalls + f.postCalls, 0);
});

test('hosted setup saves a method without charging and requires independently fetched success', async () => {
  const f = fixture(); f.seed();
  const setup = await f.billing.setupAuto(workspace, f.user.id);
  assert.deepEqual(await f.billing.setupAuto(workspace, f.user.id), setup);
  assert.equal(f.setupCalls, 1); assert.equal(f.postCalls, 0);
  assert.equal(f.billing.status(workspace).autoTopUp.pendingSetup, true);
  const receipt = f.setups.get(`sint_${setup.orderId}`);
  const event = signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata });
  assert.deepEqual(f.billing.webhook(...event), { queued: true });
  assert.deepEqual(f.billing.webhook(...event), { queued: false });
  assert.equal(f.reads, 0); assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  await f.billing.dispatch();
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, true);
  const status = JSON.stringify(f.billing.status(workspace));
  for (const privateValue of ['biz_fixture', 'mber_fixture', 'payt_fixture', 'https://whop.com', setup.orderId])
    assert.equal(status.includes(privateValue), false);
  assert.equal(f.postCalls, 0); assert.equal(f.meter.status(workspace).balanceMicros, 10_000_000);
});

test('setup readback rejects account, checkout, metadata, method, or consent identity mismatches', async () => {
  for (const mismatch of [{ account_id: 'biz_other' }, { checkout_configuration_id: 'ch_other' }, { payment_method_id: 'bad' },
    { metadata: { purple_product: 'other', offense_consent_version: AUTO_TOPUP_CONSENT } },
    { metadata: { purple_product: AUTO_TOPUP_PRODUCT, offense_consent_version: 'old-version' } }]) {
    const f = fixture(); f.seed(); const setup = await f.billing.setupAuto(workspace, f.user.id);
    const receipt = f.setups.get(`sint_${setup.orderId}`);
    Object.assign(receipt, mismatch); receipt.metadata.purple_order_id = setup.orderId;
    f.billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: f.metadata(setup.orderId) }));
    await f.billing.dispatch();
    assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
    assert.equal(f.db.prepare('SELECT status FROM scan_auto_topup_orders').get().status, 'review');
    assert.equal(f.postCalls, 0);
  }
});

test('a setup event arriving before its checkout response waits for the durable checkout binding', async () => {
  const f = fixture(); f.seed();
  f.setupHook = async (id, receipt) => {
    f.billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata }));
    await f.billing.dispatch();
    assert.equal(f.db.prepare('SELECT status FROM scan_auto_topup_orders WHERE id = ?').get(id).status, 'pending');
  };
  await f.billing.setupAuto(workspace, f.user.id);
  f.advance(); await f.billing.dispatch();
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, true);
});

test('disable invalidates setup consent and late webhooks cannot re-enable automatic payments', async () => {
  const f = fixture(); f.seed();
  const setup = await f.billing.setupAuto(workspace, f.user.id), receipt = f.setups.get(`sint_${setup.orderId}`);
  const result = f.billing.disableAuto(workspace, f.user.id);
  assert.equal(result.autoTopUp.canManage, true);
  f.billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata }));
  await f.billing.dispatch();
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  assert.equal(f.db.prepare('SELECT outcome FROM scan_auto_topup_events').get().outcome, 'canceled');
  for (const field of ['consent_id', 'consent_version', 'account_id', 'member_id', 'payment_method_id'])
    assert.equal(f.db.prepare('SELECT * FROM scan_auto_topup_preferences').get()[field], null);
  assert.equal(f.postCalls, 0);
});

test('disabling while setup is being prepared cancels the returned setup URL', async () => {
  const f = fixture(); f.seed(); f.setupHook = async () => { f.billing.disableAuto(workspace, f.user.id); };
  await assert.rejects(f.billing.setupAuto(workspace, f.user.id), { status: 409 });
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
});

test('stale setup stops polling, cannot activate from a late event, and can be replaced', async () => {
  const f = fixture(); f.seed();
  let returnUrl;
  f.setupHook = async (id, receipt, url) => { returnUrl = url; };
  const setup = await f.billing.setupAuto(workspace, f.user.id), receipt = f.setups.get(`sint_${setup.orderId}`);
  assert.equal(returnUrl, 'https://offense.example/billing?scannerSetup=returned');
  f.advance(20 * 60_000);
  assert.equal(f.billing.status(workspace).autoTopUp.pendingSetup, false);
  f.billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata }));
  await f.billing.dispatch();
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  assert.equal(f.db.prepare('SELECT status FROM scan_auto_topup_orders WHERE id = ?').get(setup.orderId).status, 'canceled');
  assert.notEqual((await f.billing.setupAuto(workspace, f.user.id)).orderId, setup.orderId);
});

test('revoked ownership prevents setup activation and subsequent automatic charges', async () => {
  const f = fixture(); f.seed();
  const setup = await f.billing.setupAuto(workspace, f.user.id), receipt = f.setups.get(`sint_${setup.orderId}`);
  f.db.prepare("UPDATE memberships SET role = 'member' WHERE workspace_id = ?").run(workspace);
  f.billing.webhook(...signed('setup_intent.succeeded', { id: receipt.id, metadata: receipt.metadata })); await f.billing.dispatch();
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  assert.equal(f.billing.status(workspace, f.user.id).autoTopUp.canManage, false);
  const g = fixture(); g.seed(); await g.consent(); g.spend(9_000_000);
  g.db.prepare("DELETE FROM memberships WHERE workspace_id = ?").run(workspace);
  await g.billing.dispatch(); assert.equal(g.postCalls, 0);
  assert.equal(g.billing.status(workspace).autoTopUp.enabled, false);
});

test('only settled balance below $2 triggers a refill; reservations never do', async () => {
  const f = fixture(); f.seed(); await f.consent();
  f.db.prepare("INSERT INTO scan_meter_jobs VALUES (?,?, 'reserved','{}',9000000,0,NULL,?,?)").run('a'.repeat(32), workspace, Date.now(), Date.now());
  assert.equal(f.meter.status(workspace).availableMicros, 1_000_000);
  await f.billing.dispatch(); assert.equal(f.postCalls, 0);
  f.spend(8_000_000); await f.billing.dispatch(); assert.equal(f.postCalls, 0);
  f.spend(1); await f.billing.dispatch(); assert.equal(f.postCalls, 1);
  assert.equal(f.meter.status(workspace).balanceMicros, 11_999_999);
});

test('an automatic payment snapshots consent before submission and credits a verified receipt only once', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  f.topUpHook = async (id, saved, receipt) => {
    const stored = f.db.prepare('SELECT * FROM scan_auto_topup_orders WHERE id = ?').get(id);
    assert.equal(stored.status, 'submitting'); assert.equal(stored.amount_cents, 1000);
    for (const field of ['consent_id', 'account_id', 'member_id', 'payment_method_id']) assert.equal(stored[field], saved[field]);
    assert.equal(f.meter.status(workspace).balanceMicros, 1_000_000);
    return { id: receipt.id };
  };
  await f.billing.dispatch();
  const order = f.autoOrder(), receipt = f.payments.get(order.payment_id);
  assert.equal(order.status, 'paid'); assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
  const event = signed('payment.succeeded', { id: receipt.id, metadata: receipt.metadata });
  f.billing.webhook(...event); f.billing.webhook(...event); await f.billing.dispatch();
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_entries WHERE id = ?").get(`purchase:${receipt.id}`).n, 1);
  assert.equal(f.meter.status(otherWorkspace).balanceMicros, 0);
});

test('uncertain payment responses permanently block a new POST, including after idempotency expiration', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  f.topUpHook = async () => { throw new Error('Response lost after provider may have charged.'); };
  await f.billing.dispatch();
  assert.equal(f.postCalls, 1); assert.equal(f.autoOrder().status, 'attention');
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  assert.equal(f.billing.status(workspace).autoTopUp.pending, true);
  f.advance(25 * 60 * 60_000);
  f.billing.disableAuto(workspace, f.user.id);
  await assert.rejects(f.billing.setupAuto(workspace, f.user.id), { status: 409 });
  await f.billing.dispatch(); await f.auto.maybeTopUp(workspace);
  assert.equal(f.postCalls, 1);
  const receipt = [...f.payments.values()][0];
  f.billing.webhook(...signed('payment.succeeded', { id: receipt.id, metadata: receipt.metadata })); await f.billing.dispatch();
  assert.equal(f.autoOrder().status, 'paid'); assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
});

test('pending receipts reconcile using GET only without needing another webhook', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000); f.paymentStatus = 'pending';
  await f.billing.dispatch(); assert.equal(f.autoOrder().status, 'pending');
  assert.equal(f.meter.status(workspace).balanceMicros, 1_000_000);
  const receipt = f.payments.get(f.autoOrder().payment_id); receipt.status = 'paid';
  f.advance(); await f.billing.dispatch();
  assert.equal(f.postCalls, 1); assert.equal(f.autoOrder().status, 'paid');
  assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
});

test('requires-action and failed payments pause auto top-up without adding credit', async () => {
  for (const paymentStatus of ['requires_action', 'failed', 'canceled']) {
    const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000); f.paymentStatus = paymentStatus;
    await f.billing.dispatch();
    assert.equal(f.postCalls, 1); assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
    assert.equal(f.meter.status(workspace).balanceMicros, 1_000_000);
    if (paymentStatus === 'requires_action') await assert.rejects(f.billing.setupAuto(workspace, f.user.id), { status: 409 });
    else assert.ok((await f.billing.setupAuto(workspace, f.user.id)).url);
  }
});

test('a different failed payment cannot replace an unresolved charge and rearm automatic billing', async () => {
  for (const changed of [{ id: 'pay_foreignfailed' }, { payment_method_id: 'payt_other' },
    { metadata: { purple_product: 'other', offense_consent_version: AUTO_TOPUP_CONSENT } }]) {
    const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000); f.paymentStatus = 'pending';
    await f.billing.dispatch(); const original = f.autoOrder();
    const receipt = structuredClone(f.payments.get(original.payment_id));
    Object.assign(receipt, changed, { status: 'failed' }); receipt.metadata.purple_order_id = original.id;
    f.payments.set(receipt.id, receipt);
    f.billing.webhook(...signed('payment.failed', { id: receipt.id, metadata: receipt.metadata }));
    await f.billing.dispatch();
    assert.equal(f.autoOrder().status, 'review'); assert.equal(f.autoOrder().payment_id, original.payment_id);
    assert.equal(f.billing.status(workspace).autoTopUp.pending, true);
    await assert.rejects(f.billing.setupAuto(workspace, f.user.id), { status: 409 });
    f.advance(25 * 60 * 60_000); await f.billing.dispatch(); assert.equal(f.postCalls, 1);
    assert.equal(f.meter.status(workspace).balanceMicros, 1_000_000);
  }
});

test('refund or dispute before payment receipt, and after credit, freezes the wallet and pauses refills', async () => {
  for (const type of ['refund.created', 'dispute.created']) for (const before of [true, false]) {
    const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
    if (before) f.topUpHook = async (id, saved, receipt) => {
      f.billing.webhook(...signed(type, { payment_id: receipt.id }));
      return { id: receipt.id };
    };
    await f.billing.dispatch();
    if (!before) f.billing.webhook(...signed(type, { payment_id: f.autoOrder().payment_id }));
    assert.equal(f.meter.status(workspace).blocked, true);
    assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
    assert.equal(f.autoOrder().status, 'review');
    assert.equal(f.meter.status(workspace).balanceMicros, before ? 1_000_000 : 11_000_000);
    f.advance(); await f.billing.dispatch(); assert.equal(f.postCalls, 1);
  }
});

test('a repeated success event still checks for refunds in the fetched payment receipt', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000); await f.billing.dispatch();
  const receipt = f.payments.get(f.autoOrder().payment_id); receipt.refunded_amount = '1.00';
  f.billing.webhook(...signed('payment.succeeded', { id: receipt.id, metadata: receipt.metadata }));
  await f.billing.dispatch();
  assert.equal(f.meter.status(workspace).blocked, true); assert.equal(f.autoOrder().status, 'review');
  assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
});

test('a second paid receipt for one automatic order enters review instead of adding another credit', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000); await f.billing.dispatch();
  const receipt = structuredClone(f.payments.get(f.autoOrder().payment_id)); receipt.id = 'pay_unexpectedsecond';
  f.payments.set(receipt.id, receipt);
  f.billing.webhook(...signed('payment.succeeded', { id: receipt.id, metadata: receipt.metadata }));
  await f.billing.dispatch();
  assert.equal(f.meter.status(workspace).blocked, true); assert.equal(f.autoOrder().status, 'review');
  assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
});

test('a readback timeout after receiving a payment ID pauses and later reconciles without another POST', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  f.paymentHook = async () => { throw new Error('Receipt is temporarily unavailable.'); };
  await f.billing.dispatch();
  assert.equal(f.autoOrder().status, 'attention'); assert.ok(f.autoOrder().payment_id);
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  f.paymentHook = undefined; f.advance(); await f.billing.dispatch();
  assert.equal(f.autoOrder().status, 'paid'); assert.equal(f.postCalls, 1);
  assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
});

test('payment readback rejects mismatched identity, amount, currency, refunds and metadata', async () => {
  for (const mismatch of [{ account_id: 'biz_other' }, { member_id: 'mber_other' }, { payment_method_id: 'payt_other' },
    { currency: 'eur' }, { total: { amount: '9.99' } }, { refunded_amount: '1.00' }, { auto_refunded: true },
    { metadata: { purple_product: 'other', offense_consent_version: AUTO_TOPUP_CONSENT } }]) {
    const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
    f.topUpHook = async (id, saved, receipt) => { Object.assign(receipt, mismatch); receipt.metadata.purple_order_id = id; return { id: receipt.id }; };
    await f.billing.dispatch();
    assert.equal(f.autoOrder().status, 'review'); assert.equal(f.meter.status(workspace).blocked, true);
    assert.equal(f.meter.status(workspace).balanceMicros, 1_000_000);
  }
});

test('two refills per rolling day are allowed, then the third waits until the window moves', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  await f.billing.dispatch(); f.advance(); f.spend(10_000_000); await f.billing.dispatch();
  assert.equal(f.postCalls, 2);
  f.advance(); f.spend(10_000_000); await f.billing.dispatch();
  assert.equal(f.postCalls, 2); assert.match(f.billing.status(workspace).autoTopUp.error, /24 hours/);
  f.advance(24 * 60 * 60_000); await f.billing.dispatch(); assert.equal(f.postCalls, 3);
});

test('concurrent dispatchers durably reserve one automatic order before the provider call', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  let finish; const gate = new Promise(resolve => { finish = resolve; });
  f.topUpHook = async (id, saved, receipt) => { await gate; return { id: receipt.id }; };
  const first = f.auto.maybeTopUp(workspace);
  const second = createScanAutoTopUp(f.db, { meter: f.meter, provider: f.provider, configured: true,
    publicUrl: 'https://offense.example' }).maybeTopUp(workspace);
  await second; assert.equal(f.postCalls, 1); finish(); await first;
  assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM scan_auto_topup_orders WHERE kind = 'topup'").get().n, 1);
});

test('disabling while an already issued payment finishes keeps credit but prevents another charge', async () => {
  const f = fixture(); f.seed(); await f.consent(); f.spend(9_000_000);
  f.topUpHook = async (id, saved, receipt) => { f.billing.disableAuto(workspace, f.user.id); return { id: receipt.id }; };
  await f.billing.dispatch(); assert.equal(f.meter.status(workspace).balanceMicros, 11_000_000);
  assert.equal(f.billing.status(workspace).autoTopUp.enabled, false);
  f.spend(10_000_000); f.advance(); await f.billing.dispatch(); assert.equal(f.postCalls, 1);
});

test('browser route only accepts current explicit policy consent and resolves workspace and owner from the session', async () => {
  const f = fixture(), routes = new Map();
  const app = Object.fromEntries(['get', 'post', 'delete'].map(method => [method, (path, handler) => routes.set(`${method} ${path}`, handler)]));
  registerScanBillingRoutes(app, f.billing);
  async function call(method, body, user = f.user.id) {
    const res = { code: 200, status(code) { this.code = code; return this; }, json(data) { this.body = data; return this; } };
    await routes.get(`${method} /api/scanner-billing/auto-top-up`)({ workspaceId: workspace, authUser: { id: user }, body }, res);
    return res;
  }
  for (const body of [undefined, [], { enabled: true }, { enabled: true, consentVersion: 'old' },
    { enabled: true, consentVersion: AUTO_TOPUP_CONSENT, workspaceId: otherWorkspace },
    { enabled: true, consentVersion: AUTO_TOPUP_CONSENT, amountCents: 100_000 }]) assert.equal((await call('post', body)).code, 400);
  assert.equal((await call('post', { enabled: true, consentVersion: AUTO_TOPUP_CONSENT }, f.otherUser.id)).code, 403);
  assert.equal(f.setupCalls, 0);
  assert.equal((await call('post', { enabled: true, consentVersion: AUTO_TOPUP_CONSENT })).code, 200);
  assert.equal((await call('delete', undefined, f.otherUser.id)).code, 403);
  assert.equal((await call('delete')).body.billing.autoTopUp.enabled, false);
});

test('provider requests use zero-charge setup and fixed $10 USD off-session purchase with stable order keys', async () => {
  const requests = [];
  const provider = createScanWhopProvider({ apiKey: 'fixture', fetchImpl: async (url, options) => {
    requests.push({ url, ...options, body: options.body && JSON.parse(options.body) }); return { ok: true, json: async () => ({ id: 'fixture' }) };
  } });
  await provider.setupCheckout('order1', 'https://offense.example/account');
  await provider.setupIntent('sint_fixture');
  const saved = { account_id: 'biz_fixture', member_id: 'mber_fixture', payment_method_id: 'payt_fixture' };
  await provider.topUp('order2', saved); await provider.topUp('order2', saved);
  assert.equal(requests[0].body.mode, 'setup'); assert.equal(requests[0].body.plan, undefined);
  assert.equal(requests[1].method, 'GET'); assert.match(requests[1].url, /setup_intents\/sint_fixture$/);
  assert.equal(requests[2].body.off_session, true); assert.equal(requests[2].body.plan.initial_price, 10);
  assert.equal(requests[2].body.plan.currency, 'usd'); assert.equal(requests[2].body.plan.plan_type, 'one_time');
  for (const field of Object.keys(saved)) assert.equal(requests[2].body[field], saved[field]);
  assert.equal(requests[2].headers['Api-Version-Date'], WHOP_API_VERSION);
  assert.equal(requests[2].headers['Idempotency-Key'], requests[3].headers['Idempotency-Key']);
  assert.equal(requests[2].headers['Idempotency-Key'], 'offense-scan-auto-order2');
});

test('auto top-up migration is additive and matches runtime tables', () => {
  const db = new DatabaseSync(':memory:');
  db.exec("CREATE TABLE scan_wallet_entries (id TEXT PRIMARY KEY, workspace_id TEXT, amount_micros INTEGER, kind TEXT, created_at INTEGER); INSERT INTO scan_wallet_entries VALUES ('existing','workspace',10000000,'purchase',1)");
  const migration = readFileSync(new URL('../migrations/0010_scan_auto_topup.sql', import.meta.url), 'utf8');
  db.exec(migration); db.exec(AUTO_TOPUP_SCHEMA);
  assert.equal(db.prepare('SELECT amount_micros FROM scan_wallet_entries').get().amount_micros, 10_000_000);
  for (const table of ['preferences', 'orders', 'events']) assert.ok(db.prepare('SELECT name FROM sqlite_master WHERE name = ?').get(`scan_auto_topup_${table}`));
});
