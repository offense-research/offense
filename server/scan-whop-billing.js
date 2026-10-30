import { randomBytes } from 'node:crypto';
import { transactionSync } from './db-transaction.js';
import { hostedScanTools } from './hosted-scans.js';
import { verifyWhopWebhook, WHOP_API_VERSION } from './whop-billing.js';
import { assessmentTool } from '../shared/assessment-tools.js';
import { createScanAutoTopUp, AUTO_TOPUP_PRODUCT, AUTO_TOPUP_CONSENT, AUTO_TOPUP_CENTS } from './scan-auto-topup.js';

export const SCAN_CREDIT_CENTS = 1000;
export const SCAN_CREDIT_MICROS = SCAN_CREDIT_CENTS * 10_000;
export const SCAN_PRODUCT = 'scanner-credit-v1';
const MAX_SCAN_BALANCE_MICROS = 50_000_000;
const PENDING_CHECKOUT_MS = 20 * 60_000;
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const validId = (value, prefix) => typeof value === 'string' && new RegExp(`^${prefix}_[A-Za-z0-9_-]+$`).test(value);

function cents(value) {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(String(value?.amount ?? value));
  if (!match || match[1].length > 10 || /[1-9]/.test((match[2] || '').slice(2))) return null;
  return Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0').slice(0, 2));
}
function checkoutUrl(value) {
  let url; try { url = new URL(value); } catch { throw fail('Whop returned an invalid scanner checkout.', 502); }
  if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname) || url.username || url.password)
    throw fail('Whop returned an invalid scanner checkout.', 502);
  return url.href;
}

export function createScanWhopProvider({ apiKey, sandbox = false, fetchImpl = fetch }) {
  const base = sandbox ? 'https://sandbox-api.whop.com/api/v1' : 'https://api.whop.com/api/v1';
  async function request(path, data, idempotencyKey) {
    const response = await fetchImpl(base + path, { method: data ? 'POST' : 'GET',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json', 'Api-Version-Date': WHOP_API_VERSION,
        ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}) },
      ...(data ? { body: JSON.stringify(data) } : {}), signal: AbortSignal.timeout(15_000) });
    if (!response.ok) throw fail(`Whop scanner payment service returned HTTP ${response.status}.`, 502);
    return response.json();
  }
  return {
    checkout: (orderId, returnUrl) => request('/checkout_configurations', {
      plan: { title: 'Offense scanner credit',
        description: '$10 prepaid scanner credit. Each scan displays its maximum USD charge before submission. No subscription.',
        plan_type: 'one_time', initial_price: 10, currency: 'usd', visibility: 'hidden',
        force_create_new_plan: true, stock: 1, unlimited_stock: false },
      mode: 'payment', redirect_url: returnUrl,
      metadata: { purple_order_id: orderId, purple_product: SCAN_PRODUCT }
    }, `purple-scan-checkout-${orderId}`),
    payment: id => request(`/payments/${encodeURIComponent(id)}`),
    setupCheckout: (orderId, returnUrl) => request('/checkout_configurations', {
      mode: 'setup', currency: 'usd', redirect_url: returnUrl,
      metadata: { purple_order_id: orderId, purple_product: AUTO_TOPUP_PRODUCT, offense_consent_version: AUTO_TOPUP_CONSENT }
    }, `offense-scan-setup-${orderId}`),
    setupIntent: id => request(`/setup_intents/${encodeURIComponent(id)}`),
    topUp: (orderId, saved) => request('/payments', {
      account_id: saved.account_id, member_id: saved.member_id, payment_method_id: saved.payment_method_id,
      off_session: true,
      plan: { title: 'Offense automatic credit', description: '$10 prepaid security-tool credit. Automatic refill authorized in Offense billing settings.',
        plan_type: 'one_time', initial_price: AUTO_TOPUP_CENTS / 100, currency: 'usd', visibility: 'hidden', force_create_new_plan: true },
      metadata: { purple_order_id: orderId, purple_product: AUTO_TOPUP_PRODUCT, offense_consent_version: AUTO_TOPUP_CONSENT }
    }, `offense-scan-auto-${orderId}`)
  };
}

export function createScanWhopBilling(db, { meter, apiKey, webhookSecret, enabled = false,
  sandbox = false, publicUrl, provider, assessmentTools = [], verify = verifyWhopWebhook, now = Date.now } = {}) {
  if (!meter) throw new Error('Scanner metering is required.');
  const configured = !!enabled && !!apiKey && !!webhookSecret && meter.status('__configuration__').enabled;
  provider ||= createScanWhopProvider({ apiKey, sandbox });
  db.exec(`CREATE TABLE IF NOT EXISTS scan_wallet_orders (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL,
    checkout_id TEXT UNIQUE, checkout_url TEXT, account_id TEXT, payment_id TEXT UNIQUE,
    amount_cents INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  ); CREATE INDEX IF NOT EXISTS scan_wallet_orders_workspace ON scan_wallet_orders(workspace_id, created_at);
  CREATE TABLE IF NOT EXISTS scan_billing_events (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, payment_id TEXT NOT NULL, order_id TEXT, created_at INTEGER NOT NULL,
    processed_at INTEGER, last_attempt_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0, outcome TEXT
  ); CREATE INDEX IF NOT EXISTS scan_billing_events_payment ON scan_billing_events(payment_id);`);
  const eventColumns = new Set(db.prepare('PRAGMA table_info(scan_billing_events)').all().map(column => column.name));
  if (!eventColumns.has('order_id')) db.exec('ALTER TABLE scan_billing_events ADD COLUMN order_id TEXT');
  if (!eventColumns.has('processed_at')) db.exec('ALTER TABLE scan_billing_events ADD COLUMN processed_at INTEGER');
  if (!eventColumns.has('last_attempt_at')) db.exec('ALTER TABLE scan_billing_events ADD COLUMN last_attempt_at INTEGER');
  if (!eventColumns.has('attempts')) db.exec('ALTER TABLE scan_billing_events ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0');
  if (!eventColumns.has('outcome')) db.exec('ALTER TABLE scan_billing_events ADD COLUMN outcome TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS scan_billing_events_pending ON scan_billing_events(type, processed_at, last_attempt_at, created_at)');
  const autoTopUp = createScanAutoTopUp(db, { meter, provider, configured, publicUrl, now });
  const orderFor = id => db.prepare('SELECT * FROM scan_wallet_orders WHERE id = ?').get(id);
  function status(workspaceId, userId) {
    const prices = hostedScanTools().tools.filter(tool => !assessmentTool(tool.id) || assessmentTools.includes(tool.id)).map(tool => {
      const price = meter.quote({ tools: [tool.id], inputBytes: 1, fileCount: 1 }).prices[0];
      return { id: tool.id, name: tool.name, unit: price.unit,
        basePriceMicros: price.basePriceMicros,
        additionalMiBPriceMicros: price.additionalMiBPriceMicros };
    });
    const pendingPurchases = db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_orders WHERE workspace_id = ? AND status = 'pending' AND created_at >= ?")
      .get(workspaceId, now() - PENDING_CHECKOUT_MS).n;
    const reviewPurchases = db.prepare("SELECT COUNT(*) AS n FROM scan_wallet_orders WHERE workspace_id = ? AND status = 'review'")
      .get(workspaceId).n;
    const pendingPayments = db.prepare(`SELECT COUNT(DISTINCT e.payment_id) AS n FROM scan_billing_events e
      JOIN scan_wallet_orders o ON o.id = e.order_id WHERE o.workspace_id = ?
      AND e.type = 'payment.succeeded' AND e.processed_at IS NULL`).get(workspaceId).n;
    return { ...meter.status(workspaceId), checkoutEnabled: configured, purchaseCents: SCAN_CREDIT_CENTS,
      maxBalanceMicros: MAX_SCAN_BALANCE_MICROS, prices, pendingPurchases, pendingPayments, reviewPurchases,
      autoTopUp: autoTopUp.status(workspaceId, userId) };
  }
  async function checkout(workspaceId, userId) {
    if (!configured) throw fail('Scanner credit checkout is not available yet.', 503);
    if (meter.status(workspaceId).blocked) throw fail('Scanner balance is under payment review.', 409);
    const order = transactionSync(db, () => {
      db.prepare("UPDATE scan_wallet_orders SET status = 'abandoned', updated_at = ? WHERE workspace_id = ? AND status = 'pending' AND created_at < ?")
        .run(now(), workspaceId, now() - PENDING_CHECKOUT_MS);
      if (meter.status(workspaceId).balanceMicros + SCAN_CREDIT_MICROS > MAX_SCAN_BALANCE_MICROS)
        throw fail('Scanner credit is limited to a $50 balance. Use existing credit before loading more.', 409);
      const existing = db.prepare("SELECT * FROM scan_wallet_orders WHERE workspace_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1")
        .get(workspaceId);
      if (existing?.checkout_url) return existing;
      // Retry an uncertain provider response with the same Whop idempotency key.
      if (existing) return existing;
      const id = randomBytes(20).toString('hex'), timestamp = now();
      db.prepare("INSERT INTO scan_wallet_orders(id,workspace_id,user_id,status,amount_cents,created_at,updated_at) VALUES (?, ?, ?, 'pending', ?, ?, ?)")
        .run(id, workspaceId, String(userId), SCAN_CREDIT_CENTS, timestamp, timestamp);
      return orderFor(id);
    });
    if (order.checkout_url) return { url: order.checkout_url, orderId: order.id };
    const value = await provider.checkout(order.id, `${publicUrl}/account?scannerPayment=returned`);
    const url = checkoutUrl(value.purchase_url);
    if (!validId(value.id, 'ch') || !validId(value.account_id, 'biz') ||
      value.plan?.currency !== 'usd' || cents(value.plan?.initial_price) !== SCAN_CREDIT_CENTS ||
      value.plan?.plan_type !== 'one_time') throw fail('Whop returned an unexpected scanner credit price.', 502);
    db.prepare('UPDATE scan_wallet_orders SET checkout_id = ?, checkout_url = ?, account_id = ?, updated_at = ? WHERE id = ?')
      .run(value.id, url, value.account_id, now(), order.id);
    return { url, orderId: order.id };
  }
  async function acceptPayment(paymentId) {
    const payment = await provider.payment(paymentId);
    if (!payment || payment.id !== paymentId) throw fail('Whop payment readback is unavailable.', 502);
    if (payment.metadata?.purple_product && payment.metadata.purple_product !== SCAN_PRODUCT &&
        !(typeof payment.metadata.purple_order_id === 'string' && orderFor(payment.metadata.purple_order_id))) return 'ignored';
    const order = typeof payment.metadata?.purple_order_id === 'string' && orderFor(payment.metadata.purple_order_id);
    if (!order) {
      // Keep the signed event in scan_billing_events for operator reconciliation.
      console.error('Scanner payment has no matching credit order.');
      return 'unmatched';
    }
    if (['draft', 'open', 'authorized', 'pending', 'unresolved'].includes(payment.status)) return 'retry';
    const matches = payment.account_id === order.account_id &&
      payment.checkout_configuration_id === order.checkout_id && payment.metadata?.purple_product === SCAN_PRODUCT &&
      payment.currency === 'usd' && (!payment.total?.currency || payment.total.currency === 'usd') &&
      cents(payment.total) !== null && cents(payment.total) >= order.amount_cents &&
      payment.status === 'paid' && !payment.auto_refunded &&
      (payment.refunded_amount == null || cents(payment.refunded_amount) === 0);
    let outcome = 'credited';
    transactionSync(db, () => {
      const latest = orderFor(order.id);
      if (latest.status === 'paid') {
        if (latest.payment_id !== paymentId) {
          db.prepare("UPDATE scan_wallet_orders SET status = 'review', updated_at = ? WHERE id = ?").run(now(), order.id);
          meter.block(order.workspace_id, 'payment_review');
          outcome = 'review';
        }
        return;
      }
      if (latest.status === 'review') { outcome = 'review'; return; }
      const reversed = db.prepare("SELECT id FROM scan_billing_events WHERE payment_id = ? AND (type LIKE 'refund.%' OR type LIKE 'dispute.%') LIMIT 1").get(paymentId);
      if (!['pending', 'abandoned'].includes(latest.status) || !matches || reversed) {
        db.prepare("UPDATE scan_wallet_orders SET status = 'review', payment_id = ?, updated_at = ? WHERE id = ?")
          .run(paymentId, now(), order.id);
        meter.block(order.workspace_id, 'payment_review');
        outcome = 'review';
        return;
      }
      db.prepare('UPDATE scan_wallet_orders SET status = ?, payment_id = ?, updated_at = ? WHERE id = ?')
        .run('paid', paymentId, now(), order.id);
      meter.recordVerifiedPurchase({ workspaceId: order.workspace_id, paymentId, amountMicros: SCAN_CREDIT_MICROS });
    });
    return outcome;
  }
  function freezeOrder(order, paymentId) {
    if (order.payment_id && order.payment_id !== paymentId)
      db.prepare("UPDATE scan_wallet_orders SET status = 'review', updated_at = ? WHERE id = ?").run(now(), order.id);
    else db.prepare("UPDATE scan_wallet_orders SET status = 'review', payment_id = ?, updated_at = ? WHERE id = ?")
      .run(paymentId, now(), order.id);
    meter.block(order.workspace_id, 'payment_review');
  }
  function manualWebhook(event, eventId) {
    if (db.prepare('SELECT id FROM scan_billing_events WHERE id = ?').get(eventId)) return { queued: false };
    const reversal = /^(refund|dispute)\.(created|updated)$/.test(event.type);
    if (event.type !== 'payment.succeeded' && !reversal) return { queued: false };
    const paymentId = reversal ? event.data?.payment_id || event.data?.payment?.id : event.data?.id;
    if (!validId(paymentId, 'pay')) throw fail('Invalid scanner payment identity.');
    if (reversal) {
      transactionSync(db, () => {
        db.prepare('INSERT OR IGNORE INTO scan_billing_events(id,type,payment_id,created_at,processed_at,outcome) VALUES (?, ?, ?, ?, ?, ?)')
          .run(eventId, event.type, paymentId, now(), now(), 'unmatched');
        const order = db.prepare('SELECT * FROM scan_wallet_orders WHERE payment_id = ?').get(paymentId) ||
          (event.data?.payment?.metadata?.purple_product === SCAN_PRODUCT &&
            typeof event.data.payment.metadata.purple_order_id === 'string' &&
            orderFor(event.data.payment.metadata.purple_order_id)) ||
          db.prepare(`SELECT o.* FROM scan_wallet_orders o JOIN scan_billing_events e ON e.order_id = o.id
            WHERE e.payment_id = ? AND e.type = 'payment.succeeded' LIMIT 1`).get(paymentId);
        if (order) {
          freezeOrder(order, paymentId);
          db.prepare('UPDATE scan_billing_events SET outcome = ? WHERE id = ?').run('applied', eventId);
        }
      });
      return { queued: false };
    }
    if (event.data?.metadata?.purple_product && event.data.metadata.purple_product !== SCAN_PRODUCT &&
        !(typeof event.data.metadata.purple_order_id === 'string' && orderFor(event.data.metadata.purple_order_id)))
      return { queued: false };
    const order = event.data?.metadata?.purple_product === SCAN_PRODUCT &&
      typeof event.data.metadata.purple_order_id === 'string' &&
      orderFor(event.data.metadata.purple_order_id);
    transactionSync(db, () => {
      db.prepare('INSERT OR IGNORE INTO scan_billing_events(id,type,payment_id,order_id,created_at) VALUES (?, ?, ?, ?, ?)')
        .run(eventId, event.type, paymentId, order?.id || null, now());
      if (order && db.prepare("SELECT id FROM scan_billing_events WHERE payment_id = ? AND (type LIKE 'refund.%' OR type LIKE 'dispute.%') LIMIT 1").get(paymentId)) {
        freezeOrder(order, paymentId);
        db.prepare("UPDATE scan_billing_events SET outcome = 'applied' WHERE payment_id = ? AND (type LIKE 'refund.%' OR type LIKE 'dispute.%')")
          .run(paymentId);
      }
    });
    return { queued: true };
  }
  function webhook(raw, headers) {
    const { event, eventId } = verify(raw, headers, webhookSecret);
    if (!event || typeof event.type !== 'string') throw fail('Invalid scanner payment event.');
    const automatic = autoTopUp.enqueue(event, eventId);
    const manual = manualWebhook(event, eventId);
    return { queued: automatic.queued || manual.queued };
  }
  let reconciling = false;
  async function dispatch() {
    if (reconciling) return { processed: 0, pending: 0 };
    reconciling = true;
    let processed = 0, pending = 0;
    try {
      const events = db.prepare(`SELECT id, payment_id FROM scan_billing_events
        WHERE type = 'payment.succeeded' AND processed_at IS NULL
          AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
        ORDER BY created_at, id LIMIT 10`).all(now() - 60_000);
      for (const event of events) {
        db.prepare('UPDATE scan_billing_events SET attempts = attempts + 1, last_attempt_at = ? WHERE id = ?')
          .run(now(), event.id);
        try {
          const outcome = await acceptPayment(event.payment_id);
          if (outcome === 'retry') { pending++; continue; }
          db.prepare('UPDATE scan_billing_events SET processed_at = ?, outcome = ? WHERE id = ?')
            .run(now(), outcome, event.id);
          processed++;
        } catch { pending++; }
      }
      const automatic = await autoTopUp.dispatch();
      return { processed: processed + automatic.processed, pending: pending + automatic.pending };
    } finally { reconciling = false; }
  }
  function disableAuto(workspaceId, userId) { autoTopUp.disable(workspaceId, userId); return status(workspaceId, userId); }
  return { status, checkout, webhook, acceptPayment, dispatch, setupAuto: autoTopUp.setup, disableAuto };
}

export function registerScanBillingWebhook(app, billing, express, schedule) {
  app.post('/api/scanner-billing/whop/webhook', express.raw({ type: 'application/json', limit: '256kb' }), (req, res) => {
    if (!Buffer.isBuffer(req.body)) return res.status(400).json({ error: 'Expected a JSON payment event.' });
    let receipt;
    try {
      receipt = billing.webhook(req.body, req.headers);
      res.json({ received: true });
    }
    catch (error) { return res.status(error.status || 503).json({ error: error.status ? error.message : 'Scanner payment verification is unavailable.' }); }
    if (receipt.queued) {
      try { schedule?.(); } catch { /* The existing dispatch alarm retries the durable event. */ }
    }
  });
}
export function registerScanBillingRoutes(app, billing) {
  app.get('/api/scanner-billing', (req, res) => res.json({ billing: billing.status(req.workspaceId, req.authUser?.id) }));
  app.post('/api/scanner-billing/checkout', async (req, res) => {
    try { res.json(await billing.checkout(req.workspaceId, req.authUser.id)); }
    catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : 'Scanner checkout is unavailable.' }); }
  });
  app.post('/api/scanner-billing/auto-top-up', async (req, res) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
        Object.keys(req.body).some(key => !['enabled', 'consentVersion'].includes(key)) ||
        req.body.enabled !== true || req.body.consentVersion !== AUTO_TOPUP_CONSENT)
      return res.status(400).json({ error: 'Confirm the automatic $10 credit refill terms first.' });
    try { res.json(await billing.setupAuto(req.workspaceId, req.authUser?.id)); }
    catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : 'Automatic top-up setup is unavailable.' }); }
  });
  app.delete('/api/scanner-billing/auto-top-up', (req, res) => {
    try { res.json({ billing: billing.disableAuto(req.workspaceId, req.authUser?.id) }); }
    catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : 'Automatic top-ups could not be disabled.' }); }
  });
}
