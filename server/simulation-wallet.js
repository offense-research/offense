import { randomBytes } from 'node:crypto';
import { transactionSync } from './db-transaction.js';

export const TOP_UP_CENTS = 500;
export const RUN_RESERVE_MICROS = 100_000; // $0.10; maximum customer charge for this bounded planner.
export const AUTO_THRESHOLD_MICROS = 1_000_000;
export const AUTO_DAILY_LIMIT_CENTS = 2000;
const PRODUCT = 'hosted-model-balance-v2';
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const identity = (value, prefix) => typeof value === 'string' && new RegExp(`^${prefix}_[\\w]+$`).test(value);
export function markedUpMicros(costUsd) {
  if (typeof costUsd !== 'number' || !Number.isFinite(costUsd) || costUsd < 0 || costUsd > 1000) throw fail('OpenRouter cost is unavailable. No estimated usage charge was applied.', 409);
  // Keep sub-cent precision. Only round the final customer amount up to $0.000001.
  return Math.ceil(Number((costUsd * 1_000_000 * 1.30).toFixed(6)));
}
function checkoutUrl(value) {
  let url; try { url = new URL(value); } catch { throw fail('Whop returned an invalid checkout.', 502); }
  if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname) || url.username || url.password) throw fail('Whop returned an invalid checkout.', 502);
  return url.href;
}

export function createSimulationWallet(db, { configured, provider, publicUrl, verify, cents }) {
  db.exec(`CREATE TABLE IF NOT EXISTS wallet_orders (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
    checkout_id TEXT UNIQUE, checkout_url TEXT, account_id TEXT, payment_id TEXT UNIQUE,
    member_id TEXT, amount_cents INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  ); CREATE INDEX IF NOT EXISTS wallet_orders_workspace ON wallet_orders(workspace_id, created_at);
  CREATE TABLE IF NOT EXISTS wallet_preferences (
    workspace_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
    consent_id TEXT, consent_user_id TEXT, consent_at INTEGER, account_id TEXT, member_id TEXT, payment_method_id TEXT, error TEXT
  ); CREATE TABLE IF NOT EXISTS wallet_entries (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, amount_micros INTEGER NOT NULL, kind TEXT NOT NULL, created_at INTEGER NOT NULL
  ); CREATE TABLE IF NOT EXISTS wallet_runs (
    job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, state TEXT NOT NULL, reserve_micros INTEGER NOT NULL,
    provider_cost_usd REAL, charge_micros INTEGER, generation_id TEXT, updated_at INTEGER NOT NULL
  ); CREATE TABLE IF NOT EXISTS billing_events (id TEXT PRIMARY KEY, type TEXT NOT NULL, payment_id TEXT NOT NULL, created_at INTEGER NOT NULL)`);
  const pref = workspace => db.prepare('SELECT * FROM wallet_preferences WHERE workspace_id = ?').get(workspace);
  const orderFor = id => db.prepare('SELECT * FROM wallet_orders WHERE id = ?').get(id);
  function ensure(workspace) { db.prepare('INSERT OR IGNORE INTO wallet_preferences(workspace_id) VALUES (?)').run(workspace); }
  function balance(workspace) { return db.prepare('SELECT COALESCE(SUM(amount_micros),0) AS value FROM wallet_entries WHERE workspace_id = ?').get(workspace).value; }
  function status(workspace) {
    const preferences = pref(workspace);
    const held = db.prepare("SELECT COALESCE(SUM(reserve_micros),0) AS value FROM wallet_runs WHERE workspace_id = ? AND state IN ('reserved','review')").get(workspace).value;
    const balanceMicros = balance(workspace), availableMicros = Math.max(0, balanceMicros - held);
    return { enabled: configured, priceCents: TOP_UP_CENTS, currency: 'usd', markupPercent: 30,
      balanceMicros, availableMicros, reservedMicros: held, runReserveMicros: RUN_RESERVE_MICROS,
      canRun: configured && !preferences?.blocked && availableMicros >= RUN_RESERVE_MICROS,
      blocked: !!preferences?.blocked, autoTopUp: { enabled: !!preferences?.enabled, pending: !!preferences?.consent_id && !preferences?.enabled && orderFor(preferences.consent_id)?.status === 'pending',
        amountCents: TOP_UP_CENTS, thresholdCents: 100, dailyLimitCents: AUTO_DAILY_LIMIT_CENTS, error: preferences?.error || null } };
  }
  function insertOrder(workspace, user, kind) {
    const id = randomBytes(20).toString('hex'), now = Date.now();
    db.prepare('INSERT INTO wallet_orders(id,workspace_id,user_id,kind,status,amount_cents,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, workspace, user, kind, 'pending', kind === 'setup' ? 0 : TOP_UP_CENTS, now, now);
    return orderFor(id);
  }
  async function checkout(workspace, userId, kind = 'purchase') {
    if (!configured) throw fail('Hosted billing is not available yet. Use your free trial or connect OpenRouter.', 503);
    if (pref(workspace)?.blocked) throw fail('This balance is under payment review. Contact Purple before adding funds.', 409);
    const order = transactionSync(db, () => {
      const existing = db.prepare("SELECT * FROM wallet_orders WHERE workspace_id = ? AND user_id = ? AND kind = ? AND status = 'pending' AND created_at > ? ORDER BY created_at DESC LIMIT 1")
        .get(workspace, userId, kind, Date.now() - 20 * 60_000);
      if (existing?.checkout_url) return existing;
      if (existing) throw fail('A checkout is already being prepared. Try again shortly.', 409);
      const value = insertOrder(workspace, userId, kind);
      if (kind === 'setup') { ensure(workspace); db.prepare('UPDATE wallet_preferences SET consent_id = ?, consent_user_id = ?, consent_at = ?, enabled = 0, error = NULL WHERE workspace_id = ?').run(value.id, userId, Date.now(), workspace); }
      return value;
    });
    if (order.checkout_url) return { url: order.checkout_url, orderId: order.id };
    try {
      const value = await provider.checkout(order.id, `${publicUrl}/?payment=returned#dependencies`, kind);
      const url = checkoutUrl(value.purchase_url);
      if (!identity(value.id, 'ch') || !identity(value.account_id, 'biz')) throw fail('Whop returned an invalid checkout.', 502);
      if (kind === 'purchase' && (value.plan?.currency !== 'usd' || cents(value.plan?.initial_price) !== TOP_UP_CENTS || value.plan?.plan_type !== 'one_time')) throw fail('Whop returned an unexpected balance price.', 502);
      if (kind === 'setup' && value.mode !== 'setup') throw fail('Whop did not return a payment-method setup.', 502);
      db.prepare('UPDATE wallet_orders SET checkout_id = ?, checkout_url = ?, account_id = ?, updated_at = ? WHERE id = ?').run(value.id, url, value.account_id, Date.now(), order.id);
      return { url, orderId: order.id };
    } catch (error) {
      db.prepare("UPDATE wallet_orders SET status = 'failed', updated_at = ? WHERE id = ?").run(Date.now(), order.id);
      if (kind === 'setup') db.prepare('UPDATE wallet_preferences SET consent_id = NULL WHERE workspace_id = ? AND consent_id = ?').run(workspace, order.id);
      throw error;
    }
  }
  function disableAuto(workspace) {
    ensure(workspace);
    db.prepare('UPDATE wallet_preferences SET enabled = 0, consent_id = NULL, payment_method_id = NULL, member_id = NULL, error = NULL WHERE workspace_id = ?').run(workspace);
    db.prepare("UPDATE wallet_orders SET status = 'canceled', updated_at = ? WHERE workspace_id = ? AND kind = 'setup' AND status = 'pending'").run(Date.now(), workspace);
    // An already submitted payment may finish; no subsequent charge is started.
    return status(workspace);
  }
  function reserve(workspace, jobId) {
    const current = status(workspace);
    if (!current.canRun) throw fail(current.blocked ? 'This balance is under payment review.' : 'Add $5 to your balance or connect your OpenRouter key to continue.', current.blocked ? 409 : 402);
    db.prepare("INSERT INTO wallet_runs VALUES (?, ?, 'reserved', ?, NULL, NULL, NULL, ?)").run(jobId, workspace, RUN_RESERVE_MICROS, Date.now());
    return jobId;
  }
  function settle(jobId, usage) {
    return transactionSync(db, () => {
      const run = db.prepare('SELECT * FROM wallet_runs WHERE job_id = ?').get(jobId);
      if (!run || run.state !== 'reserved') return;
      const charge = markedUpMicros(usage?.costUsd);
      if (charge > run.reserve_micros) throw fail('Model usage exceeded the run limit. No excess charge was applied; this run needs review.', 409);
      db.prepare("INSERT INTO wallet_entries VALUES (?, ?, ?, 'usage', ?)").run(`usage:${jobId}`, run.workspace_id, -charge, Date.now());
      db.prepare("UPDATE wallet_runs SET state = 'settled', provider_cost_usd = ?, charge_micros = ?, generation_id = ?, updated_at = ? WHERE job_id = ?")
        .run(usage.costUsd, charge, typeof usage.generationId === 'string' ? usage.generationId.slice(0, 200) : null, Date.now(), jobId);
      return { providerCostUsd: usage.costUsd, markupPercent: 30, chargedMicros: charge, currency: 'usd' };
    });
  }
  function release(jobId) {
    transactionSync(db, () => {
      const run = db.prepare('SELECT * FROM wallet_runs WHERE job_id = ?').get(jobId);
      if (!run || run.state === 'released') return;
      if (run.state === 'settled' && run.charge_micros) db.prepare("INSERT OR IGNORE INTO wallet_entries VALUES (?, ?, ?, 'refund', ?)").run(`refund:${jobId}`, run.workspace_id, run.charge_micros, Date.now());
      db.prepare("UPDATE wallet_runs SET state = 'released', updated_at = ? WHERE job_id = ?").run(Date.now(), jobId);
    });
  }
  async function maybeTopUp(workspace) {
    if (!configured) return;
    const order = transactionSync(db, () => {
      const p = pref(workspace);
      if (!p?.enabled || p.blocked || !p.payment_method_id || balance(workspace) >= AUTO_THRESHOLD_MICROS) return;
      if (db.prepare("SELECT id FROM wallet_orders WHERE workspace_id = ? AND kind = 'topup' AND status IN ('pending','attention','review') LIMIT 1").get(workspace)) return;
      const recent = db.prepare("SELECT COALESCE(SUM(amount_cents),0) AS value FROM wallet_orders WHERE workspace_id = ? AND kind = 'topup' AND created_at > ? AND status != 'failed'").get(workspace, Date.now() - 24 * 3600_000).value;
      if (recent + TOP_UP_CENTS > AUTO_DAILY_LIMIT_CENTS) {
        db.prepare("UPDATE wallet_preferences SET error = 'The $20 rolling daily auto top-up limit was reached.' WHERE workspace_id = ?").run(workspace); return;
      }
      const order = insertOrder(workspace, p.consent_user_id, 'topup');
      db.prepare('UPDATE wallet_orders SET account_id = ?, member_id = ? WHERE id = ?').run(p.account_id, p.member_id, order.id);
      return { ...order, preferences: p };
    });
    if (!order) return;
    try {
      // Unique durable order + provider idempotency key prevent duplicate debits.
      const value = await provider.topUp(order.id, order.preferences);
      if (!identity(value.id, 'pay')) throw fail('Whop did not return a payment identity.', 502);
      db.prepare('UPDATE wallet_orders SET payment_id = ?, account_id = ?, updated_at = ? WHERE id = ?').run(value.id, order.preferences.account_id, Date.now(), order.id);
      // A successful POST is not proof of payment. Only fetched paid state grants funds.
      await acceptPayment(value.id);
    } catch {
      // A timeout might have charged the card. Keep this order pending and pause
      // automatic charges until Whop delivers confirmation or an operator checks it.
      db.prepare("UPDATE wallet_preferences SET enabled = 0, error = 'Auto top-up needs attention. Check payment status before trying again.' WHERE workspace_id = ?").run(workspace);
    }
  }
  async function acceptPayment(paymentId) {
    const payment = await provider.payment(paymentId);
    const orderId = payment.metadata?.purple_order_id;
    const order = typeof orderId === 'string' && orderFor(orderId);
    if (!order || order.kind === 'setup') return;
    const p = pref(order.workspace_id);
    const accountId = order.account_id || (order.kind === 'topup' ? p?.account_id : null);
    if (payment.id !== paymentId || payment.account_id !== accountId ||
      (order.kind === 'purchase' && payment.checkout_configuration_id !== order.checkout_id) ||
      (order.kind === 'topup' && (payment.member_id !== order.member_id || (order.payment_id && order.payment_id !== paymentId))) ||
      payment.currency !== 'usd' || (payment.total?.currency && payment.total.currency !== 'usd') || cents(payment.total) === null || cents(payment.total) < order.amount_cents ||
      payment.metadata?.purple_product !== PRODUCT) throw fail('Payment does not match this balance purchase.', 409);
    if (payment.status !== 'paid' || payment.auto_refunded || (payment.refunded_amount != null && cents(payment.refunded_amount) !== 0)) throw fail('Payment is not confirmed and unrefunded.', 409);
    transactionSync(db, () => {
      const latest = orderFor(order.id);
      if (latest.status === 'paid' || latest.status === 'review') return;
      const reversal = db.prepare("SELECT id FROM billing_events WHERE payment_id = ? AND (type LIKE 'refund.%' OR type LIKE 'dispute.%') LIMIT 1").get(paymentId);
      if (!['pending', 'attention'].includes(latest.status)) throw fail('This purchase is not active.', 409);
      db.prepare('UPDATE wallet_orders SET status = ?, payment_id = ?, account_id = ?, updated_at = ? WHERE id = ?').run(reversal ? 'review' : 'paid', paymentId, accountId, Date.now(), order.id);
      if (reversal) { ensure(order.workspace_id); db.prepare('UPDATE wallet_preferences SET blocked = 1, enabled = 0 WHERE workspace_id = ?').run(order.workspace_id); return; }
      db.prepare("INSERT INTO wallet_entries VALUES (?, ?, ?, 'purchase', ?)").run(`purchase:${order.id}`, order.workspace_id, order.amount_cents * 10_000, Date.now());
    });
  }
  async function webhook(raw, headers) {
    const { event, eventId } = verify(raw, headers);
    if (!event || typeof event.type !== 'string') throw fail('Invalid payment event.');
    if (db.prepare('SELECT id FROM billing_events WHERE id = ?').get(eventId)) return;
    const reversal = /^(refund|dispute)\.(created|updated)$/.test(event.type);
    if (!['payment.succeeded', 'payment.failed', 'payment.requires_action', 'setup_intent.succeeded'].includes(event.type) && !reversal) return;
    const id = reversal ? event.data?.payment_id || event.data?.payment?.id : event.data?.id;
    if (!identity(id, event.type.startsWith('setup_intent.') ? 'sint' : 'pay')) throw fail('Invalid payment identity.');
    if (reversal) {
      transactionSync(db, () => {
        db.prepare('INSERT OR IGNORE INTO billing_events VALUES (?, ?, ?, ?)').run(eventId, event.type, id, Date.now());
        const order = db.prepare('SELECT * FROM wallet_orders WHERE payment_id = ?').get(id);
        if (order) { ensure(order.workspace_id); db.prepare('UPDATE wallet_preferences SET blocked = 1, enabled = 0 WHERE workspace_id = ?').run(order.workspace_id);
          db.prepare("UPDATE wallet_orders SET status = 'review', updated_at = ? WHERE id = ?").run(Date.now(), order.id); }
      }); return;
    }
    if (event.type === 'setup_intent.succeeded') {
      const setup = await provider.setupIntent(id), order = orderFor(setup.metadata?.purple_order_id || '');
      if (!order || order.kind !== 'setup') return;
      if (setup.id !== id || setup.status !== 'succeeded' || setup.checkout_configuration_id !== order.checkout_id || setup.account_id !== order.account_id ||
        !identity(setup.member_id, 'mber') || !identity(setup.payment_method_id, 'payt') || setup.metadata?.purple_product !== PRODUCT) throw fail('Payment-method setup is not confirmed.', 409);
      transactionSync(db, () => {
        const p = pref(order.workspace_id);
        // A late setup delivery must never re-enable canceled consent.
        if (p?.consent_id === order.id && order.status === 'pending' && !p.blocked) {
          db.prepare('UPDATE wallet_preferences SET enabled = 1, account_id = ?, member_id = ?, payment_method_id = ?, error = NULL WHERE workspace_id = ?').run(setup.account_id, setup.member_id, setup.payment_method_id, order.workspace_id);
          db.prepare("UPDATE wallet_orders SET status = 'paid', updated_at = ? WHERE id = ?").run(Date.now(), order.id);
        }
      });
    } else if (event.type === 'payment.succeeded') await acceptPayment(id);
    else {
      const payment = await provider.payment(id), order = orderFor(payment.metadata?.purple_order_id || '');
      if (order?.kind === 'topup' && payment.account_id === pref(order.workspace_id)?.account_id && ['failed', 'requires_action'].includes(payment.status)) {
        db.prepare("UPDATE wallet_preferences SET enabled = 0, error = 'Auto top-up failed or requires authentication. Add funds manually.' WHERE workspace_id = ?").run(order.workspace_id);
        // Leave uncertain/failed payments for review; no automated retry.
        db.prepare("UPDATE wallet_orders SET status = 'attention', payment_id = ?, updated_at = ? WHERE id = ? AND status = 'pending'").run(id, Date.now(), order.id);
      }
    }
    db.prepare('INSERT OR IGNORE INTO billing_events VALUES (?, ?, ?, ?)').run(eventId, event.type, id, Date.now());
  }
  async function dispatch() {
    if (!configured) return;
    for (const row of db.prepare('SELECT workspace_id FROM wallet_preferences WHERE enabled = 1 AND blocked = 0').all()) await maybeTopUp(row.workspace_id);
  }
  return { status, checkout, reserve, settle, release, webhook, disableAuto, maybeTopUp, dispatch };
}
