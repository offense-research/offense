import { randomBytes } from 'node:crypto';
import { transactionSync } from './db-transaction.js';

export const AUTO_TOPUP_PRODUCT = 'scanner-auto-credit-v1';
export const AUTO_TOPUP_CONSENT = '10-usd-below-2-cap-20-v1';
export const AUTO_TOPUP_CENTS = 1000;
export const AUTO_TOPUP_THRESHOLD_MICROS = 2_000_000;
export const AUTO_TOPUP_DAILY_LIMIT_CENTS = 2000;
const MAX_BALANCE_MICROS = 50_000_000;
const DAY = 24 * 60 * 60_000;
const SETUP_TTL = 20 * 60_000;
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
const validId = (value, prefix) => typeof value === 'string' && new RegExp(`^${prefix}_[A-Za-z0-9_-]+$`).test(value);
const unresolved = "('submitting','pending','attention','review')";
export const AUTO_TOPUP_SCHEMA = `CREATE TABLE IF NOT EXISTS scan_auto_topup_preferences (
  workspace_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
  consent_id TEXT, consent_user_id TEXT, consent_version TEXT, consent_at INTEGER,
  account_id TEXT, member_id TEXT, payment_method_id TEXT, error TEXT, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_auto_topup_orders (
  id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
  kind TEXT NOT NULL, status TEXT NOT NULL, consent_id TEXT NOT NULL,
  checkout_id TEXT UNIQUE, checkout_url TEXT, account_id TEXT, member_id TEXT,
  payment_method_id TEXT, payment_id TEXT UNIQUE, amount_cents INTEGER NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scan_auto_topup_orders_workspace ON scan_auto_topup_orders(workspace_id, kind, created_at);
CREATE TABLE IF NOT EXISTS scan_auto_topup_events (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, resource_id TEXT NOT NULL, order_id TEXT,
  created_at INTEGER NOT NULL, processed_at INTEGER, last_attempt_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0, outcome TEXT
);
CREATE INDEX IF NOT EXISTS scan_auto_topup_events_pending ON scan_auto_topup_events(processed_at, last_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS scan_auto_topup_events_resource ON scan_auto_topup_events(resource_id, type);`;

function amountCents(value) {
  const match = /^(\d+)(?:\.(\d+))?$/.exec(String(value?.amount ?? value));
  if (!match || match[1].length > 10 || /[1-9]/.test((match[2] || '').slice(2))) return null;
  return Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0').slice(0, 2));
}
function checkoutUrl(value) {
  let url; try { url = new URL(value); } catch { throw fail('Whop returned an invalid payment-method setup.', 502); }
  if (url.protocol !== 'https:' || !['whop.com', 'sandbox.whop.com'].includes(url.hostname) || url.username || url.password)
    throw fail('Whop returned an invalid payment-method setup.', 502);
  return url.href;
}

export function createScanAutoTopUp(db, { meter, provider, configured, publicUrl, now = Date.now }) {
  db.exec(AUTO_TOPUP_SCHEMA);
  const available = !!configured && ['setupCheckout', 'setupIntent', 'topUp', 'payment'].every(name => typeof provider?.[name] === 'function');
  const preference = workspace => db.prepare('SELECT * FROM scan_auto_topup_preferences WHERE workspace_id = ?').get(workspace);
  const orderFor = id => typeof id === 'string' ? db.prepare('SELECT * FROM scan_auto_topup_orders WHERE id = ?').get(id) : null;
  const pendingFor = workspace => db.prepare(`SELECT id FROM scan_auto_topup_orders
    WHERE workspace_id = ? AND kind = 'topup' AND status IN ${unresolved} LIMIT 1`).get(workspace);
  function owner(workspace, user) {
    const tables = db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name IN ('users','memberships')").get().n;
    return tables === 2 && typeof user === 'string' && typeof workspace === 'string' &&
      !!db.prepare(`SELECT m.user_id FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.workspace_id = ? AND m.user_id = ? AND m.role = 'owner'`).get(workspace, user);
  }
  function requireOwner(workspace, user) {
    if (!owner(workspace, user)) throw fail('Only a workspace owner can manage automatic top-ups.', 403);
  }
  function pause(workspace, message) {
    db.prepare('UPDATE scan_auto_topup_preferences SET enabled = 0, error = ?, updated_at = ? WHERE workspace_id = ?')
      .run(message, now(), workspace);
  }
  function status(workspace, user) {
    const p = preference(workspace), setup = p?.consent_id ? orderFor(p.consent_id) : null;
    return { available, canManage: typeof user === 'string' && owner(workspace, user), enabled: !!p?.enabled,
      pendingSetup: setup?.kind === 'setup' && setup.status === 'pending' && setup.created_at > now() - SETUP_TTL,
      amountCents: AUTO_TOPUP_CENTS, thresholdMicros: AUTO_TOPUP_THRESHOLD_MICROS,
      dailyLimitCents: AUTO_TOPUP_DAILY_LIMIT_CENTS, consentVersion: AUTO_TOPUP_CONSENT,
      pending: !!pendingFor(workspace), error: p?.error || null };
  }
  async function setup(workspace, user) {
    requireOwner(workspace, user);
    if (!available) throw fail('Automatic top-up setup is temporarily unavailable.', 503);
    if (meter.status(workspace).blocked) throw fail('This balance is under payment review.', 409);
    const order = transactionSync(db, () => {
      if (pendingFor(workspace)) throw fail('An earlier automatic top-up needs confirmation before setting up another payment method.', 409);
      const p = preference(workspace), old = p?.consent_id ? orderFor(p.consent_id) : null;
      if (p?.enabled) throw fail('Automatic top-ups are already enabled.', 409);
      if (old?.status === 'pending' && old.created_at > now() - SETUP_TTL) {
        if (old.user_id !== user) throw fail('Another owner is setting up automatic top-ups.', 409);
        if (old.checkout_url) return old;
        throw fail('Payment-method setup is being prepared. Try again shortly.', 409);
      }
      if (old?.kind === 'setup') db.prepare("UPDATE scan_auto_topup_orders SET status = 'canceled', updated_at = ? WHERE id = ? AND status IN ('pending','attention')").run(now(), old.id);
      const id = randomBytes(20).toString('hex'), timestamp = now();
      db.prepare(`INSERT INTO scan_auto_topup_orders(id,workspace_id,user_id,kind,status,consent_id,amount_cents,created_at,updated_at)
        VALUES (?,?,?,'setup','pending',?,0,?,?)`).run(id, workspace, user, id, timestamp, timestamp);
      db.prepare(`INSERT INTO scan_auto_topup_preferences(workspace_id,enabled,consent_id,consent_user_id,consent_version,consent_at,updated_at)
        VALUES (?,0,?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET enabled = 0, consent_id = excluded.consent_id,
        consent_user_id = excluded.consent_user_id, consent_version = excluded.consent_version, consent_at = excluded.consent_at,
        account_id = NULL, member_id = NULL, payment_method_id = NULL, error = NULL, updated_at = excluded.updated_at`)
        .run(workspace, id, user, AUTO_TOPUP_CONSENT, timestamp, timestamp);
      return orderFor(id);
    });
    if (order.checkout_url) return { url: order.checkout_url, orderId: order.id };
    try {
      const result = await provider.setupCheckout(order.id, `${publicUrl}/billing?scannerSetup=returned`);
      const url = checkoutUrl(result.purchase_url);
      if (!validId(result.id, 'ch') || !validId(result.account_id, 'biz') || result.mode !== 'setup')
        throw fail('Whop did not confirm a payment-method-only setup.', 502);
      transactionSync(db, () => {
        const p = preference(workspace), latest = orderFor(order.id);
        if (p?.consent_id !== order.id || latest.status !== 'pending') return;
        db.prepare('UPDATE scan_auto_topup_orders SET checkout_id = ?, checkout_url = ?, account_id = ?, updated_at = ? WHERE id = ?')
          .run(result.id, url, result.account_id, now(), order.id);
      });
      if (orderFor(order.id).status !== 'pending' || preference(workspace)?.consent_id !== order.id)
        throw fail('Automatic top-up setup was canceled.', 409);
      return { url, orderId: order.id };
    } catch (error) {
      transactionSync(db, () => {
        db.prepare("UPDATE scan_auto_topup_orders SET status = 'attention', updated_at = ? WHERE id = ? AND status = 'pending'").run(now(), order.id);
        if (preference(workspace)?.consent_id === order.id) pause(workspace, 'Payment-method setup could not be confirmed. Start setup again.');
      });
      throw error;
    }
  }
  function disable(workspace, user) {
    requireOwner(workspace, user);
    transactionSync(db, () => {
      db.prepare(`UPDATE scan_auto_topup_preferences SET enabled = 0, consent_id = NULL, consent_version = NULL,
        account_id = NULL, member_id = NULL, payment_method_id = NULL, error = NULL, updated_at = ? WHERE workspace_id = ?`).run(now(), workspace);
      db.prepare("UPDATE scan_auto_topup_orders SET status = 'canceled', updated_at = ? WHERE workspace_id = ? AND kind = 'setup' AND status IN ('pending','attention')").run(now(), workspace);
    });
    return status(workspace);
  }
  function freeze(order, paymentId) {
    db.prepare("UPDATE scan_auto_topup_orders SET status = 'review', updated_at = ? WHERE id = ?").run(now(), order.id);
    pause(order.workspace_id, 'An automatic payment needs review. Automatic top-ups are paused.');
    meter.block(order.workspace_id, 'payment_review');
  }
  function reversalSeen(id) {
    return !!db.prepare("SELECT id FROM scan_auto_topup_events WHERE resource_id = ? AND (type LIKE 'refund.%' OR type LIKE 'dispute.%') LIMIT 1").get(id);
  }
  function enqueue(event, eventId) {
    if (db.prepare('SELECT id FROM scan_auto_topup_events WHERE id = ?').get(eventId)) return { queued: false };
    const reversal = /^(refund|dispute)\.(created|updated)$/.test(event.type);
    const setupEvent = event.type.startsWith('setup_intent.');
    if (!reversal && !['payment.succeeded', 'payment.failed', 'payment.requires_action', 'payment.canceled', 'setup_intent.succeeded', 'setup_intent.canceled', 'setup_intent.requires_action'].includes(event.type)) return { queued: false };
    const id = reversal ? event.data?.payment_id || event.data?.payment?.id : event.data?.id;
    const metadata = reversal ? event.data?.payment?.metadata : event.data?.metadata;
    const order = (typeof metadata?.purple_order_id === 'string' && orderFor(metadata.purple_order_id)) ||
      (validId(id, 'pay') && db.prepare('SELECT * FROM scan_auto_topup_orders WHERE payment_id = ?').get(id)) ||
      (validId(id, 'pay') && db.prepare(`SELECT o.* FROM scan_auto_topup_orders o JOIN scan_auto_topup_events e ON e.order_id = o.id
        WHERE e.resource_id = ? LIMIT 1`).get(id));
    if (!order && !reversal && metadata?.purple_product !== AUTO_TOPUP_PRODUCT) return { queued: false };
    if (!validId(id, setupEvent ? 'sint' : 'pay')) throw fail('Invalid automatic payment event identity.');
    transactionSync(db, () => {
      db.prepare('INSERT OR IGNORE INTO scan_auto_topup_events(id,type,resource_id,order_id,created_at,processed_at,outcome) VALUES (?,?,?,?,?,?,?)')
        .run(eventId, event.type, id, order?.id || null, now(), reversal ? now() : null, reversal ? 'unmatched' : null);
      if (reversal && order?.kind === 'topup') {
        freeze(order, id);
        db.prepare("UPDATE scan_auto_topup_events SET outcome = 'review' WHERE id = ?").run(eventId);
      } else if (!setupEvent && order?.kind === 'topup' && reversalSeen(id)) freeze(order, id);
    });
    return { queued: !reversal };
  }
  async function acceptSetup(id) {
    const result = await provider.setupIntent(id), order = orderFor(result.metadata?.purple_order_id);
    if (!order || order.kind !== 'setup') return 'unmatched';
    if (order.status === 'canceled' || preference(order.workspace_id)?.consent_id !== order.id) return 'canceled';
    if (['processing', 'requires_action'].includes(result.status)) return 'retry';
    return transactionSync(db, () => {
      const p = preference(order.workspace_id), latest = orderFor(order.id);
      if (p?.consent_id !== order.id || latest.status === 'canceled') return 'canceled';
      if (latest.status === 'complete') return 'configured';
      if (latest.created_at <= now() - SETUP_TTL) {
        db.prepare("UPDATE scan_auto_topup_orders SET status = 'canceled', updated_at = ? WHERE id = ?").run(now(), order.id);
        pause(order.workspace_id, 'Payment-method setup expired. Start setup again.');
        return 'canceled';
      }
      // A webhook may beat the checkout POST response. Wait until that response
      // has durably bound the setup to the account and checkout before deciding.
      if (latest.status === 'pending' && (!latest.checkout_id || !latest.account_id)) return 'retry';
      const matches = latest.status === 'pending' && result.id === id && result.status === 'succeeded' &&
        result.checkout_configuration_id === latest.checkout_id && result.account_id === latest.account_id &&
        validId(result.member_id, 'mber') && validId(result.payment_method_id, 'payt') &&
        result.metadata?.purple_product === AUTO_TOPUP_PRODUCT && result.metadata?.offense_consent_version === AUTO_TOPUP_CONSENT &&
        p.consent_version === AUTO_TOPUP_CONSENT && owner(order.workspace_id, p.consent_user_id) && !meter.status(order.workspace_id).blocked;
      if (!matches) {
        db.prepare("UPDATE scan_auto_topup_orders SET status = 'review', updated_at = ? WHERE id = ?").run(now(), order.id);
        pause(order.workspace_id, 'Payment-method setup needs attention. Automatic top-ups remain off.');
        return 'review';
      }
      db.prepare(`UPDATE scan_auto_topup_preferences SET enabled = 1, account_id = ?, member_id = ?, payment_method_id = ?, error = NULL, updated_at = ? WHERE workspace_id = ?`)
        .run(result.account_id, result.member_id, result.payment_method_id, now(), order.workspace_id);
      db.prepare("UPDATE scan_auto_topup_orders SET status = 'complete', member_id = ?, payment_method_id = ?, updated_at = ? WHERE id = ?")
        .run(result.member_id, result.payment_method_id, now(), order.id);
      return 'configured';
    });
  }
  async function acceptPayment(id) {
    const payment = await provider.payment(id), order =
      db.prepare('SELECT * FROM scan_auto_topup_orders WHERE payment_id = ?').get(id) || orderFor(payment.metadata?.purple_order_id);
    if (!order || order.kind !== 'topup') return 'unmatched';
    if (['draft', 'open', 'authorized', 'pending', 'unresolved'].includes(payment.status)) return 'retry';
    return transactionSync(db, () => {
      const latest = orderFor(order.id);
      if (latest.status === 'review') return 'review';
      const identityMatches = payment.id === id && payment.account_id === latest.account_id && payment.member_id === latest.member_id &&
        payment.payment_method_id === latest.payment_method_id && (!latest.payment_id || latest.payment_id === id) &&
        payment.metadata?.purple_order_id === latest.id &&
        payment.metadata?.purple_product === AUTO_TOPUP_PRODUCT && payment.metadata?.offense_consent_version === AUTO_TOPUP_CONSENT &&
        validId(payment.id, 'pay');
      if (!identityMatches) { freeze(latest, id); return 'review'; }
      const matches = identityMatches &&
        payment.currency === 'usd' && (!payment.total?.currency || payment.total.currency === 'usd') &&
        amountCents(payment.total) !== null && amountCents(payment.total) >= latest.amount_cents &&
        payment.status === 'paid' && !payment.auto_refunded && (payment.refunded_amount == null || amountCents(payment.refunded_amount) === 0);
      if (reversalSeen(id)) { freeze(latest, id); return 'review'; }
      if (latest.status === 'paid') {
        if (!matches || latest.payment_id !== id) { freeze(latest, id); return 'review'; }
        return 'credited';
      }
      if (['failed', 'requires_action', 'canceled', 'voided'].includes(payment.status)) {
        const status = payment.status === 'requires_action' ? 'attention' : 'failed';
        db.prepare('UPDATE scan_auto_topup_orders SET status = ?, payment_id = ?, updated_at = ? WHERE id = ?').run(status, id, now(), order.id);
        pause(order.workspace_id, status === 'attention' ?
          'Automatic payment needs authentication. Add credit manually while this payment is confirmed.' :
          'Automatic payment failed. Add credit manually or set up the payment method again.');
        return 'attention';
      }
      if (!matches || !['submitting', 'pending', 'attention', 'failed'].includes(latest.status)) { freeze(latest, id); return 'review'; }
      db.prepare("UPDATE scan_auto_topup_orders SET status = 'paid', payment_id = ?, updated_at = ? WHERE id = ?").run(id, now(), order.id);
      meter.recordVerifiedPurchase({ workspaceId: order.workspace_id, paymentId: id, amountMicros: AUTO_TOPUP_CENTS * 10_000 });
      return 'credited';
    });
  }
  async function maybeTopUp(workspace) {
    if (!available) return;
    const order = transactionSync(db, () => {
      const p = preference(workspace), wallet = meter.status(workspace);
      if (!p?.enabled || p.consent_version !== AUTO_TOPUP_CONSENT || wallet.blocked || !validId(p.account_id, 'biz') ||
          !validId(p.member_id, 'mber') || !validId(p.payment_method_id, 'payt')) return;
      if (!owner(workspace, p.consent_user_id)) { pause(workspace, 'The consenting owner no longer has access. Automatic top-ups are paused.'); return; }
      if (wallet.balanceMicros >= AUTO_TOPUP_THRESHOLD_MICROS || pendingFor(workspace)) return;
      if (wallet.balanceMicros + AUTO_TOPUP_CENTS * 10_000 > MAX_BALANCE_MICROS) return;
      const recent = db.prepare("SELECT COUNT(*) AS n FROM scan_auto_topup_orders WHERE workspace_id = ? AND kind = 'topup' AND created_at > ?").get(workspace, now() - DAY).n;
      if (recent >= 2) {
        db.prepare('UPDATE scan_auto_topup_preferences SET error = ?, updated_at = ? WHERE workspace_id = ?')
          .run('The limit of two automatic $10 credit refills in 24 hours has been reached.', now(), workspace);
        return;
      }
      const id = randomBytes(20).toString('hex'), timestamp = now();
      db.prepare(`INSERT INTO scan_auto_topup_orders(id,workspace_id,user_id,kind,status,consent_id,account_id,member_id,payment_method_id,amount_cents,created_at,updated_at)
        VALUES (?,?,?,'topup','submitting',?,?,?,?,?,?,?)`).run(id, workspace, p.consent_user_id, p.consent_id, p.account_id, p.member_id, p.payment_method_id, AUTO_TOPUP_CENTS, timestamp, timestamp);
      return orderFor(id);
    });
    if (!order) return;
    // No await occurs between the final consent check and the POST invocation.
    if (!preference(workspace)?.enabled || preference(workspace)?.consent_id !== order.consent_id) return;
    try {
      const response = await provider.topUp(order.id, order);
      if (!validId(response.id, 'pay')) throw fail('Whop did not return a payment identity.', 502);
      transactionSync(db, () => {
        const latest = orderFor(order.id);
        if (latest.payment_id && latest.payment_id !== response.id) { freeze(latest, response.id); return; }
        if (latest.status === 'submitting') db.prepare("UPDATE scan_auto_topup_orders SET payment_id = ?, status = 'pending', updated_at = ? WHERE id = ?").run(response.id, now(), order.id);
      });
      await acceptPayment(response.id);
    } catch {
      transactionSync(db, () => {
        db.prepare("UPDATE scan_auto_topup_orders SET status = 'attention', updated_at = ? WHERE id = ? AND status NOT IN ('paid','review')").run(now(), order.id);
        pause(workspace, 'Automatic payment outcome is uncertain. No further automatic payments will start until it is confirmed.');
      });
    }
  }
  let processing = false;
  async function dispatch() {
    if (!available || processing) return { processed: 0, pending: 0 };
    processing = true; let processed = 0, pending = 0;
    try {
      const events = db.prepare(`SELECT * FROM scan_auto_topup_events WHERE processed_at IS NULL
        AND (last_attempt_at IS NULL OR last_attempt_at <= ?) ORDER BY created_at,id LIMIT 10`).all(now() - 60_000);
      for (const event of events) {
        db.prepare('UPDATE scan_auto_topup_events SET attempts = attempts + 1, last_attempt_at = ? WHERE id = ?').run(now(), event.id);
        try {
          const outcome = event.type.startsWith('setup_intent.') ? await acceptSetup(event.resource_id) : await acceptPayment(event.resource_id);
          if (outcome === 'retry') { pending++; continue; }
          db.prepare('UPDATE scan_auto_topup_events SET processed_at = ?, outcome = ? WHERE id = ?').run(now(), outcome, event.id); processed++;
        } catch { pending++; }
      }
      // Payment receipts can finish even if a delivery was missed. Never resend
      // an uncertain POST: provider idempotency keys expire after 24 hours.
      const outstanding = db.prepare(`SELECT id,payment_id FROM scan_auto_topup_orders WHERE kind = 'topup' AND status IN ('pending','attention')
        AND payment_id IS NOT NULL AND updated_at <= ? ORDER BY updated_at LIMIT 10`).all(now() - 60_000);
      for (const order of outstanding) {
        db.prepare('UPDATE scan_auto_topup_orders SET updated_at = ? WHERE id = ?').run(now(), order.id);
        try { await acceptPayment(order.payment_id); } catch { pending++; }
      }
      const candidates = db.prepare(`SELECT p.workspace_id FROM scan_auto_topup_preferences p WHERE p.enabled = 1
        AND COALESCE((SELECT SUM(w.amount_micros) FROM scan_wallet_entries w WHERE w.workspace_id = p.workspace_id),0) < ?
        AND NOT EXISTS (SELECT 1 FROM scan_wallet_blocks b WHERE b.workspace_id = p.workspace_id)
        AND NOT EXISTS (SELECT 1 FROM scan_auto_topup_orders o WHERE o.workspace_id = p.workspace_id AND o.kind = 'topup' AND o.status IN ${unresolved})
        ORDER BY p.updated_at LIMIT 10`).all(AUTO_TOPUP_THRESHOLD_MICROS);
      for (const row of candidates) await maybeTopUp(row.workspace_id);
      return { processed, pending };
    } finally { processing = false; }
  }
  return { status, setup, disable, enqueue, dispatch, maybeTopUp };
}
