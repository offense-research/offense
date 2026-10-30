import { createHmac, timingSafeEqual } from 'node:crypto';
import { createSimulationWallet, TOP_UP_CENTS } from './simulation-wallet.js';

export const SIMULATION_PRICE_CENTS = TOP_UP_CENTS;
export const WHOP_API_VERSION = '2026-10-15-1';
const fail = (message, status = 400) => Object.assign(new Error(message), { status });

// Whop SDK 2.6 signs with the literal UTF-8 ws_ secret, including its prefix.
export function verifyWhopWebhook(raw, headers, secret, now = Date.now()) {
  if (!secret) throw fail('Payment webhooks are not configured.', 503);
  const id = headers['webhook-id'], timestamp = headers['webhook-timestamp'];
  if (typeof id !== 'string' || !/^[\w-]{1,200}$/.test(id) || !/^\d{1,12}$/.test(timestamp || '') ||
    Math.abs(now / 1000 - Number(timestamp)) > 300) throw fail('Invalid payment signature.', 401);
  const expected = createHmac('sha256', secret).update(`${id}.${timestamp}.`).update(raw).digest();
  const valid = String(headers['webhook-signature'] || '').split(' ').some(value => {
    if (!/^v1,[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
    const actual = Buffer.from(value.slice(3), 'base64');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  });
  if (!valid) throw fail('Invalid payment signature.', 401);
  try { return { event: JSON.parse(raw.toString('utf8')), eventId: id }; }
  catch { throw fail('Invalid payment payload.'); }
}

function cents(value) {
  const amount = value?.amount ?? value;
  const match = /^(\d+)(?:\.(\d+))?$/.exec(String(amount));
  if (!match || match[1].length > 10 || /[1-9]/.test((match[2] || '').slice(2))) return null;
  return Number(match[1]) * 100 + Number((match[2] || '').padEnd(2, '0').slice(0, 2));
}

export function createWhopProvider({ apiKey, sandbox = false, fetchImpl = fetch }) {
  const base = sandbox ? 'https://sandbox-api.whop.com/api/v1' : 'https://api.whop.com/api/v1';
  async function request(path, data, idempotencyKey) {
    const response = await fetchImpl(base + path, { method: data ? 'POST' : 'GET',
      headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json', 'Api-Version-Date': WHOP_API_VERSION, ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}) },
      ...(data ? { body: JSON.stringify(data) } : {}), signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw fail(`Whop payment service returned HTTP ${response.status}.`, 502);
    return response.json();
  }
  return {
    checkout: (orderId, returnUrl, kind = 'purchase') => request('/checkout_configurations', {
      ...(kind === 'setup' ? { currency: 'usd' } : { plan: { title: 'Offense hosted model balance',
        description: '$5 prepaid balance. Hosted model usage costs OpenRouter cost plus 30%. No subscription.',
        plan_type: 'one_time', initial_price: 5, currency: 'usd', visibility: 'hidden',
        force_create_new_plan: true, stock: 1, unlimited_stock: false } }),
      mode: kind === 'setup' ? 'setup' : 'payment', redirect_url: returnUrl,
      metadata: { purple_order_id: orderId, purple_product: 'hosted-model-balance-v2' }
    }, `purple-checkout-${orderId}`),
    topUp: (orderId, preferences) => request('/payments', {
      account_id: preferences.account_id, member_id: preferences.member_id, payment_method_id: preferences.payment_method_id,
      off_session: true, plan: { title: 'Offense $5 balance top-up', description: 'Automatic prepaid balance top-up',
        plan_type: 'one_time', initial_price: 5, currency: 'usd', visibility: 'hidden' },
      metadata: { purple_order_id: orderId, purple_product: 'hosted-model-balance-v2' }
    }, `purple-topup-${orderId}`),
    setupIntent: id => request(`/setup_intents/${encodeURIComponent(id)}`),
    payment: id => request(`/payments/${encodeURIComponent(id)}`)
  };
}

export function createSimulationBilling(db, { apiKey, webhookSecret, enabled = false, sandbox = false, publicUrl, provider } = {}) {
  const configured = !!enabled && !!apiKey && !!webhookSecret;
  provider ||= createWhopProvider({ apiKey, sandbox });
  return createSimulationWallet(db, { configured, provider, publicUrl, cents,
    verify: (raw, headers) => verifyWhopWebhook(raw, headers, webhookSecret) });
}

export function registerBillingWebhook(app, billing, express) {
  app.post('/api/billing/whop/webhook', express.raw({ type: 'application/json', limit: '256kb' }), async (req, res) => {
    if (!Buffer.isBuffer(req.body)) return res.status(400).json({ error: 'Expected a JSON payment event.' });
    try { await billing.webhook(req.body, req.headers); res.json({ received: true }); }
    catch (error) { res.status(error.status || 503).json({ error: error.status ? error.message : 'Payment verification is temporarily unavailable.' }); }
  });
}
export function registerBillingRoutes(app, billing) {
  app.get('/api/billing', (req, res) => res.json({ billing: billing.status(req.workspaceId) }));
  app.post('/api/billing/checkout', async (req, res) => res.json(await billing.checkout(req.workspaceId, req.authUser.id)));
  app.post('/api/billing/auto-top-up', async (req, res) => {
    if (req.body?.enabled !== true || req.body?.consentVersion !== '5-usd-below-1-cap-20-v1') return res.status(400).json({ error: 'Confirm the $5 auto top-up terms first.' });
    res.json(await billing.checkout(req.workspaceId, req.authUser.id, 'setup'));
  });
  app.delete('/api/billing/auto-top-up', (req, res) => res.json({ billing: billing.disableAuto(req.workspaceId) }));
}
