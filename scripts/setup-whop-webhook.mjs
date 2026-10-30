// Run with node --env-file=.env. Creates a DISABLED endpoint; never charges a card.
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { WHOP_API_VERSION } from '../server/whop-billing.js';

if (!process.env.WHOP_API_KEY) throw new Error('Set WHOP_API_KEY in the ignored .env first.');
const appUrl = new URL(process.argv[2] || process.env.PUBLIC_URL || 'https://app.purpleteam.sh');
if (appUrl.protocol !== 'https:' || appUrl.username || appUrl.password) throw new Error('Use the public HTTPS app URL.');
const base = process.env.WHOP_SANDBOX === 'true' ? 'https://sandbox-api.whop.com' : 'https://api.whop.com';
const existingId = process.env.WHOP_WEBHOOK_ID;
if (existingId && (!/^hook_[\w]+$/.test(existingId) || !process.env.WHOP_WEBHOOK_SECRET)) throw new Error('An existing webhook requires its locally saved signing secret.');
const response = await fetch(`${base}/api/v1/webhooks${existingId ? '/'+existingId : ''}`, { method: existingId ? 'PATCH' : 'POST',
  headers: { authorization: `Bearer ${process.env.WHOP_API_KEY}`, 'content-type': 'application/json', 'Api-Version-Date': WHOP_API_VERSION },
  body: JSON.stringify({ url: `${appUrl.origin}/api/billing/whop/webhook`, enabled: false, child_resource_events: false,
    api_version_date: WHOP_API_VERSION, events: ['payment.succeeded', 'payment.failed', 'payment.requires_action', 'setup_intent.succeeded', 'refund.created', 'refund.updated', 'dispute.created', 'dispute.updated'] }),
  signal: AbortSignal.timeout(15000) });
const data = await response.json();
if (!response.ok) {
  // Never dump request headers, credentials, payment bodies or full API responses.
  console.error(`Whop setup failed (HTTP ${response.status}): ${data.error?.message || 'Request rejected.'}`);
  process.exit(1);
}
const secret = data.webhook_secret || data.secret || process.env.WHOP_WEBHOOK_SECRET;
if (!secret || !data.id) throw new Error('Whop did not return the endpoint ID and signing secret. Billing remains disabled.');
let text = readFileSync('.env', 'utf8');
for (const [key, value] of Object.entries({ WHOP_WEBHOOK_ID: data.id, WHOP_WEBHOOK_SECRET: secret, WHOP_BILLING_ENABLED: 'false' })) {
  const line = `${key}=${value}`, pattern = new RegExp(`^${key}=.*$`, 'm');
  text = pattern.test(text) ? text.replace(pattern, line) : text.trimEnd()+'\n'+line+'\n';
}
writeFileSync('.env', text); chmodSync('.env', 0o600);
console.log(`${existingId ? 'Updated' : 'Created'} disabled Whop webhook ${data.id}. Signing secret saved in ignored .env; billing remains disabled.`);
