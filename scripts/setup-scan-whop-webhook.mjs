// Usage: node --env-file=.env scripts/setup-scan-whop-webhook.mjs [public-url] [private-output-file] [--enable]
// Run with Infisical and an explicit output file to import the one-time secret.
// Creation is disabled by default. --enable only activates a matching saved endpoint.
import { existsSync, lstatSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { WHOP_API_VERSION } from '../server/whop-billing.js';
import { SCAN_WHOP_WEBHOOK_EVENTS } from '../shared/scan-webhook-events.js';

if (!process.env.WHOP_API_KEY) throw new Error('Set WHOP_API_KEY before creating the scanner webhook.');
const args = process.argv.slice(2);
if (args.some(arg => arg.startsWith('--') && arg !== '--enable')) throw new Error('Unknown scanner webhook option.');
const enable = args.includes('--enable');
const positionals = args.filter(arg => arg !== '--enable');
if (positionals.length > 2) throw new Error('Expected a public URL and optional private output file.');
const appUrl = new URL(positionals[0] || process.env.PUBLIC_URL || 'https://app.purpleteam.sh');
if (appUrl.protocol !== 'https:' || appUrl.username || appUrl.password || appUrl.search || appUrl.hash)
  throw new Error('Use the public HTTPS app URL.');
const explicitOutput = positionals[1] || process.env.SCAN_WHOP_SECRET_OUTPUT;
const output = path.resolve(explicitOutput || '.env');
if (process.env.PURPLE_SECRETS_SOURCE === 'infisical' && !explicitOutput)
  throw new Error('Pass a private output file for vault-managed scanner webhook secrets.');
if (existsSync(output) && lstatSync(output).isSymbolicLink()) throw new Error('Refusing a symlinked secret output file.');
if (output.endsWith('/.env') && !existsSync(output)) throw new Error('Create the ignored .env before local webhook setup.');
const base = process.env.WHOP_SANDBOX === 'true' ? 'https://sandbox-api.whop.com' : 'https://api.whop.com';
const existingId = process.env.SCAN_WHOP_WEBHOOK_ID;
if (existingId && (!/^hook_[A-Za-z0-9_-]+$/.test(existingId) || !process.env.SCAN_WHOP_WEBHOOK_SECRET))
  throw new Error('Updating a scanner webhook requires its saved endpoint ID and signing secret.');
if (enable && !existingId) throw new Error('Create and save the disabled scanner webhook before enabling it.');
const url = `${appUrl.origin}/api/scanner-billing/whop/webhook`;
const events = SCAN_WHOP_WEBHOOK_EVENTS;
const headers = { authorization: `Bearer ${process.env.WHOP_API_KEY}`, 'content-type': 'application/json',
  'Api-Version-Date': WHOP_API_VERSION };
if (enable) {
  const currentResponse = await fetch(`${base}/api/v1/webhooks/${existingId}`, {
    headers, signal: AbortSignal.timeout(15_000)
  });
  if (!currentResponse.ok) throw new Error(`Whop scanner webhook verification returned HTTP ${currentResponse.status}.`);
  const current = await currentResponse.json();
  if (current.id !== existingId || current.url !== url || current.api_version_date !== WHOP_API_VERSION ||
      current.child_resource_events !== false || !events.every(event => current.events?.includes(event)))
    throw new Error('Saved scanner webhook settings differ from the expected endpoint, events, or payload version.');
}
const response = await fetch(`${base}/api/v1/webhooks${existingId ? `/${existingId}` : ''}`, {
  method: existingId ? 'PATCH' : 'POST',
  headers,
  body: JSON.stringify(enable ? { enabled: true } : { url, enabled: false,
    child_resource_events: false, api_version_date: WHOP_API_VERSION, events }),
  signal: AbortSignal.timeout(15_000)
});
const data = await response.json().catch(() => ({}));
if (!response.ok) throw new Error(`Whop scanner webhook setup returned HTTP ${response.status}.`);
const id = data.id, secret = data.webhook_secret || data.secret || process.env.SCAN_WHOP_WEBHOOK_SECRET;
if (!/^hook_[A-Za-z0-9_-]+$/.test(id || '') || !/^ws_[A-Za-z0-9_-]+$/.test(secret || ''))
  throw new Error('Whop did not return a valid scanner endpoint ID and signing secret.');
let contents = existsSync(output) ? readFileSync(output, 'utf8') : '';
for (const [key, value] of Object.entries({
  SCAN_WHOP_WEBHOOK_ID: id, SCAN_WHOP_WEBHOOK_SECRET: secret,
  ...(!enable ? { SCAN_BILLING_ENABLED: 'false' } : {})
})) {
  const line = `${key}=${value}`, pattern = new RegExp(`^${key}=.*$`, 'm');
  contents = pattern.test(contents) ? contents.replace(pattern, line) : `${contents.trimEnd()}\n${line}\n`;
}
const temporary = `${output}.${randomBytes(6).toString('hex')}.tmp`;
writeFileSync(temporary, contents, { mode: 0o600, flag: 'wx' });
renameSync(temporary, output);
chmodSync(output, 0o600);
console.log(`${existingId ? 'Updated' : 'Created'} ${enable ? 'enabled' : 'disabled'} Whop scanner webhook ${id}. Signing secret saved to a private file.`);
