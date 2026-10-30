// Read-only unless --apply is explicit. Existing URL, enablement, payload
// version and signing secret are never supplied to the PATCH operation.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SCAN_WHOP_WEBHOOK_EVENTS } from '../shared/scan-webhook-events.js';
import { WHOP_API_VERSION } from '../server/whop-billing.js';

const ownedEndpoints = new Map([
  ['https://offense.sh/api/scanner-billing/whop/webhook', 'canonical'],
  ['https://app.purpleteam.sh/api/scanner-billing/whop/webhook', 'legacy']
]);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const error = (code, message) => Object.assign(new Error(message), { code });

async function json(response) {
  if (!response.ok) {
    await response.body?.cancel();
    throw error('provider_request_failed', `Whop webhook request returned HTTP ${response.status}.`);
  }
  if (!response.body) throw error('invalid_response', 'Whop returned an incomplete webhook response.');
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 262144) throw error('invalid_response', 'Whop webhook response exceeded the supported size.');
      chunks.push(value);
    }
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!object(data)) throw error('invalid_response', 'Whop returned an invalid webhook response.');
    return data;
  } catch (cause) {
    await reader.cancel().catch(() => {});
    if (cause.code === 'invalid_response') throw cause;
    throw error('invalid_response', 'Whop returned an invalid webhook response.');
  }
}

function secretMatches(data, saved) {
  // Whop returns null to API-key/OAuth callers after creation. A hidden secret
  // cannot be verified by readback; never mistake that documented absence for
  // a rotated secret, or treat masked/encoded/non-string values as equivalent.
  const secrets = ['webhook_secret', 'secret'].filter(name => Object.hasOwn(data, name))
    .map(name => data[name]).filter(value => value !== null);
  if (secrets.some(value => value !== saved)) throw error('signing_secret_mismatch', 'Whop signing secret differs from the saved scanner secret. No secret was changed by this updater.');
  return secrets.length > 0;
}

function inspect(data, { id, secret }) {
  if (data.id !== id || !ownedEndpoints.has(data.url) || data.enabled !== true ||
      data.child_resource_events !== false || data.api_version_date !== WHOP_API_VERSION ||
      data.api_version !== undefined && data.api_version !== 'v1') {
    throw error('endpoint_mismatch', 'The saved scanner endpoint is not the expected enabled, version-pinned Offense webhook.');
  }
  // These are existing provider-validated event names, not caller additions.
  // Retain other subscriptions instead of replacing them with our subset.
  if (!Array.isArray(data.events) || data.events.length > 500 || data.events.some(value =>
    typeof value !== 'string' || value.length > 100 || !/^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/.test(value))) {
    throw error('invalid_events', 'Whop returned invalid scanner webhook subscriptions.');
  }
  return { id, url: data.url, enabled: true, childResourceEvents: false, apiVersionDate: data.api_version_date,
    endpointKind: ownedEndpoints.get(data.url), events: [...new Set(data.events)], secretVerified: secretMatches(data, secret) };
}

export async function updateScanWhopEvents({ env = process.env, apply = false, fetchImpl = fetch } = {}) {
  if (typeof apply !== 'boolean') throw error('invalid_option', 'Choose an explicit boolean apply option.');
  if (env.WHOP_SANDBOX !== undefined && !['true', 'false'].includes(env.WHOP_SANDBOX)) throw error('invalid_environment', 'Choose an explicit Whop API environment.');
  const sandbox = env.WHOP_SANDBOX === 'true';
  if (!sandbox && (env.PURPLE_SECRETS_SOURCE !== 'infisical' || env.PURPLE_SECRETS_ENVIRONMENT !== 'prod')) {
    throw error('vault_required', 'Production webhook checks and updates must use the Infisical prod wrapper.');
  }
  const id = env.SCAN_WHOP_WEBHOOK_ID, secret = env.SCAN_WHOP_WEBHOOK_SECRET, apiKey = env.WHOP_API_KEY;
  if (typeof id !== 'string' || !/^hook_[A-Za-z0-9_-]{1,120}$/.test(id) ||
      typeof secret !== 'string' || !/^ws_[A-Za-z0-9_-]{1,2048}$/.test(secret) ||
      typeof apiKey !== 'string' || apiKey.length < 16 || apiKey.length > 4096 || /\s/.test(apiKey)) {
    throw error('credentials_required', 'The existing scanner webhook ID, signing secret and Whop API key are required.');
  }
  const base = sandbox ? 'https://sandbox-api.whop.com' : 'https://api.whop.com';
  const endpoint = `${base}/api/v1/webhooks/${encodeURIComponent(id)}`;
  const headers = { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json',
    accept: 'application/json', 'Api-Version-Date': WHOP_API_VERSION };
  async function request(method, body) {
    let response;
    try {
      response = await fetchImpl(endpoint, { method, headers, redirect: 'error',
        ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(15000) });
    } catch {
      throw error(method === 'PATCH' ? 'update_outcome_unknown' : 'provider_unavailable', method === 'PATCH'
        ? 'Webhook update outcome is unknown. Run the read-only check before retrying.'
        : 'Could not read the existing Whop scanner webhook.');
    }
    return json(response);
  }
  const before = inspect(await request('GET'), { id, secret });
  const required = [...SCAN_WHOP_WEBHOOK_EVENTS];
  const missingEvents = required.filter(event => !before.events.includes(event));
  const proposedEvents = [...new Set([...before.events, ...required])];
  const proof = { schemaVersion: 1, provider: 'whop', environment: sandbox ? 'sandbox' : 'production',
    mode: apply ? 'apply' : 'read_only', endpointKind: before.endpointKind, apiVersionDate: WHOP_API_VERSION,
    enabled: true, childResourceEvents: false, signingSecretVerified: before.secretVerified,
    events: before.events, requiredEvents: required, proposedEvents, missingEvents,
    ready: missingEvents.length === 0, changed: false, settingsPreserved: true };
  if (!apply || !missingEvents.length) return proof;
  const updated = await request('PATCH', { events: proposedEvents });
  secretMatches(updated, secret);
  const after = inspect(await request('GET'), { id, secret });
  if (after.url !== before.url || proposedEvents.some(event => !after.events.includes(event))) {
    throw error('readback_mismatch', 'Whop webhook readback differs from the reviewed endpoint or event union.');
  }
  return { ...proof, events: after.events, missingEvents: [], ready: true, changed: true,
    signingSecretVerified: after.secretVerified };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length > 1 || args.some(argument => argument !== '--apply')) {
    console.error('Usage: node scripts/update-scan-whop-events.mjs [--apply]');
    process.exitCode = 2;
  } else {
    try { console.log(JSON.stringify(await updateScanWhopEvents({ apply: args.includes('--apply') }), null, 2)); }
    catch (cause) {
      const safe = typeof cause.code === 'string' && /^[a-z_]+$/.test(cause.code);
      console.error(JSON.stringify({ success: false, code: safe ? cause.code : 'update_failed',
        message: safe ? cause.message : 'Scanner webhook verification could not complete.' }));
      process.exitCode = 1;
    }
  }
}
