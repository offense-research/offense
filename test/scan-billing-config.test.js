import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { scanBillingConfig } from '../server/scan-billing-config.js';

test('scanner charges require explicit prices and separate payment verification', () => {
  assert.deepEqual(scanBillingConfig({}), { enabled: false, priceByToolMicros: {} });
  assert.throws(() => scanBillingConfig({ SCAN_BILLING_ENABLED: 'true' }), /separate scanner webhook secret/);
  const credentials = { SCAN_BILLING_ENABLED: 'true', WHOP_API_KEY: 'test', SCAN_WHOP_WEBHOOK_SECRET: 'test' };
  assert.throws(() => scanBillingConfig(credentials), /explicit prices/);
  const prices = JSON.parse(readFileSync(new URL('../config/scanner-prices.json', import.meta.url), 'utf8'));
  assert.deepEqual(scanBillingConfig({ ...credentials, SCAN_TOOL_PRICES_JSON: JSON.stringify(prices) }),
    { enabled: true, priceByToolMicros: prices });
  assert.throws(() => scanBillingConfig({ ...credentials, SCAN_TOOL_PRICES_JSON: JSON.stringify({ ...prices, gitleaks: { baseMicros: 0, additionalMiBMicros: 10_000 } }) }), /bounded base/);
  assert.throws(() => scanBillingConfig({ ...credentials, SCAN_TOOL_PRICES_JSON: JSON.stringify({ ...prices, 'guarddog-pypi': undefined }) }), /bounded base/);
});
