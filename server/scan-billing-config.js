import { validScanPriceMap } from './scan-pricing.js';
import { configuredAssessmentTools } from './assessment-config.js';

export function scanBillingConfig(env) {
  if (env.SCAN_BILLING_ENABLED !== 'true') return { enabled: false, priceByToolMicros: {} };
  if (!env.WHOP_API_KEY || !env.SCAN_WHOP_WEBHOOK_SECRET) {
    throw new Error('Scanner billing requires a Whop API key and separate scanner webhook secret.');
  }
  let prices;
  try { prices = JSON.parse(env.SCAN_TOOL_PRICES_JSON || ''); }
  catch { throw new Error('Scanner billing requires SCAN_TOOL_PRICES_JSON with explicit prices.'); }
  if (!validScanPriceMap(prices))
    throw new Error('Scanner billing requires a bounded base and additional-MiB USD microprice for every catalog tool.');
  if (configuredAssessmentTools(env).some(id => !prices[id]))
    throw new Error('Every enabled assessment requires its explicit scanner price.');
  return { enabled: true, priceByToolMicros: prices };
}
