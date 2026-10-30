import { ARTIFACT_LIMITS } from './scan-artifacts.js';
import { SCAN_LIMITS } from './scan-input.js';
import { hostedScanTools } from './hosted-scans.js';
import { assessmentTool } from '../shared/assessment-tools.js';

const MIB = 1024 * 1024;
export const SCAN_PRICE_TOOLS = Object.freeze(hostedScanTools().tools.map(tool => Object.freeze({
  id: tool.id,
  maxInputMiB: Math.ceil((ARTIFACT_LIMITS[tool.inputType] || SCAN_LIMITS.totalBytes) / MIB)
})));
const MAX_SINGLE_SCAN_MICROS = 10_000_000;

export function validScanPriceMap(prices) {
  if (!prices || typeof prices !== 'object' || Array.isArray(prices)) return false;
  // Accept the exact prior catalog during a staged rollout. Once any new
  // assessment price is supplied, require the complete reviewed rate card.
  const selected = Object.keys(prices).some(id => assessmentTool(id)) ? SCAN_PRICE_TOOLS : SCAN_PRICE_TOOLS.filter(tool => !assessmentTool(tool.id));
  if (Object.keys(prices).length !== selected.length) return false;
  return selected.every(({ id, maxInputMiB }) => {
    const price = prices[id];
    return price && typeof price === 'object' && !Array.isArray(price) &&
      Object.keys(price).length === 2 &&
      Number.isSafeInteger(price.baseMicros) && price.baseMicros > 0 &&
      Number.isSafeInteger(price.additionalMiBMicros) && price.additionalMiBMicros >= 0 &&
      (!assessmentTool(id) || price.additionalMiBMicros === 0) &&
      price.baseMicros + (maxInputMiB - 1) * price.additionalMiBMicros <= MAX_SINGLE_SCAN_MICROS;
  });
}
