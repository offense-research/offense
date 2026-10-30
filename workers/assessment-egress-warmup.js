import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const message = (expiresAt, nonce) => `purple-assessment-warmup:v1:${expiresAt}:${nonce}`;
const signature = (key, expiresAt, nonce) => createHmac('sha256', key).update(message(expiresAt, nonce)).digest();
const configured = key => typeof key === 'string' && key.length >= 32;

// A readiness capability deliberately has no target and uses a separate HMAC
// context/format. It cannot be forwarded to the target-dialling tunnel route.
export function signAssessmentWarmup(key, now = Date.now) {
  if (!configured(key)) throw new Error('Assessment gateway warmup is unavailable.');
  const expiresAt = now() + 30_000, nonce = randomBytes(16).toString('hex');
  return `warm.v1.${expiresAt}.${nonce}.${signature(key, expiresAt, nonce).toString('hex')}`;
}

export function verifyAssessmentWarmup(token, key, now = Date.now) {
  if (typeof token !== 'string' || token.length > 256 || !configured(key)) throw new Error('Unauthorized warmup.');
  const match = token.match(/^warm\.v1\.(\d{13})\.([a-f0-9]{32})\.([a-f0-9]{64})$/);
  if (!match) throw new Error('Unauthorized warmup.');
  const expiresAt = Number(match[1]), nonce = match[2];
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now() || expiresAt > now() + 30_000 ||
      !timingSafeEqual(signature(key, expiresAt, nonce), Buffer.from(match[3], 'hex')))
    throw new Error('Unauthorized warmup.');
  return { expiresAt, nonce };
}
