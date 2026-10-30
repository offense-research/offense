import { createHmac, timingSafeEqual, randomBytes } from 'node:crypto';
import { publicWebScanAddress } from '../server/web-scan-target.js';

export function signAssessmentTunnel({ host, address }, key, now = Date.now) {
  if (typeof key !== 'string' || key.length < 32 || !/^[a-z0-9.-]{1,253}$/.test(host) || !publicWebScanAddress(address))
    throw new Error('Assessment egress is not configured.');
  const payload = Buffer.from(JSON.stringify({ host, address, port: 443, expiresAt: now() + 30_000,
    nonce: randomBytes(16).toString('hex') })).toString('base64url');
  return `${payload}.${createHmac('sha256', key).update(payload).digest('hex')}`;
}

export function verifyAssessmentTunnel(token, key, now = Date.now) {
  if (typeof token !== 'string' || token.length > 2048 || typeof key !== 'string' || key.length < 32) throw new Error('Unauthorized tunnel.');
  const [payload, signature, extra] = token.split('.');
  if (extra || !payload || !/^[a-f0-9]{64}$/.test(signature || '')) throw new Error('Unauthorized tunnel.');
  const expected = createHmac('sha256', key).update(payload).digest();
  if (!timingSafeEqual(expected, Buffer.from(signature, 'hex'))) throw new Error('Unauthorized tunnel.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  if (!claims || !/^[a-z0-9.-]{1,253}$/.test(claims.host || '') || !publicWebScanAddress(claims.address) ||
      claims.port !== 443 || !Number.isSafeInteger(claims.expiresAt) || claims.expiresAt <= now() ||
      claims.expiresAt > now() + 30_000 || !/^[a-f0-9]{32}$/.test(claims.nonce || '')) throw new Error('Unauthorized tunnel.');
  return claims;
}
