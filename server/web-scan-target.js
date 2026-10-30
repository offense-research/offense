import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

const CHALLENGE_LIFETIME_MS = 10 * 60_000;
const VERIFIED_LIFETIME_MS = 5 * 60_000;
const blockedSuffixes = ['.localhost', '.local', '.internal', '.test', '.invalid', '.onion', '.arpa', '.lan', '.home', '.corp'];

function signingKey(key) {
  const bytes = typeof key === 'string' ? Buffer.from(key) : key;
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 32) throw new Error('Web scan signing key is unavailable.');
  return bytes;
}

function workspaceName(workspaceId) {
  if (typeof workspaceId !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/.test(workspaceId))
    throw new Error('Invalid web scan workspace.');
  return workspaceId;
}

export function webScanOrigin(value) {
  if (typeof value !== 'string' || value.length > 2048 || value.length < 12) throw new Error('Use a public HTTPS origin.');
  let url;
  try { url = new URL(value); } catch { throw new Error('Use a public HTTPS origin.'); }
  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split('.');
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash || value.includes('@') ||
      hostname.endsWith('.') || isIP(hostname.replace(/^\[|\]$/g, '')) ||
      labels.length < 2 || !/^[a-z]{2,63}$/.test(labels.at(-1)) ||
      labels.some(label => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label)) ||
      blockedSuffixes.some(suffix => hostname.endsWith(suffix))) {
    throw new Error('Use a public HTTPS origin.');
  }
  return url.origin;
}

function hmac(key, workspaceId, origin, token, expiresAt) {
  return createHmac('sha256', signingKey(key)).update(JSON.stringify(['purple-web-target-v1', workspaceId, origin, token, expiresAt])).digest('hex');
}

export function issueWebTargetChallenge({ target, workspaceId, key, now = Date.now, random = randomBytes }) {
  const origin = webScanOrigin(target), workspace = workspaceName(workspaceId);
  const token = random(24).toString('base64url');
  if (!/^[a-zA-Z0-9_-]{32}$/.test(token)) throw new Error('Could not create web scan challenge.');
  const expiresAt = now() + CHALLENGE_LIFETIME_MS;
  return { origin, recordName: `_purple-scan.${new URL(origin).hostname}`,
    recordValue: `purple-scan-verification=${token}`, token, expiresAt,
    signature: hmac(key, workspace, origin, token, expiresAt) };
}

function publicIpv4(value) {
  const parts = value.split('.').map(Number);
  const address = parts.reduce((n, part) => ((n << 8) | part) >>> 0, 0);
  const blocked = [
    [0x00000000, 8], [0x0a000000, 8], [0x64400000, 10], [0x7f000000, 8],
    [0xa9fe0000, 16], [0xac100000, 12], [0xc0000000, 24], [0xc0000200, 24],
    [0xc0586300, 24], [0xc0a80000, 16], [0xc6120000, 15], [0xc6336400, 24],
    [0xcb007100, 24], [0xe0000000, 4], [0xf0000000, 4]
  ];
  return !blocked.some(([base, bits]) => {
    const mask = (0xffffffff << (32 - bits)) >>> 0;
    return (address & mask) >>> 0 === base;
  });
}

export function publicWebScanAddress(value) {
  if (typeof value !== 'string' || value.includes('%')) return false;
  const family = isIP(value);
  if (family === 4) return publicIpv4(value);
  if (family !== 6 || value.includes('.')) return false; // Includes IPv4-mapped and transition addresses.
  const [first = '0', second = '0', third = '0'] = value.toLowerCase().split('::')[0].split(':');
  const a = parseInt(first || '0', 16), b = parseInt(second || '0', 16), c = parseInt(third || '0', 16);
  if (a < 0x2000 || a > 0x3fff) return false; // Only global unicast.
  if (a === 0x2002 || (a === 0x2001 && (b === 0 || b === 0xdb8 || (b === 2 && c === 0)))) return false;
  return true;
}

function txtValues(records) {
  if (!Array.isArray(records) || records.length > 64) throw new Error('Web scan ownership proof is unavailable.');
  return records.map(record => Array.isArray(record) ? record.join('') : record);
}

export async function verifyWebTargetChallenge({ challenge, workspaceId, key, resolveTxt, resolveAddresses, now = Date.now }) {
  if (!challenge || typeof challenge !== 'object' || typeof resolveTxt !== 'function' || typeof resolveAddresses !== 'function')
    throw new Error('Web scan ownership proof is unavailable.');
  const origin = webScanOrigin(challenge.origin), workspace = workspaceName(workspaceId);
  const expiresAt = challenge.expiresAt, token = challenge.token;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now() || expiresAt > now() + CHALLENGE_LIFETIME_MS ||
      typeof token !== 'string' || !/^[a-zA-Z0-9_-]{32}$/.test(token) ||
      typeof challenge.signature !== 'string' || !/^[a-f0-9]{64}$/.test(challenge.signature))
    throw new Error('Web scan ownership proof is invalid or expired.');
  const expected = Buffer.from(hmac(key, workspace, origin, token, expiresAt), 'hex');
  if (!timingSafeEqual(expected, Buffer.from(challenge.signature, 'hex')))
    throw new Error('Web scan ownership proof is invalid or expired.');
  const hostname = new URL(origin).hostname;
  const recordName = `_purple-scan.${hostname}`;
  if (challenge.recordName !== recordName || challenge.recordValue !== `purple-scan-verification=${token}`)
    throw new Error('Web scan ownership proof is invalid or expired.');
  const records = txtValues(await resolveTxt(recordName));
  if (!records.includes(challenge.recordValue)) throw new Error('The target does not publish the requested ownership proof.');
  const addresses = await resolveAddresses(hostname);
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > 32 ||
      addresses.some(address => !publicWebScanAddress(typeof address === 'string' ? address : address?.address)))
    throw new Error('The target does not resolve exclusively to public addresses.');
  return Object.freeze({ origin, hostname, addresses: Object.freeze(addresses.map(address => typeof address === 'string' ? address : address.address)),
    verifiedAt: now(), expiresAt: Math.min(expiresAt, now() + VERIFIED_LIFETIME_MS) });
}

export function webScanUrlInScope(value, origin) {
  let url;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === 'https:' && !url.username && !url.password && url.origin === webScanOrigin(origin);
}
