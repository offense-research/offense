import express from 'express';
import { createHash, randomBytes } from 'node:crypto';
import { transactionSync } from './db-transaction.js';

const LIFETIME_MS = 10 * 60_000;
const RETENTION_MS = 24 * 60 * 60_000;
const POLL_SECONDS = 5;
const SCOPES = ['tools:call', 'account:read', 'billing:checkout'];
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const MAX_DEVICES = 10_000;
const MAX_LIMITS = 20_000;
const sha = value => createHash('sha256').update(value).digest('hex');
const object = value => value && typeof value === 'object' && !Array.isArray(value);

const schema = `CREATE TABLE IF NOT EXISTS cli_auth_devices (
  id TEXT PRIMARY KEY, device_hash TEXT NOT NULL UNIQUE, user_code_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','consumed')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  last_poll_at INTEGER, poll_interval INTEGER NOT NULL DEFAULT 5,
  user_id TEXT, workspace_id TEXT, approved_at INTEGER, consumed_at INTEGER
);
CREATE INDEX IF NOT EXISTS cli_auth_devices_expiry ON cli_auth_devices(expires_at);
CREATE TABLE IF NOT EXISTS cli_auth_limits (
  bucket_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cli_auth_limits_expiry ON cli_auth_limits(expires_at);`;

class CliAuthError extends Error {
  constructor(code, message, status = 400, retryAfter) {
    super(message); this.code = code; this.status = status; this.retryAfter = retryAfter;
  }
}
const failure = (code, message, status, retryAfter) => new CliAuthError(code, message, status, retryAfter);
const unavailable = () => failure('temporarily_unavailable', 'CLI authorization is temporarily unavailable. Try again later.', 503);

function userCode() {
  const bytes = randomBytes(5); let bits = 0, value = 0, result = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; result += ALPHABET[(value >>> bits) & 31]; }
  }
  return result.slice(0, 4) + '-' + result.slice(4);
}
function normalizeCode(value) {
  if (typeof value !== 'string' || value.length > 16) return null;
  const code = value.trim().toUpperCase();
  if (!/^[A-HJ-NP-Z2-9]{4}-?[A-HJ-NP-Z2-9]{4}$/.test(code)) return null;
  return code.replace('-', '');
}
const displayCode = code => code.slice(0, 4) + '-' + code.slice(4);
const principal = req => ({ userId: req.authUser?.id, workspaceId: req.workspaceId });
const source = req => ({ source: String(req.get('cf-connecting-ip') || req.socket?.remoteAddress || 'unknown').slice(0, 256) });

export function createCliAuth({ db, scans, baseUrl, allowedOrigins, now = Date.now } = {}) {
  if (!db || typeof scans?.issueKey !== 'function') throw new Error('CLI authorization requires account storage and API-key issuance.');
  const base = new URL(baseUrl);
  if ((base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname))) ||
      base.username || base.password || base.search || base.hash || base.pathname !== '/') throw new Error('CLI authorization requires an HTTPS origin.');
  const origins = new Set([base.origin]);
  for (const value of allowedOrigins || []) {
    const origin = new URL(value);
    const local = origin.protocol === 'http:' && base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname);
    if ((!local && origin.protocol !== 'https:') || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/')
      throw new Error('CLI approval origins must be explicit trusted HTTPS origins.');
    origins.add(origin.origin);
  }
  db.exec(schema);

  function time() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) throw unavailable();
    return value;
  }
  function run(action) {
    try {
      const result = transactionSync(db, action);
      if (result instanceof CliAuthError) throw result;
      return result;
    } catch (error) { throw error instanceof CliAuthError ? error : unavailable(); }
  }
  function prune(timestamp) {
    db.prepare('DELETE FROM cli_auth_devices WHERE expires_at <= ?').run(timestamp - RETENTION_MS);
    db.prepare('DELETE FROM cli_auth_limits WHERE expires_at <= ?').run(timestamp);
  }
  function admit(kind, actor, timestamp) {
    const limits = kind === 'start' ? [['global', 60_000, 50], ['global', 3_600_000, 600], [actor, 60_000, 5], [actor, 3_600_000, 20]]
      : kind === 'poll' ? [['global', 60_000, 600], [actor, 60_000, 120]]
        : kind === 'guess' ? [[actor, 60_000, 10], [actor, 3_600_000, 30]]
          : [['global', 60_000, 200], [actor, 60_000, 20], [actor, 3_600_000, 100]];
    const buckets = limits.map(([identity, duration, maximum]) => ({
      key: sha(`${kind}\0${identity}\0${duration}\0${Math.floor(timestamp / duration)}`),
      expires: (Math.floor(timestamp / duration) + 1) * duration, maximum
    }));
    if (buckets.some(bucket => (db.prepare('SELECT count FROM cli_auth_limits WHERE bucket_hash = ?').get(bucket.key)?.count || 0) >= bucket.maximum))
      return failure('slow_down', 'Too many CLI authorization requests. Wait before trying again.', 429, 60);
    if (db.prepare('SELECT COUNT(*) AS n FROM cli_auth_limits').get().n + buckets.length > MAX_LIMITS) return unavailable();
    for (const bucket of buckets) db.prepare(`INSERT INTO cli_auth_limits VALUES (?, ?, 1)
      ON CONFLICT(bucket_hash) DO UPDATE SET count = count + 1`).run(bucket.key, bucket.expires);
    return null;
  }
  function actor(context) { return sha(String(context?.source || 'unknown').slice(0, 256)); }
  function account(input) {
    if (typeof input?.userId !== 'string' || typeof input?.workspaceId !== 'string') return null;
    const row = db.prepare(`SELECT w.id, json_extract(w.data, '$.company') AS name FROM workspaces w
      JOIN memberships m ON m.workspace_id = w.id JOIN users u ON u.id = m.user_id
      WHERE m.user_id = ? AND w.id = ?`).get(input.userId, input.workspaceId);
    return row ? { id: row.id, name: typeof row.name === 'string' ? row.name.slice(0, 120) : 'Your account' } : null;
  }
  function boundTo(row, input) { return !row.user_id || row.user_id === input.userId && row.workspace_id === input.workspaceId; }

  function start(context = {}) {
    return run(() => {
      const timestamp = time(); prune(timestamp);
      const denied = admit('start', actor(context), timestamp); if (denied) return denied;
      if (db.prepare('SELECT COUNT(*) AS n FROM cli_auth_devices').get().n >= MAX_DEVICES) return unavailable();
      const deviceCode = randomBytes(32).toString('hex');
      let code;
      for (let i = 0; i < 5; i++) {
        const candidate = userCode();
        if (!db.prepare('SELECT id FROM cli_auth_devices WHERE user_code_hash = ?').get(sha(normalizeCode(candidate)))) { code = candidate; break; }
      }
      if (!code) return unavailable();
      db.prepare(`INSERT INTO cli_auth_devices
        (id,device_hash,user_code_hash,status,created_at,expires_at,poll_interval)
        VALUES (?,?,?,'pending',?,?,?)`).run(randomBytes(16).toString('hex'), sha(deviceCode), sha(normalizeCode(code)), timestamp, timestamp + LIFETIME_MS, POLL_SECONDS);
      return { device_code: deviceCode, user_code: code, verification_uri: `${base.origin}/device`,
        verification_uri_complete: `${base.origin}/device#code=${code}`, expires_in: LIFETIME_MS / 1000, interval: POLL_SECONDS };
    });
  }
  function poll(deviceCode, context = {}) {
    return run(() => {
      const timestamp = time(); prune(timestamp);
      const identity = actor(context), denied = admit('poll', identity, timestamp); if (denied) return denied;
      const row = typeof deviceCode === 'string' && /^[a-f0-9]{64}$/.test(deviceCode)
        ? db.prepare('SELECT * FROM cli_auth_devices WHERE device_hash = ?').get(sha(deviceCode)) : null;
      if (!row) return admit('guess', identity, timestamp) || failure('invalid_grant', 'This CLI authorization request is invalid. Start sign-in again.');
      if (timestamp >= row.expires_at) return failure('expired_token', 'CLI authorization expired. Start sign-in again.');
      if (row.status === 'denied') return failure('access_denied', 'CLI authorization was declined.', 403);
      if (row.status === 'consumed') return failure('access_denied', 'This CLI authorization was already completed. Start sign-in again.', 403);
      if (row.last_poll_at !== null && timestamp - row.last_poll_at < row.poll_interval * 1000) {
        const interval = Math.min(60, row.poll_interval + POLL_SECONDS);
        db.prepare('UPDATE cli_auth_devices SET last_poll_at = ?, poll_interval = ? WHERE id = ?').run(timestamp, interval, row.id);
        return failure('slow_down', 'Poll less frequently before trying again.', 400, interval);
      }
      db.prepare('UPDATE cli_auth_devices SET last_poll_at = ? WHERE id = ?').run(timestamp, row.id);
      if (row.status === 'pending') return failure('authorization_pending', 'Approve this sign-in in your browser.', 400, row.poll_interval);
      const workspace = account({ userId: row.user_id, workspaceId: row.workspace_id });
      if (!workspace) {
        db.prepare("UPDATE cli_auth_devices SET status = 'denied' WHERE id = ?").run(row.id);
        return failure('access_denied', 'Account access changed. Start sign-in again.', 403);
      }
      // The transaction also contains key insertion. No token is kept for
      // replay: a lost HTTP response requires a fresh login and key revocation.
      const key = scans.issueKey(row.workspace_id, row.user_id, { inTransaction: true });
      if (typeof key?.token !== 'string' || !key.token || typeof key.id !== 'string') throw unavailable();
      const consumed = db.prepare("UPDATE cli_auth_devices SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'approved'").run(timestamp, row.id);
      if (consumed.changes !== 1) throw unavailable();
      return { access_token: key.token, token_type: 'Bearer', scope: SCOPES.join(' '), key_id: key.id, workspace };
    });
  }
  function inspect(code, input) {
    return run(() => {
      const timestamp = time(); prune(timestamp);
      const workspace = account(input);
      if (!workspace) return failure('access_denied', 'Sign in to an account you can access before approving the CLI.', 403);
      const denied = admit('browser', sha(input.userId), timestamp); if (denied) return denied;
      const normalized = normalizeCode(code);
      const row = normalized && db.prepare('SELECT * FROM cli_auth_devices WHERE user_code_hash = ?').get(sha(normalized));
      if (!row) return failure('invalid_request', 'Check the code displayed by your CLI and try again.');
      if (!boundTo(row, input)) return failure('access_denied', 'This sign-in belongs to a different account. Start sign-in again.', 403);
      // Bind the account shown on the consent screen before approval. Another
      // tab changing the active workspace cannot silently widen this grant.
      if (timestamp < row.expires_at && row.status === 'pending' && !row.user_id) {
        db.prepare("UPDATE cli_auth_devices SET user_id = ?, workspace_id = ? WHERE id = ? AND status = 'pending' AND user_id IS NULL")
          .run(input.userId, input.workspaceId, row.id);
      }
      return { user_code: displayCode(normalized), status: timestamp >= row.expires_at ? 'expired' : row.status === 'consumed' ? 'approved' : row.status,
        completed: row.status === 'consumed', expiresAt: row.expires_at, workspace, scopes: [...SCOPES] };
    });
  }
  function approve(code, approved, input) {
    return run(() => {
      const timestamp = time(); prune(timestamp);
      const workspace = account(input);
      if (!workspace) return failure('access_denied', 'Sign in to an account you can access before approving the CLI.', 403);
      const denied = admit('browser', sha(input.userId), timestamp); if (denied) return denied;
      if (typeof approved !== 'boolean') return failure('invalid_request', 'Choose whether to approve this CLI sign-in.');
      const normalized = normalizeCode(code);
      const row = normalized && db.prepare('SELECT * FROM cli_auth_devices WHERE user_code_hash = ?').get(sha(normalized));
      if (!row) return failure('invalid_request', 'Check the code displayed by your CLI and try again.');
      if (!boundTo(row, input)) return failure('access_denied', 'This sign-in belongs to a different account. Start sign-in again.', 403);
      if (timestamp >= row.expires_at) return failure('expired_token', 'CLI authorization expired. Start sign-in again.');
      if (row.status === 'consumed') return approved ? { status: 'approved', completed: true, workspace }
        : failure('invalid_request', 'Sign-in already completed. Revoke its API key in your account to remove access.');
      if (row.status === 'denied') return { status: 'denied', workspace };
      db.prepare(`UPDATE cli_auth_devices SET status = ?, user_id = ?, workspace_id = ?, approved_at = ? WHERE id = ?`)
        .run(approved ? 'approved' : 'denied', input.userId, input.workspaceId, timestamp, row.id);
      return { status: approved ? 'approved' : 'denied', workspace };
    });
  }
  return Object.freeze({ origin: base.origin, origins, start, poll, inspect, approve });
}

function sendError(res, error) {
  const value = error instanceof CliAuthError ? error : unavailable();
  if (value.retryAfter) res.set('Retry-After', String(value.retryAfter));
  return res.status(value.status).json({ error: value.code, error_description: value.message });
}
function noCache(req, res, next) {
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache', 'X-Content-Type-Options': 'nosniff' }); next();
}
const only = (body, fields) => object(body) && Object.keys(body).every(key => fields.includes(key));

export function registerCliAuthPublic(app, { auth }) {
  const router = express.Router();
  router.use(noCache, (req, res, next) => req.get('origin')
    ? sendError(res, failure('access_denied', 'Start CLI sign-in from your terminal.', 403)) : next());
  router.use(express.json({ limit: '8kb', strict: true }));
  router.post('/device', (req, res) => {
    if (req.body !== undefined && !only(req.body, [])) return sendError(res, failure('invalid_request', 'This sign-in request does not accept account or credential fields.'));
    try { res.json(auth.start(source(req))); } catch (error) { sendError(res, error); }
  });
  router.post('/device/token', (req, res) => {
    if (!only(req.body, ['device_code'])) return sendError(res, failure('invalid_request', 'Provide only the device_code from your CLI.'));
    try { res.json(auth.poll(req.body.device_code, source(req))); } catch (error) { sendError(res, error); }
  });
  router.use((error, req, res, next) => res.headersSent ? next(error)
    : sendError(res, failure('invalid_request', 'Invalid or oversized CLI authorization request.', error.type === 'entity.too.large' ? 413 : 400)));
  app.use('/v1/auth', router);
}

export function registerCliAuthBrowser(app, { auth }) {
  const ready = (req, res, next) => {
    if (!req.authUser || !req.workspaceId) return sendError(res, failure('access_denied', 'Sign in before approving the CLI.', 401));
    if (!auth.origins.has(req.get('origin'))) return sendError(res, failure('access_denied', 'Approve CLI sign-in from this application.', 403));
    next();
  };
  const invalidBody = (error, req, res, next) => res.headersSent ? next(error)
    : sendError(res, failure('invalid_request', 'Invalid or oversized CLI authorization request.', error.type === 'entity.too.large' ? 413 : 400));
  app.post('/api/cli/device/inspect', noCache, ready, express.json({ limit: '8kb', strict: true }), (req, res) => {
    if (!only(req.body, ['user_code'])) return sendError(res, failure('invalid_request', 'Provide only the code displayed by your CLI.'));
    try { res.json(auth.inspect(req.body.user_code, principal(req))); } catch (error) { sendError(res, error); }
  }, invalidBody);
  app.post('/api/cli/device/approve', noCache, ready, express.json({ limit: '8kb', strict: true }), (req, res) => {
    if (!only(req.body, ['user_code', 'approved'])) return sendError(res, failure('invalid_request', 'Provide only the CLI code and your approval choice.'));
    try { res.json(auth.approve(req.body.user_code, req.body.approved, principal(req))); } catch (error) { sendError(res, error); }
  }, invalidBody);
}
