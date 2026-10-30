import { createHash } from 'node:crypto';
import { transactionSync } from './db-transaction.js';

export const WELCOME_CREDIT_MICROS = 5_000_000;
const prefix = 'welcome:v1:';
const unavailable = () => Object.assign(new Error('Welcome credit is temporarily unavailable.'), {
  status: 503, code: 'welcome_credit_unavailable'
});
const ineligible = () => Object.assign(new Error('Sign in to an account you can access before receiving welcome credit.'), {
  status: 403, code: 'welcome_credit_ineligible'
});
const validId = value => typeof value === 'string' && value.length > 0 && value.length <= 128;

// Eligibility comes only from the stored GitHub identity and current account
// membership. No route accepts an identity, grant amount or ledger ID from a
// caller. The existing ledger's global primary key also preserves this claim
// through normal wallet backup/restore without a second entitlement table.
export function createWelcomeCredit(db, { now = Date.now } = {}) {
  if (!db || typeof db.prepare !== 'function') throw new Error('Welcome credit requires account and scanner-wallet storage.');

  function identity(userId, workspaceId) {
    if (!validId(userId) || !validId(workspaceId)) throw ineligible();
    const user = db.prepare(`SELECT u.github_id FROM users u
      JOIN memberships m ON m.user_id = u.id JOIN workspaces w ON w.id = m.workspace_id
      WHERE u.id = ? AND w.id = ?`).get(userId, workspaceId);
    if (!user || typeof user.github_id !== 'string' || !/^[1-9]\d{0,15}$/.test(user.github_id) ||
        BigInt(user.github_id) > BigInt(Number.MAX_SAFE_INTEGER)) throw ineligible();
    return prefix + createHash('sha256').update(user.github_id).digest('hex');
  }

  function claim(id) {
    const row = db.prepare('SELECT workspace_id, amount_micros, kind, created_at FROM scan_wallet_entries WHERE id = ?').get(id);
    // Earlier users keep their $10 grant and their existing one-time claim ID.
    if (row && (row.kind !== 'welcome' || ![WELCOME_CREDIT_MICROS, 10_000_000].includes(row.amount_micros) ||
        !validId(row.workspace_id) || !Number.isSafeInteger(row.created_at) || row.created_at < 0)) throw unavailable();
    return row;
  }

  function summary(row, workspaceId) {
    return { amountMicros: row?.amount_micros ?? WELCOME_CREDIT_MICROS, currency: 'usd', claimed: !!row,
      appliedToCurrentWorkspace: !!row && row.workspace_id === workspaceId, grantedAt: row?.created_at ?? null };
  }

  function run(action) {
    try { return transactionSync(db, action); }
    catch (error) {
      if (['welcome_credit_ineligible', 'welcome_credit_unavailable'].includes(error.code)) throw error;
      throw unavailable();
    }
  }

  function grantForUser(userId, workspaceId) {
    return run(() => {
      const id = identity(userId, workspaceId), previous = claim(id);
      if (previous) return { ...summary(previous, workspaceId), granted: false };
      const timestamp = now();
      if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw unavailable();
      const inserted = db.prepare(`INSERT OR IGNORE INTO scan_wallet_entries
        (id, workspace_id, amount_micros, kind, created_at) VALUES (?, ?, ?, 'welcome', ?)`)
        .run(id, workspaceId, WELCOME_CREDIT_MICROS, timestamp);
      const row = claim(id);
      if (!row) throw unavailable();
      return { ...summary(row, workspaceId), granted: inserted.changes === 1 };
    });
  }

  function statusForUser(userId, workspaceId) {
    return run(() => summary(claim(identity(userId, workspaceId)), workspaceId));
  }

  return { grantForUser, statusForUser };
}
