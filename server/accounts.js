import { randomBytes } from 'node:crypto';
import { cloneJson, mergeJsonDraft } from './json-draft.js';
import { transactionSync } from './db-transaction.js';

export function createAccounts(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, github_id TEXT NOT NULL UNIQUE, login TEXT NOT NULL, created_at INTEGER NOT NULL
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS memberships (
    user_id TEXT NOT NULL, workspace_id TEXT NOT NULL, role TEXT NOT NULL,
    PRIMARY KEY (user_id, workspace_id),
    FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS account_connections (
    user_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  db.exec(`CREATE TABLE IF NOT EXISTS workspace_revisions (
    id INTEGER PRIMARY KEY, workspace_id TEXT NOT NULL, data TEXT NOT NULL,
    reason TEXT NOT NULL, created_at INTEGER NOT NULL
  )`);
  db.exec('CREATE INDEX IF NOT EXISTS workspace_revisions_by_workspace ON workspace_revisions(workspace_id, id DESC)');

  function findUser(id) { return db.prepare('SELECT id, github_id AS githubId, login FROM users WHERE id = ?').get(id); }
  function workspaceForUser(userId, preferredId) {
    return db.prepare(`SELECT w.id, w.data FROM workspaces w
      JOIN memberships m ON m.workspace_id = w.id
      WHERE m.user_id = ? ORDER BY (w.id = ?) DESC,
      COALESCE(json_extract(w.data, '$.collectorInstall.status') = 'installed', 0) DESC,
      ((json_extract(w.data, '$.cloudflare') IS NOT NULL) + (json_extract(w.data, '$.github') IS NOT NULL) + (json_extract(w.data, '$.openrouter') IS NOT NULL)) DESC,
      w.updated_at DESC, w.created_at ASC LIMIT 1`).get(userId, preferredId || '');
  }
  function upsertUser(githubId, login) {
    const id = randomBytes(16).toString('hex');
    db.prepare(`INSERT INTO users (id, github_id, login, created_at) VALUES (?, ?, ?, ?)
      ON CONFLICT(github_id) DO UPDATE SET login = excluded.login`).run(id, String(githubId), login, Date.now());
    return db.prepare('SELECT id, github_id AS githubId, login FROM users WHERE github_id = ?').get(String(githubId));
  }
  function updateAccountConnections(userId, update) {
    return transactionSync(db, () => {
      if (!findUser(userId)) throw new Error('Sign in first.');
      const row = db.prepare('SELECT data FROM account_connections WHERE user_id = ?').get(userId);
      const data = row ? JSON.parse(row.data) : {};
      update(data);
      db.prepare(`INSERT INTO account_connections (user_id, data, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
        .run(userId, JSON.stringify(data), Date.now());
      return data;
    });
  }
  function createWorkspace(userId, id, data) {
    const now = Date.now();
    return transactionSync(db, () => {
      const pending = db.prepare('SELECT data FROM account_connections WHERE user_id = ?').get(userId);
      const initial = { ...(pending ? JSON.parse(pending.data) : {}), ...data };
      if (initial.githubAuthorization && initial.githubAuthorization.userId !== userId) throw new Error('GitHub authorization belongs to another user.');
      db.prepare('INSERT INTO workspaces (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)').run(id, JSON.stringify(initial), now, now);
      db.prepare("INSERT INTO memberships (user_id, workspace_id, role) VALUES (?, ?, 'owner')").run(userId, id);
      db.prepare('DELETE FROM account_connections WHERE user_id = ?').run(userId);
      return { id, data: JSON.stringify(initial) };
    });
  }
  function ensureWorkspace(userId, preferredId) {
    const existing = workspaceForUser(userId, preferredId);
    if (existing) {
      const data = JSON.parse(existing.data);
      if (!data.company) {
        data.company = findUser(userId).login;
        saveWorkspace(existing.id, data);
      }
      return { id: existing.id, data: JSON.stringify(data) };
    }
    const user = findUser(userId);
    if (!user) throw new Error('Sign in first.');
    return createWorkspace(userId, randomBytes(32).toString('hex'), { company: user.login });
  }
  function writeWorkspace(id, data, reason) {
    const row = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
    if (!row) throw new Error('Workspace no longer exists. Sign in again.');
    const serialized = JSON.stringify(data);
    if (serialized === row.data) return data;
    db.prepare('INSERT INTO workspace_revisions (workspace_id, data, reason, created_at) VALUES (?, ?, ?, ?)')
      .run(id, row.data, reason, Date.now());
    db.prepare('UPDATE workspaces SET data = ?, updated_at = ? WHERE id = ?').run(serialized, Date.now(), id);
    db.prepare('DELETE FROM workspace_revisions WHERE workspace_id = ? AND id NOT IN (SELECT id FROM workspace_revisions WHERE workspace_id = ? ORDER BY id DESC LIMIT 100)').run(id, id);
    return data;
  }
  function saveWorkspace(id, data, baseline) {
    return transactionSync(db, () => {
      const row = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
      if (!row) throw new Error('Workspace no longer exists. Sign in again.');
      const merged = baseline === undefined ? cloneJson(data) : mergeJsonDraft(baseline, cloneJson(data), JSON.parse(row.data));
      return writeWorkspace(id, merged, 'request-save');
    });
  }
  function updateWorkspace(id, update, reason = 'account-update') {
    return transactionSync(db, () => {
      const row = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
      if (!row) throw new Error('Workspace no longer exists. Sign in again.');
      const data = JSON.parse(row.data);
      const result = update(data);
      if (result && typeof result.then === 'function') throw new Error('Workspace update must be synchronous.');
      return writeWorkspace(id, data, reason);
    });
  }
  function claimLegacy(userId, sourceSessionId, data) {
    const existing = workspaceForUser(userId);
    if (!existing) return createWorkspace(userId, sourceSessionId, data);
    const current = JSON.parse(existing.data);
    const incomingCollector = data.collectorInstall?.status === 'installed';
    const replacePartial = incomingCollector && !current.github && !current.openrouter && !current.collectorInstall;
    if ((current.cloudflare || current.github || current.openrouter || current.collectorInstall) && !replacePartial) {
      throw new Error('This GitHub user already owns a connected Purple workspace. Your earlier browser workspace was kept separate.');
    }
    const claimed = { ...data };
    if (replacePartial && current.cloudflare?.accounts?.some(account => account.id === data.collectorInstall.accountId)) {
      claimed.cloudflare = current.cloudflare;
    }
    transactionSync(db, () => {
      writeWorkspace(existing.id, claimed, 'legacy-claim');
      db.prepare('UPDATE ingest_tokens SET session_id = ? WHERE session_id = ?').run(existing.id, sourceSessionId);
      db.prepare('UPDATE events SET session_id = ?, exported_at = NULL WHERE session_id = ?').run(existing.id, sourceSessionId);
      db.prepare('UPDATE detection_signals SET session_id = ? WHERE session_id = ?').run(existing.id, sourceSessionId);
      db.prepare('UPDATE investigations SET session_id = ? WHERE session_id = ?').run(existing.id, sourceSessionId);
      db.prepare('UPDATE ingest_batches SET session_id = ? WHERE session_id = ?').run(existing.id, sourceSessionId);
      if (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vulnerability_discoveries'").get()) {
        db.prepare('UPDATE vulnerability_discoveries SET session_id = ? WHERE session_id = ?').run(existing.id, sourceSessionId);
      }
    });
    return { id: existing.id, data: JSON.stringify(claimed) };
  }
  function unclaimedPersonalInstall(accountLogin, installationId) {
    const rows = db.prepare(`SELECT id, data FROM sessions
      WHERE json_extract(data, '$.github.account') = ?
        AND json_extract(data, '$.github.installationId') = ?
        AND json_extract(data, '$.collectorInstall.status') = 'installed'
        AND json_extract(data, '$.userId') IS NULL`).all(accountLogin, installationId);
    return rows.length === 1 ? { id: rows[0].id, data: JSON.parse(rows[0].data) } : null;
  }
  return { findUser, ensureWorkspace, workspaceForUser, upsertUser, createWorkspace, saveWorkspace, updateWorkspace, updateAccountConnections, claimLegacy, unclaimedPersonalInstall };
}
