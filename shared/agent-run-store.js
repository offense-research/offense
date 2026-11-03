import { verificationQualified } from '../agent/verification-gate.mjs';

const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function createAgentRunStore(db, { github }) {
  const mapping = db.prepare('SELECT source_worker AS sourceWorker, repository, installation_id AS installationId FROM worker_repositories WHERE session_id = ? ORDER BY source_worker');
  const runForInvestigation = db.prepare('SELECT id, status, repository, commit_sha AS commitSha, result, error, verification, (patch IS NOT NULL) AS hasPatch, created_at AS createdAt, started_at AS startedAt, finished_at AS finishedAt FROM agent_runs WHERE session_id = ? AND investigation_id = ?');

  function mappings(sessionId) { return mapping.all(sessionId); }
  function run(sessionId, investigationId) {
    const row = runForInvestigation.get(sessionId, investigationId);
    if (!row) return null;
    const verification = row.verification ? JSON.parse(row.verification) : null;
    return { ...row, hasPatch: Boolean(row.hasPatch), verification, needsReverification: row.status === 'verified' && !verificationQualified(verification) };
  }
  function patch(sessionId, investigationId) {
    return db.prepare('SELECT patch FROM agent_runs WHERE session_id = ? AND investigation_id = ?').get(sessionId, investigationId)?.patch || null;
  }

  function retry(sessionId, investigationId) {
    if (run(sessionId, investigationId)?.needsReverification) db.prepare("UPDATE agent_runs SET status = 'verification_failed' WHERE session_id = ? AND investigation_id = ? AND status = 'verified'").run(sessionId, investigationId);
    return Boolean(db.prepare(`UPDATE agent_runs SET status = 'queued', error = NULL, result = NULL, patch = NULL, verification = NULL, commit_sha = NULL,
      started_at = NULL, finished_at = NULL, repository = (
        SELECT m.repository FROM investigations i JOIN worker_repositories m
          ON m.session_id = i.session_id AND m.source_worker = i.source_worker
        WHERE i.id = agent_runs.investigation_id AND i.status = 'open'),
      installation_id = (
        SELECT m.installation_id FROM investigations i JOIN worker_repositories m
          ON m.session_id = i.session_id AND m.source_worker = i.source_worker
        WHERE i.id = agent_runs.investigation_id AND i.status = 'open')
      WHERE session_id = ? AND investigation_id = ? AND status IN ('failed', 'verification_failed')
        AND EXISTS (SELECT 1 FROM investigations i JOIN worker_repositories m
          ON m.session_id = i.session_id AND m.source_worker = i.source_worker
          WHERE i.id = agent_runs.investigation_id AND i.status = 'open')`)
      .run(sessionId, investigationId).changes);
  }

  async function setMapping(sessionId, worker, repository, installationId, { onlyIfUnlinked = false } = {}) {
    if (!github) throw new Error('GitHub App agent access is not configured.');
    if (typeof worker !== 'string' || worker.length > 128 || !worker || (repository && !REPOSITORY.test(repository))) throw new Error('Invalid Worker or repository.');
    if (!repository) {
      db.prepare('DELETE FROM worker_repositories WHERE session_id = ? AND source_worker = ?').run(sessionId, worker);
      db.prepare(`DELETE FROM agent_runs WHERE session_id = ? AND status = 'queued' AND investigation_id IN
        (SELECT id FROM investigations WHERE session_id = ? AND source_worker = ?)`).run(sessionId, sessionId, worker);
      return;
    }
    const available = await github.repositories(installationId);
    const selected = available.find(item => item.fullName === repository);
    if (!selected) throw new Error('Repository is not available to this GitHub App installation.');
    if (selected.sizeKb > 250000) throw new Error('Repository exceeds the current 250 MB analysis limit.');
    if (onlyIfUnlinked && mappings(sessionId).some(item => item.sourceWorker === worker)) return;
    db.prepare(`INSERT INTO worker_repositories (session_id, source_worker, repository, installation_id, updated_at)
      VALUES (?, ?, ?, ?, ?) ON CONFLICT(session_id, source_worker) DO UPDATE SET
      repository = excluded.repository, installation_id = excluded.installation_id, updated_at = excluded.updated_at`)
      .run(sessionId, worker, repository, installationId, Date.now());
    db.prepare(`UPDATE agent_runs SET repository = ?, installation_id = ? WHERE session_id = ? AND status = 'queued'
      AND investigation_id IN (SELECT id FROM investigations WHERE session_id = ? AND source_worker = ?)`)
      .run(repository, installationId, sessionId, sessionId, worker);
  }

  function enqueueMapped() {
    db.exec("DELETE FROM agent_runs WHERE status = 'queued' AND investigation_id IN (SELECT id FROM investigations WHERE status != 'open')");
    db.prepare(`INSERT OR IGNORE INTO agent_runs (session_id, investigation_id, repository, installation_id, created_at)
      SELECT i.session_id, i.id, m.repository, m.installation_id, ?
      FROM investigations i JOIN worker_repositories m
        ON m.session_id = i.session_id AND m.source_worker = i.source_worker
      WHERE i.status = 'open' AND i.rule_id IN ('suspicious_request', 'repeated_auth_failure', 'worker_exception', 'resource_limit', 'server_error_burst')`)
      .run(Date.now());
  }

  return { mappings, run, patch, retry, setMapping, enqueueMapped };
}
