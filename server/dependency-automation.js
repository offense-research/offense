import { randomUUID } from 'node:crypto';
import { defaultAutomationPolicy, normalizeAutomationPolicy } from '../shared/offense-policy.js';

export const dependencyAutomationSchema = `
CREATE TABLE IF NOT EXISTS dependency_automation_policies (
  session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
  policy_json TEXT NOT NULL, updated_at INTEGER NOT NULL,
  PRIMARY KEY (session_id, repository, installation_id)
);
CREATE TABLE IF NOT EXISTS dependency_automation_runs (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, repository TEXT NOT NULL,
  installation_id INTEGER NOT NULL, trigger TEXT NOT NULL, status TEXT NOT NULL,
  started_at INTEGER NOT NULL, finished_at INTEGER, duration_ms INTEGER,
  revision TEXT, advisory_matches INTEGER, coverage_status TEXT NOT NULL,
  error_code TEXT
);
CREATE INDEX IF NOT EXISTS dependency_automation_runs_repository
  ON dependency_automation_runs(session_id, repository, installation_id, started_at, id);
`;

const runView = row => row ? { id: row.id, trigger: row.trigger, status: row.status,
  startedAt: row.started_at, finishedAt: row.finished_at, durationMs: row.duration_ms,
  revision: row.revision, advisoryMatches: row.advisory_matches,
  coverageStatus: row.coverage_status, errorCode: row.error_code } : null;

// This is bounded operational history, separate from billing and confirmed
// vulnerability/discovery metrics. Repeated advisory matches are observations.
export function createDependencyAutomationStore(db, { now = Date.now } = {}) {
  db.exec(dependencyAutomationSchema);
  const key = (id, repository, installationId) => [id, repository, installationId];
  const find = db.prepare('SELECT policy_json FROM dependency_automation_policies WHERE session_id = ? AND repository = ? AND installation_id = ?');
  const save = db.prepare(`INSERT INTO dependency_automation_policies VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(session_id, repository, installation_id) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at`);
  const history = db.prepare(`SELECT * FROM dependency_automation_runs WHERE session_id = ? AND repository = ? AND installation_id = ?
    ORDER BY started_at DESC, id DESC LIMIT 10`);
  function policy(id, repository, installationId) {
    const row = find.get(...key(id, repository, installationId));
    if (!row) return defaultAutomationPolicy();
    try { return normalizeAutomationPolicy(JSON.parse(row.policy_json)); }
    catch { return { ...defaultAutomationPolicy(), enabled: false }; }
  }
  function configure(id, repository, installationId, input) {
    const result = normalizeAutomationPolicy(input);
    save.run(...key(id, repository, installationId), JSON.stringify(result), now());
    return result;
  }
  function recent(id, repository, installationId) { return history.all(...key(id, repository, installationId)).map(runView); }
  function recoverInterrupted(activeLocks) {
    for (const row of db.prepare("SELECT id, session_id, repository, installation_id FROM dependency_automation_runs WHERE status = 'running'").all()) {
      if (activeLocks.has(`${row.session_id}:${row.installation_id}:${row.repository}`)) continue;
      // Time while an isolate was absent is not measured scan execution time.
      db.prepare("UPDATE dependency_automation_runs SET status = 'interrupted', finished_at = ?, duration_ms = NULL, error_code = 'interrupted' WHERE id = ? AND status = 'running'")
        .run(now(), row.id);
    }
  }
  function start(id, repository, installationId, trigger) {
    const startedAt = now(), runId = randomUUID();
    // A previous isolate may have stopped mid-run. Repository locks prevent a
    // second active dispatcher from retiring a live run in the same process.
    db.prepare(`UPDATE dependency_automation_runs SET status = 'interrupted', finished_at = ?,
      duration_ms = NULL, error_code = 'interrupted'
      WHERE session_id = ? AND repository = ? AND installation_id = ? AND status = 'running'`)
      .run(startedAt, ...key(id, repository, installationId));
    db.prepare(`INSERT INTO dependency_automation_runs
      (id, session_id, repository, installation_id, trigger, status, started_at, coverage_status)
      VALUES (?, ?, ?, ?, ?, 'running', ?, 'unknown')`).run(runId, ...key(id, repository, installationId), trigger, startedAt);
    return runId;
  }
  function finish(runId, status, snapshot = null, errorCode = null) {
    const finishedAt = now();
    const revision = typeof snapshot?.revision === 'string' ? snapshot.revision.slice(0, 200) : null;
    const count = Array.isArray(snapshot?.vulnerabilityCheck?.findings) ? Math.min(1_000_000, snapshot.vulnerabilityCheck.findings.length) : null;
    const coverage = snapshot ? status === 'completed' ? 'complete' : 'partial' : 'unknown';
    db.prepare(`UPDATE dependency_automation_runs SET status = ?, finished_at = ?, duration_ms = MAX(0, ? - started_at),
      revision = ?, advisory_matches = ?, coverage_status = ?, error_code = ? WHERE id = ? AND status = 'running'`)
      .run(status, finishedAt, finishedAt, revision, count, coverage, errorCode, runId);
    const row = db.prepare('SELECT session_id, repository, installation_id FROM dependency_automation_runs WHERE id = ?').get(runId);
    if (row) db.prepare(`DELETE FROM dependency_automation_runs WHERE id IN (
      SELECT id FROM dependency_automation_runs WHERE session_id = ? AND repository = ? AND installation_id = ?
      AND status != 'running' ORDER BY started_at DESC, id DESC LIMIT -1 OFFSET 1000
    )`).run(row.session_id, row.repository, row.installation_id);
  }
  return { policy, configure, recent, start, finish, recoverInterrupted };
}
