import { createAgentRunStore } from '../shared/agent-run-store.js';
import { verificationQualified } from '../agent/verification-gate.mjs';
import { createVulnerabilityStore } from '../server/vulnerability-store.js';
import { randomBytes } from 'node:crypto';
import { workspaceInstallations } from '../server/github-installations.js';


export function createAgentRunner(db, { github, decrypt, sandbox, model = 'deepseek/deepseek-v4.1-flash', searchLogs = null }) {
  db.exec(`CREATE TABLE IF NOT EXISTS worker_repositories (
    session_id TEXT NOT NULL, source_worker TEXT NOT NULL, repository TEXT NOT NULL,
    installation_id INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, source_worker)
  )`);
  db.exec(`CREATE TABLE IF NOT EXISTS agent_runs (
    id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, investigation_id INTEGER NOT NULL UNIQUE,
    repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', commit_sha TEXT, result TEXT, error TEXT,
    created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER
  )`);
  const runColumns = new Set(db.prepare('PRAGMA table_info(agent_runs)').all().map(column => column.name));
  if (!runColumns.has('patch')) db.exec('ALTER TABLE agent_runs ADD COLUMN patch TEXT');
  if (!runColumns.has('attempt_id')) db.exec('ALTER TABLE agent_runs ADD COLUMN attempt_id TEXT');
  if (!runColumns.has('verification')) db.exec('ALTER TABLE agent_runs ADD COLUMN verification TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS agent_runs_workspace ON agent_runs(session_id, created_at DESC)');

  const vulnerabilities = createVulnerabilityStore(db);

  const { mappings, run, patch, retry, setMapping, enqueueMapped } = createAgentRunStore(db, { github });

  function saveResult(id, result) {
    if (result.status === 'failed') {
      db.prepare("UPDATE agent_runs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run(String(result.error || 'Pi analysis failed.').slice(0, 1000), Date.now(), id);
      return;
    }
    if (!['completed', 'verified', 'verification_failed'].includes(result.status)) throw new Error('Pi returned an invalid status.');
    if (result.status === 'verified' && !verificationQualified(result.verification)) { result.status = 'verification_failed'; result.verification = { ...result.verification, verified: false, blocker: 'Agent result did not satisfy the current structured verification gate.' }; }
    db.prepare('UPDATE agent_runs SET status = ?, commit_sha = ?, result = ?, patch = ?, verification = ?, finished_at = ? WHERE id = ?')
      .run(result.status, result.commitSha || null, result.summary || null, result.patch || null,
        result.verification ? JSON.stringify(result.verification) : null, Date.now(), id);
    vulnerabilities.record(id);
  }

  async function pollRunning() {
    const job = db.prepare("SELECT id, started_at AS startedAt, attempt_id AS attemptId FROM agent_runs WHERE status = 'running' ORDER BY started_at LIMIT 1").get();
    if (!job || !sandbox) return false;
    if (Date.now() - job.startedAt > 16 * 60_000) {
      saveResult(job.id, { status: 'failed', error: 'Pi analysis timed out.' });
      return true;
    }
    try {
      const result = await sandbox.getInvestigation(job.id, job.attemptId);
      if (result.status === 'running') return false;
      if (result.status === 'missing') {
        saveResult(job.id, { status: 'failed', error: 'Pi container lost the investigation.' });
      } else saveResult(job.id, result);
      return true;
    } catch (error) {
      console.error(`Pi result check paused: ${error.message}`);
      return false;
    }
  }

  async function processOne() {
    if (db.prepare("SELECT COUNT(*) AS count FROM agent_runs WHERE status = 'running'").get().count >= 1) return false;
    const job = db.prepare(`SELECT r.id, r.session_id AS sessionId, r.investigation_id AS investigationId,
      r.repository, r.installation_id AS installationId, w.data AS workspaceData,
      i.source_worker AS sourceWorker, i.rule_id AS ruleId, i.title, i.description,
      i.severity, i.first_seen AS firstSeen, i.last_seen AS lastSeen
      FROM agent_runs r JOIN workspaces w ON w.id = r.session_id
      JOIN investigations i ON i.id = r.investigation_id AND i.session_id = r.session_id
      WHERE r.status = 'queued' AND i.status = 'open' ORDER BY r.id LIMIT 1`).get();
    if (!job) return false;
    const attemptId = randomBytes(16).toString('hex');
    const claimed = db.prepare("UPDATE agent_runs SET status = 'running', started_at = ?, attempt_id = ? WHERE id = ? AND status = 'queued'").run(Date.now(), attemptId, job.id);
    if (!claimed.changes) return false;
    try {
      if (!github || !sandbox) throw new Error('Cloudflare agent sandbox is not configured.');
      const workspace = JSON.parse(job.workspaceData);
      if (!workspaceInstallations(workspace).some(item => item.installationId === job.installationId)) throw new Error('GitHub installation changed. Reconnect the repository mapping.');
      if (!workspace.openrouter?.secret) throw new Error('Connect an OpenRouter key before running Pi.');
      const key = decrypt(workspace.openrouter.secret);
      if (!key) throw new Error('Could not decrypt the OpenRouter key.');
      const githubToken = await github.installationToken(job.installationId, job.repository);
      const rows = db.prepare(`SELECT e.id, e.received_at AS receivedAt, e.payload FROM investigation_events ie
        JOIN events e ON e.id = ie.event_id AND e.session_id = ?
        WHERE ie.investigation_id = ? ORDER BY ie.received_at DESC LIMIT 100`).all(job.sessionId, job.investigationId);
      let logs = rows.map(row => ({ id: row.id, receivedAt: row.receivedAt, ...JSON.parse(row.payload) }));
      if (searchLogs && logs.length < 20) {
        try {
          const found = await searchLogs(job.sessionId, { worker: job.sourceWorker, from: job.firstSeen - 300000, to: job.lastSeen + 300001, limit: 100 });
          const ids = new Set(logs.map(event => Number(event.id)));
          logs = [...logs, ...found.filter(event => !ids.has(Number(event.id)))].slice(0, 100);
        } catch { /* Local evidence remains available during a ClickHouse outage. */ }
      }
      const result = await sandbox.startInvestigation({
        runId: job.id, attemptId, repository: job.repository, githubToken, openrouterKey: key, model,
        incident: { investigationId: job.investigationId, ruleId: job.ruleId, title: job.title,
          description: job.description, severity: job.severity, sourceWorker: job.sourceWorker,
          firstSeen: job.firstSeen, lastSeen: job.lastSeen },
        logs
      });
      if (result.status !== 'running') saveResult(job.id, result);
    } catch (error) {
      db.prepare("UPDATE agent_runs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run(String(error.message || error).slice(0, 1000), Date.now(), job.id);
    }
    return true;
  }

  function recoverInterrupted() {
    // Container jobs persist across Worker isolate restarts and are polled by the alarm.
  }

  return { vulnerabilities, mappings, run, patch, retry, setMapping, enqueueMapped, pollRunning, processOne, recoverInterrupted };
}
