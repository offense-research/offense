import { createVulnerabilityStore } from './vulnerability-store.js';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readFile, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { validateSecurityPlan, verificationQualified } from '../agent/verification-gate.mjs';
import { verifyPatch as verifyStructuredPatch } from '../agent/verify-patch.mjs';
import { verificationInstructions } from '../agent/verification-prompt.mjs';
import { workspaceInstallations } from './github-installations.js';

const MAX_OUTPUT = 128 * 1024;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_PATCH = 256 * 1024;

export const validateAgentPlan = validateSecurityPlan;

async function verifyPatch({ execute, image, baselineDir, repoDir, plan, runId }) {
  const env = { PATH: process.env.PATH || '/usr/bin:/bin', HOME: process.env.HOME || '/tmp' };
  async function command(dir, args, network = 'none') {
    const name = `purple-verify-${runId}-${randomBytes(4).toString('hex')}`;
    try {
      const output = await execute('docker', ['run', '--name', name, '--rm', '--init', '--read-only', '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g', '--cpus=1', `--network=${network}`,
        `--user=${process.getuid()}:${process.getgid()}`, '--tmpfs=/tmp:rw,nosuid,size=128m',
        '--tmpfs=/home/agent:rw,nosuid,size=128m', '--mount', `type=bind,src=${dir},dst=/work/repo`,
        '--workdir=/work/repo', '--entrypoint=/usr/bin/env', image, ...args], { env, timeout: 180000, maxOutput: 128000, captureFailureOutput: true });
      return { code: 0, passed: true, stdout: output, output };
    } catch (error) {
      return { code: null, passed: false, classification: 'infrastructure_error', output: String(error.message || error).slice(-2000) };
    } finally {
      await execute('docker', ['rm', '-f', name], { env, timeout: 10000 }).catch(() => {});
    }
  }
  return verifyStructuredPatch({ baseline: baselineDir, candidate: repoDir, plan, command: (directory, argv, phase) => command(directory, argv, phase === 'setup' ? 'bridge' : 'none') });
}

export function runProcess(command, args, { cwd, env, timeout = 300000, maxOutput = MAX_OUTPUT, captureFailureOutput = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let output = '';
    let errorOutput = '';
    let exceeded = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
    child.stdout.on('data', chunk => { if (output.length < maxOutput) output += chunk.toString().slice(0, maxOutput - output.length); else exceeded = true; });
    child.stderr.on('data', chunk => { if (errorOutput.length < 4096) errorOutput += chunk.toString().slice(0, 4096 - errorOutput.length); });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0 && !exceeded) resolve(output.trim());
      else reject(new Error(code === null ? `${command} timed out.` : `${command} exited ${code}: ${(captureFailureOutput ? `${output.slice(-1500)}\n` : '') + errorOutput.slice(-500)}`));
    });
  });
}

export function createAgentRunner(db, { github, decrypt, dataDir, image = 'purple-pi-agent:0.2', model = 'deepseek/deepseek-v4.1-flash', execute = runProcess, searchLogs = null }) {
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
  if (!runColumns.has('verification')) db.exec('ALTER TABLE agent_runs ADD COLUMN verification TEXT');
  db.exec('CREATE INDEX IF NOT EXISTS agent_runs_workspace ON agent_runs(session_id, created_at DESC)');

  const vulnerabilities = createVulnerabilityStore(db);

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

  async function processOne() {
    const job = db.prepare(`SELECT r.id, r.session_id AS sessionId, r.investigation_id AS investigationId,
      r.repository, r.installation_id AS installationId, w.data AS workspaceData,
      i.source_worker AS sourceWorker, i.rule_id AS ruleId, i.title, i.description,
      i.severity, i.first_seen AS firstSeen, i.last_seen AS lastSeen
      FROM agent_runs r JOIN workspaces w ON w.id = r.session_id
      JOIN investigations i ON i.id = r.investigation_id AND i.session_id = r.session_id
      WHERE r.status = 'queued' AND i.status = 'open' ORDER BY r.id LIMIT 1`).get();
    if (!job) return false;
    const claimed = db.prepare("UPDATE agent_runs SET status = 'running', started_at = ? WHERE id = ? AND status = 'queued'").run(Date.now(), job.id);
    if (!claimed.changes) return false;
    let dir;
    let containerName;
    try {
      if (!github) throw new Error('GitHub App agent access is not configured.');
      const workspace = JSON.parse(job.workspaceData);
      if (!workspaceInstallations(workspace).some(item => item.installationId === job.installationId)) throw new Error('GitHub installation changed. Reconnect the repository mapping.');
      if (!workspace.openrouter?.secret) throw new Error('Connect an OpenRouter key before running Pi.');
      const key = decrypt(workspace.openrouter.secret);
      if (!key) throw new Error('Could not decrypt the OpenRouter key.');
      const token = await github.installationToken(job.installationId, job.repository);
      dir = await mkdtemp(path.join(dataDir || tmpdir(), 'purple-agent-'));
      const repoDir = path.join(dir, 'repo');
      const contextDir = path.join(dir, 'context');
      await mkdir(contextDir);
      const gitEnv = { ...process.env, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
        GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}`, GIT_TERMINAL_PROMPT: '0' };
      await execute('git', ['clone', '--depth', '1', '--single-branch', `https://github.com/${job.repository}.git`, repoDir], { env: gitEnv, timeout: 120000 });
      const sha = await execute('git', ['rev-parse', 'HEAD'], { cwd: repoDir, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, timeout: 10000 });
      if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error('Invalid repository commit.');
      db.prepare('UPDATE agent_runs SET commit_sha = ? WHERE id = ?').run(sha, job.id);
      const rows = db.prepare(`SELECT e.id, e.received_at AS receivedAt, e.payload FROM investigation_events ie
        JOIN events e ON e.id = ie.event_id AND e.session_id = ?
        WHERE ie.investigation_id = ? ORDER BY ie.received_at DESC LIMIT 100`).all(job.sessionId, job.investigationId);
      let logs = rows.map(row => ({ id: row.id, receivedAt: row.receivedAt, ...JSON.parse(row.payload) }));
      if (searchLogs && logs.length < 20) {
        try {
          const found = await searchLogs(job.sessionId, { worker: job.sourceWorker, from: job.firstSeen - 300000, to: job.lastSeen + 300001, limit: 100 });
          const ids = new Set(logs.map(event => Number(event.id)));
          logs = [...logs, ...found.filter(event => !ids.has(Number(event.id)))].slice(0, 100);
        } catch { /* Retained SQLite evidence remains available during a ClickHouse outage. */ }
      }
      const incident = { investigationId: job.investigationId, ruleId: job.ruleId, title: job.title, description: job.description,
        severity: job.severity, sourceWorker: job.sourceWorker, firstSeen: job.firstSeen, lastSeen: job.lastSeen,
        repository: job.repository, commitSha: sha, evidenceCount: logs.length };
      await writeFile(path.join(contextDir, 'incident.json'), JSON.stringify(incident, null, 2), { mode: 0o444 });
      await writeFile(path.join(contextDir, 'events.json'), JSON.stringify(logs, null, 2), { mode: 0o444 });
      const outputDir = path.join(dir, 'output');
      await mkdir(outputDir);
      const prompt = `Read /work/context/incident.json and /work/context/events.json, investigate the suspected issue in /work/repo, and write /work/output/plan.json. ${verificationInstructions}`;
      containerName = `purple-pi-${job.id}-${randomBytes(4).toString('hex')}`;
      await execute('docker', ['run', '--name', containerName, '--rm', '--init', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128', '--memory=1g', '--cpus=1', '--network=bridge', `--user=${process.getuid()}:${process.getgid()}`, '--tmpfs=/tmp:rw,nosuid,size=64m', '--tmpfs=/home/agent:rw,nosuid,size=64m', '--mount', `type=bind,src=${repoDir},dst=/work/repo`, '--mount', `type=bind,src=${contextDir},dst=/work/context,readonly`, '--mount', `type=bind,src=${outputDir},dst=/work/output`, '--env', 'OPENROUTER_API_KEY', '--env', 'PI_CODING_AGENT_DIR=/tmp/pi-agent', image, '-p', '--no-session', '--no-context-files', '--no-skills', '--no-extensions', '--no-mcp', '--no-approve', '--provider', 'openrouter', '--model', model, '--tools', 'read,grep,find,ls,edit,write', prompt],
        { env: { ...process.env, OPENROUTER_API_KEY: key }, timeout: 600000 });
      const planPath = path.join(outputDir, 'plan.json');
      if (!(await lstat(planPath)).isFile()) throw new Error('Pi did not write a regular plan file.');
      const plan = validateAgentPlan(JSON.parse(await readFile(planPath, 'utf8')));
      if (!plan.confirmed) {
        if (await execute('git', ['status', '--porcelain'], { cwd: repoDir, timeout: 10000 })) throw new Error('Pi changed the repository without a reproducible finding.');
        db.prepare("UPDATE agent_runs SET status = 'completed', commit_sha = ?, result = ?, finished_at = ? WHERE id = ?")
          .run(sha, plan.summary, Date.now(), job.id);
      } else {
        await execute('git', ['add', '-N', '--all'], { cwd: repoDir, timeout: 10000 });
        const patch = await execute('git', ['diff', '--binary', '--no-ext-diff', 'HEAD'], { cwd: repoDir, timeout: 10000, maxOutput: MAX_PATCH });
        if (!patch || patch.length > MAX_PATCH) throw new Error('Pi did not produce a reviewable patch within the 256 KB limit.');
        const changed = (await execute('git', ['diff', '--name-only', 'HEAD'], { cwd: repoDir, timeout: 10000 })).split('\n');
        if (!plan.testPaths.every(testPath => changed.includes(testPath)) || changed.every(file => plan.testPaths.includes(file))) throw new Error('Pi must change both a regression test and source code.');
        const baselineDir = path.join(dir, 'baseline');
        await execute('git', ['clone', '--quiet', '--no-hardlinks', repoDir, baselineDir], { timeout: 30000 });
        const verification = await verifyPatch({ execute, image, baselineDir, repoDir, plan, runId: job.id });
        db.prepare('UPDATE agent_runs SET status = ?, commit_sha = ?, result = ?, patch = ?, verification = ?, finished_at = ? WHERE id = ?')
          .run(verification.verified ? 'verified' : 'verification_failed', sha, plan.summary, patch, JSON.stringify(verification), Date.now(), job.id);
        vulnerabilities.record(job.id);
      }
    } catch (error) {
      db.prepare("UPDATE agent_runs SET status = 'failed', error = ?, finished_at = ? WHERE id = ?")
        .run(String(error.message || error).slice(0, 1000), Date.now(), job.id);
    } finally {
      if (containerName) await execute('docker', ['rm', '-f', containerName], { timeout: 10000 }).catch(() => {});
      if (dir) await rm(dir, { recursive: true, force: true });
    }
    return true;
  }

  function recoverInterrupted() {
    db.prepare("UPDATE agent_runs SET status = 'failed', error = 'Server restarted during analysis.', finished_at = ? WHERE status = 'running'").run(Date.now());
  }

  return { vulnerabilities, mappings, run, patch, retry, setMapping, enqueueMapped, processOne, recoverInterrupted };
}
