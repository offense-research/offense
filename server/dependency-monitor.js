import { dependencySelection } from './dependency-routes.js';
import { createDependencyAutomationStore } from './dependency-automation.js';

// The DO alarm (or local server timer) drives this without a browser session.
// Persist attempts so restarts and provider outages cannot create a retry storm.
export function createDependencyMonitor(db, { github, mapper, runner, now = Date.now, interval = 5 * 60_000 }) {
  db.exec(`CREATE TABLE IF NOT EXISTS dependency_monitor (
    session_id TEXT NOT NULL, repository TEXT NOT NULL, installation_id INTEGER NOT NULL,
    attempted_at INTEGER NOT NULL, checked_at INTEGER, status TEXT NOT NULL,
    PRIMARY KEY (session_id, repository, installation_id)
  )`);
  const locks = mapper.repositoryLocks ||= new Set();
  const automation = createDependencyAutomationStore(db, { now });
  const rows = db.prepare('SELECT * FROM dependency_monitor WHERE session_id = ?');
  const save = db.prepare(`INSERT INTO dependency_monitor VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(session_id, repository, installation_id) DO UPDATE SET
    attempted_at = excluded.attempted_at, checked_at = excluded.checked_at, status = excluded.status`);
  automation.recoverInterrupted(locks);
  for (const row of db.prepare("SELECT * FROM dependency_monitor WHERE status = 'checking'").all()) {
    if (!locks.has(`${row.session_id}:${row.installation_id}:${row.repository}`))
      save.run(row.session_id, row.repository, row.installation_id, row.attempted_at, row.checked_at, 'retrying');
  }
  function selected(id, data) { return dependencySelection(data, runner?.mappings(id) || []).repositories; }
  function backgroundEnabled(policy) { return policy.enabled && (policy.onChange || policy.schedule !== 'off'); }
  const scheduleInterval = policy => policy.schedule === 'daily' ? 86400000 : policy.schedule === 'weekly' ? 7 * 86400000 : null;
  function nextCheckAt(policy, previous, snapshot) {
    if (!backgroundEnabled(policy)) return null;
    const last = Math.max(previous?.attempted_at || 0, snapshot?.lastSyncedAt || 0);
    const earliest = last ? last + interval : now();
    if (!snapshot || policy.onChange || snapshot.vulnerabilityCheck?.status === 'failed') return Math.max(now(), earliest);
    const advisoryAt = snapshot.vulnerabilityCheck?.checkedAt || previous?.checked_at || 0;
    return Math.max(now(), earliest, advisoryAt + scheduleInterval(policy));
  }
  function status(id) {
    const workspace = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
    if (!workspace) return [];
    const saved = rows.all(id), snapshots = mapper.snapshots(id);
    return selected(id, JSON.parse(workspace.data)).map(item => {
      const previous = saved.find(row => row.repository === item.repository && row.installation_id === item.installationId);
      const snapshot = snapshots.find(row => row.repository === item.repository && row.installationId === item.installationId);
      const policy = automation.policy(id, item.repository, item.installationId);
      const recentRuns = automation.recent(id, item.repository, item.installationId);
      return { ...item, attemptedAt: previous?.attempted_at || null, checkedAt: previous?.checked_at || null,
        status: !policy.enabled ? 'paused' : !backgroundEnabled(policy) ? 'manual' : previous?.status || 'pending',
        policy, latestRun: recentRuns[0] || null, recentRuns, nextCheckAt: nextCheckAt(policy, previous, snapshot) };
    });
  }
  function configure(id, repository, installationId, policy) {
    return automation.configure(id, repository, installationId, policy);
  }
  let busy = false;
  async function dispatch() {
    if (!github || busy) return;
    busy = true;
    try {
      const candidates = [];
      for (const workspace of db.prepare('SELECT id, data FROM workspaces').all()) {
        const attempts = rows.all(workspace.id);
        const snapshots = mapper.snapshots(workspace.id);
        for (const repo of selected(workspace.id, JSON.parse(workspace.data))) {
          const policy = automation.policy(workspace.id, repo.repository, repo.installationId);
          if (!backgroundEnabled(policy)) continue;
          const previous = attempts.find(item => item.repository === repo.repository && item.installation_id === repo.installationId);
          const snapshot = snapshots.find(item => item.repository === repo.repository && item.installationId === repo.installationId);
          const last = Math.max(previous?.attempted_at || 0, snapshot?.lastSyncedAt || 0);
          if (nextCheckAt(policy, previous, snapshot) <= now()) candidates.push({ ...repo, id: workspace.id, previous, snapshot, last });
        }
      }
      // Oldest first, bounded work per alarm; large workspaces cannot starve others.
      for (const item of candidates.sort((a, b) => a.last - b.last)
        .filter(item => !locks.has(`${item.id}:${item.installationId}:${item.repository}`)).slice(0, 3)) {
        const { id, repository, installationId, previous, snapshot } = item;
        const lock = `${id}:${installationId}:${repository}`;
        if (locks.has(lock)) continue;
        locks.add(lock);
        const attemptedAt = now();
        save.run(id, repository, installationId, attemptedAt, previous?.checked_at || null, 'checking');
        let runId = null;
        try {
          const accessible = await github.repositories(installationId);
          // Re-read enrollment after I/O: disconnecting must stop new scans.
          const current = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
          if (!current || !selected(id, JSON.parse(current.data)).some(repo => repo.repository === repository && repo.installationId === installationId)) continue;
          if (!accessible.some(repo => repo.fullName === repository)) {
            save.run(id, repository, installationId, attemptedAt, previous?.checked_at || null, 'access_required');
            continue;
          }
          const revision = snapshot ? await github.dependencyRevision(installationId, repository) : null;
          // Settings may have changed while access or revision requests were in
          // flight. A paused/detached repository must not start a new scan.
          const latestWorkspace = db.prepare('SELECT data FROM workspaces WHERE id = ?').get(id);
          if (!latestWorkspace || !selected(id, JSON.parse(latestWorkspace.data)).some(repo => repo.repository === repository && repo.installationId === installationId)) continue;
          const policy = automation.policy(id, repository, installationId);
          if (!backgroundEnabled(policy)) continue;
          const changed = snapshot && (snapshot.mapperVersion !== 3 || revision !== snapshot.revision);
          const due = policy.schedule !== 'off' && ((snapshot?.vulnerabilityCheck?.checkedAt || 0) <= now() - scheduleInterval(policy) || snapshot?.vulnerabilityCheck?.status === 'failed');
          const trigger = !snapshot ? 'initial' : changed && policy.onChange ? 'dependency_change' : due ? 'scheduled' : null;
          if (!trigger) {
            save.run(id, repository, installationId, attemptedAt, previous?.checked_at || null, 'watching');
            continue;
          }
          runId = automation.start(id, repository, installationId, trigger);
          const result = !snapshot || changed ? await mapper.scan(id, repository, installationId, { preserveOnFailure: true })
            : await mapper.recheck(id, repository, installationId, { preserveOnFailure: true });
          if (result?.vulnerabilityCheck?.status === 'failed') throw new Error('Advisory provider check failed.');
          const complete = result?.vulnerabilityCheck?.status === 'complete' && result.coverage?.complete !== false && !(result.vulnerabilityCheck.skippedPackages > 0);
          automation.finish(runId, complete ? 'completed' : 'partial', result);
          save.run(id, repository, installationId, attemptedAt, now(), 'watching');
        } catch {
          // Keep the last successful snapshot and retry on the next interval.
          if (runId) automation.finish(runId, 'failed', null, 'provider_failure');
          save.run(id, repository, installationId, attemptedAt, previous?.checked_at || null, 'retrying');
        } finally { locks.delete(lock); }
      }
    } finally { busy = false; }
  }
  return { dispatch, status, configure, policy: automation.policy };
}
