import { workspaceInstallations } from './github-installations.js';
import { buildUpgradeHandoff } from './upgrade-handoff.js';

export function dependencySelection(session, workerMappings = []) {
  const installations = new Set(workspaceInstallations(session).map(item => item.installationId));
  const mappings = workerMappings.filter(item => installations.has(item.installationId) &&
    (session.collectorInstall?.sources || []).includes(item.sourceWorker));
  const enrolled = Object.values(session.dependencyRepositories || {}).filter(item => installations.has(item.installationId));
  const repositories = [...new Map([...enrolled, ...mappings].map(item => [`${item.installationId}:${item.repository}`,
    { repository: item.repository, installationId: item.installationId }])).values()];
  return { mappings, repositories };
}

// Repo enrollment belongs to the workspace, independently of deployed Workers.
// Workspace drafts merge concurrent changes and persist these choices across devices.
export function registerDependencyRoutes(app, { trackers, github, mapper, runner, syncGitHubAccess, autoLinkWorkers, rehearsals, monitor, dispatchRehearsals = () => {} }) {
  const locks = mapper.repositoryLocks ||= new Set();
  function selection(req) { return dependencySelection(req.session, runner.mappings(req.sessionId)); }
  async function authorize(req, requireEnrolled = true) {
    const repository = req.body?.repository, installationId = Number(req.body?.installationId);
    if (!github || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || '') ||
        !workspaceInstallations(req.session).some(item => item.installationId === installationId)) {
      throw Object.assign(new Error('Choose a repository from a connected GitHub installation.'), { status: 403 });
    }
    if (requireEnrolled && !selection(req).repositories.some(item => item.repository === repository && item.installationId === installationId)) {
      throw Object.assign(new Error('Add this repository to the dependency map first.'), { status: 403 });
    }
    // Check GitHub again even for cached checks/plans: removed App access must not
    // allow old credentials or guessed repository IDs to authorize a new operation.
    const accessible = await github.repositories(installationId);
    if (!accessible.some(item => item.fullName === repository)) {
      throw Object.assign(new Error('This repository is no longer accessible to the GitHub App.'), { status: 403 });
    }
    return { repository, installationId };
  }
  app.get('/api/dependencies', async (req, res) => {
    try { if (req.query.cached !== '1') { await syncGitHubAccess(req); await autoLinkWorkers(req); } } catch { /* Preserve saved selections during provider outages. */ }
    const selected = selection(req);
    const linked = new Set(selected.repositories.map(item => `${item.installationId}:${item.repository}`));
    res.json({ ...selected, simulationTrial: rehearsals?.entitlement(req.sessionId) || { available: false }, monitoring: (monitor?.status(req.sessionId) || []).filter(item => linked.has(`${item.installationId}:${item.repository}`)), snapshots: mapper.snapshots(req.sessionId).filter(item => linked.has(`${item.installationId}:${item.repository}`))
      .map(item => ({ ...item, rehearsal: rehearsals?.latest(req.sessionId, item.repository, item.installationId) || null })) });
    dispatchRehearsals();
  });
  app.post('/api/dependencies/automation', async (req, res) => {
    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
        Object.keys(req.body).some(key => !['repository', 'installationId', 'policy'].includes(key)) ||
        !Object.hasOwn(req.body, 'policy')) return res.status(400).json({ error: 'Provide repository, installationId and policy only.' });
    const { repository, installationId } = await authorize(req);
    if (!monitor) return res.status(503).json({ error: 'Repository automation is not configured.' });
    let policy;
    try { policy = monitor.configure(req.sessionId, repository, installationId, req.body.policy); }
    catch (error) { return res.status(400).json({ error: error.message || 'Invalid automation policy.' }); }
    const monitoring = monitor.status(req.sessionId).find(item => item.repository === repository && item.installationId === installationId);
    res.json({ policy, monitoring });
  });
  app.post('/api/dependencies/issue', async (req, res) => {
    const { repository, installationId } = await authorize(req);
    if (!trackers) return res.status(503).json({ error: 'Issue trackers are not configured.' });
    let snapshot = mapper.snapshots(req.sessionId).find(item => item.repository === repository && item.installationId === installationId);
    const find = value => value?.vulnerabilityCheck?.findings?.find(item => item.id === req.body.advisoryId && item.package === req.body.package && item.version === req.body.version);
    let finding = find(snapshot);
    if (!finding || snapshot.revision !== req.body.revision || snapshot.vulnerabilityCheck.status !== 'complete' ||
      !snapshot.vulnerabilityCheck.checkedAt || Date.now() - snapshot.vulnerabilityCheck.checkedAt > 86400000) {
      return res.status(409).json({ error: 'Finding evidence changed or expired. Rescan before creating an issue.' });
    }
    let plan;
    if (finding.resolved !== false && !snapshot.coverage?.requiresLockfile) {
      try { plan = await mapper.upgradePlan(req.sessionId, repository, installationId, finding.package, finding.version); }
      catch { /* Create a triage issue with an explicit unchecked-path notice. */ }
      const latest = mapper.snapshots(req.sessionId).find(item => item.repository === repository && item.installationId === installationId);
      if (!latest || latest.revision !== snapshot.revision || latest.scannedAt !== snapshot.scannedAt ||
        latest.vulnerabilityCheck?.checkedAt !== snapshot.vulnerabilityCheck.checkedAt || !find(latest)) return res.status(409).json({ error: 'Scan evidence changed. Review the current finding before creating an issue.' });
      snapshot = latest; finding = find(latest);
    }
    const prompt = plan ? buildUpgradeHandoff({ repository, workers: [], snapshot, plan }).prompt : null;
    res.json({ issue: await trackers.create(req.sessionId, req.body.provider, { repository, snapshot, finding, prompt }) });
  });
  app.post('/api/dependencies/rehearsal', async (req, res) => {
    const { repository, installationId } = await authorize(req);
    if (!rehearsals) return res.status(503).json({ error: 'Upgrade rehearsals are not configured.' });
    try {
      const rehearsal = rehearsals.start(req.sessionId, repository, installationId, req.session, { refresh: req.body.refresh === true });
      res.status(202).json({ rehearsal });
      dispatchRehearsals();
    } catch (error) {
      if (error.code !== 'lockfile_required') throw error;
      res.status(400).json({ error: error.message, code: error.code, coverage: error.coverage });
    }
  });
  app.post('/api/dependencies/repositories', async (req, res) => {
    const item = await authorize(req, false);
    const key = `${item.installationId}:${item.repository}`;
    req.session.dependencyRepositories ||= {};
    req.session.dependencyRepositories[key] = item;
    req.save();
    res.json(selection(req));
  });
  app.delete('/api/dependencies/repositories', (req, res) => {
    const key = `${Number(req.body?.installationId)}:${req.body?.repository}`;
    if (req.session.dependencyRepositories) delete req.session.dependencyRepositories[key];
    req.save();
    res.json(selection(req));
  });
  for (const action of ['scan', 'sync', 'check', 'upgrade-plan']) app.post(`/api/dependencies/${action}`, async (req, res) => {
    const { repository, installationId } = await authorize(req);
    const lock = `${req.sessionId}:${installationId}:${repository}`;
    if (locks.has(lock)) return res.status(409).json({ error: 'A scan or update plan is already running for this repository.' });
    locks.add(lock);
    try {
      if (action === 'upgrade-plan') {
        const plan = await mapper.upgradePlan(req.sessionId, repository, installationId, req.body.name, req.body.version, { force: req.body.refresh === true });
        const snapshot = mapper.snapshots(req.sessionId).find(item => item.repository === repository && item.installationId === installationId);
        const workers = selection(req).mappings.filter(item => item.repository === repository && item.installationId === installationId).map(item => item.sourceWorker);
        res.json({ plan, handoff: buildUpgradeHandoff({ repository, workers, snapshot, plan }) });
      } else res.json({ snapshot: await mapper[action === 'check' ? 'recheck' : action](req.sessionId, repository, installationId) });
    } catch (error) { res.status(error.code === 'lockfile_required' ? 400 : 502).json({ error: `Could not ${action}: ${error.message}`,
      ...(error.code === 'lockfile_required' ? { code: error.code, coverage: error.coverage } : {}) }); }
    finally { locks.delete(lock); }
  });
}
