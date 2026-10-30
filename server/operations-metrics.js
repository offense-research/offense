import { timingSafeEqual } from 'node:crypto';
import { verificationQualified } from '../agent/verification-gate.mjs';
import { usageMetrics } from './usage-metrics.js';
import { skillUsageMetrics } from './skill-usage.js';

// Operator-only aggregates. Never return provider credentials, sessions, logs,
// repository contents, or investigation evidence across tenant boundaries.
export function operationsMetrics(db) {
  const workspaces = new Map();
  function workspace(id, name = 'Unclaimed workspace') {
    if (!workspaces.has(id)) workspaces.set(id, { id, name, confirmed: { total: 0, customer: 0, test: 0 },
      scans: { repositories: 0, completed: 0, failed: 0, findings: 0, severity: {}, lastCheckedAt: null },
      advisoryIds: new Set(), cveIds: new Set() });
    return workspaces.get(id);
  }
  for (const row of db.prepare("SELECT id, json_extract(data, '$.company') AS name FROM workspaces").all()) {
    workspace(row.id, row.name || 'Unnamed workspace');
  }
  for (const row of db.prepare('SELECT session_id, is_test, verification FROM vulnerability_discoveries').all()) {
    let evidence; try { evidence = JSON.parse(row.verification); } catch {}
    if (!verificationQualified(evidence)) continue;
    const counts = workspace(row.session_id).confirmed;
    counts.total++; counts[row.is_test ? 'test' : 'customer']++;
  }
  const allAdvisories = new Set(), allCVEs = new Set();
  const latestRepositories = new Map();
  for (const row of db.prepare(`SELECT session_id, repository, scanned_at, data FROM dependency_snapshots`).all()) {
    const target = workspace(row.session_id), check = JSON.parse(row.data).vulnerabilityCheck;
    const repositoryKey = row.repository.toLowerCase();
    const previous = latestRepositories.get(repositoryKey);
    const observedAt = check?.checkedAt || row.scanned_at;
    if (!previous || observedAt > previous.observedAt) latestRepositories.set(repositoryKey, { repository: row.repository, check, observedAt });
    target.scans.repositories++;
    if (check?.checkedAt) target.scans.lastCheckedAt = Math.max(target.scans.lastCheckedAt || 0, check.checkedAt);
    if (check?.status === 'failed') target.scans.failed++;
    if (check?.status !== 'complete') continue;
    target.scans.completed++;
    for (const finding of check.findings || []) {
      target.scans.findings++;
      const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
      target.scans.severity[severity] = (target.scans.severity[severity] || 0) + 1;
      if (finding.id) { target.advisoryIds.add(finding.id); allAdvisories.add(finding.id); }
      for (const cve of finding.cves || []) { target.cveIds.add(cve); allCVEs.add(cve); }
    }
  }
  const list = [...workspaces.values()].map(({ advisoryIds, cveIds, ...item }) => ({ ...item,
    scans: { ...item.scans, uniqueAdvisories: advisoryIds.size, uniqueCVEs: cveIds.size } }));
  const totals = { workspaces: list.length, scannedWorkspaces: 0, repositories: 0, findings: 0,
    uniqueAdvisories: allAdvisories.size, uniqueCVEs: allCVEs.size, confirmed: { total: 0, customer: 0, test: 0 } };
  for (const item of list) {
    if (item.scans.repositories) totals.scannedWorkspaces++;
    totals.repositories += item.scans.repositories; totals.findings += item.scans.findings;
    for (const key of ['total', 'customer', 'test']) totals.confirmed[key] += item.confirmed[key];
  }
  const owners = new Map();
  for (const { repository, check } of latestRepositories.values()) {
    const owner = repository.split('/')[0].toLowerCase();
    if (!owners.has(owner)) owners.set(owner, { owner, repositories: 0, completed: 0, failed: 0, findings: 0,
      severity: {}, advisories: new Set(), cves: new Set(), lastCheckedAt: null });
    const group = owners.get(owner);
    group.repositories++;
    if (check?.checkedAt) group.lastCheckedAt = Math.max(group.lastCheckedAt || 0, check.checkedAt);
    if (check?.status === 'failed') group.failed++;
    if (check?.status !== 'complete') continue;
    group.completed++;
    for (const finding of check.findings || []) {
      group.findings++;
      const severity = String(finding.severity || 'UNKNOWN').toUpperCase();
      group.severity[severity] = (group.severity[severity] || 0) + 1;
      if (finding.id) group.advisories.add(finding.id);
      for (const cve of finding.cves || []) group.cves.add(cve);
    }
  }
  const repositoryOwners = [...owners.values()].map(({ advisories, cves, ...group }) => ({ ...group,
    uniqueAdvisories: advisories.size, uniqueCVEs: cves.size })).sort((a, b) => b.findings - a.findings || a.owner.localeCompare(b.owner));
  return { generatedAt: Date.now(), scope: 'Latest stored dependency snapshots, including repositories subsequently unlinked. Not a new scan.',
    repositoryOwners, repositoryOwnerScope: 'Latest stored snapshot per case-insensitive repository, deduplicated across workspaces. Owner may be an organization or a personal account.',
    totals, usage: usageMetrics(db), skillUsage: skillUsageMetrics(db), workspaces: list.sort((a, b) => b.scans.findings - a.scans.findings || a.name.localeCompare(b.name)) };
}

export function registerOperationsMetrics(app, { db, key, callMetrics }) {
  const authorized = req => {
    const supplied = Buffer.from(req.get('authorization')?.replace(/^Bearer /, '') || '');
    const expected = Buffer.from(key || '');
    return expected.length > 0 && supplied.length === expected.length && timingSafeEqual(supplied, expected);
  };
  app.get('/api/internal/metrics', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Authorization');
    if (!authorized(req)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(operationsMetrics(db));
  });
  if (callMetrics) app.get('/api/internal/tool-calls', (req, res) => {
    res.set('Cache-Control', 'no-store'); res.set('Vary', 'Authorization');
    if (!authorized(req)) return res.status(401).json({ error: 'Unauthorized' });
    if (Object.keys(req.query).some(name => !['days', 'scope'].includes(name)) ||
        req.query.days !== undefined && (typeof req.query.days !== 'string' || !/^(7|30|90)$/.test(req.query.days)) ||
        req.query.scope !== undefined && (typeof req.query.scope !== 'string' || !['tools', 'requests'].includes(req.query.scope)))
      return res.status(400).json({ error: 'Choose only days (7, 30 or 90) and scope (tools or requests).' });
    try { res.json(callMetrics.read({ days: req.query.days === undefined ? 30 : Number(req.query.days), scope: req.query.scope || 'tools' })); }
    catch { res.status(503).json({ error: 'Company call metrics are temporarily unavailable.' }); }
  });
}
