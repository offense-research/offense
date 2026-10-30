import { upgradeRoutes } from './upgrade-routes.js';

// Advisory-listed versions are useful leads, but only the planner has checked
// the repository's parent ranges and peers. Keep those states visibly distinct.
export function findingReadiness(finding, plan, { manifestOnly = false } = {}) {
  const advisoryTarget = finding.fixedVersions?.join(', ') || '';
  if (manifestOnly || finding.resolved === false) return { state: 'unknown', label: 'Exact version needed', target: '', detail: 'Generate a lockfile to check installed versions and upgrade paths.', blockers: [] };
  if (!plan) return { state: 'unplanned', label: advisoryTarget ? 'Advisory-listed fix' : 'No published fix', target: advisoryTarget, detail: 'The repository upgrade path has not been checked.', blockers: [] };
  if (plan.mitigation || !plan.targetVersion) return { state: 'blocked', label: 'Needs mitigation', target: '', detail: plan.mitigation?.reason || 'No checked upgrade target is available.', blockers: [] };
  const route = upgradeRoutes(plan).find(value => value.id === 'published');
  if (!route?.recommended) return { state: 'blocked', label: 'Needs review', target: plan.targetVersion, detail: 'The proposed target has unresolved dependency constraints.', blockers: route?.blockers || [] };
  const parentUpgrade = route.changes.some(change => change.name !== plan.name);
  return { state: parentUpgrade ? 'parent' : 'checked', label: parentUpgrade ? 'Needs parent upgrade' : 'Path checked', target: plan.targetVersion, detail: parentUpgrade ? 'A coordinated parent upgrade is included in this path. Repository checks are still needed.' : 'Checked dependency constraints allow this path. Repository checks are still needed.', blockers: [] };
}
