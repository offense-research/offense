import { assessUpgradeScenario } from '../shared/upgrade-verification.js';
import { sameScanEvidence } from '../shared/scan-evidence.js';

const identity = change => JSON.stringify([change?.name, change?.currentVersion, change?.targetVersion]);
export function upgradeRoutes(plan) {
  if (!plan || plan.mitigation || !plan.targetVersion) return [];
  const change = { name: plan.name, currentVersion: plan.currentVersion, targetVersion: plan.targetVersion };
  const parents = plan.impact?.parents || [];
  const blocked = parents.filter(parent => !parent.isRoot && parent.compatible === false);
  const unknown = parents.filter(parent => parent.compatible == null);
  const options = blocked.map(parent => (plan.parentOptions || []).find(option =>
    option.parent === parent.name && option.currentVersion === parent.version && option.version));
  const missing = blocked.filter((parent, i) => !options[i]);
  const upstream = options.filter(Boolean).flatMap(option => (option.upstream || []).map(parent =>
    ({ ...parent, dependency: option.parent, targetVersion: option.version }))).filter(parent => parent.compatible !== true);
  const rootUpdates = [...new Map([
    ...parents.filter(parent => parent.isRoot && parent.compatible === false).map(parent => ({ name: plan.name,
      range: parent.range, targetVersion: plan.targetVersion, file: parent.file, workspace: parent.workspace })),
    ...upstream.filter(parent => parent.isRoot && parent.compatible === false).map(parent => ({ name: parent.dependency,
      range: parent.range, targetVersion: parent.targetVersion, file: parent.file, workspace: parent.workspace }))
  ].map(update => [JSON.stringify(update), update])).values()];
  const changes = [...new Map([...options.filter(Boolean).map(option => ({ name: option.parent, currentVersion: option.currentVersion, targetVersion: option.version })), change]
    .map(value => [identity(value), value])).values()];
  const targets = new Map();
  for (const change of changes) {
    if (!targets.has(change.name)) targets.set(change.name, new Set());
    targets.get(change.name).add(change.targetVersion);
  }
  const blockers = [...missing.map(parent => `No compatible release of ${parent.name} was found.`),
    ...unknown.map(parent => `The dependency range from ${parent.name} still needs checking.`),
    ...upstream.filter(parent => !parent.isRoot).map(parent => `Check the upstream constraint from ${parent.name} before updating its dependency.`),
    ...upstream.filter(parent => parent.isRoot && parent.compatible == null).map(parent => `The application's declared range for ${parent.dependency} still needs checking.`),
    ...[...targets].filter(([, versions]) => versions.size > 1).map(([name, versions]) => `Conflicting targets for ${name}: ${[...versions].join(', ')}. Coordinate one compatible target before proceeding.`),
    ...(plan.impact?.truncated ? ['Dependency path analysis was truncated. Inspect the remaining paths and constraints before choosing this route.'] : []),
    ...(plan.constraintWarnings || []),
    ...(!Array.isArray(plan.impact?.parents) ? ['Parent dependency constraints have not been inspected.'] : [])];
  const route = { id: 'published', title: blocked.length ? 'Upgrade the parent packages first' : 'Use the checked published target',
    description: [blocked.length ? 'Update the packages that pin this dependency, then resolve the fixed version through them.' :
      rootUpdates.length ? 'Update your project’s declared range, then regenerate the lockfile.' : 'The existing declared ranges allow this target where they have been checked.',
      ...rootUpdates.map(update => `Update the application declaration${update.workspace ? ` in ${update.workspace}` : ''} for ${update.name}${update.range ? ` (${update.range})` : ''} to allow ${update.targetVersion}.`)].join(' '),
    changes, blockers, recommended: blockers.length === 0, majorChange: !!plan.majorChange,
    requiresRootUpdate: rootUpdates.length > 0, rootUpdates };
  const routes = [route];
  if (blocked.length) routes.push({ id: 'override', title: 'Review a scoped override or patch',
    description: 'Use this only after checking source compatibility. An override bypasses the parent’s declared range; it is not an automatically verified fix.',
    changes: [change], blockers: ['Requires explicit compatibility review and repository tests.'], recommended: false, majorChange: !!plan.majorChange });
  return routes;
}

export function routeEvidence(route, rehearsal, snapshot) {
  if (!rehearsal || rehearsal.stale || !sameScanEvidence(rehearsal, snapshot)) return 'Not simulated for this scan';
  if (!Array.isArray(route?.changes) || !route.changes.length) return 'Not simulated for this path';
  const scenarios = Array.isArray(rehearsal.result?.scenarios) ? rehearsal.result.scenarios : [];
  const matching = scenarios.filter(scenario => scenario && Array.isArray(scenario.changes) && route.changes.every(change => scenario.changes.some(value => identity(value) === identity(change))) &&
    (route.id !== 'override' || (Array.isArray(scenario.applied) && route.changes.every(change => scenario.applied.some(value => value?.field === 'overrides' && identity(value) === identity(change))))));
  const scenario = matching.find(value => value.changes.length === route.changes.length) || matching[0];
  if (!scenario) return 'Not simulated for this path';
  if (scenario.changes.length !== route.changes.length) return 'Tested only with other upgrades; review the full scenario';
  const assessment = assessUpgradeScenario(rehearsal.result?.baseline, scenario);
  if (!assessment.baselinePassed) return 'Original checks need attention';
  if (rehearsal.status !== 'completed' || rehearsal.result?.status !== 'completed' || rehearsal.result.revision !== rehearsal.revision) return 'Simulation is incomplete';
  if (assessment.blockers.some(blocker => !['advisories','scan_coverage','uncovered_findings'].includes(blocker.code))) return 'Candidate needs review';
  if (!assessment.finalAdvisoriesPassed || assessment.blockers.some(blocker => ['scan_coverage','uncovered_findings'].includes(blocker.code))) return 'Advisory checks need attention';
  if (rehearsal.blockers?.length) return 'Scenario checks passed; other findings need review';
  return route.id === 'override' ? 'Scenario checks passed; override needs review' : 'Scenario checks passed';
}
