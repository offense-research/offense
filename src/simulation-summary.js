import { assessUpgradeRehearsal, commandPassed } from '../shared/upgrade-verification.js';
export function simulationSummary(rehearsal, snapshot) {
  const raw = rehearsal.result?.scenarios ?? rehearsal.prediction?.scenarios ?? [];
  const rows = Array.isArray(raw) ? raw : [];
  const issues = [];
  if (!Array.isArray(raw)) issues.push('The simulation returned an incomplete list of upgrade paths.');
  const scenarios = rows.filter(scenario => {
    if (scenario && typeof scenario === 'object') return true;
    issues.push('An upgrade path was incomplete and could not be displayed.'); return false;
  }).map(scenario => {
    const changes = Array.isArray(scenario.changes) ? scenario.changes.filter(change => change && ['name', 'currentVersion', 'targetVersion'].every(key => typeof change[key] === 'string')) : [];
    if (!Array.isArray(scenario.changes) || changes.length !== scenario.changes.length) issues.push('Some proposed changes are incomplete. No result has been verified for those changes.');
    if (Array.isArray(scenario.checks) && scenario.checks.some(check => !check || typeof check !== 'object')) issues.push('Some test results are incomplete. Review the recorded evidence before applying this upgrade.');
    return { ...scenario, status: typeof scenario.status === 'string' && scenario.status ? scenario.status : 'not_tested', changes,
      checks: Array.isArray(scenario.checks) ? scenario.checks.filter(check => check && typeof check === 'object') : [] };
  });
  const baseline = rehearsal.result?.baseline;
  const baselineChecks = Array.isArray(baseline?.checks) ? baseline.checks : [];
  const baselineSetup = Array.isArray(baseline?.setup) ? baseline.setup : [];
  const baselineBlocked = !!rehearsal.result && (baseline?.integrity !== true || baseline.integrityVersion !== 2 || !baselineSetup.length || !baselineChecks.length || [...baselineSetup, ...baselineChecks].some(check => !commandPassed(check)));
  const assessment = assessUpgradeRehearsal(rehearsal, { snapshot });
  const verified = assessment.compatibilityPassed && !issues.length;
  const title = !assessment.current ? 'Report is out of date' : rehearsal.status === 'failed' ? 'Simulation could not finish' :
    baselineBlocked ? 'Original repository checks are blocked' : verified ? 'Candidate passed the recorded checks' : 'Review the upgrade blockers';
  const nextStep = baselineBlocked ? 'Fix the original repository setup or failing checks first. The candidate cannot be verified against a failing baseline. Copy the fix prompt below with these diagnostics.' :
    verified ? 'Copy the fix prompt below to apply this upgrade path in your coding agent, review the patch, and rerun verification before merging.' :
      'Copy the fix prompt below to resolve failed checks, uncovered findings and remaining advisories. This simulation has not established a verified fix.';
  return { assessment, scenarios, issues: [...new Set(issues)], baselineBlocked, verified, title, nextStep };
}
