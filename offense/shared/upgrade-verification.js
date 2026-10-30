// One fail-closed compatibility gate for the API, browser and copied prompts.
// A passing compatibility rehearsal never establishes exploit reproduction.
import { sameScanEvidence } from './scan-evidence.js';
const list = value => Array.isArray(value) ? value : [];
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
export function commandPassed(value) {
  return object(value) && value.passed === true && !value.timedOut && !value.truncated && !value.signal &&
    (value.exitCode ?? value.code) === 0 && (value.exitCode === undefined || value.exitCode === 0) &&
    (value.code === undefined || value.code === 0) && Array.isArray(value.command) && value.command.length > 0 &&
    value.command.every(part => typeof part === 'string' && part.length > 0);
}
const allPassed = values => Array.isArray(values) && values.length > 0 && values.every(commandPassed);
const directory = value => String(value || '.').replace(/^(?:source|candidate-\d+)(?:\/|$)/, '') || '.';
const commandKey = value => JSON.stringify([directory(value?.directory), value?.command]);
const sameCommands = (a,b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
  JSON.stringify(a.map(commandKey).sort()) === JSON.stringify(b.map(commandKey).sort());
const changeKey = value => JSON.stringify([value?.name, value?.currentVersion, value?.targetVersion]);
export function assessUpgradeScenario(baseline, scenario) {
  const blockers = [];
  function block(code,message,nextStep) { blockers.push({code,message,nextStep}); }
  const baselinePassed = baseline?.integrity === true && baseline.integrityVersion === 2 && allPassed(baseline.setup) && allPassed(baseline.checks);
  if (!baselinePassed) block('baseline', baseline?.integrity === true && baseline.integrityVersion !== 2 ? 'The original result has no tracked-file integrity verification.' : 'The original checkout has no complete passing baseline.', 'Rerun the original checkout with tracked-file integrity checks; fix any original setup/test failure before comparing the candidate.');
  if (!object(scenario) || scenario.status !== 'tests_passed') block('candidate_status', 'The candidate has not completed all required checks.', 'Review the resolver or failed command diagnostics and rerun the candidate.');
  if (!allPassed(scenario?.resolution) || !allPassed(scenario?.setup)) block('candidate_setup', 'Dependency resolution or the frozen candidate install is incomplete.', 'Resolve dependency, peer and engine conflicts without force flags; repeat the frozen install.');
  if (scenario?.integrity !== true || scenario.integrityVersion !== 2) block('integrity', 'Candidate repository integrity was not preserved or checked.', 'Review changed files and rerun without allowing install/test scripts to rewrite tracked source, tests or dependency evidence.');
  const checksMatched = sameCommands(baseline?.setup,scenario?.setup) && sameCommands(baseline?.checks,scenario?.checks);
  if (!allPassed(scenario?.checks) || !checksMatched) block('check_parity', 'The candidate did not pass the same complete checks as the original checkout.', 'Run the same commands in the same workspace directories before and after the upgrade; include failed, interrupted and unrun checks.');
  const changes = list(scenario?.changes), coverage = list(scenario?.coverage);
  const validChanges = changes.length > 0 && changes.every(change => object(change) && ['name','currentVersion','targetVersion'].every(key=>typeof change[key]==='string' && change[key])) &&
    new Set(changes.map(changeKey)).size === changes.length;
  const targets = new Map(); let conflicting = false;
  for (const change of changes) { if (!object(change)) continue; if (targets.has(change?.name) && targets.get(change.name) !== change.targetVersion) conflicting = true; targets.set(change?.name,change?.targetVersion); }
  const targetCoveragePassed = validChanges && !conflicting && coverage.length === changes.length && new Set(coverage.map(changeKey)).size === coverage.length && changes.every(change => coverage.some(value =>
    changeKey(value) === changeKey(change) && value.targetPresent === true && value.oldVersionRemaining === false));
  if (!targetCoveragePassed) block('target_coverage', 'Not every requested upgrade was proven present with its old version removed.', 'Inspect every occurrence in the regenerated lockfiles and coordinate parent upgrades; rescan the complete resolved tree.');
  const advisory = scenario?.vulnerabilityCheck;
  const finalAdvisoriesPassed = advisory?.status === 'complete' && Number.isInteger(advisory.checkedPackages) && advisory.checkedPackages > 0 && Array.isArray(advisory.findings) && !advisory.findings.length &&
    scenario?.remainingAdvisories === 0 && Array.isArray(scenario?.newAdvisories) && !scenario.newAdvisories.length;
  if (!finalAdvisoriesPassed) block('advisories', 'The final advisory rescan is incomplete or still contains matches.', 'Recheck every resolved package/version, address remaining or newly introduced advisories, and report coverage gaps.');
  if (Number(advisory?.skippedPackages || 0) > 0 || advisory?.coverage?.complete === false || list(advisory?.coverage?.omissions).length || list(advisory?.warnings).length || scenario?.inventoryComplete === false) block('scan_coverage', 'The final dependency/advisory inventory has coverage gaps.', 'Resolve unsupported or omitted dependency files and rerun the advisory check; an incomplete scan cannot establish a clean candidate.');
  if (list(scenario?.unrehearsedFindings).length) block('uncovered_findings', 'Some findings were outside this candidate’s direct upgrade coverage.', 'Include every uncovered finding in the remediation plan and record its resolution or explicit blocker.');
  return { compatibilityPassed: blockers.length === 0, baselinePassed, checksMatched, targetCoveragePassed, finalAdvisoriesPassed, blockers };
}
export function assessUpgradeRehearsal(rehearsal, { snapshot, now } = {}) {
  const current = !!rehearsal && !rehearsal.stale && (!snapshot || sameScanEvidence(rehearsal,snapshot,now));
  const scenarios = list(rehearsal?.result?.scenarios).map(scenario => assessUpgradeScenario(rehearsal?.result?.baseline,scenario));
  const blockers = [];
  if (!current) blockers.push({code:'stale',message:'No current simulation is bound to this scan.',nextStep:'Run a simulation against the current repository and advisory evidence.'});
  if (rehearsal?.status !== 'completed' || rehearsal?.result?.status !== 'completed') blockers.push({code:'incomplete',message:'The simulation has not completed.',nextStep:'Wait for the sandbox to finish or resolve its recorded failure.'});
  if (rehearsal?.result && rehearsal.result.revision !== rehearsal.revision) blockers.push({code:'revision',message:'Sandbox results do not match the requested commit.',nextStep:'Rerun the exact pinned repository revision; do not reuse a candidate from another commit.'});
  if (!scenarios.length) blockers.push({code:'no_scenarios',message:'No executed upgrade candidate was recorded.',nextStep:'Plan a checked upgrade candidate and run it in the sandbox.'});
  if (list(rehearsal?.blockers).length) blockers.push({code:'planning_blockers',message:'Some upgrade planning tasks remain blocked.',nextStep:'Resolve each listed package blocker or include a verified mitigation; do not omit those advisories.'});
  for (const [index,assessment] of scenarios.entries()) for (const blocker of assessment.blockers) blockers.push({...blocker,scenario:index+1});
  return { current, evidenceAvailable: !!rehearsal?.result, compatibilityPassed: blockers.length === 0,
    exploitRemediationVerified: false, scenarios, blockers };
}
