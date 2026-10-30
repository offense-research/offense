const list = values => values.length < 2 ? values[0] || '' : `${values.slice(0, -1).join(', ')} and ${values.at(-1)}`;
const summarize = (values, limit = 3) => list(values.length > limit ? [...values.slice(0, limit), `${values.length - limit} more`] : values);

// Describe recorded dependency evidence without inventing affected app features.
export function describeBlastRadius(scenario, impacts = [], baseline) {
  const changes = scenario.changes || [];
  if (!changes.length) return 'No upgrade changes were recorded, so the dependency impact is not yet known.';
  const relevant = changes.map(change => impacts.find(impact => impact.name === change.name && impact.currentVersion === change.currentVersion));
  const sentences = [`This change would move ${summarize(changes.map(change => `${change.name} from ${change.currentVersion} to ${change.targetVersion}`))}.`];
  const parents = [...new Set(relevant.flatMap(impact => [
    ...(impact?.parents || []).filter(parent => !parent.isRoot).map(parent => parent.name),
    ...(impact?.paths || []).filter(path => path.length > 2).map(path => path.at(-2))
  ]).filter(Boolean))];
  if (parents.length) sentences.push(`Your project uses ${changes.length === 1 ? 'this dependency' : 'these dependencies'} through ${summarize(parents)}, so those packages should be included in compatibility checks.`);
  else if (relevant.some(impact => impact?.parents?.some(parent => parent.isRoot))) sentences.push('The upgrade includes a dependency declared directly by your project.');
  else sentences.push('The saved report does not identify which packages depend on these versions.');
  const count = scenario.totalDependencyChanges;
  if (Number.isInteger(count) && count >= 0) sentences.push(`The simulation changed ${count} installed dependency ${count === 1 ? 'entry' : 'entries'} across the lockfiles.`);
  else sentences.push('The full set of dependency changes has not been measured yet.');
  const major = [...new Set(relevant.filter(impact => impact?.majorChange).map(impact => impact.name))];
  if (major.length) sentences.push(`The ${summarize(major)} ${major.length === 1 ? 'upgrade crosses' : 'upgrades cross'} a major version and ${major.length === 1 ? 'needs' : 'need'} a review of breaking changes.`);
  const blocked = [...new Set(relevant.flatMap(impact => (impact?.parents || []).filter(parent => parent.compatible === false).map(parent => parent.name)))];
  if (blocked.length) sentences.push(`The proposed targets are outside the dependency ranges declared by ${summarize(blocked)}; upgrade those parents or review a scoped override before applying this plan.`);
  const assessment = assessUpgradeScenario(baseline, scenario);
  if (baseline && !assessment.baselinePassed) sentences.push('The original project did not pass a complete recorded baseline, so this run cannot establish whether the upgrade introduces a regression.');
  else if (scenario.status === 'resolution_failed') sentences.push('Dependency resolution failed, so the proposed upgrade could not be tested.');
  else if (scenario.checks?.length) {
    const failed = scenario.checks.filter(check => !check.passed).length;
    sentences.push(failed ? `${failed} candidate ${failed === 1 ? 'check failed' : 'checks failed'} and ${failed === 1 ? 'needs' : 'need'} attention before merging.` :
      assessment.checksMatched && assessment.baselinePassed && scenario.checks.every(commandPassed)
        ? `The candidate passed its ${scenario.checks.length} recorded ${scenario.checks.length === 1 ? 'check' : 'checks'} against the same checks in the original checkout.`
        : `${scenario.checks.length} candidate ${scenario.checks.length === 1 ? 'check reported passing' : 'checks reported passing'}, but a complete matching baseline comparison has not passed.`);
  } else sentences.push('No candidate checks were recorded.');
  if (scenario.remainingAdvisories > 0) sentences.push(`${scenario.remainingAdvisories} advisory ${scenario.remainingAdvisories === 1 ? 'match still needs' : 'matches still need'} remediation.`);
  else if (scenario.vulnerabilityCheck?.status !== 'complete') sentences.push('The advisory recheck has not completed.');
  sentences.push('The effect on application features still needs verification.');
  return sentences.join(' ');
}
import { assessUpgradeScenario, commandPassed } from '../shared/upgrade-verification.js';

