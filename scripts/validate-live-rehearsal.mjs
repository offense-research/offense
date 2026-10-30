#!/usr/bin/env node
import { assessUpgradeRehearsal } from '../shared/upgrade-verification.js';
// Read-only evidence validation. No GitHub, scanner, model, or production calls.
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { scanEvidenceKey, sameScanEvidence } from '../shared/scan-evidence.js';

const array = value => Array.isArray(value) ? value : [];
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const identity = value => `${value?.package}\0${value?.installedVersion ?? value?.version}\0${value?.advisory ?? value?.id}`;
const packageKey = value => `${value?.package ?? value?.name}\0${value?.installedVersion ?? value?.currentVersion ?? value?.version}`;
const sorted = value => [...value].sort();
const sameItems = (a, b) => isDeepStrictEqual(sorted(a), sorted(b));
const relativeDirectory = value => String(value || '.').replace(/^(?:source|candidate-\d+)(?:\/|$)/, '') || '.';
const commandIdentity = value => JSON.stringify([relativeDirectory(value?.directory), value?.command]);
const passed = value => object(value) && value.passed === true && !value.timedOut && !value.truncated && !value.signal &&
  Number.isInteger(value.exitCode ?? value.code) && (value.exitCode ?? value.code) === 0 &&
  (value.exitCode === undefined || value.exitCode === 0) && (value.code === undefined || value.code === 0) &&
  Array.isArray(value.command) && value.command.length > 0 && value.command.every(part => typeof part === 'string');
const allPassed = value => Array.isArray(value) && value.length > 0 && value.every(passed);
const diagnostic = value => ({ phase: value?.phase || null, directory: value?.directory || '.', command: value?.command || null,
  passed: passed(value), exitCode: value?.exitCode ?? value?.code ?? null, timedOut: value?.timedOut === true,
  output: String(value?.output || value?.stderr || '').replace(/(?:gh[opsu]_[\w]+|github_pat_[\w]+|sk-or-[\w-]+|Bearer\s+\S+)/gi, '[REDACTED]').slice(-1200) });

function parsePrompt(prompt) {
  if (typeof prompt !== 'string' || Buffer.byteLength(prompt) > 10_000_000) throw new Error('Provide copied prompt text no larger than 10 MB.');
  let start = -1, depth = 0, quoted = false, escaped = false;
  for (let index = 0; index < prompt.length; index++) {
    const char = prompt[index];
    if (start < 0) { if (char === '{') { start = index; depth = 1; } continue; }
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') quoted = false;
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === '{' || char === '[') depth++;
    else if (char === '}' || char === ']') {
      if (--depth !== 0) continue;
      try {
        const value = JSON.parse(prompt.slice(start, index + 1));
        if (object(value) && typeof value.repository === 'string' && Array.isArray(value.tasks)) return { evidence: value, start, end: index + 1 };
      } catch {}
      start = -1;
    }
  }
  throw new Error('The copied prompt does not contain repository task evidence.');
}
export function extractPromptEvidence(prompt) { return parsePrompt(prompt).evidence; }

export function validateLiveRehearsal({ snapshot, prompt, repository = snapshot?.repository, installationId,
  expectedRevision, requireCompleted = true, requireCurrent = true, requirePlanningOutcomes = true, now = Date.now(), maxEvidenceAgeMs = 24 * 3600_000 } = {}) {
  const errors = [], warnings = [];
  const fail = message => errors.push(message);
  let copied, instructions;
  try { const parsed = parsePrompt(prompt); copied = parsed.evidence; instructions = prompt.slice(0, parsed.start) + prompt.slice(parsed.end); }
  catch (error) { return { valid: false, errors: [error.message], warnings, compatibilityPassed: false, exploitRemediationVerified: false }; }
  if (!object(snapshot)) return { valid: false, errors: ['Provide the saved repository snapshot.'], warnings, compatibilityPassed: false, exploitRemediationVerified: false };
  if (repository !== snapshot.repository || copied.repository !== repository) fail('The saved snapshot and copied prompt do not identify the selected repository.');
  if (installationId !== undefined && snapshot.installationId !== installationId) fail('The saved snapshot belongs to a different GitHub installation.');
  if (!/^[a-f0-9]{40}$/.test(snapshot.revision || '')) fail('The repository revision is not a full pinned Git commit.');
  if (expectedRevision !== undefined && snapshot.revision !== expectedRevision) fail('The saved scan does not match the independently expected repository revision.');
  const copiedIdentity = scanEvidenceKey(copied), snapshotIdentity = scanEvidenceKey(snapshot);
  if (copied.evidenceIdentity && !copiedIdentity) fail('The copied content evidence identity is invalid.');
  if (copiedIdentity && snapshotIdentity && !sameScanEvidence(copied, snapshot)) fail('The copied immutable scan content differs from the saved snapshot.');
  for (const [copiedKey, savedValue] of [['revision', snapshot.revision], ...(!copiedIdentity || !snapshotIdentity ? [['scannedAt', snapshot.scannedAt], ['advisoryCheckedAt', snapshot.vulnerabilityCheck?.checkedAt]] : [])]) {
    if (copied[copiedKey] !== savedValue) fail(`Copied ${copiedKey} does not match the saved scan.`);
  }
  if (snapshot.vulnerabilityCheck?.status !== 'complete') fail('The saved advisory scan is incomplete or failed.');
  if (!Number.isFinite(snapshot.vulnerabilityCheck?.checkedAt) || snapshot.vulnerabilityCheck.checkedAt > now + 300_000 || snapshot.vulnerabilityCheck.checkedAt < now - maxEvidenceAgeMs) fail('The saved advisory check is missing, future-dated, or older than the allowed evidence window.');
  if (snapshot.coverage?.missingLockfiles?.length || array(snapshot.vulnerabilityCheck?.findings).some(item => item.resolved === false)) fail('Declared dependency risks cannot establish an installed-version upgrade rehearsal; generate lockfiles and rescan.');
  if (!sameItems(array(copied.files), array(snapshot.files))) fail('The copied lockfile scope differs from the saved scan.');
  const findings = array(snapshot.vulnerabilityCheck?.findings), tasks = array(copied.tasks);
  if (!sameItems(tasks.map(identity), findings.map(identity))) fail('The prompt omits, duplicates, or adds advisory tasks relative to the saved scan.');
  const taskPaths = new Map(), chosenTargets = new Map();
  for (const task of tasks) {
    if (!object(task)) { fail('The copied advisory task list contains an invalid row.'); continue; }
    const finding = findings.find(value => identity(value) === identity(task));
    if (finding && (task.severity !== finding.severity || !sameItems(array(task.cves), array(finding.cves)) || !sameItems(array(task.listedFixedVersions), array(finding.fixedVersions)))) fail(`Advisory metadata changed for ${task.package} ${task.advisory}.`);
    const key = packageKey(task), update = task.updatePath;
    if (!object(update)) { fail(`No upgrade or blocker outcome is recorded for ${task.package} ${task.advisory}.`); continue; }
    if (taskPaths.has(key) && !isDeepStrictEqual(taskPaths.get(key), update)) fail(`Overlapping advisories have conflicting upgrade paths for ${task.package}@${task.installedVersion}.`);
    taskPaths.set(key, update);
    if (requirePlanningOutcomes && update.status === 'not yet planned') fail(`Upgrade planning did not run for ${task.package}@${task.installedVersion}.`);
    if (update.status === 'blocked') {
      if (typeof update.reason !== 'string' || !update.reason) fail(`The planner blocker has no diagnostic for ${task.package}.`);
      continue;
    }
    const plan = array(snapshot.upgradePlans).find(value => value.name === task.package && value.currentVersion === task.installedVersion);
    if (!plan) { fail(`The copied path for ${task.package}@${task.installedVersion} has no persisted source plan.`); continue; }
    const planBinding = { ...plan, repository: plan.repository ?? snapshot.repository, installationId: plan.installationId ?? snapshot.installationId,
      revision: plan.revision ?? plan.snapshotRevision, scannedAt: plan.scannedAt ?? plan.snapshotScannedAt };
    if (!sameScanEvidence(planBinding, snapshot) || (plan.snapshotRevision !== undefined && plan.snapshotRevision !== snapshot.revision)) fail(`The persisted plan is stale for ${task.package}@${task.installedVersion}.`);
    if (plan.mitigation) {
      if (update.kind !== 'mitigation' || !isDeepStrictEqual(update.mitigation, plan.mitigation)) fail(`The proposed mitigation changed for ${task.package}.`);
      continue;
    }
    if (update.targetVersion !== plan.targetVersion) fail(`The copied target differs from the saved plan for ${task.package}.`);
    for (const [key, value] of [['releasesInspected', plan.releases], ['compatibilityChanges', plan.steps], ['dependencyPaths', plan.impact?.paths], ['parentConstraints', plan.impact?.parents], ['parentUpgrades', plan.parentOptions], ['targetCandidates', plan.considered], ['constraintWarnings', plan.constraintWarnings || []], ['peerConstraints', plan.peerConstraints || null], ['targetSelection', plan.targetSelection || null], ['dependencyPathsTruncated', !!plan.impact?.truncated]]) {
      if (!isDeepStrictEqual(update[key], value)) fail(`The copied ${key} changed for ${task.package}.`);
    }
    if (!array(plan.considered).some(value => value.version === plan.targetVersion && value.advisories === 0)) fail(`No saved clean target check exists for ${task.package}@${plan.targetVersion}.`);
    chosenTargets.set(`${task.package}\0${task.installedVersion}`, plan.targetVersion);
  }
  if (!/deduplicate overlapping upgrades/i.test(instructions)) fail('The one-shot prompt does not coordinate overlapping upgrades.');
  if (!/untrusted (?:data|evidence)/i.test(instructions) || !/do not claim fixes or passing tests without evidence/i.test(instructions) || !/Passing existing checks does not prove exploit remediation/.test(instructions) || !/do not deploy to production/i.test(instructions)) fail('The prompt is missing the evidence and security-verification safeguards.');

  const saved = snapshot.rehearsal, evidence = copied.upgradeRehearsal;
  if (!isDeepStrictEqual(copied.upgradeAssessment, assessUpgradeRehearsal(saved, { snapshot, now }))) fail('The copied compatibility assessment differs from the saved command and blocker evidence.');
  const current = !!saved && !saved.stale && sameScanEvidence(saved, snapshot);
  const completed = saved?.status === 'completed';
  if (requireCurrent && !current) fail('There is no current saved rehearsal for this repository scan.');
  if (requireCompleted && !completed) fail('The saved rehearsal has not completed.');
  if (completed && (!Number.isFinite(saved.finishedAt) || saved.finishedAt > now + 300_000 || saved.finishedAt < now - maxEvidenceAgeMs)) fail('The completed rehearsal has no current valid finish time.');
  if (saved) {
    const { usable, ...body } = object(evidence) ? evidence : {};
    if (!isDeepStrictEqual(body, saved)) fail('The copied rehearsal is not the exact saved job, including its command outcomes.');
    if (usable !== assessUpgradeRehearsal(saved, { snapshot, now }).compatibilityPassed) fail('The copied rehearsal usability flag contradicts the complete compatibility assessment.');
  } else if (evidence?.status !== 'not_run' || evidence.usable !== false) fail('The copied prompt fabricates a rehearsal that was not saved.');
  const result = saved?.result, baseline = result?.baseline;
  if (completed && (!object(result) || result.status !== 'completed' || result.revision !== snapshot.revision)) fail('The completed job has no completed sandbox result for the pinned revision.');
  const baselinePass = baseline?.integrity === true && allPassed(baseline.setup) && allPassed(baseline.checks);
  const baselineDiagnostics = [...array(baseline?.setup), ...array(baseline?.checks)].filter(value => !passed(value)).map(diagnostic);
  if (completed && !baselinePass) warnings.push('The original repository setup/checks did not establish a passing baseline.');
  const expectedChecks = array(baseline?.checks).map(commandIdentity), expectedSetups = array(baseline?.setup).map(commandIdentity);
  const allowedChanges = new Set(array(snapshot.upgradePlans).flatMap(plan => [
    ...(plan.targetVersion ? [`${plan.name}\0${plan.currentVersion}\0${plan.targetVersion}`] : []),
    ...array(plan.parentOptions).filter(parent => parent?.version).map(parent => `${parent.parent}\0${parent.currentVersion}\0${parent.version}`)
  ]));
  const scenarios = array(result?.scenarios).map((row, index) => {
    const scenario = object(row) ? row : {};
    if (!object(row)) fail(`Scenario ${index + 1} contains invalid evidence.`);
    const changes = array(scenario.changes), seen = new Set(), targets = new Map();
    for (const change of changes) {
      if (!object(change)) { fail(`Scenario ${index + 1} contains an invalid change.`); continue; }
      const key = packageKey(change);
      if (seen.has(key)) fail(`Scenario ${index + 1} duplicates an upgrade for ${change.name}@${change.currentVersion}.`);
      seen.add(key);
      if (targets.has(change.name) && targets.get(change.name) !== change.targetVersion) fail(`Scenario ${index + 1} selects conflicting targets for ${change.name}.`);
      targets.set(change.name, change.targetVersion);
      if (!allowedChanges.has(`${change.name}\0${change.currentVersion}\0${change.targetVersion}`)) fail(`Scenario ${index + 1} includes a target absent from the persisted checked plans: ${change.name}@${change.targetVersion}.`);
    }
    const coverage = array(scenario.coverage);
    const covered = changes.length > 0 && coverage.length === changes.length && changes.every(change => object(change) && coverage.some(value =>
      value?.name === change.name && value.currentVersion === change.currentVersion && value.targetVersion === change.targetVersion && value.targetPresent === true && value.oldVersionRemaining === false));
    const sameCommands = sameItems(array(scenario.setup).map(commandIdentity), expectedSetups) && sameItems(array(scenario.checks).map(commandIdentity), expectedChecks);
    const checksPassed = baselinePass && scenario.integrity === true && allPassed(scenario.resolution) && allPassed(scenario.setup) && allPassed(scenario.checks) && sameCommands && covered;
    const advisoryPassed = scenario.vulnerabilityCheck?.status === 'complete' && Array.isArray(scenario.vulnerabilityCheck.findings) && scenario.vulnerabilityCheck.findings.length === 0 &&
      scenario.remainingAdvisories === 0 && Array.isArray(scenario.newAdvisories) && scenario.newAdvisories.length === 0;
    if (scenario.status === 'tests_passed' && !checksPassed) fail(`Scenario ${index + 1} claims passing checks without complete baseline, resolution, install, matching checks, integrity, and target coverage evidence.`);
    if (!advisoryPassed) warnings.push(`Scenario ${index + 1} has no complete clean final advisory rescan; remaining/new matches or unrun checks need review.`);
    if (array(scenario.unrehearsedFindings).length) warnings.push(`Scenario ${index + 1} explicitly leaves ${scenario.unrehearsedFindings.length} advisory task(s) outside direct upgrade coverage.`);
    const diagnostics = [...array(scenario.resolution), ...array(scenario.setup), ...array(scenario.checks)].filter(value => !passed(value)).map(diagnostic);
    return { index: index + 1, status: scenario.status || 'unrun', changes, checksPassed, advisoryPassed, covered,
      checks: array(scenario.checks).map(diagnostic), diagnostics, remainingAdvisories: scenario.remainingAdvisories ?? null,
      newAdvisories: array(scenario.newAdvisories), unrehearsedFindings: array(scenario.unrehearsedFindings) };
  });
  if (completed && !scenarios.length) fail('The completed sandbox result contains no upgrade scenarios.');
  const compatibilityPassed = assessUpgradeRehearsal(saved, { snapshot, now }).compatibilityPassed && current && completed && baselinePass && scenarios.length > 0 && scenarios.every(value => value.status === 'tests_passed' && value.checksPassed && value.advisoryPassed);
  if (completed && !compatibilityPassed) warnings.push('A completed rehearsal contains diagnostics, not a verified dependency fix.');
  return { valid: errors.length === 0, repository, revision: snapshot.revision, errors, warnings: [...new Set(warnings)],
    advisoryTasks: tasks.length, coordinatedPackages: taskPaths.size, plannedPackages: chosenTargets.size,
    job: { id: saved?.id || null, status: saved?.status || 'not_run', current, completed, copiedUsable: evidence?.usable === true, evidenceIdentity: scanEvidenceKey(saved) },
    baseline: { passed: baselinePass, setup: array(baseline?.setup).map(diagnostic), checks: array(baseline?.checks).map(diagnostic), diagnostics: baselineDiagnostics },
    scenarios, compatibilityPassed: errors.length === 0 && compatibilityPassed, exploitRemediationVerified: false,
    outcome: !current ? 'stale_or_missing' : !completed ? saved.status : compatibilityPassed ? 'recorded_checks_passed' : 'completed_with_blockers',
    limitation: 'This compares copied text with saved scan and sandbox evidence. It does not attest browser actions, reproduce an exploit, establish CI results, or prove application security.' };
}

async function main() {
  const options = {};
  const args = process.argv.slice(2);
  while (args.length) {
    const key = args.shift();
    if (!['--snapshot', '--prompt', '--repository', '--installation-id', '--revision', '--output'].includes(key) || !args[0]) throw new Error('Usage: node scripts/validate-live-rehearsal.mjs --snapshot snapshot.json --prompt copied-prompt.txt [--repository owner/repo] [--installation-id id] [--revision sha] [--output validation.json]');
    options[key.slice(2)] = args.shift();
  }
  if (!options.snapshot || !options.prompt) throw new Error('Provide --snapshot and --prompt local evidence files.');
  const saved = JSON.parse(await readFile(options.snapshot, 'utf8'));
  const snapshot = Array.isArray(saved.snapshots) ? saved.snapshots.find(value => value.repository === options.repository && (!options['installation-id'] || value.installationId === Number(options['installation-id']))) : saved;
  const report = validateLiveRehearsal({ snapshot, prompt: await readFile(options.prompt, 'utf8'), repository: options.repository || snapshot?.repository,
    ...(options.revision ? { expectedRevision: options.revision } : {}),
    ...(options['installation-id'] ? { installationId: Number(options['installation-id']) } : {}) });
  if (options.output) await writeFile(options.output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  process.stdout.write(JSON.stringify(report, null, 2) + '\n'); process.exitCode = report.valid ? 0 : 2;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
