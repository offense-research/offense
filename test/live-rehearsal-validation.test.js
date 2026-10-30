import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOneShotPrompt } from '../src/remediation-prompts.js';
import { extractPromptEvidence, validateLiveRehearsal } from '../scripts/validate-live-rehearsal.mjs';

function fixture() {
  const now = Date.now();
  const check = (directory, phase, command) => ({ directory, phase, command, exitCode: 0, passed: true, timedOut: false, output: 'Recorded fixture command output' });
  const snapshot = { repository: 'owner/tinkered', installationId: 123, revision: 'a'.repeat(40), scannedAt: now - 5000, files: ['package-lock.json'],
    vulnerabilityCheck: { status: 'complete', checkedAt: now - 4000, findings: [
      { id: 'GHSA-one', package: 'example', version: '1.0.0', severity: 'HIGH', cves: ['CVE-fixture'], fixedVersions: ['1.1.0'] },
      { id: 'GHSA-overlap', package: 'example', version: '1.0.0', severity: 'HIGH', cves: [], fixedVersions: ['1.2.0'] }
    ] } };
  const plan = { name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0', releases: ['1.0.0', '1.1.0', '1.2.0'], steps: [],
    impact: { paths: [['app', 'example']], parents: [] }, parentOptions: [], considered: [{ version: '1.2.0', advisories: 0 }],
    snapshotRevision: snapshot.revision, snapshotScannedAt: snapshot.scannedAt, advisoryCheckedAt: snapshot.vulnerabilityCheck.checkedAt };
  snapshot.upgradePlans = [plan];
  const install = ['npm', 'ci', '--ignore-scripts'], tests = ['npm', 'run', '--ignore-scripts', 'test'];
  snapshot.rehearsal = { id: 'saved-job', repository: snapshot.repository, installationId: snapshot.installationId, revision: snapshot.revision,
    scannedAt: snapshot.scannedAt, advisoryCheckedAt: snapshot.vulnerabilityCheck.checkedAt, status: 'completed', stale: false, createdAt: now - 1000, finishedAt: now - 100,
    result: { status: 'completed', revision: snapshot.revision,
      baseline: { integrity: true, integrityVersion: 2, setup: [check('source', 'baseline:install', install)], checks: [check('source', 'baseline:test', tests)] },
      scenarios: [{ status: 'tests_passed', changes: [{ name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0' }],
        resolution: [check('candidate-0', 'candidate:resolve', ['npm', 'install', '--package-lock-only'])],
        integrity: true, integrityVersion: 2, setup: [check('candidate-0', 'candidate:install', install)], checks: [check('candidate-0', 'candidate:test', tests)],
        coverage: [{ name: 'example', currentVersion: '1.0.0', targetVersion: '1.2.0', targetPresent: true, oldVersionRemaining: false }],
        remainingAdvisories: 0, vulnerabilityCheck: { status: 'complete', checkedPackages:1, skippedPackages:0, findings: [] }, newAdvisories: [], unrehearsedFindings: [] }]
    } };
  const prompt = () => buildOneShotPrompt({ repository: snapshot.repository, snapshot, findings: snapshot.vulnerabilityCheck.findings, plans: snapshot.upgradePlans });
  return { snapshot, prompt };
}

test('live validator binds all advisory tasks, coordinated paths, revision and exact saved command evidence', () => {
  const f = fixture(), result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt(), expectedRevision: f.snapshot.revision });
  assert.equal(result.valid, true, result.errors.join('; ')); assert.equal(result.compatibilityPassed, true);
  assert.equal(result.advisoryTasks, 2); assert.equal(result.coordinatedPackages, 1); assert.equal(result.plannedPackages, 1);
  assert.equal(result.job.id, 'saved-job'); assert.equal(result.scenarios[0].checks[0].exitCode, 0);
  assert.equal(result.outcome, 'recorded_checks_passed'); assert.equal(result.exploitRemediationVerified, false);
});

test('a completed baseline failure is useful copied diagnostics and never a passing upgrade', () => {
  const f = fixture(), baseline = f.snapshot.rehearsal.result.baseline;
  baseline.checks[0].passed = false; baseline.checks[0].exitCode = 1; baseline.checks[0].output = 'Original test failed';
  f.snapshot.rehearsal.result.scenarios[0].status = 'baseline_failed';
  const result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt() });
  assert.equal(result.valid, true); assert.equal(result.compatibilityPassed, false); assert.equal(result.outcome, 'completed_with_blockers');
  assert.equal(result.job.copiedUsable, false); assert.equal(result.baseline.diagnostics[0].output, 'Original test failed');
  assert.ok(result.warnings.some(value => /passing baseline/.test(value)));
});

test('resolver failures and unrun checks stay explicit and cannot be promoted by a passing status string', () => {
  const f = fixture(), scenario = f.snapshot.rehearsal.result.scenarios[0];
  scenario.resolution[0].passed = false; scenario.resolution[0].exitCode = 1; scenario.resolution[0].output = 'npm ERESOLVE';
  scenario.status = 'resolution_failed'; scenario.setup = []; scenario.checks = []; scenario.coverage = [];
  delete scenario.vulnerabilityCheck; delete scenario.remainingAdvisories;
  let result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt() });
  assert.equal(result.valid, true); assert.equal(result.compatibilityPassed, false); assert.match(result.scenarios[0].diagnostics[0].output, /ERESOLVE/);
  scenario.status = 'tests_passed';
  result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt() });
  assert.equal(result.valid, false); assert.ok(result.errors.some(value => /claims passing checks/.test(value)));
});

test('stale, pending, stale plans and copied command modifications are rejected', () => {
  for (const change of [f => { f.snapshot.rehearsal.stale = true; }, f => { f.snapshot.rehearsal.status = 'running'; },
    f => { f.snapshot.upgradePlans[0].snapshotRevision = 'b'.repeat(40); }, f => { f.snapshot.rehearsal.finishedAt -= 25 * 3600000; }]) {
    const f = fixture(); change(f);
    const result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt() });
    assert.equal(result.valid, false); assert.equal(result.compatibilityPassed, false);
  }
  const f = fixture(), copied = f.prompt(); f.snapshot.rehearsal.result.baseline.checks[0].output = 'Changed after copy';
  const result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: copied });
  assert.equal(result.valid, false); assert.ok(result.errors.some(value => /exact saved job/.test(value)));
});

test('dropped advisories, conflicting paths and fabricated targets cannot pass prompt validation', () => {
  const f = fixture();
  const incomplete = buildOneShotPrompt({ repository: f.snapshot.repository, snapshot: f.snapshot, findings: [f.snapshot.vulnerabilityCheck.findings[0]], plans: f.snapshot.upgradePlans });
  assert.equal(validateLiveRehearsal({ snapshot: f.snapshot, prompt: incomplete }).valid, false);
  const evidence = extractPromptEvidence(f.prompt());
  evidence.tasks[1].updatePath.targetVersion = '99.0.0';
  const altered = f.prompt().replace(JSON.stringify(extractPromptEvidence(f.prompt()), null, 2), JSON.stringify(evidence, null, 2));
  const result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: altered });
  assert.equal(result.valid, false); assert.ok(result.errors.some(value => /conflicting upgrade paths/.test(value)));
});

test('missing or malformed command, integrity, coverage and final scan records remain unverified', () => {
  for (const change of [f => { delete f.snapshot.rehearsal.result.baseline.integrity; },
    f => { delete f.snapshot.rehearsal.result.scenarios[0].setup[0].exitCode; },
    f => { f.snapshot.rehearsal.result.scenarios[0].coverage[0].oldVersionRemaining = true; },
    f => { f.snapshot.rehearsal.result.scenarios[0].vulnerabilityCheck.status = 'failed'; },
    f => { f.snapshot.rehearsal.result.scenarios = [null]; }]) {
    const f = fixture(); change(f);
    const result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: f.prompt() });
    assert.equal(result.compatibilityPassed, false);
  }
});

test('immutable content identities preserve copied evidence across a timestamp-only scan refresh', () => {
  const f = fixture();
  f.snapshot.evidenceIdentity = '1'.repeat(64); f.snapshot.rehearsal.evidenceIdentity = f.snapshot.evidenceIdentity;
  f.snapshot.upgradePlans[0].evidenceIdentity = f.snapshot.evidenceIdentity;
  const copied = f.prompt();
  f.snapshot.scannedAt += 50; f.snapshot.vulnerabilityCheck.checkedAt += 50;
  let result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: copied });
  assert.equal(result.valid, true, result.errors.join('; ')); assert.equal(result.compatibilityPassed, true);
  f.snapshot.evidenceIdentity = '2'.repeat(64);
  result = validateLiveRehearsal({ snapshot: f.snapshot, prompt: copied });
  assert.equal(result.valid, false); assert.equal(result.compatibilityPassed, false);
  assert.ok(result.errors.some(value => /immutable scan content/.test(value)));
});

test('copied prompts cannot erase planner peer/coverage warnings or invent a passing assessment',()=>{
  const f=fixture();Object.assign(f.snapshot.upgradePlans[0],{constraintWarnings:['A peer still needs coordination.'],peerConstraints:{status:'blocked',checks:[{peer:'react',compatible:false}]},targetSelection:{limited:true}});f.snapshot.upgradePlans[0].impact.truncated=true;
  const original=f.prompt(),parsed=extractPromptEvidence(original);
  for(const field of ['constraintWarnings','peerConstraints','targetSelection','dependencyPathsTruncated']){
    const changed=structuredClone(parsed);for(const task of changed.tasks)task.updatePath[field]=field==='dependencyPathsTruncated'?false:field==='constraintWarnings'?[]:null;
    const prompt=original.replace(JSON.stringify(parsed,null,2),JSON.stringify(changed,null,2));const validation=validateLiveRehearsal({snapshot:f.snapshot,prompt});assert.equal(validation.valid,false);assert.ok(validation.errors.some(error=>error.includes(field)));
  }
  f.snapshot.rehearsal.result.baseline.integrity=false;const failed=f.prompt(),evidence=extractPromptEvidence(failed);evidence.upgradeAssessment={compatibilityPassed:true,blockers:[]};
  const validation=validateLiveRehearsal({snapshot:f.snapshot,prompt:failed.replace(JSON.stringify(extractPromptEvidence(failed),null,2),JSON.stringify(evidence,null,2))});
  assert.equal(validation.valid,false);assert.ok(validation.errors.some(error=>error.includes('compatibility assessment')));
});
