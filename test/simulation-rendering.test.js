import test from 'node:test';
import assert from 'node:assert/strict';
import { simulationSummary } from '../src/simulation-summary.js';

test('model predictions can render before a scenario has a test status', () => {
  const summary = simulationSummary({ status: 'running', prediction: { scenarios: [{ changes: [{ name: 'example', currentVersion: '1', targetVersion: '2' }], rationale: 'Proposed upgrade' }] } });
  assert.equal(summary.scenarios[0].status, 'not_tested');
  assert.equal(summary.scenarios[0].changes.length, 1);
  assert.equal(summary.verified, false);
});

test('incomplete simulation data produces an explicit unverified warning rather than a render exception', () => {
  for (const scenarios of [{}, [null], [{ status: 'tests_passed', changes: null }], [{ changes: [null, { name: {} }] }]]) {
    const summary = simulationSummary({ status: 'completed', result: { scenarios } });
    assert.equal(summary.verified, false);
    assert.ok(summary.issues.length);
    for (const scenario of summary.scenarios) { assert.equal(typeof scenario.status, 'string'); assert.ok(Array.isArray(scenario.changes)); }
  }
});

test('a missing candidate check cannot disappear while the remaining checks make the report look passing', () => {
  const summary = simulationSummary({ status: 'completed', result: { baseline: { setup: [{ passed: true }], checks: [{ passed: true }], integrity: true },
    scenarios: [{ status: 'tests_passed', changes: [{ name: 'example', currentVersion: '1', targetVersion: '2' }], checks: [null, { passed: true }], remainingAdvisories: 0, vulnerabilityCheck: { status: 'complete' } }] } });
  assert.equal(summary.verified, false);
  assert.ok(summary.issues.some(issue => issue.includes('test results')));
});

test('the report and copied evidence use the complete compatibility gate rather than a passing status string',async()=>{
  const {passingUpgradeEvidence}=await import('./fixtures/upgrade-evidence.js');
  const job=passingUpgradeEvidence();assert.equal(simulationSummary(job).verified,true);
  for(const change of [j=>delete j.result.scenarios[0].integrity,j=>j.result.scenarios[0].setup=[],j=>j.result.scenarios[0].checks[0].truncated=true,j=>j.result.scenarios[0].coverage[0].oldVersionRemaining=true,j=>j.blockers=[{package:'unplanned',reason:'No fixed release'}]]){
    const candidate=structuredClone(job);change(candidate);const report=simulationSummary(candidate);assert.equal(report.verified,false);assert.ok(report.assessment.blockers.length);
  }
});

test('the visible simulation stops claiming a passing result after its evidence expires', async () => {
  const { passingUpgradeEvidence } = await import('./fixtures/upgrade-evidence.js');
  const job = { ...passingUpgradeEvidence(), repository: 'org/app', installationId: 1,
    evidenceIdentity: 'c'.repeat(64), createdAt: Date.now() - 25 * 60 * 60 * 1000 };
  const snapshot = { repository: job.repository, installationId: job.installationId,
    revision: job.revision, evidenceIdentity: job.evidenceIdentity };
  const report = simulationSummary(job, snapshot);
  assert.equal(report.verified, false);
  assert.equal(report.title, 'Report is out of date');
  assert.ok(report.assessment.blockers.some(blocker => blocker.code === 'stale'));
});
