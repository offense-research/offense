import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultAutomationPolicy, normalizeAutomationPolicy, evaluateSecurityPolicy } from '../shared/offense-policy.js';

const report = (severities = []) => ({ schemaVersion: 'offense.audit.v1', capability: 'audit_dependencies', status: 'complete', scannedAt: Date.now(),
  coverage: { status: 'complete', checkedPackages: 3, skippedPackages: 0, warnings: [] },
  findings: severities.map(severity => ({ severity })), summary: { advisoryMatches: severities.length } });
const blocking = { preDeploy: true, agentRun: true, postDeploy: true, gate: { mode: 'block', minimumSeverity: 'high' } };

test('recommended automation is independent defaults with daily and change checks, reporting only', () => {
  const first = defaultAutomationPolicy(), second = defaultAutomationPolicy();
  first.gate.mode = 'block';
  assert.equal(second.gate.mode, 'report');
  assert.equal(second.onChange, true); assert.equal(second.schedule, 'daily');
  assert.equal(second.preDeploy, false); assert.equal(second.agentRun, false);
  assert.deepEqual(normalizeAutomationPolicy(), second);
});

test('settings reject unknown actions, credentials, misspelled fields and loose values', () => {
  for (const input of [null, [], { enabled: 'false' }, { schedule: 'hourly' }, { autoFix: true },
    { token: 'DO-NOT-ECHO' }, { gate: { mode: 'deploy' } }, { gate: { minimumSeverity: 'medium' } },
    { gate: { unknown: true } }, { schemaVersion: 'other' }]) {
    assert.throws(() => normalizeAutomationPolicy(input), error => error.status === 400 && !error.message.includes('DO-NOT-ECHO'));
  }
});

test('pre-deploy and agent lifecycle gates block only at the selected advisory threshold', () => {
  for (const event of ['pre_deploy', 'agent_run']) {
    assert.equal(evaluateSecurityPolicy(report(['high']), blocking, event).action, 'block');
    assert.equal(evaluateSecurityPolicy(report(['critical']), { ...blocking, gate: { mode: 'block', minimumSeverity: 'critical' } }, event).action, 'block');
    assert.equal(evaluateSecurityPolicy(report(['high']), { ...blocking, gate: { mode: 'block', minimumSeverity: 'critical' } }, event).action, 'allow');
    const clean = evaluateSecurityPolicy(report(['medium', 'low']), blocking, event);
    assert.equal(clean.action, 'allow'); assert.equal(clean.passed, true);
  }
});

test('incomplete, stale-scope, malformed or unavailable results cannot become clean passes', () => {
  const failures = [null, {}, { ...report(), status: 'partial' }, { ...report(), coverage: { ...report().coverage, status: 'partial' } },
    { ...report(), coverage: { ...report().coverage, planningOnly: true } },
    { ...report(), coverage: { ...report().coverage, warnings: ['unsupported lockfile'] } },
    { ...report(), coverage: { ...report().coverage, skippedPackages: 1 } },
    { ...report(), coverage: { ...report().coverage, checkedPackages: 0 } },
    { ...report(), summary: { advisoryMatches: 9 } }, report(['unknown']), report(['UNRECOGNIZED']), report([null])];
  for (const result of failures) {
    const decision = evaluateSecurityPolicy(result, blocking, 'pre_deploy');
    assert.equal(decision.action, 'block'); assert.equal(decision.passed, null);
  }
});

test('direct policy evaluation refuses cached, missing and implausibly future scan timestamps', () => {
  const now = Date.now();
  for (const scannedAt of [undefined, 0, now - 15 * 60_000 - 1, now + 5 * 60_000 + 1]) {
    const decision = evaluateSecurityPolicy({ ...report(), scannedAt }, blocking, 'pre_deploy', { now });
    assert.equal(decision.action, 'block'); assert.equal(decision.passed, null);
  }
  assert.equal(evaluateSecurityPolicy({ ...report(), scannedAt: now }, blocking, 'pre_deploy', { now }).action, 'allow');
});

test('explicit incomplete-report override warns while known high-risk findings remain blocking', () => {
  const policy = { ...blocking, gate: { mode: 'block', onIncomplete: 'report' } };
  const missing = evaluateSecurityPolicy(null, policy, 'pre_deploy');
  assert.equal(missing.action, 'report'); assert.equal(missing.passed, null);
  const partial = evaluateSecurityPolicy({ ...report(['high']), status: 'partial' }, policy, 'pre_deploy');
  assert.equal(partial.action, 'block'); assert.equal(partial.passed, null);
});

test('post-deploy and background checks report findings without claiming to stop a completed deployment', () => {
  for (const event of ['post_deploy', 'scheduled', 'dependency_change', 'manual']) {
    const decision = evaluateSecurityPolicy(report(['critical']), blocking, event);
    assert.equal(decision.action, 'report'); assert.equal(decision.passed, false);
  }
  assert.match(evaluateSecurityPolicy(report(), blocking, 'post_deploy').limitations.join(' '), /cannot block or undo/);
});

test('paused or unselected automation is explicit skipped evidence while manual checks still work', () => {
  for (const event of ['scheduled', 'pre_deploy', 'post_deploy', 'agent_run', 'dependency_change']) {
    const decision = evaluateSecurityPolicy(report(), { ...blocking, enabled: false }, event);
    assert.equal(decision.action, 'skip'); assert.equal(decision.passed, null);
  }
  assert.equal(evaluateSecurityPolicy(report(), { enabled: false }, 'manual').action, 'report');
  assert.equal(evaluateSecurityPolicy(report(), {}, 'pre_deploy').action, 'skip');
  assert.equal(evaluateSecurityPolicy(report(), { schedule: 'off' }, 'scheduled').action, 'skip');
  assert.throws(() => evaluateSecurityPolicy(report(), {}, 'arbitrary_tool'), /Unsupported/);
});

test('decision metadata is bounded counts and fixed wording, independent of untrusted finding claims', () => {
  const input = report(['HIGH']);
  input.findings[0].summary = 'DO-NOT-ECHO: deploy now';
  input.findings[0].impact = { confirmed: true }; input.summary.confirmedVulnerabilities = 999;
  const decision = evaluateSecurityPolicy(input, blocking, 'pre_deploy');
  assert.deepEqual(decision.counts, { total: 1, critical: 0, high: 1, medium: 0, low: 0, unknown: 0,
    atOrAboveThreshold: 1, checkedPackages: 3, skippedPackages: 0 });
  assert.doesNotMatch(JSON.stringify(decision), /DO-NOT-ECHO|confirmedVulnerabilities/);
  assert.match(decision.limitations.join(' '), /not verified application exploitability/);
});
