import test from 'node:test';
import assert from 'node:assert/strict';
import { describeBlastRadius } from '../src/blast-radius.js';
import { passingUpgradeEvidence } from './fixtures/upgrade-evidence.js';

const change = { name: 'playwright', currentVersion: '1.48.2', targetVersion: '1.55.1' };
const scenario = { changes: [change], totalDependencyChanges: 2, status: 'tests_passed', checks: [{ passed: true }], remainingAdvisories: 0, vulnerabilityCheck: { status: 'complete' } };

test('blast radius explains recorded upgrades and parents as a paragraph without inventing app features', () => {
  const text = describeBlastRadius(scenario, [{ ...change, paths: [['app', 'bugpatrol', 'playwright']], parents: [{ name: 'bugpatrol', compatible: false }] }]);
  assert.match(text, /playwright from 1.48.2 to 1.55.1/);
  assert.match(text, /uses this dependency through bugpatrol/);
  assert.match(text, /2 installed dependency entries/);
  assert.match(text, /outside the dependency ranges declared by bugpatrol/);
  assert.match(text, /1 candidate check reported passing, but a complete matching baseline comparison has not passed/);
  assert.doesNotMatch(text, /candidate passed/);
  assert.match(text, /application features still needs verification/);
  assert.equal(text.includes('\n'), false);
  assert.doesNotMatch(text, /safe to merge|no breaking changes|checkout page|authentication flow/);
});

test('blast radius cannot describe mismatched or incomplete checks as a passed comparison', () => {
  const evidence = passingUpgradeEvidence({ changes: [change] }).result;
  assert.match(describeBlastRadius(evidence.scenarios[0], [], evidence.baseline), /candidate passed its 1 recorded check against the same checks/);
  evidence.scenarios[0].checks[0].command = ['npm', 'run', 'build'];
  const text = describeBlastRadius(evidence.scenarios[0], [], evidence.baseline);
  assert.match(text, /complete matching baseline comparison has not passed/);
  assert.doesNotMatch(text, /candidate passed/);
});

test('blast radius preserves unknown coverage and highlights major upgrade and baseline blockers', () => {
  const text = describeBlastRadius({ changes: [change] }, [{ ...change, majorChange: true }], { checks: [{ passed: false }] });
  assert.match(text, /does not identify which packages depend/);
  assert.match(text, /has not been measured/);
  assert.match(text, /crosses a major version/);
  assert.match(text, /original project did not pass/);
  assert.match(text, /advisory recheck has not completed/);
  assert.doesNotMatch(text, /candidate passed/);
});

test('blast radius distinguishes direct dependencies, resolution failures and outstanding advisories', () => {
  const text = describeBlastRadius({ ...scenario, status: 'resolution_failed', checks: [], remainingAdvisories: 3 }, [{ ...change, parents: [{ isRoot: true, name: 'app' }] }]);
  assert.match(text, /declared directly by your project/);
  assert.match(text, /Dependency resolution failed/);
  assert.match(text, /3 advisory matches still need remediation/);
  assert.doesNotMatch(text, /through app/);
  const failed = describeBlastRadius({ ...scenario, checks: [{ passed: false }, { passed: true }] });
  assert.match(failed, /1 candidate check failed/);
});

test('long scenarios stay readable while the full evidence remains available separately', () => {
  const changes = Array.from({ length: 8 }, (_, i) => ({ ...change, name: `package-${i}` }));
  const text = describeBlastRadius({ ...scenario, changes });
  assert.match(text, /package-0 from/);
  assert.match(text, /5 more/);
  assert.ok(!text.includes('package-7 from'));
  assert.match(describeBlastRadius({ changes: [] }), /impact is not yet known/);
});
