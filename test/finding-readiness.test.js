import test from 'node:test';
import assert from 'node:assert/strict';
import { findingReadiness } from '../src/finding-readiness.js';

const finding = { package: 'leaf', version: '1.0.0', fixedVersions: ['1.2.0'] };
const checkedPlan = () => ({ name: 'leaf', currentVersion: '1.0.0', targetVersion: '1.2.0', impact: { parents: [] }, constraintWarnings: [] });

test('advisory-listed versions do not imply a repository path has been checked', () => {
  assert.deepEqual(findingReadiness(finding), { state: 'unplanned', label: 'Advisory-listed fix', target: '1.2.0', detail: 'The repository upgrade path has not been checked.', blockers: [] });
  assert.equal(findingReadiness({ ...finding, resolved: false }, checkedPlan()).label, 'Exact version needed');
  assert.equal(findingReadiness(finding, checkedPlan(), { manifestOnly: true }).target, '');
});

test('blocked targets and incomplete path analysis cannot display the checked label', () => {
  for (const plan of [
    { ...checkedPlan(), constraintWarnings: ['Required peer range is incompatible.'] },
    { ...checkedPlan(), impact: { parents: [], truncated: true } },
    { ...checkedPlan(), impact: { parents: [{ name: 'parent', version: '1.0.0', compatible: false }] } }
  ]) {
    const readiness = findingReadiness(finding, plan);
    assert.equal(readiness.label, 'Needs review');
    assert.equal(readiness.state, 'blocked');
    assert.ok(readiness.blockers.length);
  }
  assert.equal(findingReadiness(finding, { ...checkedPlan(), mitigation: { reason: 'No published release covers the vulnerable path.' } }).label, 'Needs mitigation');
});

test('a checked coordinated parent path remains distinguishable from a standalone target', () => {
  assert.equal(findingReadiness(finding, checkedPlan()).label, 'Path checked');
  const plan = { ...checkedPlan(), impact: { parents: [{ name: 'parent', version: '1.0.0', compatible: false }] }, parentOptions: [{ parent: 'parent', currentVersion: '1.0.0', version: '2.0.0' }] };
  assert.equal(findingReadiness(finding, plan).label, 'Needs parent upgrade');
  assert.equal(findingReadiness(finding, plan).state, 'parent');
});
