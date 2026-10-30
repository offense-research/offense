import { passingUpgradeEvidence } from './fixtures/upgrade-evidence.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { upgradeRoutes, routeEvidence } from '../src/upgrade-routes.js';
const change = { name: 'leaf', currentVersion: '1.0.0', targetVersion: '1.0.1' };
const plan = { ...change, impact: { parents: [{ name: 'parent', version: '2.0.0', compatible: false }] },
  parentOptions: [{ parent: 'parent', currentVersion: '2.0.0', version: '2.0.1', upstream: [] }] };
const snapshot = { repository: 'owner/repo', installationId: 123, revision: 'revision', scannedAt: 1, vulnerabilityCheck: { checkedAt: 2 } };
const good = { ...passingUpgradeEvidence({ revision:snapshot.revision, changes:[{name:'parent',currentVersion:'2.0.0',targetVersion:'2.0.1'},change] }), ...snapshot, advisoryCheckedAt:2 };

test('published path coordinates parent upgrades before the fixed dependency and leaves override unendorsed', () => {
  const routes = upgradeRoutes(plan);
  assert.equal(routes.length, 2);
  assert.equal(routes[0].recommended, true);
  assert.deepEqual(routes[0].changes.map(change => change.name), ['parent', 'leaf']);
  assert.equal(routes[1].recommended, false);
  assert.match(routes[1].description, /bypasses the parent/);
  assert.deepEqual(routes[1].changes, [change]);
});

test('missing parent releases, upstream blockers and unassessed ranges prevent recommendations', () => {
  const missing = upgradeRoutes({ ...plan, parentOptions: [] })[0];
  assert.equal(missing.recommended, false); assert.match(missing.blockers[0], /No compatible release/);
  const upstream = upgradeRoutes({ ...plan, parentOptions: [{ ...plan.parentOptions[0], upstream: [{ name: 'grandparent', compatible: false }] }] })[0];
  assert.equal(upstream.recommended, false);
  const unknown = upgradeRoutes({ ...plan, impact: { parents: [{ name: 'parent', compatible: null }] } })[0];
  assert.equal(unknown.recommended, false);
  assert.deepEqual(upgradeRoutes({ ...plan, mitigation: { reason: 'No fix' } }), []);
});

test('project range changes stay explicit and different installed parent versions are never conflated', () => {
  const root = upgradeRoutes({ ...plan, impact: { parents: [{ name: 'app', isRoot: true, compatible: false }] } })[0];
  assert.equal(root.requiresRootUpdate, true); assert.equal(root.recommended, true);
  assert.match(root.description, /declared range/);
  const wrongParent = upgradeRoutes({ ...plan, parentOptions: [{ ...plan.parentOptions[0], currentVersion: '1.0.0' }] })[0];
  assert.equal(wrongParent.recommended, false);
});

test('test evidence must match the exact path and scan before it can appear passed', () => {
  const [route, override] = upgradeRoutes(plan);
  assert.equal(routeEvidence(route, good, snapshot), 'Scenario checks passed');
  assert.equal(routeEvidence(override, good, snapshot), 'Not simulated for this path');
  const explicitOverride = structuredClone(good); explicitOverride.result.scenarios[0].changes = [change]; explicitOverride.result.scenarios[0].coverage = [{...change,targetPresent:true,oldVersionRemaining:false}]; explicitOverride.result.scenarios[0].applied = [{ ...change, field: 'overrides' }];
  assert.equal(routeEvidence(override, explicitOverride, snapshot), 'Scenario checks passed; override needs review');
  const withoutParent = structuredClone(good); withoutParent.result.scenarios[0].changes = [change];
  assert.equal(routeEvidence(route, withoutParent, snapshot), 'Not simulated for this path');
  assert.equal(routeEvidence(route, { ...good, stale: true }, snapshot), 'Not simulated for this scan');
  assert.equal(routeEvidence(route, good, { ...snapshot, revision: 'new' }), 'Not simulated for this scan');
  const baseline = structuredClone(good); baseline.result.baseline.checks[0].passed = false;
  assert.equal(routeEvidence(route, baseline, snapshot), 'Original checks need attention');
  const advisories = structuredClone(good); advisories.result.scenarios[0].remainingAdvisories = 1;
  assert.equal(routeEvidence(route, advisories, snapshot), 'Advisory checks need attention');
});

test('truncated dependency paths cannot produce a recommended upgrade route', () => {
  const route = upgradeRoutes({ ...plan, impact: { ...plan.impact, truncated: true } })[0];
  assert.equal(route.recommended, false);
  assert.ok(route.blockers.some(blocker => /path analysis was truncated/i.test(blocker)));
});

test('upgrading a parent makes application declaration changes explicit', () => {
  const route = upgradeRoutes({ ...plan, parentOptions: [{ ...plan.parentOptions[0], upstream: [
    { name: 'app', isRoot: true, compatible: false, range: '2.0.0', file: 'package-lock.json', workspace: 'web' }
  ] }] })[0];
  assert.equal(route.recommended, true);
  assert.equal(route.requiresRootUpdate, true);
  assert.deepEqual(route.rootUpdates, [{ name: 'parent', range: '2.0.0', targetVersion: '2.0.1', file: 'package-lock.json', workspace: 'web' }]);
  assert.match(route.description, /application declaration in web for parent \(2\.0\.0\) to allow 2\.0\.1/);
});

test('unassessed application constraints on a parent upgrade require review', () => {
  const route = upgradeRoutes({ ...plan, parentOptions: [{ ...plan.parentOptions[0], upstream: [
    { name: 'app', isRoot: true, compatible: null, range: 'catalog:' }
  ] }] })[0];
  assert.equal(route.recommended, false);
  assert.ok(route.blockers.some(blocker => /application's declared range for parent still needs checking/.test(blocker)));
});

test('conflicting targets for different installed instances of a parent are not recommended', () => {
  const route = upgradeRoutes({ ...plan, impact: { parents: [
    { name: 'parent', version: '1.0.0', compatible: false }, { name: 'parent', version: '2.0.0', compatible: false }
  ] }, parentOptions: [
    { parent: 'parent', currentVersion: '1.0.0', version: '1.0.1', upstream: [] },
    { parent: 'parent', currentVersion: '2.0.0', version: '2.0.1', upstream: [] }
  ] })[0];
  assert.equal(route.recommended, false);
  assert.ok(route.blockers.some(blocker => /Conflicting targets for parent: 1\.0\.1, 2\.0\.1/.test(blocker)));
  assert.deepEqual(route.changes.map(change => change.targetVersion), ['1.0.1', '2.0.1', '1.0.1']);
});

test('a route cannot borrow an isolated passing badge from a larger coordinated simulation',()=>{
  const [route]=upgradeRoutes(plan), candidate=structuredClone(good);
  candidate.result.scenarios[0].changes.push({name:'other',currentVersion:'1.0.0',targetVersion:'2.0.0'});
  assert.equal(routeEvidence(route,candidate,snapshot),'Tested only with other upgrades; review the full scenario');
});

test('a route badge rejects candidate results from a different commit',()=>{
  const [route]=upgradeRoutes(plan),candidate=structuredClone(good);candidate.result.revision='other-commit';
  assert.equal(routeEvidence(route,candidate,snapshot),'Simulation is incomplete');
});

test('route evidence prefers an exact scenario and handles partial sandbox rows without crashing',()=>{
  const [route]=upgradeRoutes(plan),candidate=structuredClone(good),exact=structuredClone(candidate.result.scenarios[0]);
  candidate.result.scenarios[0].changes.push({name:'other',currentVersion:'1',targetVersion:'2'});candidate.result.scenarios.push(exact);
  assert.equal(routeEvidence(route,candidate,snapshot),'Scenario checks passed');
  for(const rows of [{},[null],[{changes:{}}],[{changes:[null,null]}]]){
    candidate.result.scenarios=rows;assert.equal(routeEvidence(route,candidate,snapshot),'Not simulated for this path');
  }
});
