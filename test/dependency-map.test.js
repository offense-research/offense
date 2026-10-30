import test from 'node:test';
import assert from 'node:assert/strict';
import { dependencyChoices, dependencyMap, resolutionAdvice } from '../src/dependency-map.js';
import { CLOUDFLARE_FEATURES, productSection } from '../src/product-features.js';

const nodes = [
  { id: 'app', name: 'product', version: '1', path: '', file: 'package-lock.json', requires: [{ to: 'parent', range: '^2', type: 'runtime' }] },
  { id: 'parent', name: 'parent', version: '2', path: 'node_modules/parent', file: 'package-lock.json', requires: [{ to: 'lib-old', range: '1.0.0', type: 'runtime' }, { to: 'lib-new', range: '2.0.0', type: 'optional' }] },
  { id: 'lib-old', name: 'lib', version: '1.0.0', path: 'node_modules/lib', file: 'package-lock.json', requires: [] },
  { id: 'lib-new', name: 'lib', version: '2.0.0', path: 'node_modules/parent/node_modules/lib', file: 'package-lock.json', requires: [] },
];

test('map follows exact installed versions and parent edges without inventing application reachability', () => {
  const map = dependencyMap({ nodes }, 'lib', '1.0.0');
  assert.deepEqual(new Set(map.nodes.map(node => node.id)), new Set(['app', 'parent', 'lib-old']));
  assert.equal(map.edges.length, 2);
  assert.equal(map.instances, 1); assert.equal(map.parents, 1);
  assert.ok(map.nodes.find(node => node.id === 'app').x < map.nodes.find(node => node.id === 'lib-old').x);
  assert.equal(map.edges.find(edge => edge.to.id === 'lib-old').range, '1.0.0');
});

test('map preserves multiple lockfiles and terminates on cycles and bounded large graphs', () => {
  const other = nodes.map(node => ({ ...node, id: 'other:'+node.id, file: 'service/package-lock.json', requires: node.requires.map(edge => ({ ...edge, to: 'other:'+edge.to })) }));
  const both = dependencyMap({ nodes: [...nodes, ...other] }, 'lib', '1.0.0');
  assert.equal(both.instances, 2); assert.equal(both.parents, 2);
  const cyclic = structuredClone(nodes); cyclic[2].requires = [{ to: 'parent' }];
  assert.equal(dependencyMap({ nodes: cyclic }, 'lib', '1.0.0').nodes.length, 3);
  const limited = dependencyMap({ nodes }, 'lib', '1.0.0', { limit: 2 });
  assert.equal(limited.nodes.length, 2); assert.equal(limited.truncated, true);
  assert.deepEqual(dependencyMap(undefined, 'lib', '1.0.0').nodes, []);
});

test('choices group overlapping advisories, retain separate versions and exclude declared ranges', () => {
  const finding = { id: 'one', package: 'lib', version: '1.0.0' };
  const choices = dependencyChoices({ vulnerabilityCheck: { findings: [finding, finding, { ...finding, id: 'two' }] },
    packages: [{ name: 'lib', version: '1.0.0', resolved: true }, { name: 'lib', version: '2.0.0', resolved: true }, { name: 'declared', version: '^1', resolved: false }] });
  assert.equal(choices.length, 2); assert.equal(choices[0].advisories.length, 2);
  assert.notEqual(choices[0].key, choices[1].key);
});

test('resolution prioritizes blocked parent upgrades and never presents an override as automatically safe', () => {
  const plan = { name: 'lib', currentVersion: '1.0.0', targetVersion: '1.0.1', impact: { parents: [{ compatible: false }] }, parentOptions: [] };
  assert.match(resolutionAdvice(plan).title, /parent constraint/);
  assert.match(resolutionAdvice(plan).steps[0], /review a scoped override/);
  plan.parentOptions = [{ parent: 'parent', currentVersion: '2', version: '3', action: 'Review compatibility.' }];
  assert.match(resolutionAdvice(plan).steps[0], /Upgrade parent: 2 → 3/);
  assert.equal(resolutionAdvice({ mitigation: { steps: ['Isolate affected code'] } }).steps[0], 'Isolate affected code');
  assert.match(resolutionAdvice(undefined).title, /Check the upgrade path/);
});

test('paused runtime features redirect old deep links but preserve dependency and settings navigation', () => {
  assert.equal(CLOUDFLARE_FEATURES, false);
  for (const target of ['collector', 'overview', 'events', 'investigations', 'worker-repositories']) {
    assert.equal(productSection(target, true), 'dependencies');
    assert.equal(productSection(target, false), 'connections');
  }
  assert.equal(productSection('connections', true), 'connections');
  assert.equal(productSection('dependencies', true), 'dependencies');
});
