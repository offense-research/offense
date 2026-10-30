import test from 'node:test';
import assert from 'node:assert/strict';
import { dependencyImpact } from '../server/dependency-graph.js';

function node(id, name, targets = [], { root = false, version = '1.0.0' } = {}) {
  return { id, name, version, path: root ? '' : `node_modules/${id}`, file: 'package-lock.json',
    requires: targets.map(to => ({ to, name: to, range: '*', type: 'runtime' })) };
}
const leaf = () => node('leaf', 'leaf');
const impact = nodes => dependencyImpact({ nodes }, 'leaf', '1.0.0', '1.0.1');

test('path budgets explicitly mark omitted branches while preserving the existing 20-path limit', () => {
  const nodes = [leaf(), ...Array.from({ length: 21 }, (_, i) => node(`root-${i}`, `root-${i}`, ['leaf'], { root: true }))];
  const result = impact(nodes);
  assert.equal(result.paths.length, 20);
  assert.equal(result.parents.length, 21);
  assert.equal(result.truncated, true);
  assert.ok(result.truncationReasons.includes('path_limit'));
  const exact = impact(nodes.slice(0, 21));
  assert.equal(exact.paths.length, 20);
  assert.equal(exact.truncated, undefined, 'exactly exhausting the output count is complete when no branch remains');
});

test('a later installed instance cannot silently lose all paths after an earlier instance fills the path budget', () => {
  const nodes = [leaf(), ...Array.from({ length: 20 }, (_, i) => node(`root-${i}`, `root-${i}`, ['leaf'], { root: true })),
    node('leaf-second', 'leaf'), node('other-root', 'other-root', ['leaf-second'], { root: true })];
  const result = impact(nodes);
  assert.equal(result.instances, 2);
  assert.equal(result.parents.length, 21);
  assert.equal(result.paths.length, 20);
  assert.ok(result.truncationReasons.includes('path_limit'));
});

test('depth limits mark partial suffixes but a complete path exactly eight nodes long remains complete', () => {
  const chain = length => Array.from({ length }, (_, i) => node(`chain-${i}`, i === length - 1 ? 'leaf' : `parent-${i}`,
    i < length - 1 ? [`chain-${i + 1}`] : [], { root: i === 0 }));
  const limited = impact(chain(10));
  assert.equal(limited.paths.length, 1);
  assert.equal(limited.paths[0].length, 8);
  assert.equal(limited.truncated, true);
  assert.deepEqual(limited.truncationReasons, ['depth_limit']);
  const complete = impact(chain(8));
  assert.equal(complete.paths[0].length, 8);
  assert.equal(complete.truncated, undefined);
});

test('queue and traversal caps are explicitly recorded instead of silently dropping ancestors', () => {
  const queued = impact([leaf(), ...Array.from({ length: 2001 }, (_, i) => node(`root-${i}`, `root-${i}`, ['leaf'], { root: true }))]);
  assert.equal(queued.truncated, true);
  assert.ok(queued.truncationReasons.includes('queue_limit'));
  assert.ok(queued.paths.length <= 20);

  // A shared diamond graph fills 2,000 ancestor entries without terminal paths;
  // the traversal budget is reached before any queued root can be processed.
  const parents = Array.from({ length: 40 }, (_, i) => node(`parent-${i}`, `parent-${i}`, ['leaf']));
  const grandparents = Array.from({ length: 50 }, (_, i) => node(`grand-${i}`, `grand-${i}`, parents.map(parent => parent.id)));
  const traversed = impact([leaf(), ...parents, ...grandparents, node('root', 'app', grandparents.map(parent => parent.id), { root: true })]);
  assert.equal(traversed.truncated, true);
  assert.ok(traversed.truncationReasons.includes('traversal_limit'));
});

test('same-name installed instances remain in valid paths while actual node cycles terminate', () => {
  const repeatedName = impact([leaf(), node('parent-new', 'parent', ['leaf'], { version: '2.0.0' }),
    node('parent-old', 'parent', ['parent-new']), node('root', 'app', ['parent-old'], { root: true })]);
  assert.deepEqual(repeatedName.paths, [['app', 'parent', 'parent', 'leaf']]);
  assert.equal(repeatedName.truncated, undefined);
  const cycle = impact([leaf(), node('a', 'a', ['leaf', 'b']), node('b', 'b', ['a']), node('root', 'app', ['a'], { root: true })]);
  assert.deepEqual(cycle.paths, [['app', 'a', 'leaf']]);
  assert.equal(cycle.truncated, undefined);
  const boundaryCycle = impact(Array.from({ length: 8 }, (_, i) => node(`cycle-${i}`, i === 7 ? 'leaf' : `package-${i}`, [`cycle-${(i + 1) % 8}`])));
  assert.equal(boundaryCycle.truncated, undefined, 'closing a known cycle at the depth boundary does not hide a new ancestor');
});
