import test from 'node:test';
import assert from 'node:assert/strict';
import { selectRepository } from '../src/repository-selection.js';

const repositories = [
  { installationId: 1, repository: 'owner/first' },
  { installationId: 2, repository: 'owner/second' }
];
const snapshot = (repository, count) => ({ ...repository, vulnerabilityCheck: { findings: Array(count).fill({}) } });

test('valid selection wins while invalid selection falls back to the most findings', () => {
  const snapshots = [snapshot(repositories[0], 1), snapshot(repositories[1], 3)];
  assert.equal(selectRepository(repositories, snapshots, '1:owner/first'), '1:owner/first');
  assert.equal(selectRepository(repositories, snapshots, 'missing'), '2:owner/second');
});

test('ties and missing findings retain repository order without mutating inputs', () => {
  const snapshots = [snapshot(repositories[0], 2), snapshot(repositories[1], 2)];
  const before = structuredClone({ repositories, snapshots });
  assert.equal(selectRepository(repositories, snapshots), '1:owner/first');
  assert.equal(selectRepository(repositories, [{}]), '1:owner/first');
  assert.deepEqual({ repositories, snapshots }, before);
});

test('snapshot lookup uses the first strict installation and repository match', () => {
  const snapshots = [
    snapshot({ ...repositories[0], installationId: '1' }, 10),
    snapshot(repositories[0], 1), snapshot(repositories[0], 20),
    snapshot(repositories[1], 2)
  ];
  assert.equal(selectRepository(repositories, snapshots), '2:owner/second');
});

test('empty repositories return undefined for render and allow refresh empty-string fallback', () => {
  assert.equal(selectRepository([], [], '1:owner/first'), undefined);
  assert.equal(selectRepository([], [], '1:owner/first') || '', '');
});
