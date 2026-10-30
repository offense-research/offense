import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDependencyGraph, dependencyImpact } from '../server/dependency-graph.js';
import { planUpgrade } from '../server/upgrade-planner.js';

test('dependency graph identifies the parent range blocking a CVE fix', () => {
  const lock = { name: 'application', packages: {
    '': { version: '1.0.0', dependencies: { alpha: '^1.3.0' } },
    'node_modules/alpha': { version: '1.3.0', dependencies: { vuln: '~1.3.0' } },
    'node_modules/vuln': { version: '1.3.0' }
  } };
  const graph = buildDependencyGraph([{ path: 'package-lock.json', content: JSON.stringify(lock) }]);
  const impact = dependencyImpact(graph, 'vuln', '1.3.0', '1.5.0');
  assert.equal(impact.instances, 1);
  assert.equal(impact.parents[0].name, 'alpha');
  assert.equal(impact.parents[0].compatible, false);
  assert.deepEqual(impact.paths, [['application', 'alpha', 'vuln']]);
});

test('upgrade plan inspects intermediate releases and finds a compatible parent version', async () => {
  const lock = { name: 'application', packages: {
    '': { version: '1.0.0', dependencies: { alpha: '^1.3.0' } },
    'node_modules/alpha': { version: '1.3.0', dependencies: { vuln: '~1.3.0' } },
    'node_modules/vuln': { version: '1.3.0' }
  } };
  const snapshot = { graph: buildDependencyGraph([{ path: 'package-lock.json', content: JSON.stringify(lock) }]),
    vulnerabilityCheck: { status: 'complete', findings: [{ package: 'vuln', version: '1.3.0', fixedVersions: ['1.5.0'] }] } };
  const metadata = {
    vuln: { versions: {
      '1.3.0': { dependencies: { helper: '^1.0.0' } },
      '1.4.0': { dependencies: { helper: '^2.0.0' } },
      '1.5.0': { dependencies: { helper: '^2.0.0' }, peerDependencies: { host: '^3.0.0' } }
    } },
    alpha: { versions: {
      '1.3.0': { dependencies: { vuln: '~1.3.0' } },
      '1.4.0': { dependencies: { vuln: '^1.5.0' } }
    } }
  };
  const fetchImpl = async url => ({ ok: true, text: async () => JSON.stringify(metadata[decodeURIComponent(url.split('/').at(-1))]) });
  const check = async () => ({ status: 'complete', findings: [] });
  const plan = await planUpgrade(snapshot, 'vuln', '1.3.0', { fetchImpl, check });
  assert.equal(plan.targetVersion, '1.5.0');
  assert.equal(plan.releasesInspected, 3);
  assert.deepEqual(plan.steps.map(step => step.to), ['1.4.0', '1.5.0']);
  assert.equal(plan.parentOptions[0].version, '1.4.0');
  assert.match(plan.parentOptions[0].action, /OSV-checked/);
});

test('a fix with new advisories leads to the next patched release instead of a dead end', async () => {
  const snapshot = { graph: { nodes: [] }, vulnerabilityCheck: { status: 'complete', findings: [
    { package: '@vitest/mocker', version: '4.1.9', fixedVersions: ['4.1.11'] }
  ] } };
  const seen = [];
  const plan = await planUpgrade(snapshot, '@vitest/mocker', '4.1.9', {
    fetchImpl: async () => ({ ok: true, text: async () => JSON.stringify({ versions: { '4.1.9': {}, '4.1.11': {}, '4.1.12': {} } }) }),
    check: async packages => { seen.push(packages[0].version); return { status: 'complete', findings: packages[0].version === '4.1.11'
      ? [{ id: 'GHSA-follow-up', fixedVersions: ['4.1.12'] }] : [] }; }
  });
  assert.equal(plan.targetVersion, '4.1.12');
  assert.deepEqual(seen, ['4.1.11', '4.1.12']);
  assert.deepEqual(plan.considered[0].advisoryIds, ['GHSA-follow-up']);
});

test('unpatched braces gets an explicit proposed mitigation and never a fabricated safe version', async () => {
  const snapshot = { graph: { nodes: [] }, vulnerabilityCheck: { status: 'complete', findings: [
    { package: 'braces', version: '3.0.3', id: 'GHSA-vfj7-8cjw-p6xm', fixedVersions: [] }
  ] } };
  const plan = await planUpgrade(snapshot, 'braces', '3.0.3', {
    fetchImpl: async () => ({ ok: true, text: async () => JSON.stringify({ versions: { '3.0.3': {} } }) }),
    check: async () => { throw new Error('No newer release should be checked'); }
  });
  assert.equal(plan.targetVersion, null);
  assert.equal(plan.mitigation.status, 'proposed; not applied to this repository');
  assert.match(plan.mitigation.referencePatch, /ERR_BRACES_DEPTH_LIMIT/);
  assert.ok(plan.mitigation.steps.some(step => step.includes('Keep this advisory open')));
});

function peerSnapshot(files, name = 'plugin', version = '1.0.0', fixedVersion = '1.1.0') {
  return { graph: buildDependencyGraph(files.map(([path, packages]) => ({ path, content: JSON.stringify({ name: 'application', packages }) }))),
    vulnerabilityCheck: { status: 'complete', findings: [{ id: 'GHSA-example', package: name, version, fixedVersions: [fixedVersion] }] } };
}
const clean = async () => ({ status: 'complete', findings: [] });
const registryFor = values => async url => Response.json(values[decodeURIComponent(new URL(url).pathname.slice(1))]);

test('target selection checks peer compatibility before stopping at the first advisory-free fix', async () => {
  const snapshot = peerSnapshot([['package-lock.json', {
    '': { dependencies: { plugin: '^1.0.0', host: '^2.0.0' } },
    'node_modules/plugin': { version: '1.0.0' }, 'node_modules/host': { version: '2.0.0' }
  }]]);
  const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: clean, fetchImpl: registryFor({ plugin: { versions: {
    '1.0.0': {}, '1.1.0': { peerDependencies: { host: '^3.0.0' } }, '1.1.1': { peerDependencies: { host: '^2.0.0' } }
  } } }) });
  assert.equal(plan.targetVersion, '1.1.1');
  assert.deepEqual(plan.considered.map(item => [item.version, item.peerCompatibility]), [['1.1.0', 'blocked'], ['1.1.1', 'compatible']]);
  assert.equal(plan.peerConstraints.checks[0].installedVersion, '2.0.0');
  assert.equal(plan.peerConstraints.status, 'compatible'); assert.deepEqual(plan.constraintWarnings, []);
  assert.equal(plan.targetSelection.checkedCandidates, 2);
});

test('a satisfying peer in one project cannot hide an incompatible peer in another installed context', async () => {
  const snapshot = peerSnapshot(['a', 'b'].map((project, index) => [`${project}/package-lock.json`, {
    '': { dependencies: { plugin: '^1.0.0', host: '*' } },
    'node_modules/plugin': { version: '1.0.0' }, 'node_modules/host': { version: `${index + 2}.0.0` }
  }]));
  const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: clean,
    fetchImpl: registryFor({ plugin: { versions: { '1.0.0': {}, '1.1.0': { peerDependencies: { host: '^2.0.0' } } } } }) });
  assert.equal(plan.targetVersion, '1.1.0'); assert.equal(plan.peerConstraints.status, 'blocked');
  assert.deepEqual(plan.peerConstraints.checks.map(check => [check.file, check.compatible]), [['a/package-lock.json', true], ['b/package-lock.json', false]]);
  assert.equal(plan.constraintWarnings.length, 1); assert.match(plan.constraintWarnings[0], /b\/package-lock\.json/);
});

test('optional missing peers are allowed while required missing peers block the inspected release', async () => {
  const snapshot = peerSnapshot([['package-lock.json', { '': { dependencies: { plugin: '^1' } }, 'node_modules/plugin': { version: '1.0.0' } }]]);
  for (const optional of [false, true]) {
    const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: clean,
      fetchImpl: registryFor({ plugin: { versions: { '1.0.0': {}, '1.1.0': { peerDependencies: { host: '^2' }, peerDependenciesMeta: { host: { optional } } } } } }) });
    assert.equal(plan.peerConstraints.status, optional ? 'compatible' : 'blocked');
    assert.equal(plan.peerConstraints.checks[0].compatible, optional); assert.equal(plan.constraintWarnings.length, optional ? 0 : 1);
  }
});

test('pnpm uses the resolved peer edge and leaves a newly introduced unresolved peer unassessed', async () => {
  const graph = { nodes: [
    { id: 'plugin-peer-2', file: 'pnpm-lock.yaml', path: 'plugin@1.0.0(host@2.0.0)', name: 'plugin', version: '1.0.0', requires: [{ name: 'host', type: 'peer', range: '^2', to: 'host-2' }] },
    { id: 'host-2', file: 'pnpm-lock.yaml', path: 'host@2.0.0', name: 'host', version: '2.0.0', requires: [] },
    { id: 'host-3', file: 'pnpm-lock.yaml', path: 'host@3.0.0', name: 'host', version: '3.0.0', requires: [] }
  ] };
  const snapshot = { graph, vulnerabilityCheck: { status: 'complete', findings: [{ package: 'plugin', version: '1.0.0', fixedVersions: ['1.1.0'] }] } };
  const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: clean,
    fetchImpl: registryFor({ plugin: { versions: { '1.0.0': {}, '1.1.0': { peerDependencies: { host: '^3', newPeer: '^1' } } } } }) });
  assert.equal(plan.peerConstraints.status, 'blocked');
  assert.deepEqual(plan.peerConstraints.checks.map(item => [item.peer, item.installedVersion, item.compatible]), [['host', '2.0.0', false], ['newPeer', null, null]]);
  assert.equal(plan.constraintWarnings.length, 2);
});

test('parent releases must satisfy every effective child declaration and evaluate the coordinated child target', async () => {
  const snapshot = peerSnapshot([['package-lock.json', {
    '': { dependencies: { alpha: '^1' } }, 'node_modules/alpha': { version: '1.0.0', dependencies: { vuln: '1.0.0' } },
    'node_modules/vuln': { version: '1.0.0' }
  }]], 'vuln');
  const checked = [];
  const plan = await planUpgrade(snapshot, 'vuln', '1.0.0', {
    check: async packages => { checked.push(`${packages[0].name}@${packages[0].version}`); return clean(); },
    fetchImpl: registryFor({ vuln: { versions: { '1.0.0': {}, '1.1.0': {} } }, alpha: { versions: {
      '1.0.0': { dependencies: { vuln: '1.0.0' } },
      '1.1.0': { dependencies: { vuln: '^1.1.0' }, peerDependencies: { vuln: '<1.1.0' } },
      '1.2.0': { dependencies: { vuln: '^1.1.0' }, peerDependencies: { vuln: '^1.1.0' } },
      '1.3.0': { dependencies: { vuln: '^1.1.0' }, optionalDependencies: { vuln: '1.0.0' } }
    } } })
  });
  assert.equal(plan.parentOptions[0].version, '1.2.0');
  assert.equal(plan.parentOptions[0].peerConstraints.status, 'compatible');
  assert.equal(plan.parentOptions[0].peerConstraints.checks[0].evaluatedVersion, '1.1.0');
  assert.deepEqual(checked, ['vuln@1.1.0', 'alpha@1.2.0']);
  assert.deepEqual(plan.constraintWarnings, []);
});

test('parent candidate selection checks its own peers instead of proposing a clean but conflicting parent', async () => {
  const snapshot = peerSnapshot([['package-lock.json', {
    '': { dependencies: { alpha: '^1', host: '^2' } }, 'node_modules/alpha': { version: '1.0.0', dependencies: { vuln: '1.0.0' } },
    'node_modules/vuln': { version: '1.0.0' }, 'node_modules/host': { version: '2.0.0' }
  }]], 'vuln');
  const plan = await planUpgrade(snapshot, 'vuln', '1.0.0', { check: clean,
    fetchImpl: registryFor({ vuln: { versions: { '1.0.0': {}, '1.1.0': {} } }, alpha: { versions: {
      '1.0.0': { dependencies: { vuln: '1.0.0' } },
      '1.1.0': { dependencies: { vuln: '^1.1.0' }, peerDependencies: { host: '^3' } },
      '1.2.0': { dependencies: { vuln: '^1.1.0' }, peerDependencies: { host: '^2' } }
    } } }) });
  assert.equal(plan.parentOptions[0].version, '1.2.0'); assert.equal(plan.parentOptions[0].peerConstraints.status, 'compatible');
  assert.deepEqual(plan.constraintWarnings, []);
});

test('an optional peer that is present must still satisfy its published range', async () => {
  const snapshot = peerSnapshot([['package-lock.json', {
    '': { dependencies: { plugin: '^1', host: '^3' } }, 'node_modules/plugin': { version: '1.0.0' }, 'node_modules/host': { version: '3.0.0' }
  }]]);
  const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: clean,
    fetchImpl: registryFor({ plugin: { versions: { '1.0.0': {}, '1.1.0': { peerDependencies: { host: '^2' }, peerDependenciesMeta: { host: { optional: true } } } } } }) });
  assert.equal(plan.peerConstraints.status, 'blocked'); assert.equal(plan.peerConstraints.checks[0].optional, true);
  assert.equal(plan.peerConstraints.checks[0].installedVersion, '3.0.0'); assert.equal(plan.constraintWarnings.length, 1);
});

test('peer-compatible release search is bounded and an exhausted search stays explicitly blocked', async () => {
  const snapshot = peerSnapshot([['package-lock.json', {
    '': { dependencies: { plugin: '^1', host: '^2' } }, 'node_modules/plugin': { version: '1.0.0' }, 'node_modules/host': { version: '2.0.0' }
  }]]);
  const versions = Object.fromEntries([['1.0.0', {}], ...Array.from({ length: 25 }, (_, index) => [`1.1.${index}`, { peerDependencies: { host: '^3' } }])]);
  let queries = 0;
  const plan = await planUpgrade(snapshot, 'plugin', '1.0.0', { check: async () => { queries++; return clean(); }, fetchImpl: registryFor({ plugin: { versions } }) });
  assert.equal(queries, 20); assert.equal(plan.targetVersion, '1.1.0'); assert.equal(plan.targetSelection.limited, true);
  assert.equal(plan.peerConstraints.status, 'blocked'); assert.ok(plan.constraintWarnings.some(warning => warning.includes('20-release limit')));
});
