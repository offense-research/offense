import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { normalizePnpm, pnpmGraph } from '../public/skills/purple/scripts/pnpm.mjs';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { collectMetadata } from '../public/skills/purple/scripts/purple.mjs';
import { coordinatedChanges, rehearse } from '../public/skills/purple/scripts/workflow.mjs';
import { mapDependencies } from '../server/dependency-mapper.js';
import { buildDependencyGraph, dependencyImpact } from '../server/dependency-graph.js';
import { planUpgrade } from '../server/upgrade-planner.js';

const source = `lockfileVersion: '9.0'
catalogs:
  default:
    semver: {specifier: '~7.5.1', version: 7.5.1}
importers:
  .:
    dependencies:
      app: {specifier: 'workspace:*', version: 'link:packages/app'}
  packages/app:
    dependencies:
      parent: {specifier: '^1.0.0', version: 1.0.0}
      semver: {specifier: 'catalog:', version: 7.5.1}
    devDependencies:
      alias: {specifier: 'npm:real@^2.0.0', version: 2.0.0}
packages:
  parent@1.0.0:
    resolution: {integrity: DO-NOT-SEND, tarball: 'https://user:SECRET@private.example/parent.tgz'}
  semver@7.5.1: {}
  real@2.0.0: {}
  plugin@1.0.0:
    peerDependencies: {real: '^2.0.0'}
snapshots:
  parent@1.0.0:
    dependencies: {semver: 7.5.1}
  semver@7.5.1: {}
  real@2.0.0: {}
  plugin@1.0.0(real@2.0.0):
    dependencies: {real: 2.0.0}
  plugin@1.0.0(real@2.1.0):
    dependencies: {real: 2.0.0}
`;
const file = { path: 'pnpm-lock.yaml', content: source };

test('pnpm v9 normalization preserves workspaces, aliases, catalogs and peer identities without registry secrets', () => {
  const clean = sanitizeLockfiles([file]);
  const wire = JSON.stringify(clean.files);
  for (const secret of ['SECRET', 'private.example', 'DO-NOT-SEND', 'tarball', 'integrity']) assert.ok(!wire.includes(secret));
  assert.deepEqual(sanitizeLockfiles(clean.files), clean);
  const graph = pnpmGraph(clean.files[0]);
  assert.deepEqual(graph.warnings, []);
  assert.equal(graph.nodes.filter(node => node.name === 'plugin').length, 2);
  const app = graph.nodes.find(node => node.workspace === 'packages/app');
  assert.equal(app.requires.find(edge => edge.name === 'semver').range, '~7.5.1');
  const alias = app.requires.find(edge => edge.name === 'alias');
  assert.equal(graph.nodes.find(node => node.id === alias.to).name, 'real');
  assert.equal(graph.packages.find(item => item.name === 'real').kind, 'development');
  const mapped = mapDependencies(clean.files);
  assert.equal(mapped.packages.filter(item => item.name === 'plugin').length, 1);
  assert.equal(mapped.packages.find(item => item.name === 'semver').version, '7.5.1');
  const impact = dependencyImpact(buildDependencyGraph(clean.files), 'semver', '7.5.1', '7.5.2');
  assert.ok(impact.paths.some(parts => parts.join('/').includes('application/workspace:packages/app/parent/semver')));
  assert.equal(impact.parents.find(parent => parent.name === 'parent').compatible, null);
});

test('pnpm v6 package snapshots survive repeated normalization and unsupported versions never look clean', () => {
  const legacy = { path: 'pnpm-lock.yaml', content: `lockfileVersion: '6.0'
dependencies:
  parent: {specifier: '^1.0.0', version: 1.0.0}
packages:
  /parent@1.0.0:
    dependencies: {semver: 7.5.1}
  /semver@7.5.1: {}
` };
  const first = sanitizeLockfiles([legacy]);
  assert.deepEqual(sanitizeLockfiles(first.files), first);
  const impact = dependencyImpact(buildDependencyGraph(first.files), 'semver', '7.5.1', '7.5.2');
  assert.deepEqual(impact.paths, [['application', 'parent', 'semver']]);
  assert.throws(() => normalizePnpm({ ...file, content: "lockfileVersion: '5.4'\npackages: {}" }), /versions are 6 and 9/);
  assert.throws(() => normalizePnpm({ ...file, content: "lockfileVersion: '9.0'\npackages: {}" }), /snapshots are missing/);
  assert.throws(() => normalizePnpm({ ...file, content: "lockfileVersion: '9.0'\nlockfileVersion: '6.0'" }), /Invalid YAML/);
  assert.throws(() => normalizePnpm({ ...file, content: "lockfileVersion: '9.0'\npackages: &p {}\nsnapshots: *p" }), /alias/i);
});

test('pnpm planning reads declared parent constraints from published metadata instead of treating pinned refs as ranges', async () => {
  const findings = [{ package: 'semver', version: '7.5.1', fixedVersions: ['7.5.2'] }];
  const snapshot = { graph: buildDependencyGraph([file]), vulnerabilityCheck: { status: 'complete', findings } };
  const fetchImpl = async url => {
    const name = decodeURIComponent(new URL(url).pathname.slice(1));
    if (name === 'semver') return Response.json({ versions: { '7.5.1': {}, '7.5.2': {} } });
    assert.equal(name, 'parent');
    return Response.json({ versions: { '1.0.0': { dependencies: { semver: '7.5.1' } }, '1.1.0': { dependencies: { semver: '^7.5.2' } } } });
  };
  const plan = await planUpgrade(snapshot, 'semver', '7.5.1', { fetchImpl, check: async () => ({ status: 'complete', findings: [] }) });
  const parent = plan.impact.parents.find(parent => parent.name === 'parent');
  assert.equal(parent.range, '7.5.1'); assert.equal(parent.rangeSource, 'npm_registry'); assert.equal(parent.compatible, false);
  assert.equal(plan.parentOptions.find(option => option.parent === 'parent').version, '1.1.0');
  assert.deepEqual(plan.constraintWarnings, []);
});

test('workspace manifests are covered by their pnpm importer and fingerprints detect manifest or lockfile changes', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-pnpm-')); t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'packages/app'), { recursive: true });
  await writeFile(path.join(root, 'package.json'), '{}');
  await writeFile(path.join(root, 'packages/app/package.json'), '{}');
  await writeFile(path.join(root, 'pnpm-lock.yaml'), source);
  const first = await collectMetadata(root);
  assert.deepEqual(first.warnings, []);
  await writeFile(path.join(root, 'packages/app/package.json'), '{"dependencies":{"semver":"7.5.2"}}');
  assert.notEqual((await collectMetadata(root)).fingerprint, first.fingerprint);
  const report = path.join(root, 'old-scan.json');
  await writeFile(report, JSON.stringify({ metadataFingerprint: first.fingerprint, vulnerabilityCheck: { status: 'complete', findings: [] } }));
  await assert.rejects(rehearse(root, { scanFile: report, sandboxed: true }), /Dependency files changed/);
});

test('coordinated rehearsal includes checked parent upgrades and blocks conflicting targets or stale evidence', async () => {
  const plan = { name: 'semver', currentVersion: '7.5.1', targetVersion: '7.5.2', considered: [{ version: '7.5.2', advisories: 0 }],
    parentOptions: [{ parent: 'parent', currentVersion: '1.0.0', version: '1.1.0' }] };
  const changes = coordinatedChanges({ plans: [plan] });
  assert.deepEqual(changes.map(change => change.name), ['semver', 'parent']);
  assert.equal(coordinatedChanges({ plans: [plan, { ...plan, currentVersion: '6.3.0', targetVersion: '6.3.1', considered: [{ version: '6.3.1', advisories: 0 }] }] }).filter(item => item.name === 'semver').length, 2);
  assert.throws(() => coordinatedChanges({ plans: [plan, { ...plan, targetVersion: '8.0.0', considered: [{ version: '8.0.0', advisories: 0 }] }] }), /Conflicting/);
  assert.throws(() => coordinatedChanges({ plans: [{ ...plan, considered: [] }] }), /checked target/);
  await assert.rejects(rehearse('.', {}), /isolated test environment/);
});
