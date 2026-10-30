import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyMapper, mapDependencies } from '../server/dependency-mapper.js';
import { assessManifestDeclarations, dependencyCoverage } from '../server/manifest-dependencies.js';
import { checkVulnerabilities } from '../server/osv.js';

const manifest = (dependencies, extra = {}) => [{ path: 'package.json', content: JSON.stringify({ name: 'fixture', dependencies, ...extra }) }];
function registryAndOsv({ vulnerable = true, unpublished = [] } = {}) {
  const queries = [], registry = [];
  const fetchImpl = async (url, options) => {
    if (url.startsWith('https://registry.npmjs.org/')) {
      registry.push(url);
      const [, , , encodedName, version] = url.split('/'), name = decodeURIComponent(encodedName);
      return { ok: !unpublished.includes(name), status: unpublished.includes(name) ? 404 : 200,
        text: async () => JSON.stringify({ name, version }) };
    }
    if (url.endsWith('/querybatch')) {
      const batch = JSON.parse(options.body).queries; queries.push(...batch);
      return { ok: true, json: async () => ({ results: batch.map(item => ({ vulns: vulnerable && item.package.name === 'lodash' ? [{ id: 'GHSA-manifest-fixture' }] : [] })) }) };
    }
    return { ok: true, json: async () => ({ summary: 'Synthetic representative-version advisory', database_specific: { severity: 'HIGH' },
      affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }) };
  };
  return { fetchImpl, queries, registry };
}

test('manifest-only scans assess published range representatives and exact declarations without claiming installed versions', async () => {
  const db = new DatabaseSync(':memory:'), fake = registryAndOsv({ unpublished: ['unpublished'] });
  const files = manifest({ lodash: '^4.17.20', exact: '1.2.3', tagged: 'latest', local: 'workspace:*', unpublished: '^9.0.0' }, { packageManager: 'npm@10.0.0' });
  try {
    const mapper = createDependencyMapper(db, { dependencyFiles: async () => ({ revision: 'fixture-revision', files, warnings: [] }) },
      packages => checkVulnerabilities(packages, fake.fetchImpl), undefined, { fetchImpl: fake.fetchImpl });
    const result = await mapper.scan('workspace', 'owner/repo', 1);
    assert.equal(result.coverage.status, 'manifest_only'); assert.equal(result.coverage.complete, false);
    assert.equal(result.coverage.missingLockfiles[0].packageManager, 'npm');
    assert.equal(result.coverage.missingLockfiles[0].commands[0].command, 'npm install --package-lock-only --ignore-scripts --no-audit --no-fund');
    assert.equal(result.coverage.omissions.length, 3);
    assert.match(result.coverage.notice, /do not identify installed versions/);
    assert.equal(result.vulnerabilityCheck.status, 'complete'); assert.equal(result.vulnerabilityCheck.scope, 'declared_versions');
    assert.equal(result.vulnerabilityCheck.declaredAssessment.checkedRepresentatives, 2);
    assert.deepEqual(fake.queries.map(item => [item.package.name, item.version]).sort(), [['exact', '1.2.3'], ['lodash', '4.17.20']]);
    const finding = result.vulnerabilityCheck.findings[0];
    assert.equal(finding.version, '4.17.20'); assert.equal(finding.declaredRange, '^4.17.20');
    assert.equal(finding.assessmentKind, 'declared_range'); assert.equal(finding.versionEvidence, 'declared_range'); assert.equal(finding.resolved, false);
    assert.deepEqual(finding.files, ['package.json']);
    assert.deepEqual(result.packages.find(item => item.name === 'lodash'), { name: 'lodash', version: '^4.17.20', kind: 'runtime', resolved: false, files: ['package.json'] });
    assert.deepEqual(mapper.snapshots('workspace')[0].coverage, result.coverage);
    await assert.rejects(mapper.upgradePlan('workspace', 'owner/repo', 1, 'lodash', '4.17.20'), error => error.code === 'lockfile_required' && error.status === 400 && /lockfile/.test(error.message));
    const refreshed = await mapper.recheck('workspace', 'owner/repo', 1);
    assert.equal(refreshed.coverage.complete, false); assert.equal(refreshed.vulnerabilityCheck.findings[0].resolved, false);
  } finally { db.close(); }
});

test('a clean representative check remains incomplete for the declaration and its transitive dependencies', async () => {
  const db = new DatabaseSync(':memory:'), fake = registryAndOsv({ vulnerable: false });
  try {
    const mapper = createDependencyMapper(db, { dependencyFiles: async () => ({ revision: 'fixture', files: manifest({ lodash: '^4.17.21' }), warnings: [] }) },
      packages => checkVulnerabilities(packages, fake.fetchImpl), undefined, { fetchImpl: fake.fetchImpl });
    const result = await mapper.scan('w', 'owner/repo', 1);
    assert.equal(result.vulnerabilityCheck.status, 'complete'); assert.deepEqual(result.vulnerabilityCheck.findings, []);
    assert.equal(result.coverage.complete, false); assert.match(result.coverage.notice, /not evidence that its range/);
    assert.equal(result.graph.nodes.length, 0); assert.ok(result.warnings.some(warning => /no covering/.test(warning)));
  } finally { db.close(); }
});

test('workspace lock importers cover their manifests while independent nested projects remain explicit omissions', () => {
  const files = [{ path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'packages/client': { version: '1.0.0' }, 'node_modules/locked': { version: '1.0.0' } } }) },
    { path: 'packages/client/package.json', content: JSON.stringify({ dependencies: { locked: '^1.0.0' } }) },
    { path: 'tools/other/package.json', content: JSON.stringify({ dependencies: { loose: '^2.0.0' }, packageManager: 'pnpm@10.0.0' }) }];
  const coverage = dependencyCoverage(files, { nodes: [{ path: '', file: 'package-lock.json' }], warnings: [] }, mapDependencies(files).packages);
  assert.equal(coverage.status, 'partial'); assert.deepEqual(coverage.missingLockfiles.map(item => item.manifest), ['tools/other/package.json']);
  assert.equal(coverage.missingLockfiles[0].commands[0].directory, 'tools/other'); assert.match(coverage.missingLockfiles[0].commands[0].command, /^pnpm /);
  const pnpm = dependencyCoverage([{ path: 'packages/client/package.json', content: '{}' }], { nodes: [{ path: '', file: 'pnpm-lock.yaml', workspace: 'packages/client' }], warnings: [] }, []);
  assert.equal(pnpm.missingLockfiles.length, 0);
});

test('unpublished minima, unsupported declarations, and registry outages are coverage omissions without fabricated OSV queries', async () => {
  const files = manifest({ missing: '^1.0.0', git: 'git+https://example.com/package.git', prerelease: '1.0.0-beta.1' }, { packageManager: 'yarn@4.0.0' });
  const packages = mapDependencies(files).packages, coverage = dependencyCoverage(files, { nodes: [], warnings: [] }, packages);
  assert.equal(coverage.missingLockfiles[0].commands.length, 0); assert.match(coverage.missingLockfiles[0].message, /Keep using yarn/);
  const result = await assessManifestDeclarations(packages, coverage, { fetchImpl: async () => { throw new Error('registry unavailable'); } });
  assert.deepEqual(result.packages, []); assert.equal(result.omissions.length, 3); assert.ok(result.omissions.some(item => /registry unavailable/.test(item.reason)));
  const empty = dependencyCoverage([], { nodes: [], warnings: [] }, []);
  assert.equal(empty.status, 'empty'); assert.equal(empty.complete, false); assert.match(empty.notice, /No supported/);
});
