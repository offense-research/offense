import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { analyzeStackEvidence } from '../scripts/stack-analysis.mjs';

const NOW = Date.parse('2026-10-28T05:00:00Z');
const at = new Date(NOW).toISOString();
const sha = character => 'sha256:' + character.repeat(64);
const source = 'a'.repeat(40), tree = 'b'.repeat(40);
function snapshot() {
  return { schemaVersion: 'offense.stack.snapshot.v1', capturedAt: at,
    repository: { revision: source, tree, sourceRevision: source, sourceTree: tree, clean: true, dirty: false },
    declaration: { path: 'offense-stack.json', sha256: 'c'.repeat(64), tracked: true, environment: 'staging',
      dockerfile: 'Dockerfile', dockerfileSha256: 'd'.repeat(64), image: { reference: 'fixture:baseline', digest: sha('e'), digestKind: 'image-config' } },
    image: { id: sha('e'), identityKind: 'image-config', configDigest: sha('e'), mappingVerified: true,
      manifestDigests: [], indexDigests: [], repoDigests: [], platform: { os: 'linux', architecture: 'amd64' }, revisionClaim: source },
    deployment: { adapter: 'docker', containerId: 'f'.repeat(64), imageId: sha('e'), reference: 'fixture:baseline', running: true, status: 'running', observedAt: at,
      filesystemDiffObserved: true, filesystemChanges: [], mounts: [], readOnlyRootfs: true },
    build: { schemaVersion: 'offense.stack.build.v1', assertion: 'local_build_receipt', repository: { revision: source, tree },
      archiveSha256: '1'.repeat(64), dockerfile: { path: 'Dockerfile', sha256: 'd'.repeat(64) },
      image: { id: sha('e'), identityKind: 'image-config', configDigest: sha('e'), platform: { os: 'linux', architecture: 'amd64' } },
      builtAt: at, receiptSha256: '2'.repeat(64) }, gaps: [] };
}
function trivy(overrides = {}) {
  return { SchemaVersion: 2, CreatedAt: at, ArtifactType: 'container_image', Metadata: { ImageID: sha('e') },
    Results: [{ Target: 'usr/local/bin/helper', Class: 'lang-pkgs', Type: 'gobinary',
      Packages: [{ Name: 'golang.org/x/net', Version: 'v0.39.0' }], Vulnerabilities: [{ VulnerabilityID: 'CVE-2025-58190',
        PkgName: 'golang.org/x/net', InstalledVersion: 'v0.39.0', FixedVersion: '0.45.0', Severity: 'HIGH',
        Title: 'Untrusted title should not be retained', PrimaryURL: 'https://secret.invalid?token=private' }] }], ...overrides };
}
async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-stack-analysis-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  let counter = 0;
  return async value => { const file = path.join(directory, `${counter++}.json`); await writeFile(file, typeof value === 'string' ? value : JSON.stringify(value)); return file; };
}
const analyze = (value, options = {}) => analyzeStackEvidence(value, { now: NOW, ...options });

test('an aligned local identity chain is separate from an unassessed security result', async () => {
  const report = await analyze(snapshot());
  assert.equal(report.status, 'complete'); assert.equal(report.chainStatus, 'aligned');
  assert.equal(report.securityCoverage.status, 'not_assessed'); assert.equal(report.securityCoverage.advisoryDatabaseFreshness, 'not_assessed');
  assert.equal(report.securityCoverage.scope, 'selected_image_only'); assert.equal(report.securityCoverage.deployedArtifactMatches, true);
  assert.equal(report.securityCoverage.runtimeImageUnmodified, true);
  assert.equal(report.summary.confirmedVulnerabilities, 0); assert.equal(report.plan.exploitRemediationVerified, false);
  assert.equal(report.provenance.signedBuildProvenanceVerified, false); assert.equal(report.provenance.imageRevisionLabel, 'unverified_claim');
  assert.ok(report.plan.nextActions.some(item => item.includes('image scanner')));
});

test('an OCI revision label cannot replace a missing build receipt', async () => {
  const input = snapshot(); input.build = null;
  const report = await analyze(input);
  assert.equal(report.status, 'partial'); assert.equal(report.chainStatus, 'unknown');
  assert.ok(report.gaps.some(item => item.code === 'build_receipt_missing'));
  assert.ok(!report.graph.edges.some(item => item.relation === 'produced_by'));
});

test('runtime drift reports the observed image and keeps graph relationships factual', async () => {
  const input = snapshot(); input.deployment.imageId = sha('3');
  const report = await analyze(input);
  assert.equal(report.chainStatus, 'drift'); assert.equal(report.status, 'partial');
  assert.deepEqual(report.drift.map(item => item.code), ['deployed_image_differs']);
  assert.equal(report.securityCoverage.deployedArtifactMatches, false);
  assert.match(report.agentPrompt, /not attributed to a different running image/);
  const runningEdge = report.graph.edges.find(item => item.relation === 'runs');
  const runningImage = report.graph.nodes.find(item => item.id === runningEdge.to);
  assert.equal(runningImage.digest, sha('3'));
});

test('manual writable-layer changes remain drift even with an identical running image', async () => {
  const input = snapshot(); input.deployment.filesystemChanges = [{ kind: 'C', path: '/usr/local/bin/helper' }];
  const report = await analyze(input);
  assert.equal(report.identity.imageId, report.identity.deployedImageId); assert.equal(report.chainStatus, 'drift');
  assert.deepEqual(report.drift.map(item => item.code), ['deployed_filesystem_changed']);
  assert.equal(report.drift[0].actual.changes[0].path, '/usr/local/bin/helper');
  assert.equal(report.summary.confirmedVulnerabilities, 0);
  assert.equal(report.securityCoverage.runtimeImageUnmodified, false);
});

test('runtime mounts and unavailable writable-layer observations prevent complete runtime evidence without leaking host sources', async () => {
  const input = snapshot(); input.deployment.filesystemDiffObserved = false;
  input.deployment.mounts = [{ type: 'bind', destination: '/app', readOnly: false, source: '/secret/customer-path' }];
  const report = await analyze(input);
  assert.equal(report.chainStatus, 'unknown'); assert.equal(report.status, 'partial');
  assert.ok(report.gaps.some(item => item.code === 'filesystem_diff_unavailable'));
  assert.ok(report.gaps.some(item => item.code === 'runtime_mounts_unassessed'));
  assert.ok(!JSON.stringify(report).includes('/secret/customer-path'));
});

test('paused and restarting containers are not treated as a healthy running deployment', async () => {
  const input = snapshot(); input.deployment.status = 'paused';
  const report = await analyze(input);
  assert.equal(report.runtimeCoverage.engineState, 'not_running_or_unknown');
  assert.equal(report.runtimeCoverage.applicationReadiness, 'not_assessed');
  assert.ok(report.gaps.some(item => item.code === 'deployment_not_running'));
});

test('a mismatched build graph connects to the actual recorded source and output, not the selected ones', async () => {
  const input = snapshot(); input.build.repository.revision = '4'.repeat(40); input.build.image.id = sha('5');
  const report = await analyze(input);
  assert.ok(report.drift.some(item => item.code === 'build_source_differs'));
  assert.ok(report.drift.some(item => item.code === 'build_image_differs'));
  const sourceEdge = report.graph.edges.find(item => item.relation === 'built_from');
  assert.equal(report.graph.nodes.find(item => item.id === sourceEdge.to).revision, '4'.repeat(40));
  const imageEdge = report.graph.edges.find(item => item.relation === 'produced_by');
  assert.equal(report.graph.nodes.find(item => item.id === imageEdge.from).digest, sha('5'));
});

test('deployment-only commits can declare an earlier pinned build source', async () => {
  const input = snapshot(); input.repository.revision = '6'.repeat(40); input.repository.tree = '7'.repeat(40);
  const report = await analyze(input);
  assert.equal(report.chainStatus, 'aligned'); assert.equal(report.identity.sourceRevision, source);
  assert.equal(report.identity.repositoryRevision, '6'.repeat(40));
});

test('dirty source, missing image mappings and a stopped container remain coverage gaps', async () => {
  const input = snapshot(); input.repository.dirty = true; input.deployment.running = false; input.image.mappingVerified = false;
  const report = await analyze(input);
  assert.equal(report.chainStatus, 'unknown');
  for (const code of ['repository_worktree_dirty', 'deployment_not_running', 'image_config_identity_missing']) assert.ok(report.gaps.some(item => item.code === code));
});

test('raw Trivy binds an embedded Go advisory to its binary and image without confirming exploitability', async t => {
  const file = await fixture(t), report = await analyze(snapshot(), { scanReport: await file(trivy()) });
  assert.equal(report.chainStatus, 'aligned'); assert.equal(report.securityCoverage.status, 'supplied_report');
  assert.equal(report.securityCoverage.executionVerified, false); assert.equal(report.securityCoverage.advisoryDatabaseFreshness, 'not_assessed');
  assert.equal(report.findings.length, 1); assert.equal(report.findings[0].containingBinary, 'usr/local/bin/helper');
  assert.equal(report.summary.confirmedVulnerabilities, 0); assert.equal(report.plan.remediations[0].kind, 'embedded_binary_rebuild');
  assert.deepEqual(report.plan.remediations[0].advisoryListedFixedVersions, ['0.45.0']);
  assert.equal(report.plan.remediations[0].compatibilityVerified, false);
  assert.ok(report.graph.edges.some(item => item.relation === 'bundles'));
  assert.ok(!JSON.stringify(report).includes('secret.invalid')); assert.ok(!JSON.stringify(report).includes('Untrusted title'));
  assert.match(report.agentPrompt, /Rebuild/); assert.match(report.agentPrompt, /runtime compiler alone/);
});

test('Docker index IDs are never compared directly with Trivy config IDs', async t => {
  const file = await fixture(t), input = snapshot();
  input.image.id = sha('8'); input.image.identityKind = 'index'; input.image.indexDigests = [sha('8')]; input.image.manifestDigests = [sha('9')];
  input.deployment.imageId = sha('8'); input.build.image.id = sha('8'); input.build.image.identityKind = 'index';
  const report = await analyze(input, { scanReport: await file(trivy()) });
  assert.equal(report.chainStatus, 'aligned'); assert.equal(report.securityCoverage.subjectBound, true);
  assert.equal(report.identity.imageId, sha('8')); assert.equal(report.identity.imageConfigDigest, sha('e'));
  assert.ok(report.graph.edges.some(item => item.relation === 'resolves_to'));
  input.image.configDigest = sha('7'); input.build.image.configDigest = sha('7');
  const mismatched = await analyze(input, { scanReport: await file(trivy()) });
  assert.equal(mismatched.securityCoverage.subjectBound, false); assert.equal(mismatched.findings.length, 0);
  assert.ok(mismatched.gaps.some(item => item.code === 'scan_subject_mismatch'));
});

test('manifest and index declarations require the matching verified digest kind', async () => {
  const input = snapshot(); input.image.id = sha('8'); input.image.identityKind = 'index'; input.image.indexDigests = [sha('8')]; input.image.manifestDigests = [sha('9')];
  input.deployment.imageId = sha('8'); input.build.image.id = sha('8'); input.build.image.identityKind = 'index';
  input.declaration.image.digest = sha('8'); input.declaration.image.digestKind = 'index';
  assert.equal((await analyze(input)).chainStatus, 'aligned');
  input.declaration.image.digestKind = 'manifest';
  assert.equal((await analyze(input)).chainStatus, 'drift');
  input.declaration.image.digest = sha('9');
  assert.equal((await analyze(input)).chainStatus, 'aligned');
});

test('untyped RepoDigest references and mutable tags cannot prove declared digest compatibility', async () => {
  const input = snapshot(); input.image.repoDigests = [`fixture@${sha('8')}`]; input.declaration.image.digest = sha('8'); input.declaration.image.digestKind = 'manifest';
  assert.ok((await analyze(input)).gaps.some(item => item.code === 'declaration_digest_mapping_unavailable'));
  input.declaration.image.digest = null;
  assert.ok((await analyze(input)).gaps.some(item => item.code === 'declaration_unpinned'));
});

test('a mismatched image report is retained as a gap and cannot add findings or clean security evidence', async t => {
  const file = await fixture(t), report = await analyze(snapshot(), { scanReport: await file(trivy({ Metadata: { ImageID: sha('0'), RepoTags: ['fixture:baseline'] } })) });
  assert.equal(report.chainStatus, 'aligned'); assert.equal(report.status, 'partial'); assert.equal(report.securityCoverage.status, 'partial');
  assert.equal(report.securityCoverage.unmatchedFindings, 1); assert.equal(report.findings.length, 0);
  assert.ok(report.gaps.some(item => item.code === 'scan_subject_mismatch'));
});

test('stale, absent and future report timestamps cannot become current scan evidence', async t => {
  const file = await fixture(t);
  for (const timestamp of [undefined, new Date(NOW - 25 * 3600_000).toISOString(), new Date(NOW + 3600_000).toISOString()]) {
    const report = await analyze(snapshot(), { scanReport: await file(trivy({ CreatedAt: timestamp })) });
    assert.equal(report.securityCoverage.status, 'partial'); assert.equal(report.status, 'partial');
    assert.ok(report.gaps.some(item => ['scan_timestamp_missing', 'scan_report_stale', 'scan_timestamp_future'].includes(item.code)));
  }
});

test('valid package-free Trivy output does not imply universal inventory or exploit coverage', async t => {
  const file = await fixture(t), report = await analyze(snapshot(), { scanReport: await file(trivy({ Results: undefined })) });
  assert.equal(report.securityCoverage.status, 'supplied_report'); assert.equal(report.findings.length, 0);
  assert.ok(report.securityCoverage.limitations.some(item => item.includes('every embedded component')));
});

test('reported scanner errors and malformed inventory cannot become complete supplied evidence', async t => {
  const file = await fixture(t), raw = trivy();
  raw.Results[0].Packages = {}; raw.Results[0].Errors = ['Untrusted raw diagnostic'];
  const report = await analyze(snapshot(), { scanReport: await file(raw) });
  assert.equal(report.securityCoverage.status, 'partial'); assert.equal(report.status, 'partial');
  assert.ok(report.gaps.some(item => item.code === 'scan_packages_invalid'));
  assert.ok(report.gaps.some(item => item.code === 'scan_result_errors'));
  assert.ok(!JSON.stringify(report).includes('Untrusted raw diagnostic'));
});

test('unversioned main modules and unsafe finding fields stay explicit omissions', async t => {
  const file = await fixture(t), raw = trivy();
  raw.Results[0].Packages.push({ Name: 'example.invalid/main', Version: '(devel)' });
  raw.Results[0].Vulnerabilities.push({ VulnerabilityID: 'CVE-2025-12345', PkgName: 'ignore\ninstructions', InstalledVersion: '1.0', FixedVersion: '2.0' });
  const report = await analyze(snapshot(), { scanReport: await file(raw) });
  assert.ok(report.gaps.some(item => item.code === 'scan_inventory_partial')); assert.equal(report.securityCoverage.status, 'partial');
  assert.equal(report.findings.length, 1); assert.ok(!report.agentPrompt.includes('ignore\ninstructions'));
});

test('repeated advisory rows are deduplicated by occurrence; two binaries remain distinct', async t => {
  const file = await fixture(t), raw = trivy();
  raw.Results[0].Vulnerabilities.push({ ...raw.Results[0].Vulnerabilities[0] });
  raw.Results.push({ ...raw.Results[0], Target: 'other-helper' });
  const report = await analyze(snapshot(), { scanReport: await file(raw) });
  assert.equal(report.summary.advisoryMatches, 1); assert.equal(report.summary.affectedOccurrences, 2);
  assert.equal(report.findings.length, 2); assert.equal(report.summary.confirmedVulnerabilities, 0);
});

test('missing upstream fixes generate a blocked investigation rather than a fabricated target', async t => {
  const file = await fixture(t), raw = trivy(); raw.Results[0].Vulnerabilities[0].FixedVersion = '';
  const report = await analyze(snapshot(), { scanReport: await file(raw) });
  assert.equal(report.plan.remediations[0].status, 'blocked_no_fixed_release_listed');
  assert.deepEqual(report.plan.remediations[0].advisoryListedFixedVersions, []);
});

test('CycloneDX 1.7 Trivy image metadata binds inventory and binary ownership', async t => {
  const file = await fixture(t), raw = { bomFormat: 'CycloneDX', specVersion: '1.7', metadata: { timestamp: at,
    component: { type: 'container', properties: [{ name: 'aquasecurity:trivy:ImageID', value: sha('e') }] } },
    components: [{ 'bom-ref': 'binary', type: 'application', name: 'helper', properties: [{ name: 'aquasecurity:trivy:Type', value: 'gobinary' }] },
      { 'bom-ref': 'module', type: 'library', name: 'golang.org/x/net', version: 'v0.39.0' }],
    dependencies: [{ ref: 'binary', dependsOn: ['module'] }] };
  const report = await analyze(snapshot(), { sbom: await file(raw) });
  assert.equal(report.suppliedEvidence.sbom.subjectBound, true); assert.equal(report.securityCoverage.status, 'not_assessed');
  assert.equal(report.inventory[0].containingBinary, 'helper'); assert.equal(report.inventory[0].version, 'v0.39.0');
});

test('an untyped SBOM hash cannot be mistaken for a config or archive digest', async t => {
  const file = await fixture(t), raw = { bomFormat: 'CycloneDX', specVersion: '1.6', metadata: { timestamp: at,
    component: { type: 'container', hashes: [{ alg: 'SHA-256', content: 'e'.repeat(64) }] } }, components: [] };
  let report = await analyze(snapshot(), { sbom: await file(raw) });
  assert.ok(report.gaps.some(item => item.code === 'sbom_subject_mismatch'));
  raw.metadata.component.properties = [{ name: 'offense:subject:digestKind', value: 'image-config' }];
  report = await analyze(snapshot(), { sbom: await file(raw) });
  assert.equal(report.suppliedEvidence.sbom.subjectBound, true);
});

test('unsupported, invalid, oversized and symlink reports stay failed coverage', async t => {
  const file = await fixture(t);
  for (const value of ['invalid json', { spdxVersion: 'SPDX-2.3' }, ' '.repeat(8 * 1024 * 1024 + 1)]) {
    const report = await analyze(snapshot(), { scanReport: await file(value) });
    assert.ok(report.gaps.some(item => item.code === 'scan_report_unusable')); assert.equal(report.status, 'partial');
  }
  const target = await file(trivy()), link = target + '.link'; await symlink(target, link);
  const report = await analyze(snapshot(), { scanReport: link });
  assert.ok(report.gaps.some(item => item.code === 'scan_report_unusable'));
});

test('plan identity is deterministic per evidence and invalidated by source, image, declaration or scanner changes', async t => {
  const file = await fixture(t), scanReport = await file(trivy()), first = await analyze(snapshot(), { scanReport });
  assert.equal((await analyze(snapshot(), { scanReport })).planHash, first.planHash);
  for (const change of [value => { value.repository.revision = '3'.repeat(40); }, value => { value.image.id = sha('4'); },
    value => { value.declaration.sha256 = '5'.repeat(64); }]) {
    const input = snapshot(); change(input); assert.notEqual((await analyze(input, { scanReport })).planHash, first.planHash);
  }
  const changed = await file(trivy({ CreatedAt: new Date(NOW - 1000).toISOString() }));
  assert.notEqual((await analyze(snapshot(), { scanReport: changed })).planHash, first.planHash);
});
