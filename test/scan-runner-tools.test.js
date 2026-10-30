import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { runScan } from '../agent/scan-runner.mjs';
import { scanController } from '../workers/scan-container.js';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-runner-tools-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const databaseMetadataPath = path.join(root, 'metadata.json');
  await writeFile(databaseMetadataPath, JSON.stringify({ UpdatedAt: new Date().toISOString() }));
  return { root, databaseMetadataPath };
}

test('selected IaC scan normalizes Trivy misconfigurations without carrying source snippets', async t => {
  const options = await fixture(t);
  let calls = 0;
  const execute = (binary, args) => {
    calls++;
    assert.equal(binary, 'trivy');
    assert.equal(args[0], 'config');
    assert.ok(args.includes('--skip-check-update'));
    const output = args[args.indexOf('--output') + 1];
    writeFileSync(output, JSON.stringify({ SchemaVersion: 2, Results: [{ Target: path.join(options.root, 'source', 'Dockerfile'), Misconfigurations: [{
      ID: 'DS001', Title: 'Container runs as root', Severity: 'HIGH', Status: 'FAIL', Resolution: 'Set a non-root USER.',
      CauseMetadata: { StartLine: 1, Code: { Lines: [{ Content: 'synthetic-secret-value' }] } }
    }, { ID: 'DS002', Title: 'Passed check', Status: 'PASS', Severity: 'LOW' }] }] }));
    return { status: 0 };
  };
  const report = await runScan({ tools: ['trivy-config'], files: [{ path: 'Dockerfile', content: 'FROM alpine:3.21\n' }] }, { ...options, execute });
  assert.equal(calls, 1);
  assert.equal(report.status, 'completed');
  assert.deepEqual(report.tools.map(tool => tool.name), ['trivy-config']);
  assert.equal(report.findings[0].file, 'Dockerfile');
  assert.equal(report.findings[0].line, 1);
  assert.equal(report.findings.length, 1);
  assert.ok(!JSON.stringify(report).includes('synthetic-secret-value'));
});

test('SBOM scan is isolated to one JSON document and findings point to that upload', async t => {
  const options = await fixture(t);
  const execute = (binary, args) => {
    assert.equal(binary, 'trivy');
    assert.equal(args[0], 'sbom');
    writeFileSync(args[args.indexOf('--output') + 1], JSON.stringify({ SchemaVersion: 2, Results: [{ Target: 'alpine:3.21', Vulnerabilities: [{
      VulnerabilityID: 'CVE-TEST-1', PkgName: 'libdemo', InstalledVersion: '1.0', FixedVersion: '1.1', Severity: 'HIGH'
    }] }] }));
    return { status: 0 };
  };
  const sbom = { bomFormat: 'CycloneDX', specVersion: '1.6', version: 1, components: [] };
  const input = { tools: ['trivy-sbom'], files: [{ path: 'image.cdx.json', content: JSON.stringify(sbom) }] };
  const report = await runScan(input, { ...options, execute });
  assert.equal(report.status, 'completed');
  assert.equal(report.findings[0].file, 'image.cdx.json');
  assert.equal(report.findings[0].tool, 'trivy-sbom');
  await assert.rejects(runScan({ ...input, tools: ['trivy-sbom', 'gitleaks'] }, { ...options, execute }), /own job/);
  await assert.rejects(runScan({ ...input, files: [{ path: 'not-sbom.json', content: '{}' }] }, { ...options, execute }), /CycloneDX or SPDX/);
});

test('container forwards the selected tool without enabling network access', async () => {
  let forwarded;
  const ctx = { storage: { kv: { get: () => null, put() {} }, async setAlarm() {} },
    container: { images: { scan: 'scanner-image' }, start(options) { assert.equal(options.enableInternet, false); },
      async setInactivityTimeout() {}, async exec(_argv, options) { forwarded = JSON.parse(await new Response(options.stdin).text()); } } };
  await scanController(ctx).start({ tools: ['trivy-config'], files: [{ path: 'Dockerfile', content: 'FROM alpine' }] });
  assert.deepEqual(forwarded.tools, ['trivy-config']);
  assert.equal(forwarded.files[0].path, 'Dockerfile');
  await scanController(ctx).start({ tools: ['k8s-deprecations', 'k8s-manifest-validate'], kubernetesVersion: '1.33.0',
    files: [{ path: 'pod.yaml', content: 'apiVersion: v1\nkind: Pod\n' }] });
  assert.equal(forwarded.kubernetesVersion, '1.33.0');
  assert.deepEqual(forwarded.tools, ['k8s-deprecations', 'k8s-manifest-validate']);
});

test('workflow scans preserve fixed findings and bounded offline execution through the shared runner', async t => {
  const options = await fixture(t); let calls = 0;
  const execute = (binary, args, processOptions) => {
    calls++; assert.equal(binary, '/usr/local/bin/zizmor');
    for (const flag of ['--offline', '--no-config', '--no-ignores', '--strict-collection']) assert.ok(args.includes(flag));
    assert.ok(processOptions.timeout <= 120000); assert.equal(processOptions.env.GITHUB_TOKEN, undefined);
    return { status: 0, stdout: JSON.stringify([{ ident: 'template-injection', determinations: { severity: 'High', confidence: 'High' },
      desc: 'PRIVATE_SOURCE_CANARY', locations: [{ symbolic: { kind: 'Primary', key: { Local: { verbatim_path: args.at(-1) } } },
        concrete: { location: { start_point: { row: 6 } }, feature: 'PRIVATE_SOURCE_CANARY' } }] }]) };
  };
  const report = await runScan({ tools: ['zizmor'], files: [{ path: '.github/workflows/ci.yml', content: 'name: synthetic\non: push\njobs: {}\n' }] }, { ...options, execute });
  assert.equal(calls, 1); assert.equal(report.status, 'completed');
  assert.equal(report.findings[0].file, '.github/workflows/ci.yml'); assert.equal(report.findings[0].line, 7);
  assert.equal(report.findings[0].verification, 'scanner_finding');
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
});

test('unsupported workflow input remains partial and does not invoke a scanner', async t => {
  const options = await fixture(t);
  const report = await runScan({ tools: ['zizmor'], files: [{ path: 'README.md', content: 'No workflows in this upload' }] },
    { ...options, execute() { assert.fail('No supported input should execute'); } });
  assert.equal(report.status, 'partial'); assert.equal(report.tools[0].status, 'partial');
  assert.equal(report.findings.length, 0);
});

test('Kubernetes scans preserve target, document locations and distinct findings without raw source', async t => {
  const options = await fixture(t);
  const manifest = 'apiVersion: extensions/v1beta1\nkind: Deployment\nmetadata: {name: PRIVATE_SOURCE_CANARY}\n';
  const execute = (binary, args, processOptions) => {
    if (binary.endsWith('/pluto')) return { status: 3, stdout: JSON.stringify({
      'target-versions': { k8s: 'v1.34.0' }, items: [0, 1].map(index => ({
        filePath: path.join(processOptions.cwd, 'manifests', `${index}.json`), name: 'PRIVATE_SOURCE_CANARY',
        api: { version: 'extensions/v1beta1', kind: 'Deployment', 'replacement-api': 'apps/v1' },
        deprecated: true, removed: true, replacementAvailable: true
      })) }) };
    return { status: 1, stdout: JSON.stringify({ resources: [0, 1].map(index => ({
      filename: `manifests/${index}.json`, status: index === 0 ? 'statusInvalid' : 'statusValid', msg: 'PRIVATE_SOURCE_CANARY'
    })), summary: { valid: 1, invalid: 1, errors: 0, skipped: 0 } }) };
  };
  const input = { tools: ['k8s-deprecations', 'k8s-manifest-validate'], kubernetesVersion: '1.34.0',
    files: [{ path: 'rendered.yaml', content: manifest + '---\n' + manifest }] };
  const report = await runScan(input, { ...options, execute });
  assert.equal(report.status, 'completed');
  assert.deepEqual(report.findings.map(item => [item.tool, item.file, item.document, item.line]), [
    ['k8s-deprecations', 'rendered.yaml', 1, 1], ['k8s-deprecations', 'rendered.yaml', 2, 4],
    ['k8s-manifest-validate', 'rendered.yaml', 1, 1]
  ]);
  assert.equal(new Set(report.findings.map(item => item.id)).size, 3);
  assert.ok(report.findings.every(item => item.kubernetesVersion === '1.34.0'));
  assert.match(report.findings[0].remediation, /apps\/v1/);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
  assert.deepEqual(report.tools.map(item => item.coverage.resources), [2, 2]);
  await assert.rejects(runScan({ ...input, kubernetesVersion: undefined }, options), /kubernetesVersion/);
});

test('Kubernetes parsing gaps and unknown schemas cannot become clean results', async t => {
  const options = await fixture(t);
  for (const tool of ['k8s-deprecations', 'k8s-manifest-validate']) {
    for (const content of ['', 'ordinary: config', 'apiVersion: v1\nkind: Pod\nkind: Secret', 'apiVersion: v1\nkind: [',
      'apiVersion: v1\nkind: ../../Secret', 'apiVersion: v1\nkind: Pod\nmetadata: &x {name: x}\nspec: *x',
      'apiVersion: v1\nkind: ConfigMap\ndata: {value: .inf}', 'apiVersion: v1\nkind: ConfigMap\ndata: {value: .nan}']) {
      const report = await runScan({ tools: [tool], kubernetesVersion: '1.35.0', files: [{ path: 'bad.yaml', content }] },
        { ...options, execute() { assert.fail('Invalid manifests must not reach a scanner'); } });
      assert.equal(report.status, 'partial'); assert.equal(report.findings.length, 0);
    }
  }
  const report = await runScan({ tools: ['k8s-manifest-validate'], kubernetesVersion: '1.35.0',
    files: [{ path: 'custom.yaml', content: 'apiVersion: example.com/v1\nkind: CustomResource\n' }] },
  { ...options, execute: () => ({ status: 1, stdout: JSON.stringify({
    resources: [{ filename: 'manifests/0.json', status: 'statusError', msg: 'PRIVATE_SOURCE_CANARY' }],
    summary: { valid: 0, invalid: 0, errors: 1, skipped: 0 }
  }) }) });
  assert.equal(report.status, 'partial'); assert.equal(report.findings.length, 0);
  assert.equal(report.tools[0].coverage.unvalidatedResources, 1);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
});

test('Kubernetes schema validation retains YAML 1.1 booleans rather than silently accepting them as strings', async t => {
  const options = await fixture(t);
  // Stand in for a string-valued ConfigMap schema, using the actual staged input.
  const execute = (_binary, _args, processOptions) => {
    const resource = JSON.parse(readFileSync(path.join(processOptions.cwd, 'manifests/0.json'), 'utf8'));
    const invalid = typeof resource.data.enabled !== 'string';
    return { status: invalid ? 1 : 0, stdout: JSON.stringify({
      resources: [{ filename: 'manifests/0.json', status: invalid ? 'statusInvalid' : 'statusValid' }],
      summary: { valid: invalid ? 0 : 1, invalid: invalid ? 1 : 0, errors: 0, skipped: 0 }
    }) };
  };
  for (const [value, findings] of [['yes', 1], ['"yes"', 0]]) {
    const report = await runScan({ tools: ['k8s-manifest-validate'], kubernetesVersion: '1.35.0', files: [{ path: 'config.yaml',
      content: `apiVersion: v1\nkind: ConfigMap\nmetadata: {name: example}\ndata: {enabled: ${value}}\n` }] }, { ...options, execute });
    assert.equal(report.status, 'completed');
    assert.equal(report.findings.length, findings);
  }
});

test('Kubernetes runner fails closed on unavailable, timed-out and malformed scanner reports', async t => {
  const options = await fixture(t);
  for (const tool of ['k8s-deprecations', 'k8s-manifest-validate']) {
    for (const response of [{ status: null, error: new Error('ENOENT') }, { status: null, signal: 'SIGKILL' },
      { status: 0, stdout: '{}' }, { status: 0, stdout: 'PRIVATE_SOURCE_CANARY' }]) {
      const report = await runScan({ tools: [tool], kubernetesVersion: '1.32.0',
        files: [{ path: 'pod.json', content: '{"apiVersion":"v1","kind":"Pod"}' }] }, { ...options, execute: () => response });
      assert.equal(report.status, 'failed'); assert.equal(report.findings.length, 0);
      assert.ok(!JSON.stringify(report).includes('PRIVATE_SOURCE_CANARY'));
    }
  }
});
