import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildClientPatchCandidate, inspectClientPatchCandidate, verifyClientPatchArtifact,
  verifyPublishedClientPatchResources, CLIENT_PATCH_KIND, CLIENT_PATCH_PATHS } from '../scripts/build-client-patch-release.mjs';
import { buildAgentConsoleCandidate, digest, embeddedAssets, proofPath } from '../scripts/build-agent-console-release.mjs';
import { verifyAgentConsoleArtifact } from '../scripts/verify-agent-console-release.mjs';
import { deployAgentConsoleRelease } from '../scripts/deploy-agent-console-release.mjs';

const previousId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', nextId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const prefix = '/skills/offense/';
const filesFor = files => Object.entries(files).map(([file, value]) => ({ path: file, bytes: Buffer.byteLength(value), sha256: digest(value) }));
const textFor = version => `---\nname: offense\nmetadata:\n  version: "${version}"\n---\nUse the existing account.\n`;
async function fixture(t, { padding = '' } = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-client-patch-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const skillDirectory = path.join(directory, 'skill'); await mkdir(skillDirectory);
  const oldFiles = { 'SKILL.md': textFor('0.8.0'), 'scripts/offense.mjs': 'export const audit = true;',
    'scripts/update.mjs': 'export const update = true;', 'scripts/cli.mjs': 'export const version = "0.1.2";' };
  const nextFiles = { ...oldFiles, 'SKILL.md': textFor('0.8.1'), 'scripts/cli.mjs': 'export const version = "0.1.3";' };
  const previous = { schemaVersion: 1, skill: 'offense', version: '0.8.0', minimumNodeMajor: 20, files: filesFor(oldFiles), previousReleases: [] };
  const next = { ...previous, version: '0.8.1', files: filesFor(nextFiles),
    previousReleases: [{ version: '0.8.0', files: Object.fromEntries(previous.files.map(file => [file.path, file.sha256])) }] };
  const assets = { '/index.html': '<script src="/assets/old.js"></script>', '/skills/purple/SKILL.md': 'Unchanged advanced skill.',
    '/assets/old.js': 'export const old = true;', ...Object.fromEntries(Object.entries(oldFiles).filter(([name]) => name !== 'scripts/cli.mjs').map(([name, text]) => [prefix + name, text])),
    [prefix + 'manifest.json']: JSON.stringify(previous) };
  const pooled = Object.values(assets).map(text => Buffer.from(text).toString('base64'));
  const map = '{' + Object.keys(assets).map((name, index) => JSON.stringify(name) + ':pool[' + index + ']').join(',') + '}';
  const baseline = `const pool=${JSON.stringify(pooled)};const assets=${map};const backendMarker="unchanged";
export default {async fetch(request){const name=new URL(request.url).pathname;const value=assets[name]||assets['/index.html'];
const headers={'content-type':name.endsWith('.json')?'application/json':name.endsWith('.html')||!assets[name]?'text/html':'text/plain','cache-control':'no-store'};
const bytes=Uint8Array.from(atob(typeof value==='string'?value:value.gzip),character=>character.charCodeAt(0));
const body=typeof value==='string'?bytes:new ReadableStream({start(controller){controller.enqueue(bytes);controller.close();}}).pipeThrough(new DecompressionStream('gzip'));
return new Response(body,{headers});}};\n${padding}`;
  const baselineFile = path.join(directory, 'baseline.js'), deploymentFile = path.join(directory, 'deployment.json'), outputFile = path.join(directory, 'candidate.js');
  await writeFile(baselineFile, baseline);
  const deployment = { versionId: previousId, version: 87, moduleSha256: digest(baseline), release: digest(baseline).slice(0, 12), activeVersionVerified: true, statefulApiVerified: true };
  await writeFile(deploymentFile, JSON.stringify(deployment));
  await writeFile(path.join(skillDirectory, 'SKILL.md'), nextFiles['SKILL.md']);
  await writeFile(path.join(skillDirectory, 'manifest.json'), JSON.stringify(next));
  const canonical = new Map([[prefix + 'manifest.json', Buffer.from(JSON.stringify(next))], ...Object.entries(nextFiles).map(([name, text]) => [prefix + name, Buffer.from(text)])]);
  return { directory, baseline, baselineFile, deploymentFile, outputFile, skillDirectory, deployment, previous, next, oldFiles, nextFiles, canonical,
    build: () => buildClientPatchCandidate({ baselineFile, deploymentFile, outputFile, skillDirectory }) };
}
async function reseal(fixture, edit, editProof = value => value) {
  const before = await readFile(fixture.outputFile, 'utf8'), module = edit(before);
  await writeFile(fixture.outputFile, module);
  const proof = JSON.parse(await readFile(proofPath(fixture.outputFile), 'utf8'));
  await writeFile(proofPath(fixture.outputFile), JSON.stringify(editProof({ ...proof, moduleSha256: digest(module), release: digest(module).slice(0, 12) })));
}

test('client patch changes only existing release metadata while preserving pooled references and exact backend', async t => {
  const f = await fixture(t), proof = await f.build(), candidate = await inspectClientPatchCandidate(f.outputFile);
  assert.equal(proof.kind, CLIENT_PATCH_KIND); assert.deepEqual(proof.clientPaths, CLIENT_PATCH_PATHS);
  assert.equal(proof.previousSkillVersion, '0.8.0'); assert.equal(proof.skillVersion, '0.8.1');
  assert.equal(candidate.before.backend, candidate.after.backend);
  for (const name of Object.keys(candidate.before.assets).filter(name => !CLIENT_PATCH_PATHS.includes(name))) {
    assert.equal(candidate.before.rawValues[name], candidate.after.rawValues[name]);
  }
  assert.ok(proof.canonicalResources.some(file => file.path === prefix + 'scripts/cli.mjs'));
  assert.equal(Object.hasOwn(candidate.after.assets, prefix + 'scripts/cli.mjs'), false);
});

test('resealed proofs cannot authorize unrelated asset, backend or resource-reference changes', async t => {
  for (const kind of ['backend', 'asset', 'new-asset', 'proof-paths']) {
    await t.test(kind, async t => {
      const f = await fixture(t); await f.build();
      await reseal(f, source => {
        if (kind === 'backend') return source.replace('backendMarker="unchanged"', 'backendMarker="changed"');
        if (kind === 'asset') return source.replace('"/assets/old.js":pool[2]', '"/assets/old.js":pool[1]');
        if (kind === 'new-asset') return source.replace('const assets={', 'const assets={"/unexpected":"bmV3",');
        return source;
      }, proof => kind === 'proof-paths' ? { ...proof, clientPaths: [...proof.clientPaths, '/assets/old.js'] } : proof);
      await assert.rejects(inspectClientPatchCandidate(f.outputFile), /backend|scope|unrelated/i);
    });
  }
});

test('skill references, version metadata, prior hashes and deployment identity must agree before packaging', async t => {
  for (const kind of ['resource', 'history', 'version', 'deployment']) {
    await t.test(kind, async t => {
      const f = await fixture(t);
      if (kind === 'resource') f.next.files.find(file => file.path === 'scripts/update.mjs').sha256 = 'f'.repeat(64);
      if (kind === 'history') f.next.previousReleases[0].files['scripts/cli.mjs'] = 'f'.repeat(64);
      if (kind === 'version') f.next.version = '0.8.2';
      if (kind === 'deployment') await writeFile(f.deploymentFile, JSON.stringify({ ...f.deployment, statefulApiVerified: false }));
      await writeFile(path.join(f.skillDirectory, 'manifest.json'), JSON.stringify(f.next));
      await assert.rejects(f.build(), /resource|hashes|versions|deployment/i);
    });
  }
  const large = await fixture(t, { padding: '//' + 'x'.repeat(3_000_000) });
  await assert.rejects(large.build(), /upload budget/);
});

test('proof and verified deployment remain pinned after a candidate is built', async t => {
  const f = await fixture(t); await f.build();
  await writeFile(f.deploymentFile, JSON.stringify({ ...f.deployment, versionId: nextId }));
  await assert.rejects(inspectClientPatchCandidate(f.outputFile), /deployment pin/);
});

test('canonical static preflight verifies every resource including the unembedded CLI', async t => {
  const f = await fixture(t); await f.build(); const candidate = await inspectClientPatchCandidate(f.outputFile), urls = [];
  await verifyPublishedClientPatchResources(candidate, { download: async url => {
    const address = new URL(url); urls.push(url); assert.equal(address.origin, 'https://offense.sh');
    return { bytes: f.canonical.get(address.pathname) };
  } });
  assert.equal(urls.length, f.next.files.length + 1);
  await assert.rejects(verifyPublishedClientPatchResources(candidate, { download: async url => ({ bytes: new URL(url).pathname.endsWith('cli.mjs') ? Buffer.from('outdated') : f.canonical.get(new URL(url).pathname) }) }), /canonical client resources/);
});

test('offline verifier executes the exact module and publication requires the explicit client scope', { skip: typeof vm.SourceTextModule !== 'function' }, async t => {
  const f = await fixture(t); await f.build(); const validation = await verifyClientPatchArtifact(f.outputFile);
  assert.equal(validation.passed, true); assert.equal(validation.outboundRequests, 0);
  const validationFile = path.join(f.directory, 'validation.json'); await writeFile(validationFile, JSON.stringify(validation));
  let requests = 0;
  await assert.rejects(deployAgentConsoleRelease({ artifactFile: f.outputFile, validationFile, expectedVersion: previousId }, {
    env: { PURPLE_SECRETS_SOURCE: 'infisical', PURPLE_SECRETS_ENVIRONMENT: 'prod' }, transport: { request() { requests++; throw Error('Must not run'); } }
  }), /preserve the reviewed production backend/);
  assert.equal(requests, 0);
  await publishFixture(f, { validationFile, validation });

  // The original frontend scope still uses its own inspector and publication
  // path. A client patch cannot silently replace that existing contract.
  const dist = path.join(f.directory, 'dist'); await mkdir(path.join(dist, 'assets'), { recursive: true });
  await writeFile(path.join(dist, 'index.html'), '<script src="/assets/new.js"></script><link href="/assets/new.css">');
  await writeFile(path.join(dist, 'assets/new.js'), 'Get started;API keys;Usage;Billing;Settings;/legacy');
  await writeFile(path.join(dist, 'assets/new.css'), 'body{}');
  const outputFile = path.join(f.directory, 'frontend.js');
  await buildAgentConsoleCandidate({ baselineFile: f.baselineFile, deploymentFile: f.deploymentFile, dist, outputFile });
  const frontendValidation = await verifyAgentConsoleArtifact(outputFile), frontendValidationFile = path.join(f.directory, 'frontend-validation.json');
  await writeFile(frontendValidationFile, JSON.stringify(frontendValidation));
  await publishFixture({ ...f, outputFile }, { validationFile: frontendValidationFile, validation: frontendValidation, kind: 'agent_console_frontend_only' });
});

async function publishFixture(f, { validationFile, kind = CLIENT_PATCH_KIND }) {
  const proof = JSON.parse(await readFile(proofPath(f.outputFile), 'utf8'));
  const multipart = new FormData(); multipart.append('app-staging.js', new File([f.baseline], 'app-staging.js', { type: 'application/javascript+module' }));
  const response = new Response(multipart), bytes = await response.arrayBuffer(), contentType = response.headers.get('content-type');
  const settings = { compatibility_date: '2026-10-21', compatibility_flags: ['nodejs_compat'], placement: {}, observability: { enabled: true },
    bindings: [{ name: 'PURPLE_RELEASE', type: 'plain_text', text: f.deployment.release }, { name: 'FIXTURE_SECRET', type: 'secret_text' },
      { name: 'STATE', type: 'durable_object_namespace', namespace_id: 'fixture-namespace' }] };
  let active = previousId, uploaded = false, canonicalDownloads = 0;
  const transport = {
    async download(url) {
      const address = new URL(url);
      if (address.origin === 'https://offense.sh') { canonicalDownloads++; return { bytes: f.canonical.get(address.pathname) }; }
      assert.equal(url, 'https://module.example/active'); return { bytes, contentType };
    },
    request(args) {
      if (args[0] === 'execute') {
        const payload = JSON.parse(readFileSync(args.at(-1).slice(1), 'utf8'));
        assert.equal(Buffer.from(payload.modules[0].content_base64, 'base64').toString(), readFileSync(f.outputFile, 'utf8'));
        assert.equal(payload.bindings.find(binding => binding.name === 'STATE').type, 'inherit');
        assert.equal(payload.bindings.find(binding => binding.name === 'FIXTURE_SECRET').text, 'synthetic-secret');
        assert.match(payload.annotations.workers_message, kind === CLIENT_PATCH_KIND ? /client patch metadata only/ : /frontend assets only/);
        uploaded = true; return { successful: true, data: { result: { id: nextId, number: 88 } } };
      }
      const url = new URL(args[1]), method = args[args.indexOf('-X') + 1];
      if (url.pathname.endsWith('/deployments')) {
        if (method === 'POST') { assert.equal(uploaded, true); active = nextId; }
        return { success: true, result: { deployments: [{ versions: [{ version_id: active, percentage: 100 }] }] } };
      }
      if (url.pathname.endsWith('/settings')) return { success: true, result: { ...settings, bindings: settings.bindings.map(binding => binding.name === 'PURPLE_RELEASE' && active === nextId ? { ...binding, text: proof.release } : binding) } };
      assert.equal(method, 'GET'); return { binary_data: { url: 'https://module.example/active' } };
    }
  };
  const recordDirectory = await mkdtemp(path.join(f.directory, 'records-'));
  const { record } = await deployAgentConsoleRelease({ artifactFile: f.outputFile, validationFile, expectedVersion: previousId, recordDirectory, kind },
    { transport, env: { PURPLE_SECRETS_SOURCE: 'infisical', PURPLE_SECRETS_ENVIRONMENT: 'prod', FIXTURE_SECRET: 'synthetic-secret' } });
  assert.equal(record.settingsPreserved, true); assert.equal(record.versionId, nextId);
  assert.equal(canonicalDownloads, kind === CLIENT_PATCH_KIND ? f.next.files.length + 1 : 0);
  const recordName = kind === CLIENT_PATCH_KIND ? 'offense-client-patch-production.json' : 'agent-console-production.json';
  assert.equal(JSON.parse(await readFile(path.join(recordDirectory, recordName), 'utf8')).kind, kind);
}
