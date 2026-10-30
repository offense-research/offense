import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildSkillClientCandidate, inspectSkillClientCandidate, verifySkillClientArtifact,
  verifyPublishedSkillClientResources, SKILL_CLIENT_KIND } from '../scripts/build-skill-client-release.mjs';
import { digest, proofPath } from '../scripts/build-agent-console-release.mjs';
import { deployAgentConsoleRelease } from '../scripts/deploy-agent-console-release.mjs';

const previousId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', nextId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const prefix = '/skills/offense/';
const filesFor = files => Object.entries(files).map(([name, value]) => ({ path: name, bytes: Buffer.byteLength(value), sha256: digest(value) }));
const skillText = version => `---\nname: offense\nmetadata:\n  version: "${version}"\n---\nUse the selected project.\n`;

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-skill-release-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const skillDirectory = path.join(directory, 'skill'); await mkdir(skillDirectory);
  const oldFiles = { 'SKILL.md': skillText('0.8.2'), 'scripts/offense.mjs': 'export const audit = true;',
    'scripts/cli.mjs': 'export const version = "0.1.4";', 'scripts/update.mjs': 'export const update = true;', 'references/local-tools.md': 'Old local tools.' };
  const nextFiles = { ...oldFiles, 'SKILL.md': skillText('0.9.0'), 'scripts/cli.mjs': 'export const version = "0.2.0";',
    'references/local-tools.md': 'New local tools.', 'references/stack.md': 'Track source, image and deployment identities.' };
  const previous = { schemaVersion: 1, skill: 'offense', version: '0.8.2', minimumNodeMajor: 20, files: filesFor(oldFiles), previousReleases: [] };
  const next = { ...previous, version: '0.9.0', files: filesFor(nextFiles),
    previousReleases: [{ version: previous.version, files: Object.fromEntries(previous.files.map(file => [file.path, file.sha256])) }] };
  const assets = { '/index.html': 'Keep the live frontend.', '/skills/purple/SKILL.md': 'Keep the advanced skill.', '/assets/keep.js': 'export const keep = true;',
    ...Object.fromEntries(Object.entries(oldFiles).filter(([name]) => name !== 'scripts/cli.mjs').map(([name, value]) => [prefix + name, value])),
    [prefix + 'manifest.json']: JSON.stringify(previous) };
  const pool = Object.values(assets).map(value => Buffer.from(value).toString('base64'));
  const map = '{' + Object.keys(assets).map((name, index) => JSON.stringify(name) + ':pool[' + index + ']').join(',') + '}';
  const baseline = `const pool=${JSON.stringify(pool)};const assets=${map};const backendMarker="unchanged";
export default {async fetch(request){const name=new URL(request.url).pathname;const value=assets[name];if(!value)return new Response('missing',{status:404});
const bytes=Uint8Array.from(atob(typeof value==='string'?value:value.gzip),character=>character.charCodeAt(0));
const body=typeof value==='string'?bytes:new ReadableStream({start(controller){controller.enqueue(bytes);controller.close();}}).pipeThrough(new DecompressionStream('gzip'));
return new Response(body,{headers:{'content-type':name.endsWith('.json')?'application/json':'text/plain','cache-control':'no-store'}});}};`;
  const baselineFile = path.join(directory, 'baseline.js'), deploymentFile = path.join(directory, 'deployment.json'), outputFile = path.join(directory, 'candidate.js');
  await writeFile(baselineFile, baseline);
  const deployment = { versionId: previousId, version: 95, moduleSha256: digest(baseline), release: digest(baseline).slice(0, 12), activeVersionVerified: true, statefulApiVerified: true };
  await writeFile(deploymentFile, JSON.stringify(deployment));
  for (const [name, value] of Object.entries(nextFiles)) { await mkdir(path.dirname(path.join(skillDirectory, name)), { recursive: true }); await writeFile(path.join(skillDirectory, name), value); }
  await writeFile(path.join(skillDirectory, 'manifest.json'), JSON.stringify(next));
  const canonical = new Map([[prefix + 'manifest.json', Buffer.from(JSON.stringify(next))], ...Object.entries(nextFiles).map(([name, value]) => [prefix + name, Buffer.from(value)])]);
  return { directory, baseline, baselineFile, deploymentFile, outputFile, skillDirectory, deployment, previous, next, canonical,
    build: () => buildSkillClientCandidate({ baselineFile, deploymentFile, outputFile, skillDirectory }) };
}

test('complete skill release adds a managed reference while preserving production backend and unrelated pooled assets', async t => {
  const f = await fixture(t), proof = await f.build(), candidate = await inspectSkillClientCandidate(f.outputFile);
  assert.equal(proof.kind, SKILL_CLIENT_KIND); assert.equal(proof.previousSkillVersion, '0.8.2'); assert.equal(proof.skillVersion, '0.9.0');
  assert.equal(candidate.before.backend, candidate.after.backend);
  assert.ok(Object.hasOwn(candidate.after.assets, prefix + 'references/stack.md'));
  assert.equal(Object.hasOwn(candidate.after.assets, prefix + 'scripts/cli.mjs'), false);
  for (const name of ['/index.html', '/assets/keep.js', '/skills/purple/SKILL.md']) assert.equal(candidate.before.rawValues[name], candidate.after.rawValues[name]);
  assert.equal(proof.canonicalResources.length, f.next.files.length + 1);
});

test('malformed local resources, removed prior files, prior hashes and version mismatches stop packaging', async t => {
  for (const kind of ['resource', 'removed', 'history', 'version', 'unsafe-path']) {
    await t.test(kind, async t => {
      const f = await fixture(t);
      if (kind === 'resource') await writeFile(path.join(f.skillDirectory, 'references/stack.md'), 'Changed after manifest validation');
      if (kind === 'removed') f.next.files = f.next.files.filter(file => file.path !== 'scripts/offense.mjs');
      if (kind === 'history') f.next.previousReleases[0].files['scripts/cli.mjs'] = 'f'.repeat(64);
      if (kind === 'version') f.next.version = '0.8.2';
      if (kind === 'unsafe-path') f.next.files.push({ path: '../../AGENTS.md', bytes: 1, sha256: 'f'.repeat(64) });
      await writeFile(path.join(f.skillDirectory, 'manifest.json'), JSON.stringify(f.next));
      await assert.rejects(f.build());
    });
  }
});

test('resealed hashes cannot authorize backend changes or an asset outside the manifest', async t => {
  for (const kind of ['backend', 'unrelated', 'addition']) {
    await t.test(kind, async t => {
      const f = await fixture(t); await f.build();
      let source = await readFile(f.outputFile, 'utf8');
      if (kind === 'backend') source = source.replace('backendMarker="unchanged"', 'backendMarker="changed"');
      if (kind === 'unrelated') source = source.replace('"/assets/keep.js":pool[2]', '"/assets/keep.js":pool[1]');
      if (kind === 'addition') source = source.replace('const assets={', 'const assets={"/skills/offense/references/unlisted.md":"bmV3",');
      await writeFile(f.outputFile, source);
      const proof = JSON.parse(await readFile(proofPath(f.outputFile), 'utf8'));
      await writeFile(proofPath(f.outputFile), JSON.stringify({ ...proof, moduleSha256: digest(source), release: digest(source).slice(0, 12) }));
      await assert.rejects(inspectSkillClientCandidate(f.outputFile), /backend|unrelated/);
    });
  }
});

test('canonical preflight verifies newly added references and unembedded CLI bytes', async t => {
  const f = await fixture(t); await f.build(); const candidate = await inspectSkillClientCandidate(f.outputFile), urls = [];
  await verifyPublishedSkillClientResources(candidate, { download: async url => { urls.push(url); return { bytes: f.canonical.get(new URL(url).pathname) }; } });
  assert.ok(urls.includes('https://offense.sh/skills/offense/references/stack.md'));
  assert.ok(urls.includes('https://offense.sh/skills/offense/scripts/cli.mjs'));
  await assert.rejects(verifyPublishedSkillClientResources(candidate, { download: async url => ({ bytes: new URL(url).pathname.endsWith('cli.mjs') ? Buffer.from('old CLI') : f.canonical.get(new URL(url).pathname) }) }), /matching canonical/);
});

test('the exact candidate serves the newly managed asset without network requests', { skip: typeof vm.SourceTextModule !== 'function' }, async t => {
  const f = await fixture(t); await f.build(); const validation = await verifySkillClientArtifact(f.outputFile);
  assert.equal(validation.passed, true); assert.equal(validation.kind, SKILL_CLIENT_KIND); assert.equal(validation.outboundRequests, 0);
  assert.ok(validation.clientPaths.includes(prefix + 'references/stack.md'));
});

test('publication requires canonical matching and explicit scope before any control-plane mutation', { skip: typeof vm.SourceTextModule !== 'function' }, async t => {
  const f = await fixture(t); await f.build(); const validation = await verifySkillClientArtifact(f.outputFile);
  const validationFile = path.join(f.directory, 'validation.json'); await writeFile(validationFile, JSON.stringify(validation));
  let controlCalls = 0;
  await assert.rejects(deployAgentConsoleRelease({ artifactFile: f.outputFile, validationFile, expectedVersion: previousId }, {
    env: { PURPLE_SECRETS_SOURCE: 'infisical', PURPLE_SECRETS_ENVIRONMENT: 'prod' }, transport: { request() { controlCalls++; throw Error('Must stop before requests'); } }
  }), /preserve the reviewed production backend/);
  await assert.rejects(deployAgentConsoleRelease({ artifactFile: f.outputFile, validationFile, expectedVersion: previousId, kind: SKILL_CLIENT_KIND }, {
    env: { PURPLE_SECRETS_SOURCE: 'infisical', PURPLE_SECRETS_ENVIRONMENT: 'prod' },
    transport: { download: async () => ({ bytes: Buffer.from('stale canonical resource') }), request() { controlCalls++; throw Error('Must stop before mutation'); } }
  }), /matching canonical/);
  assert.equal(controlCalls, 0);
});
