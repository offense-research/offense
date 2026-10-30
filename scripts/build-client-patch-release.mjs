// Update only the two embedded Offense release metadata files. The CLI itself
// stays on the canonical static distribution, checked again before publication.
import vm from 'node:vm';
import { builtinModules } from 'node:module';
import { webcrypto } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { assetBytes, digest, embeddedAssets, proofPath, regularBytes } from './build-agent-console-release.mjs';
import { validateRelease } from './skill-updater.mjs';

export const CLIENT_PATCH_KIND = 'offense_client_patch';
export const CLIENT_PATCH_PATHS = Object.freeze(['/skills/offense/SKILL.md', '/skills/offense/manifest.json']);
const prefix = '/skills/offense/';
const cliPath = prefix + 'scripts/cli.mjs';
const encoded = bytes => {
  const compressed = gzipSync(bytes, { level: 9 });
  return compressed.length + 40 < bytes.length ? { gzip: compressed.toString('base64') } : bytes.toString('base64');
};
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const skillVersion = bytes => bytes.toString().match(/\n\s+version:\s*"([^"]+)"/)?.[1];
const manifestFrom = assets => validateRelease(JSON.parse(assetBytes(assets[prefix + 'manifest.json'])), 'offense');
function budget(bytes) {
  if (bytes.toString('base64').length + 32768 > 4_000_000) throw Error('Client patch exceeds the conservative connected-upload budget.');
}
function verifiedDeployment(deployment, baseline) {
  if (!deployment.activeVersionVerified || !deployment.statefulApiVerified ||
      !/^[a-f0-9-]{36}$/.test(deployment.versionId || '') || deployment.moduleSha256 !== digest(baseline) ||
      deployment.release !== digest(baseline).slice(0, 12)) throw Error('The client patch baseline differs from the verified deployment.');
}
function checkRelease(before, after) {
  const previous = manifestFrom(before.assets), next = manifestFrom(after.assets);
  const parts = value => value.split('.').map(Number);
  const oldVersion = parts(previous.version), newVersion = parts(next.version);
  const firstDifference = newVersion.findIndex((number, index) => number !== oldVersion[index]);
  if (firstDifference < 0 || newVersion[firstDifference] < oldVersion[firstDifference] ||
      skillVersion(assetBytes(before.assets[prefix + 'SKILL.md'])) !== previous.version ||
      skillVersion(assetBytes(after.assets[prefix + 'SKILL.md'])) !== next.version) throw Error('Client patch skill versions are inconsistent or not increasing.');
  if (!same(previous.files.map(file => file.path).sort(), next.files.map(file => file.path).sort())) throw Error('Client patch cannot add or remove managed resources.');
  const history = next.previousReleases.find(release => release.version === previous.version);
  const historical = Object.fromEntries(previous.files.map(file => [file.path, file.sha256]));
  if (!history || !same(Object.entries(history.files).sort(), Object.entries(historical).sort())) throw Error('Client patch must preserve the published prior release hashes.');
  for (const file of next.files) {
    const name = prefix + file.path;
    if (name === cliPath) {
      if (Object.hasOwn(before.assets, name) || Object.hasOwn(after.assets, name)) throw Error('The canonical CLI must not be embedded by a client patch.');
      continue;
    }
    if (!Object.hasOwn(after.assets, name)) throw Error('A referenced embedded skill resource is missing.');
    const bytes = assetBytes(after.assets[name]);
    if (bytes.length !== file.bytes || digest(bytes) !== file.sha256) throw Error('A referenced skill resource differs from the client patch manifest.');
    if (!CLIENT_PATCH_PATHS.includes(name)) {
      const old = previous.files.find(item => item.path === file.path);
      if (old.bytes !== file.bytes || old.sha256 !== file.sha256) throw Error('Client patch cannot change another managed resource.');
    }
  }
  const canonicalResources = [{ path: prefix + 'manifest.json', bytes: assetBytes(after.assets[prefix + 'manifest.json']).length,
    sha256: digest(assetBytes(after.assets[prefix + 'manifest.json'])) },
  ...next.files.map(file => ({ path: prefix + file.path, bytes: file.bytes, sha256: file.sha256 }))];
  return { previous, next, canonicalResources };
}

export async function inspectClientPatchCandidate(artifactFile) {
  const module = await regularBytes(artifactFile), proofBytes = await regularBytes(proofPath(artifactFile), 512000);
  const proof = JSON.parse(proofBytes), baseline = await regularBytes(proof.baselineFile);
  const before = embeddedAssets(baseline.toString()), after = embeddedAssets(module.toString());
  budget(module);
  if (proof.schemaVersion !== 1 || proof.kind !== CLIENT_PATCH_KIND || proof.moduleSha256 !== digest(module) ||
      proof.baselineSha256 !== digest(baseline) || proof.release !== digest(module).slice(0, 12) ||
      proof.backendUnchanged !== true || proof.backendSha256 !== digest(before.backend) || before.backend !== after.backend) throw Error('Client patch does not preserve the reviewed backend exactly.');
  if (!same(proof.clientPaths, CLIENT_PATCH_PATHS) || !same(Object.keys(proof.clientSha256 || {}).sort(), [...CLIENT_PATCH_PATHS].sort()) ||
      !same(Object.keys(before.assets), Object.keys(after.assets))) throw Error('Client patch has an invalid asset scope.');
  for (const name of Object.keys(before.assets)) {
    if (!CLIENT_PATCH_PATHS.includes(name)) {
      if (before.rawValues[name] !== after.rawValues[name] || !same(before.assets[name], after.assets[name])) throw Error('Client patch changed an unrelated asset or reference.');
    } else if (digest(assetBytes(after.assets[name])) !== proof.clientSha256[name]) throw Error('A client patch asset differs from its reviewed hash.');
  }
  for (const name of CLIENT_PATCH_PATHS) if (!Object.hasOwn(before.assets, name) || !Object.hasOwn(after.assets, name)) throw Error('Client patch requires existing metadata assets.');
  const release = checkRelease(before, after);
  if (proof.skillVersion !== release.next.version || proof.previousSkillVersion !== release.previous.version ||
      !same(proof.canonicalResources, release.canonicalResources)) throw Error('Client patch proof does not match its managed release.');
  const deployment = JSON.parse(await regularBytes(proof.deploymentFile, 128000));
  verifiedDeployment(deployment, baseline);
  if (deployment.versionId !== proof.previousVersionId || deployment.release !== proof.previousRelease) throw Error('Client patch deployment pin is inconsistent.');
  return { module, proof, proofBytes, baseline, before, after, deployment };
}

export async function buildClientPatchCandidate({ baselineFile, deploymentFile, skillDirectory, outputFile }) {
  if (!outputFile.endsWith('.js')) throw Error('Use a .js output module.');
  const baseline = await regularBytes(baselineFile), deployment = JSON.parse(await regularBytes(deploymentFile, 128000));
  verifiedDeployment(deployment, baseline);
  const before = embeddedAssets(baseline.toString()), updates = {};
  for (const name of CLIENT_PATCH_PATHS) {
    if (!Object.hasOwn(before.assets, name)) throw Error('Client patch requires existing metadata assets.');
    updates[name] = await regularBytes(path.join(skillDirectory, name.slice(prefix.length)), name.endsWith('.json') ? 128000 : 2_000_000);
  }
  const assets = { ...before.assets, ...Object.fromEntries(Object.entries(updates).map(([name, bytes]) => [name, encoded(bytes)])) };
  const replacement = '{' + Object.keys(assets).map(name => JSON.stringify(name) + ':' +
    (Object.hasOwn(updates, name) ? JSON.stringify(assets[name]) : before.rawValues[name])).join(',') + '}';
  const module = Buffer.from(baseline.toString().slice(0, before.start) + replacement + baseline.toString().slice(before.end));
  budget(module);
  const after = embeddedAssets(module.toString()), release = checkRelease(before, after);
  const proof = { schemaVersion: 1, kind: CLIENT_PATCH_KIND, builtAt: new Date().toISOString(),
    baselineFile: path.resolve(baselineFile), deploymentFile: path.resolve(deploymentFile), previousVersionId: deployment.versionId,
    previousVersion: deployment.version, previousRelease: deployment.release,
    baselineSha256: digest(baseline), moduleSha256: digest(module), release: digest(module).slice(0, 12),
    backendUnchanged: true, backendSha256: digest(before.backend), priorAssetsRetained: true,
    clientPaths: CLIENT_PATCH_PATHS, clientSha256: Object.fromEntries(Object.entries(updates).map(([name, bytes]) => [name, digest(bytes)])),
    previousSkillVersion: release.previous.version, skillVersion: release.next.version, canonicalResources: release.canonicalResources,
    scope: 'Only existing embedded Offense SKILL.md and manifest.json; backend, frontend, other resources and asset references retained exactly.' };
  await writeFile(outputFile, module, { mode: 0o600, flag: 'wx' });
  await writeFile(proofPath(outputFile), JSON.stringify(proof, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  await inspectClientPatchCandidate(outputFile);
  return proof;
}

// Called only by the explicit publication helper after the canonical site is
// published. A staged patch cannot point old-host updates at unverified bytes.
export async function verifyPublishedClientPatchResources(candidate, { download }) {
  for (const resource of candidate.proof.canonicalResources) {
    const response = await download(new URL(resource.path, 'https://offense.sh').href);
    const bytes = Buffer.from(response.bytes);
    if (bytes.length !== resource.bytes || digest(bytes) !== resource.sha256) throw Error('Publish the exact matching canonical client resources before the app client patch.');
  }
}

export async function verifyClientPatchArtifact(artifactFile) {
  if (typeof vm.SourceTextModule !== 'function') throw Error('Run client patch verification with --experimental-vm-modules.');
  const candidate = await inspectClientPatchCandidate(artifactFile), { module, proof, proofBytes, after } = candidate;
  const report = { passed: false, kind: CLIENT_PATCH_KIND, checkedAt: new Date().toISOString(), artifactSha256: digest(module),
    proofSha256: digest(proofBytes), baselineSha256: proof.baselineSha256, backendSha256: proof.backendSha256,
    clientPaths: proof.clientPaths, checks: [], outboundRequests: 0 };
  const safeProcess = new Proxy(process, { get(target, key) { if (key === 'env') return { NODE_ENV: 'test' };
    const value = Reflect.get(target, key); return typeof value === 'function' ? value.bind(target) : value; } });
  const context = vm.createContext({ console, Buffer, process: safeProcess, fetch() { report.outboundRequests++; throw Error('Offline client patch verification cannot make outbound requests.'); },
    Request, Response, Headers, URL, URLSearchParams, AbortController, AbortSignal, TextEncoder, TextDecoder, TextEncoderStream, TextDecoderStream,
    TransformStream, ReadableStream, WritableStream, DecompressionStream, Blob, File, FormData, crypto: webcrypto, performance, setTimeout, clearTimeout,
    setInterval, clearInterval, setImmediate, clearImmediate, queueMicrotask, atob, btoa, structuredClone }, { codeGeneration: { strings: false, wasm: false } });
  const builtins = new Set(builtinModules.flatMap(name => [name, name.replace(/^node:/, '')])), cache = new Map();
  const worker = new vm.SourceTextModule(module.toString(), { context, identifier: path.resolve(artifactFile),
    initializeImportMeta(meta) { meta.url = 'file://' + path.resolve(artifactFile); }, importModuleDynamically() { throw Error('Unexpected dynamic import.'); } });
  await worker.link(async specifier => {
    if (cache.has(specifier)) return cache.get(specifier);
    let namespace;
    if (specifier === 'cloudflare:workers') namespace = { DurableObject: class { constructor(ctx, env) { this.ctx = ctx; this.env = env; } } };
    else if (specifier === 'cloudflare:node') namespace = { httpServerHandler() { throw Error('Offline verification must not start a Cloudflare bridge.'); } };
    else { if (!specifier.startsWith('node:') && !builtins.has(specifier)) throw Error('Unexpected external module.'); namespace = await import(specifier); }
    const names = Object.keys(namespace), linked = new vm.SyntheticModule(names, function() { for (const name of names) this.setExport(name, namespace[name]); }, { context, identifier: specifier });
    cache.set(specifier, linked); return linked;
  });
  await worker.evaluate({ timeout: 15000 });
  for (const [name, value] of Object.entries(after.assets)) {
    const response = await worker.namespace.default.fetch(new Request('https://app.example' + name), {}, {});
    if (response.status !== 200 || digest(Buffer.from(await response.arrayBuffer())) !== digest(assetBytes(value))) throw Error('The exact client patch module does not serve a reviewed asset.');
    if (name === prefix + 'manifest.json' && (!response.headers.get('content-type')?.startsWith('application/json') || response.headers.get('cache-control') !== 'no-store')) throw Error('Client patch manifest must be JSON and no-store.');
  }
  if (report.outboundRequests) throw Error('Unexpected outbound artifact request.');
  report.checks = ['Every backend byte and every unrelated asset/reference is unchanged.',
    'Managed release hashes match retained resources and preserve the prior published release.',
    'The actual Worker serves every reviewed embedded asset and a JSON/no-store Offense manifest.',
    'Canonical-only CLI bytes are pinned for mandatory publication-time static verification.'];
  report.passed = true;
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, ...args] = process.argv.slice(2);
  if (action === 'build' && args.length === 4) {
    const [baselineFile, deploymentFile, skillDirectory, outputFile] = args;
    console.log(JSON.stringify(await buildClientPatchCandidate({ baselineFile, deploymentFile, skillDirectory, outputFile })));
  } else if (action === 'verify' && args.length === 2) {
    const [artifactFile, outputFile] = args, report = await verifyClientPatchArtifact(artifactFile);
    await writeFile(outputFile, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify(report));
  } else throw Error('Usage: build-client-patch-release.mjs build LIVE_MODULE VERIFIED_DEPLOYMENT SKILL_DIRECTORY OUTPUT.js | verify CANDIDATE.js VALIDATION.json');
}
