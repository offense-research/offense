// Publish a complete managed Offense skill without rebuilding production code.
// The standalone CLI remains canonical-only and is verified before activation.
import vm from 'node:vm';
import { builtinModules } from 'node:module';
import { webcrypto } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { assetBytes, digest, embeddedAssets, proofPath, regularBytes } from './build-agent-console-release.mjs';
import { validateRelease } from './skill-updater.mjs';

export const SKILL_CLIENT_KIND = 'offense_skill_release';
const prefix = '/skills/offense/';
const cliPath = prefix + 'scripts/cli.mjs';
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const versionFrom = bytes => bytes.toString().match(/\n\s+version:\s*"([^"]+)"/)?.[1];
const manifestFrom = assets => validateRelease(JSON.parse(assetBytes(assets[prefix + 'manifest.json'])), 'offense');
const encoded = bytes => {
  const compressed = gzipSync(bytes, { level: 9 });
  return compressed.length + 40 < bytes.length ? { gzip: compressed.toString('base64') } : bytes.toString('base64');
};
function budget(bytes) {
  if (bytes.toString('base64').length + 32768 > 4_000_000) throw Error('Skill release exceeds the conservative connected-upload budget.');
}
function verifiedDeployment(deployment, baseline) {
  if (!deployment.activeVersionVerified || !deployment.statefulApiVerified ||
      !/^[a-f0-9-]{36}$/.test(deployment.versionId || '') || deployment.moduleSha256 !== digest(baseline) ||
      deployment.release !== digest(baseline).slice(0, 12)) throw Error('The skill release baseline differs from the verified deployment.');
}
function managedPaths(manifest) {
  return [prefix + 'manifest.json', ...manifest.files.filter(file => prefix + file.path !== cliPath).map(file => prefix + file.path)].sort();
}
function checkRelease(before, after) {
  const previous = manifestFrom(before.assets), next = manifestFrom(after.assets);
  const oldVersion = previous.version.split('.').map(Number), newVersion = next.version.split('.').map(Number);
  const difference = newVersion.findIndex((part, index) => part !== oldVersion[index]);
  if (difference < 0 || newVersion[difference] < oldVersion[difference] ||
      versionFrom(assetBytes(before.assets[prefix + 'SKILL.md'])) !== previous.version ||
      versionFrom(assetBytes(after.assets[prefix + 'SKILL.md'])) !== next.version) throw Error('Skill release versions are inconsistent or not increasing.');
  if (previous.files.some(file => !next.files.some(item => item.path === file.path))) throw Error('A managed skill release cannot silently remove prior resources.');
  const historical = Object.fromEntries(previous.files.map(file => [file.path, file.sha256]));
  const history = next.previousReleases.find(release => release.version === previous.version);
  if (!history || !same(Object.entries(history.files).sort(), Object.entries(historical).sort())) throw Error('The skill release must preserve the prior published hashes.');
  if (Object.hasOwn(before.assets, cliPath) || Object.hasOwn(after.assets, cliPath)) throw Error('The canonical CLI must not be embedded by this release.');
  const clientPaths = managedPaths(next);
  for (const file of next.files) {
    const name = prefix + file.path;
    if (name === cliPath) continue;
    if (!Object.hasOwn(after.assets, name)) throw Error('A managed skill resource is missing.');
    const bytes = assetBytes(after.assets[name]);
    if (bytes.length !== file.bytes || digest(bytes) !== file.sha256) throw Error('A managed skill resource differs from its release manifest.');
  }
  const manifestBytes = assetBytes(after.assets[prefix + 'manifest.json']);
  const canonicalResources = [{ path: prefix + 'manifest.json', bytes: manifestBytes.length, sha256: digest(manifestBytes) },
    ...next.files.map(file => ({ path: prefix + file.path, bytes: file.bytes, sha256: file.sha256 }))];
  return { previous, next, clientPaths, canonicalResources };
}

export async function inspectSkillClientCandidate(artifactFile) {
  const module = await regularBytes(artifactFile), proofBytes = await regularBytes(proofPath(artifactFile), 512000);
  const proof = JSON.parse(proofBytes), baseline = await regularBytes(proof.baselineFile);
  const before = embeddedAssets(baseline.toString()), after = embeddedAssets(module.toString());
  budget(module);
  if (proof.schemaVersion !== 1 || proof.kind !== SKILL_CLIENT_KIND || proof.moduleSha256 !== digest(module) ||
      proof.baselineSha256 !== digest(baseline) || proof.release !== digest(module).slice(0, 12) ||
      proof.backendUnchanged !== true || proof.backendSha256 !== digest(before.backend) || before.backend !== after.backend) throw Error('The skill release does not preserve the reviewed backend exactly.');
  const release = checkRelease(before, after);
  if (!same(proof.clientPaths, release.clientPaths) || !same(Object.keys(proof.clientSha256 || {}).sort(), release.clientPaths) ||
      proof.skillVersion !== release.next.version || proof.previousSkillVersion !== release.previous.version ||
      !same(proof.canonicalResources, release.canonicalResources)) throw Error('The skill release proof differs from its managed resource scope.');
  const allowed = new Set(release.clientPaths);
  for (const name of Object.keys(before.assets)) {
    if (!Object.hasOwn(after.assets, name)) throw Error('The skill release removed an existing asset.');
    if (!allowed.has(name) && (before.rawValues[name] !== after.rawValues[name] || !same(before.assets[name], after.assets[name]))) throw Error('The skill release changed an unrelated asset or reference.');
  }
  for (const name of Object.keys(after.assets)) if (!Object.hasOwn(before.assets, name) && !allowed.has(name)) throw Error('The skill release added an unrelated asset.');
  for (const name of release.clientPaths) if (digest(assetBytes(after.assets[name])) !== proof.clientSha256[name]) throw Error('A skill release asset differs from its reviewed hash.');
  const deployment = JSON.parse(await regularBytes(proof.deploymentFile, 128000));
  verifiedDeployment(deployment, baseline);
  if (deployment.versionId !== proof.previousVersionId || deployment.release !== proof.previousRelease) throw Error('The skill release deployment pin is inconsistent.');
  return { module, proof, proofBytes, baseline, before, after, deployment };
}

export async function buildSkillClientCandidate({ baselineFile, deploymentFile, skillDirectory, outputFile }) {
  if (!outputFile.endsWith('.js')) throw Error('Use a .js output module.');
  const baseline = await regularBytes(baselineFile), deployment = JSON.parse(await regularBytes(deploymentFile, 128000));
  verifiedDeployment(deployment, baseline);
  const before = embeddedAssets(baseline.toString());
  const manifestBytes = await regularBytes(path.join(skillDirectory, 'manifest.json'), 128000);
  const manifest = validateRelease(JSON.parse(manifestBytes), 'offense');
  const updates = { [prefix + 'manifest.json']: manifestBytes };
  for (const file of manifest.files) {
    const bytes = await regularBytes(path.join(skillDirectory, file.path), 2_000_000);
    if (bytes.length !== file.bytes || digest(bytes) !== file.sha256) throw Error('A local skill resource differs from the release manifest.');
    const name = prefix + file.path;
    if (name !== cliPath && (!Object.hasOwn(before.assets, name) || digest(assetBytes(before.assets[name])) !== file.sha256)) updates[name] = bytes;
  }
  const assets = { ...before.assets, ...Object.fromEntries(Object.entries(updates).map(([name, bytes]) => [name, encoded(bytes)])) };
  const replacement = '{' + Object.keys(assets).map(name => JSON.stringify(name) + ':' +
    (Object.hasOwn(updates, name) ? JSON.stringify(assets[name]) : before.rawValues[name])).join(',') + '}';
  const module = Buffer.from(baseline.toString().slice(0, before.start) + replacement + baseline.toString().slice(before.end));
  budget(module);
  const after = embeddedAssets(module.toString()), release = checkRelease(before, after);
  const proof = { schemaVersion: 1, kind: SKILL_CLIENT_KIND, builtAt: new Date().toISOString(),
    baselineFile: path.resolve(baselineFile), deploymentFile: path.resolve(deploymentFile), previousVersionId: deployment.versionId,
    previousVersion: deployment.version, previousRelease: deployment.release,
    baselineSha256: digest(baseline), moduleSha256: digest(module), release: digest(module).slice(0, 12),
    backendUnchanged: true, backendSha256: digest(before.backend), priorAssetsRetained: true,
    clientPaths: release.clientPaths, clientSha256: Object.fromEntries(release.clientPaths.map(name => [name, digest(assetBytes(after.assets[name]))])),
    previousSkillVersion: release.previous.version, skillVersion: release.next.version, canonicalResources: release.canonicalResources,
    scope: 'Managed Offense skill resources and manifest only; canonical CLI, backend, frontend and unrelated asset references retained.' };
  await writeFile(outputFile, module, { mode: 0o600, flag: 'wx' });
  await writeFile(proofPath(outputFile), JSON.stringify(proof, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  await inspectSkillClientCandidate(outputFile);
  return proof;
}

export async function verifyPublishedSkillClientResources(candidate, { download }) {
  for (const resource of candidate.proof.canonicalResources) {
    const response = await download(new URL(resource.path, 'https://offense.sh').href);
    const bytes = Buffer.from(response.bytes);
    if (bytes.length !== resource.bytes || digest(bytes) !== resource.sha256) throw Error('Publish the matching canonical skill resources before app activation.');
  }
}

export async function verifySkillClientArtifact(artifactFile) {
  if (typeof vm.SourceTextModule !== 'function') throw Error('Run skill release verification with --experimental-vm-modules.');
  const candidate = await inspectSkillClientCandidate(artifactFile), { module, proof, proofBytes, after } = candidate;
  const report = { passed: false, kind: SKILL_CLIENT_KIND, checkedAt: new Date().toISOString(), artifactSha256: digest(module),
    proofSha256: digest(proofBytes), baselineSha256: proof.baselineSha256, backendSha256: proof.backendSha256,
    clientPaths: proof.clientPaths, checks: [], outboundRequests: 0 };
  const safeProcess = new Proxy(process, { get(target, key) { if (key === 'env') return { NODE_ENV: 'test' };
    const value = Reflect.get(target, key); return typeof value === 'function' ? value.bind(target) : value; } });
  const context = vm.createContext({ console, Buffer, process: safeProcess, fetch() { report.outboundRequests++; throw Error('Offline skill verification cannot make outbound requests.'); },
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
    if (response.status !== 200 || digest(Buffer.from(await response.arrayBuffer())) !== digest(assetBytes(value))) throw Error('The exact Worker does not serve a reviewed skill release asset.');
    if (name === prefix + 'manifest.json' && (!response.headers.get('content-type')?.startsWith('application/json') || response.headers.get('cache-control') !== 'no-store')) throw Error('The skill release manifest must be JSON and no-store.');
  }
  if (report.outboundRequests) throw Error('Unexpected outbound verification request.');
  report.checks = ['Every production backend byte and unrelated asset/reference is unchanged.',
    'Every complete managed skill resource matches its release manifest and retains the previous hashes.',
    'The exact Worker serves every embedded asset, including newly managed references.',
    'The canonical-only CLI and all canonical resources require matching public bytes before activation.'];
  report.passed = true;
  return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [action, ...args] = process.argv.slice(2);
  if (action === 'build' && args.length === 4) {
    const [baselineFile, deploymentFile, skillDirectory, outputFile] = args;
    console.log(JSON.stringify(await buildSkillClientCandidate({ baselineFile, deploymentFile, skillDirectory, outputFile })));
  } else if (action === 'verify' && args.length === 2) {
    const [artifactFile, outputFile] = args, report = await verifySkillClientArtifact(artifactFile);
    await writeFile(outputFile, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify(report));
  } else throw Error('Usage: build-skill-client-release.mjs build LIVE_MODULE VERIFIED_DEPLOYMENT SKILL_DIRECTORY OUTPUT.js | verify CANDIDATE.js VALIDATION.json');
}
