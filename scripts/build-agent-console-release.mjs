// Frontend-only packaging: existing backend bytes and public client packages
// are retained exactly. This command reads no credentials and never deploys.
import { readFile, writeFile, readdir, lstat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { gzipSync, gunzipSync } from 'node:zlib';
import { parse } from '@babel/parser';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const proofPath = file => file.replace(/\.js$/, '') + '-proof.json';
export async function regularBytes(file, maximum = 12 * 1024 * 1024) {
  const absolute = path.resolve(file);let current = path.parse(absolute).root;
  for (const part of path.relative(current, absolute).split(path.sep)) { current = path.join(current, part);if ((await lstat(current)).isSymbolicLink()) throw Error('Release inputs cannot contain symlinks.'); }
  const stat = await lstat(absolute);if (!stat.isFile() || stat.size > maximum) throw Error('Release input is not a bounded regular file.');
  return readFile(absolute);
}
export function embeddedAssets(source) {
  const ast = parse(source, { sourceType: 'module' });
  const declarations = ast.program.body.flatMap(node => node.type === 'VariableDeclaration' ? node.declarations : []);
  const found = declarations.filter(declaration =>
    declaration.init?.type === 'ObjectExpression' && ['/index.html', '/skills/purple/SKILL.md'].every(key => declaration.init.properties.some(property => property.key?.type === 'StringLiteral' && property.key.value === key)));
  if (found.length !== 1) throw Error('Expected exactly one existing embedded asset map.');
  const node = found[0].init, assets = {}, rawValues = {};
  for (const property of node.properties) {
    if (property.type !== 'ObjectProperty' || property.computed || property.key.type !== 'StringLiteral' || !property.key.value.startsWith('/') || Object.hasOwn(assets, property.key.value)) throw Error('Unsupported existing asset map.');
    let value = property.value;
    rawValues[property.key.value] = source.slice(value.start, value.end);
    if (value.type === 'MemberExpression') {
      if (!value.computed || value.object.type !== 'Identifier' || value.property.type !== 'NumericLiteral' || !Number.isSafeInteger(value.property.value) || value.property.value < 0) throw Error('Unsupported asset pool reference.');
      const pool = declarations.filter(declaration => declaration.id.type === 'Identifier' && declaration.id.name === value.object.name);
      if (pool.length !== 1 || pool[0].init?.type !== 'ArrayExpression' || !pool[0].init.elements[value.property.value]) throw Error('Asset pool reference is out of bounds.');
      value = pool[0].init.elements[value.property.value];
    }
    if (value.type === 'StringLiteral') assets[property.key.value] = value.value;
    else {
      const gzip = value.type === 'ObjectExpression' && value.properties.length === 1 && value.properties[0];
      if (!gzip || gzip.type !== 'ObjectProperty' || gzip.computed || !['Identifier', 'StringLiteral'].includes(gzip.key.type) || (gzip.key.name || gzip.key.value) !== 'gzip' || gzip.value.type !== 'StringLiteral') throw Error('Unsupported existing asset encoding.');
      assets[property.key.value] = { gzip: gzip.value.value };
    }
  }
  return { start: node.start, end: node.end, assets, rawValues, backend: source.slice(0, node.start) + '<STATIC_ASSETS>' + source.slice(node.end) };
}
export function assetBytes(value) {
  return typeof value === 'string' ? Buffer.from(value, 'base64') : gunzipSync(Buffer.from(value.gzip, 'base64'), { maxOutputLength: 16 * 1024 * 1024 });
}
const encoded = bytes => { const gzip = gzipSync(bytes, { level: 9 });return gzip.length + 40 < bytes.length ? { gzip: gzip.toString('base64') } : bytes.toString('base64'); };
async function frontend(dist) {
  const files = ['/index.html'];
  for (const name of await readdir(path.join(dist, 'assets'))) {
    if (!/^[A-Za-z0-9_.-]+\.(?:js|css)$/.test(name)) throw Error('Unexpected frontend asset; review its release scope.');
    files.push('/assets/' + name);
  }
  if (files.length < 3 || files.length > 33 || !files.some(file => file.endsWith('.js')) || !files.some(file => file.endsWith('.css'))) throw Error('Expected a bounded complete frontend build.');
  return Object.fromEntries(await Promise.all(files.map(async name => [name, await regularBytes(path.join(dist, name.slice(1)), 3 * 1024 * 1024)])));
}
export async function inspectAgentConsoleCandidate(artifactFile) {
  const module = await regularBytes(artifactFile), proofBytes = await regularBytes(proofPath(artifactFile), 512000), proof = JSON.parse(proofBytes);
  const baseline = await regularBytes(proof.baselineFile), before = embeddedAssets(baseline.toString()), after = embeddedAssets(module.toString());
  if (proof.schemaVersion !== 1 || proof.kind !== 'agent_console_frontend_only' || proof.moduleSha256 !== digest(module) || proof.baselineSha256 !== digest(baseline) ||
    proof.release !== digest(module).slice(0, 12) || !proof.backendUnchanged || proof.backendSha256 !== digest(before.backend) || before.backend !== after.backend) throw Error('Candidate does not preserve the reviewed production backend exactly.');
  if (!Array.isArray(proof.frontendPaths) || !proof.frontendPaths.includes('/index.html') || proof.frontendPaths.length > 33 ||
    proof.frontendPaths.some(name => name !== '/index.html' && !/^\/assets\/[A-Za-z0-9_.-]+\.(?:js|css)$/.test(name))) throw Error('Candidate has invalid frontend scope.');
  const changed = new Set(proof.frontendPaths);
  for (const [name, value] of Object.entries(before.assets)) if (!changed.has(name) && JSON.stringify(after.assets[name]) !== JSON.stringify(value)) throw Error('An existing non-frontend asset was changed or removed.');
  for (const name of Object.keys(after.assets)) if (!Object.hasOwn(before.assets, name) && !changed.has(name)) throw Error('An unrelated asset was added.');
  for (const name of proof.frontendPaths) if (!Object.hasOwn(after.assets, name) || digest(assetBytes(after.assets[name])) !== proof.frontendSha256[name]) throw Error('A packaged frontend asset differs from its reviewed hash.');
  const deployment = JSON.parse(await regularBytes(proof.deploymentFile, 128000));
  if (!deployment.activeVersionVerified || !deployment.statefulApiVerified || deployment.versionId !== proof.previousVersionId || deployment.moduleSha256 !== proof.baselineSha256 || deployment.release !== proof.baselineSha256.slice(0, 12)) throw Error('The baseline differs from the verified deployment record.');
  return { module, proof, proofBytes, baseline, before, after, deployment };
}
export async function buildAgentConsoleCandidate({ baselineFile, deploymentFile, dist, outputFile }) {
  if (!outputFile.endsWith('.js')) throw Error('Use a .js output module.');
  const baseline = await regularBytes(baselineFile), deployment = JSON.parse(await regularBytes(deploymentFile, 128000));
  if (!deployment.activeVersionVerified || !deployment.statefulApiVerified || deployment.moduleSha256 !== digest(baseline) || deployment.release !== digest(baseline).slice(0, 12)) throw Error('Existing module does not match the verified production deployment.');
  const before = embeddedAssets(baseline.toString()), updates = await frontend(dist), assets = { ...before.assets };
  for (const [name, bytes] of Object.entries(updates)) assets[name] = encoded(bytes);
  const replacement = '{' + Object.entries(assets).map(([name, value]) => JSON.stringify(name) + ':' + (Object.hasOwn(updates, name) ? JSON.stringify(value) : before.rawValues[name])).join(',') + '}';
  const module = Buffer.from(baseline.toString().slice(0, before.start) + replacement + baseline.toString().slice(before.end));
  // Actual credential-bearing metadata is checked again by workerUpload at
  // publication. Reserve space here without reading any runtime bindings.
  if (module.toString('base64').length + 32768 > 4_000_000) throw Error('Frontend candidate exceeds the conservative connected-upload budget.');
  const proof = { schemaVersion: 1, kind: 'agent_console_frontend_only', builtAt: new Date().toISOString(), baselineFile: path.resolve(baselineFile), deploymentFile: path.resolve(deploymentFile),
    previousVersionId: deployment.versionId, previousVersion: deployment.version, previousRelease: deployment.release,
    baselineSha256: digest(baseline), moduleSha256: digest(module), release: digest(module).slice(0, 12), backendUnchanged: true, backendSha256: digest(before.backend),
    priorAssetCount: Object.keys(before.assets).length, priorAssetsRetained: true, priorSkillsAndDownloadsPreserved: true,
    frontendPaths: Object.keys(updates), frontendSha256: Object.fromEntries(Object.entries(updates).map(([name, bytes]) => [name, digest(bytes)])),
    scope: 'Embedded index.html and frontend JS/CSS only; all backend bytes and prior assets, skills, downloads and client manifests retained.' };
  await writeFile(outputFile, module, { mode: 0o600, flag: 'wx' });
  await writeFile(proofPath(outputFile), JSON.stringify(proof, null, 2)+'\n', { mode: 0o600, flag: 'wx' });
  await inspectAgentConsoleCandidate(outputFile);
  return proof;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [baselineFile, deploymentFile, dist, outputFile] = process.argv.slice(2);
  if (!outputFile || process.argv.length !== 6) throw Error('Usage: node scripts/build-agent-console-release.mjs LIVE_MODULE VERIFIED_DEPLOYMENT DIST OUTPUT.js');
  console.log(JSON.stringify(await buildAgentConsoleCandidate({ baselineFile, deploymentFile, dist, outputFile })));
}
