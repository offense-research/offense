// Validate the exact frontend-only artifact offline. No account, billing,
// scanner, provider or production requests are made by these checks.
import vm from 'node:vm';
import { builtinModules } from 'node:module';
import { webcrypto } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectAgentConsoleCandidate, assetBytes, digest } from './build-agent-console-release.mjs';

export async function verifyAgentConsoleArtifact(artifactFile) {
  const candidate = await inspectAgentConsoleCandidate(artifactFile), { module: bytes, proof, before, after, proofBytes } = candidate;
  const report = { passed: false, checkedAt: new Date().toISOString(), artifactSha256: digest(bytes), proofSha256: digest(proofBytes), baselineSha256: proof.baselineSha256,
    backendSha256: proof.backendSha256, frontendPaths: proof.frontendPaths, checks: [], outboundRequests: 0 };
  report.checks.push('Every backend byte outside the embedded static asset object is unchanged.');
  report.checks.push('All prior skills, downloads, manifests, media and superseded frontend assets are retained exactly.');
  const index = assetBytes(after.assets['/index.html']).toString();
  const references = [...index.matchAll(/(?:src|href)=["'](\/assets\/[^"']+)["']/g)].map(match => match[1]);
  if (!references.length || references.some(name => !Object.hasOwn(after.assets, name) || !proof.frontendPaths.includes(name))) throw Error('The new index references an absent or unreviewed asset.');
  const scriptText = proof.frontendPaths.filter(name => name.endsWith('.js')).map(name => assetBytes(after.assets[name]).toString()).join('\n');
  for (const marker of ['Get started', 'API keys', 'Usage', 'Billing', 'Settings', '/legacy']) if (!scriptText.includes(marker)) throw Error('The reviewed console frontend is missing a required release marker.');
  const safeProcess = new Proxy(process, { get(target, key) { if (key === 'env') return { NODE_ENV: 'test' };const value = Reflect.get(target, key);return typeof value === 'function' ? value.bind(target) : value; } });
  const context = vm.createContext({ console, Buffer, process: safeProcess, fetch() { report.outboundRequests++;throw Error('Artifact validation cannot make outbound requests.'); }, Request, Response, Headers, URL, URLSearchParams,
    AbortController, AbortSignal, TextEncoder, TextDecoder, TextEncoderStream, TextDecoderStream, TransformStream, ReadableStream, WritableStream, DecompressionStream,
    Blob, File, FormData, crypto: webcrypto, performance, setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate, queueMicrotask, atob, btoa, structuredClone },
  { name: 'agent-console-artifact', codeGeneration: { strings: false, wasm: false } });
  const builtins = new Set(builtinModules.flatMap(name => [name, name.replace(/^node:/, '')])), cache = new Map();
  const worker = new vm.SourceTextModule(bytes.toString(), { context, identifier: path.resolve(artifactFile), initializeImportMeta(meta) { meta.url = 'file://' + path.resolve(artifactFile); }, importModuleDynamically() { throw Error('Unexpected dynamic import.'); } });
  await worker.link(async specifier => {
    if (cache.has(specifier)) return cache.get(specifier);
    let namespace;
    if (specifier === 'cloudflare:workers') namespace = { DurableObject: class { constructor(ctx, env) { this.ctx = ctx;this.env = env; } } };
    else if (specifier === 'cloudflare:node') namespace = { httpServerHandler() { throw Error('Static verification must not start a Cloudflare bridge.'); } };
    else { if (!specifier.startsWith('node:') && !builtins.has(specifier)) throw Error('Unexpected non-builtin external module.');namespace = await import(specifier); }
    const names = Object.keys(namespace), linked = new vm.SyntheticModule(names, function() { for (const name of names) this.setExport(name, namespace[name]); }, { context, identifier: specifier });cache.set(specifier, linked);return linked;
  });
  await worker.evaluate({ timeout: 15000 });
  for (const route of ['/app', '/account', '/billing', '/legacy', '/legacy/']) {
    const response = await worker.namespace.default.fetch(new Request('https://app.example' + route), {}, {});
    if (response.status !== 200 || !response.headers.get('content-type')?.startsWith('text/html') || response.headers.get('cache-control') !== 'no-store' || await response.text() !== index) throw Error('Candidate does not serve the exact new index at ' + route);
  }
  for (const name of proof.frontendPaths.filter(name => name !== '/index.html')) {
    const response = await worker.namespace.default.fetch(new Request('https://app.example' + name), {}, {});
    if (response.status !== 200 || digest(Buffer.from(await response.arrayBuffer())) !== proof.frontendSha256[name]) throw Error('Candidate does not serve an exact reviewed frontend chunk.');
  }
  for (const [name, value] of Object.entries(before.assets).filter(([name]) => name.startsWith('/skills/'))) {
    const response = await worker.namespace.default.fetch(new Request('https://app.example' + name), {}, {});
    if (response.status !== 200 || digest(Buffer.from(await response.arrayBuffer())) !== digest(assetBytes(value))) throw Error('A previously published client resource changed.');
  }
  if (report.outboundRequests) throw Error('Unexpected outbound validation request.');
  report.checks.push('Actual module serves new no-store index at app/account/billing and exact legacy routes, plus every new frontend chunk.');
  report.checks.push('Actual module still serves every prior skill byte unchanged; embedded download/client assets are byte-identical and no local rebuilt client package is published.');
  report.passed = true;return report;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [artifact, output] = process.argv.slice(2);if (!artifact || !output) throw Error('Usage: node --experimental-vm-modules scripts/verify-agent-console-release.mjs CANDIDATE.js VALIDATION.json');
  const report = await verifyAgentConsoleArtifact(artifact);await writeFile(output, JSON.stringify(report, null, 2)+'\n', { mode: 0o600, flag: 'wx' });console.log(JSON.stringify(report));
}
