import { readdir, realpath, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';
import { createOffenseClient, defaultAutomationPolicy, normalizeAutomationPolicy, evaluateSecurityPolicy } from './index.mjs';
export { assertSecurityDecision, SecurityGateError } from './index.mjs';

const excluded = new Set(['node_modules', 'vendor', 'dist', 'build', 'coverage']);
const supported = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml']);
const unsupported = new Set(['yarn.lock', 'bun.lock', 'bun.lockb', 'Cargo.lock', 'poetry.lock', 'uv.lock', 'go.sum', 'Gemfile.lock', 'composer.lock']);
const inside = (root, target) => target === root || target.startsWith(root + path.sep);

async function readBounded(handle, maximum) {
  const chunks = []; let length = 0;
  while (true) {
    const buffer = Buffer.alloc(Math.min(64_000, maximum - length + 1));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
    if (!bytesRead) return Buffer.concat(chunks, length).toString('utf8');
    length += bytesRead;
    if (length > maximum) throw Error('Dependency file exceeded the byte limit while reading.');
    chunks.push(buffer.subarray(0, bytesRead));
  }
}

export async function collectDependencyMetadata(directory) {
  if (typeof directory !== 'string' || !directory) throw Error('Choose an explicit project directory.');
  const root = await realpath(directory), files = [], manifests = [], warnings = [];
  let entries = 0, rawBytes = 0;
  async function walk(folder, depth = 0) {
    if (depth > 12) { warnings.push('Directory search depth was exceeded; some dependency files were not inspected.'); return; }
    if (!inside(root, await realpath(folder))) throw Error('A project directory changed during collection.');
    const listing = await readdir(folder, { withFileTypes: true });
    const shrinkwrap = listing.some(entry => entry.isFile() && entry.name === 'npm-shrinkwrap.json');
    for (const entry of listing.sort((a, b) => a.name.localeCompare(b.name))) {
      if (++entries > 30000) throw Error('Dependency collection exceeded the directory entry limit. Select a narrower project.');
      if (entry.name.startsWith('.') || excluded.has(entry.name)) continue;
      const target = path.join(folder, entry.name), relative = path.relative(root, target).split(path.sep).join('/');
      if (entry.isSymbolicLink()) { warnings.push(`${relative}: symlink was not followed; its dependency coverage is unknown.`); continue; }
      if (entry.isDirectory()) { await walk(target, depth + 1); continue; }
      if (!entry.isFile()) continue;
      if (entry.name === 'package.json') manifests.push(relative);
      if (unsupported.has(entry.name)) warnings.push(`${relative}: this lockfile format is not supported.`);
      if (!supported.has(entry.name) || shrinkwrap && entry.name === 'package-lock.json') continue;
      if (!inside(root, await realpath(target))) throw Error('A dependency file resolves outside the project.');
      const handle = await open(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
      try {
        const info = await handle.stat();
        if (!info.isFile() || info.size > 12_000_000 || rawBytes + info.size > 24_000_000) throw Error('Dependency files exceed the bounded collection size.');
        const content = await readBounded(handle, Math.min(12_000_000, 24_000_000 - rawBytes));
        rawBytes += Buffer.byteLength(content);
        files.push({ path: relative, content });
        if (files.length > 20) throw Error('More than 20 dependency lockfiles were found. Select a narrower project.');
      } finally { await handle.close(); }
    }
  }
  await walk(root);
  if (!files.length) throw Error('No supported resolved npm or pnpm lockfile was found. Generate and review a lockfile before running this check.');
  const clean = sanitizeLockfiles(files), covered = new Set();
  for (const file of clean.files) {
    const base = path.posix.dirname(file.path), lock = JSON.parse(file.content);
    if (file.path.endsWith('pnpm-lock.yaml')) for (const importer of Object.keys(lock.importers || {})) covered.add(path.posix.join(base, importer, 'package.json'));
    else {
      covered.add(path.posix.join(base, 'package.json'));
      for (const location of Object.keys(lock.packages || {})) if (location && !location.split('/').includes('node_modules')) covered.add(path.posix.join(base, location, 'package.json'));
    }
  }
  for (const manifest of manifests) if (!covered.has(manifest)) warnings.push(`${manifest}: no covering lockfile importer was found.`);
  return { files: clean.files, warnings: [...new Set([...warnings, ...clean.warnings])], inspectedLockfiles: clean.files.length };
}

export async function checkRepository({ directory, event = 'manual', policy = defaultAutomationPolicy(), client = createOffenseClient(), signal } = {}) {
  const configuration = normalizeAutomationPolicy(policy), initial = evaluateSecurityPolicy(null, configuration, event);
  if (initial.action === 'skip') return { report: null, decision: initial, durationMs: 0, localCoverage: { status: 'not_checked', warnings: [] } };
  const started = performance.now();
  let metadata;
  try { metadata = await collectDependencyMetadata(directory); }
  catch { return { report: null, decision: evaluateSecurityPolicy(null, configuration, event), durationMs: Math.round(performance.now() - started),
    error: { code: 'local_metadata_incomplete' }, localCoverage: { status: 'incomplete', warnings: ['Supported dependency metadata could not be collected completely. Check the project directory and resolved lockfiles.'] } }; }
  const result = await client.check({ files: metadata.files, event, policy: configuration, signal });
  if (result.report && metadata.warnings.length) {
    result.report = { ...result.report, status: 'partial', coverage: { ...result.report.coverage, status: 'partial',
      warnings: [...new Set([...result.report.coverage.warnings, ...metadata.warnings])] } };
    result.decision = evaluateSecurityPolicy(result.report, configuration, event);
  }
  return { ...result, durationMs: Math.round(performance.now() - started), localCoverage: {
    status: metadata.warnings.length ? 'incomplete' : 'complete', inspectedLockfiles: metadata.inspectedLockfiles, warnings: metadata.warnings } };
}
