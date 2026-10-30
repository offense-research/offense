import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// BugPatrol 0.3.0 declares Zod 3, although its MCP SDK supports Zod 4.
// Migrate its consumer APIs before using the scoped Zod 4 override. Never alter
// Zod itself or automatically adapt an unreviewed future BugPatrol release.
export const BUGPATROL_VERSION = '0.3.0';
export const ZOD_VERSION = '4.6.6';
export const ORIGINAL_BUNDLE_SHA256 = 'ec3cd27ee20fecd8de1c34a06ebddf40f35b9d2219827ef86b1f5a4d55f297fe';
export const PATCHED_BUNDLE_SHA256 = '3b2a0f371249958dfd43ff46ea2a434195a8de2a63d625ca9e805599fb39f6d1';

const replacements = [
  ['z.record(z.unknown())', 'z.record(z.string(), z.unknown())', 1],
  ['z.record(z.string())', 'z.record(z.string(), z.string())', 2],
  ['z5.record(z5.string()).optional()', 'z5.record(z5.string(), z5.string()).optional()', 1],
  // Zod 4 defaults short-circuit parsing. Prefaults preserve Zod 3's nested
  // defaults and runtimeFor's preprocessing/CLI command generation.
  ['.default({})', '.prefault({})', 28],
  ['.default(fallback)', '.prefault(fallback)', 1],
  ['errorMap: () => ({', 'error: () => ({', 1],
];

const sha256 = source => createHash('sha256').update(source).digest('hex');

export function patchBugpatrolBundle(source) {
  const digest = sha256(source);
  if (digest === PATCHED_BUNDLE_SHA256) return { source, changed: false };
  if (digest !== ORIGINAL_BUNDLE_SHA256) {
    throw new Error('BugPatrol bundle differs from reviewed 0.3.0; review its Zod APIs before updating the compatibility patch.');
  }
  let patched = source;
  for (const [before, after, expected] of replacements) {
    const actual = patched.split(before).length - 1;
    if (actual !== expected) throw new Error(`Unexpected BugPatrol patch count: ${before} (${actual}, expected ${expected}).`);
    patched = patched.split(before).join(after);
  }
  if (sha256(patched) !== PATCHED_BUNDLE_SHA256) throw new Error('BugPatrol compatibility patch produced an unexpected digest.');
  return { source: patched, changed: true };
}

export function patchInstalledBugpatrol(projectRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)))) {
  const require = createRequire(path.join(projectRoot, 'package.json'));
  let manifestPath;
  try {
    manifestPath = require.resolve('bugpatrol/package.json');
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') return { skipped: true, reason: 'BugPatrol is not installed (production dependencies only).' };
    throw error;
  }
  const relativeManifest = path.relative(path.resolve(projectRoot, 'node_modules'), manifestPath);
  if (relativeManifest.startsWith('..') || path.isAbsolute(relativeManifest)) {
    throw new Error('Refusing to patch BugPatrol outside this project’s node_modules directory.');
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (manifest.version !== BUGPATROL_VERSION) {
    throw new Error(`BugPatrol ${manifest.version} has not been reviewed for the Zod compatibility patch.`);
  }
  const bugpatrolRequire = createRequire(manifestPath);
  const zod = bugpatrolRequire('zod/package.json');
  if (zod.version !== ZOD_VERSION) {
    throw new Error(`BugPatrol must resolve reviewed Zod ${ZOD_VERSION}, found ${zod.version}.`);
  }
  const bundlePath = path.join(path.dirname(manifestPath), 'dist/bin.js');
  if (!lstatSync(bundlePath).isFile() || lstatSync(bundlePath).isSymbolicLink()) {
    throw new Error('Refusing to patch an unexpected BugPatrol bundle file.');
  }
  const patched = patchBugpatrolBundle(readFileSync(bundlePath, 'utf8'));
  if (patched.changed) writeFileSync(bundlePath, patched.source);
  return { skipped: false, changed: patched.changed, version: manifest.version, zodVersion: zod.version };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const result = patchInstalledBugpatrol();
    console.log(result.skipped ? result.reason : `BugPatrol ${result.version}: Zod ${result.zodVersion} compatibility patch ${result.changed ? 'applied' : 'already applied'}.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
