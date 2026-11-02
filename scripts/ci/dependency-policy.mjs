import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const policyFile = new URL('../../.github/offense/dependency-policy.json', import.meta.url);
export const loadPolicy = async () => JSON.parse(await readFile(policyFile, 'utf8'));
export function validateCheckMatrix(phase, policy) {
  const identity = items => items?.map(({ directory, command }) => ({ directory, command }));
  const setup = policy.lockfiles.map(file => ({ directory: path.posix.dirname(file), command: ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'] }));
  const sort = items => items?.toSorted((a, b) => a.directory.localeCompare(b.directory));
  if (!isDeepStrictEqual(sort(identity(phase?.setup)), sort(setup)) || !isDeepStrictEqual(identity(phase?.checks), policy.checks)) {
    throw Error('Verification did not run the full trusted install/check matrix.');
  }
}
export function minorUpgrade(from, to) {
  const parse = value => /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value || '') ? value.split('.').map(Number) : null;
  const a = parse(from), b = parse(to);
  return !!(a && b && a[0] === b[0] && (a[0] !== 0 || a[1] === b[1]) &&
    (b[1] > a[1] || (b[1] === a[1] && b[2] > a[2])));
}
export function allowedPath(file, policy) {
  if (typeof file !== 'string' || !/^[A-Za-z0-9_./-]+$/.test(file) || file.split('/').some(p => !p || p.startsWith('.'))) return false;
  if (policy.lockfiles.includes(file) || policy.lockfiles.map(f => f.replace('package-lock.json', 'package.json')).includes(file)) return true;
  return policy.allowedSourcePrefixes.some(prefix => file.startsWith(prefix)) && /\.[cm]?[jt]sx?$/.test(file) && !/(^|\/)(test|tests|__tests__)\/|(^|\/|\.)(test|spec)\./.test(file);
}
export function validateManifest(before, after) {
  const fields = ['dependencies', 'devDependencies', 'optionalDependencies', 'overrides'];
  const strip = value => Object.fromEntries(Object.entries(value).filter(([key]) => !fields.includes(key)));
  if (!isDeepStrictEqual(strip(before), strip(after))) throw Error('Package scripts, engines and other manifest policy must remain unchanged.');
  const inspect = (a, b) => {
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) || Array.isArray(b)) throw Error('Invalid dependency declaration.');
    if (!isDeepStrictEqual(Object.keys(a).sort(), Object.keys(b).sort())) throw Error('Adding/removing dependencies requires manual review.');
    for (const key of Object.keys(a)) {
      if (isDeepStrictEqual(a[key], b[key])) continue;
      if (typeof a[key] === 'object') inspect(a[key], b[key]);
      else if (typeof b[key] !== 'string' || !minorUpgrade(String(a[key]).replace(/^[~^]/, ''), b[key].replace(/^[~^]/, ''))) throw Error('Only stable patch/minor dependency upgrades are allowed.');
    }
  };
  for (const field of fields) inspect(before[field] || {}, after[field] || {});
}
export function validateLock(lock) {
  if (![2, 3].includes(lock.lockfileVersion) || !lock.packages) throw Error('Expected npm lockfile v2/v3.');
  for (const [location, entry] of Object.entries(lock.packages)) {
    if (location) {
      if (!location.includes('node_modules/') || entry.link || !entry.resolved || !entry.version) throw Error('Only resolved registry packages are supported by CI policy.');
      const url = new URL(entry.resolved);
      if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password) throw Error('Only public npm registry artifacts are allowed.');
      if (!/^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(entry.integrity || '')) throw Error('Registry artifact integrity is required.');
    }
  }
}
export async function validateRegistryArtifacts(lock, { fetchImpl = fetch } = {}) {
  validateLock(lock);
  const entries = [...new Map(Object.entries(lock.packages).filter(([location]) => location).map(([location, entry]) => {
    const name = entry.name || location.slice(location.lastIndexOf('node_modules/') + 13);
    return [JSON.stringify([name, entry.version, entry.resolved, entry.integrity]), { name, ...entry }];
  })).values()];
  if (entries.length > 5000) throw Error('Registry verification exceeds the package limit.');
  // Registry metadata is fetched by the controller, never supplied by the model.
  // A valid npm URL/SRI alone does not prove it contains the declared release.
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(8, entries.length) }, async () => {
    while (next < entries.length) {
      const entry = entries[next++];
      const response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(entry.name)}/${encodeURIComponent(entry.version)}`, { redirect: 'error', signal: AbortSignal.timeout(30000) });
      if (!response.ok) throw Error('Registry release identity could not be verified.');
      let bytes = 0;
      const chunks = [];
      for await (const chunk of response.body) {
        bytes += chunk.length;
        if (bytes > 1_000_000) throw Error('Registry release metadata exceeds its limit.');
        chunks.push(chunk);
      }
      const release = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (release.name !== entry.name || release.version !== entry.version || release.dist?.tarball !== entry.resolved || release.dist?.integrity !== entry.integrity) {
        throw Error('Lockfile artifact does not match the declared registry release.');
      }
    }
  }));
}
export async function reviewedCoverage(directory, metadata, policy) {
  const actual = metadata.files.map(f => f.path).sort();
  if (!isDeepStrictEqual(actual, [...policy.lockfiles].sort())) throw Error('Dependency inventory changed; review the trusted policy.');
  const exclusions = [];
  for (const file of policy.dependencyFreeManifests) {
    const manifest = JSON.parse(await readFile(path.join(directory, file), 'utf8'));
    if (['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'].some(key => Object.keys(manifest[key] || {}).length)) throw Error(`${file} now declares dependencies; add lockfile coverage.`);
    exclusions.push(`${file}: no covering lockfile importer was found; verify coverage.`);
  }
  const warnings = metadata.warnings.filter(w => !exclusions.includes(w));
  if (warnings.length) throw Error('Incomplete dependency coverage; review scan warnings.');
  for (const file of policy.lockfiles) await validateRegistryArtifacts(JSON.parse(await readFile(path.join(directory, file), 'utf8')));
  return { ...metadata, warnings: [], reviewedExclusions: policy.dependencyFreeManifests };
}
