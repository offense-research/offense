import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const policyFile = new URL('../../.github/offense/dependency-policy.json', import.meta.url);
export const loadPolicy = async () => JSON.parse(await readFile(policyFile, 'utf8'));
export function minorUpgrade(from, to) {
  const parse = value => /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value || '') ? value.split('.').map(Number) : null;
  const a = parse(from), b = parse(to);
  return !!(a && b && a[0] === b[0] && (a[0] !== 0 || a[1] === b[1]) &&
    (b[1] > a[1] || (b[1] === a[1] && b[2] > a[2])));
}
export function allowedPath(file, policy) {
  if (typeof file !== 'string' || !/^[A-Za-z0-9_./-]+$/.test(file) || file.split('/').some(p => !p || p.startsWith('.'))) return false;
  if (policy.lockfiles.includes(file) || policy.lockfiles.map(f => f.replace('package-lock.json', 'package.json')).includes(file)) return true;
  return policy.allowedSourcePrefixes.some(prefix => file.startsWith(prefix)) && /\.[cm]?[jt]sx?$/.test(file) && !/(^|\/)(test|tests|__tests__)\/|\.(test|spec)\./.test(file);
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
  for (const entry of Object.values(lock.packages)) {
    if (entry.resolved && !entry.link) {
      const url = new URL(entry.resolved);
      if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password) throw Error('Only public npm registry artifacts are allowed.');
      if (!/^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(entry.integrity || '')) throw Error('Registry artifact integrity is required.');
    }
  }
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
  for (const file of policy.lockfiles) validateLock(JSON.parse(await readFile(path.join(directory, file), 'utf8')));
  return { ...metadata, warnings: [], reviewedExclusions: policy.dependencyFreeManifests };
}
