// Shared by the thin client and hosted API. Never send raw lockfiles.
import { normalizePnpm } from './pnpm.mjs';
const packageName = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;
const version = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;
const range = /^(?:workspace:)?[0-9A-Za-z.*~^<>=| +\-]+$/;
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const relative = value => typeof value === 'string' && value.length <= 240 &&
  !value.startsWith('/') && !value.split('/').some(part => !part || part === '.' || part === '..') &&
  /^[a-z0-9@._/\-]+$/i.test(value);

export function sanitizeLockfiles(files) {
  if (!Array.isArray(files) || !files.length || files.length > 20) throw new Error('Provide between 1 and 20 npm or pnpm lockfiles.');
  let count = 0;
  const seen = new Set(), warnings = [];
  const clean = files.map(file => {
    if (!object(file) || !relative(file.path) || !/(^|\/)(?:(?:package-lock|npm-shrinkwrap)\.json|pnpm-lock\.yaml)$/.test(file.path) || seen.has(file.path)) {
      throw new Error('Lockfiles need unique, relative npm or pnpm lockfile paths.');
    }
    seen.add(file.path);
    if (file.path.endsWith('pnpm-lock.yaml')) {
      const result = normalizePnpm(file);
      count += Object.keys(result.lock.snapshots).length;
      if (count > 5000) throw new Error('This scan exceeds 5,000 lockfile entries. Scan a smaller project.');
      warnings.push(...result.warnings);
      return { path: file.path, content: JSON.stringify(result.lock) };
    }
    const lock = typeof file.content === 'string' ? JSON.parse(file.content) : file.content;
    if (!object(lock) || ![2, 3].includes(lock.lockfileVersion) || !object(lock.packages)) {
      throw new Error(`${file.path}: npm lockfile v2 or v3 is required. Other formats are not scanned.`);
    }
    const packages = Object.create(null);
    for (const [location, entry] of Object.entries(lock.packages)) {
      if (++count > 5000) throw new Error('This scan exceeds 5,000 lockfile entries. Scan a smaller project.');
      if ((location && !relative(location)) || !object(entry)) throw new Error('Invalid lockfile package entry.');
      if (entry.link) { warnings.push(`${file.path}: workspace link ${location} needs local reachability review.`); continue; }
      if (location && (!version.test(entry.version || '') || entry.version.length > 100)) {
        warnings.push(`${file.path}: ${location} has no supported exact npm version.`); continue;
      }
      const cleanEntry = { ...(location ? { version: entry.version } : {}) };
      if (location && packageName.test(entry.name || '') && entry.name.length <= 214) cleanEntry.name = entry.name;
      for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
        if (entry[field] === undefined) continue;
        if (!object(entry[field])) throw new Error(`Invalid ${field} metadata.`);
        const dependencies = Object.create(null);
        for (const [name, constraint] of Object.entries(entry[field])) {
          if (!packageName.test(name) || name.length > 214 || typeof constraint !== 'string' || constraint.length > 200 || !range.test(constraint)) {
            warnings.push(`${file.path}: a non-registry or unsupported ${field} constraint was omitted.`); continue;
          }
          dependencies[name] = constraint;
        }
        cleanEntry[field] = dependencies;
      }
      if (entry.dev === true) cleanEntry.dev = true;
      packages[location] = cleanEntry;
    }
    return { path: file.path, content: JSON.stringify({ lockfileVersion: lock.lockfileVersion, packages }) };
  });
  if (JSON.stringify(clean).length > 2_000_000) throw new Error('Dependency metadata exceeds the 2 MB scan limit.');
  return { files: clean, warnings: [...new Set(warnings)] };
}
