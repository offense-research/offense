import { parseDocument, stringify } from './yaml.mjs';
export { stringify as stringifyYaml };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const namePattern = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;
const exact = '\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?';
const identity = new RegExp(`^((?:@[a-z0-9._-]+/)?[a-z0-9._-]+)@(${exact})(.*)$`, 'i');
const referenceCharacters = /^[a-z0-9@._/+()=\-]+$/i;
const rangeCharacters = /^(?:(?:workspace|catalog):)?[0-9A-Za-z.*~^<>=| +_\-]*$/;
function aliasTarget(value) { return typeof value === 'string' ? value.match(/^npm:((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)@(.+)$/i) : null; }
const safePath = value => typeof value === 'string' && value.length <= 240 &&
  (value === '.' || /^[a-z0-9@._/\-]+$/i.test(value) && !value.split('/').some(part => !part || part === '.' || part === '..'));

export function parseYaml(text) {
  if (typeof text !== 'string' || text.length > 12_000_000) throw new Error('YAML input exceeds 12 MB.');
  const document = parseDocument(text, { uniqueKeys: true, strict: true });
  if (document.errors.length) throw new Error(`Invalid YAML: ${document.errors[0].message.slice(0, 180)}`);
  return document.toJS({ maxAliasCount: 0 });
}
export function pnpmIdentity(key) {
  if (typeof key !== 'string' || key.length > 1500 || !referenceCharacters.test(key)) return null;
  key = key.replace(/^\//, '');
  const match = key.match(identity);
  if (!match || (match[3] && !match[3].startsWith('('))) return null;
  return { key, name: match[1], version: match[2] };
}
function dependencyRef(name, ref) {
  if (typeof ref !== 'string') return null;
  if (ref.startsWith('link:')) {
    const target = ref.slice(5);
    return target.length <= 240 && /^[a-z0-9@._/\-]+$/i.test(target) && !target.startsWith('/') ? ref : null;
  }
  return pnpmIdentity(ref)?.key || pnpmIdentity(`${name}@${ref}`)?.key || null;
}

// Preserve pnpm snapshot identities, but never serialize resolution URLs or scripts.
export function normalizePnpm(file) {
  let lock = file.content;
  if (typeof lock === 'string') {
    try { lock = JSON.parse(lock); } catch { lock = parseYaml(lock); }
  }
  const major = Number.parseInt(lock?.lockfileVersion, 10);
  if (!object(lock) || ![6, 9].includes(major) || !object(lock.packages || {}) || !object(lock.importers || {})) {
    throw new Error(`${file.path}: supported pnpm lockfile versions are 6 and 9.`);
  }
  if (major === 9 && !object(lock.snapshots)) throw new Error(`${file.path}: pnpm v9 snapshots are missing.`);
  if (Object.keys(lock.importers || {}).length > 200) throw new Error('pnpm workspace exceeds 200 importers.');
  const warnings = [], importers = Object.create(null), packages = Object.create(null), snapshots = Object.create(null), catalogs = Object.create(null);
  const warn = text => warnings.push(`${file.path}: ${text}`);
  let count = 0;
  function constraints(values) {
    const clean = Object.create(null);
    if (!values) return clean;
    if (!object(values)) throw new Error('Invalid pnpm dependency constraints.');
    for (const [name, value] of Object.entries(values)) {
      const alias = aliasTarget(value);
      if (!namePattern.test(name) || name.length > 214 || typeof value !== 'string' || value.length > 200 || !(rangeCharacters.test(value) || alias && rangeCharacters.test(alias[2]))) { warn('unsupported dependency constraint omitted.'); continue; }
      clean[name] = value;
    }
    return clean;
  }
  for (const [catalog, values] of Object.entries(lock.catalogs || {})) {
    if (!/^[a-z0-9._-]{1,100}$/i.test(catalog) || !object(values)) throw new Error('Invalid pnpm catalog.');
    catalogs[catalog] = Object.create(null);
    for (const [name, item] of Object.entries(values)) {
      const range = constraints({ [name]: item?.specifier });
      if (Object.hasOwn(range, name)) catalogs[catalog][name] = { specifier: range[name] };
    }
  }
  for (const [key, value] of Object.entries(lock.packages || {})) {
    if (++count > 5000) throw new Error('pnpm lockfile exceeds 5,000 package entries.');
    const parsed = pnpmIdentity(key);
    if (!parsed || !object(value)) { warn('non-registry or unsupported package snapshot omitted.'); continue; }
    packages[parsed.key] = { peerDependencies: constraints(value.peerDependencies) };
    if (parsed.key.includes('patch_hash=')) warn(`${parsed.name} has a local patch; inspect its applicability separately.`);
  }
  function refs(values) {
    const clean = Object.create(null);
    if (!values) return clean;
    if (!object(values)) throw new Error('Invalid pnpm snapshot dependencies.');
    for (const [name, value] of Object.entries(values)) {
      if (!namePattern.test(name) || name.length > 214) throw new Error('Invalid pnpm dependency name.');
      const ref = dependencyRef(name, value);
      if (!ref) { warn(`${name}: unsupported dependency reference omitted.`); continue; }
      clean[name] = ref;
    }
    return clean;
  }
  let snapshotCount = 0;
  for (const [key, value] of Object.entries(major === 9 || lock.purpleFormat === 1 ? lock.snapshots : lock.packages || {})) {
    if (++snapshotCount > 5000) throw new Error('pnpm lockfile exceeds 5,000 snapshot entries.');
    const parsed = pnpmIdentity(key);
    if (!parsed || !object(value)) continue;
    snapshots[parsed.key] = { dependencies: refs(value.dependencies), optionalDependencies: refs(value.optionalDependencies) };
  }
  const sourceImporters = lock.importers && Object.keys(lock.importers).length ? lock.importers : major === 6 ? { '.': lock } : {};
  for (const [location, value] of Object.entries(sourceImporters)) {
    if (++count > 10200 || !safePath(location) || !object(value)) throw new Error('Invalid or excessive pnpm workspace importers.');
    const result = Object.create(null);
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      result[field] = Object.create(null);
      if (value[field] && !object(value[field])) throw new Error('Invalid pnpm importer dependencies.');
      for (const [name, item] of Object.entries(value[field] || {})) {
        if (!namePattern.test(name) || name.length > 214 || !object(item)) { warn('unsupported pnpm importer entry omitted.'); continue; }
        const ref = dependencyRef(aliasTarget(item.specifier)?.[1] || name, item.version);
        const declared = constraints({ [name]: item.specifier });
        if (!ref || !Object.hasOwn(declared, name)) { warn(`${name}: unsupported importer dependency omitted.`); continue; }
        result[field][name] = { specifier: declared[name], version: ref };
      }
    }
    importers[location] = result;
  }
  if (!Object.keys(importers).length) warn('no workspace importers found; direct dependency coverage is incomplete.');
  return { lock: { purpleFormat: 1, lockfileVersion: major, importers, packages, snapshots, catalogs }, warnings: [...new Set(warnings)] };
}

export function pnpmGraph(file) {
  const { lock, warnings } = normalizePnpm(file), nodes = [], prefix = `${file.path}:`;
  const importerId = name => `${prefix}importer:${name}`;
  function resolve(ref, importer) {
    if (!ref.startsWith('link:')) return lock.snapshots[ref] ? `${prefix}${ref}` : null;
    const segments = importer === '.' ? [] : importer.split('/');
    for (const part of ref.slice(5).split('/')) {
      if (part === '..') { if (!segments.length) return null; segments.pop(); }
      else if (part && part !== '.') segments.push(part);
    }
    const target = segments.join('/') || '.';
    return lock.importers[target] ? importerId(target) : null;
  }
  for (const [location, entry] of Object.entries(lock.importers)) {
    const requires = [];
    for (const [field, type] of [['dependencies', 'runtime'], ['devDependencies', 'development'], ['optionalDependencies', 'optional']]) {
      for (const [name, item] of Object.entries(entry[field])) {
        const catalog = item.specifier.startsWith('catalog:') ? item.specifier.slice(8) || 'default' : null;
        const range = catalog ? lock.catalogs[catalog]?.[name]?.specifier || null : item.specifier.startsWith('workspace:') ? null : aliasTarget(item.specifier)?.[2] || item.specifier;
        const to = resolve(item.version, location);
        if (!to) warnings.push(`${file.path}: unresolved dependency ${name} in importer ${location}.`);
        requires.push({ name, range, declaredRange: item.specifier, type, to, catalog });
      }
    }
    nodes.push({ id: importerId(location), path: '', workspace: location, file: file.path,
      name: location === '.' ? 'application' : `workspace:${location}`, version: '', requires });
  }
  for (const [key, entry] of Object.entries(lock.snapshots)) {
    const parsed = pnpmIdentity(key), packageKey = `${parsed.name}@${parsed.version}`;
    const peers = lock.packages[key]?.peerDependencies || lock.packages[packageKey]?.peerDependencies || {};
    const requires = [];
    for (const [field, type] of [['dependencies', 'runtime'], ['optionalDependencies', 'optional']]) {
      for (const [name, ref] of Object.entries(entry[field])) {
        const to = resolve(ref, '.');
        if (!to) warnings.push(`${file.path}: unresolved dependency ${name} in ${parsed.name}.`);
        requires.push({ name, range: peers[name] || null, type: peers[name] ? 'peer' : type, to });
      }
    }
    nodes.push({ id: `${prefix}${key}`, path: key, file: file.path, name: parsed.name, version: parsed.version, requires });
  }
  // v9 packages without snapshots still have exact versions worth checking.
  const seen = new Set(nodes.filter(node => node.path).map(node => `${node.name}@${node.version}`));
  for (const key of Object.keys(lock.packages)) {
    const parsed = pnpmIdentity(key);
    if (!seen.has(`${parsed.name}@${parsed.version}`)) {
      warnings.push(`${file.path}: ${parsed.name}@${parsed.version} has no dependency snapshot.`);
      nodes.push({ id: `${prefix}unresolved:${key}`, path: key, file: file.path, name: parsed.name, version: parsed.version, requires: [] });
    }
  }
  const kinds = new Map();
  for (const node of nodes.filter(node => !node.path)) for (const edge of node.requires) {
    if (!edge.to) continue;
    const kind = edge.type === 'development' ? 'development' : 'runtime';
    if (kind === 'runtime' || !kinds.has(edge.to)) kinds.set(edge.to, kind);
  }
  const packages = nodes.filter(node => node.path).map(node => ({ name: node.name, version: node.version,
    kind: kinds.get(node.id) || 'transitive', resolved: true, files: [file.path] }));
  return { nodes, packages, warnings: [...new Set(warnings)] };
}
