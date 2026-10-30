import { pnpmGraph } from '../public/skills/purple/scripts/pnpm.mjs';

function packageName(location, entry) {
  if (entry.name) return entry.name;
  const offset = location.lastIndexOf('node_modules/');
  return offset < 0 ? '' : location.slice(offset + 'node_modules/'.length);
}

export function mapDependencies(files) {
  const packages = new Map();
  const warnings = [];
  function add(name, version, kind, file, resolved) {
    if (typeof name !== 'string' || typeof version !== 'string' || !name || !version || name.length > 214 || version.length > 200) {
      warnings.push(`${file} contains an unsupported dependency declaration; no version was inferred.`); return;
    }
    const key = `${name}\0${version}\0${resolved}`;
    const previous = packages.get(key);
    if (previous) {
      if (kind === 'runtime' || (kind === 'development' && previous.kind === 'transitive')) previous.kind = kind;
      if (!previous.files.includes(file)) previous.files.push(file);
    } else packages.set(key, { name, version, kind, resolved, files: [file] });
  }
  for (const file of files) {
    if (file.path.endsWith('pnpm-lock.yaml')) {
      try { const result = pnpmGraph(file); for (const item of result.packages) add(item.name, item.version, item.kind, file.path, true); warnings.push(...result.warnings); }
      catch (error) { warnings.push(error.message); }
      continue;
    }
    let manifest;
    try { manifest = JSON.parse(file.content); }
    catch { warnings.push(`${file.path} is not valid JSON.`); continue; }
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) { warnings.push(`${file.path} must contain a JSON object.`); continue; }
    if (file.path.endsWith('package.json') && !file.path.endsWith('package-lock.json')) {
      for (const [field, kind] of [['dependencies', 'runtime'], ['devDependencies', 'development'], ['optionalDependencies', 'runtime'], ['peerDependencies', 'peer']]) {
        if (manifest[field] === undefined) continue;
        if (!manifest[field] || typeof manifest[field] !== 'object' || Array.isArray(manifest[field])) { warnings.push(`${file.path}: ${field} must contain dependency declarations.`); continue; }
        for (const [name, version] of Object.entries(manifest[field])) add(name, version, kind, file.path, false);
      }
      continue;
    }
    const root = manifest.packages?.[''] || {};
    const runtime = new Set([...Object.keys(root.dependencies || {}), ...Object.keys(root.optionalDependencies || {})]);
    const development = new Set(Object.keys(root.devDependencies || {}));
    if (manifest.packages) {
      for (const [location, entry] of Object.entries(manifest.packages)) {
        if (!location.includes('node_modules/') || !entry?.version || entry.link) continue;
        const name = packageName(location, entry);
        const kind = runtime.has(name) ? 'runtime' : development.has(name) ? 'development' : 'transitive';
        add(name, entry.version, kind, file.path, true);
      }
    } else if (manifest.dependencies) {
      function walk(dependencies, direct = false) {
        for (const [name, entry] of Object.entries(dependencies || {})) {
          if (!entry || typeof entry !== 'object') continue;
          add(name, entry.version, direct ? entry.dev ? 'development' : 'runtime' : 'transitive', file.path, true);
          walk(entry.dependencies);
        }
      }
      walk(manifest.dependencies, true);
    }
  }
  return { packages: [...packages.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)), warnings };
}

