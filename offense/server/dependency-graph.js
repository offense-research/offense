import semver from 'semver';
import { pnpmGraph } from '../public/skills/purple/scripts/pnpm.mjs';

function nameForPath(location, entry) {
  if (entry.name) return entry.name;
  const offset = location.lastIndexOf('node_modules/');
  return offset < 0 ? '' : location.slice(offset + 'node_modules/'.length);
}

export function buildDependencyGraph(files) {
  const nodes = [];
  const warnings = [];
  for (const file of files) {
    if (file.path.endsWith('pnpm-lock.yaml')) {
      try { const result = pnpmGraph(file); nodes.push(...result.nodes); warnings.push(...result.warnings); }
      catch (error) { warnings.push(error.message); }
      continue;
    }
    if (!/(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(file.path)) continue;
    let lock;
    try { lock = JSON.parse(file.content); }
    catch { continue; }
    if (!lock.packages || Object.keys(lock.packages).length > 10000) {
      warnings.push(`${file.path} has no supported npm package tree.`);
      continue;
    }
    const prefix = `${file.path}:`;
    const locations = new Map(Object.entries(lock.packages));
    function resolve(from, name) {
      let base = from;
      for (;;) {
        const candidate = `${base ? `${base}/` : ''}node_modules/${name}`;
        if (locations.has(candidate)) return `${prefix}${candidate}`;
        if (!base) return null;
        const marker = base.lastIndexOf('/node_modules/');
        if (marker >= 0) base = base.slice(0, marker);
        else if (base.startsWith('node_modules/')) base = '';
        else base = base.includes('/') ? base.slice(0, base.lastIndexOf('/')) : '';
      }
    }
    for (const [location, entry] of locations) {
      if (!entry || typeof entry !== 'object' || entry.link) continue;
      const name = location ? nameForPath(location, entry) : lock.name || 'application';
      if (!name) continue;
      const requires = [];
      for (const [field, type] of [['dependencies', 'runtime'], ['optionalDependencies', 'optional'],
        ['peerDependencies', 'peer'], ...(location ? [] : [['devDependencies', 'development']])]) {
        for (const [dependency, range] of Object.entries(entry[field] || {})) {
          requires.push({ name: dependency, range, type, to: resolve(location, dependency) });
        }
      }
      nodes.push({ id: `${prefix}${location}`, path: location, file: file.path, name,
        version: entry.version || '', requires });
    }
  }
  return { nodes, warnings };
}

export function dependencyImpact(graph, name, version, targetVersion) {
  const nodes = new Map((graph?.nodes || []).map(node => [node.id, node]));
  const targets = [...nodes.values()].filter(node => node.name === name && node.version === version);
  const incoming = new Map();
  for (const node of nodes.values()) for (const edge of node.requires) {
    if (!edge.to || !nodes.has(edge.to)) continue;
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to).push({ node, edge });
  }
  const parents = [];
  const paths = [];
  const truncationReasons = new Set();
  let traversed = 0;
  for (const target of targets) {
    for (const { node, edge } of incoming.get(target.id) || []) {
      const range = semver.validRange(edge.range);
      parents.push({ name: node.name, version: node.version, range: edge.range, type: edge.type,
        compatible: range ? semver.satisfies(targetVersion, range) : null, file: target.file,
        isRoot: node.path === '', ...(edge.range == null ? { rangeSource: 'registry_lookup_required' } : {}),
        ...(node.workspace ? { workspace: node.workspace } : {}) });
    }
    const queue = [{ id: target.id, path: [target.name], visited: new Set([target.id]) }];
    while (queue.length) {
      if (paths.length >= 20) { truncationReasons.add('path_limit'); break; }
      if (traversed >= 2000) { truncationReasons.add('traversal_limit'); break; }
      traversed++;
      const current = queue.shift();
      const upstream = incoming.get(current.id) || [];
      if (!upstream.length) { paths.push(current.path.toReversed()); continue; }
      // Already visited ancestors close a known cycle rather than extending
      // the path; do not mislabel that as an exhausted depth budget.
      const unexplored = upstream.filter(({ node }) => !current.visited.has(node.id));
      if (!unexplored.length) continue;
      if (current.path.length >= 8) {
        // Retain the visible suffix for navigation, but never present it as a
        // complete application-to-dependency path when ancestors remain.
        truncationReasons.add('depth_limit');
        paths.push(current.path.toReversed());
        continue;
      }
      for (const { node } of unexplored) {
        // Different installed versions may share a package name. Only an
        // actual repeated node is a cycle within this path.
        if (queue.length >= 2000) { truncationReasons.add('queue_limit'); break; }
        queue.push({ id: node.id, path: [...current.path, node.name], visited: new Set([...current.visited, node.id]) });
      }
    }
  }
  return { instances: targets.length, parents, paths,
    ...(truncationReasons.size ? { truncated: true, truncationReasons: [...truncationReasons] } : {}) };
}
