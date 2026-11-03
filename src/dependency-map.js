export function dependencyChoices(snapshot) {
  const findings = snapshot?.vulnerabilityCheck?.findings || [];
  const advisoriesByPackage = new Map();
  for (const finding of findings) {
    if (!advisoriesByPackage.has(finding.package)) advisoriesByPackage.set(finding.package, new Map());
    const versions = advisoriesByPackage.get(finding.package);
    if (!versions.has(finding.version)) versions.set(finding.version, new Map());
    versions.get(finding.version).set(finding.id, finding);
  }
  const choices = new Map();
  for (const item of [...findings.map(f => ({ name: f.package, version: f.version })), ...(snapshot?.packages || []).filter(p => p.resolved)]) {
    const key = JSON.stringify([item.name, item.version]);
    if (!choices.has(key)) choices.set(key, { key, name: item.name, version: item.version,
      advisories: [...(advisoriesByPackage.get(item.name)?.get(item.version)?.values() || [])] });
  }
  return [...choices.values()].sort((a, b) => b.advisories.length - a.advisories.length || a.name.localeCompare(b.name));
}

// Follow exact lockfile node IDs, preserving separate installed versions and files.
// Bound traversal so a large or cyclic dependency graph cannot overwhelm the UI.
export function dependencyMap(graph, name, version, { limit = 24, depth = 5 } = {}) {
  const all = new Map((graph?.nodes || []).map(node => [node.id, node]));
  const incoming = new Map();
  for (const node of all.values()) for (const edge of node.requires || []) {
    if (!edge.to || !all.has(edge.to)) continue;
    if (!incoming.has(edge.to)) incoming.set(edge.to, []);
    incoming.get(edge.to).push({ node, edge });
  }
  const focus = [...all.values()].filter(node => node.name === name && node.version === version);
  const selected = new Map(), queue = [];
  let truncated = focus.length > limit;
  for (const node of focus.slice(0, limit)) { selected.set(node.id, { ...node, distance: 0 }); queue.push(node.id); }
  for (let i = 0; i < queue.length; i++) {
    const node = selected.get(queue[i]);
    for (const { node: parent } of incoming.get(node.id) || []) {
      if (selected.has(parent.id)) continue;
      if (node.distance >= depth || selected.size >= limit) { truncated = true; continue; }
      selected.set(parent.id, { ...parent, distance: node.distance + 1 }); queue.push(parent.id);
    }
  }
  const maxDepth = Math.max(0, ...[...selected.values()].map(node => node.distance));
  const columns = Array.from({ length: maxDepth + 1 }, () => []);
  for (const node of selected.values()) columns[maxDepth - node.distance].push(node);
  const rows = Math.max(1, ...columns.map(column => column.length));
  const nodes = columns.flatMap((column, index) => column.map((node, row) => ({ ...node,
    x: 20 + index * 240, y: 38 + ((rows - column.length) / 2 + row) * 100, focus: node.name === name && node.version === version })));
  const byId = new Map(nodes.map(node => [node.id, node]));
  const edges = nodes.flatMap(node => (node.requires || []).filter(edge => byId.has(edge.to)).map((edge, i) => ({
    key: `${node.id}:${edge.to}:${i}`, from: node, to: byId.get(edge.to), range: edge.range, type: edge.type
  })));
  return { nodes, edges, truncated, width: Math.max(400, columns.length * 240), height: rows * 100 + 50,
    instances: focus.length, parents: new Set(focus.flatMap(node => (incoming.get(node.id) || []).map(item => item.node.id))).size };
}

export function resolutionAdvice(plan) {
  if (!plan) return { title: 'Check the upgrade path', steps: ['Check published fixed versions and parent constraints.', 'Copy one coordinated fix prompt for all advisories on this package.'] };
  if (plan.mitigation || !plan.targetVersion) return { title: 'A reviewed mitigation is needed', steps: plan.mitigation?.steps || ['No checked upgrade target is available. Ask your agent to evaluate a patch or replacement.'] };
  const blocked = plan.impact?.parents?.filter(parent => parent.compatible === false) || [];
  const parents = plan.parentOptions?.filter(option => option.version) || [];
  return { title: blocked.length ? 'Resolve the parent constraint first' : `Upgrade to ${plan.targetVersion}`, steps: [
    ...(blocked.length ? parents.length ? parents.map(parent => `Upgrade ${parent.parent}: ${parent.currentVersion} → ${parent.version}. ${parent.action || ''}`) :
      ['No compatible parent release was found. Have your agent review a scoped override, patch or replacement before changing the lockfile.'] : [`Update ${plan.name}: ${plan.currentVersion} → ${plan.targetVersion}.`]),
    ...(plan.majorChange ? ['Review breaking API changes for this major upgrade.'] : []),
    'Run repository checks and rescan the resolved versions before merging.'
  ] };
}
