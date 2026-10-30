// Static, local-only JS/TS analysis. This module never executes repository code.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { parse, traverse as babelTraverse } from './syntax.mjs';
import { pnpmGraph } from './pnpm.mjs';
const traverse = babelTraverse.default || babelTraverse;
const digest = value => createHash('sha256').update(value).digest('hex');
const advisoryHash = finding => digest(JSON.stringify([finding.id, finding.severity, finding.cves || [], finding.summary, finding.fixedVersions, finding.advisory || null]));
const keyOf = finding => `${finding.package}@${finding.version}:${finding.id}`;
const extensions = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];

// Explicit API mappings from reviewed advisories; do not guess affected symbols
// from prose or equate a package import with use of its vulnerable function.
export const builtinTargets = [
  { package: 'semver', ids: ['GHSA-c2qf-rxjj-qqgw', 'CVE-2022-25883'], symbols: ['Range', 'classes.range'],
    reference: 'https://github.com/advisories/GHSA-c2qf-rxjj-qqgw',
    prerequisites: 'Untrusted data must control the range passed to the constructor; inspect the range argument, not only the version string.' },
  { package: 'semver', ids: ['GHSA-c2qf-rxjj-qqgw', 'CVE-2022-25883'], versions: ['7.5.1'],
    symbols: ['satisfies', 'validRange', 'functions.satisfies', 'ranges.valid'],
    reference: 'https://github.com/advisories/GHSA-c2qf-rxjj-qqgw',
    implementationReferences: ['https://github.com/npm/node-semver/blob/v7.5.1/functions/satisfies.js', 'https://github.com/npm/node-semver/blob/v7.5.1/ranges/valid.js'],
    prerequisites: 'These reviewed wrappers construct Range in semver 7.5.1. Verify attacker control of the range argument; a constant range does not establish this ReDoS prerequisite.' },
  { package: 'lodash', ids: ['GHSA-35jh-r3h4-6jhm', 'CVE-2021-23337'], symbols: ['template'],
    reference: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm',
    prerequisites: 'Attacker influence over template compilation/options must be investigated; a call path alone does not demonstrate command injection.' },
  { package: 'lodash', ids: ['GHSA-p6mc-m468-83gw', 'CVE-2020-8203'], symbols: ['pick', 'set', 'setWith', 'update', 'updateWith', 'zipObjectDeep'],
    reference: 'https://github.com/advisories/GHSA-p6mc-m468-83gw',
    prerequisites: 'Check whether attacker-controlled property paths reach an affected operation; a call path alone does not demonstrate prototype pollution.' }
];

export function targetsFor(finding, custom = []) {
  const ids = new Set([finding.id, ...(finding.cves || []), ...(finding.advisory?.aliases || [])]);
  const builtin = builtinTargets.filter(item => item.package === finding.package && (!item.versions || item.versions.includes(finding.version)) && item.ids.some(id => ids.has(id)));
  const supplied = custom.filter(item => item.key === keyOf(finding));
  return [...builtin.map(item => ({ ...item, provenance: 'bundled_advisory_mapping' })), ...supplied.map(item => ({ ...item, provenance: 'reviewer_supplied_mapping' }))];
}

function installationResolver(files) {
  const locks = files.map(file => ({ file: file.path, base: path.posix.dirname(file.path),
    ...(file.path.endsWith('pnpm-lock.yaml') ? { graph: pnpmGraph(file) } : { lock: JSON.parse(file.content) }) }));
  return (sourceFile, specifier) => {
    const spec = specifier.split('/'), name = specifier.startsWith('@') ? spec.slice(0, 2).join('/') : spec[0];
    const owner = locks.filter(item => item.base === '.' || sourceFile.startsWith(`${item.base}/`)).sort((a, b) => (b.base === '.' ? 0 : b.base.length) - (a.base === '.' ? 0 : a.base.length))[0];
    if (!owner) return null;
    let directory = path.posix.dirname(path.posix.relative(owner.base, sourceFile));
    if (owner.graph) {
      const importers = owner.graph.nodes.filter(node => !node.path && (node.workspace === '.' || directory === node.workspace || directory.startsWith(`${node.workspace}/`)))
        .sort((a, b) => (b.workspace === '.' ? 0 : b.workspace.length) - (a.workspace === '.' ? 0 : a.workspace.length));
      // pnpm does not permit falling back to a sibling/root importer dependency.
      const importer = importers[0], edge = importer?.requires.find(item => item.name === name);
      const target = owner.graph.nodes.find(node => node.id === edge?.to);
      return target?.path ? { name: target.name, version: target.version, lockfile: owner.file, installation: target.id } : null;
    }
    for (;;) {
      const location = `${directory === '.' ? '' : `${directory}/`}node_modules/${name}`;
      const entry = owner.lock.packages?.[location];
      if (entry && !entry.link) return { name: entry.name || name, version: entry.version, lockfile: owner.file, installation: location };
      if (directory === '.') return null;
      const parent = path.posix.dirname(directory); if (parent === directory) return null; directory = parent;
    }
  };
}

export async function analyzeReachability(directory, { source, metadata, findings, targets = [], entries = [] } = {}) {
  if (!Array.isArray(targets) || targets.length > 200 || targets.some(item =>
    typeof item.key !== 'string' || !findings.some(f => keyOf(f) === item.key && item.advisoryFingerprint === advisoryHash(f)) || typeof item.reviewedBy !== 'string' || !item.reviewedBy.trim() || !Array.isArray(item.symbols) || !item.symbols.length || item.symbols.length > 30 ||
    item.symbols.some(symbol => typeof symbol !== 'string' || !/^(?:default|[A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)*$/.test(symbol)) ||
    typeof item.reference !== 'string' || !/^https:\/\//.test(item.reference) || typeof item.prerequisites !== 'string' || item.prerequisites.length < 20)) throw new Error('Affected API targets require a reviewer, advisory fingerprint, current finding key, static symbol paths, HTTPS advisory reference, and concrete prerequisites.');
  const modules = new Map(), functions = new Map(), edges = new Map(), roots = new Map(), calls = [], issues = [];
  const resolveInstallation = installationResolver(metadata.files);
  let visited = 0, edgeCount = 0;
  const issue = (file, line, reason) => { if (issues.length < 100) issues.push({ file, line, reason }); };
  const location = (file, p) => ({ file, line: p.node.loc?.start.line || 1 });
  const nodeId = (file, node) => `${file}:${node.start}`;
  function edge(from, to, at) {
    if (++edgeCount > 30000) throw new Error('Static analysis exceeds 30,000 call edges. Narrow the project.');
    if (!edges.has(from)) edges.set(from, []);
    edges.get(from).push({ to, ...at });
  }
  for (const file of source.files) {
    if (/\.(?:vue|svelte)$/.test(file.path)) issue(file.path, 1, 'Component single-file syntax is not analyzed.');
    if (!extensions.some(ext => file.path.endsWith(ext)) || /\.d\.[cm]?ts$/.test(file.path)) continue;
    if (modules.size >= 500) { issue(file.path, 1, 'Source module limit reached.'); break; }
    const text = await readFile(path.join(directory, file.path), 'utf8');
    if (digest(text) !== file.sha256) throw new Error('Source changed during reachability analysis. Retry triage.');
    try {
      const ast = parse(text, { sourceType: 'unambiguous', allowReturnOutsideFunction: true,
        plugins: [...(/\.[cm]?tsx?$/.test(file.path) ? ['typescript'] : []), ...(!/\.[cm]ts$/.test(file.path) ? ['jsx'] : []), 'decorators-legacy'] });
      modules.set(file.path, { ast, exports: new Map(), functions: [], top: `${file.path}:module` });
    } catch (error) { issue(file.path, error.loc?.line || 1, 'JavaScript/TypeScript parse failed; module not analyzed.'); }
  }
  for (const [file, module] of modules) {
    functions.set(module.top, { id: module.top, file, line: 1, function: '<module>' });
    traverse(module.ast, {
      enter(p) { if (++visited > 250000) throw new Error('Static analysis exceeds 250,000 syntax nodes. Narrow the project.'); },
      Class(p) { issue(file, p.node.loc.start.line, 'Class dispatch/inheritance is not modeled.'); },
      WithStatement(p) { issue(file, p.node.loc.start.line, 'Dynamic with scope is not modeled.'); },
      Function(p) {
        const parent = p.parentPath;
        const name = p.node.id?.name || (parent.isVariableDeclarator() ? parent.node.id.name : null) || p.node.key?.name || p.node.key?.value || '<callback>';
        const id = nodeId(file, p.node); functions.set(id, { id, ...location(file, p), function: name }); module.functions.push(p);
      },
      ExportNamedDeclaration(p) {
        if (p.node.exportKind === 'type') return;
        const declaration = p.get('declaration');
        if (declaration.node) for (const name of Object.keys(declaration.getBindingIdentifiers())) module.exports.set(name, { binding: declaration.scope.getBinding(name) });
        for (const spec of p.get('specifiers')) {
          if (spec.node.exportKind === 'type') continue;
          const name = spec.node.exported.name || spec.node.exported.value;
          module.exports.set(name, p.node.source ? { specifier: p.node.source.value, symbol: spec.node.local?.name || '*', at: spec } : { binding: spec.scope.getBinding(spec.node.local.name) });
        }
      },
      ExportDefaultDeclaration(p) { module.exports.set('default', { expression: p.get('declaration') }); },
      ExportAllDeclaration(p) { issue(file, p.node.loc.start.line, 'Wildcard re-export requires manual review.'); },
      AssignmentExpression(p) {
        const left = p.node.left;
        if (left.type !== 'MemberExpression') return;
        if (left.object.type === 'MemberExpression' && !left.object.computed && left.object.object.name === 'module' && left.object.property.name === 'exports' && !p.scope.getBinding('module') && !left.computed) module.exports.set(left.property.name, { expression: p.get('right') });
        if (left.object.type === 'Identifier' && left.object.name === 'module' && !p.scope.getBinding('module') && left.property.name === 'exports' && !left.computed) module.exports.set('default', { expression: p.get('right') });
        if (left.object.type === 'Identifier' && left.object.name === 'exports' && !p.scope.getBinding('exports') && !left.computed) module.exports.set(left.property.name, { expression: p.get('right') });
      }
    });
  }
  function localModule(file, specifier) {
    const base = path.posix.normalize(path.posix.join(path.posix.dirname(file), specifier));
    const candidates = [base, ...extensions.map(ext => base + ext), ...extensions.map(ext => `${base}/index${ext}`)];
    if (/\.[cm]?jsx?$/.test(base)) candidates.push(...['.ts', '.tsx', '.mts', '.cts'].map(ext => base.replace(/\.[cm]?jsx?$/, ext)));
    return candidates.find(item => modules.has(item));
  }
  function append(value, member, seen = new Set()) {
    return !value ? null : value.kind === 'package' ? { ...value, symbols: [...value.symbols, member] }
      : value.kind === 'namespace' ? imported(value.file, value.specifier, [member], seen)
        : value.kind === 'object' ? expression(value.properties.get(member), value.file, seen) : null;
  }
  function imported(file, specifier, symbols, seen) {
    if (!specifier.startsWith('.')) {
      if (specifier.startsWith('/') || specifier.startsWith('#')) { issue(file, 1, 'Custom module resolution is unsupported.'); return null; }
      const spec = specifier.split('/'), packageName = specifier.startsWith('@') ? spec.slice(0, 2).join('/') : spec[0];
      const subpath = spec.slice(specifier.startsWith('@') ? 2 : 1).join('/').replace(/\.[cm]?js$/, '');
      const install = resolveInstallation(file, specifier);
      return { kind: 'package', name: packageName, specifier, install,
        symbols: [...(subpath ? subpath.split('/') : []), ...symbols.filter(symbol => symbol !== 'default')] };
    }
    const target = localModule(file, specifier);
    if (!target) { issue(file, 1, `Unresolved local module: ${specifier}`); return null; }
    if (!symbols.length) return { kind: 'namespace', file, specifier };
    const [name, ...rest] = symbols;
    const id = `${target}:export:${name}`;
    if (seen.has(id)) { issue(target, 1, 'Cyclic export resolution.'); return null; }
    const next = new Set(seen).add(id), definition = modules.get(target).exports.get(name);
    if (!definition) {
      const fallback = modules.get(target).exports.get('default');
      const object = fallback?.expression ? expression(fallback.expression, target, next) : null;
      if (object?.kind === 'object' && object.properties.has(name)) {
        let value = expression(object.properties.get(name), target, next);
        for (const member of rest) value = append(value, member, next);
        return value;
      }
      issue(target, 1, `Unresolved export: ${name}`); return null;
    }
    let value = definition.binding ? bindingValue(definition.binding, target, next) : definition.specifier ? imported(target, definition.specifier, [definition.symbol], next) : expression(definition.expression, target, next);
    for (const member of rest) value = append(value, member, next);
    return value;
  }
  function bindingValue(binding, file, seen, name) {
    if (!binding) return null;
    if (!binding.constant) { issue(file, binding.path.node.loc?.start.line || 1, 'Reassigned binding needs manual call-target review.'); return null; }
    const p = binding.path, id = `${file}:binding:${p.node.start}:${name || ''}`;
    if (seen.has(id)) return null;
    const next = new Set(seen).add(id);
    if (p.isImportSpecifier() || p.isImportDefaultSpecifier() || p.isImportNamespaceSpecifier()) {
      if (p.node.importKind === 'type' || p.parentPath.node.importKind === 'type') return null;
      const symbols = p.isImportNamespaceSpecifier() ? [] : [p.isImportDefaultSpecifier() ? 'default' : p.node.imported.name || p.node.imported.value];
      return imported(file, p.parentPath.node.source.value, symbols, next);
    }
    if (p.isFunctionDeclaration()) return { kind: 'local', id: nodeId(file, p.node) };
    if (p.isVariableDeclarator()) {
      let value = expression(p.get('init'), file, next);
      if (p.node.id.type === 'ObjectPattern') {
        const property = p.node.id.properties.find(item => item.type === 'ObjectProperty' && (item.value.name === name || item.value.left?.name === name));
        if (!property || property.computed) { issue(file, p.node.loc.start.line, 'Complex destructuring requires manual review.'); return null; }
        value = append(value, property.key.name || property.key.value, next);
      }
      return value;
    }
    return null;
  }
  function expression(p, file, seen = new Set()) {
    if (!p?.node || seen.size > 40) return null;
    if (p.isFunction()) return { kind: 'local', id: nodeId(file, p.node) };
    if (p.isIdentifier()) return bindingValue(p.scope.getBinding(p.node.name), file, seen, p.node.name);
    if (['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TypeCastExpression', 'ParenthesizedExpression'].includes(p.node.type)) return expression(p.get('expression'), file, seen);
    if (p.isMemberExpression() || p.isOptionalMemberExpression()) {
      const member = p.node.computed ? p.node.property.type === 'StringLiteral' ? p.node.property.value : null : p.node.property.name;
      if (!member) { issue(file, p.node.loc.start.line, 'Computed member access may hide a call target.'); return null; }
      return append(expression(p.get('object'), file, seen), member, seen);
    }
    if (p.isCallExpression() && p.get('callee').isIdentifier({ name: 'require' }) && !p.scope.getBinding('require') && p.node.arguments.length === 1 && p.node.arguments[0].type === 'StringLiteral') {
      const specifier = p.node.arguments[0].value, local = specifier.startsWith('.') ? localModule(file, specifier) : null;
      return imported(file, specifier, local && modules.get(local).exports.has('default') ? ['default'] : [], seen);
    }
    if (p.isCallExpression() || p.isOptionalCallExpression()) issue(file, p.node.loc.start.line, 'Factory-returned call target is not modeled.');
    if (p.isObjectExpression()) {
      const properties = new Map();
      for (const property of p.get('properties')) {
        if ((property.isObjectProperty() || property.isObjectMethod()) && !property.node.computed) properties.set(property.node.key.name || property.node.key.value, property.isObjectMethod() ? property : property.get('value'));
        else issue(file, property.node.loc.start.line, 'Object spread/computed method may hide a call target.');
      }
      return { kind: 'object', file, properties };
    }
    return null;
  }
  function parentFunction(file, p) { const owner = p.findParent(item => item.isFunction()); return owner ? nodeId(file, owner.node) : modules.get(file).top; }
  for (const [file, module] of modules) {
    traverse(module.ast, {
      'CallExpression|OptionalCallExpression|NewExpression'(p) {
        const owner = parentFunction(file, p), callee = p.get('callee');
        let receiver = callee;
        while (receiver.isMemberExpression() || receiver.isOptionalMemberExpression()) receiver = receiver.get('object');
        if (receiver.isIdentifier() && receiver.scope.getBinding(receiver.node.name)?.kind === 'param') issue(file, p.node.loc.start.line, 'Parameter-based dispatch is not resolved to an exact function.');
        let target = expression(callee, file);
        if (target?.kind === 'package' && ['call', 'apply'].includes(target.symbols.at(-1))) target = { ...target, symbols: target.symbols.slice(0, -1) };
        if (target?.kind === 'package' && target.symbols.at(-1) === 'bind') issue(file, p.node.loc.start.line, 'Bound dependency functions need manual review.');
        if (target?.kind === 'local') edge(owner, target.id, location(file, p));
        else if (target?.kind === 'package') calls.push({ owner, ...location(file, p), target });
        // Callbacks may be invoked by an external framework or library. Add a
        // conservative edge without pretending to know its runtime conditions.
        for (const argument of p.get('arguments')) {
          const callback = expression(argument, file);
          if (callback?.kind === 'package') calls.push({ owner, ...location(file, argument), target: callback, assumption: 'dependency callback may execute' });
          if (callback?.kind === 'local') edge(owner, callback.id, { ...location(file, argument), assumption: 'callback may execute' });
        }
        if (callee.node.type === 'Import' || callee.isIdentifier({ name: 'eval' }) && !callee.scope.getBinding('eval') || callee.isIdentifier({ name: 'require' }) && !callee.scope.getBinding('require') && p.node.arguments[0]?.type !== 'StringLiteral') issue(file, p.node.loc.start.line, 'Dynamic import/require/eval needs manual reachability review.');
        if (target?.kind === 'package' && !target.install && !target.specifier.startsWith('node:')) issue(file, p.node.loc.start.line, `Exact installation could not be resolved for ${target.name}.`);
      },
      ImportExpression(p) { issue(file, p.node.loc.start.line, 'Dynamic import needs manual reachability review.'); }
    });
    // Explicit entries narrow the entry assumptions, never justify suppression.
    if (!entries.length || entries.includes(file)) {
      roots.set(module.top, 'module may execute');
      for (const [name, definition] of module.exports) {
        const target = definition.binding ? bindingValue(definition.binding, file, new Set(), name) : definition.specifier ? imported(file, definition.specifier, [definition.symbol], new Set()) : expression(definition.expression, file);
        if (target?.kind === 'package') calls.push({ owner: module.top, file, line: 1, target, assumption: 're-exported dependency API may be called externally' });
        if (target?.kind === 'local') roots.set(target.id, 'export may be called externally');
        if (target?.kind === 'object') for (const property of target.properties.values()) {
          const method = expression(property, file); if (method?.kind === 'local') roots.set(method.id, 'exported handler may be called externally');
        }
      }
    }
    // Loading a relative module executes its top level, including CJS requires.
    traverse(module.ast, {
      ImportDeclaration(p) {
        if (p.node.importKind === 'type' || p.node.specifiers.length && p.node.specifiers.every(specifier => specifier.importKind === 'type') || !p.node.source.value.startsWith('.')) return;
        const target = localModule(file, p.node.source.value); if (target) edge(module.top, modules.get(target).top, location(file, p));
      },
      CallExpression(p) {
        if (!p.get('callee').isIdentifier({ name: 'require' }) || p.scope.getBinding('require') || p.node.arguments[0]?.type !== 'StringLiteral' || !p.node.arguments[0].value.startsWith('.')) return;
        const target = localModule(file, p.node.arguments[0].value); if (target) edge(parentFunction(file, p), modules.get(target).top, location(file, p));
      }
    });
  }
  for (const entry of entries) if (!modules.has(entry)) throw new Error(`Entry module was not analyzed: ${entry}`);
  // One bounded shortest path per graph node prevents exponential path growth.
  const paths = new Map([...roots].map(([id, assumption]) => [id, [{ ...functions.get(id), assumption }]]));
  const queue = [...roots.keys()];
  for (let i = 0; i < queue.length; i++) {
    const from = queue[i];
    for (const link of edges.get(from) || []) if (!paths.has(link.to)) {
      const previous = paths.get(from);
      if (previous.length >= 32) { issue(link.file, link.line, 'Call path exceeds 32 frames.'); continue; }
      paths.set(link.to, [...previous, { ...functions.get(link.to), calledAt: { file: link.file, line: link.line }, ...(link.assumption ? { assumption: link.assumption } : {}) }]); queue.push(link.to);
    }
  }
  const coverageWarnings = [...source.warnings, ...(metadata.warnings || [])];
  const results = findings.map(finding => {
    const mappings = targetsFor(finding, targets), symbols = new Set(mappings.flatMap(item => item.symbols));
    const matching = calls.filter(call => call.target.install?.name === finding.package && call.target.install.version === finding.version && symbols.has(call.target.symbols.join('.') || 'default'));
    const reachable = matching.filter(call => paths.has(call.owner));
    const unresolved = calls.some(call => (!call.target.install && call.target.name === finding.package) ||
      (call.target.install?.name === finding.package && call.target.install.version === finding.version && call.target.symbols.length > 1 && !symbols.has(call.target.symbols.join('.'))));
    const status = reachable.length ? 'static_path_found' : !mappings.length || issues.length || coverageWarnings.length || unresolved || !modules.size ? 'unknown' : 'no_path_observed';
    return { key: keyOf(finding), status, verification: 'static_analysis_only', mappings,
      callPaths: reachable.slice(0, 5).map(call => [...paths.get(call.owner), { file: call.file, line: call.line, function: `${finding.package}.${call.target.symbols.join('.') || 'default'}`, role: 'affected_api', ...(call.assumption ? { assumption: call.assumption } : {}), installation: call.target.install }]),
      observedAffectedCalls: matching.length, pathsTruncated: reachable.length > 5,
      explanation: reachable.length ? 'A conservative entry can call an affected API in this exact locked version. Input/configuration prerequisites and exploitability remain unproven.'
        : !mappings.length ? 'No reviewed affected-API mapping is available for this advisory.' : 'No entry-to-affected-API path was established in the supported graph. This does not establish unreachability or safety; dependency internals, dynamic behavior and unmodeled entrypoints require review.',
      attackerInput: 'not_analyzed', prerequisites: mappings.map(item => item.prerequisites) };
  });
  const analyzerFingerprint = digest(await readFile(new URL('./reachability.mjs', import.meta.url)));
  const result = { version: 1, analyzerFingerprint, syntaxFingerprint: digest(await readFile(new URL('./syntax.mjs', import.meta.url))), targetsFingerprint: digest(JSON.stringify(targets)), entries,
    entryPolicy: entries.length ? 'explicit modules, their exports and imported top-level code' : 'conservative: every module top level and public export may execute',
    sourceFingerprint: source.fingerprint, modules: modules.size, functions: functions.size, callEdges: edgeCount,
    issues, coverageWarnings, findings: results,
    limitations: ['Static paths are potential calls, not exploit reproduction or proof of attacker input.',
      'Branch conditions and argument taint are not analyzed; infeasible or constant-input calls may appear.',
      'Dependency internals are not traversed; transitive-only exposure may remain unknown.',
      'Framework reflection, TS path aliases, dynamic loading, class dispatch and package export conditions are not fully modeled.',
      'No-path results never automatically suppress an advisory or count as confirmed discoveries.'] };
  return { ...result, analysisFingerprint: digest(JSON.stringify(result)) };
}
