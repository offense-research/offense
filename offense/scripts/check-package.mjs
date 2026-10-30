// Portable release hygiene. Errors identify a file and rule, never matched data.
import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { builtinModules } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
const traverse = traverseModule.default || traverseModule;

const defaultRoot = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const allowedDirectories = new Set(['bin', 'lib', 'server', 'shared', 'src', 'public', 'tools', 'skills', 'test', 'docs', 'scripts', '.github', 'licenses']);
const allowedRootFiles = new Set(['package.json', 'package-lock.json', 'README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md',
  'THIRD_PARTY_NOTICES.md', '.gitignore', '.npmignore', '.env.example', 'CHANGELOG.md']);
const engineFiles = new Set(['braces-remediation.js', 'dependency-graph.js', 'dependency-intelligence.js', 'dependency-mapper.js', 'osv.js', 'upgrade-handoff.js', 'upgrade-planner.js']);
const ignoredRoot = new Set(['node_modules', '.git', 'coverage', 'dist']);
const forbiddenNames = /^(?:\.env(?:\..+)?|\.infisical\.(?:yaml|json)|\.codex|\.claude|\.agents|\.pi|\.aws|\.ssh|\.git|\.npmrc|\.netrc|node_modules|credentials(?:\..*)?|data|reports|__pycache__)$/i;
const forbiddenExtension = /\.(?:pem|key|p12|pfx|sqlite(?:-.*)?|db(?:-.*)?|pyc|jsonl)$/i;
const builtin = new Set(builtinModules.map(name => name.replace(/^node:/, '')));
const fixedTools = new Set(['triage', 'rehearse', 'source-scan', 'api-test', 'hardened-image']);
const lifecycle = /^(?:preinstall|install|postinstall|prepare|prepublish|prepublishOnly|prepack|publish|postpublish)$/;
const secretPatterns = [
  /(?:sk-(?:or-v1-|proj-|ant-)|gh[opsu]_|github_pat_|xox[baprs]-)[A-Za-z0-9_-]{20,}/,
  /(?:offense_sk_|purple_scan_)[A-Za-z0-9_-]{32,}/,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\/home\/[A-Za-z0-9._-]+\//,
  /\/Users\/[A-Za-z0-9._-]+\//,
  /https?:\/\/[^\s'"<>]+\.workers\.dev\b/,
  /\/accounts\/[a-f0-9]{32}\b/i,
  /\b(?:accountId|account_id|zoneId|zone_id|workerId|worker_id|database_id|namespace_id)\s*[:=]\s*['"][a-f0-9]{32,}['"]/i
];
const hostedAnalysisOrigin = /https?:\/\/(?:offense\.sh|app\.purpleteam\.sh)(?=[/?#'"\s]|$)/;
const inside = (root, filename) => filename === root || filename.startsWith(root + path.sep);
const fail = (rule, filename) => { throw Error(`${rule}: ${filename}`); };
const literal = node => node?.type === 'StringLiteral' ? node.value : node?.type === 'TemplateLiteral' && !node.expressions.length ? node.quasis[0].value.cooked : undefined;
const importMeta = node => node?.type === 'MemberExpression' && node.object?.type === 'MetaProperty' && node.object.meta.name === 'import' && node.object.property.name === 'meta' && node.property?.name === 'url';

function walkAst(node, visit, parent = null) {
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node, parent);
  for (const [key, value] of Object.entries(node)) {
    if (['loc', 'start', 'end', 'extra', 'comments', 'tokens', 'errors'].includes(key)) continue;
    if (Array.isArray(value)) for (const item of value) walkAst(item, visit, node);
    else if (value && typeof value === 'object') walkAst(value, visit, node);
  }
}

async function inspectCode(text, filename, relative, root, dependencies) {
  let ast;
  try { ast = parse(text, { sourceType: 'unambiguous', createImportExpressions: true, plugins: ['importAttributes'] }); }
  catch { fail('JavaScript syntax check failed', relative); }
  const constants = new Map(), tasks = [], paths = new WeakMap();
  traverse(ast, { enter(context) { paths.set(context.node, context); } });
  function constantBinding(node) {
    if (node?.type !== 'Identifier') return null;
    const binding = paths.get(node)?.scope.getBinding(node.name);
    return binding?.kind === 'const' && binding.path.isVariableDeclarator() ? binding : null;
  }
  walkAst(ast, (node, parent) => {
    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && parent?.kind === 'const') constants.set(node.id.name, node.init);
  });
  async function localResource(target) {
    if (!inside(root, target)) fail('Local resource escapes community package', relative);
    if (ignoredRoot.has(path.relative(root, target).split(path.sep)[0])) fail('Local resource points at omitted runtime artifacts', relative);
    let info; try { info = await lstat(target); } catch { fail('Missing local resource', relative); }
    if (info.isSymbolicLink()) fail('Local resource is a symlink', relative);
    if (!inside(root, await realpath(target))) fail('Local resource escapes community package', relative);
  }
  async function moduleSource(source) {
    if (typeof source !== 'string') fail('Unreviewed computed module import', relative);
    if (source.startsWith('.')) return localResource(path.resolve(path.dirname(filename), source));
    if (source.startsWith('/') || /^(?:[a-z][a-z0-9+.-]*:)/i.test(source) && !source.startsWith('node:')) fail('Nonportable or remote module import', relative);
    const name = source.startsWith('@') ? source.split('/').slice(0, 2).join('/') : source.split('/')[0];
    if (source.startsWith('node:') ? !builtin.has(source.slice(5)) : !builtin.has(source) && !dependencies.has(name)) fail('Undeclared external module import', relative);
  }
  function resourceUrl(node, seen = new Set()) {
    if (importMeta(node)) return pathToFileURL(filename);
    const binding = constantBinding(node);
    if (binding && !seen.has(binding)) {
      seen.add(binding); return resourceUrl(binding.path.node.init, seen);
    }
    if (node?.type !== 'NewExpression' || node.callee.name !== 'URL') return null;
    const first = literal(node.arguments[0]), base = resourceUrl(node.arguments[1], seen);
    if (first === undefined || !base) return null;
    try { return new URL(first, base); } catch { fail('Invalid local resource URL', relative); }
  }
  function toolVariants(node) {
    if (!['bin/purple.mjs', 'bin/offense.mjs'].includes(relative) || node?.type !== 'TemplateLiteral' || node.expressions.length !== 1 ||
      node.expressions[0].type !== 'Identifier' || node.expressions[0].name !== 'tool' || node.quasis[0].value.cooked !== '../tools/' || node.quasis[1].value.cooked !== '.mjs') return null;
    const mapping = constantBinding(node.expressions[0])?.path.node.init;
    if (mapping?.type !== 'MemberExpression' || mapping.object.type !== 'ObjectExpression') return null;
    const variants = mapping.object.properties.map(property => property.type === 'ObjectProperty' && !property.computed ? literal(property.value) : undefined);
    if (!variants.length || variants.some(value => !fixedTools.has(value))) return null;
    return variants.map(value => `../tools/${value}.mjs`);
  }
  // This reviewed adapter loads builtins and a parser URL validated by the local
  // rehearsal boundary. Its source is not a general package-import exemption.
  const rehearsalAdapter = relative === 'tools/rehearsal-runner.mjs' && (() => {
    const loader = constants.get('loadModule');
    if (loader?.type !== 'ArrowFunctionExpression' || loader.params.length !== 1 || loader.params[0].name !== 'name' ||
      loader.body.type !== 'ImportExpression' || loader.body.source.type !== 'Identifier' || loader.body.source.name !== 'name') return false;
    let valid = true;
    walkAst(ast, node => {
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'loadModule') {
        const source = literal(node.arguments[0]);
        const parser = node.arguments[0]?.type === 'MemberExpression' && node.arguments[0].object.name === 'parserUrl' && node.arguments[0].property.name === 'href';
        if (node.arguments.length !== 1 || !(source?.startsWith('node:') && builtin.has(source.slice(5)) || parser)) valid = false;
      }
    });
    return valid;
  })();
  walkAst(ast, (node, parent) => {
    if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type) && node.source) tasks.push(() => moduleSource(literal(node.source)));
    if (node.type === 'ImportExpression') {
      const source = literal(node.source), variants = source === undefined ? toolVariants(node.source) : null;
      if (source !== undefined) tasks.push(() => moduleSource(source));
      else if (variants) for (const value of variants) tasks.push(() => moduleSource(value));
      else if (!(rehearsalAdapter && parent?.type === 'ArrowFunctionExpression' && parent === constants.get('loadModule'))) fail('Unreviewed computed module import', relative);
    }
    if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require') tasks.push(() => moduleSource(literal(node.arguments[0])));
    if (node.type === 'NewExpression' && node.callee.name === 'URL') {
      const resolved = resourceUrl(node);
      if (resolved?.protocol === 'file:') tasks.push(() => localResource(fileURLToPath(resolved)));
    }
  });
  await Promise.all(tasks.map(task => task()));
}

export async function checkPackage({ root: requestedRoot = defaultRoot } = {}) {
  const root = await realpath(requestedRoot), files = [];
  let metadata;
  try { metadata = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')); }
  catch { fail('Missing or invalid package metadata', 'package.json'); }
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) fail('Invalid package metadata', 'package.json');
  if (metadata.license !== 'Apache-2.0') fail('Community license must remain Apache-2.0', 'package.json');
  if (metadata.private !== true) fail('Keep the local community package private until publication is explicitly authorized', 'package.json');
  const dependencies = new Set(Object.keys(metadata.dependencies || {}));
  for (const hook of Object.keys(metadata.scripts || {})) if (lifecycle.test(hook)) fail('Unreviewed package lifecycle hook', 'package.json');
  for (const entry of metadata.files || []) {
    const name = entry.replace(/\/$/, '');
    if (!allowedDirectories.has(name) && !allowedRootFiles.has(name)) fail('Unreviewed npm package entry', 'package.json');
  }
  async function walk(directory, prefix = '') {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (!prefix && ignoredRoot.has(entry.name)) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (!prefix && (entry.isDirectory() ? !allowedDirectories.has(entry.name) : !allowedRootFiles.has(entry.name))) fail('Unreviewed release entry', relative);
      if (relative.startsWith('server/') && !engineFiles.has(relative.slice(7))) fail('Private or unreviewed server service', relative);
      if ((forbiddenNames.test(entry.name) && relative !== '.env.example') || forbiddenExtension.test(entry.name)) fail('Private/runtime artifact in release', relative);
      const filename = path.join(directory, entry.name), info = await lstat(filename);
      if (info.isSymbolicLink()) fail('Release symlink requires review', relative);
      if (info.isDirectory()) { await walk(filename, relative); continue; }
      if (!info.isFile() || info.nlink > 1) fail('Unsupported release entry', relative);
      if (info.size > 2_000_000) fail('Oversized release file requires review', relative);
      const bytes = await readFile(filename);
      if (bytes.includes(0)) fail('Binary artifact requires review', relative);
      let text; try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail('Binary artifact requires review', relative); }
      if (secretPatterns.some(pattern => pattern.test(text))) fail('Sensitive content requires review', relative);
      if (/\.(?:mjs|js|cjs)$/.test(entry.name)) {
        if (!relative.startsWith('test/') && !['lib/hosted-cli.mjs', 'scripts/check-package.mjs'].includes(relative) && hostedAnalysisOrigin.test(text)) fail('Hosted analysis origin outside the optional client', relative);
        await inspectCode(text, filename, relative, root, dependencies);
      }
      files.push(relative);
    }
  }
  await walk(root);
  for (const required of ['README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md', 'THIRD_PARTY_NOTICES.md', 'package-lock.json'])
    if (!files.includes(required)) fail('Missing release resource', required);
  if (!files.includes('skills/offense/SKILL.md') && !files.includes('skills/purple/SKILL.md')) fail('Missing the community agent skill', 'skills/');
  let lock;
  try { lock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8')); }
  catch { fail('Invalid locked dependency metadata', 'package-lock.json'); }
  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) fail('Invalid locked dependency metadata', 'package-lock.json');
  for (const entry of Object.values(lock.packages || {})) if (entry.resolved) {
    let url; try { url = new URL(entry.resolved); } catch { fail('Nonportable dependency resolution', 'package-lock.json'); }
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.search || url.hash)
      fail('Private or unreviewed dependency registry', 'package-lock.json');
  }
  return { passed: true, filesChecked: files.length, syntaxAndLocalImports: 'passed', privateArtifactExclusions: 'passed', sensitiveContentChecks: 'passed', publicationHold: 'private' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  checkPackage().then(result => console.log(JSON.stringify(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
