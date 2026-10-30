// Add the reviewed Offense capability to an exact live module. This does not
// build the shared backend or publish anything. Credentials are not read.
import { readFile, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { build, transform } from 'esbuild';
import { parse } from '@babel/parser';
import traverseModule from '@babel/traverse';
import generateModule from '@babel/generator';
import * as t from '@babel/types';

const [liveFile, outputFile, ...options] = process.argv.slice(2);
if (!liveFile || !outputFile || (options.length && (options.length !== 4 || options[0] !== '--update-from' || options[2] !== '--previous-proof'))) {
  throw Error('Usage: node scripts/build-offense-release.mjs <reviewed-pre-capability-baseline> <output-module> [--update-from <downloaded-active-module> --previous-proof <active-release-proof>]');
}
const traverse = traverseModule.default || traverseModule, generate = generateModule.default || generateModule;
const hash = value => createHash('sha256').update(value).digest('hex');
const live = await readFile(liveFile, 'utf8');
let active = live, activeProof;
if (options.length) {
  active = await readFile(options[1], 'utf8');
  activeProof = JSON.parse(await readFile(options[3], 'utf8'));
  if (!activeProof.unrelatedBackendPreserved || !activeProof.activeVersionVerified ||
      activeProof.moduleSha256 !== hash(active) || (activeProof.baselineSha256 || activeProof.sourceSha256) !== hash(live)) {
    throw Error('The active module and original baseline do not match the verified isolated production release.');
  }
}
const oldCall = 'registerSkillApi(app, { db, production: true });';
const oldForward = 'url.pathname === "/health" || url.pathname.startsWith("/api/")';
for (const text of [oldCall, oldForward, 'function createWorkerApp(']) if (live.split(text).length !== 2) throw Error('Unexpected live insertion point: ' + text);
if (live.includes('const purpleOffenseRelease =')) throw Error('Offense is already installed; prepare an explicit update.');
const liveAst = parse(live, { sourceType: 'module' });
const appFactory = liveAst.program.body.find(node => t.isFunctionDeclaration(node) && node.id?.name === 'createWorkerApp');
const appDeclaration = appFactory?.body.body.find(node => t.isVariableDeclaration(node) && node.declarations.some(d => t.isIdentifier(d.id, { name: 'app' })));
const appValue = appDeclaration?.declarations.find(d => d.id.name === 'app')?.init?.callee;
const expressBinding = t.isSequenceExpression(appValue) ? appValue.expressions.at(-1) : appValue;
if (!t.isMemberExpression(expressBinding) || !t.isIdentifier(expressBinding.object) || !t.isIdentifier(expressBinding.property, { name: 'default' })) throw Error('Cannot identify the production Express instance.');
const expressExpression = generate(expressBinding).code;

const addon = await build({ stdin: { contents: 'export {registerSkillApi} from "./server/skill-api.js"; export {registerOffenseApi} from "./server/offense-api.js";',
  resolveDir: process.cwd(), sourcefile: 'offense-release-entry.js' }, bundle: true, format: 'esm', platform: 'node', target: 'es2022', external: ['node:*', 'express'], write: false, minify: true, legalComments: 'inline' });
const code = addon.outputFiles[0].text;
if (/__require\(["']/.test(code)) throw Error('The isolated capability bundle contains a runtime require.');
const ast = parse(code, { sourceType: 'module' }), imports = [], body = [], exported = new Map();
traverse(ast, { Program(program) {
  for (const node of program.node.body) if (t.isImportDeclaration(node) && node.source.value.startsWith('node:')) {
    for (const specifier of node.specifiers) program.scope.rename(specifier.local.name, `__purpleOffense_${specifier.local.name}`);
  }
} });
for (const node of ast.program.body) {
  if (t.isImportDeclaration(node)) {
    if (node.source.value === 'express') {
      if (node.specifiers.length !== 1 || !t.isImportDefaultSpecifier(node.specifiers[0])) throw Error('Unexpected Express import.');
      body.push(t.variableDeclaration('const', [t.variableDeclarator(node.specifiers[0].local, t.identifier('__purpleOffenseProductionExpress'))]));
    } else if (node.source.value === 'node:crypto') imports.push(node);
    else throw Error('Unsupported isolated import: ' + node.source.value);
  } else if (t.isExportNamedDeclaration(node)) {
    if (node.declaration) throw Error('Unexpected exported declaration.');
    for (const specifier of node.specifiers) exported.set(specifier.exported.name, specifier.local.name);
  } else if (t.isExportDefaultDeclaration(node) || t.isExportAllDeclaration(node)) throw Error('Unexpected capability export.');
  else body.push(node);
}
if (!exported.has('registerSkillApi') || !exported.has('registerOffenseApi')) throw Error('Missing capability registrations.');
for (const node of imports) for (const specifier of node.specifiers) if (live.includes(specifier.local.name)) throw Error('Injected import name collides with production.');
const injection = `// BEGIN ISOLATED OFFENSE RELEASE\n${imports.map(node => generate(node).code).join('\n')}\nconst purpleOffenseRelease = ((__purpleOffenseProductionExpress) => {\n${generate(t.file(t.program(body)), { comments: true, compact: true, minified: true }).code}\nreturn { registerSkillApi: ${exported.get('registerSkillApi')}, registerOffenseApi: ${exported.get('registerOffenseApi')} };\n})(${expressExpression});\n// END ISOLATED OFFENSE RELEASE\n`;
const newCall = 'const purpleOffenseController = purpleOffenseRelease.registerSkillApi(app, { db, production: true, traceEnabled: env.OFFENSE_TRACE_ENABLED !== "false" });\n  app.purplePruneTraces = () => purpleOffenseController.pruneTraces();\n  purpleOffenseRelease.registerOffenseApi(app, { intelligence: purpleOffenseController, publicUrl: publicUrl.href });';
const newForward = 'url.pathname === "/health" || url.pathname === "/mcp" || url.pathname.startsWith("/api/")';
let output = live.replace('function createWorkerApp(', () => injection + 'function createWorkerApp(').replace(oldCall, newCall).replace(oldForward, newForward);
function assetNode(source) {
  const found = parse(source, { sourceType: 'module' }).program.body.flatMap(node => t.isVariableDeclaration(node) ? node.declarations.filter(d =>
    t.isObjectExpression(d.init) && d.init.properties.some(p => t.isObjectProperty(p) && t.isStringLiteral(p.key, { value: '/index.html' })) &&
    d.init.properties.some(p => t.isObjectProperty(p) && t.isStringLiteral(p.key, { value: '/skills/purple/SKILL.md' }))) : []);
  if (found.length !== 1 || !t.isObjectExpression(found[0].init)) throw Error('Unexpected embedded asset layout.');
  return found[0].init;
}
function readAssets(source) {
  return Object.fromEntries(assetNode(source).properties.map(property => {
    if (!t.isObjectProperty(property) || property.computed || !t.isStringLiteral(property.key) || !property.key.value.startsWith('/')) throw Error('Unexpected static asset key.');
    const value = property.value;
    if (t.isStringLiteral(value)) return [property.key.value, value.value];
    const compressed = t.isObjectExpression(value) && value.properties.length === 1 && value.properties[0];
    if (!t.isObjectProperty(compressed) || compressed.computed ||
        !(t.isIdentifier(compressed.key, { name: 'gzip' }) || t.isStringLiteral(compressed.key, { value: 'gzip' })) || !t.isStringLiteral(compressed.value)) {
      throw Error('Unexpected static asset encoding.');
    }
    return [property.key.value, { gzip: compressed.value.value }];
  }));
}
const location = assetNode(output), assets = readAssets(active);
const originalPurple = Object.entries(assets).filter(([name]) => name.startsWith('/skills/purple/'));
// This frontend is one self-contained JS/CSS pair and index.html is no-store.
// Retire superseded entry bundles, retaining unrelated media and static files,
// so the connected deployment payload does not carry every prior frontend.
const frontendAssets = (await readdir('dist/assets')).filter(name => /\.(js|css)$/.test(name)).map(name => '/assets/' + name);
const retiredAssets = Object.keys(assets).filter(name => /^\/assets\/index-[^/]+\.(?:js|css)$/.test(name) && !frontendAssets.includes(name));
for (const name of retiredAssets) delete assets[name];
const changed = ['/index.html', ...frontendAssets];
for (const skill of ['offense', 'purple']) {
  const manifest = JSON.parse(await readFile(`dist/skills/${skill}/manifest.json`, 'utf8'));
  changed.push(`/skills/${skill}/manifest.json`, ...manifest.files.map(file => `/skills/${skill}/${file.path}`));
  for (const file of manifest.files) {
    const bytes = await readFile(`dist/skills/${skill}/${file.path}`);
    if (bytes.length !== file.bytes || hash(bytes) !== file.sha256) throw Error('A skill resource differs from its release manifest: ' + file.path);
  }
}
const assetHashes = {};
for (const name of changed) {
  const bytes = await readFile('dist' + name), compressed = gzipSync(bytes, { level: 9 });
  assets[name] = compressed.length + 40 < bytes.length ? { gzip: compressed.toString('base64') } : bytes.toString('base64'); assetHashes[name] = hash(bytes);
}
output = output.slice(0, location.start) + JSON.stringify(assets) + output.slice(location.end);
const stripAssets = source => { const node = assetNode(source); return source.slice(0, node.start) + '<STATIC_ASSETS>' + source.slice(node.end); };
const restored = output.replace(injection, '').replace(newCall, oldCall).replace(newForward, oldForward);
if (stripAssets(live) !== stripAssets(restored)) throw Error('An unrelated production backend change was detected.');
if (activeProof && activeProof.preservedBackendFingerprint !== hash(stripAssets(live))) throw Error('The original backend differs from the active release provenance.');

// Skill release manifests must be JSON and bypass browser caches. Replace only
// the static response function and its MIME table with the reviewed source;
// all application routes, state and resource bindings remain as above.
const staticSource = parse(await readFile('workers/static-assets.js', 'utf8'), { sourceType: 'module' });
const staticFunction = staticSource.program.body.find(node => t.isExportNamedDeclaration(node) && node.declaration?.id?.name === 'staticAssetResponse')?.declaration;
const mimeTable = staticSource.program.body.find(node => t.isVariableDeclaration(node) && node.declarations.some(d => d.id.name === 'contentTypes'));
if (!staticFunction || !mimeTable) throw Error('Cannot identify the static response implementation.');
const packagingAst = parse(output, { sourceType: 'module' });
const oldStatic = packagingAst.program.body.filter(node => t.isFunctionDeclaration(node) && node.id.name === 'staticAssetResponse');
const oldMime = packagingAst.program.body.filter(node => t.isVariableDeclaration(node) && node.declarations.some(d => d.id.name === 'contentTypes'));
if (oldStatic.length !== 1 || oldMime.length !== 1) throw Error('Unexpected static response layout.');
for (const replacement of [{ node: oldStatic[0], value: staticFunction }, { node: oldMime[0], value: mimeTable }].sort((a, b) => b.node.start - a.node.start)) {
  output = output.slice(0, replacement.node.start) + generate(replacement.value).code + output.slice(replacement.node.end);
}

// Carry the previously verified decoder fix into the production Express
// instance without replacing unrelated application modules. This is a narrow
// backport of the exact upstream 2.4.0 read implementation, not a claim that
// the retained production bundle was rebuilt from the entire new lockfile.
const parserMetadata = JSON.parse(await readFile('node_modules/body-parser/package.json', 'utf8'));
const fixedReader = await readFile('node_modules/body-parser/lib/read.js', 'utf8');
if (parserMetadata.version !== '2.4.0' || hash(fixedReader) !== 'c77982d481a9fe5b13c0fdd68515a5931729961e7135124f70236d5a30bdd701') {
  throw Error('The reviewed upstream body-parser reader changed. Revalidate its compatibility before packaging.');
}
const parserAst = parse(output, { sourceType: 'module' });
const parserModules = new Map(parserAst.program.body.flatMap(node => t.isVariableDeclaration(node) ? node.declarations.flatMap(declaration => {
  const init = declaration.init;
  if (!t.isIdentifier(declaration.id) || !t.isCallExpression(init) || !t.isIdentifier(init.callee, { name: '__commonJS' }) || !t.isObjectExpression(init.arguments[0])) return [];
  const key = init.arguments[0].properties[0]?.key;
  return t.isStringLiteral(key) ? [[key.value, { node, declaration }]] : [];
}) : []));
const currentReader = parserModules.get('node_modules/body-parser/lib/read.js');
if (!currentReader || hash(output.slice(currentReader.node.start, currentReader.node.end)) !== 'f42519c599b43dfc9763bb6aedd86650c86576ad4664b1adbf0b2bb80f26e179') {
  throw Error('The production decoder differs from the reviewed backport baseline.');
}
const readerDependencies = new Map([
  ['http-errors', 'node_modules/http-errors/index.js'], ['raw-body', 'node_modules/raw-body/index.js'],
  ['iconv-lite', 'node_modules/iconv-lite/lib/index.js'], ['on-finished', 'node_modules/on-finished/index.js'],
  ['type-is', 'node_modules/type-is/index.js'], ['content-type', 'node_modules/content-type/dist/index.js']
].map(([name, file]) => {
  const module = parserModules.get(file);
  if (!module) throw Error('Missing production reader dependency: ' + file);
  return [name, module.declaration.id.name];
}));
readerDependencies.set('node:zlib', 'require_node_zlib');
const upstreamAst = parse(fixedReader, { sourceType: 'script' });
traverse(upstreamAst, { CallExpression(reference) {
  if (!t.isIdentifier(reference.node.callee, { name: 'require' })) return;
  const argument = reference.node.arguments[0], alias = t.isStringLiteral(argument) && readerDependencies.get(argument.value);
  if (!alias) throw Error('Unexpected dependency in the reviewed upstream reader.');
  reference.replaceWith(t.callExpression(t.identifier(alias), []));
} });
const readerWrapper = currentReader.declaration.init.arguments[0].properties[0];
if (!t.isObjectMethod(readerWrapper)) throw Error('Unexpected production decoder wrapper.');
readerWrapper.body.body = upstreamAst.program.body;
const patchedReader = generate(currentReader.node, { comments: true }).code;
const decoderBackport = { package: 'body-parser', productionBaseline: '2.3.0', upstreamReader: '2.4.0',
  originalModuleSha256: hash(output.slice(currentReader.node.start, currentReader.node.end)),
  upstreamSourceSha256: hash(fixedReader), patchedModuleSha256: hash(patchedReader),
  scope: 'Upstream compressed-request reader only; unrelated production modules and dependency declarations retained.' };
output = output.slice(0, currentReader.node.start) + patchedReader + output.slice(currentReader.node.end);

// Reuse the existing maintenance alarm for diagnostic expiry. Keep this
// isolated update equivalent to the maintained Worker source: no second alarm
// or background request is introduced and no trace bodies enter platform logs.
const maintenanceAst = parse(output, { sourceType: 'module' }), maintenanceMethods = [];
traverse(maintenanceAst, { Class(reference) {
  const constructor = reference.node.body.body.find(method => t.isClassMethod(method) && method.kind === 'constructor');
  if (!constructor?.body.body.some(statement => t.isVariableDeclaration(statement) && statement.declarations.some(declaration =>
    t.isCallExpression(declaration.init) && t.isIdentifier(declaration.init.callee, { name: 'createWorkerApp' })))) return;
  const alarm = reference.node.body.body.find(method => t.isClassMethod(method) && t.isIdentifier(method.key, { name: 'alarm' }));
  const alarmTry = alarm?.body.body.find(statement => t.isTryStatement(statement));
  if (!alarmTry) throw Error('Unexpected production maintenance alarm.');
  constructor.body.body.push(t.expressionStatement(t.assignmentExpression('=',
    t.memberExpression(t.thisExpression(), t.identifier('pruneTraces')), t.memberExpression(t.identifier('app'), t.identifier('purplePruneTraces')))));
  alarmTry.block.body.unshift(t.expressionStatement(t.callExpression(t.memberExpression(t.thisExpression(), t.identifier('pruneTraces')), [])));
  maintenanceMethods.push(constructor, alarm);
} });
if (maintenanceMethods.length !== 2) throw Error('Cannot identify exactly one production maintenance alarm and constructor.');
for (const method of maintenanceMethods.sort((a, b) => b.start - a.start)) {
  output = output.slice(0, method.start) + generate(method).code + output.slice(method.end);
}
// Standard minification keeps function/class names and required license notices.
// The temporary factory export records its compiled binding for exact-artifact
// tests; it is removed before publishing, leaving the original Worker exports.
output = (await transform(output + '\nexport {createWorkerApp as __offenseArtifactFactory};\n', { loader: 'js', target: 'es2022', format: 'esm',
  minify: true, keepNames: true, legalComments: 'inline' })).code;
const compiled = parse(output, { sourceType: 'module' });
const exportNode = compiled.program.body.find(node => t.isExportNamedDeclaration(node) && node.specifiers.some(s => s.exported?.name === '__offenseArtifactFactory'));
if (!exportNode) throw Error('Missing artifact-validation factory.');
const validationFactoryName = exportNode.specifiers.find(s => s.exported?.name === '__offenseArtifactFactory').local.name;
exportNode.specifiers = exportNode.specifiers.filter(s => s.exported?.name !== '__offenseArtifactFactory');
output = output.slice(0, exportNode.start) + (exportNode.specifiers.length ? generate(exportNode, { compact: true }).code : '') + output.slice(exportNode.end);
await writeFile(outputFile, output, { mode: 0o600 });
const proof = { builtAt: new Date().toISOString(), sourceSha256: hash(active), baselineSha256: hash(live), previousVersionId: activeProof?.versionId || null,
  moduleSha256: hash(output), release: hash(output).slice(0, 12),
  preservedBackendFingerprint: hash(stripAssets(live)), unrelatedBackendPreserved: true, sharedProductionExpress: expressExpression,
  registrationsReplaced: 1, forwardingPredicatesChanged: 1, onlyAddedBackend: 'Isolated Offense capability and shared legacy skill controller; JSON/no-store release manifest responses',
  decoderBackport,
  traceMaintenance: { scheduled: true, mechanism: 'Existing Durable Object alarm prunes diagnostics before other maintenance; no new external requests.' },
  previousPurpleAssets: originalPurple.length, managedSkillResources: changed.filter(name => name.startsWith('/skills/')).length,
  packaging: 'Minified with function/class names preserved; active assets retained and both managed skill packages updated', retiredAssets, validationFactoryName, assetHashes, outputFile: path.resolve(outputFile) };
await writeFile(outputFile.replace(/\.js$/, '') + '-proof.json', JSON.stringify(proof, null, 2) + '\n');
console.log(JSON.stringify(proof));
