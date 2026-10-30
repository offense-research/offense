import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { inspectSources, advisoryFingerprint } from '../tools/evidence.mjs';
import { analyzeReachability } from '../tools/reachability.mjs';
const finding = { package: 'lodash', version: '4.17.20', id: 'GHSA-35jh-r3h4-6jhm', cves: ['CVE-2021-23337'] };
async function analyze(t, files, options = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-functions-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) { await mkdir(path.dirname(path.join(root, name)), { recursive: true }); await writeFile(path.join(root, name), content); }
  const lock = { path: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { lodash: '^4.17.20' } }, 'node_modules/lodash': { version: '4.17.20' } } }) };
  const findings = options.findings || [finding];
  const result = await analyzeReachability(root, { source: await inspectSources(root, findings), metadata: { files: options.locks || [lock], warnings: [] }, findings, ...options });
  return result;
}

test('TS alias -> local wrapper -> re-export -> exported Worker handler yields an exact-version affected API path', async t => {
  const result = await analyze(t, {
    'api.ts': "import { template as compile } from 'lodash'; export function render(input: string){return compile(input);}",
    'barrel.ts': "export {render as view} from './api.js';",
    'worker.ts': "import {view} from './barrel.js'; function respond(input:string){return view(input);} export default {fetch(request:Request){return respond(request.url);}}"
  }, { entries: ['worker.ts'] });
  const item = result.findings[0]; assert.equal(item.status, 'static_path_found');
  const chain = item.callPaths[0]; assert.deepEqual(chain.map(frame => frame.function), ['fetch', 'respond', 'render', 'lodash.template']);
  assert.equal(chain.at(-1).installation.version, '4.17.20'); assert.equal(chain.at(-1).installation.lockfile, 'package-lock.json');
  assert.equal(item.attackerInput, 'not_analyzed');
});

test('CommonJS destructuring, const aliases, and static subpath imports resolve the affected symbol', async t => {
  for (const code of [
    "const {template: render} = require('lodash'); const alias=render; module.exports = function handler(){return alias('hi');};",
    "const render = require('lodash/template'); exports.handler=()=>render('hi');",
    "import compile from 'lodash/template.js'; export const handler=()=>compile('hi');",
    "import * as _ from 'lodash'; export function handler(){return _['template']('hi');}"
  ]) {
    const result = await analyze(t, { 'index.js': code });
    assert.equal(result.findings[0].status, 'static_path_found', code);
  }
});

test('shadowed identifiers, comments, type-only imports and unrelated properties never masquerade as package calls', async t => {
  for (const code of [
    "import _ from 'lodash'; export function handle(_){ return _.template('hi'); }",
    "// import {template} from 'lodash'; template('danger');\nexport const ok=()=>true;",
    "import type {template} from 'lodash'; export const safe=()=>true;",
    "const _={template:x=>x}; export const handle=()=>_.template('hi');",
    "export function handle(require){ return require('lodash').template('hi'); }"
  ]) {
    const result = await analyze(t, { 'index.ts': code }); assert.notEqual(result.findings[0].status, 'static_path_found', code);
  }
});

test('a safe sibling API does not match template; dead private functions have no observed entry path', async t => {
  for (const code of [
    "import _ from 'lodash'; export const handle=()=>_.map([1],x=>x);",
    "import {template} from 'lodash'; function neverCalled(){return template('hi');} export const handle=()=>true;"
  ]) {
    const result = await analyze(t, { 'index.js': code }); assert.equal(result.findings[0].status, 'no_path_observed');
  }
});

test('callbacks and re-exported dependency APIs are conservative externally callable paths', async t => {
  for (const code of [
    "import {template} from 'lodash'; declareRoute('/render', function handler(){return template('hi');});",
    "import {template} from 'lodash'; registerCallback(template);",
    "export {template as compile} from 'lodash';",
    "import {template} from 'lodash'; export const handle=()=>template.call(null,'hi');"
  ]) assert.equal((await analyze(t, { 'index.js': code })).findings[0].status, 'static_path_found', code);
});

test('dynamic access, loading, parse failures, wildcard exports and unresolved imports remain unknown', async t => {
  for (const code of [
    "import _ from 'lodash'; export function handle(method){return _[method]('hi');}",
    "export const handle = name=>require(name);",
    "export const handle = name=>import(name);",
    "export * from './missing.js';",
    "import {render} from './missing.js'; export const handle=()=>render('hi');",
    "export function broken( {"
  ]) {
    const result = await analyze(t, { 'index.js': code }); assert.equal(result.findings[0].status, 'unknown', code); assert.ok(result.issues.length);
  }
});

test('an unknown advisory requires an explicit reviewed API mapping and never guesses from the summary', async t => {
  const unknown = { ...finding, id: 'GHSA-custom', cves: [], summary: 'template is vulnerable' };
  const files = { 'index.js': "import {template} from 'lodash'; export const handle=()=>template('hi');" };
  assert.equal((await analyze(t, files, { findings: [unknown] })).findings[0].status, 'unknown');
  const result = await analyze(t, files, { findings: [unknown], targets: [{ key: 'lodash@4.17.20:GHSA-custom', reviewedBy: 'fixture reviewer', advisoryFingerprint: advisoryFingerprint(unknown), symbols: ['template'],
    reference: 'https://example.test/advisory', prerequisites: 'Review attacker control over template arguments.' }] });
  assert.equal(result.findings[0].status, 'static_path_found'); assert.equal(result.findings[0].mappings[0].provenance, 'reviewer_supplied_mapping');
  await assert.rejects(analyze(t, files, { targets: [{ key: 'made-up', symbols: ['template'] }] }), /targets require/);
  await assert.rejects(analyze(t, files, { findings: [unknown], targets: [{ ...result.findings[0].mappings[0], advisoryFingerprint: 'stale' }] }), /targets require/);
});

test('multiple npm projects do not assign a call on a patched version to a vulnerable copy elsewhere', async t => {
  const lock = (file, version) => ({ path: file, content: JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/lodash': { version } } }) });
  const result = await analyze(t, {
    'a/index.js': "import {template} from 'lodash'; export const handle=()=>template('hi');",
    'b/index.js': "export const handle=()=>true;"
  }, { locks: [lock('package-lock.json', '4.17.20'), lock('a/package-lock.json', '4.17.21'), lock('b/package-lock.json', '4.17.20')] });
  assert.equal(result.findings[0].status, 'no_path_observed'); assert.equal(result.findings[0].observedAffectedCalls, 0);
});

test('pnpm importer aliases bind each call to its actual npm identity and version', async t => {
  const lock = { path: 'pnpm-lock.yaml', content: `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: 4.17.20\n        version: 4.17.20\n  a:\n    dependencies:\n      utils:\n        specifier: npm:lodash@4.17.21\n        version: lodash@4.17.21\npackages:\n  lodash@4.17.20: {}\n  lodash@4.17.21: {}\nsnapshots:\n  lodash@4.17.20: {}\n  lodash@4.17.21: {}\n` };
  const files = { 'a/index.js': "import {template} from 'utils'; export const handle=()=>template('hi');" };
  const result = await analyze(t, files, { locks: [lock] });
  assert.equal(result.findings[0].status, 'no_path_observed');
  const patched = { ...finding, version: '4.17.21' };
  const bound = await analyze(t, files, { locks: [lock], findings: [patched] });
  assert.equal(bound.findings[0].status, 'static_path_found'); assert.equal(bound.findings[0].callPaths[0].at(-1).installation.name, 'lodash');
});


test('CommonJS local default and object exports retain caller paths across files', async t => {
  for (const declaration of [
    "module.exports = function render(x){return template(x);};",
    "module.exports = {render(x){return template(x);}};",
    "module.exports.render = function render(x){return template(x);};"
  ]) {
    const member = declaration.startsWith('module.exports = function') ? '' : '.render';
    const result = await analyze(t, {
      'helper.cjs': "const {template}=require('lodash');" + declaration,
      'worker.cjs': "const helper=require('./helper.cjs'); exports.fetch=function fetch(){return helper" + member + "('hi');};"
    }, { entries: ['worker.cjs'] });
    assert.equal(result.findings[0].status, 'static_path_found', declaration);
    assert.ok(result.findings[0].callPaths[0].some(frame => frame.file === 'helper.cjs'));
  }
});

test('unsupported class dispatch and component modules are reported as unknown', async t => {
  for (const files of [
    { 'index.js': "import {template} from 'lodash'; class Renderer { render(){return template('hi');} } export const handle=()=>new Renderer().render();" },
    { 'component.vue': '<script>import {template} from "lodash"; template("hi")</script>' }
  ]) assert.equal((await analyze(t, files)).findings[0].status, 'unknown');
});


test('type-only import specifiers do not execute the imported module from an explicit entry', async t => {
  const result = await analyze(t, {
    'helper.ts': "import {template} from 'lodash'; template('hi'); export type View=string;",
    'worker.ts': "import {type View} from './helper.js'; export const handle=():View=>'ok';"
  }, { entries: ['worker.ts'] });
  assert.equal(result.findings[0].status, 'no_path_observed');
});


test('cyclic namespace aliases terminate as unknown instead of recursing indefinitely', async t => {
  const result = await analyze(t, {
    'a.js': "import * as b from './b.js'; export const render=b.render;",
    'b.js': "import * as a from './a.js'; export const render=a.render;",
    'worker.js': "import {render} from './a.js'; export const handle=()=>render();"
  }, { entries: ['worker.js'] });
  assert.equal(result.findings[0].status, 'unknown');
  assert.ok(result.issues.some(item => item.reason.includes('Cyclic')));
});
