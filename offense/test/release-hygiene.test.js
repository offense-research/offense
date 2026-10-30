import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { checkPackage } from '../scripts/check-package.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'offense-release-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const metadata = { name: 'offense-community-fixture', version: '0.2.0', type: 'module', license: 'Apache-2.0', private: true,
    files: ['bin/', 'lib/', 'server/', 'tools/', 'skills/', 'docs/', 'README.md', 'LICENSE'] };
  async function put(relative, data) { const file = path.join(root, relative); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, typeof data === 'string' ? data : JSON.stringify(data)); }
  async function packageMetadata(next = metadata) { await put('package.json', next); }
  await packageMetadata();
  await put('package-lock.json', { lockfileVersion: 3, packages: {} });
  for (const name of ['README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CONTRIBUTING.md', 'THIRD_PARTY_NOTICES.md', 'skills/offense/SKILL.md']) await put(name, 'Synthetic release fixture.\n');
  return { root, metadata, put, packageMetadata };
}

test('release checks use AST imports/resources and ignore text examples plus omitted dependency installations', async t => {
  const f = await fixture(t);
  await f.put('lib/inside.mjs', 'export const ready = true;');
  await f.put('lib/data.txt', 'Reviewed local resource');
  await f.put('lib/entry.mjs', `import './inside.mjs'; export * from './inside.mjs';
const example = "import '../../outside.mjs'";
const base = new URL('./', import.meta.url); const data = new URL('data.txt', base);
export async function load() { return import('./inside.mjs'); }`);
  await f.put('node_modules/ignored/package.json', 'private dependency installation, not release source');
  const result = await checkPackage({ root: f.root });
  assert.equal(result.passed, true); assert.equal(result.publicationHold, 'private');
  assert.equal(result.filesChecked, 12);
});

test('literal secrets and private environment coordinates fail without exposing their matches', async t => {
  const f = await fixture(t);
  const secrets = [
    'sk' + '-or-v1-' + 'a'.repeat(40),
    'offense_' + 'sk_' + 'b'.repeat(64),
    '-----BEGIN ' + 'PRIVATE KEY-----',
    '/home/' + 'private-user/project',
    '/Users/' + 'private-user/project',
    'https://customer-private.' + 'workers.dev/api',
    '/accounts/' + 'c'.repeat(32),
    'const accountId = "' + 'd'.repeat(32) + '";'
  ];
  for (const secret of secrets) {
    await f.put('README.md', secret);
    await assert.rejects(checkPackage({ root: f.root }), error => {
      assert.equal(error.message, 'Sensitive content requires review: README.md');
      assert.ok(!error.message.includes(secret)); return true;
    });
  }
});

test('side-effect imports, dynamic literal imports, reexports, require and file resources cannot escape', async t => {
  const f = await fixture(t);
  const programs = [
    "import '../../outside.mjs';",
    "export * from '../../outside.mjs';",
    "export async function run() { return import('../../outside.mjs'); }",
    "const data = require('../../outside.cjs');",
    "const resource = new URL('../../private.txt', import.meta.url);",
    "const base = new URL('../../', import.meta.url); const resource = new URL('private.txt', base);",
    "const data = import('file:///private/application.mjs');",
    "const data = import('unlisted-dependency');",
    "export const load = target => import(target);"
  ];
  for (const program of programs) {
    await f.put('lib/entry.mjs', program);
    await assert.rejects(checkPackage({ root: f.root }), /(?:escapes community|Nonportable|Undeclared|Unreviewed computed)/);
  }
  await f.put('lib/entry.mjs', "import './missing.mjs';");
  await assert.rejects(checkPackage({ root: f.root }), /Missing local resource/);
});

test('computed tool loading accepts only the fixed packaged command map', async t => {
  const f = await fixture(t);
  await f.put('tools/triage.mjs', 'export function main() {}');
  await f.put('bin/offense.mjs', "export function main(command) { const tool = {triage:'triage'}[command];return import(`../tools/${tool}.mjs`); }");
  assert.equal((await checkPackage({ root: f.root })).passed, true);
  await f.put('bin/offense.mjs', "export function main(command) { const tool = {triage:'../../private'}[command];return import(`../tools/${tool}.mjs`); }");
  await assert.rejects(checkPackage({ root: f.root }), /Unreviewed computed/);
});

test('private server services, symlinks and nested dependency directories fail the release allowlist', async t => {
  const f = await fixture(t);
  await f.put('server/scan-whop-billing.js', 'export const enabled = false;');
  await assert.rejects(checkPackage({ root: f.root }), /Private or unreviewed server service/);
  await rm(path.join(f.root, 'server'), { recursive: true });
  await f.put('lib/target.mjs', 'export const value = 1;');
  await symlink(path.join(f.root, 'lib/target.mjs'), path.join(f.root, 'lib/link.mjs'));
  await assert.rejects(checkPackage({ root: f.root }), /symlink/);
  await rm(path.join(f.root, 'lib/link.mjs'));
  await f.put('lib/node_modules/private/index.js', 'export const privateValue = 1;');
  await assert.rejects(checkPackage({ root: f.root }), /Private\/runtime artifact/);
});

test('publication hold, package contents, lifecycle hooks and dependency registry credentials are enforced', async t => {
  const f = await fixture(t);
  await f.packageMetadata({ ...f.metadata, private: false });
  await assert.rejects(checkPackage({ root: f.root }), /Keep the local community package private/);
  await f.packageMetadata({ ...f.metadata, files: [...f.metadata.files, 'dist/'] });
  await assert.rejects(checkPackage({ root: f.root }), /Unreviewed npm package entry/);
  await f.packageMetadata({ ...f.metadata, scripts: { prepack: 'node deploy.mjs' } });
  await assert.rejects(checkPackage({ root: f.root }), /lifecycle hook/);
  await f.packageMetadata();
  for (const resolved of ['https://user:synthetic-password@registry.npmjs.org/pkg/-/pkg.tgz', 'file:../../private-package', 'https://registry.npmjs.org/pkg/-/pkg.tgz?token=synthetic']) {
    await f.put('package-lock.json', { lockfileVersion: 3, packages: { 'node_modules/pkg': { resolved } } });
    await assert.rejects(checkPackage({ root: f.root }), /dependency registry|dependency resolution/);
  }
});

test('hosted analysis URLs belong only to the optional hosted client, never the local engine', async t => {
  const f = await fixture(t), origin = 'https://' + 'offense.sh';
  await f.put('lib/audit.mjs', `export const endpoint = '${origin}';`);
  await assert.rejects(checkPackage({ root: f.root }), /Hosted analysis origin outside the optional client/);
  await rm(path.join(f.root, 'lib/audit.mjs'));
  await f.put('lib/hosted-cli.mjs', `export const endpoint = '${origin}';`);
  assert.equal((await checkPackage({ root: f.root })).passed, true);
});

test('ignored root installations cannot satisfy a released local import or file resource', async t => {
  const f = await fixture(t);
  await f.put('node_modules/private-module/index.mjs', 'export const value = 1;');
  for (const program of [
    "import '../node_modules/private-module/index.mjs';",
    "const file = new URL('../node_modules/private-module/index.mjs', import.meta.url);"
  ]) {
    await f.put('lib/entry.mjs', program);
    await assert.rejects(checkPackage({ root: f.root }), /omitted runtime artifacts/);
  }
});

test('malformed metadata and invalid license fields never echo their contents', async t => {
  const f = await fixture(t), privateValue = 'sensitive-field-' + 'x'.repeat(40);
  await f.put('package.json', '{"name":"' + privateValue);
  await assert.rejects(checkPackage({ root: f.root }), error => {
    assert.equal(error.message, 'Missing or invalid package metadata: package.json');
    assert.ok(!error.message.includes(privateValue)); return true;
  });
  await f.packageMetadata({ ...f.metadata, license: privateValue });
  await assert.rejects(checkPackage({ root: f.root }), error => {
    assert.equal(error.message, 'Community license must remain Apache-2.0: package.json');
    assert.ok(!error.message.includes(privateValue)); return true;
  });
  await f.packageMetadata();
  await f.put('package-lock.json', '{"private":"' + privateValue);
  await assert.rejects(checkPackage({ root: f.root }), error => {
    assert.equal(error.message, 'Invalid locked dependency metadata: package-lock.json');
    assert.ok(!error.message.includes(privateValue)); return true;
  });
});
