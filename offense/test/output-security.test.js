import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, stat, access } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { analyze } from '../tools/purple.mjs';
import { reserveExternalOutput } from '../tools/output.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-output-fixture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project'); await mkdir(project);
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ dependencies: { semver: '7.5.1' } }));
  await writeFile(path.join(project, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
    '': { dependencies: { semver: '7.5.1' } }, 'node_modules/semver': { version: '7.5.1' }
  } }));
  const sentinel = path.join(root, 'unrelated'); await writeFile(sentinel, 'preserve-existing-content');
  return { root, project, sentinel };
}

test('scan rejects existing/symlink/checkout outputs before any provider request and preserves unrelated files', async t => {
  const f = await fixture(t), existing = path.join(f.root, 'existing'); await mkdir(existing);
  await symlink(f.sentinel, path.join(existing, 'scan.json'));
  await symlink(f.sentinel, path.join(existing, 'remediation.md'));
  const link = path.join(f.root, 'link'); await symlink(existing, link);
  const outputs = [existing, link, path.join(link, 'new-report'), path.join(f.project, 'report')];
  let calls = 0;
  for (const output of outputs) await assert.rejects(analyze(f.project, { output,
    fetchImpl() { calls++; throw Error('Provider should not be contacted for invalid output'); }, log() {} }));
  assert.equal(calls, 0);
  assert.equal(await readFile(f.sentinel, 'utf8'), 'preserve-existing-content');
  await assert.rejects(access(path.join(f.project, 'report')), { code: 'ENOENT' });
});

test('owned report updates are private and concurrent edits are preserved', async t => {
  const f = await fixture(t), output = await reserveExternalOutput(f.project, path.join(f.root, 'report'));
  await output.write('scan.json', 'first');
  await output.write('scan.json', 'second');
  const file = path.join(output.directory, 'scan.json');
  assert.equal(await readFile(file, 'utf8'), 'second');
  assert.equal((await stat(output.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  await writeFile(file, 'user-modified');
  await assert.rejects(output.write('scan.json', 'overwrite'), /preserved/);
  assert.equal(await readFile(file, 'utf8'), 'user-modified');
});

test('a report target replaced by a symlink is never followed', async t => {
  const f = await fixture(t), output = await reserveExternalOutput(f.project, path.join(f.root, 'report'));
  await output.write('scan.json', 'first');
  await rm(path.join(output.directory, 'scan.json'));
  await symlink(f.sentinel, path.join(output.directory, 'scan.json'));
  await assert.rejects(output.write('scan.json', 'overwrite'), /preserved/);
  assert.equal(await readFile(f.sentinel, 'utf8'), 'preserve-existing-content');
});
