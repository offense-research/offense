import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, lstat, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createOffenseCli } from '../scripts/offense-cli.mjs';
import { StackCollectionError } from '../scripts/stack-collection.mjs';

async function fixture(t, overrides = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'offense-stack-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project'); await mkdir(project);
  const badConfig = path.join(root, 'bad-config'); await writeFile(badConfig, 'not a directory');
  const stdout = [], stderr = [], calls = [];
  const snapshot = { schemaVersion: 'offense.stack.snapshot.v1', capturedAt: '2026-10-28T00:00:00Z', gaps: [] };
  const report = { schemaVersion: 'offense.stack.report.v1', status: 'complete', chainStatus: 'aligned',
    drift: [], gaps: [], findings: [], securityCoverage: { status: 'not_assessed' }, planHash: 'a'.repeat(64),
    agentPrompt: 'Review the exact source, image and deployment before acting.' };
  const cli = createOffenseCli({
    env: { OFFENSE_CONFIG_DIR: badConfig, OFFENSE_API_URL: 'this must not be read' },
    output: value => stdout.push(value), diagnostic: value => stderr.push(value),
    fetchImpl: async () => { throw Error('Local stack operations must not call the hosted service'); },
    stackCollect: async options => { calls.push({ kind: 'collect', options }); return snapshot; },
    stackAnalyze: async (value, options) => { assert.equal(value, snapshot); calls.push({ kind: 'analyze', options }); return report; },
    stackBuild: async options => { calls.push({ kind: 'build', options }); return { receipt: { schemaVersion: 'offense.stack.build.v1' }, image: { id: 'sha256:' + 'b'.repeat(64) } }; },
    ...overrides,
  });
  return { root, project, cli, calls, snapshot, report, out: () => JSON.parse(stdout.at(-1)), err: () => JSON.parse(stderr.at(-1)) };
}

test('stack check bypasses authentication and endpoint settings and preserves private local evidence', async t => {
  const f = await fixture(t), output = path.join(f.root, 'check');
  assert.equal(await f.cli.run(['stack', 'check', '--project', f.project, '--container', 'staging', '--output', output]), 0);
  assert.equal(f.out().chainStatus, 'aligned');
  assert.equal(f.out().securityCoverage.status, 'not_assessed');
  assert.equal(f.out().confirmedVulnerabilities, 0);
  assert.match(f.out().note, /does not establish vulnerability absence/);
  assert.deepEqual(JSON.parse(await readFile(f.out().snapshot)), f.snapshot);
  assert.deepEqual(JSON.parse(await readFile(f.out().report)), f.report);
  assert.equal(await readFile(f.out().prompt, 'utf8'), f.report.agentPrompt + '\n');
  for (const file of [output, f.out().snapshot, f.out().report, f.out().prompt]) assert.equal((await lstat(file)).mode & 0o077, 0);
});

test('stack check retains drift and partial coverage and returns a nonpassing exit', async t => {
  const f = await fixture(t);
  f.report.status = 'partial'; f.report.chainStatus = 'drift';
  f.report.drift.push({ code: 'deployed_image_differs' }); f.report.gaps.push({ code: 'scan_subject_mismatch' });
  assert.equal(await f.cli.run(['stack', 'check', '--project', f.project, '--output', path.join(f.root, 'partial')]), 2);
  assert.equal(f.out().drift, 1); assert.equal(f.out().gaps, 1);
  assert.equal(JSON.parse(await readFile(f.out().report)).chainStatus, 'drift');
});

test('preview never builds or creates evidence and build requires an explicit execution choice', async t => {
  const f = await fixture(t), output = path.join(f.root, 'preview');
  assert.equal(await f.cli.run(['stack', 'build', '--project', f.project, '--image', 'example/app:test', '--output', output]), 0);
  assert.equal(f.out().status, 'preview'); assert.equal(f.calls.length, 0);
  await assert.rejects(lstat(output), { code: 'ENOENT' });
  assert.equal(await f.cli.run(['stack', 'build', '--project', f.project, '--image', 'example/app:test', '--preview', '--run']), 1);
  assert.equal(f.calls.length, 0);
});

test('explicit local build writes the receipt without hosted credentials', async t => {
  const f = await fixture(t), output = path.join(f.root, 'build');
  assert.equal(await f.cli.run(['stack', 'build', '--project', f.project, '--image', 'example/app:test', '--dockerfile', 'build/Dockerfile', '--run', '--output', output]), 0);
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].kind, 'build');
  assert.equal(f.calls[0].options.dockerfile, 'build/Dockerfile');
  assert.equal(JSON.parse(await readFile(f.out().receipt)).schemaVersion, 'offense.stack.build.v1');
  assert.match(f.out().assurance, /not signed/);
});

test('reports cannot overwrite source, existing evidence or symlink destinations', async t => {
  const f = await fixture(t);
  assert.equal(await f.cli.run(['stack', 'check', '--project', f.project, '--output', f.project]), 1);
  assert.equal(f.calls.length, 0);
  const output = path.join(f.root, 'reports'); await mkdir(output, { mode: 0o700 });
  const existing = path.join(output, 'stack-report.json'); await writeFile(existing, 'previous evidence');
  assert.equal(await f.cli.run(['stack', 'check', '--project', f.project, '--output', output]), 1);
  assert.equal(await readFile(existing, 'utf8'), 'previous evidence'); assert.equal(f.calls.length, 0);
  await rm(existing); await symlink(f.project, path.join(output, 'stack-report.json'));
  assert.equal(await f.cli.run(['stack', 'check', '--project', f.project, '--output', output]), 1);
  assert.equal(f.calls.length, 0);
});

test('a built image with an unavailable digest mapping is retained as partial evidence', async t => {
  const f = await fixture(t, { stackBuild: async () => ({ receipt: { schemaVersion: 'offense.stack.build.v1' },
    image: { id: 'sha256:' + 'b'.repeat(64), mappingVerified: false },
    gaps: [{ code: 'image_digest_mapping_unavailable', message: 'The image mapping was not established.' }] }) });
  assert.equal(await f.cli.run(['stack', 'build', '--project', f.project, '--image', 'example/app:test', '--run']), 2);
  assert.equal(f.out().built, true); assert.equal(f.out().status, 'partial');
  assert.equal(f.out().gaps[0].code, 'image_digest_mapping_unavailable');
  assert.equal(JSON.parse(await readFile(f.out().receipt)).schemaVersion, 'offense.stack.build.v1');
});

test('fixed collection errors explain the missing prerequisite without relaying process details', async t => {
  const f = await fixture(t, { stackBuild: async () => { throw new StackCollectionError('build_requires_clean_repository', 'Commit or isolate source changes before building.'); } });
  assert.equal(await f.cli.run(['stack', 'build', '--project', f.project, '--image', 'example/app:test', '--run']), 1);
  assert.equal(f.err().error.code, 'build_requires_clean_repository');
  assert.match(f.err().error.message, /isolate source changes/);
});

test('stack options reject unrelated hosted flags and extra positional arguments before collection', async t => {
  const f = await fixture(t);
  for (const args of [['stack', 'check', '--endpoint', 'https://example.com'], ['stack', 'check', 'unexpected'], ['stack', 'build', '--run']]) {
    assert.equal(await f.cli.run([...args, '--project', f.project]), 1);
  }
  assert.equal(f.calls.length, 0);
});
