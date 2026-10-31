import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { parse } from 'yaml';
import { installationUrl } from '../src/install.js';

const template = await readFile(new URL('../public/templates/offense.yml', import.meta.url), 'utf8');
const workflow = parse(template);

test('installation links preserve the complete workflow and selected repository and branch', () => {
  for (const repository of ['octocat/example', 'https://github.com/octocat/example/', ' https://github.com/octocat/example.git ']) {
    const url = new URL(installationUrl(repository, 'release/1.x', template));
    assert.equal(url.origin, 'https://github.com');
    assert.equal(url.pathname, '/octocat/example/new/release/1.x');
    assert.equal(url.searchParams.get('filename'), '.github/workflows/offense.yml');
    assert.equal(url.searchParams.get('value'), template);
    assert.equal(url.hash, '');
  }
  assert.match(installationUrl('Team/repo.name', 'master', template), /\/Team\/repo.name\/new\/master\?/);
  for (const repository of ['', 'repo', 'owner/..', 'owner/repo/tree/main', 'owner/repo?x=1', 'https://github.com.evil.test/a/b', 'https://u:p@github.com/a/b', 'javascript:alert(1)', 'owner/repo#x', 'owner/ repo', '-owner/repo']) {
    assert.throws(() => installationUrl(repository, 'main', template), /Enter owner\/repository/);
  }
  for (const branch of ['', '../main', 'foo//bar', 'main?x=y', 'main..other', 'main@{1}', 'a.lock', '-main', 'a\nb', 'a/.hidden', 'main~1']) {
    assert.throws(() => installationUrl('owner/repo', branch, template), /existing base branch/);
  }
});

test('starter workflow is pinned, read-only and keeps project code separate from scanner installation', () => {
  assert.deepEqual(Object.keys(workflow.on).sort(), ['pull_request', 'workflow_dispatch']);
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  const { steps } = workflow.jobs.audit;
  for (const step of steps.filter(step => step.uses)) assert.match(step.uses, /@[a-f0-9]{40}$/);
  const checkouts = steps.filter(step => step.uses?.startsWith('actions/checkout@'));
  assert.deepEqual(checkouts.map(step => step.with['persist-credentials']), [false, false]);
  assert.deepEqual(checkouts.map(step => step.with.path), ['project', 'engine']);
  assert.equal(checkouts[1].with.repository, 'offense-research/offense');
  assert.match(checkouts[1].with.ref, /^[a-f0-9]{40}$/);
  assert.doesNotMatch(template, /secrets\.|pull_request_target|continue-on-error|npm --prefix project|npm install/);
  const artifact = steps.find(step => step.uses?.startsWith('actions/upload-artifact@'));
  assert.equal(artifact.with['retention-days'], 7);
  assert.equal(artifact.if, '${{ !cancelled() }}');
});

test('the installed check reports advisories but fails incomplete coverage and missing evidence', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'offense-workflow-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(path.join(directory, 'offense-report'));
  const summary = path.join(directory, 'summary.md');
  const script = workflow.jobs.audit.steps.find(step => step.name?.startsWith('Check coverage')).run;
  const run = () => spawnSync('bash', ['-e', '-c', script], {
    encoding: 'utf8', env: { PATH: process.env.PATH, RUNNER_TEMP: directory, GITHUB_STEP_SUMMARY: summary },
  });
  for (const [findings, warnings, expected] of [[[], [], 0], [[{ severity: 'HIGH' }], [], 0], [[], ['unscanned lockfile'], 1]]) {
    await writeFile(path.join(directory, 'offense-report/scan.json'), JSON.stringify({ vulnerabilityCheck: { findings }, warnings }));
    await writeFile(summary, '');
    const result = run();
    assert.equal(result.status, expected, result.stderr);
    assert.match(await readFile(summary, 'utf8'), new RegExp(`${findings.length} advisory matches; ${warnings.length} coverage warnings`));
  }
  await rm(path.join(directory, 'offense-report/scan.json'));
  assert.notEqual(run().status, 0);
});
