import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { analyze } from '../tools/purple.mjs';
import { triage } from '../tools/evidence.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-community-triage-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project'); await mkdir(project);
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ name: 'synthetic-review', private: true,
    dependencies: { lodash: '4.17.20' } }));
  await writeFile(path.join(project, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
    '': { name: 'synthetic-review', dependencies: { lodash: '4.17.20' } },
    'node_modules/lodash': { version: '4.17.20' }
  } }));
  await writeFile(path.join(project, 'app.mjs'), "import {template} from 'lodash'; export function render(value){return template(value);}\n");
  for (const args of [['init', '-q'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com',
    '-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', 'Synthetic review fixture']])
    execFileSync('git', args, { cwd: project, stdio: 'pipe' });
  return { root, project };
}
const id = 'GHSA-35jh-r3h4-6jhm';
async function advisory(url) {
  assert.equal(new URL(url).hostname, 'api.osv.dev');
  return String(url).endsWith('/querybatch') ? Response.json({ results: [{ vulns: [{ id }] }] }) : Response.json({
    id, aliases: ['CVE-2021-23337'], summary: 'Synthetic advisory response for static review',
    details: 'Review template compilation options and attacker control before assessing applicability.',
    references: [{ type: 'ADVISORY', url: 'https://github.com/advisories/' + id }],
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, database_specific: { severity: 'HIGH' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }]
  });
}

test('direct-provider scan feeds local triage without a hosted account and retains advisory uncertainty', async t => {
  const f = await fixture(t);
  const scan = await analyze(f.project, { planLimit: 0, output: path.join(f.root, 'scan'), fetchImpl: advisory, log() {} });
  const result = await triage(f.project, { scanFile: scan.json, output: path.join(f.root, 'review') });
  assert.equal(result.needs_review, 1);
  assert.equal(result.staticPathsFound, 1);
  const evidence = JSON.parse(await readFile(result.evidence, 'utf8'));
  assert.equal(evidence.findings[0].reachability, 'static_path_found');
  assert.equal(evidence.findings[0].verification, 'unassessed');
  assert.equal(evidence.totals.not_affected, 0);
  assert.match(await readFile(result.handoff, 'utf8'), /not reproduced vulnerabilities or verified fixes/);
});

test('triage rejects a dependency snapshot changed after the direct-provider scan', async t => {
  const f = await fixture(t);
  const scan = await analyze(f.project, { planLimit: 0, output: path.join(f.root, 'scan'), fetchImpl: advisory, log() {} });
  await writeFile(path.join(f.project, 'package.json'), JSON.stringify({ name: 'changed-fixture', dependencies: { lodash: '4.17.20' } }));
  await assert.rejects(triage(f.project, { scanFile: scan.json, output: path.join(f.root, 'review') }), /stale/);
});

test('triage preserves existing report targets and does not create output inside the checkout', async t => {
  const f = await fixture(t);
  const scan = await analyze(f.project, { planLimit: 0, output: path.join(f.root, 'scan'), fetchImpl: advisory, log() {} });
  const sentinel = path.join(f.root, 'unrelated'); await writeFile(sentinel, 'preserve');
  const existing = path.join(f.root, 'review'); await mkdir(existing);
  await symlink(sentinel, path.join(existing, 'triage.json'));
  await assert.rejects(triage(f.project, { scanFile: scan.json, output: existing }), /new directory/);
  await assert.rejects(triage(f.project, { scanFile: scan.json, output: path.join(f.project, 'review') }), /outside/);
  assert.equal(await readFile(sentinel, 'utf8'), 'preserve');
  await assert.rejects(access(path.join(f.project, 'review')), { code: 'ENOENT' });
});
