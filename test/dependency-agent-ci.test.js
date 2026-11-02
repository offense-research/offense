import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { allowedPath, minorUpgrade, validateManifest, validateLock, reviewedCoverage, loadPolicy, digest } from '../scripts/ci/dependency-policy.mjs';
import { validateBundle } from '../scripts/ci/dependency-bundle.mjs';
import { ciServices } from '../scripts/ci/dependency-services.mjs';
import YAML from 'yaml';

test('upgrade policy rejects breaking, prerelease and downgrade candidates', () => {
  for (const pair of [['1.2.3', '1.2.4'], ['1.2.3', '1.3.0'], ['0.2.3', '0.2.4']]) assert.equal(minorUpgrade(...pair), true);
  for (const pair of [['1.2.3', '2.0.0'], ['0.2.3', '0.3.0'], ['1.2.3', '1.2.3'], ['1.2.3', '1.2.2'], ['1.2.3', '1.3.0-beta'], ['file:x', '1.2.3']]) assert.equal(minorUpgrade(...pair), false);
});
test('manifest checks preserve execution policy and reject supply-chain changes', () => {
  const before = { scripts: { test: 'node --test' }, engines: { node: '>=24' }, dependencies: { x: '^1.2.3' } };
  validateManifest(before, { ...before, dependencies: { x: '^1.2.4' } });
  for (const after of [{ ...before, scripts: { test: 'true' } }, { ...before, dependencies: { x: 'https://attacker.example/x' } }, { ...before, dependencies: { x: '2.0.0' } }, { ...before, dependencies: { x: '^1.2.3', y: '1.0.0' } }]) assert.throws(() => validateManifest(before, after));
});
test('registry policy rejects credentials, custom registries and absent integrity', () => {
  const entry = { resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-YWJj' };
  const lock = item => ({ lockfileVersion: 3, packages: { 'node_modules/x': item } });
  validateLock(lock(entry));
  for (const item of [{ ...entry, resolved: 'https://attacker.example/x' }, { ...entry, resolved: 'https://secret@registry.npmjs.org/x' }, { ...entry, integrity: undefined }]) assert.throws(() => validateLock(lock(item)));
});
test('coverage exclusions stop being valid when a distribution manifest acquires dependencies', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'offense-ci-'));
  try {
    await mkdir(path.join(dir, 'cli'));
    await writeFile(path.join(dir, 'cli/package.json'), '{}');
    await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {} }));
    const policy = { lockfiles: ['package-lock.json'], dependencyFreeManifests: ['cli/package.json'] };
    const metadata = { files: [{ path: 'package-lock.json' }], warnings: ['cli/package.json: no covering lockfile importer was found; verify coverage.'] };
    assert.deepEqual((await reviewedCoverage(dir, metadata, policy)).warnings, []);
    await writeFile(path.join(dir, 'cli/package.json'), JSON.stringify({ dependencies: { x: '1.0.0' } }));
    await assert.rejects(reviewedCoverage(dir, metadata, policy), /now declares dependencies/);
    await assert.rejects(reviewedCoverage(dir, { ...metadata, files: [] }, policy), /inventory changed/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('delivery validation rejects tampering, wrong run, stale evidence and protected paths', async () => {
  const policy = await loadPolicy(), now = Date.now();
  const expected = { repository: 'example/repo', runId: '123', engineSha: 'b'.repeat(40), policy, now };
  const content = Buffer.from('export const x = 1;');
  const bundle = { version: 1, repository: expected.repository, runId: '123', engineSha: expected.engineSha, baseSha: 'a'.repeat(40), finishedAt: now,
    policyHash: digest(JSON.stringify(policy)), body: 'Verified upgrade.', evidence: { baselinePassed: true, candidatePassed: true, advisoriesComplete: true, newAdvisories: 0 },
    changes: [{ path: 'src/x.js', mode: '100644', status: 'M', content: content.toString('base64'), sha256: digest(content) }] };
  validateBundle(bundle, expected);
  for (const patch of [{ runId: '124' }, { finishedAt: now - 3600001 }, { policyHash: 'bad' }, { evidence: { ...bundle.evidence, newAdvisories: 1 } }]) assert.throws(() => validateBundle({ ...bundle, ...patch }, expected));
  for (const patch of [{ path: '.github/workflows/ci.yml' }, { path: '../src/x.js' }, { content: Buffer.from('changed').toString('base64') }, { mode: '120000' }]) assert.throws(() => validateBundle({ ...bundle, changes: [{ ...bundle.changes[0], ...patch }] }, expected));
  assert.equal(allowedPath('test/security.test.js', policy), false);
  assert.equal(allowedPath('scripts/ci/run.mjs', policy), false);
  assert.throws(() => validateBundle({ ...bundle, changes: [bundle.changes[0], bundle.changes[0]] }, expected));
});
test('CI services enforce parent upgrade policy as well as the target', async () => {
  const services = await ciServices();
  assert.throws(() => services.validateChanges([{ currentVersion: '1.0.0', targetVersion: '1.0.1' }, { currentVersion: '2.0.0', targetVersion: '3.0.0' }]));
});
test('workflow has no fork-triggered secret path, keeps publisher separate, and pins all actions', async () => {
  const audit = YAML.parse(await readFile(new URL('../.github/workflows/dependency-audit.yml', import.meta.url), 'utf8'));
  const agent = YAML.parse(await readFile(new URL('../.github/workflows/dependency-agent.yml', import.meta.url), 'utf8'));
  assert.equal(Object.hasOwn(agent.on, 'pull_request'), false);
  assert.equal(Object.hasOwn(agent.on, 'pull_request_target'), false);
  assert.equal(audit.permissions.contents, 'read');
  assert.equal(agent.jobs.repair.permissions, undefined);
  assert.equal(agent.jobs.publish.permissions.contents, 'write');
  const secretSteps = agent.jobs.repair.steps.filter(s => JSON.stringify(s).includes('secrets.'));
  assert.equal(secretSteps.length, 1);
  assert.match(secretSteps[0].run, /dependencies fix/);
  assert.doesNotMatch(JSON.stringify(agent.jobs.publish), /npm |docker |OPENROUTER/);
  for (const wf of [audit, agent]) for (const job of Object.values(wf.jobs)) for (const step of job.steps) if (step.uses) assert.match(step.uses, /@[a-f0-9]{40}$/);
});

test('plan selection preserves findings and chooses a checked nonbreaking group', async () => {
  const { selectPlan } = await import('../scripts/ci/select-dependency-plan.mjs');
  const findings = [{ package: 'x', version: '1.0.0', severity: 'HIGH' }, { package: 'y', version: '1.0.0', severity: 'CRITICAL' }];
  const plans = [{ name: 'x', currentVersion: '1.0.0', targetVersion: '2.0.0', considered: [{ version: '2.0.0', advisories: 0 }] }, { name: 'y', currentVersion: '1.0.0', targetVersion: '1.0.1', considered: [{ version: '1.0.1', advisories: 0 }] }];
  const scan = { vulnerabilityCheck: { status: 'complete', findings }, warnings: [], plans };
  assert.equal(selectPlan(scan).name, 'y');
  assert.equal(scan.vulnerabilityCheck.findings.length, 2);
  assert.equal(selectPlan({ ...scan, plans: [] }), undefined);
  assert.throws(() => selectPlan({ ...scan, warnings: ['partial'] }));
});

test('publisher makes no writes when the base moved and creates only a draft with a stable base', async () => {
  const { publishBundle } = await import('../scripts/ci/publish-dependency-pr.mjs');
  const policy = await loadPolicy();
  const expected = { repository: 'example/repo', runId: '1', engineSha: 'e'.repeat(40) };
  const content = Buffer.from('export const x = 2;');
  const bundle = { version: 1, ...expected, baseSha: 'a'.repeat(40), finishedAt: Date.now(), policyHash: digest(JSON.stringify(policy)), body: 'Compatibility evidence',
    evidence: { baselinePassed: true, candidatePassed: true, advisoriesComplete: true, newAdvisories: 0 }, changes: [{ path: 'src/app.js', mode: '100644', status: 'M', content: content.toString('base64'), sha256: digest(content) }] };
  const calls = [];
  let moved = true;
  const api = async (method, endpoint, body) => {
    calls.push({ method, endpoint, body });
    if (endpoint === '/repos/example/repo') return { default_branch: 'main', owner: { login: 'example' }, html_url: 'https://github.com/example/repo' };
    if (endpoint.includes('/git/ref/')) return { object: { sha: moved ? 'b'.repeat(40) : bundle.baseSha } };
    if (endpoint.includes('/pulls?')) return [];
    if (method === 'GET' && endpoint.includes('/git/commits/')) return { tree: { sha: 'base-tree' } };
    if (endpoint.endsWith('/pulls')) return { html_url: 'https://github.com/example/repo/pull/1' };
    return { sha: 'created' };
  };
  await assert.rejects(publishBundle(bundle, { policy, api, expected }), /branch moved/);
  assert.equal(calls.filter(c => c.method !== 'GET').length, 0);
  calls.length = 0; moved = false;
  assert.equal(await publishBundle(bundle, { policy, api, expected }), 'https://github.com/example/repo/pull/1');
  assert.equal(calls.find(c => c.endpoint.endsWith('/pulls')).body.draft, true);
  assert.deepEqual(calls.find(c => c.method === 'POST' && c.endpoint.endsWith('/git/commits')).body.parents, [bundle.baseSha]);
});
