import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { allowedPath, minorUpgrade, validateManifest, validateLock, validateRegistryArtifacts, reviewedCoverage, loadPolicy, digest } from '../scripts/ci/dependency-policy.mjs';
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
  const entry = { version: '1.0.0', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-YWJj' };
  const lock = item => ({ lockfileVersion: 3, packages: { 'node_modules/x': item } });
  validateLock(lock(entry));
  for (const item of [{ ...entry, resolved: 'https://attacker.example/x' }, { ...entry, resolved: 'https://secret@registry.npmjs.org/x' }, { ...entry, integrity: undefined }]) assert.throws(() => validateLock(lock(item)));
});
test('registry binding rejects an old or different package tarball masquerading as a fixed version', async () => {
  const release = { name: 'x', version: '1.0.1', dist: { tarball: 'https://registry.npmjs.org/x/-/x-1.0.1.tgz', integrity: 'sha512-Zml4ZWQ=' } };
  const entry = { version: '1.0.1', resolved: release.dist.tarball, integrity: release.dist.integrity };
  const lock = value => ({ lockfileVersion: 3, packages: { 'node_modules/x': value } });
  const fetchImpl = async url => {
    assert.equal(url, 'https://registry.npmjs.org/x/1.0.1');
    return Response.json(release);
  };
  await validateRegistryArtifacts(lock(entry), { fetchImpl });
  for (const patch of [
    { resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz', integrity: 'sha512-b2xk' },
    { resolved: 'https://registry.npmjs.org/y/-/y-1.0.1.tgz', integrity: 'sha512-b3RoZXI=' },
    { resolved: undefined }, { link: true }
  ]) await assert.rejects(validateRegistryArtifacts(lock({ ...entry, ...patch }), { fetchImpl }));
  await assert.rejects(validateRegistryArtifacts(lock(entry), { fetchImpl: async () => new Response('', { status: 503 }) }), /could not be verified/);
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
  assert.equal(allowedPath('src/test.js', policy), false);
  assert.equal(allowedPath('scripts/ci/run.mjs', policy), false);
  assert.throws(() => validateBundle({ ...bundle, changes: [bundle.changes[0], bundle.changes[0]] }, expected));
});
test('CI services enforce parent upgrade policy as well as the target', async () => {
  const services = await ciServices();
  assert.throws(() => services.validateChanges([{ currentVersion: '1.0.0', targetVersion: '1.0.1' }, { currentVersion: '2.0.0', targetVersion: '3.0.0' }]));
});
test('CI verification requires every approved install and check without substitutions', async () => {
  const services = await ciServices();
  const phase = {
    setup: ['.', 'offense', 'site', 'agent/spectral'].map(directory => ({ directory, command: ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'] })),
    checks: services.checks
  };
  services.validateVerification(phase);
  for (const section of ['setup', 'checks']) {
    for (let i = 0; i < phase[section].length; i++) {
      const shortened = structuredClone(phase); shortened[section].splice(i, 1);
      assert.throws(() => services.validateVerification(shortened), /full trusted/);
    }
    const replaced = structuredClone(phase); replaced[section][0].command = ['true'];
    assert.throws(() => services.validateVerification(replaced), /full trusted/);
  }
});
test('untracked verification files are refused before candidate commands run', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'offense-ci-policy-'));
  try {
    execFileSync('git', ['init', dir], { stdio: 'pipe' });
    execFileSync('git', ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '--allow-empty', '-m', 'fixture'], { cwd: dir, stdio: 'pipe' });
    await mkdir(path.join(dir, 'src'));
    await writeFile(path.join(dir, 'src/new.js'), 'export const value = 1;');
    const services = await ciServices();
    await services.validateCandidate(dir, dir);
    await writeFile(path.join(dir, 'src/test.js'), 'process.exit(0);');
    await assert.rejects(services.validateCandidate(dir, dir), /manual review/);
  } finally { await rm(dir, { recursive: true, force: true }); }
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

test('the always-present CI gate fails closed on missing, failed, cancelled or unexpectedly skipped checks', async () => {
  const ci = YAML.parse(await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8'));
  assert.deepEqual(ci.on.push.branches, ['main']);
  assert.equal(ci.on.pull_request, null);
  assert.equal(ci.concurrency['cancel-in-progress'], true);
  assert.equal(ci.jobs['ci-gate'].if, '${{ always() }}');
  assert.deepEqual(ci.jobs['ci-gate'].needs, ['changes', 'verify', 'audit', 'cli', 'runtime']);
  for (const name of ['dependency-audit', 'cli-release', 'dependency-runtime']) {
    const workflow = YAML.parse(await readFile(new URL(`../.github/workflows/${name}.yml`, import.meta.url), 'utf8'));
    assert.deepEqual(Object.keys(workflow.on).sort(), ['workflow_call', 'workflow_dispatch']);
    assert.deepEqual(workflow.permissions, { contents: 'read' });
    assert.doesNotMatch(JSON.stringify(workflow), /secrets\.|secrets: inherit/);
  }
  const gate = ci.jobs['ci-gate'].steps[0].run;
  const success = { CHANGES: 'success', VERIFY: 'success', AUDIT: 'success', CLI: 'success', RUNTIME_REQUIRED: 'true', RUNTIME: 'success' };
  const run = patch => execFileSync('bash', ['-eu', '-c', gate], { env: { PATH: process.env.PATH, ...success, ...patch }, stdio: 'pipe' });
  assert.match(run({}).toString(), /All applicable CI checks passed/);
  assert.match(run({ RUNTIME_REQUIRED: 'false', RUNTIME: 'skipped' }).toString(), /All applicable CI checks passed/);
  for (const key of ['CHANGES', 'VERIFY', 'AUDIT', 'CLI', 'RUNTIME']) {
    for (const result of ['failure', 'cancelled', 'skipped', '']) assert.throws(() => run({ [key]: result }));
  }
  for (const required of ['', 'unknown']) assert.throws(() => run({ RUNTIME_REQUIRED: required, RUNTIME: 'skipped' }));
  assert.throws(() => run({ RUNTIME_REQUIRED: 'false', RUNTIME: 'failure' }));
});

test('runtime selection handles docs-only PRs, affected files and deletions without workflow path filters', async () => {
  const ci = YAML.parse(await readFile(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8'));
  const script = ci.jobs.changes.steps.find(step => step.id === 'paths').run;
  const root = await mkdtemp(path.join(tmpdir(), 'ci-paths-'));
  const git = args => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: 'pipe' }).trim();
  const commit = () => { git(['add', '.']); git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-m', 'fixture']); return git(['rev-parse', 'HEAD']); };
  try {
    git(['init']); const base = commit();
    const output = path.join(root, '.git', 'output');
    const run = async (event, head) => {
      await writeFile(output, '');
      execFileSync('bash', ['-eu', '-c', script], { cwd: root, env: { PATH: process.env.PATH, EVENT: event, BASE: base, HEAD: head, GITHUB_OUTPUT: output }, stdio: 'pipe' });
      return readFile(output, 'utf8');
    };
    await writeFile(path.join(root, 'README.md'), 'documentation');
    assert.equal(await run('pull_request', commit()), 'runtime=false\n');
    for (const file of ['agent/runtime.mjs', 'scripts/offense.mjs', 'public/skills/purple/scripts/purple.mjs', 'package-lock.json', '.github/workflows/ci.yml', 'test/new.test.js']) {
      await mkdir(path.dirname(path.join(root, file)), { recursive: true });
      await writeFile(path.join(root, file), 'changed');
      assert.equal(await run('pull_request', commit()), 'runtime=true\n');
      git(['reset', '--hard', base]);
    }
    await mkdir(path.join(root, 'agent'), { recursive: true });
    await writeFile(path.join(root, 'agent/deleted.mjs'), 'removed');
    const beforeDelete = commit(); git(['rm', 'agent/deleted.mjs']); const deleted = commit();
    execFileSync('bash', ['-eu', '-c', script], { cwd: root, env: { PATH: process.env.PATH, EVENT: 'pull_request', BASE: beforeDelete, HEAD: deleted, GITHUB_OUTPUT: output }, stdio: 'pipe' });
    assert.match(await readFile(output, 'utf8'), /runtime=true\n$/);
    assert.equal(await run('push', ''), 'runtime=true\n');
    assert.equal(await run('workflow_dispatch', ''), 'runtime=true\n');
    await assert.rejects(run('pull_request', 'missing-revision'));
  } finally { await rm(root, { recursive: true, force: true }); }
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

test('publisher only reuses an open draft whose base, bytes and file modes still match', async () => {
  const { publishBundle } = await import('../scripts/ci/publish-dependency-pr.mjs');
  const policy = await loadPolicy(), content = Buffer.from('export const x = 2;');
  const expected = { repository: 'example/repo', runId: '1', engineSha: 'e'.repeat(40) };
  const bundle = { version: 1, ...expected, baseSha: 'a'.repeat(40), finishedAt: Date.now(), policyHash: digest(JSON.stringify(policy)), body: 'Verified',
    evidence: { baselinePassed: true, candidatePassed: true, advisoriesComplete: true, newAdvisories: 0 }, changes: [{ path: 'src/app.js', mode: '100644', status: 'M', content: content.toString('base64'), sha256: digest(content) }] };
  const branch = `offense/dependencies-${bundle.baseSha.slice(0, 12)}-${digest(JSON.stringify(bundle.changes)).slice(0, 12)}`;
  const sha = createHash('sha1').update(`blob ${content.length}\0`).update(content).digest('hex');
  const pr = { state: 'open', draft: true, base: { ref: 'main' }, head: { ref: branch, sha: 'b'.repeat(40), repo: { full_name: expected.repository } }, html_url: 'https://github.com/example/repo/pull/1' };
  let mutation = '';
  const api = async (method, endpoint) => {
    assert.equal(method, 'GET', 'Reuse must not write or overwrite anything.');
    if (endpoint === '/repos/example/repo') return { default_branch: 'main', owner: { login: 'example' } };
    if (endpoint.endsWith('/git/ref/heads/main')) return { object: { sha: bundle.baseSha } };
    if (endpoint.includes('/git/ref/heads/')) return { object: { sha: pr.head.sha } };
    if (endpoint.includes('/pulls?')) return [{ ...pr, ...(mutation === 'closed' ? { state: 'closed' } : mutation === 'ready' ? { draft: false } : mutation === 'retargeted' ? { base: { ref: 'other' } } : {}) }];
    if (endpoint.includes('/compare/')) return { total_commits: 1, files: [{ filename: 'src/app.js', status: 'modified', sha: mutation === 'bytes' ? 'bad' : sha }] };
    if (endpoint.includes('/git/commits/')) return { parents: [{ sha: bundle.baseSha }], tree: { sha: 'c'.repeat(40) } };
    if (endpoint.includes('/git/trees/')) return { truncated: false, tree: [{ path: 'src/app.js', type: 'blob', sha, mode: mutation === 'mode' ? '100755' : '100644' }] };
    throw Error(`Unexpected request: ${endpoint}`);
  };
  assert.equal(await publishBundle(bundle, { policy, api, expected }), pr.html_url);
  for (mutation of ['closed', 'ready', 'retargeted', 'bytes', 'mode']) await assert.rejects(publishBundle(bundle, { policy, api, expected }), /Existing PR/);
});
