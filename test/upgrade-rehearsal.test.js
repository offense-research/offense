import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, mkdir, readFile, writeFile, rm, chmod } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createUpgradeRehearsals, proposeRehearsal, rehearsalOptions, validateRehearsalScenarios, allowedRehearsalChanges } from '../server/upgrade-rehearsal.js';
import { runUpgradeRehearsal, rehearsalProgram } from '../agent/upgrade-rehearsal.js';
import { buildOneShotPrompt } from '../src/remediation-prompts.js';

const change = { name: 'semver', currentVersion: '7.5.1', targetVersion: '7.5.2' };
const plan = { ...change, name: 'semver', impact: { parents: [], paths: [] }, parentOptions: [], steps: [] };
const snapshot = { repository: 'org/repo', installationId: 1, revision: 'a'.repeat(40), scannedAt: 1,
  files: ['package-lock.json'], graph: { nodes: [{}] }, vulnerabilityCheck: { checkedAt: 2, status: 'complete', findings: [{ id: 'old', package: 'semver', version: '7.5.1' }] } };
const scenario = { rationale: 'Update the checked semver target.', changes: [change] };

test('unchanged automatic refreshes during planning and execution keep the simulation pinned and reusable', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
    const session = { github: { installationId: 1, account: 'org' } };
    db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
    let current = structuredClone(snapshot), starts = 0, reads = 0;
    const refresh = () => { current = { ...current, scannedAt: current.scannedAt + 100,
      vulnerabilityCheck: { ...current.vulnerabilityCheck, checkedAt: current.vulnerabilityCheck.checkedAt + 100 } }; };
    const service = createUpgradeRehearsals(db, {
      mapper: { snapshots: () => [current], upgradePlan: async () => { refresh(); return plan; } },
      github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => 'checkout-only' },
      sandbox: { start: async () => { starts++; return { status: 'running' }; }, get: async () => { reads++; return {
        status: 'completed', revision: snapshot.revision, baseline: { setup: [{ passed: true }], checks: [{ passed: true }], integrity: true },
        scenarios: [{ status: 'tests_passed', resolvedPackages: [{ name: 'semver', version: '7.5.2' }] }]
      }; } }, check: async () => ({ status: 'complete', checkedAt: Date.now(), findings: [] })
    });
    const first = service.start('workspace', 'org/repo', 1, session);
    assert.match(first.evidenceIdentity, /^[a-f0-9]{64}$/);
    await service.dispatch();
    assert.equal(service.latest('workspace', 'org/repo', 1).status, 'running');
    refresh(); await service.dispatch();
    const completed = service.latest('workspace', 'org/repo', 1);
    assert.equal(completed.status, 'completed'); assert.equal(completed.stale, false);
    assert.equal(completed.scannedAt, snapshot.scannedAt); assert.equal(completed.advisoryCheckedAt, snapshot.vulnerabilityCheck.checkedAt);
    assert.equal(completed.evidenceIdentity, first.evidenceIdentity);
    assert.equal(completed.result.revision, first.revision); assert.equal(starts, 1); assert.equal(reads, 1);
    assert.equal(service.start('workspace', 'org/repo', 1, session).id, first.id);
    db.prepare('UPDATE upgrade_rehearsals SET created_at = ? WHERE id = ?').run(Date.now() - 25 * 3600000, first.id);
    refresh(); assert.equal(service.latest('workspace', 'org/repo', 1).stale, true, 'an unchanged new observation cannot revive an expired candidate check');
  } finally { db.close(); }
});

test('real commit, graph and advisory changes during a simulation still invalidate its pinned evidence', async () => {
  for (const mutate of [
    value => { value.revision = 'b'.repeat(40); },
    value => { value.graph.nodes.push({ name: 'changed', version: '2.0.0' }); },
    value => { value.vulnerabilityCheck.findings.push({ id: 'new', package: 'semver', version: '7.5.1' }); },
    value => { value.vulnerabilityCheck.findings[0].fixedVersions = ['7.5.3']; }
  ]) {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
      const session = { github: { installationId: 1, account: 'org' } };
      db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
      const current = structuredClone(snapshot);
      const service = createUpgradeRehearsals(db, { mapper: { snapshots: () => [current], upgradePlan: async () => plan },
        github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => 'checkout-only' },
        sandbox: { start: async () => ({ status: 'running' }), get: async () => { throw new Error('Changed evidence must not reach the result polling step.'); } } });
      const pinned = service.start('workspace', 'org/repo', 1, session); await service.dispatch(); mutate(current); await service.dispatch();
      const failed = service.latest('workspace', 'org/repo', 1);
      assert.equal(failed.status, 'failed'); assert.equal(failed.stale, true); assert.match(failed.error, /dependency scan changed/);
      assert.equal(failed.evidenceIdentity, pinned.evidenceIdentity); assert.equal(failed.result, undefined);
    } finally { db.close(); }
  }
});

test('hosted simulation rejects manifest-only and partial unresolved evidence before using a free simulation', () => {
  const missingLockfiles = [{ manifest: 'package.json', packageManager: 'npm', expectedLockfiles: ['package-lock.json'], commands: [{ directory: '.', command: 'npm install --package-lock-only --ignore-scripts' }] }];
  for (const evidence of [
    { coverage: { status: 'manifest_only', complete: false, missingLockfiles } },
    { coverage: { status: 'partial', complete: false, missingLockfiles } },
    { vulnerabilityCheck: { ...snapshot.vulnerabilityCheck, findings: [{ ...snapshot.vulnerabilityCheck.findings[0], assessmentKind: 'declared_range', resolved: false }] } },
    { vulnerabilityCheck: { ...snapshot.vulnerabilityCheck, findings: [{ ...snapshot.vulnerabilityCheck.findings[0], assessmentKind: 'advisory_match', versionEvidence: 'declared_range', resolved: false }] } }
  ]) {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
      const session = { github: { installationId: 1, account: 'org' } };
      db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
      const service = createUpgradeRehearsals(db, { mapper: { snapshots: () => [{ ...snapshot, ...evidence }] }, sandbox: {} });
      assert.throws(() => service.start('workspace', 'org/repo', 1, session), error => error.status === 400 && error.code === 'lockfile_required' && /lockfile.*rescan/i.test(error.message));
      assert.equal(db.prepare('SELECT COUNT(*) AS count FROM upgrade_rehearsals').get().count, 0);
      assert.equal(db.prepare('SELECT COUNT(*) AS count FROM rehearsal_trials').get().count, 0);
      assert.equal(service.entitlement('workspace').available, true);
    } finally { db.close(); }
  }
});

test('provider rejection and malformed response become actionable simulation failures without exposing response bodies', async () => {
  for (const [status, content, code, message] of [
    [401, '<html>private-provider-response</html>', 'model_auth_failed', /OpenRouter.*key/i],
    [402, 'private-provider-response', 'model_credit_required', /credit/i],
    [429, 'private-provider-response', 'model_rate_limited', /try again/i],
    [503, 'private-provider-response', 'model_planning_failed', /temporarily unavailable/i],
    [200, 'not-json-private-provider-response', 'invalid_model_response', /unreadable/i],
    [200, 'null', 'invalid_model_response', /unreadable/i]
  ]) {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
      const session = { github: { installationId: 1, account: 'org' }, openrouter: { secret: 'encrypted' } };
      db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
      let calls = 0;
      const service = createUpgradeRehearsals(db, {
        mapper: { snapshots: () => [snapshot], upgradePlan: async () => plan }, decrypt: () => 'private-test-key',
        github: { repositories: async () => [{ fullName: 'org/repo' }] },
        propose: (value, plans, key) => proposeRehearsal(value, plans, key, async () => { calls++; return new Response(content, { status }); }),
        sandbox: { start: async () => { throw new Error('Rejected model response must not start a sandbox.'); } }
      });
      service.start('workspace', 'org/repo', 1, session);
      await service.dispatch(); await service.dispatch();
      const failed = service.latest('workspace', 'org/repo', 1);
      assert.equal(failed.status, 'failed'); assert.equal(failed.errorCode, code); assert.match(failed.error, message);
      assert.equal(calls, 1); assert.ok(!JSON.stringify(failed).includes('private-provider-response')); assert.ok(!JSON.stringify(failed).includes('private-test-key'));
    } finally { db.close(); }
  }
});

test('cheap-model proposals accept only checked versions and reject conflicting selections', async () => {
  let request;
  const prediction = await proposeRehearsal(snapshot, [plan], 'private-test-key', async (url, options) => {
    request = JSON.parse(options.body);
    return Response.json({ choices: [{ message: { content: JSON.stringify({ scenarios: [{ rationale: scenario.rationale, optionIds: [1] }] }) } }], usage: { prompt_tokens: 100, completion_tokens: 100, cost: 0.0001 } });
  });
  assert.equal(request.model, 'qwen/qwen3.7-flash');
  assert.equal(request.max_tokens, 3000);
  assert.deepEqual(request.reasoning, { enabled: false });
  assert.equal(prediction.usage.costUsd, 0.0001);
  assert.deepEqual(prediction.scenarios, [scenario]);
  const context = JSON.parse(request.messages[1].content);
  assert.deepEqual(context.allowedOptions, [{ id: 1, ...change }]);
  assert.ok(!JSON.stringify(request).includes('private-test-key'));
  assert.throws(() => validateRehearsalScenarios({ scenarios: [{ ...scenario, changes: [{ ...change, targetVersion: '99.0.0' }] }] }, [change]), /unchecked/);
  assert.throws(() => validateRehearsalScenarios({ scenarios: [{ ...scenario, changes: [change, change] }] }, [change]), /conflicting/);
});

test('numbered options share one checked target per package without inventing targets for other installed versions', () => {
  const allowed = [change, { ...change, targetVersion: '8.0.0' },
    { ...change, currentVersion: '7.5.0' }, { name: 'parent', currentVersion: '1.0.0', targetVersion: '2.0.0' }];
  const options = rehearsalOptions(allowed);
  assert.equal(options.length, 3);
  assert.deepEqual(options.map(item => item.id), [1, 2, 3]);
  assert.ok(options.every(({ id, ...item }) => allowed.some(value => JSON.stringify(value) === JSON.stringify(item))));
  assert.ok(options.filter(item => item.name === 'semver').every(item => item.targetVersion === '7.5.2'));
  const incompatible = rehearsalOptions([change, { ...change, currentVersion: '7.6.0', targetVersion: '8.0.0' }]);
  assert.deepEqual(incompatible, [], 'Do not silently drop one installed branch to choose a target.');
});

test('empty, truncated and invalid model plans retain billing evidence without retrying or starting a sandbox', async () => {
  for (const [content, finishReason, message] of [
    ['', 'stop', /empty upgrade plan/],
    ['{"scenarios":', 'length', /response limit/],
    ['{}', 'stop', /one or two/],
    [JSON.stringify({ scenarios: [{ rationale: scenario.rationale, optionIds: [999] }] }), 'stop', /unknown upgrade option/]
  ]) {
    const db = new DatabaseSync(':memory:');
    db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
    const session = { github: { installationId: 1, account: 'org' }, openrouter: { secret: 'encrypted' } };
    db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
    let modelCalls = 0, sandboxCalls = 0;
    const service = createUpgradeRehearsals(db, {
      mapper: { snapshots: () => [snapshot], upgradePlan: async () => plan },
      github: { repositories: async () => [{ fullName: 'org/repo' }] }, decrypt: () => 'private-test-key',
      propose: (value, plans, key) => proposeRehearsal(value, plans, key, async () => {
        modelCalls++;
        const progress = service.latest('workspace', 'org/repo', 1).progress;
        assert.equal(progress.phase, 'Preparing a coordinated upgrade plan');
        return Response.json({ choices: [{ message: { content }, finish_reason: finishReason }], usage: { cost: 0.0002, completion_tokens: 3000 } });
      }),
      sandbox: { start: async () => { sandboxCalls++; } }
    });
    service.start('workspace', 'org/repo', 1, session);
    await service.dispatch(); await service.dispatch();
    const failed = service.latest('workspace', 'org/repo', 1);
    assert.equal(failed.status, 'failed'); assert.match(failed.error, message);
    assert.equal(failed.errorCode, 'invalid_upgrade_plan');
    assert.equal(failed.prediction.usage.costUsd, 0.0002);
    assert.equal(failed.prediction.finishReason, finishReason);
    assert.equal(modelCalls, 1); assert.equal(sandboxCalls, 0);
    assert.ok(!JSON.stringify(failed).includes('private-test-key'));
    db.close();
  }
});

test('jobs persist, deduplicate costs, scope evidence by workspace and invalidate changed scans', async t => {
  // A fast retry must be newest even when both jobs share a millisecond.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE workspaces(id TEXT PRIMARY KEY, data TEXT)');
  const session = { github: { installationId: 1, account: 'org' }, openrouter: { secret: 'encrypted' } };
  db.prepare('INSERT INTO workspaces VALUES (?, ?)').run('workspace', JSON.stringify(session));
  let current = structuredClone(snapshot), calls = 0, failSandbox = false;
  const service = createUpgradeRehearsals(db, { mapper: { snapshots: id => id === 'workspace' ? [current] : [], upgradePlan: async () => plan },
    github: { repositories: async () => [{ fullName: 'org/repo' }], installationToken: async () => 'github-test' }, decrypt: () => 'openrouter-test',
    propose: async () => { calls++; return { scenarios: [scenario], usage: { costUsd: 0.001 } }; },
    sandbox: { start: async input => { assert.equal(input.githubToken, 'github-test'); assert.ok(!JSON.stringify(input).includes('openrouter-test')); if (failSandbox) throw new Error('Checkout unavailable'); return { status: 'running' }; },
      get: async () => ({ status: 'completed', revision: snapshot.revision, scenarios: [{ status: 'tests_passed', resolvedPackages: [{ name: 'semver', version: '7.5.2' }] }] }) },
    check: async () => ({ status: 'complete', findings: [{ id: 'new', package: 'semver', version: '7.5.2' }] }) });
  const first = service.start('workspace', 'org/repo', 1, session);
  assert.equal(service.start('workspace', 'org/repo', 1, session).id, first.id);
  assert.equal(service.latest('other', 'org/repo', 1), null);
  await service.dispatch(); await service.dispatch();
  const completed = service.latest('workspace', 'org/repo', 1);
  assert.equal(completed.status, 'completed');
  assert.equal(completed.result.scenarios[0].status, 'tests_passed_with_advisory_blockers');
  assert.equal(completed.result.scenarios[0].newAdvisories[0].id, 'new');
  assert.equal(completed.result.scenarios[0].resolvedPackages, undefined);
  assert.equal(service.start('workspace', 'org/repo', 1, session).id, first.id);
  assert.equal(calls, 1);
  current = { ...current, revision: 'b'.repeat(40) };
  assert.equal(service.latest('workspace', 'org/repo', 1).stale, true);
  const prompt = buildOneShotPrompt({ repository: 'org/repo', snapshot: { ...current, rehearsal: service.latest('workspace', 'org/repo', 1) }, findings: [] });
  assert.match(prompt, /"usable": false/);
  assert.match(prompt, /tests_passed_with_advisory_blockers/);
  failSandbox = true;
  service.start('workspace', 'org/repo', 1, session); await service.dispatch();
  const failed = service.latest('workspace', 'org/repo', 1);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.prediction.usage.costUsd, 0.001);
  db.close();
});

test('real npm rehearsal records baseline and candidate tests without credentials or lifecycle scripts', { timeout: 180000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-rehearsal-test-'));
  const source = path.join(root, 'source');
  try {
    await mkdir(source);
    await writeFile(path.join(source, '.gitignore'), 'node_modules/\n');
    await writeFile(path.join(source, 'package.json'), JSON.stringify({ name: 'rehearsal-fixture', version: '1.0.0',
      dependencies: { semver: '7.5.1' }, scripts: { test: 'node test.cjs', postinstall: 'node -e "process.exit(99)"' } }));
    await writeFile(path.join(source, 'test.cjs'), `const assert=require('node:assert/strict');const semver=require('semver');assert.equal(semver.satisfies('1.2.3','^1.0.0'),true);assert.equal(process.env.OPENROUTER_API_KEY,undefined);assert.equal(process.env.GITHUB_TOKEN,undefined);`);
    const exec = args => execFileSync(args[0], args.slice(1), { cwd: source, stdio: 'pipe' });
    exec(['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
    await mkdir(path.join(source, 'safe'));
    await writeFile(path.join(source, 'safe/package.json'), JSON.stringify({ name: 'already-safe', version: '1.0.0', dependencies: { semver: '7.5.4' } }));
    execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: path.join(source, 'safe'), stdio: 'pipe' });
    exec(['git', 'init']); exec(['git', 'add', '.']);
    exec(['git', '-c', 'user.name=Purple test', '-c', 'user.email=test@example.com', 'commit', '-m', 'fixture']);
    process.env.OPENROUTER_API_KEY = 'must-not-leak';
    const result = await runUpgradeRehearsal({ root, revision: snapshot.revision, scenarios: [scenario] });
    delete process.env.OPENROUTER_API_KEY;
    assert.equal(result.scenarios[0].status, 'tests_passed');
    assert.equal(result.baseline.checks[0].passed, true);
    assert.equal(result.scenarios[0].checks[0].passed, true);
    assert.equal(result.scenarios[0].coverage[0].oldVersionRemaining, false);
    assert.ok(result.scenarios[0].dependencyChanges.some(item => item.before?.version === '7.5.1' && item.after?.version === '7.5.2'));
    assert.equal(JSON.parse(await readFile(path.join(root, 'candidate-0/safe/package.json'), 'utf8')).dependencies.semver, '7.5.4', 'Do not downgrade an unrelated safe version of the same package.');
    assert.match(rehearsalProgram(), /for await/);
    // A real peer conflict must remain visible rather than using --force or
    // legacy peer resolution to manufacture a passing upgrade.
    await mkdir(path.join(source, 'peer'));
    await writeFile(path.join(source, 'peer/package.json'), JSON.stringify({ name: 'rehearsal-peer', version: '1.0.0', peerDependencies: { semver: '7.5.1' } }));
    const manifest = JSON.parse(await readFile(path.join(source, 'package.json'), 'utf8'));
    manifest.dependencies['rehearsal-peer'] = 'file:./peer';
    await writeFile(path.join(source, 'package.json'), JSON.stringify(manifest));
    exec(['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']);
    exec(['git', 'add', '.']); exec(['git', '-c', 'user.name=Purple test', '-c', 'user.email=test@example.com', 'commit', '-m', 'peer conflict']);
    // Remove the previous candidate so this second run also starts clean.
    await rm(path.join(root, 'candidate-0'), { recursive: true, force: true });
    const conflict = await runUpgradeRehearsal({ root, revision: snapshot.revision, scenarios: [scenario] });
    assert.equal(conflict.scenarios[0].status, 'resolution_failed');
    assert.ok(conflict.scenarios[0].resolution.some(item => /ERESOLVE/.test(item.output)));
  } finally { delete process.env.OPENROUTER_API_KEY; await rm(root, { recursive: true, force: true }); }
});


test('rehearsal allowlists exclude downgrades, incomplete graphs and unresolved parent constraints', () => {
  const unsafe = [
    { ...plan, targetVersion: '7.4.0' },
    { ...plan, impact: { ...plan.impact, truncated: true } },
    { ...plan, impact: { ...plan.impact, parents: [{ name: 'parent', version: '1.0.0', compatible: false }] } },
    { ...plan, impact: { ...plan.impact, parents: [{ name: 'parent', version: '1.0.0', compatible: null }] } },
    { ...plan, peerConstraints: { status: 'blocked' } }
  ];
  for (const value of unsafe) assert.deepEqual(allowedRehearsalChanges([value]), [], JSON.stringify(value));
  const coordinated = { ...unsafe[2], parentOptions: [{ parent: 'parent', currentVersion: '1.0.0', version: '1.1.0', upstream: [], peerConstraints: { status: 'compatible' } }] };
  assert.deepEqual(allowedRehearsalChanges([coordinated]), [change, { name: 'parent', currentVersion: '1.0.0', targetVersion: '1.1.0' }]);
  const downgrade = { ...change, targetVersion: '7.4.0' };
  assert.throws(() => validateRehearsalScenarios({ scenarios: [{ ...scenario, changes: [downgrade] }] }, [downgrade]), /newer|downgrade/i);
});

test('different installed branches require an explicit coordinated-planning blocker', () => {
  assert.deepEqual(rehearsalOptions([
    { name: 'example', currentVersion: '2.0.0', targetVersion: '2.0.1' },
    { name: 'example', currentVersion: '4.0.0', targetVersion: '4.0.1' }
  ]), []);
  assert.deepEqual(rehearsalOptions([
    { name: 'example', currentVersion: '2.0.0', targetVersion: '2.0.1' },
    { name: 'example', currentVersion: '4.0.0', targetVersion: '4.0.1' }, change
  ]), [{ id: 1, ...change }], 'Independent compatible upgrades remain available.');
});

test('selected child upgrades require their checked parent upgrades in the same scenario', () => {
  const parentChange = { name: 'parent', currentVersion: '1.0.0', targetVersion: '1.1.0' };
  const coordinated = { ...plan, impact: { ...plan.impact, parents: [{ name: 'parent', version: '1.0.0', compatible: false }] },
    parentOptions: [{ parent: 'parent', currentVersion: '1.0.0', version: '1.1.0', upstream: [], peerConstraints: { status: 'compatible' } }] };
  const allowed = allowedRehearsalChanges([coordinated]);
  assert.throws(() => validateRehearsalScenarios({ scenarios: [scenario] }, allowed, [coordinated]), /parent|coordinat/i);
  assert.equal(validateRehearsalScenarios({ scenarios: [{ ...scenario, changes: [change, parentChange] }] }, allowed, [coordinated]).length, 1);
});

// Root installs have no registry dependencies. The proposed package is a local
// fixture; these cases must reject policy collisions before any installation.
async function overridePreflight(overrides, proposed = { name: 'fixture-child', currentVersion: '1.0.0', targetVersion: '1.0.1' }) {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-override-preflight-'));
  const source = path.join(root, 'source');
  try {
    await mkdir(source);
    const manifest = { name: 'override-fixture', version: '1.0.0', overrides };
    await writeFile(path.join(source, 'package.json'), JSON.stringify(manifest));
    await writeFile(path.join(source, 'package-lock.json'), JSON.stringify({ name: manifest.name, version: manifest.version, lockfileVersion: 3,
      packages: { '': { name: manifest.name, version: manifest.version } } }));
    for (const args of [['init'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'fixture']]) {
      execFileSync('git', args, { cwd: source, stdio: 'pipe' });
    }
    await assert.rejects(runUpgradeRehearsal({ root, revision: 'fixture', scenarios: [{ rationale: 'Review existing policy.', changes: [proposed] }] }), /Existing override|newer stable/i);
    assert.equal(await readFile(path.join(source, 'package.json'), 'utf8'), JSON.stringify(manifest));
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('runner preserves nested, range and scoped-package override policies', { timeout: 60000 }, async () => {
  await overridePreflight({ 'fixture-child@^1': '1.0.0' });
  await overridePreflight({ parent: { 'fixture-child': '1.0.0' } });
  await overridePreflight({ parent: { '@fixture/child@^1': '1.0.0' } }, { name: '@fixture/child', currentVersion: '1.0.0', targetVersion: '1.0.1' });
});

test('runner independently refuses downgrade proposals', { timeout: 60000 }, async () => {
  await overridePreflight({}, { name: 'fixture-child', currentVersion: '2.10.0', targetVersion: '2.8.0' });
});

async function checkResolverDowngrade(moved) {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-resolved-downgrade-'));
  const source = path.join(root, 'source'), bin = path.join(root, 'bin');
  const originalPath = process.env.PATH;
  try {
    await mkdir(source); await mkdir(bin);
    const manifest = { name: 'resolver-fixture', version: '1.0.0', dependencies: { 'fixture-child': '1.0.0' }, scripts: { test: 'fixture-check' } };
    await writeFile(path.join(source, 'package.json'), JSON.stringify(manifest));
    await writeFile(path.join(source, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': manifest, 'node_modules/fixture-child': { version: '1.0.0' }, 'node_modules/unaffected': { version: '2.12.0' }
    } }));
    // Supply a deterministic package-manager boundary response, not registry
    // compatibility evidence. Production code must inspect its actual lockfile.
    await writeFile(path.join(bin, 'npm'), `#!${process.execPath}
const fs = require('node:fs');
if (process.argv.includes('--package-lock-only')) {
  const lock = JSON.parse(fs.readFileSync('package-lock.json', 'utf8'));
  lock.packages['node_modules/fixture-child'].version = '1.0.1';
  const location = ${JSON.stringify(moved ? 'node_modules/parent/node_modules/unaffected' : 'node_modules/unaffected')};
  delete lock.packages['node_modules/unaffected'];
  lock.packages[location] = { version: '2.8.0' };
  fs.writeFileSync('package-lock.json', JSON.stringify(lock));
}
`);
    await chmod(path.join(bin, 'npm'), 0o755);
    for (const args of [['init'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'fixture']]) {
      execFileSync('git', args, { cwd: source, stdio: 'pipe' });
    }
    process.env.PATH = `${bin}${path.delimiter}${originalPath}`;
    const result = await runUpgradeRehearsal({ root, revision: 'fixture', scenarios: [{ rationale: 'Upgrade the vulnerable copy.',
      changes: [{ name: 'fixture-child', currentVersion: '1.0.0', targetVersion: '1.0.1' }] }] });
    const candidate = result.scenarios[0];
    assert.equal(candidate.checks.every(check => check.passed), true);
    assert.equal(candidate.status, 'dependency_changes_blocked');
    assert.equal(candidate.dependencyBlockers.length, 1);
    assert.equal(candidate.dependencyBlockers[0].location, 'package-lock.json:node_modules/unaffected');
    assert.equal(candidate.dependencyBlockers[0].before.version, '2.12.0');
    assert.equal(candidate.dependencyBlockers[0].after.version, '2.8.0');
    if (moved) assert.equal(candidate.dependencyBlockers[0].afterLocation, 'package-lock.json:node_modules/parent/node_modules/unaffected');
  } finally {
    process.env.PATH = originalPath;
    await rm(root, { recursive: true, force: true });
  }
}

test('resolver downgrades of unaffected installed copies cannot receive a passing status', async () => {
  await checkResolverDowngrade(false);
});

test('a removed copy and newly introduced lower version at another location require review', async () => {
  await checkResolverDowngrade(true);
});

async function checkAmbiguousResolution({ manager = 'npm', fromVersion = '2.12.0', deduplicate = false, changeUnaffected = true } = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-resolution-policy-'));
  const source = path.join(root, 'source'), bin = path.join(root, 'bin');
  const originalPath = process.env.PATH;
  try {
    await mkdir(source); await mkdir(bin);
    const manifest = { name: 'resolution-policy-fixture', version: '1.0.0', dependencies: { 'fixture-child': '1.0.0', parent: '1.0.0' }, scripts: { test: 'fixture-check' } };
    if (deduplicate) manifest.dependencies.unaffected = '2.8.0';
    await writeFile(path.join(source, 'package.json'), JSON.stringify(manifest));
    const pnpm = manager === 'pnpm';
    const lockfile = pnpm ? 'pnpm-lock.yaml' : 'package-lock.json';
    const importer = Object.fromEntries(Object.entries(manifest.dependencies).map(([name, version]) => [name, { specifier: version, version }]));
    const packages = { 'fixture-child@1.0.0': {}, 'parent@1.0.0': {}, [`unaffected@${fromVersion}`]: {} };
    if (deduplicate) packages['unaffected@2.8.0'] = {};
    const snapshots = { ...packages, 'parent@1.0.0': { dependencies: { unaffected: fromVersion } } };
    const lock = pnpm ? { lockfileVersion: '9.0', importers: { '.': { dependencies: importer } }, packages, snapshots } : {
      lockfileVersion: 3, packages: { '': manifest, 'node_modules/fixture-child': { version: '1.0.0' },
        'node_modules/parent': { version: '1.0.0', dependencies: { unaffected: '>=2.8.0' } },
        'node_modules/parent/node_modules/unaffected': { version: fromVersion },
        ...(deduplicate ? { 'node_modules/unaffected': { version: '2.8.0' } } : {}) }
    };
    await writeFile(path.join(source, lockfile), JSON.stringify(lock));
    await writeFile(path.join(bin, manager), `#!${process.execPath}
const fs = require('node:fs');
if (process.argv.includes('--package-lock-only') || process.argv.includes('--lockfile-only')) {
  const filename = ${JSON.stringify(lockfile)};
  const lock = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (${pnpm}) {
    lock.importers['.'].dependencies['fixture-child'] = { specifier: '1.0.1', version: '1.0.1' };
    for (const field of ['packages', 'snapshots']) {
      delete lock[field]['fixture-child@1.0.0']; lock[field]['fixture-child@1.0.1'] = {};
      if (${changeUnaffected}) { delete lock[field][${JSON.stringify(`unaffected@${fromVersion}`)}]; lock[field]['unaffected@2.8.0'] = {}; }
    }
    if (${changeUnaffected}) lock.snapshots['parent@1.0.0'].dependencies.unaffected = '2.8.0';
  } else {
    lock.packages['node_modules/fixture-child'].version = '1.0.1';
    if (${changeUnaffected}) {
      if (${deduplicate}) delete lock.packages['node_modules/parent/node_modules/unaffected'];
      else lock.packages['node_modules/parent/node_modules/unaffected'].version = '2.8.0';
    }
  }
  fs.writeFileSync(filename, JSON.stringify(lock));
}
`);
    await chmod(path.join(bin, manager), 0o755);
    for (const args of [['init'], ['add', '.'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.com', 'commit', '-m', 'fixture']]) {
      execFileSync('git', args, { cwd: source, stdio: 'pipe' });
    }
    process.env.PATH = `${bin}${path.delimiter}${originalPath}`;
    const result = await runUpgradeRehearsal({ root, revision: 'fixture',
      pnpmParserPath: new URL('../public/skills/purple/scripts/pnpm.mjs', import.meta.url).href,
      scenarios: [{ rationale: 'Check the complete resolver inventory.', changes: [{ name: 'fixture-child', currentVersion: '1.0.0', targetVersion: '1.0.1' }] }] });
    const candidate = result.scenarios[0];
    assert.equal(candidate.checks.every(check => check.passed), true);
    assert.equal(candidate.status, changeUnaffected ? 'dependency_changes_blocked' : 'tests_passed');
    if (changeUnaffected) {
      assert.ok(candidate.dependencyBlockers.some(item => item.before.name === 'unaffected' && item.before.version === fromVersion && item.after.version === '2.8.0'));
    } else assert.deepEqual(candidate.dependencyBlockers, []);
  } finally { process.env.PATH = originalPath; await rm(root, { recursive: true, force: true }); }
}

for (const manager of ['npm', 'pnpm']) {
  test(`${manager} deduplication onto an existing lower copy requires review`, async () => {
    await checkAmbiguousResolution({ manager, deduplicate: true });
  });
  test(`${manager} cannot pass an unorderable changed prerelease copy`, async () => {
    await checkAmbiguousResolution({ manager, fromVersion: '3.0.0-beta.1' });
  });
}

test('pnpm scoped resolution can pass while retaining an unrelated copy', async () => {
  await checkAmbiguousResolution({ manager: 'pnpm', changeUnaffected: false });
});
