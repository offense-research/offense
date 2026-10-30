import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { verifiedEvidence } from './helpers/verification-evidence.js';
const exec = promisify(execFile);
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createEventStore } from '../server/event-store.js';
import { createAccounts } from '../server/accounts.js';
import { createAgentRunner, validateAgentPlan } from '../server/agent-runner.js';

test('agent plans require a runnable regression and normal behavior check', () => {
  assert.throws(() => validateAgentPlan({ confirmed: true, summary: 'issue', testPaths: ['../escape.test.js'], reproduction: ['node'], normal: ['node'] }), /Invalid regression/);
  assert.throws(() => validateAgentPlan({ confirmed: true, summary: 'issue', testPaths: ['test/auth.test.js'], securityTests: verifiedEvidence().contract.securityTests.map(item => ({ ...item, file: 'test/auth.test.js' })), reproduction: 'npm test', normal: ['npm', 'test'] }), /Invalid reproduction/);
  assert.deepEqual(validateAgentPlan({ confirmed: false, summary: 'No code path found.' }), { confirmed: false, summary: 'No code path found.' });
});

test('one workspace-scoped Pi run receives the mapped checkout and sanitized evidence', async () => {
  const db = new DatabaseSync(':memory:');
  const dir = await mkdtemp(path.join(tmpdir(), 'purple-agent-test-'));
  try {
    const store = createEventStore(db);
    createAccounts(db);
    db.prepare('INSERT INTO workspaces (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)')
      .run('customer-a', JSON.stringify({ github: { installationId: 41, account: 'owner' }, githubInstallations: [{ installationId: 42, account: 'another-org' }], openrouter: { secret: 'encrypted' } }), Date.now(), Date.now());
    store.receiveBatch('customer-a', [{ sourceWorker: 'api', queueMessageId: 'event-1', outcome: 'exception', exceptionNames: ['TypeError'], logs: [{ level: 'error', message: 'A redacted error' }] }]);
    const investigationId = store.investigations('customer-a')[0].id;
    let dockerRuns = 0;
    let verifierRuns = 0;
    const runner = createAgentRunner(db, {
      dataDir: dir, decrypt: () => 'test-openrouter-key',
      github: { repositories: async () => [{ fullName: 'owner/service' }], installationToken: async () => 'test-installation-token' },
      execute: async (command, args, options) => {
        if (command === 'git' && args[0] === 'clone') {
          if (args.includes('--depth')) {
            assert.match(options.env.GIT_CONFIG_VALUE_0, /AUTHORIZATION: basic /);
            assert.equal(Buffer.from(options.env.GIT_CONFIG_VALUE_0.split(' ').at(-1), 'base64').toString(), 'x-access-token:test-installation-token');
          }
          if (args.includes('--depth')) {
            const target = args.at(-1); await mkdir(target); await mkdir(path.join(target, 'src')); await mkdir(path.join(target, 'test'));
            await writeFile(path.join(target, 'package.json'), JSON.stringify({ type: 'module', scripts: { test: 'node --test test/smoke.test.js' } }));
            await writeFile(path.join(target, 'src/auth.js'), 'export const read=(a,b)=>200;');
            await writeFile(path.join(target, 'test/smoke.test.js'), "import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/auth.js';test('owner access',()=>assert.equal(read('a','a'),200));");
            await exec('git', ['init', '-q'], { cwd: target }); await exec('git', ['add', '.'], { cwd: target });
            await exec('git', ['-c','user.name=Test','-c','user.email=test@purple.invalid','-c','core.hooksPath=/dev/null','commit','-qm','fixture'], { cwd: target }); return '';
          }
          return (await exec('git', args, { cwd: options?.cwd })).stdout.trim();
        }
        if (command === 'git') return (await exec('git', args, { cwd: options?.cwd })).stdout.trim();
        if (args[0] === 'rm') return '';
        if (args.includes('--entrypoint=/usr/bin/env')) {
          verifierRuns++;
          assert.equal(options.env.OPENROUTER_API_KEY, undefined);
          assert.ok(args.includes('--network=none'));
          assert.ok(!args.some(arg => arg.includes('dst=/work/context')));
          const verifyRepo = args.find(arg => arg.includes('dst=/work/repo')).match(/src=([^,]+)/)[1];
          const baseline = verifyRepo.endsWith('/baseline');
          const files = JSON.parse(args.at(-1));
          if (baseline && files.includes('test/smoke.test.js')) await assert.rejects(readFile(path.join(verifyRepo, 'test/auth.test.js')), /ENOENT/);
          return (await exec(process.execPath, [fileURLToPath(new URL('../agent/test-observer.mjs', import.meta.url)), JSON.stringify(files)], { cwd: verifyRepo, env: { PATH: process.env.PATH }, maxBuffer: 128000 })).stdout;
        }
        dockerRuns++;
        assert.equal(options.env.OPENROUTER_API_KEY, 'test-openrouter-key');
        assert.equal(options.env.GIT_CONFIG_VALUE_0, undefined);
        assert.ok(args.includes('--read-only'));
        assert.ok(args.includes('read,grep,find,ls,edit,write'));
        assert.ok(args.includes('deepseek/deepseek-v4.1-flash'));
        assert.ok(args.includes('PI_CODING_AGENT_DIR=/tmp/pi-agent'));
        const mount = args.find(arg => arg.includes('dst=/work/context'));
        const context = mount.match(/src=([^,]+)/)[1];
        const output = args.find(arg => arg.includes('dst=/work/output')).match(/src=([^,]+)/)[1];
        const repo = args.find(arg => arg.includes('dst=/work/repo')).match(/src=([^,]+)/)[1];
        const incident = JSON.parse(await readFile(path.join(context, 'incident.json')));
        const events = JSON.parse(await readFile(path.join(context, 'events.json')));
        assert.equal(incident.repository, 'owner/service');
        assert.ok(incident.investigationId > 0);
        assert.equal(events[0].sourceWorker, 'api');
        await mkdir(path.join(repo, 'test'), {recursive:true});
        await mkdir(path.join(repo, 'src'), {recursive:true});
        await writeFile(path.join(repo, 'test/auth.test.js'), "import{test}from'node:test';import assert from'node:assert/strict';import{read}from'../src/auth.js';test('cross-tenant read is forbidden',()=>assert.equal(read('a','b'),403));");
        await writeFile(path.join(repo, 'src/auth.js'), dockerRuns === 2 ? 'export const read=(a,b)=>200; // ineffective patch' : 'export const read=(a,b)=>a===b?200:403;');
        await writeFile(path.join(output, 'plan.json'), JSON.stringify({ confirmed: true, summary: 'Fixed auth flaw.', testPaths: ['test/auth.test.js'], securityTests: verifiedEvidence().contract.securityTests.map(item => ({ ...item, file: 'test/auth.test.js' })), reproduction: ['node', '--test', 'test/auth.test.js'], normal: ['node', '--test', 'test/smoke.test.js'] }));
        return 'Proposed a fix.';
      }
    });
    await assert.rejects(runner.setMapping('customer-a', 'api', 'other/repo', 42), /not available/);
    await runner.setMapping('customer-a', 'api', 'owner/service', 42);
    assert.equal(runner.mappings('customer-a')[0].installationId, 42);
    runner.enqueueMapped(); runner.enqueueMapped();
    assert.equal(runner.run('customer-b', investigationId), null);
    assert.equal(runner.run('customer-a', investigationId).status, 'queued');
    assert.equal(await runner.processOne(), true);
    assert.equal(runner.run('customer-a', investigationId).status, 'verified');
    assert.equal(runner.run('customer-a', investigationId).result, 'Fixed auth flaw.');
    assert.equal(runner.run('customer-a', investigationId).verification.verified, true);
    assert.match(runner.patch('customer-a', investigationId), /diff --git/);
    assert.equal(runner.patch('customer-b', investigationId), null);
    runner.enqueueMapped();
    assert.equal(await runner.processOne(), false);
    assert.equal(dockerRuns, 1);
    assert.equal(verifierRuns, 4);
    store.receiveBatch('customer-a', [{ sourceWorker: 'api', queueMessageId: 'event-2', outcome: 'exceededCpu' }]);
    const nextId = store.investigations('customer-a').find(item => item.ruleId === 'resource_limit').id;
    runner.enqueueMapped();
    assert.equal(runner.run('customer-a', nextId).status, 'queued');
    assert.equal(await runner.processOne(), true);
    assert.equal(runner.run('customer-a', nextId).status, 'verification_failed', runner.run('customer-a', nextId).error);
    assert.equal(runner.run('customer-a', nextId).verification.patchedReproduction.passed, false);
    assert.equal(runner.retry('customer-a', nextId), true);
    assert.equal(runner.run('customer-a', nextId).status, 'queued');
    await runner.setMapping('customer-a', 'api', '', 42);
    assert.equal(runner.run('customer-a', nextId), null);
  } finally { db.close(); await rm(dir, { recursive: true, force: true }); }
});
