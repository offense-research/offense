import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { repositoryCommandIdentity, prepareIsolationDirectories, prepareRepositoryTree, runRepositoryCommand } from '../agent/repository-isolation.mjs';

function withoutIsolation(fn) {
  return async () => {
    const previous = process.env.PURPLE_FIX_ISOLATE_COMMANDS;
    delete process.env.PURPLE_FIX_ISOLATE_COMMANDS;
    try { await fn(); }
    finally { if (previous === undefined) delete process.env.PURPLE_FIX_ISOLATE_COMMANDS; else process.env.PURPLE_FIX_ISOLATE_COMMANDS = previous; }
  };
}

test('repository isolation leaves existing non-Docker callers and directory ownership unchanged', withoutIsolation(async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-isolation-test-'));
  try {
    assert.equal(repositoryCommandIdentity(), undefined);
    const result = await prepareIsolationDirectories({ workDirectory: path.join(root, 'work'), outputDirectory: root });
    assert.equal(result.home, path.join(root, 'work', 'command-home'));
    await assert.rejects(stat(path.join(root, 'work')), { code: 'ENOENT' });
    await prepareRepositoryTree(path.join(root, 'not-present'));
    const command = await runRepositoryCommand([process.execPath, '-e', 'process.stdout.write(JSON.stringify({uid:process.getuid(),key:process.env.OPENROUTER_API_KEY??null}))'],
      { cwd: root, env: { PATH: process.env.PATH }, timeoutMs: 10000 });
    assert.equal(command.code, 0); assert.equal(command.timedOut, false);
    assert.deepEqual(JSON.parse(command.stdout), { uid: process.getuid(), key: null });
  } finally { await rm(root, { recursive: true, force: true }); }
}));

test('unprivileged callers cannot claim UID isolation', { skip: process.getuid?.() === 0 }, async () => {
  const previous = process.env.PURPLE_FIX_ISOLATE_COMMANDS;
  process.env.PURPLE_FIX_ISOLATE_COMMANDS = '1';
  try {
    assert.throws(repositoryCommandIdentity, /trusted root controller/);
    await assert.rejects(prepareRepositoryTree('/tmp/never-mutate'), /trusted root controller/);
  } finally { if (previous === undefined) delete process.env.PURPLE_FIX_ISOLATE_COMMANDS; else process.env.PURPLE_FIX_ISOLATE_COMMANDS = previous; }
});

test('repository command time and output budgets terminate the process without waiting for close indefinitely', withoutIsolation(async () => {
  const started = Date.now();
  const timeout = await runRepositoryCommand([process.execPath, '-e', 'setInterval(()=>{},10000)'], { cwd: os.tmpdir(), env: { PATH: process.env.PATH }, timeoutMs: 120 });
  assert.equal(timeout.timedOut, true); assert.ok(Date.now() - started < 3000);
  const excess = await runRepositoryCommand([process.execPath, '-e', 'process.stdout.write("x".repeat(100000));setInterval(()=>{},10000)'],
    { cwd: os.tmpdir(), env: { PATH: process.env.PATH }, timeoutMs: 5000, maxOutputBytes: 1024 });
  assert.equal(excess.truncated, true); assert.ok(excess.stdout.length <= 1024);
}));
