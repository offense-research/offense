import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { npmProjects } from '../agent/npm-projects.mjs';
import { verificationCheck } from '../src/verification.js';

test('verification installs independent nested npm projects and ignores symlinks and vendored dependencies', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'purple-npm-projects-'));
  try {
    for (const dir of ['.', 'api', 'links', 'node_modules/ignored']) {
      await mkdir(path.join(root, dir), { recursive: true });
      await writeFile(path.join(root, dir, 'package-lock.json'), '{}');
    }
    await symlink(path.join(root, 'api'), path.join(root, 'outside-link'));
    assert.deepEqual(await npmProjects(root), ['.', 'api', 'links']);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('both runner result formats display correctly and an interrupted regression is never treated as expected failure', () => {
  assert.deepEqual(verificationCheck({ code: 0, stdout: 'all good', stderr: '' }), { label: 'passed', output: 'all good' });
  assert.equal(verificationCheck({ passed: true, output: 'legacy success' }).label, 'passed');
  assert.equal(verificationCheck({ code: 1, stdout: 'assertion failed' }, true).label, 'failed');
  assert.equal(verificationCheck({ passed: false, classification: 'security_assertion_failure' }, true).label, 'security assertion reproduced');
  assert.equal(verificationCheck({ passed: false, classification: 'infrastructure_error' }, true).label, 'setup / runtime error');
  assert.equal(verificationCheck({ protocolVersion: 2, complete: true, passed: true, summary: { passed: 1, skipped: 1 } }).label, 'incomplete / skipped tests');
  assert.equal(verificationCheck({ protocolVersion: 2, complete: true, passed: true, infrastructureErrors: [{ kind: 'hookFailed' }] }).label, 'setup / runtime error');
  assert.equal(verificationCheck({ code: null, stdout: '' }, true).label, 'interrupted');
});
