import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { HISTORY_LIMITS, normalizeGitHistoryFindings, scanGitHistoryArtifact } from '../agent/gitleaks-history.mjs';
import { prepareGitHistoryBundle } from '../public/skills/purple/scripts/git-history-bundle.mjs';

const secret = 'synthetic-secret-never-return';

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-git-history-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repository = path.join(root, 'source');
  git(root, 'init', '-q', repository);
  git(repository, 'config', 'user.email', 'fixture@example.test');
  git(repository, 'config', 'user.name', 'Fixture');
  await writeFile(path.join(repository, 'key.txt'), `token=${secret}\n`);
  git(repository, 'add', 'key.txt'); git(repository, 'commit', '-qm', 'Add fixture secret');
  const firstCommit = git(repository, 'rev-parse', 'HEAD');
  await writeFile(path.join(repository, 'key.txt'), 'token=removed\n');
  git(repository, 'add', 'key.txt'); git(repository, 'commit', '-qm', 'Remove fixture secret');
  const artifactPath = path.join(root, 'history.bundle');
  git(repository, 'bundle', 'create', artifactPath, '--all');
  const bytes = await readFile(artifactPath);
  return { root, repository, artifactPath, expectedBytes: bytes.length,
    expectedSha256: createHash('sha256').update(bytes).digest('hex'), firstCommit };
}

test('normalization retains source location and commit while dropping scanner secret fields', () => {
  const commit = 'a'.repeat(40);
  const result = normalizeGitHistoryFindings([
    { File: 'src/key.txt', StartLine: 3, RuleID: 'generic-api-key', Commit: commit,
      Secret: secret, Match: secret, Fingerprint: secret, Entropy: secret, Message: secret },
    { File: '../outside', RuleID: 'unsafe', Commit: commit, Secret: secret },
    { File: 'src/key.txt', RuleID: 'unsafe', Commit: 'not-a-sha', Secret: secret }
  ]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.omitted, 2);
  assert.equal(result.findings[0].file, 'src/key.txt');
  assert.equal(result.findings[0].commit, commit);
  assert.equal(result.findings[0].line, 3);
  assert.ok(!JSON.stringify(result).includes(secret));
});

test('self-contained bundle is verified, cloned bare, bounded, scanned and discarded', async t => {
  const f = await fixture(t), scratch = path.join(f.root, 'scratch');
  let gitleaksArgs;
  const execute = (command, args, options) => {
    if (command !== 'gitleaks') return spawnSync(command, args, options);
    gitleaksArgs = args;
    assert.equal(args[0], 'git');
    assert.ok(args.includes('--log-opts=--all'));
    assert.ok(args.includes('--redact=100'));
    assert.ok(args.includes('--ignore-gitleaks-allow'));
    writeFileSync(args[args.indexOf('--report-path') + 1], JSON.stringify([
      { File: 'key.txt', StartLine: 1, RuleID: 'generic-api-key', Commit: f.firstCommit,
        Secret: secret, Match: secret, Fingerprint: secret }
    ]));
    return { status: 0 };
  };
  const result = await scanGitHistoryArtifact({ ...f, root: scratch, execute });
  assert.equal(result.status, 'completed');
  assert.equal(result.coverage.commitCount, 2);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].commit, f.firstCommit);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(gitleaksArgs[1], path.join(scratch, 'repository.git'));
  await assert.rejects(readFile(scratch), { code: 'ENOENT' });
});

test('wrong digest and oversized history fail before a clean result', async t => {
  const f = await fixture(t);
  await assert.rejects(scanGitHistoryArtifact({ ...f, expectedSha256: '0'.repeat(64),
    root: path.join(f.root, 'digest-scratch') }), /digest mismatch/);
  await assert.rejects(scanGitHistoryArtifact({ ...f, expectedBytes: f.expectedBytes - 1,
    root: path.join(f.root, 'size-scratch') }), /size mismatch/);
  await assert.rejects(scanGitHistoryArtifact({ ...f, root: path.join(f.root, 'limit-scratch'),
    limits: { ...HISTORY_LIMITS, commits: 1 } }), /commit limit/);
});

test('client bundles only local refs with bounded size and cleans its temporary artifact', async t => {
  const f = await fixture(t);
  const prepared = await prepareGitHistoryBundle(f.repository);
  assert.equal(prepared.coverage.commits, 2);
  assert.equal(prepared.coverage.refs, 1);
  assert.equal(prepared.sha256, createHash('sha256').update(await readFile(prepared.artifactPath)).digest('hex'));
  const scanned = await scanGitHistoryArtifact({ artifactPath: prepared.artifactPath,
    expectedSha256: prepared.sha256, expectedBytes: prepared.bytes, root: path.join(f.root, 'client-scratch'),
    execute(command, args, options) {
      if (command !== 'gitleaks') return spawnSync(command, args, options);
      writeFileSync(args[args.indexOf('--report-path') + 1], '[]');
      return { status: 0 };
    } });
  assert.equal(scanned.status, 'completed');
  await prepared.cleanup();
  await assert.rejects(readFile(prepared.artifactPath), { code: 'ENOENT' });
  await assert.rejects(prepareGitHistoryBundle(f.repository, { maxCommits: 1 }), /exceeds 1 commits/);
});
