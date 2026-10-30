import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const MAX_BYTES = 32 * 1024 * 1024;
const MAX_COMMITS = 1000;
const MAX_REFS = 32;

function git(cwd, args, { execute, maxBuffer = 1024 * 1024, timeout = 30000, encoding = 'utf8' } = {}) {
  const result = execute('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', ...args], {
    cwd, encoding, maxBuffer, timeout, stdio: ['ignore', 'pipe', 'pipe'],
    env: { PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0', GIT_PROTOCOL_FROM_USER: '0' }
  });
  if (result.status !== 0 || result.error) throw new Error('Could not create a bounded Git history bundle. Narrow the repository or inspect its Git state.');
  return result.stdout;
}

/** Create a capped, self-contained local bundle without contacting a remote. */
export async function prepareGitHistoryBundle(directory, { execute = spawnSync, maxBytes = MAX_BYTES,
  maxCommits = MAX_COMMITS, maxRefs = MAX_REFS } = {}) {
  const requested = path.resolve(directory);
  const repository = git(requested, ['rev-parse', '--show-toplevel'], { execute }).trim();
  if (!path.isAbsolute(repository)) throw new Error('Git did not identify a repository root.');
  const commits = Number(git(repository, ['rev-list', '--all', '--count'], { execute }).trim());
  if (!Number.isSafeInteger(commits) || commits < 1 || commits > maxCommits) throw new Error(`Git history exceeds ${maxCommits} commits. Narrow the local repository before uploading.`);
  const refs = git(repository, ['for-each-ref', '--format=%(refname)'], { execute }).trim().split('\n').filter(Boolean).length;
  if (!refs || refs > maxRefs) throw new Error(`Git history exceeds ${maxRefs} references. Narrow the local repository before uploading.`);
  const bytes = git(repository, ['bundle', 'create', '-', '--all'], { execute, encoding: null,
    maxBuffer: maxBytes + 1, timeout: 90000 });
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > maxBytes) throw new Error(`Git bundle exceeds ${maxBytes} bytes.`);
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-history-bundle-'));
  const artifactPath = path.join(root, 'history.bundle');
  try {
    await writeFile(artifactPath, bytes, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
  return {
    artifactPath, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length,
    coverage: { repository, commits, refs,
      scope: 'All local Git refs at bundle creation time; uncommitted changes and remote-only history are excluded.' },
    cleanup: () => rm(root, { recursive: true, force: true })
  };
}
