import { spawn } from 'node:child_process';
import { chmod, chown, lstat, mkdir, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

export const REPOSITORY_UID = 1001;
export const REPOSITORY_GID = 1001;
const isolated = () => process.env.PURPLE_FIX_ISOLATE_COMMANDS === '1';
const generated = new Set(['node_modules', '.pnpm-store']);
let groupsCleared = false;

// This opt-in is set only by the dedicated disposable job controller. Never set
// it in a shared host process: the reaper owns every UID1001 process in the job.
export function repositoryCommandIdentity() {
  if (!isolated()) return undefined;
  if (process.getuid?.() !== 0) throw new Error('Repository command isolation requires the trusted root controller.');
  if (!groupsCleared) { process.setgroups([]); groupsCleared = true; }
  return { uid: REPOSITORY_UID, gid: REPOSITORY_GID };
}

async function regularDirectory(directory, mode, owner = 0) {
  await mkdir(directory, { recursive: true, mode });
  const record = await lstat(directory);
  if (!record.isDirectory() || record.isSymbolicLink()) throw new Error('Isolation directories must be real directories.');
  await chown(directory, owner, owner === REPOSITORY_UID ? REPOSITORY_GID : 0);
  await chmod(directory, mode);
}

export async function prepareIsolationDirectories({ workDirectory, outputDirectory }) {
  const home = path.join(workDirectory, 'command-home'), cache = path.join(workDirectory, 'npm-cache');
  if (!repositoryCommandIdentity()) return { home, cache };
  // Traverse-only parents keep root-owned reports and controller output intact.
  await regularDirectory(outputDirectory, 0o711);
  await regularDirectory(workDirectory, 0o711);
  await regularDirectory(home, 0o700, REPOSITORY_UID);
  await regularDirectory(cache, 0o700, REPOSITORY_UID);
  return { home, cache };
}

export async function prepareRepositoryTree(directory) {
  if (!repositoryCommandIdentity()) return;
  await reapRepositoryProcesses();
  const root = path.resolve(directory);
  async function visit(file, git = false, first = false) {
    const record = await lstat(file);
    if (record.isSymbolicLink() || (!record.isDirectory() && (!record.isFile() || record.nlink !== 1))) {
      throw new Error('Repository isolation supports only regular, unlinked source and Git files.');
    }
    const owner = git || first ? 0 : REPOSITORY_UID;
    await chown(file, owner, owner === REPOSITORY_UID ? REPOSITORY_GID : 0);
    if (record.isDirectory()) {
      // The sticky bit prevents UID1001 from renaming/replacing root-owned .git
      // while npm can still atomically replace its own lockfiles in the root.
      await chmod(file, first ? 0o1777 : git ? 0o755 : 0o755);
      for (const name of await readdir(file)) {
        if (!git && generated.has(name)) continue;
        await visit(path.join(file, name), git || (first && name === '.git'));
      }
    } else await chmod(file, (record.mode & 0o111) ? 0o755 : 0o644);
  }
  await visit(root, false, true);
}

async function repositoryProcesses() {
  const processes = [];
  for (const name of await readdir('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const status = await readFile(`/proc/${name}/status`, 'utf8');
      const ids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m.exec(status)?.slice(1).map(Number);
      if (ids?.includes(REPOSITORY_UID) && !/^State:\s+Z/m.test(status)) processes.push(Number(name));
    } catch (error) { if (!['ENOENT', 'ESRCH'].includes(error.code)) throw error; }
  }
  return processes;
}

export async function reapRepositoryProcesses() {
  if (!repositoryCommandIdentity()) return;
  const deadline = Date.now() + 3000;
  for (;;) {
    const pids = await repositoryProcesses();
    if (!pids.length) return;
    for (const signal of ['SIGSTOP', 'SIGKILL']) for (const pid of pids) {
      try { process.kill(pid, signal); } catch (error) { if (!['ESRCH'].includes(error.code)) throw new Error('The repository process boundary could not terminate an untrusted process.'); }
    }
    if (Date.now() >= deadline) throw new Error('Untrusted repository processes survived their command boundary.');
    await new Promise(resolve => setTimeout(resolve, 15));
  }
}

// Reap at leader exit, not only at stdio close: an escaped setsid daemon can
// inherit a pipe and otherwise hold the close event forever. Timeout cleanup is
// independently bounded and destroys pipes even if that daemon keeps them open.
export async function runRepositoryCommand(argv, { cwd, env, timeoutMs = 90000, maxOutputBytes = 500000, repository = true, repositoryDirectory = cwd } = {}) {
  const identity = repository ? repositoryCommandIdentity() : undefined;
  if (identity) await reapRepositoryProcesses();
  if (identity) env = { ...env, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'safe.directory', GIT_CONFIG_VALUE_0: repositoryDirectory };
  return new Promise((resolve, reject) => {
    let child, stdout = '', stderr = '', bytes = 0, timedOut = false, truncated = false, settled = false;
    let exitCode = null, exitSignal = null, cleanupPromise, drainTimer;
    const groupKill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
    const cleanup = () => cleanupPromise ||= (async () => { groupKill(); await reapRepositoryProcesses(); })();
    const done = async error => {
      if (settled) return; settled = true; clearTimeout(timer); clearTimeout(drainTimer);
      try { await cleanup(); } catch (failure) { error ||= failure; }
      child.stdout?.destroy(); child.stderr?.destroy();
      if (error) reject(error);
      else resolve({ code: exitCode, signal: exitSignal, timedOut, truncated, stdout, stderr });
    };
    const timer = setTimeout(() => { timedOut = true; void done(); }, timeoutMs);
    try { child = spawn(argv[0], argv.slice(1), { cwd, env, ...identity, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (error) { clearTimeout(timer); reject(error); return; }
    child.on('error', error => { void done(error); });
    child.on('exit', (code, signal) => {
      exitCode = code; exitSignal = signal;
      // Ignore inherited output after the leader exits, and kill escaped jobs.
      void cleanup().catch(error => { void done(error); });
      if (identity) void cleanup().then(() => { if (!settled) drainTimer = setTimeout(() => { void done(); }, 100); }).catch(error => { void done(error); });
    });
    child.on('close', (code, signal) => { exitCode ??= code; exitSignal ??= signal; void done(); });
    for (const [stream, label] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) stream.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > maxOutputBytes) { truncated = true; void done(); return; }
      if (label === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
    });
  });
}
