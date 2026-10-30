// Trusted controllers only. Never follow a repository-created symlink while
// reclaiming writable job artifacts from the separate repository UID.
import { lstat, readdir, chown, lchown, chmod, realpath } from 'node:fs/promises';
import path from 'node:path';

const preserved = new Set(['input-repository', '.purple-managed-job.json']);
const uidValid = value => Number.isSafeInteger(value) && value >= 0 && value <= 2147483647;
async function jobRoot(output) {
  if (typeof output !== 'string' || !path.isAbsolute(output) || path.resolve(output) !== output || output === path.parse(output).root || output === '/tmp' || output === '/home') throw new Error('Artifact ownership requires a narrow absolute job directory.');
  let cursor = path.parse(output).root;
  for (const name of path.relative(cursor, output).split(path.sep)) {
    cursor = path.join(cursor, name);
    const stat = await lstat(cursor);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('Artifact ownership refuses symlinked job roots.');
  }
  if (await realpath(output) !== output) throw new Error('Artifact job directory changed during validation.');
  return output;
}
async function walk(output, { uid, gid, preparing = false }) {
  const root = await jobRoot(output), controllerUid = process.getuid(), controllerGid = process.getgid();
  const deadline = Date.now() + 45000; let entries = 0;
  async function visit(file, depth) {
    if (++entries > 250000 || depth > 100 || Date.now() > deadline) throw new Error('Artifact ownership traversal exceeded its bounds.');
    const stat = await lstat(file);
    if (stat.isSymbolicLink()) { await lchown(file, preparing ? controllerUid : uid, preparing ? controllerGid : gid); return; }
    if (stat.isDirectory()) {
      // CAP_CHOWN lets the trusted root regain access to mode0700 worker dirs;
      // it does not require DAC_OVERRIDE or permit following their symlinks.
      await chown(file, controllerUid, controllerGid); await chmod(file, 0o700);
      for (const name of await readdir(file)) {
        if (depth === 0 && preserved.has(name)) continue;
        await visit(path.join(file, name), depth + 1);
      }
      await chmod(file, depth === 0 ? (preparing ? 0o711 : 0o700) : (preparing ? 0o700 : 0o755));
      if (!preparing) await chown(file, uid, gid);
    } else if (stat.isFile()) {
      await chown(file, preparing ? controllerUid : uid, preparing ? controllerGid : gid);
    } else {
      // FIFOs and sockets can be created by tests. Reclaim their directory entry
      // without opening them (which could block) or following a target.
      await lchown(file, preparing ? controllerUid : uid, preparing ? controllerGid : gid);
    }
  }
  try { await visit(root, 0); }
  finally {
    // A bound/error in one subtree must not strand the top-level job as root.
    if (!preparing) {
      await chown(root, controllerUid, controllerGid); await chmod(root, 0o700); await chown(root, uid, gid);
    }
  }
  return { entries, uid: preparing ? controllerUid : uid, gid: preparing ? controllerGid : gid };
}
export async function prepareArtifactOwnership(output) {
  if (process.getuid() !== 0) throw new Error('Isolated job controller must run as root with limited ownership capabilities.');
  return walk(output, { uid: 0, gid: 0, preparing: true });
}
export async function restoreArtifactOwnership({ output, uid, gid }) {
  if (!uidValid(uid) || !uidValid(gid)) throw new Error('Invalid artifact owner identity.');
  return walk(output, { uid, gid });
}
