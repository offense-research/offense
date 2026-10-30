// Private, invocation-owned report directories. No application context is copied.
import { lstat, realpath, readFile, mkdtemp, mkdir, writeFile, rename, rm, rmdir } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';

const inside = (root, target) => {
  const relative = path.relative(root, target);
  return relative === '' || (relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative));
};
const digest = value => createHash('sha256').update(value).digest('hex');

async function inspectDirectories(directory) {
  let current = path.parse(directory).root;
  for (const part of directory.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const entry = await lstat(current);
    if (!entry.isDirectory() || entry.isSymbolicLink()) throw Error('Report paths cannot contain symlinks or non-directories.');
  }
  if (await realpath(directory) !== directory) throw Error('Use a canonical report directory.');
}

export async function reserveExternalOutput(project, output, prefix = 'purple-report-') {
  const root = await realpath(path.resolve(project));
  let directory;
  if (output === undefined) {
    const temporaryRoot = await realpath(os.tmpdir());
    await inspectDirectories(temporaryRoot);
    directory = await mkdtemp(path.join(temporaryRoot, prefix));
    if (inside(root, directory)) { await rmdir(directory); throw Error('Choose a fresh report directory outside the project.'); }
  } else {
    if (typeof output !== 'string' || !output) throw Error('Choose a fresh report directory outside the project.');
    directory = path.resolve(output);
    if (inside(root, directory) || inside(directory, root)) throw Error('Choose a fresh report directory outside the project.');
    await inspectDirectories(path.dirname(directory));
    try { await mkdir(directory, { mode: 0o700 }); }
    catch { throw Error('Report output must be a new directory; existing files are preserved.'); }
  }
  const owned = new Map();
  async function write(name, content) {
    if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$/.test(name)) throw Error('Invalid report filename.');
    await inspectDirectories(directory);
    const target = path.join(directory, name);
    let current;
    try { current = await lstat(target); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (current) {
      if (!current.isFile() || current.isSymbolicLink() || !owned.has(name) ||
          digest(await readFile(target)) !== owned.get(name)) throw Error('A report target changed; existing content was preserved.');
    } else if (owned.has(name)) throw Error('A report target changed; existing content was preserved.');
    const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const temporary = path.join(directory, `.report-${randomUUID()}`);
    try {
      await writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
      await rename(temporary, target);
      owned.set(name, digest(bytes));
    } finally { await rm(temporary, { force: true }); }
  }
  return { directory, write };
}
