import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const validScanPath = value => typeof value === 'string' && value.length > 0 && value.length <= 240 &&
  !path.posix.isAbsolute(value) && !value.includes('\\') && !/[\u0000-\u001f\u007f]/u.test(value) &&
  !value.split('/').some(part => !part || ['.', '..', '.git', 'node_modules', '.ssh'].includes(part));

export function validateAdapterOptions({ root, files, reportPath, timeoutMs }) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || !Array.isArray(files) || files.length > 500 ||
      files.some(file => !validScanPath(file)) || new Set(files).size !== files.length ||
      reportPath !== undefined && (typeof reportPath !== 'string' || !path.isAbsolute(reportPath)) ||
      !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 210000)
    throw new Error('Scanner requires a staged absolute root and bounded relative file paths.');
}

// Only eligible files enter a fresh workspace. Uploaded configuration, ignore
// files, credentials, symlinks and package-manager hooks never reach the tool.
export async function stageAdapterFiles(root, files) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'offense-scanner-'));
  const source = path.join(directory, 'inputs');
  try {
    const actualRoot = await realpath(root);
    await mkdir(source, { mode: 0o700 });
    let total = 0;
    for (const relative of files) {
      const target = path.join(actualRoot, relative), metadata = await lstat(target);
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 256 * 1024 ||
          await realpath(target) !== target) throw new Error('Invalid staged file');
      const bytes = await readFile(target);
      if (bytes.length > 256 * 1024 || (total += bytes.length) > 4 * 1024 * 1024 || bytes.includes(0))
        throw new Error('Staged files exceed bounds');
      const destination = path.join(source, relative);
      await mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
      await writeFile(destination, bytes, { mode: 0o600, flag: 'wx' });
    }
    return { directory, source, cleanup: () => rm(directory, { recursive: true, force: true }) };
  } catch (error) { await rm(directory, { recursive: true, force: true }); throw error; }
}

export function adapterLocation(value, root, allowed) {
  if (typeof value !== 'string' || value.length > root.length + 241) return null;
  const relative = path.isAbsolute(value) ? path.relative(root, value) : value.replace(/^\.\//, '');
  return validScanPath(relative) && allowed.has(relative) ? relative : null;
}

export async function persistAdapterResult(reportPath, result) {
  if (reportPath) await writeFile(reportPath, JSON.stringify(result), { mode: 0o600 });
  return result;
}
