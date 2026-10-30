import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

export const SCAN_LIMITS = { files: 500, fileBytes: 256 * 1024, totalBytes: 4 * 1024 * 1024 };
export function sourceFiles(input) {
  if (!Array.isArray(input) || !input.length || input.length > SCAN_LIMITS.files) throw new Error('Upload between 1 and 500 text files.');
  const seen = new Set(); let bytes = 0;
  const files = input.map(file => {
    const name = file?.path;
    if (typeof name !== 'string' || name.length > 240 || !/^[\p{L}\p{N}_.@ /+()-]+$/u.test(name) ||
        name.split('/').some(part => !part || part === '.' || part === '..' || ['.git', 'node_modules', '.ssh'].includes(part)) || name.startsWith('/') || seen.has(name)) throw new Error('Files need unique, safe relative paths.');
    if (typeof file.content !== 'string' || file.content.includes('\0')) throw new Error('Only UTF-8 text files are supported.');
    const size = Buffer.byteLength(file.content);
    if (size > SCAN_LIMITS.fileBytes || (bytes += size) > SCAN_LIMITS.totalBytes) throw new Error('Source exceeds the 256 KB per-file or 4 MB total limit. Narrow the scan directory.');
    seen.add(name); return { path: name, content: file.content };
  });
  // Reject file/directory collisions before anything reaches the filesystem.
  for (const name of seen) for (let end = name.indexOf('/'); end !== -1; end = name.indexOf('/', end + 1)) {
    if (seen.has(name.slice(0, end))) throw new Error('File paths conflict with directories.');
  }
  const fingerprint = createHash('sha256');
  for (const file of [...files].sort((a, b) => a.path.localeCompare(b.path))) fingerprint.update(JSON.stringify([file.path, file.content]));
  return { files, bytes, fingerprint: fingerprint.digest('hex') };
}
