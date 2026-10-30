import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export async function writeOsvCacheManifest(directory) {
  const ecosystems = {};
  for (const ecosystem of ['npm', 'PyPI']) {
    const filename = path.join(directory, 'osv-scalibr', ecosystem, 'all.zip');
    const metadata = await stat(filename), bytes = await readFile(filename);
    if (!metadata.isFile() || metadata.size < 1024 || metadata.size > 512 * 1024 * 1024 || bytes.readUInt32LE(0) !== 0x04034b50)
      throw new Error('Invalid OSV ecosystem database');
    ecosystems[ecosystem] = { size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
      source: `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip` };
  }
  await writeFile(path.join(directory, 'metadata.json'), JSON.stringify({ schemaVersion: 1,
    downloadedAt: new Date().toISOString(), ecosystems }) + '\n', { mode: 0o644 });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) throw new Error('Supply the absolute OSV cache directory.');
  await writeOsvCacheManifest(process.argv[2]);
}
