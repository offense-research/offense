import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isClientAsset } from '../workers/client-assets.js';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export async function verifyClientDistribution({ directory = 'dist', fetchImpl = fetch } = {}) {
  const files = [];
  async function walk(folder) {
    for (const entry of await readdir(folder, { withFileTypes: true })) {
      const file = path.join(folder, entry.name);
      if (entry.isDirectory()) await walk(file);
      else if (entry.isFile()) {
        const urlPath = '/' + path.relative(directory, file).replaceAll(path.sep, '/');
        if (isClientAsset(urlPath)) files.push({ file, urlPath });
      }
    }
  }
  await walk(directory);
  if (!files.some(file => file.urlPath === '/downloads/offense-cli.tgz')) throw Error('Build the Offense client distribution before deploying.');
  for (const { file, urlPath } of files) {
    const local = await readFile(file);
    const response = await fetchImpl(new URL(urlPath, 'https://offense.sh'), {
      redirect: 'manual', cache: 'no-store', signal: AbortSignal.timeout(20_000)
    });
    const mismatch = () => Error(`Publish the matching public client assets to offense-landing before deploying the app: ${urlPath}`);
    if (!response.ok || !response.body) { await response.body?.cancel(); throw mismatch(); }
    const reader = response.body.getReader(), chunks = []; let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read(); if (done) break;
        size += value.byteLength;
        if (size > local.length) throw mismatch();
        chunks.push(value);
      }
    } catch (error) { await reader.cancel().catch(() => {}); throw error; }
    if (size !== local.length || digest(Buffer.concat(chunks)) !== digest(local)) throw mismatch();
  }
  return { verifiedFiles: files.length };
}
