import { createHash } from 'node:crypto';
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const configuration = JSON.parse(await readFile(join(root, 'wrangler.jsonc'), 'utf8'));
const directory = resolve(root, configuration.assets.directory);
const types = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'application/javascript;charset=utf-8',
  '.json': 'application/json;charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.tgz': 'application/gzip',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.mp4': 'video/mp4',
};
const manifest = {};
const files = {};
async function collect(folder) {
  for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const path = join(folder, entry.name);
    if (entry.isDirectory()) {
      await collect(path);
    } else if (entry.isFile() && !['_headers', '_redirects', '.assetsignore'].includes(entry.name)) {
      const bytes = await readFile(path);
      const base64 = bytes.toString('base64');
      // This is the hash convention used by Cloudflare's direct-upload example.
      const extension = extname(path).slice(1);
      const hash = createHash('sha256').update(base64 + extension).digest('hex').slice(0, 32);
      manifest['/' + relative(directory, path).replaceAll('\\', '/')] = { hash, size: bytes.length };
      files[hash] = { base64, contentType: types[extname(path)] || 'application/octet-stream' };
    }
  }
}
await collect(directory);
const bundle = {
  name: configuration.name,
  compatibilityDate: configuration.compatibility_date,
  observability: configuration.observability,
  services: configuration.services,
  workerSource: await readFile(resolve(root, configuration.main), 'utf8'),
  assetConfig: {
    html_handling: configuration.assets.html_handling,
    not_found_handling: configuration.assets.not_found_handling,
    _headers: await readFile(join(directory, '_headers'), 'utf8'),
  },
  manifest,
  files,
};
const output = join(root, '.cloudflare-build');
await mkdir(output, { recursive: true });
await writeFile(join(output, 'bundle.json'), JSON.stringify(bundle));
await writeFile(join(output, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Prepared ${Object.keys(manifest).length} static files for ${bundle.name}.`);
