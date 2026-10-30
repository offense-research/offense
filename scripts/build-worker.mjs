import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { isClientAsset } from '../workers/client-assets.js';
import './build-worker-sources.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const name = path.join(directory, entry.name);
    return entry.isDirectory() ? files(name) : [name];
  });
}

const assets = Object.fromEntries(files(path.join(root, 'dist')).filter(file =>
  !isClientAsset('/' + path.relative(path.join(root, 'dist'), file).replaceAll(path.sep, '/'))).map(file => {
  const bytes = readFileSync(file), compressed = gzipSync(bytes, { level: 9 });
  return [`/${path.relative(path.join(root, 'dist'), file).replaceAll(path.sep, '/')}`,
    !['.mp4', '.webm'].includes(path.extname(file)) && compressed.length + 40 < bytes.length ? { gzip: compressed.toString('base64') } : bytes.toString('base64')];
}));
// Share identical assets across legacy and canonical URLs without embedding
// duplicate CLI/update bundles into the Worker.
const assetValues = [], assetIndexes = new Map();
const assetEntries = Object.entries(assets).map(([name, value]) => {
  const serialized = JSON.stringify(value);
  if (!assetIndexes.has(serialized)) { assetIndexes.set(serialized, assetValues.length); assetValues.push(value); }
  return `${JSON.stringify(name)}:assetContents[${assetIndexes.get(serialized)}]`;
});
writeFileSync(path.join(root, 'workers/asset-manifest.generated.js'),
  `const assetContents = ${JSON.stringify(assetValues)};\nexport const assets = {${assetEntries.join(',')}};\n`);

execFileSync('npx', ['wrangler', 'deploy', '-c', 'wrangler.staging.jsonc', '--dry-run', '--minify', '--outdir', '.worker-build'],
  { cwd: root, stdio: 'inherit' });
