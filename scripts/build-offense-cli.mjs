import { build } from 'esbuild';
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { OFFENSE_CLI_VERSION } from './offense-cli.mjs';

const packageBytes = await readFile('cli/package.json');
const packageMetadata = JSON.parse(packageBytes);
if (packageMetadata.version !== OFFENSE_CLI_VERSION) throw Error('CLI package and implementation versions must match.');

await mkdir('cli/dist', { recursive: true });
await mkdir('public/downloads', { recursive: true });
await mkdir('public/skills/offense/scripts', { recursive: true });
const result = await build({ entryPoints: ['scripts/offense-cli.mjs'], bundle: true,
  format: 'esm', platform: 'node', target: 'node20', minify: true, mainFields: ['module', 'main'], write: false, metafile: true,
  banner: { js: "import { createRequire as offenseCreateRequire } from 'node:module'; const require = offenseCreateRequire(import.meta.url);" },
  define: { OFFENSE_CLI_EMBEDDED: 'true' },
  plugins: [{ name: 'embedded-helpers-use-pure-updater', setup(plugin) {
    plugin.onResolve({ filter: /^\.\/update\.mjs$/ }, args => args.importer.includes('/public/skills/purple/scripts/') ?
      { path: path.resolve('scripts/skill-updater.mjs') } : undefined);
  } }] });
const roots = [...new Set(Object.keys(result.metafile.inputs).flatMap(file => {
  const match = file.match(/^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//); return match ? [match[1]] : [];
}))].sort();
const notices = [];
for (const root of roots) {
  const pkg = JSON.parse(await readFile(`${root}/package.json`, 'utf8'));
  const names = (await readdir(root)).filter(name => /^licen[cs]e(?:[.-]|$)/i.test(name));
  if (!names.length) throw Error(`Missing bundled license for ${pkg.name}`);
  notices.push(`${pkg.name}@${pkg.version}\n${await readFile(`${root}/${names[0]}`, 'utf8')}`);
}
const licenses = notices.join('\n\n');
const body = result.outputFiles[0].text.replace(/^#![^\n]*\n/, '');
const code = Buffer.from(`#!/usr/bin/env node\n/* Third-party licenses:\n${licenses.replaceAll('*/', '* /')}\n*/\n${body}`);
for (const file of ['cli/dist/offense.mjs', 'public/downloads/offense-cli.mjs', 'public/skills/offense/scripts/cli.mjs']) await writeFile(file, code, { mode: 0o755 });
await writeFile('cli/THIRD_PARTY_LICENSES.txt', licenses + '\n');
const entries = { 'package.json': packageBytes, 'README.md': await readFile('cli/README.md'),
  'LICENSE': await readFile('LICENSE'), 'NOTICE': await readFile('NOTICE'),
  'THIRD_PARTY_LICENSES.txt': Buffer.from(licenses + '\n'), 'dist/offense.mjs': code };
const blocks = [];
for (const [name, bytes] of Object.entries(entries).sort(([a], [b]) => a.localeCompare(b))) {
  const header = Buffer.alloc(512); header.write('package/' + name, 0, 100, 'utf8');
  const octal = (number, start, width) => header.write(number.toString(8).padStart(width - 1, '0') + '\0', start, width, 'ascii');
  octal(name.endsWith('.mjs') ? 0o755 : 0o644, 100, 8); octal(0, 108, 8); octal(0, 116, 8);
  octal(bytes.length, 124, 12); octal(0, 136, 12); header.fill(32, 148, 156); header.write('0', 156, 1);
  header.write('ustar\0', 257, 6); header.write('00', 263, 2);
  header.write(header.reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
}
blocks.push(Buffer.alloc(1024));
const archive = gzipSync(Buffer.concat(blocks), { level: 9 });
await writeFile('public/downloads/offense-cli.tgz', archive);
await writeFile('public/downloads/offense-cli-manifest.json', JSON.stringify({ version: packageMetadata.version, minimumNodeMajor: 20,
  files: [{ path: 'offense-cli.mjs', bytes: code.length, sha256: createHash('sha256').update(code).digest('hex') },
    { path: 'offense-cli.tgz', bytes: archive.length, sha256: createHash('sha256').update(archive).digest('hex') }] }, null, 2) + '\n');
console.log('Built standalone Offense CLI, private npm-compatible archive and checksum manifest.');
