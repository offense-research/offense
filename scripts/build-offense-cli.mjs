import { build } from 'esbuild';
import { mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { OFFENSE_CLI_VERSION } from './offense-cli.mjs';

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--release-dir' || !args[1]))
  throw Error('Usage: node scripts/build-offense-cli.mjs [--release-dir <new-directory>]');
const releaseDir = args.length ? path.resolve(args[1]) : null;
const packageBytes = await readFile('cli/package.json');
const packageMetadata = JSON.parse(packageBytes);
if (packageMetadata.version !== OFFENSE_CLI_VERSION) throw Error('CLI package and implementation versions must match.');
if (releaseDir && !/^\d+\.\d+\.\d+$/.test(packageMetadata.version)) throw Error('Stable CLI candidates require an explicit stable version.');

if (releaseDir) {
  await mkdir(path.dirname(releaseDir), { recursive: true });
  await mkdir(releaseDir); // Refuse to overwrite a previously reviewed candidate.
} else {
  await mkdir('cli/dist', { recursive: true });
  await mkdir('public/downloads', { recursive: true });
  await mkdir('public/skills/offense/scripts', { recursive: true });
}
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
if (!releaseDir) {
  for (const file of ['cli/dist/offense.mjs', 'public/downloads/offense-cli.mjs', 'public/skills/offense/scripts/cli.mjs']) await writeFile(file, code, { mode: 0o755 });
  await writeFile('cli/THIRD_PARTY_LICENSES.txt', licenses + '\n');
}
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
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
if (releaseDir) {
  const archiveName = `offense-cli-${packageMetadata.version}.tgz`;
  const url = `https://github.com/offense-research/offense/releases/download/cli-v${packageMetadata.version}/${archiveName}`;
  const formula = (await readFile('Formula/offense.rb', 'utf8'))
    .replace(/^  url .*$/m, `  url "${url}"`)
    .replace(/^  version .*\n/m, '') // Homebrew infers the version from the release URL.
    .replace(/^  sha256 .*$/m, `  sha256 "${hash(archive)}"`)
    .replace('"public/skills/offense/scripts/cli.mjs"', '"dist/offense.mjs"')
    .replace('"cli/THIRD_PARTY_LICENSES.txt"', '"THIRD_PARTY_LICENSES.txt"');
  await writeFile(path.join(releaseDir, archiveName), archive);
  await writeFile(path.join(releaseDir, 'offense.rb'), formula);
  await writeFile(path.join(releaseDir, 'SHA256SUMS'), `${hash(archive)}  ${archiveName}\n`);
  await writeFile(path.join(releaseDir, 'RELEASE-NOTES.md'), await readFile('cli/CHANGELOG.md'));
  console.log(`Prepared CLI ${packageMetadata.version} in ${releaseDir}. Nothing was tagged, published or deployed.`);
} else {
  await writeFile('public/downloads/offense-cli.tgz', archive);
  await writeFile('public/downloads/offense-cli-manifest.json', JSON.stringify({ version: packageMetadata.version, minimumNodeMajor: 20,
    files: [{ path: 'offense-cli.mjs', bytes: code.length, sha256: hash(code) },
      { path: 'offense-cli.tgz', bytes: archive.length, sha256: hash(archive) }] }, null, 2) + '\n');
  console.log('Built standalone Offense CLI, private npm-compatible archive and checksum manifest.');
}
