import { build } from 'esbuild';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';

const license = (await readFile('node_modules/yaml/LICENSE', 'utf8')).replaceAll('*/', '* /');
const banner = { js: `/* Bundled YAML parser license:\n${license}\n*/` };
await mkdir('sdk/dist', { recursive: true });
await mkdir('public/downloads', { recursive: true });
await build({ entryPoints: ['sdk/index.mjs'], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022',
  outfile: 'sdk/dist/index.mjs', banner });
await build({ entryPoints: ['sdk/node.mjs'], bundle: true, format: 'esm', platform: 'node', target: 'node20',
  outfile: 'sdk/dist/node.mjs', banner });
await build({ entryPoints: ['scripts/offense-automation.mjs'], bundle: true, format: 'esm', platform: 'node', target: 'node20',
  outfile: 'public/downloads/offense-automation.mjs', banner });

const resources = {
  'package.json': 'sdk/package.json', 'index.d.ts': 'sdk/index.d.ts', 'node.d.ts': 'sdk/node.d.ts',
  'LICENSE': 'LICENSE', 'NOTICE': 'NOTICE',
  'README.md': 'sdk/README.md', 'dist/index.mjs': 'sdk/dist/index.mjs', 'dist/node.mjs': 'sdk/dist/node.mjs',
  'examples/claude-agent.mjs': 'examples/agent-security/claude-agent.mjs',
  'examples/opencode-agent.mjs': 'examples/agent-security/opencode-agent.mjs',
  'examples/deploy.mjs': 'examples/agent-security/deploy.mjs'
};
// Deterministic USTAR: fixed ordering, IDs, modes, mtime and gzip metadata. No
// checkout paths, environment variables or credentials enter the download.
const blocks = [];
for (const [relative, source] of Object.entries(resources).sort(([a], [b]) => a.localeCompare(b))) {
  const bytes = await readFile(source), header = Buffer.alloc(512), name = `package/${relative}`;
  if (Buffer.byteLength(name) > 100) throw Error('SDK archive name exceeds the USTAR field.');
  header.write(name, 0, 100, 'utf8');
  const octal = (value, start, width) => header.write(value.toString(8).padStart(width - 1, '0') + '\0', start, width, 'ascii');
  octal(0o644, 100, 8); octal(0, 108, 8); octal(0, 116, 8); octal(bytes.length, 124, 12); octal(0, 136, 12);
  header.fill(32, 148, 156); header.write('0', 156, 1); header.write('ustar\0', 257, 6); header.write('00', 263, 2);
  const checksum = header.reduce((sum, value) => sum + value, 0);
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  blocks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
}
blocks.push(Buffer.alloc(1024));
await writeFile('public/downloads/offense-sdk.tgz', gzipSync(Buffer.concat(blocks), { level: 9 }));
console.log('Built standalone automation helper and private agent SDK archive.');
