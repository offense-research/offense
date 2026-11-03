import { build } from 'esbuild';
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { buildSkillManifests } from './skill-manifests.mjs';
import { buildOffensePlugin } from './build-offense-plugin.mjs';
import { buildSkillCatalog } from './build-skill-catalog.mjs';
import './build-offense-cli.mjs';
const license = await readFile('node_modules/yaml/LICENSE', 'utf8');
await build({ entryPoints: ['yaml'], bundle: true, minify: true, format: 'esm', platform: 'neutral', target: 'es2022',
  outfile: 'public/skills/purple/scripts/yaml.mjs', banner: { js: `/* YAML parser license:\n${license.replaceAll('*/', '* /')}\n*/` } });
await writeFile('public/skills/purple/scripts/rehearsal-runner.mjs', await readFile('agent/upgrade-rehearsal.js', 'utf8'));
// Bundle the parser and lexical binding resolver for standalone skill installs.
// Preserve MIT notices for every npm package whose code is included.
const syntax = await build({ entryPoints: ['scripts/reachability-syntax.mjs'], bundle: true, minify: true,
  format: 'esm', platform: 'node', target: 'node20', write: false, metafile: true,
  banner: { js: "import { createRequire as purpleCreateRequire } from 'node:module'; const require = purpleCreateRequire(import.meta.url);" } });
const roots = [...new Set(Object.keys(syntax.metafile.inputs).flatMap(file => {
  const match = file.match(/^(.*node_modules\/(?:@[^/]+\/)?[^/]+)\//);
  return match ? [match[1]] : [];
}))];
const notices = await Promise.all(roots.map(async root => {
  const metadata = JSON.parse(await readFile(`${root}/package.json`, 'utf8'));
  let license;
  for (const name of (await readdir(root)).filter(name => /^licen[cs]e(?:[.-]|$)/i.test(name))) {
    try { license = await readFile(`${root}/${name}`, 'utf8'); break; } catch {}
  }
  if (!license) throw new Error(`Missing license notice for ${root}`);
  return `${metadata.name}@${metadata.version}\n${license}`;
}));
await writeFile('public/skills/purple/scripts/syntax.mjs', `/*\n${notices.join('\n\n').replaceAll('*/', '* /')}\n*/\n${syntax.outputFiles[0].text}`);

// The same dependency-free updater serves both installed skill packages.
const updater = await build({ entryPoints: ['scripts/skill-updater-cli.mjs'], bundle: true,
  format: 'esm', platform: 'node', target: 'node20', write: false });
for (const name of ['offense', 'purple']) await writeFile(`public/skills/${name}/scripts/update.mjs`, updater.outputFiles[0].text);

// The small capability client has no runtime npm dependencies after download.
await build({ entryPoints: ['scripts/offense-audit-client.mjs'], bundle: true, minify: false,
  format: 'esm', platform: 'node', target: 'node20', outfile: 'public/skills/offense/scripts/offense.mjs',
  banner: { js: `/* YAML parser license:\n${license.replaceAll('*/', '* /')}\n*/` } });
// Local static tools share the hosted finding filter; code never leaves the agent.
await build({ entryPoints: ['scripts/source-scan-client.mjs'], bundle: true, minify: false,
  format: 'esm', platform: 'node', target: 'node20', outfile: 'public/skills/purple/scripts/source-scan.mjs',
  define: { PURPLE_SOURCE_RULES: JSON.stringify(await readFile('agent/scan-rules.yml', 'utf8')) } });
const apiImageFiles = {
  'Dockerfile': await readFile('agent/api-test.Dockerfile', 'utf8'),
  'schemathesis-sandbox.py': await readFile('agent/schemathesis-sandbox.py', 'utf8'),
  '.dockerignore': await readFile('agent/api-test.Dockerfile.dockerignore', 'utf8'),
};
await writeFile('public/skills/purple/scripts/api-test-image.mjs',
  `// Fixed, inspected image build inputs. Importing this file performs no I/O.\nexport const apiImageFiles = ${JSON.stringify(apiImageFiles)};\n`);
// Keep the shipped assessment reference identical to its maintained source.
await writeFile('public/skills/purple/references/hosted-assessments.md',
  await readFile('docs/hosted-assessments.md', 'utf8'));
await buildSkillCatalog();
await buildSkillManifests();
await buildOffensePlugin();
