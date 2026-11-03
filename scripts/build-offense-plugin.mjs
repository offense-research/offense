import { readFile, writeFile, mkdir, lstat, realpath, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SKILL_FILES } from './skill-manifests.mjs';
import { validateRelease } from './skill-updater.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const pluginInstallation = `## Install and update this Codex plugin

This copy is managed by Codex, as recorded in .offense-distribution.json.
Use the Codex plugin manager for installation, upgrade and removal. Do not fetch
or stage hosted skill updates, run a manual skill installer over this package,
or edit files in the plugin cache. The bundled update command reports this mode
without fetching or modifying releases. Start a new coding-agent session after
installation or update; saved configuration is not proof of active tool discovery.

This is a skills-plus-CLI plugin; installation does not register MCP, log in,
scan, buy credit or change application files. Reuse existing callable MCP tools
or the bundled scripts/cli.mjs and scripts/offense.mjs. Credentials stay in the
CLI's existing private configuration outside the plugin. Only follow the manual
[setup reference](references/install.md) for a separately requested account or
connection setup, not for replacing this plugin's files.

Check for an existing manually installed offense or scanning-with-offense skill
in the client's discovered skill locations before migration. If both are present,
explain the duplicate entry points and let the user choose which to keep enabled.
Never delete customized skills or rewrite project instructions automatically.

`;

export function pluginSkillText(source) {
  const start = source.indexOf('## Install once\n'), end = source.indexOf('## Audit the selected repository\n');
  if (start < 0 || end <= start) throw Error('Canonical skill installation sections changed; review the plugin overlay.');
  return source.slice(0, start) + pluginInstallation + source.slice(end);
}

export async function buildOffensePlugin({ source = path.join(repo, 'public/skills/offense'), output = path.join(repo, 'plugins/offense') } = {}) {
  const release = validateRelease(JSON.parse(await readFile(path.join(source, 'manifest.json'), 'utf8')), 'offense');
  const sourceRoot = await realpath(source);
  const resources = [];
  for (const name of SKILL_FILES.offense) {
    const filename = path.join(source, name), info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink() || await realpath(filename) !== path.join(sourceRoot, name)) throw Error('Plugin resource must be a regular file inside the skill: ' + name);
    const bytes = await readFile(filename), entry = release.files.find(file => file.path === name);
    if (!entry || entry.bytes !== bytes.length || entry.sha256 !== createHash('sha256').update(bytes).digest('hex')) throw Error('Plugin resource does not match skill release: ' + name);
    resources.push([name, name === 'SKILL.md' ? pluginSkillText(bytes.toString()) : bytes]);
  }
  const allowed = new Set(['plugin.json', 'skills/offense/.offense-distribution.json', ...SKILL_FILES.offense.map(name => 'skills/offense/' + name)]);
  async function inspectOutput(directory, prefix = '') {
    const info = await lstat(directory).catch(error => { if (error.code === 'ENOENT') return null; throw error; });
    if (!info) return;
    if (!info.isDirectory() || info.isSymbolicLink()) throw Error('Plugin output must be a real directory: ' + directory);
    for (const name of await readdir(directory)) {
      const relative = prefix + name, filename = path.join(directory, name), entry = await lstat(filename);
      if (entry.isSymbolicLink()) throw Error('Plugin output contains a symlink: ' + relative);
      if (entry.isDirectory() && [...allowed].some(file => file.startsWith(relative + '/'))) await inspectOutput(filename, relative + '/');
      else if (!entry.isFile() || !allowed.has(relative)) throw Error('Unexpected plugin output; review before packaging: ' + relative);
    }
  }
  await inspectOutput(output);
  for (const [name, bytes] of resources) {
    const filename = path.join(output, 'skills/offense', name);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, bytes);
  }
  await writeFile(path.join(output, 'skills/offense/.offense-distribution.json'), JSON.stringify({ schemaVersion: 1, manager: 'codex-plugin' }, null, 2) + '\n');
  await writeFile(path.join(output, 'plugin.json'), JSON.stringify({
    '$schema': 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',
    name: 'offense', version: release.version,
    description: 'Guided security assessments that explain findings, consequences and fix choices.',
    author: { name: 'Offense Security' }, homepage: 'https://offense.sh',
    repository: 'https://github.com/offense-research/offense', license: 'Apache-2.0',
    keywords: ['security', 'assessment', 'offense'],
    extensions: { 'com.openai': { requires_local_executor: true } },
  }, null, 2) + '\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await buildOffensePlugin();
