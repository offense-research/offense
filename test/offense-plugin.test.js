import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm, lstat, realpath, writeFile, symlink, cp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { buildOffensePlugin, pluginSkillText } from '../scripts/build-offense-plugin.mjs';
import { SKILL_FILES } from '../scripts/skill-manifests.mjs';

test('plugin is self-contained and preserves canonical payload except its declared install overlay', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'offense-plugin-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  await buildOffensePlugin({ output: root });
  const manifest = JSON.parse(await readFile(path.join(root, 'plugin.json')));
  const release = JSON.parse(await readFile('public/skills/offense/manifest.json'));
  assert.equal(manifest.name, 'offense');
  assert.equal(manifest.version, release.version);
  assert.equal(manifest.extensions['com.openai'].requires_local_executor, true);
  assert.deepEqual((await readdir(root)).sort(), ['plugin.json', 'skills']);
  const skill = path.join(root, 'skills/offense');
  const expected = [...SKILL_FILES.offense, '.offense-distribution.json'].sort();
  const actual = [];
  async function walk(directory, prefix = '') {
    for (const name of await readdir(directory)) {
      const relative = prefix + name, info = await lstat(path.join(directory, name));
      assert.equal(info.isSymbolicLink(), false);
      if (info.isDirectory()) await walk(path.join(directory, name), relative + '/');
      else actual.push(relative);
    }
  }
  await walk(skill);
  assert.deepEqual(actual.sort(), expected);
  for (const file of SKILL_FILES.offense) {
    const canonical = await readFile(path.join('public/skills/offense', file));
    const bytes = await readFile(path.join(skill, file));
    assert.deepEqual(bytes, file === 'SKILL.md' ? Buffer.from(pluginSkillText(canonical.toString())) : canonical);
    if (file.endsWith('.md')) {
      for (const [, link] of bytes.toString().matchAll(/\]\(([^)]+)\)/g)) {
        if (/^(?:https?:|#)/.test(link)) continue;
        const target = path.posix.normalize(path.posix.join(path.posix.dirname(file), link.split('#')[0]));
        assert.ok(expected.includes(target), `Unpackaged link ${file}: ${target}`);
      }
    }
  }
  const marker = JSON.parse(await readFile(path.join(skill, '.offense-distribution.json')));
  assert.equal(marker.manager, 'codex-plugin');
  assert.equal(marker.schemaVersion, 1);
  assert.equal((await readFile(path.join(skill, 'SKILL.md'), 'utf8')).includes('Download every file listed'), false);
});

test('repository marketplace resolves the generated package without MCP or secrets', async () => {
  const marketplace = JSON.parse(await readFile('.agents/plugins/marketplace.json'));
  assert.equal(marketplace.name, 'offense');
  assert.deepEqual(marketplace.plugins.map(p => [p.name, p.source]), [['offense', { source: 'local', path: './plugins/offense' }]]);
});

test('packaging rejects missing, changed, symlinked and unexpected resources', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'offense-plugin-invalid-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const kind of ['missing', 'changed', 'symlink', 'private-output']) {
    const source = path.join(root, kind), output = path.join(root, kind + '-output');
    await cp('public/skills/offense', source, { recursive: true });
    const reference = path.join(source, 'references/assessment.md');
    if (kind === 'missing' || kind === 'symlink') await rm(reference);
    if (kind === 'changed') await writeFile(reference, 'Unexpected changed guidance');
    if (kind === 'symlink') await symlink(path.resolve('public/skills/offense/references/assessment.md'), reference);
    if (kind === 'private-output') {
      await buildOffensePlugin({ source, output });
      await writeFile(path.join(output, '.env'), 'fixture-only');
    }
    await assert.rejects(buildOffensePlugin({ source, output }));
  }
});
