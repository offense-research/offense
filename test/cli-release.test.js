import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

test('CLI candidates are reproducible, installable and do not overwrite reviewed distributions', async t => {
  const temporary = await mkdtemp(path.join(tmpdir(), 'offense-release-test-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const root = new URL('../', import.meta.url);
  const run = args => execFileSync(process.execPath, args, { cwd: root, encoding: 'utf8', stdio: 'pipe' });
  const preserved = ['public/skills/offense/scripts/cli.mjs', 'cli/THIRD_PARTY_LICENSES.txt', 'Formula/offense.rb'];
  const before = await Promise.all(preserved.map(file => readFile(new URL(file, root))));
  const first = path.join(temporary, 'first'), second = path.join(temporary, 'second');
  for (const dir of [first, second]) run(['scripts/build-offense-cli.mjs', '--release-dir', dir]);
  const files = await readdir(first);
  for (const file of files) assert.deepEqual(await readFile(path.join(first, file)), await readFile(path.join(second, file)), file);
  for (const [i, file] of preserved.entries()) assert.deepEqual(await readFile(new URL(file, root)), before[i], file);
  assert.match(run(['scripts/test-cli-release.mjs', first]), /PASS: CLI .* npm installation and offline commands/);
  assert.throws(() => run(['scripts/build-offense-cli.mjs', '--release-dir', first]), /EEXIST/);
  const archive = files.find(file => file.endsWith('.tgz'));
  await appendFile(path.join(second, archive), 'tampered');
  assert.throws(() => run(['scripts/test-cli-release.mjs', second]), /AssertionError/);
});
