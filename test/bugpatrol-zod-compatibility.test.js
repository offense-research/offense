import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { patchBugpatrolBundle, patchInstalledBugpatrol, PATCHED_BUNDLE_SHA256 } from '../scripts/patch-bugpatrol-zod.mjs';

const require = createRequire(import.meta.url);
const manifestPath = require.resolve('bugpatrol/package.json');
const bugpatrolRequire = createRequire(manifestPath);
const bin = path.join(path.dirname(manifestPath), 'dist/bin.js');
const source = readFileSync(bin, 'utf8');
const schemaStart = source.indexOf('// ../core/dist/config/schema.js');
const configSource = source.slice(schemaStart, source.indexOf('// ../core/dist/config/load.js', schemaStart))
  .replace('import { z } from "zod";', '');
const agentsSource = source.slice(source.indexOf('// ../core/dist/config/agents.js'), source.indexOf('// ../core/dist/config/load.js'));
const apiStart = source.indexOf('var apiRequestSchema =');
const apiSource = source.slice(apiStart, source.indexOf('var text =', apiStart));
const { z } = bugpatrolRequire('zod');
const schemas = vm.runInNewContext(`${agentsSource}\n${configSource}\n${apiSource}\n({config:bugpatrolConfigSchema, api:apiRequestSchema})`, { z, z5: z });

const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]))
    : value;
const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

// These digests record complete normalized outputs from the original BugPatrol
// 0.3.0 + Zod 3.25.76 before the migration, not outputs inferred from Zod 4.
const validConfigs = [
  ['web defaults', { version: 1, run: { command: 'echo ok', url: 'http://localhost:3000' } }, '8e314760fda4d1ac44ccd78f8df41c25bb79f285c6000a4c9fcbd871a6085a5b'],
  ['API defaults', { version: 1, app: { platform: 'api', connect: { url: 'http://localhost:3000' } } }, '6524c32c3a6efc35a7dc010c4b914ed5fdecc70c1d2c92f6b9b609815d8a33aa'],
  ['records and setup', { version: 1, app: { platform: 'cli', setup: [{ run: 'echo ok', capture: { FOO: '/a' } }], teardown: [{ run: 'echo bye' }], connect: { headers: { Authorization: 'test' } } } }, '2c04dce1d59160548f8e0b941f8adde8b227ca3be3c1132982d68ab09729dda9'],
  ['desktop defaults', { version: 1, app: { platform: 'desktop', connect: { cua: { launch: '/tmp/probe' } } } }, '7c35640401bebc8bddb4a143ac300b8b2aa9b84d046b6ddf09a457485227f9aa'],
  ['agent defaults and CLI expansion', { version: 1, app: { platform: 'cli' }, agents: { fixer: { enabled: true }, explorer: { use: 'codex' } } }, 'ce65e0c39ce1f53a69f774fc7ee5f76f4d40f47623f0021edadfece378a33330'],
  ['custom CLI command', { version: 1, app: { platform: 'cli' }, agents: { explorer: { use: { runtime: 'cli', command: 'agent -p' } } } }, '2816a11fe84016225c9547caf134b06212eb63c23a0b81ae2a78058c6e185121'],
  ['viewport element defaults', { version: 1, app: { platform: 'cli' }, viewports: [{ name: 'small', width: 100, height: 100 }] }, '841fe56b624af4bcc50b5228a575a8f19c44f610886a3701e318facdd9526f0d'],
  ['legacy auth:none', { version: 1, app: { platform: 'cli' }, auth: { kind: 'none' } }, '7382f3e1b981ee4e3324386dc07ae183bbbbf25bed87ec14b7925b015edf696c'],
];

for (const [name, input, expected] of validConfigs) {
  test(`BugPatrol preserves original Zod 3 behavior: ${name}`, () => {
    assert.equal(digest(schemas.config.parse(input)), expected);
  });
}

test('BugPatrol still rejects invalid configuration and preserves the auth warning', () => {
  for (const input of [
    { version: 1 },
    { version: 1, app: { platform: 'cli', setup: [{ run: 'echo ok', capture: { FOO: 4 } }] } },
    { version: 1, app: { platform: 'cli' }, agents: { explorer: { use: 'badagent' } } },
  ]) assert.equal(schemas.config.safeParse(input).success, false);
  const auth = schemas.config.safeParse({ version: 1, app: { platform: 'cli' }, auth: { kind: 'oauth' } });
  assert.equal(auth.success, false);
  assert.ok(auth.error.issues.some(issue => issue.message === 'Bugpatrol does not read `auth`. Sign in through `app.setup` and `app.instructions`.'));
});

test('BugPatrol API headers and captures retain value and key validation', () => {
  for (const input of [
    { method: 'GET', url: '/foo', headers: { accept: 'application/json' } },
    { method: 'POST', url: '/foo', capture: { RESPONSE_FOO: '/x' } },
  ]) assert.deepEqual(canonical(schemas.api.parse(input)), canonical(input));
  for (const input of [
    { method: 'POST', url: '/foo', headers: { accept: 3 } },
    { method: 'POST', url: '/foo', capture: { BAD: '/x' } },
  ]) assert.equal(schemas.api.safeParse(input).success, false);
});

test('BugPatrol patch is already applied, idempotent, and rejects unreviewed bundle content', () => {
  assert.equal(createHash('sha256').update(source).digest('hex'), PATCHED_BUNDLE_SHA256);
  assert.deepEqual(patchBugpatrolBundle(source), { source, changed: false });
  assert.throws(() => patchBugpatrolBundle(`${source}\n// unexpected change`), /differs from reviewed/);
});

test('production installs can omit the BugPatrol development dependency', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'offense-no-bugpatrol-'));
  try {
    writeFileSync(path.join(root, 'package.json'), '{"private":true}');
    assert.equal(patchInstalledBugpatrol(root).skipped, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('BugPatrol CLI help and issue listing work with the migrated config parser', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'offense-bugpatrol-cli-'));
  try {
    mkdirSync(path.join(root, '.bugpatrol'));
    writeFileSync(path.join(root, '.bugpatrol/bugpatrol.yml'), 'version: 1\napp:\n  platform: cli\n  connect:\n    headers:\n      accept: application/json\n');
    for (const [args, expected] of [
      [['explore', '--help'], /bugpatrol explore/],
      [['issue', 'list'], /No issues\./],
    ]) {
      const run = spawnSync(process.execPath, [bin, ...args], { cwd: root, encoding: 'utf8', timeout: 10_000 });
      assert.equal(run.status, 0, `${args.join(' ')}: ${run.stderr}`);
      assert.match(run.stdout, expected);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
