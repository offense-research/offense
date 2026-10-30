// Check the actual distributable, not the source entrypoint. No hosted calls.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const [input, ...extra] = process.argv.slice(2);
if (!input || extra.length) throw Error('Usage: node scripts/test-cli-release.mjs <candidate-directory>');
const directory = path.resolve(input);
const archives = (await readdir(directory)).filter(name => /^offense-cli-\d+\.\d+\.\d+\.tgz$/.test(name));
assert.equal(archives.length, 1, 'Expected exactly one versioned CLI archive');
const archive = path.join(directory, archives[0]);
const version = archives[0].slice('offense-cli-'.length, -4);
const digest = createHash('sha256').update(await readFile(archive)).digest('hex');
assert.equal(await readFile(path.join(directory, 'SHA256SUMS'), 'utf8'), `${digest}  ${archives[0]}\n`);
const formula = await readFile(path.join(directory, 'offense.rb'), 'utf8');
assert.ok(formula.includes(`sha256 "${digest}"`));
assert.ok(formula.includes(`/releases/download/cli-v${version}/${archives[0]}`));
assert.ok(formula.includes('libexec.install "dist/offense.mjs"'));
assert.ok(formula.includes('"THIRD_PARTY_LICENSES.txt"'));
const run = (command, args, options = {}) => execFileSync(command, args, { encoding: 'utf8', stdio: 'pipe', ...options });
assert.deepEqual(run('tar', ['-tzf', archive]).trim().split('\n').sort(), [
  'package/LICENSE', 'package/NOTICE', 'package/README.md', 'package/THIRD_PARTY_LICENSES.txt',
  'package/dist/offense.mjs', 'package/package.json'
].sort());
const metadata = JSON.parse(run('tar', ['-xOzf', archive, 'package/package.json']));
assert.equal(metadata.version, version);
assert.equal(metadata.license, 'Apache-2.0');
assert.equal(metadata.private, true);
assert.equal(metadata.bin.offense, 'dist/offense.mjs');
assert.equal(metadata.scripts, undefined, 'No package lifecycle scripts');
assert.equal(metadata.dependencies, undefined, 'No install-time dependency resolution');
assert.ok(run('tar', ['-xOzf', archive, 'package/LICENSE']).includes('Apache License'));
assert.ok(run('tar', ['-xOzf', archive, 'package/NOTICE']).includes('Offense'));
assert.ok(run('tar', ['-xOzf', archive, 'package/THIRD_PARTY_LICENSES.txt']).includes('smol-toml'));

const temporary = await mkdtemp(path.join(tmpdir(), 'offense-cli-release-'));
try {
  // Exclude real user credentials and npm configuration; use an isolated prefix.
  const env = { PATH: process.env.PATH, HOME: temporary, npm_config_cache: path.join(temporary, 'cache'),
    OFFENSE_CONFIG_DIR: path.join(temporary, 'config'), OFFENSE_API_URL: 'http://127.0.0.1:1' };
  run('npm', ['install', '--global', '--prefix', temporary, '--ignore-scripts', '--no-audit', '--no-fund', archive], { env });
  const cli = path.join(temporary, 'bin', 'offense');
  const invoke = args => JSON.parse(run(cli, args, { env }));
  assert.equal(invoke(['--version']).version, version);
  assert.ok(invoke(['--help']).commands.includes('login [--no-browser]'));
  const status = invoke(['status']);
  assert.equal(status.signedIn, false);
  assert.equal(status.endpoint, env.OFFENSE_API_URL);
  const preview = invoke(['k8s', 'collect', '--context', 'release-check', '--preview']);
  assert.equal(preview.status, 'preview');
  assert.equal(preview.scope.context, 'release-check');
  assert.equal(preview.scope.withNova, false);
  await assert.rejects(access(env.OFFENSE_CONFIG_DIR), { code: 'ENOENT' });
  console.log(`PASS: CLI ${version} archive, licenses, checksum, npm installation and offline commands on ${process.version}`);
} finally { await rm(temporary, { recursive: true, force: true }); }
