import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { runSpectral, runGuardDog, verifyPackageArchive } from '../agent/scan-additional-adapters.mjs';

function npmArchive(name = 'fixture', version = '1.0.0') {
  const content = Buffer.from(JSON.stringify({ name, version }));
  const header = Buffer.alloc(512);
  header.write('package/package.json', 0);
  header.write('0000644\0', 100);
  header.write('0000000\0', 108);
  header.write('0000000\0', 116);
  header.write(content.length.toString(8).padStart(11, '0') + '\0', 124);
  header.write('00000000000\0', 136);
  header.fill(32, 148, 156);
  header.write('0', 156);
  header.write('ustar\0', 257);
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
  return gzipSync(Buffer.concat([header, content, Buffer.alloc((512 - content.length % 512) % 512), Buffer.alloc(1024)]));
}

test('Spectral maps findings without echoing OpenAPI values or scanner messages', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-spectral-test-'));
  try {
    const reportPath = path.join(root, 'report.json');
    const secret = 'private-token-in-openapi-server-url';
    const result = await runSpectral({ filePath: path.join(root, 'openapi.yaml'), displayPath: 'api/openapi.yaml', reportPath,
      rulesetPath: path.join(root, '.spectral.yaml'), execute: (binary, args, options) => {
        assert.equal(args.includes('--ruleset'), true);
        assert.equal(options.env.PATH, '/usr/local/bin:/usr/bin:/bin');
        return { status: 1, stdout: JSON.stringify([{ code: 'owasp:api8:2023-no-server-http', severity: 0,
          message: `Server URL contains ${secret}`, range: { start: { line: 4 } }, source: secret }]) };
      } });
    assert.equal(result.status, 'complete');
    assert.equal(result.findings[0].file, 'api/openapi.yaml');
    assert.equal(result.findings[0].line, 5);
    assert.equal(result.findings[0].severity, 'HIGH');
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.ok(!await readFile(reportPath, 'utf8').then(text => text.includes(secret)));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Spectral keeps unresolved specifications partial', async () => {
  const result = await runSpectral({ filePath: '/tmp/openapi.json', execute: () => ({ status: 1,
    stdout: JSON.stringify([{ code: 'resolver', message: 'Unable to resolve reference', severity: 0 }]) }) });
  assert.equal(result.status, 'partial');
});

test('GuardDog refuses a clean claim when its operator cache is stale', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-guarddog-stale-'));
  try {
    await writeFile(path.join(root, 'package.tgz'), npmArchive());
    const result = await runGuardDog({ archivePath: path.join(root, 'package.tgz'), ecosystem: 'npm',
      packageName: 'fixture', version: '1.0.0', cacheDir: root,
      execute: () => { throw new Error('Scanner must not run with stale data'); } });
    assert.equal(result.status, 'partial');
    assert.equal(result.findings.length, 0);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('GuardDog returns risks while discarding raw package code and matching secrets', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-guarddog-test-'));
  try {
    await writeFile(path.join(root, 'package.tgz'), npmArchive('@scope/fixture'));
    const cacheDir = path.join(root, 'cache'); await mkdir(cacheDir);
    for (const ecosystem of ['npm', 'pypi', 'rubygems', 'go'])
      await writeFile(path.join(cacheDir, `top_${ecosystem}_packages.json`), JSON.stringify({
        downloaded_timestamp: Math.floor(Date.now() / 1000), packages: Array.from({ length: 101 }, (_, i) => `p${i}`)
      }));
    const reportPath = path.join(root, 'report.json'), secret = 'ghp_exposed_fixture_secret';
    const result = await runGuardDog({ archivePath: path.join(root, 'package.tgz'), ecosystem: 'npm',
      packageName: '@scope/fixture', version: '1.0.0', cacheDir, reportPath,
      execute: (binary, args) => {
        assert.ok(!args.includes('--no-sandbox'));
        assert.ok(args.includes(path.join(root, 'package.tgz')));
        return { status: 0, stderr: '', stdout: JSON.stringify({ errors: {}, risk_score: { score: 7.4 }, risks: [{
          name: 'risk.process.hooks', threat_rule: 'threat-npm-preinstall-script', severity: 'high',
          threat_code: secret, threat_match: secret, threat_description: secret, file_path: 'package/install.js'
        }] }) };
      } });
    assert.equal(result.status, 'complete');
    assert.equal(result.findings[0].package, '@scope/fixture');
    assert.equal(result.findings[0].installedVersion, '1.0.0');
    assert.equal(result.findings[0].file, 'package.tgz');
    assert.ok(!JSON.stringify(result).includes(secret));
    assert.ok(!await readFile(reportPath, 'utf8').then(text => text.includes(secret)));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('GuardDog rejects a package archive whose metadata does not match the declared coordinate', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-guarddog-identity-'));
  try {
    const archivePath = path.join(root, 'package.tgz');
    await writeFile(archivePath, npmArchive('different-name'));
    assert.equal(await verifyPackageArchive({ archivePath, ecosystem: 'npm', packageName: 'claimed-name', version: '1.0.0' }), false);
    const result = await runGuardDog({ archivePath, ecosystem: 'npm', packageName: 'claimed-name', version: '1.0.0',
      execute: () => { throw new Error('Mismatched archive must never be scanned as the claimed package'); } });
    assert.equal(result.status, 'partial');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('GuardDog retries only its exact missing-kernel-sandbox preflight in the isolated scanner', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-guarddog-landlock-'));
  try {
    await writeFile(path.join(root, 'package.tgz'), npmArchive());
    const cacheDir = path.join(root, 'cache'); await mkdir(cacheDir);
    for (const ecosystem of ['npm', 'pypi', 'rubygems', 'go'])
      await writeFile(path.join(cacheDir, `top_${ecosystem}_packages.json`), JSON.stringify({
        downloaded_timestamp: Math.floor(Date.now() / 1000), packages: Array.from({ length: 101 }, (_, i) => `p${i}`)
      }));
    let calls = 0;
    const options = { archivePath: path.join(root, 'package.tgz'), ecosystem: 'npm',
      packageName: 'fixture', version: '1.0.0', cacheDir };
    const result = await runGuardDog({ ...options, execute: (binary, args) => {
      calls++;
      if (calls === 1) {
        assert.equal(binary, '/opt/purple/guarddog/bin/guarddog');
        assert.ok(!args.includes('--no-sandbox'));
        return { status: 1, stdout: '', stderr: 'ERROR: Kernel-level sandbox is not available on this platform. Use --no-sandbox to scan without it.\n' };
      }
      assert.equal(binary, '/usr/bin/setpriv');
      assert.deepEqual(args.slice(0, 3), ['--no-new-privs', '--', '/opt/purple/guarddog/bin/guarddog']);
      assert.ok(args.includes('--no-sandbox'));
      return { status: 0, stdout: JSON.stringify({ errors: {}, risk_score: { score: 0 }, risks: [] }), stderr: '' };
    } });
    assert.equal(calls, 2);
    assert.equal(result.status, 'complete');
    calls = 0;
    const otherFailure = await runGuardDog({ ...options, execute: () => {
      calls++;
      return { status: 1, stdout: '', stderr: 'ERROR: Sandbox application failed.' };
    } });
    assert.equal(calls, 1);
    assert.equal(otherFailure.status, 'failed');
  } finally { await rm(root, { recursive: true, force: true }); }
});
