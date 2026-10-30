import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { auditMetadata, createLocalIntelligence } from '../lib/audit.mjs';
import { collectMetadata } from '../lib/metadata.mjs';
import { doctor } from '../lib/doctor.mjs';
import { analyze } from '../tools/purple.mjs';

const lock = { lockfileVersion: 3, packages: { '': { dependencies: { semver: '^7.5.1' }, scripts: { test: 'DO_NOT_READ_SCRIPT' } },
  'node_modules/semver': { version: '7.5.1', resolved: 'https://PRIVATE:SECRET@registry.example/semver.tgz', integrity: 'DO_NOT_SEND_INTEGRITY' } } };
const input = (planLimit = 0) => ({ files: [{ path: 'package-lock.json', content: JSON.stringify(lock) }], planLimit });
const finding = { package: 'semver', version: '7.5.1', kind: 'runtime', id: 'GHSA-c2qf-rxjj-qqgw', cves: ['CVE-2022-25883'], severity: 'HIGH',
  summary: 'Synthetic advisory fixture', fixedVersions: ['7.5.2'], advisory: { aliases: ['CVE-2022-25883'], affected: [], references: [] } };
const checked = findings => async () => ({ status: 'complete', checkedPackages: 1, skippedPackages: 0, checkedAt: 100, findings });
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'purple-community-fixture-')); t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'app'); await mkdir(project);
  await writeFile(path.join(project, 'package.json'), JSON.stringify({ private: true, dependencies: { semver: '^7.5.1' } }));
  await writeFile(path.join(project, 'package-lock.json'), JSON.stringify(lock));
  return { root, project };
}

test('local engine returns bounded advisory evidence without confirming exploitability or needing a database/model', async () => {
  const result = await auditMetadata(input(), { check: checked([finding]) });
  assert.equal(result.schemaVersion, 'purple.audit.v1'); assert.equal(result.status, 'complete');
  assert.equal(result.findings[0].package.name, 'semver'); assert.equal(result.findings[0].verification.confirmed, false);
  assert.equal(result.summary.confirmedVulnerabilities, 0); assert.equal(result.summary.high, 1);
  assert.equal(result.summary.provenance.capability, 'purple.audit_dependencies');
  assert.equal(result.remediation.status, 'not_requested');
  assert.match(result.remediation.agentPrompt, /before|baseline/i);
  assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
});

test('invalid metadata is rejected before provider work', async () => {
  let called = false;
  await assert.rejects(auditMetadata({ files: [{ path: '../package-lock.json', content: lock }] }, { check: async () => { called = true; } }), /relative|lockfile/i);
  assert.equal(called, false);
  await assert.rejects(auditMetadata({ ...input(), token: 'NEVER_SEND' }, { check: checked([]) }), /Only files/);
});

test('a failed or incomplete upstream check cannot become a complete result', async () => {
  await assert.rejects(auditMetadata(input(), { check: async () => ({ status: 'partial', findings: [] }) }), /did not complete/);
  await assert.rejects(auditMetadata(input(), { fetchImpl: async () => new Response('', { status: 503 }) }), /OSV returned HTTP 503/);
});

test('direct OSV requests contain only package identity, not raw registry URLs, scripts or source', async () => {
  const calls = [];
  const result = await auditMetadata(input(), { fetchImpl: async (url, options) => {
    calls.push({ url: String(url), body: options.body });
    assert.equal(new URL(url).hostname, 'api.osv.dev');
    return Response.json({ results: [{ vulns: [] }] });
  } });
  assert.equal(result.coverage.checkedPackages, 1);
  assert.equal(calls.length, 1); assert.deepEqual(JSON.parse(calls[0].body), { queries: [{ package: { ecosystem: 'npm', name: 'semver' }, version: '7.5.1' }] });
  for (const value of ['PRIVATE', 'SECRET', 'DO_NOT_READ_SCRIPT', 'DO_NOT_SEND_INTEGRITY']) assert.equal(JSON.stringify(calls).includes(value), false);
});

test('engine blocks provider redirects and unexpected provider hosts', async () => {
  await assert.rejects(auditMetadata(input(), { fetchImpl: async () => new Response('', { status: 302, headers: { location: 'https://untrusted.example' } }) }), /redirects/);
  const intelligence = createLocalIntelligence({ check: async (packages, fetchImpl) => {
    await fetchImpl('https://untrusted.example/data'); return { status: 'complete', findings: [] };
  } });
  await assert.rejects(intelligence.audit(input()), /Unsupported intelligence provider/);
});

test('planning failures retain advisory evidence and a concrete blocker', async () => {
  const result = await auditMetadata(input(1), { check: checked([finding]), plan: async () => { throw Error('npm metadata is unavailable'); } });
  assert.equal(result.status, 'partial'); assert.equal(result.findings.length, 1);
  assert.equal(result.remediation.blockers.length, 1); assert.equal(result.summary.confirmedVulnerabilities, 0);
  assert.equal(result.remediation.plans.length, 0);
});

test('npm inventory is offline, omits credential metadata and preserves pnpm support', async t => {
  const f = await fixture(t); const report = await collectMetadata(f.project);
  assert.equal(report.files.length, 1); assert.equal(report.files[0].path, 'package-lock.json');
  assert.equal(report.files[0].content.includes('SECRET'), false);
  await rm(path.join(f.project, 'package-lock.json'));
  await writeFile(path.join(f.project, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      semver:\n        specifier: ^7.5.1\n        version: 7.5.1\npackages:\n  semver@7.5.1: {}\nsnapshots:\n  semver@7.5.1: {}\n`);
  const pnpm = await collectMetadata(f.project);
  assert.equal(pnpm.files[0].path, 'pnpm-lock.yaml');
  const result = await auditMetadata({ files: pnpm.files, planLimit: 0 }, { check: checked([]) });
  assert.equal(result.coverage.packageManagers[0], 'pnpm'); assert.equal(result.coverage.checkedPackages, 1);
});

test('local scan writes legacy-compatible evidence and a remediation prompt through direct providers', async t => {
  const f = await fixture(t), calls = [];
  const result = await analyze(f.project, { planLimit: 0, output: path.join(f.root, 'report'), log: () => {},
    fetchImpl: async (url, options) => { calls.push(String(url)); assert.equal(new URL(url).hostname, 'api.osv.dev'); return Response.json({ results: [{ vulns: [] }] }); } });
  const report = JSON.parse(await readFile(result.json, 'utf8'));
  assert.equal(report.vulnerabilityCheck.status, 'complete'); assert.equal(report.verification, 'advisory_matches_only');
  assert.equal(report.packageManagers[0], 'npm'); assert.match(await readFile(result.report, 'utf8'), /not confirmed exploitable/);
  assert.ok(calls.length > 0); assert.equal(report.metadataFingerprint.length, 64);
});

test('doctor checks tool availability without executing tools, reading credentials or making requests', async t => {
  const f = await fixture(t), fakeBin = path.join(f.root, 'bin'); await mkdir(fakeBin);
  const sentinel = path.join(f.root, 'executed');
  await writeFile(path.join(fakeBin, 'docker'), '#!/bin/sh\ntouch ' + sentinel + '\n', { mode: 0o700 });
  const result = await doctor(f.project, { env: { PATH: fakeBin } });
  assert.equal(result.status, 'ready'); assert.equal(result.tools.docker.executableAvailable, true); assert.equal(result.tools.docker.executed, false);
  assert.equal(result.privacy.networkRequests, 0); assert.equal(result.privacy.credentialFilesRead, false);
  assert.equal(result.provider.model, 'not_used'); await assert.rejects(readFile(sentinel), { code: 'ENOENT' });
});

test('CLI help and preview execute without network access or provider credentials', async t => {
  const f = await fixture(t), cli = fileURLToPath(new URL('../bin/purple.mjs', import.meta.url));
  for (const args of [['--help'], ['scan', f.project, '--preview'], ['doctor', f.project]]) {
    const result = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 10000,
      env: { PATH: process.env.PATH, HOME: f.root, NODE_OPTIONS: '', HTTP_PROXY: 'http://127.0.0.1:1', HTTPS_PROXY: 'http://127.0.0.1:1' } });
    assert.equal(result.status, 0, result.stderr); assert.ok(result.stdout.length > 0);
  }
});
