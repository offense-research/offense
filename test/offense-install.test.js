import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, symlink, rm, lstat } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';
import { auditDependencies, prepareAudit } from '../scripts/offense-audit-client.mjs';
import { DatabaseSync } from 'node:sqlite';
import { createDependencyIntelligence } from '../server/dependency-intelligence.js';
import { createHash } from 'node:crypto';
import { sanitizeLockfiles } from '../public/skills/purple/scripts/metadata.mjs';

const execute = promisify(execFile);
const lock = JSON.stringify({ name: 'do-not-upload-this-repository', lockfileVersion: 3, packages: {
  '': { scripts: { postinstall: 'do-not-run-this-script' }, dependencies: { example: '^1.0.0' } },
  'node_modules/example': { version: '1.0.0', resolved: 'https://user:private-password@registry.test/example', integrity: 'do-not-upload-integrity' }
} });
async function fixture(t) {
  const outer = await mkdtemp(path.join(os.tmpdir(), 'offense-install-test-')), root = path.join(outer, 'repo');
  await mkdir(root); await writeFile(path.join(root, 'package-lock.json'), lock); await writeFile(path.join(root, 'package.json'), '{"name":"private-repository"}');
  t.after(() => rm(outer, { recursive: true, force: true })); return { outer, root, output: path.join(outer, 'report') };
}
const report = (status = 'complete') => ({ schemaVersion: 'offense.audit.v1', capability: 'audit_dependencies', status,
  metadataFingerprint: createHash('sha256').update(JSON.stringify(sanitizeLockfiles([{ path: 'package-lock.json', content: lock }]).files)).digest('hex'),
  findings: [{ id: 'finding-example', advisoryId: 'GHSA-example', package: { ecosystem: 'npm', name: 'example', installedVersion: '1.0.0', kind: 'runtime', lockfiles: ['package-lock.json'] }, verification: { status: 'advisory_match', confirmed: false } }], coverage: { complete: true },
  remediation: { plans: [], blockers: status === 'partial' ? [{ package: 'example', reason: 'No checked target' }] : [], agentPrompt: 'Review the recorded advisory and verify a fix.' } });

test('Offense preparation sends only sanitized metadata and keeps local omissions explicit', async t => {
  const { root } = await fixture(t);
  await writeFile(path.join(root, '.npmrc'), '//registry.test/:_authToken=do-not-read-config');
  await writeFile(path.join(root, 'index.js'), 'source code secret must stay local');
  await writeFile(path.join(root, 'yarn.lock'), 'unsupported');
  await symlink(path.join(root, 'package-lock.json'), path.join(root, 'external-lock.json'));
  await mkdir(path.join(root, 'other')); await writeFile(path.join(root, 'other/package.json'), '{}');
  const result = await prepareAudit(root, { planLimit: 0 }), sent = JSON.stringify(result.request);
  assert.equal(result.request.planLimit, 0); assert.equal(result.request.files.length, 1);
  assert.ok(result.local.warnings.some(value => value.includes('unsupported')));
  assert.ok(result.local.warnings.some(value => value.includes('symlink')));
  assert.ok(result.local.warnings.some(value => value.includes('other/package.json')));
  for (const forbidden of ['private-password', 'do-not-run', 'do-not-upload', 'source code secret', '_authToken', 'private-repository']) assert.ok(!sent.includes(forbidden), forbidden);
  assert.deepEqual(JSON.parse(result.request.files[0].content).packages['node_modules/example'], { version: '1.0.0' });
  assert.equal(await readFile(path.join(root, 'package-lock.json'), 'utf8'), lock);
});

test('Offense helper returns saved partial evidence and preserves it after an upstream failure', async t => {
  const { root, output } = await fixture(t); let calls = 0;
  const result = await auditDependencies(root, { output, fetchImpl: async (url, options) => {
    calls++; assert.equal(String(url), 'https://app.purpleteam.sh/api/offense/audit');
    assert.equal(options.redirect, 'error'); assert.equal(options.headers.authorization, undefined);
    assert.deepEqual(Object.keys(JSON.parse(options.body)).sort(), ['files', 'planLimit']);
    return Response.json(report('partial'));
  } });
  assert.equal(calls, 1); assert.equal(result.status, 'partial'); assert.equal(result.blockers, 1); assert.equal(result.confirmedVulnerabilities, 0);
  const saved = await readFile(result.json, 'utf8'); assert.equal(JSON.parse(saved).status, 'partial');
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ error: { code: 'provider_unavailable', message: 'Advisory provider unavailable' } }, { status: 502 }) }), /provider unavailable/);
  assert.equal(await readFile(result.json, 'utf8'), saved);
});

test('preview makes no request; unsupported or incomplete results cannot become a clean audit', async t => {
  const { root, output } = await fixture(t);
  const preview = await auditDependencies(root, { preview: true, fetchImpl: () => assert.fail('Preview sent metadata') });
  assert.equal(preview.request.files.length, 1);
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ status: 'complete', findings: [] }) }), /incomplete Offense response/);
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ ...report(), findings: [{ id: 'GHSA-legacy', package: 'example', version: '1.0.0' }] }) }), /incomplete Offense response/);
  await assert.rejects(auditDependencies(root, { output, fetchImpl: async () => Response.json({ ...report(), metadataFingerprint: '0'.repeat(64) }) }), /does not match the normalized dependency metadata/);
  await assert.rejects(auditDependencies(root, { output: path.join(root, 'reports'), fetchImpl: () => assert.fail('Invalid report location sent a request') }), /outside the source checkout/);
  await assert.rejects(prepareAudit(root, { planLimit: 11 }), /0 to 10/);
  await rm(path.join(root, 'package-lock.json'));
  await assert.rejects(prepareAudit(root), /Exact dependency versions are unknown/);
});

test('downloaded-client contract accepts the actual intelligence service report and saves its structured evidence', async t => {
  const { root, output } = await fixture(t), db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const intelligence = createDependencyIntelligence({ db,
    check: async packages => ({ status: 'complete', checkedAt: Date.now(), checkedPackages: packages.length, skippedPackages: 0,
      findings: [{ package: 'example', version: '1.0.0', id: 'GHSA-integration', severity: 'HIGH', summary: 'Synthetic advisory', fixedVersions: ['1.0.1'] }] }),
    plan: async (snapshot, name, version) => ({ name, currentVersion: version, targetVersion: '1.0.1', releases: [version, '1.0.1'], steps: [], considered: [], parentOptions: [], impact: { paths: [['app', name]], parents: [] } }) });
  const result = await auditDependencies(root, { output, fetchImpl: async (url, options) => Response.json(await intelligence.audit(JSON.parse(options.body))) });
  assert.equal(result.status, 'complete'); assert.equal(result.advisoryMatches, 1); assert.equal(result.upgradePlans, 1);
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.equal(saved.findings[0].package.name, 'example'); assert.equal(saved.findings[0].package.installedVersion, '1.0.0');
  assert.equal(saved.findings[0].advisoryId, 'GHSA-integration'); assert.equal(saved.findings[0].verification.confirmed, false);
  assert.match(saved.metadataFingerprint, /^[a-f0-9]{64}$/); assert.match(await readFile(result.prompt, 'utf8'), /GHSA-integration/);
  const preview = await prepareAudit(root); assert.equal(saved.metadataFingerprint, preview.local.metadataFingerprint);
  assert.notEqual(preview.local.fingerprint, preview.local.metadataFingerprint, 'raw local content and normalized dependency identity have different purposes');
});

test('client omissions make a server-complete audit partial instead of implying complete coverage', async t => {
  const { root, output } = await fixture(t); await writeFile(path.join(root, 'yarn.lock'), 'unsupported');
  const result = await auditDependencies(root, { output, fetchImpl: async () => Response.json(report()) });
  assert.equal(result.status, 'partial'); assert.equal(result.localCoverageWarnings, 1);
  const saved = JSON.parse(await readFile(result.json, 'utf8')); assert.equal(saved.status, 'partial'); assert.equal(saved.serverStatus, 'complete');
  assert.match(await readFile(result.prompt, 'utf8'), /unsupported lockfile/);
});

test('the downloadable client is standalone and its CLI emits one usable MCP argument object', async t => {
  const { root, outer } = await fixture(t);
  const installed = path.join(outer, 'offense.mjs');
  await writeFile(installed, await readFile('public/skills/offense/scripts/offense.mjs'));
  const { stdout, stderr } = await execute(process.execPath, [installed, 'metadata', root, '--plan-limit', '2'], { cwd: outer, env: { PATH: process.env.PATH, HOME: process.env.HOME } });
  const request = JSON.parse(stdout); assert.equal(request.planLimit, 2); assert.equal(request.files.length, 1); assert.equal(stderr, '');
  assert.ok(!stdout.includes('private-password'));
});

test('pnpm metadata is normalized without uploading registry credentials or executing package scripts', async t => {
  const { root } = await fixture(t); await rm(path.join(root, 'package-lock.json'));
  await writeFile(path.join(root, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      semver:\n        specifier: 7.5.1\n        version: 7.5.1\npackages:\n  semver@7.5.1:\n    resolution:\n      integrity: do-not-upload-integrity\n      tarball: https://user:private-password@registry.test/package\nsnapshots:\n  semver@7.5.1: {}\n`);
  const result = await prepareAudit(root), payload = JSON.stringify(result.request);
  assert.equal(result.request.files[0].path, 'pnpm-lock.yaml');
  assert.match(payload, /7\.5\.1/); assert.doesNotMatch(payload, /private-password|do-not-upload-integrity|registry.test/);
  assert.equal(result.local.warnings.length, 0);
});

async function plannedRepository(t) {
  const fixtureData = await fixture(t), names = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];
  const packages = Object.fromEntries([['', { dependencies: Object.fromEntries(names.map(name => [name, '^1.0.0'])) }],
    ...names.map(name => [`node_modules/${name}`, { version: '1.0.0' }])]);
  await writeFile(path.join(fixtureData.root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages }));
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  const intelligence = createDependencyIntelligence({ db,
    check: async packages => ({ status: 'complete', checkedPackages: packages.length, skippedPackages: 0, checkedAt: Date.now(),
      findings: packages.map(pkg => ({ package: pkg.name, version: pkg.version, id: `GHSA-${pkg.name}`, severity: 'HIGH', fixedVersions: ['1.0.1'] })) }),
    plan: async (snapshot, name, version) => ({ name, currentVersion: version, targetVersion: '1.0.1', considered: [{ version: '1.0.1', advisories: 0 }],
      releases: [version, '1.0.1'], steps: [], parentOptions: [], impact: { paths: [['app', name]], parents: [] } }) });
  return { ...fixtureData, names, intelligence };
}

test('audit automatically continues planning without replacing the full scan with a smaller page', async t => {
  const { root, output, names, intelligence } = await plannedRepository(t), requests = [];
  const result = await auditDependencies(root, { output, planLimit: 2, fetchImpl: async (url, options) => {
    const input = JSON.parse(options.body); requests.push(input);
    return Response.json(await intelligence.audit(input));
  } });
  assert.equal(requests.length, 3);
  assert.deepEqual(Object.keys(requests[0]).sort(), ['files', 'planLimit']);
  assert.deepEqual(requests.slice(1).map(input => input.planning.pendingTargetIds.length), [3, 1]);
  assert.equal(result.planningPages, 3); assert.equal(result.remainingPlanningTargets, 0);
  assert.equal(result.advisoryMatches, 5); assert.equal(result.upgradePlans, 5); assert.equal(result.confirmedVulnerabilities, 0);
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.equal(saved.coverage.checkedPackages, 5);
  assert.equal(saved.remediation.planning.scope, 'full_audit');
  assert.equal(saved.remediation.planning.next, null);
  assert.equal(saved.clientPlanning.stopReason, 'finished');
  assert.deepEqual(saved.findings.map(item => item.package.name).sort(), names.sort());
  const prompt = await readFile(result.prompt, 'utf8');
  for (const name of names) assert.match(prompt, new RegExp(`GHSA-${name}`));
});

test('a later planning failure retains the saved original findings, completed plans, diagnostics and next targets', async t => {
  const { root, output, intelligence } = await plannedRepository(t); let calls = 0;
  const result = await auditDependencies(root, { output, planLimit: 2, fetchImpl: async (url, options) => {
    if (++calls > 1) return Response.json({ error: { code: 'quota_exceeded', message: 'Try later' } }, { status: 429, headers: { 'retry-after': '60', 'cf-ray': 'safe-edge-id' } });
    return Response.json(await intelligence.audit(JSON.parse(options.body)));
  } });
  assert.equal(calls, 2); assert.equal(result.status, 'partial');
  assert.equal(result.advisoryMatches, 5); assert.equal(result.upgradePlans, 2); assert.equal(result.remainingPlanningTargets, 3);
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.equal(saved.clientPlanning.stopReason, 'request_failed');
  assert.equal(saved.clientPlanning.error.diagnostics.httpStatus, 429);
  assert.equal(saved.clientPlanning.error.diagnostics.edgeRequestId, 'safe-edge-id');
  assert.equal(saved.clientPlanning.error.diagnostics.retryAfter, '60');
  assert.equal(saved.remediation.planning.next.pendingTargetIds.length, 3);
  assert.match(await readFile(result.prompt, 'utf8'), /planning-only response is not a new full audit/);
});

test('explicit page budgets stop with resumable target IDs and scan-only mode performs no planning continuation', async t => {
  const { root, output, intelligence } = await plannedRepository(t); let calls = 0;
  const fetchImpl = async (url, options) => { calls++; return Response.json(await intelligence.audit(JSON.parse(options.body))); };
  const result = await auditDependencies(root, { output, planLimit: 2, maxPages: 1, fetchImpl });
  assert.equal(calls, 1); assert.equal(result.remainingPlanningTargets, 3);
  assert.equal(JSON.parse(await readFile(result.json, 'utf8')).clientPlanning.stopReason, 'client_page_limit');
  const scanOnly = await auditDependencies(root, { output, planLimit: 0, fetchImpl });
  assert.equal(calls, 2); assert.equal(scanOnly.upgradePlans, 0);
  assert.equal(JSON.parse(await readFile(scanOnly.json, 'utf8')).clientPlanning.stopReason, 'not_requested');
  await assert.rejects(auditDependencies(root, { maxPages: 11, fetchImpl: () => assert.fail('Invalid budget sent metadata') }), /1 to 10/);
});

test('invalid continuation identities cannot overwrite valid earlier scan evidence', async t => {
  const { root, output, intelligence } = await plannedRepository(t); let calls = 0;
  const result = await auditDependencies(root, { output, planLimit: 2, fetchImpl: async (url, options) => {
    const body = await intelligence.audit(JSON.parse(options.body));
    if (++calls > 1) body.metadataFingerprint = '0'.repeat(64);
    return Response.json(body);
  } });
  assert.equal(calls, 2); assert.equal(result.status, 'partial');
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.notEqual(saved.metadataFingerprint, '0'.repeat(64));
  assert.equal(saved.findings.length, 5); assert.equal(saved.remediation.plans.length, 2);
  assert.match(saved.clientPlanning.error.message, /does not match/);
});

test('local unsupported-ecosystem tasks and reviewed verification never enter the hosted request or hide matches', async t => {
  const { root, outer, output } = await fixture(t), evidence = path.join(outer, 'verification.json');
  await writeFile(path.join(root, 'requirements.txt'), 'Pillow==12.3.0\n--extra-index-url https://user:LOCAL-PYTHON-CREDENTIAL@private-registry.test\n');
  await writeFile(evidence, JSON.stringify({ schemaVersion: 'offense.verification.v1', reviewedBy: 'LOCAL-REVIEWER-NAME', findings: [] }));
  const result = await auditDependencies(root, { output, evidence, fetchImpl: async (url, options) => {
    assert.deepEqual(Object.keys(JSON.parse(options.body)).sort(), ['files', 'planLimit']);
    assert.doesNotMatch(options.body, /Pillow|LOCAL-PYTHON-CREDENTIAL|LOCAL-REVIEWER-NAME|requirements\.txt/);
    return Response.json(report());
  } });
  assert.equal(result.status, 'partial'); assert.equal(result.advisoryMatches, 1); assert.equal(result.confirmedVulnerabilities, 0);
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.equal(saved.localVerification.status, 'needs_review');
  assert.equal(saved.localVerification.counts.advisory_match, 1);
  assert.equal(saved.findings[0].verification.confirmed, false);
  assert.equal(saved.clientCoverage.evidence.coverage.unsupportedFiles[0].ecosystem, 'Python');
  assert.match(await readFile(result.prompt, 'utf8'), /Agent-owned coverage follow-up/);
});

test('report symlinks cannot make an audit write into the checkout', async t => {
  const { root, outer, output } = await fixture(t);
  await mkdir(output);
  const source = path.join(root, 'package.json'), original = await readFile(source, 'utf8');
  await symlink(source, path.join(output, 'audit.json'));
  await assert.rejects(auditDependencies(root, { output, fetchImpl: () => assert.fail('Unsafe report path sent metadata') }), /report symlinks/);
  assert.equal(await readFile(source, 'utf8'), original);
  await symlink(root, path.join(outer, 'linked-checkout'));
  await assert.rejects(auditDependencies(root, { output: path.join(outer, 'linked-checkout/should-not-create'), fetchImpl: () => assert.fail('Unsafe report parent sent metadata') }), /inside the source checkout/);
  await assert.rejects(lstat(path.join(root, 'should-not-create')), { code: 'ENOENT' });
});

test('large advisory audits continue automatically with full lockfiles and exact merged counts', async t => {
  const { root, output } = await fixture(t);
  const packages = { '': {} }, matches = new Map(), expected = new Set();
  for (let n = 0; n < 2004; n++) packages[`node_modules/example-${String(n).padStart(4, '0')}`] = { version: '1.0.0' };
  const add = (target, id) => {
    const name = `example-${String(target * 29).padStart(4, '0')}`;
    if (!matches.has(name)) matches.set(name, []);
    matches.get(name).push(`GHSA-fixture-${id}`); expected.add(`${name}:GHSA-fixture-${id}`);
  };
  for (let id = 0; id < 263; id++) add(id < 200 ? 0 : id - 199, id);
  for (let id = 0; id < 62; id++) add(1 + (id + 10) % 67, id);
  const original = JSON.stringify({ lockfileVersion: 3, packages });
  await writeFile(path.join(root, 'package-lock.json'), original);
  const db = new DatabaseSync(':memory:'); t.after(() => db.close());
  let outbound = 0, calls = 0;
  const intelligence = createDependencyIntelligence({ db, fetchImpl: async (url, options) => {
    outbound++;
    if (url.endsWith('/querybatch')) return Response.json({ results: JSON.parse(options.body).queries.map(q => ({
      vulns: (matches.get(q.package.name) || []).map(id => ({ id, modified: '2026-01-01T00:00:00Z' }))
    })) });
    const id = url.split('/').at(-1), number = Number(id.split('-').at(-1));
    return Response.json({ id, aliases: [`CVE-2026-${10000 + number}`], database_specific: { severity: 'HIGH' } });
  } });
  const result = await auditDependencies(root, { output, planLimit: 0, fetchImpl: async (url, options) => {
    calls++; outbound = 0;
    const input = JSON.parse(options.body);
    assert.equal(Object.keys(JSON.parse(input.files[0].content).packages).length, 2005);
    const page = await intelligence.audit(input);
    assert.ok(outbound <= 60, `Page exceeded bounded scan requests: ${outbound}`);
    if (input.scanning || page.scanning.next) assert.equal(page.status, 'partial');
    return Response.json(page);
  } });
  const saved = JSON.parse(await readFile(result.json, 'utf8'));
  assert.ok(calls > 1 && calls <= 10);
  assert.equal(result.scanningPages, calls); assert.equal(result.status, 'complete');
  assert.equal(saved.coverage.checkedPackages, 2004); assert.equal(saved.coverage.status, 'complete');
  assert.equal(saved.scanning.next, null);
  assert.equal(saved.summary.advisoryMatches, 325); assert.equal(saved.summary.distinctAdvisoryIds, 263);
  assert.equal(saved.summary.distinctCves, 263); assert.equal(saved.summary.affectedPackages, 68);
  assert.deepEqual(new Set(saved.findings.map(f => `${f.package.name}:${f.advisoryId}`)), expected);
  assert.equal(await readFile(path.join(root, 'package-lock.json'), 'utf8'), original);
});

test('scan interruptions retain resumable evidence, reject stale pages, and defer planning until complete', async t => {
  const { root, outer, output } = await fixture(t), db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  let changed = false, planned = 0;
  const intelligence = createDependencyIntelligence({ db, fetchImpl: async url => {
    if (url.endsWith('/querybatch')) return Response.json({ results: [{ vulns: Array.from({ length: changed ? 66 : 65 }, (_, n) => ({ id: `GHSA-test-${n}`, modified: '2026-01-01' })) }] });
    return Response.json({ database_specific: { severity: 'HIGH' } });
  }, plan: async (snapshot, name, version) => {
    planned++;
    assert.equal(snapshot.graph.nodes.length, 1);
    return { name, currentVersion: version, targetVersion: '1.0.1', releases: [], steps: [], parentOptions: [], impact: { paths: [], parents: [] } };
  } });
  const fetchImpl = async (url, options) => Response.json(await intelligence.audit(JSON.parse(options.body)));
  const limited = await auditDependencies(root, { output, planLimit: 1, maxPages: 1, fetchImpl });
  const first = JSON.parse(await readFile(limited.json, 'utf8'));
  assert.equal(first.status, 'partial'); assert.equal(first.findings.length, 59);
  assert.equal(first.coverage.checkedPackages, 0); assert.ok(first.scanning.next); assert.equal(planned, 0);
  const input = (await prepareAudit(root)).request;
  await assert.rejects(intelligence.audit({ ...input, scanning: { ...first.scanning.next, metadataFingerprint: '0'.repeat(64) } }), /exact dependency files/);
  await assert.rejects(intelligence.audit({ ...input, scanning: { ...first.scanning.next, advisoryOffset: -1 } }), /Invalid advisory scanning/);
  changed = true;
  await assert.rejects(intelligence.audit({ ...input, scanning: first.scanning.next }), /Advisory evidence changed/);
  changed = false;
  for (const failure of ['provider', 'cursor', 'replay']) {
    let requests = 0;
    const result = await auditDependencies(root, { output: path.join(outer, failure), planLimit: 1, fetchImpl: async (url, options) => {
      requests++;
      if (requests === 2 && failure === 'provider') throw Error('Provider unavailable');
      const page = await intelligence.audit(JSON.parse(options.body));
      if (requests === 2 && failure === 'cursor') page.scanning.start.advisoryOffset--;
      if (requests === 2 && failure === 'replay') return Response.json(first);
      return Response.json(page);
    } });
    const saved = JSON.parse(await readFile(result.json, 'utf8'));
    assert.equal(saved.status, 'partial'); assert.equal(saved.findings.length, 59);
    assert.deepEqual(saved.scanning.next, first.scanning.next);
    assert.equal(saved.clientScanning.stopReason, 'request_failed');
    assert.equal(planned, 0);
  }
  const completed = await auditDependencies(root, { output: path.join(outer, 'finished'), resume: limited.json, planLimit: 1, fetchImpl });
  const saved = JSON.parse(await readFile(completed.json, 'utf8'));
  assert.equal(planned, 1); assert.equal(saved.coverage.status, 'complete');
  assert.equal(saved.findings.length, 65); assert.equal(saved.scanning.completedPages, 2);
  assert.equal(saved.remediation.planning.hasMore, false);
  assert.equal(await readFile(limited.json, 'utf8'), JSON.stringify(first, null, 2) + '\n');
  await writeFile(path.join(root, 'package-lock.json'), lock.replace('1.0.0', '1.0.2').replace('"version":"1.0.0"', '"version":"1.0.2"'));
  await assert.rejects(auditDependencies(root, { output: path.join(outer, 'stale'), resume: limited.json,
    fetchImpl: () => assert.fail('Stale resume sent metadata') }), /matching the current dependency metadata/);
});
